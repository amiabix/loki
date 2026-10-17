use super::{
    journal::{Journal, MemberLock},
    AcceptedCeremonyRoster,
};
use crate::{
    distributed_setup::{Completed, Member, Round2Member},
    setup_transport::Identity,
    state::MemberDir,
    vault, zip2005,
};
use rand_core::{OsRng, RngCore};
use std::{collections::BTreeMap, path::Path};
use zeroize::Zeroizing;
use zcash_protocol::consensus::Parameters;

const ERROR: &str = "setup_ceremony";
const MAX_WIRE: usize = 66 * 1024;
const MAX_PREPARED: usize = 8 * 1024 * 1024;
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum CeremonyPhase {
    AwaitingRoster = 0,
    Starting = 1,
    Round1Saved = 2,
    Round2Saved = 3,
    CertificateSaved = 4,
    AwaitingBackups = 5,
    Certified = 6,
    PaymentHandoff = 7,
    Active = 8,
    Aborted = 9,
}
impl CeremonyPhase {
    fn decode(value: u8) -> Result<Self, String> {
        Ok(match value {
            0 => Self::AwaitingRoster,
            1 => Self::Starting,
            2 => Self::Round1Saved,
            3 => Self::Round2Saved,
            4 => Self::CertificateSaved,
            5 => Self::AwaitingBackups,
            6 => Self::Certified,
            7 => Self::PaymentHandoff,
            8 => Self::Active,
            9 => Self::Aborted,
            _ => return Err(ERROR.into()),
        })
    }
}
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SavedCheckpoint {
    pub generation: u64,
    pub predecessor: [u8; 32],
    pub digest: [u8; 32],
    pub operation: [u8; 32],
}
pub struct CheckpointState {
    pub generation: u64,
    pub digest: [u8; 32],
    pub terminal: bool,
}
/// Implementations authenticate admission state and reconcile the saved operation without changing it.
pub trait CheckpointAuthority {
    fn reconcile(&mut self, expected: &SavedCheckpoint) -> Result<CheckpointState, String>;
    fn reconcile_active(&mut self, expected: &SavedCheckpoint) -> Result<CheckpointState, String> {
        self.reconcile(expected)
    }
}
/// Native phase wires from authenticated setup records; transport noise is rejected before this boundary.
pub struct CeremonyRecord {
    pub phase: CeremonyPhase,
    pub author: u16,
    pub bytes: Vec<u8>,
}
pub struct CeremonyStep {
    pub phase: CeremonyPhase,
    pub missing_slots: Vec<u16>,
    pub checkpoint: SavedCheckpoint,
}
struct PrivateShares(BTreeMap<u16, Vec<u8>>);
impl Drop for PrivateShares {
    fn drop(&mut self) {
        for bytes in self.0.values_mut() {
            zeroize::Zeroize::zeroize(bytes);
        }
    }
}
struct Snapshot {
    phase: CeremonyPhase,
    contribution: Zeroizing<[u8; 32]>,
    dkg: Zeroizing<Vec<u8>>,
    round1: BTreeMap<u16, Vec<u8>>,
    round2: BTreeMap<u16, Vec<u8>>,
    outgoing: BTreeMap<u16, Vec<u8>>,
    certificates: BTreeMap<u16, Vec<u8>>,
    backups: BTreeMap<u16, Vec<u8>>,
    vs: Zeroizing<[u8; 32]>,
    prepared: Vec<u8>,
}
pub struct SetupCeremony {
    journal: Journal,
    accepted: AcceptedCeremonyRoster,
    identity: Identity,
    snapshot: Snapshot,
    anchored: bool,
    live_start: bool,
    poisoned: bool,
    _member_lock: MemberLock,
}
fn digest(personal: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(personal)
        .to_state();
    for part in parts {
        hash.update(part);
    }
    hash.finalize()
        .as_bytes()
        .try_into()
        .expect("32 byte digest")
}
fn field(out: &mut Vec<u8>, value: &[u8]) -> Result<(), String> {
    if value.len() > MAX_PREPARED || out.len().saturating_add(value.len() + 4) > 16 * 1024 * 1024 {
        return Err(ERROR.into());
    }
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}
fn map(out: &mut Vec<u8>, values: &BTreeMap<u16, Vec<u8>>) -> Result<(), String> {
    if values.len() > 4 {
        return Err(ERROR.into());
    }
    out.push(values.len() as u8);
    for (id, bytes) in values {
        if !(1..=4).contains(id) || bytes.len() > MAX_WIRE {
            return Err(ERROR.into());
        }
        out.extend_from_slice(&id.to_be_bytes());
        field(out, bytes)?;
    }
    Ok(())
}
struct Reader<'a> {
    raw: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(n)
            .filter(|n| *n <= self.raw.len())
            .ok_or(ERROR)?;
        let bytes = &self.raw[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }
    fn field(&mut self, limit: usize) -> Result<&'a [u8], String> {
        let size = u32::from_be_bytes(self.take(4)?.try_into().map_err(|_| ERROR)?) as usize;
        if size > limit {
            return Err(ERROR.into());
        }
        self.take(size)
    }
    fn map(&mut self) -> Result<BTreeMap<u16, Vec<u8>>, String> {
        let count = self.take(1)?[0];
        if count > 4 {
            return Err(ERROR.into());
        }
        let mut map = BTreeMap::new();
        let mut previous = 0;
        for _ in 0..count {
            let id = u16::from_be_bytes(self.take(2)?.try_into().map_err(|_| ERROR)?);
            if id <= previous || id > 4 {
                return Err(ERROR.into());
            }
            previous = id;
            map.insert(id, self.field(MAX_WIRE)?.to_vec());
        }
        Ok(map)
    }
}
impl Snapshot {
    fn ready() -> Self {
        Self {
            phase: CeremonyPhase::AwaitingRoster,
            contribution: Zeroizing::new([0; 32]),
            dkg: Zeroizing::new(Vec::new()),
            round1: BTreeMap::new(),
            round2: BTreeMap::new(),
            outgoing: BTreeMap::new(),
            certificates: BTreeMap::new(),
            backups: BTreeMap::new(),
            vs: Zeroizing::new([0; 32]),
            prepared: Vec::new(),
        }
    }
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        let mut out = Zeroizing::new(b"LOKIENG1".to_vec());
        out.push(self.phase as u8);
        out.extend_from_slice(&*self.contribution);
        field(&mut out, &self.dkg)?;
        map(&mut out, &self.round1)?;
        map(&mut out, &self.round2)?;
        map(&mut out, &self.outgoing)?;
        map(&mut out, &self.certificates)?;
        map(&mut out, &self.backups)?;
        out.extend_from_slice(&*self.vs);
        field(&mut out, &self.prepared)?;
        Ok(out)
    }
    fn decode(raw: &[u8]) -> Result<Self, String> {
        let mut reader = Reader { raw, offset: 0 };
        if reader.take(8)? != b"LOKIENG1" {
            return Err(ERROR.into());
        }
        let phase = CeremonyPhase::decode(reader.take(1)?[0])?;
        let contribution = Zeroizing::new(reader.take(32)?.try_into().map_err(|_| ERROR)?);
        let dkg = Zeroizing::new(reader.field(64 * 1024)?.to_vec());
        let round1 = reader.map()?;
        let round2 = reader.map()?;
        let outgoing = reader.map()?;
        let certificates = reader.map()?;
        let backups = reader.map()?;
        let vs = Zeroizing::new(reader.take(32)?.try_into().map_err(|_| ERROR)?);
        let prepared = reader.field(MAX_PREPARED)?.to_vec();
        if reader.offset != raw.len() {
            return Err(ERROR.into());
        }
        Ok(Self {
            phase,
            contribution,
            dkg,
            round1,
            round2,
            outgoing,
            certificates,
            backups,
            vs,
            prepared,
        })
    }
}
impl SetupCeremony {
    pub fn open(
        member_root: &Path,
        passphrase: &str,
        accepted: AcceptedCeremonyRoster,
    ) -> Result<Self, String> {
        super::journal::check_private_root(member_root)?;
        let secrets = member_root.join("secrets");
        super::journal::check_private_root(&secrets)?;
        let member_lock = super::journal::lock_file(&secrets.join(".setup.lock"))?;
        Self::open_with_member_lock(member_root, passphrase, accepted, &member_lock)
    }
    pub(crate) fn open_with_member_lock(
        member_root: &Path,
        passphrase: &str,
        accepted: AcceptedCeremonyRoster,
        held_lock: &MemberLock,
    ) -> Result<Self, String> {
        super::journal::check_private_root(member_root)?;
        let secrets = member_root.join("secrets");
        super::journal::check_private_root(&secrets)?;
        let member_lock = held_lock.share_for(&secrets.join(".setup.lock"))?;
        let identity_path = secrets.join("identity.sealed");
        let file = super::journal::checked_file(&identity_path)?;
        if file.metadata().map_err(|_| ERROR)?.len() != 49 + 66 + 16 {
            return Err(ERROR.into());
        }
        let bytes = Zeroizing::new(
            MemberDir::open(member_root, "secrets")
                .read_sealed("identity.sealed", passphrase)
                .map_err(|_| ERROR)?,
        );
        let identity = Identity::from_secret_bytes(&bytes).map_err(|_| ERROR)?;
        if accepted.roster().members.get(&identity.public().id) != Some(&identity.public()) {
            return Err(ERROR.into());
        }
        let mut journal = Journal::open(
            &member_root.join("setup-ceremony"),
            passphrase,
            accepted.context_digest(),
            identity.public().id,
        )?;
        if journal.latest().is_none() {
            journal.append(&Snapshot::ready().encode()?)?;
        }
        let snapshot = Snapshot::decode(&journal.latest().ok_or(ERROR)?.payload)?;
        if matches!(
            snapshot.phase,
            CeremonyPhase::Starting | CeremonyPhase::Aborted
        ) {
            return Err("setup_fresh_vault_required".into());
        }
        let engine = Self {
            journal,
            accepted,
            identity,
            snapshot,
            anchored: false,
            live_start: false,
            poisoned: false,
            _member_lock: member_lock,
        };
        engine.validate_snapshot()?;
        Ok(engine)
    }
    pub(crate) fn saved_phase(
        member_root: &Path,
        passphrase: &str,
        context: [u8; 32],
        own: u16,
        held_lock: &MemberLock,
    ) -> Result<Option<CeremonyPhase>, String> {
        super::journal::check_private_root(member_root)?;
        let _lock = held_lock.share_for(&member_root.join("secrets/.setup.lock"))?;
        let path = member_root.join("setup-ceremony");
        if !path.try_exists().map_err(|_| ERROR)? {
            return Ok(None);
        }
        let journal = Journal::open(&path, passphrase, context, own)?;
        Ok(Some(
            Snapshot::decode(&journal.latest().ok_or(ERROR)?.payload)?.phase,
        ))
    }
    pub(crate) fn abort_saved_checkpoint(
        member_root: &Path,
        passphrase: &str,
        context: [u8; 32],
        own: u16,
        held_lock: &MemberLock,
        confirmed_terminal: Option<u16>,
    ) -> Result<(), String> {
        super::journal::check_private_root(member_root)?;
        let _lock = held_lock.share_for(&member_root.join("secrets/.setup.lock"))?;
        let path = member_root.join("setup-ceremony");
        if !path.try_exists().map_err(|_| ERROR)? {
            return Ok(());
        }
        let mut journal = Journal::open(&path, passphrase, context, own)?;
        let mut snapshot = Snapshot::decode(&journal.latest().ok_or(ERROR)?.payload)?;
        if snapshot.phase == CeremonyPhase::Aborted {
            return Ok(());
        }
        if snapshot.phase == CeremonyPhase::Active {
            if !matches!(confirmed_terminal, Some(1 | 3 | 4)) {
                return Err("setup_already_active".into());
            }
            let marker = member_root.join("secrets/activation.sealed");
            if marker.try_exists().map_err(|_| ERROR)? {
                super::journal::checked_file(&marker)?;
                return Err("setup_already_active".into());
            }
        }
        snapshot.phase = CeremonyPhase::Aborted;
        snapshot.outgoing.clear();
        snapshot.prepared.clear();
        zeroize::Zeroize::zeroize(&mut *snapshot.dkg);
        zeroize::Zeroize::zeroize(&mut *snapshot.contribution);
        zeroize::Zeroize::zeroize(&mut *snapshot.vs);
        journal.append(&snapshot.encode()?)?;
        Ok(())
    }
    pub fn phase(&self) -> CeremonyPhase {
        self.snapshot.phase
    }
    pub fn checkpoint(&self) -> SavedCheckpoint {
        let g = self.journal.latest().expect("initial generation saved");
        SavedCheckpoint {
            generation: g.number,
            predecessor: g.predecessor,
            digest: g.digest,
            operation: g.operation,
        }
    }
    pub fn synchronize<A: CheckpointAuthority>(&mut self, authority: &mut A) -> Result<(), String> {
        if self.poisoned {
            return Err("setup_fresh_vault_required".into());
        }
        self.anchored = false;
        let expected = self.checkpoint();
        let remote = if self.phase() == CeremonyPhase::Active {
            authority.reconcile_active(&expected)?
        } else {
            authority.reconcile(&expected)?
        };
        if remote.terminal
            || remote.generation != expected.generation
            || remote.digest != expected.digest
        {
            self.persist_terminal()?;
            return Err("setup_fresh_vault_required".into());
        }
        self.anchored = true;
        Ok(())
    }
    pub fn outgoing(&self) -> Result<&BTreeMap<u16, Vec<u8>>, String> {
        if !self.anchored || self.poisoned {
            return Err("setup_checkpoint_pending".into());
        }
        Ok(&self.snapshot.outgoing)
    }
    pub fn prepared_delivery(&self) -> Result<&[u8], String> {
        self.outgoing()?;
        Ok(&self.snapshot.prepared)
    }
    fn certificate_body(&self) -> Result<Vec<u8>, String> {
        let completed = Completed::restore_checkpoint(&self.snapshot.dkg)?;
        let mut body = completed.certificate_digest().to_vec();
        body.extend_from_slice(&digest(b"Loki_vs_cert_v1", &[&*self.snapshot.vs]));
        body.extend_from_slice(&self.accepted.roster().fingerprint());
        body.extend_from_slice(zip2005::VERSION.as_bytes());
        Ok(body)
    }
    fn authenticated_round1(&self) -> Result<BTreeMap<u16, Vec<u8>>, String> {
        let mut packages = BTreeMap::new();
        for (id, wire) in &self.snapshot.round1 {
            let member = self.accepted.roster().members.get(id).ok_or(ERROR)?;
            let body = self
                .identity
                .verify_round1(member, &self.accepted.roster().vault, wire)
                .map_err(|_| ERROR)?;
            if body.len() <= 32 {
                return Err(ERROR.into());
            }
            packages.insert(*id, body[32..].to_vec());
        }
        Ok(packages)
    }

    fn validate_completed_inputs(
        &self,
        completed: &Completed,
        packages: &BTreeMap<u16, Vec<u8>>,
    ) -> Result<(), String> {
        use reddsa_frost::frost::redpallas::{self as frost, keys::EvenY};
        let own = self.identity.public().id;
        let roster = self.accepted.roster();
        let expected: Vec<_> = roster
            .members
            .keys()
            .filter(|id| **id != own)
            .copied()
            .collect();
        if self.snapshot.round2.keys().copied().collect::<Vec<_>>() != expected {
            return Err(ERROR.into());
        }
        let mut decoded = BTreeMap::new();
        for (&id, bytes) in packages {
            decoded.insert(
                frost::Identifier::try_from(id).map_err(|_| ERROR)?,
                frost::keys::dkg::round1::Package::deserialize(bytes).map_err(|_| ERROR)?,
            );
        }
        let commitments = decoded
            .iter()
            .map(|(id, p)| (*id, p.commitment()))
            .collect();
        let public = frost::keys::PublicKeyPackage::from_dkg_commitments(&commitments)
            .map_err(|_| ERROR)?
            .into_even_y(None);
        if public.serialize().map_err(|_| ERROR)?.as_slice() != completed.public_package() {
            return Err(ERROR.into());
        }
        let mut contributions = BTreeMap::new();
        contributions.insert(own, Zeroizing::new(*self.snapshot.contribution));
        for (&id, wire) in &self.snapshot.round2 {
            let body = Zeroizing::new(
                self.identity
                    .open_round2(&roster.members[&id], &roster.vault, wire)
                    .map_err(|_| ERROR)?,
            );
            if body.len() <= 32 {
                return Err(ERROR.into());
            }
            let contribution =
                Zeroizing::new(<[u8; 32]>::try_from(&body[..32]).map_err(|_| ERROR)?);
            let round1 = self
                .identity
                .verify_round1(
                    &roster.members[&id],
                    &roster.vault,
                    &self.snapshot.round1[&id],
                )
                .map_err(|_| ERROR)?;
            if round1[..32]
                != digest(
                    b"Loki_vs_commit1",
                    &[&roster.vault, &id.to_be_bytes(), &*contribution],
                )
            {
                return Err(ERROR.into());
            }
            let share =
                frost::keys::dkg::round2::Package::deserialize(&body[32..]).map_err(|_| ERROR)?;
            let encoded = Zeroizing::new(share.serialize().map_err(|_| ERROR)?);
            if encoded.as_slice() != &body[32..] {
                return Err(ERROR.into());
            }
            frost::keys::SecretShare::new(
                frost::Identifier::try_from(own).map_err(|_| ERROR)?,
                *share.signing_share(),
                decoded[&frost::Identifier::try_from(id).map_err(|_| ERROR)?]
                    .commitment()
                    .clone(),
            )
            .verify()
            .map_err(|_| ERROR)?;
            contributions.insert(id, contribution);
        }
        let mut hash = blake2b_simd::Params::new()
            .hash_length(32)
            .personal(b"Loki_vs_v1")
            .to_state();
        hash.update(&completed.certificate_digest());
        for contribution in contributions.values() {
            hash.update(&**contribution);
        }
        if hash.finalize().as_bytes() != *self.snapshot.vs {
            return Err(ERROR.into());
        }
        Ok(())
    }
    fn validate_snapshot(&self) -> Result<(), String> {
        let s = &self.snapshot;
        let own = self.identity.public().id;
        let roster = self.accepted.roster();
        if self.accepted.transport_required && !s.outgoing.is_empty() && s.prepared.is_empty() {
            return Err(ERROR.into());
        }
        if matches!(
            s.phase,
            CeremonyPhase::PaymentHandoff | CeremonyPhase::Active
        ) && (s.outgoing.len() != roster.members.len()
            || s.outgoing.values().any(Vec::is_empty)
            || s.prepared.is_empty())
        {
            return Err(ERROR.into());
        }
        for values in [
            &s.round1,
            &s.round2,
            &s.outgoing,
            &s.certificates,
            &s.backups,
        ] {
            if values.keys().any(|id| !roster.members.contains_key(id)) {
                return Err(ERROR.into());
            }
        }
        if s.phase as u8 >= CeremonyPhase::Round1Saved as u8
            && (s.dkg.len() < 13
                || s.dkg[9..11] != own.to_be_bytes()
                || s.dkg[11..13] != (roster.members.len() as u16).to_be_bytes())
        {
            return Err(ERROR.into());
        }
        match s.phase {
            CeremonyPhase::AwaitingRoster => {
                if !s.dkg.is_empty()
                    || !s.round1.is_empty()
                    || !s.round2.is_empty()
                    || !s.outgoing.is_empty()
                    || *s.contribution != [0; 32]
                    || *s.vs != [0; 32]
                    || !s.certificates.is_empty()
                    || !s.backups.is_empty()
                    || !s.prepared.is_empty()
                {
                    return Err(ERROR.into());
                }
            }
            CeremonyPhase::Starting => return Err("setup_fresh_vault_required".into()),
            CeremonyPhase::Round1Saved => {
                let member = Member::restore_checkpoint(&s.dkg)?;
                if self.authenticated_round1()?.get(&own).map(Vec::as_slice)
                    != Some(member.own_round1())
                {
                    return Err(ERROR.into());
                }
            }
            CeremonyPhase::Round2Saved => {
                let member = Round2Member::restore_checkpoint(&s.dkg)?;
                if member.round1_packages()? != self.authenticated_round1()? {
                    return Err(ERROR.into());
                }
            }
            _ => {
                let completed = Completed::restore_checkpoint(&s.dkg)?;
                let packages = self.authenticated_round1()?;
                self.validate_completed_inputs(&completed, &packages)?;
                let mut hash = blake2b_simd::Params::new()
                    .hash_length(32)
                    .personal(b"Loki_dkg_r1_v1")
                    .to_state();
                for (id, package) in packages {
                    hash.update(&id.to_be_bytes());
                    hash.update(&(package.len() as u32).to_be_bytes());
                    hash.update(&package);
                }
                if hash.finalize().as_bytes() != completed.transcript() {
                    return Err(ERROR.into());
                }
                let body = self.certificate_body()?;
                for (id, wire) in &s.certificates {
                    if self
                        .identity
                        .verify_certificate(&roster.members[id], &roster.vault, wire)
                        .map_err(|_| ERROR)?
                        != body
                    {
                        return Err(ERROR.into());
                    }
                }
                if s.phase as u8 >= CeremonyPhase::AwaitingBackups as u8
                    && s.certificates.len() != roster.members.len()
                {
                    return Err(ERROR.into());
                }
            }
        }
        if s.phase as u8 >= CeremonyPhase::AwaitingBackups as u8 {
            let expected = self.backup_body()?;
            for (id, wire) in &s.backups {
                if self
                    .identity
                    .verify_backup(&roster.members[id], &roster.vault, wire)
                    .map_err(|_| ERROR)?
                    .as_slice()
                    != expected
                {
                    return Err(ERROR.into());
                }
            }
            if s.phase as u8 >= CeremonyPhase::Certified as u8
                && s.backups.len() != roster.members.len()
            {
                return Err(ERROR.into());
            }
        }
        if s.phase as u8 >= CeremonyPhase::Round1Saved as u8 {
            let own_wire = s.round1.get(&own).ok_or(ERROR)?;
            let body = self
                .identity
                .verify_round1(&self.identity.public(), &roster.vault, own_wire)
                .map_err(|_| ERROR)?;
            if body.len() <= 32
                || body[..32]
                    != digest(
                        b"Loki_vs_commit1",
                        &[&roster.vault, &own.to_be_bytes(), &*s.contribution],
                    )
            {
                return Err(ERROR.into());
            }
            if s.phase as u8 >= CeremonyPhase::Round2Saved as u8
                && s.round1.len() != roster.members.len()
            {
                return Err(ERROR.into());
            }
            for (id, wire) in &s.round1 {
                if self
                    .identity
                    .verify_round1(&roster.members[id], &roster.vault, wire)
                    .map_err(|_| ERROR)?
                    .len()
                    <= 32
                {
                    return Err(ERROR.into());
                }
            }
        }
        Ok(())
    }
    fn persist_terminal(&mut self) -> Result<(), String> {
        self.anchored = false;
        self.poisoned = true;
        self.live_start = false;
        let mut next = Snapshot::decode(&self.snapshot.encode()?)?;
        next.phase = CeremonyPhase::Aborted;
        next.outgoing.clear();
        next.prepared.clear();
        zeroize::Zeroize::zeroize(&mut *next.dkg);
        zeroize::Zeroize::zeroize(&mut *next.contribution);
        zeroize::Zeroize::zeroize(&mut *next.vs);
        self.journal.append(&next.encode()?)?;
        self.snapshot = next;
        Ok(())
    }
    fn save<F>(&mut self, next: Snapshot, prepare: F) -> Result<CeremonyStep, String>
    where
        F: FnOnce(CeremonyPhase, &BTreeMap<u16, Vec<u8>>) -> Result<Vec<u8>, String>,
    {
        let mut next = next;
        next.prepared = prepare(next.phase, &next.outgoing)?;
        if next.prepared.len() > MAX_PREPARED
            || (self.accepted.transport_required
                && !next.outgoing.is_empty()
                && next.prepared.is_empty())
        {
            return Err(ERROR.into());
        }
        self.anchored = false;
        if self.journal.append(&next.encode()?).is_err() {
            self.poisoned = true;
            return Err(ERROR.into());
        }
        self.snapshot = next;
        Ok(CeremonyStep {
            phase: self.phase(),
            missing_slots: Vec::new(),
            checkpoint: self.checkpoint(),
        })
    }
    pub fn step(&mut self, incoming: &[CeremonyRecord]) -> Result<CeremonyStep, String> {
        self.step_with_preparation(incoming, |_, _| Ok(Vec::new()))
    }
    pub fn step_with_preparation<F>(
        &mut self,
        incoming: &[CeremonyRecord],
        prepare: F,
    ) -> Result<CeremonyStep, String>
    where
        F: FnOnce(CeremonyPhase, &BTreeMap<u16, Vec<u8>>) -> Result<Vec<u8>, String>,
    {
        if !self.anchored || self.poisoned {
            return Err("setup_checkpoint_pending".into());
        }
        let own = self.identity.public().id;
        let roster = self.accepted.roster();
        if matches!(self.phase(), CeremonyPhase::AwaitingRoster) {
            let mut next = Snapshot::ready();
            next.phase = CeremonyPhase::Starting;
            let result = self.save(next, prepare)?;
            self.live_start = true;
            return Ok(result);
        }
        if self.phase() == CeremonyPhase::Starting {
            if !self.live_start {
                return Err("setup_fresh_vault_required".into());
            }
            self.live_start = false;
            // Once entropy may have been used, failure cannot authorize another part1 invocation.
            self.poisoned = true;
            let mut next = Snapshot::ready();
            next.phase = CeremonyPhase::Round1Saved;
            OsRng.fill_bytes(&mut *next.contribution);
            let (member, public) = Member::start_with_policy(own, 2, roster.members.len() as u16)?;
            next.dkg = member.checkpoint()?;
            let mut body = digest(
                b"Loki_vs_commit1",
                &[&roster.vault, &own.to_be_bytes(), &*next.contribution],
            )
            .to_vec();
            body.extend_from_slice(&public);
            let wire = self
                .identity
                .sign_round1(&roster.vault, &body)
                .map_err(|_| ERROR)?;
            next.round1.insert(own, wire.clone());
            for id in roster.members.keys() {
                next.outgoing.insert(*id, wire.clone());
            }
            let result = self.save(next, prepare)?;
            self.poisoned = false;
            return Ok(result);
        }
        let phase = self.phase();
        if !matches!(
            phase,
            CeremonyPhase::Round1Saved
                | CeremonyPhase::Round2Saved
                | CeremonyPhase::CertificateSaved
                | CeremonyPhase::AwaitingBackups
        ) {
            return Ok(CeremonyStep {
                phase,
                missing_slots: Vec::new(),
                checkpoint: self.checkpoint(),
            });
        }
        if phase == CeremonyPhase::AwaitingBackups && !self.snapshot.backups.contains_key(&own) {
            return Ok(CeremonyStep {
                phase,
                missing_slots: vec![own],
                checkpoint: self.checkpoint(),
            });
        }
        let mut records = BTreeMap::new();
        for record in incoming {
            if record.phase != phase
                || !roster.members.contains_key(&record.author)
                || record.bytes.len() > MAX_WIRE
            {
                return Err(ERROR.into());
            }
            if let Some(previous) = records.insert(record.author, record.bytes.as_slice()) {
                if previous != record.bytes {
                    self.persist_terminal()?;
                    return Err("setup_equivocation".into());
                }
            }
        }
        let missing: Vec<_> = roster
            .members
            .keys()
            .filter(|id| **id != own && !records.contains_key(id))
            .copied()
            .collect();
        if !missing.is_empty() {
            return Ok(CeremonyStep {
                phase,
                missing_slots: missing,
                checkpoint: self.checkpoint(),
            });
        }
        if let Some(bytes) = records.get(&own) {
            if self.snapshot.outgoing.get(&own).map(Vec::as_slice) != Some(*bytes) {
                self.persist_terminal()?;
                return Err("setup_equivocation".into());
            }
        }
        let transition = (|| -> Result<Snapshot, String> {
            let mut next = Snapshot::decode(&self.snapshot.encode()?)?;
            next.outgoing.clear();
            next.prepared.clear();
            match phase {
                CeremonyPhase::Round1Saved => {
                    for (id, wire) in &records {
                        if *id != own {
                            next.round1.insert(*id, wire.to_vec());
                        }
                    }
                    let mut round1 = BTreeMap::new();
                    for (id, wire) in &next.round1 {
                        let body = self
                            .identity
                            .verify_round1(&roster.members[id], &roster.vault, wire)
                            .map_err(|_| ERROR)?;
                        if body.len() <= 32 {
                            return Err(ERROR.into());
                        }
                        round1.insert(*id, body[32..].to_vec());
                    }
                    let (member, outgoing) =
                        Member::restore_checkpoint(&next.dkg)?.advance(&round1)?;
                    next.dkg = member.checkpoint()?;
                    let outgoing = PrivateShares(outgoing);
                    for (&id, bytes) in &outgoing.0 {
                        let mut body = Zeroizing::new(next.contribution.to_vec());
                        body.extend_from_slice(&bytes);
                        next.outgoing.insert(
                            id,
                            self.identity
                                .seal_round2(&roster.members[&id], &roster.vault, &body)
                                .map_err(|_| ERROR)?,
                        );
                    }
                    next.outgoing.insert(
                        own,
                        self.identity
                            .sign_round2_self(&roster.vault, &member.transcript)
                            .map_err(|_| ERROR)?,
                    );
                    next.phase = CeremonyPhase::Round2Saved;
                }
                CeremonyPhase::Round2Saved => {
                    let member = Round2Member::restore_checkpoint(&next.dkg)?;
                    let mut incoming = PrivateShares(BTreeMap::new());
                    let mut contributions = BTreeMap::new();
                    contributions.insert(own, Zeroizing::new(*next.contribution));
                    for (&id, wire) in &records {
                        if id == own {
                            continue;
                        }
                        let body = Zeroizing::new(
                            self.identity
                                .open_round2(&roster.members[&id], &roster.vault, wire)
                                .map_err(|_| ERROR)?,
                        );
                        if body.len() <= 32 {
                            return Err(ERROR.into());
                        }
                        let contribution =
                            Zeroizing::new(<[u8; 32]>::try_from(&body[..32]).map_err(|_| ERROR)?);
                        let commitment = digest(
                            b"Loki_vs_commit1",
                            &[&roster.vault, &id.to_be_bytes(), &*contribution],
                        );
                        let r1 = self
                            .identity
                            .verify_round1(&roster.members[&id], &roster.vault, &next.round1[&id])
                            .map_err(|_| ERROR)?;
                        if r1[..32] != commitment {
                            return Err("setup_contribution".into());
                        }
                        contributions.insert(id, contribution);
                        incoming.0.insert(id, body[32..].to_vec());
                        next.round2.insert(id, wire.to_vec());
                    }
                    let completed = member.finish(&incoming.0)?;
                    let mut hash = blake2b_simd::Params::new()
                        .hash_length(32)
                        .personal(b"Loki_vs_v1")
                        .to_state();
                    hash.update(&completed.certificate_digest());
                    for contribution in contributions.values() {
                        hash.update(&**contribution);
                    }
                    next.vs =
                        Zeroizing::new(hash.finalize().as_bytes().try_into().map_err(|_| ERROR)?);
                    next.dkg = completed.checkpoint()?;
                    let mut body = completed.certificate_digest().to_vec();
                    body.extend_from_slice(&digest(b"Loki_vs_cert_v1", &[&*next.vs]));
                    body.extend_from_slice(&roster.fingerprint());
                    body.extend_from_slice(zip2005::VERSION.as_bytes());
                    let wire = self
                        .identity
                        .sign_certificate(&roster.vault, &body)
                        .map_err(|_| ERROR)?;
                    next.certificates.insert(own, wire.clone());
                    for id in roster.members.keys() {
                        next.outgoing.insert(*id, wire.clone());
                    }
                    next.phase = CeremonyPhase::CertificateSaved;
                }
                CeremonyPhase::CertificateSaved => {
                    let expected = self.certificate_body()?;
                    let mut digests = BTreeMap::new();
                    digests.insert(
                        own,
                        Completed::restore_checkpoint(&next.dkg)?.certificate_digest(),
                    );
                    for (&id, wire) in &records {
                        if self
                            .identity
                            .verify_certificate(&roster.members[&id], &roster.vault, wire)
                            .map_err(|_| ERROR)?
                            != expected
                        {
                            return Err("setup_certificate".into());
                        }
                        next.certificates.insert(id, wire.to_vec());
                        digests.insert(id, expected[..32].try_into().map_err(|_| ERROR)?);
                    }
                    let mut certified =
                        Completed::restore_checkpoint(&next.dkg)?.certify(&digests)?;
                    let _secret = Zeroizing::new(std::mem::take(&mut certified.key_package));
                    next.phase = CeremonyPhase::AwaitingBackups;
                }
                CeremonyPhase::AwaitingBackups => {
                    let expected = self.backup_body()?;
                    for (&id, wire) in &records {
                        if self
                            .identity
                            .verify_backup(&roster.members[&id], &roster.vault, wire)
                            .map_err(|_| ERROR)?
                            .as_slice()
                            != expected
                        {
                            return Err("setup_backup".into());
                        }
                        next.backups.insert(id, wire.to_vec());
                    }
                    if next.backups.len() != roster.members.len() {
                        return Err(ERROR.into());
                    }
                    next.phase = CeremonyPhase::Certified;
                }
                _ => return Err(ERROR.into()),
            }
            Ok(next)
        })();
        match transition {
            Ok(next) => self.save(next, prepare),
            Err(error) => {
                self.persist_terminal()?;
                Err(error)
            }
        }
    }
    pub fn certified_address(&self) -> Result<String, String> {
        if !self.anchored
            || self.poisoned
            || (self.phase() as u8) < CeremonyPhase::AwaitingBackups as u8
        {
            return Err("setup_certificates_pending".into());
        }
        let completed = Completed::restore_checkpoint(&self.snapshot.dkg)?;
        let mut digests = BTreeMap::new();
        for id in self.accepted.roster().members.keys() {
            digests.insert(*id, completed.certificate_digest());
        }
        let mut certified = completed.certify(&digests)?;
        let _secret = Zeroizing::new(std::mem::take(&mut certified.key_package));
        let key = zip2005::frost_viewing_key(&certified.group_ak, &self.snapshot.vs)
            .map_err(|_| ERROR)?;
        Ok(vault::unified_address(&key, self.accepted.roster().network.network_type()))
    }
    pub(crate) fn certified_group_key(&self) -> Result<[u8; 32], String> {
        let mut certified = self.certified()?;
        let _secret = Zeroizing::new(std::mem::take(&mut certified.key_package));
        Ok(certified.group_ak)
    }
    fn certified(&self) -> Result<crate::distributed_setup::Certified, String> {
        if !self.anchored
            || self.poisoned
            || (self.phase() as u8) < CeremonyPhase::AwaitingBackups as u8
        {
            return Err("setup_certificates_pending".into());
        }
        let completed = Completed::restore_checkpoint(&self.snapshot.dkg)?;
        let mut digests = BTreeMap::new();
        for id in self.accepted.roster().members.keys() {
            digests.insert(*id, completed.certificate_digest());
        }
        completed.certify(&digests)
    }
    fn backup_body(&self) -> Result<[u8; 32], String> {
        let completed = Completed::restore_checkpoint(&self.snapshot.dkg)?;
        let mut digests = BTreeMap::new();
        for id in self.accepted.roster().members.keys() {
            digests.insert(*id, completed.certificate_digest());
        }
        let mut certified = completed.certify(&digests)?;
        let _secret = Zeroizing::new(std::mem::take(&mut certified.key_package));
        let key = zip2005::frost_viewing_key(&certified.group_ak, &self.snapshot.vs)
            .map_err(|_| ERROR)?;
        let address = vault::unified_address(&key, self.accepted.roster().network.network_type());
        Ok(digest(
            b"Loki_bkup_v2",
            &[
                &self.accepted.roster().vault,
                &self.accepted.roster().fingerprint(),
                &certified.group_ak,
                zip2005::VERSION.as_bytes(),
                &*self.snapshot.vs,
                address.as_bytes(),
            ],
        ))
    }
    pub fn certified_vault_state(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        let mut certified = self.certified()?;
        let secret = Zeroizing::new(std::mem::take(&mut certified.key_package));
        let identity = Zeroizing::new(self.identity.to_secret_bytes());
        let address = self.certified_address()?;
        struct PrivateJson(serde_json::Value);
        impl Drop for PrivateJson {
            fn drop(&mut self) {
                fn wipe(value: &mut serde_json::Value) {
                    match value {
                        serde_json::Value::String(s) => zeroize::Zeroize::zeroize(s),
                        serde_json::Value::Array(a) => a.iter_mut().for_each(wipe),
                        serde_json::Value::Object(o) => o.values_mut().for_each(wipe),
                        _ => {}
                    }
                }
                wipe(&mut self.0);
            }
        }
        let mut value = PrivateJson(
            serde_json::json!({"version":2,"backup_version":2,"network":self.accepted.roster().network.label(),"key_derivation":zip2005::VERSION,"vault":hex::encode(self.accepted.roster().vault),"threshold":2,"members":self.accepted.roster().members.len(),"roster_fingerprint":hex::encode(self.accepted.roster().fingerprint()),"identity_secret":hex::encode(&*identity),"key_package":hex::encode(&*secret),"vault_secret":hex::encode(&*self.snapshot.vs),"public_package":hex::encode(&certified.public_package),"group_ak":hex::encode(certified.group_ak),"address":address}),
        );
        if let Some(height) = self.accepted.roster().birth_height {
            value.0["birth_height"] = serde_json::json!(height);
        }
        Ok(Zeroizing::new(
            serde_json::to_vec(&value.0).map_err(|_| ERROR)?,
        ))
    }
    /// The caller decrypts the member's recovery card and supplies its recovered state for comparison.
    pub fn confirm_local_backup<F>(
        &mut self,
        recovered: &[u8],
        prepare: F,
    ) -> Result<CeremonyStep, String>
    where
        F: FnOnce(CeremonyPhase, &BTreeMap<u16, Vec<u8>>) -> Result<Vec<u8>, String>,
    {
        if self.phase() != CeremonyPhase::AwaitingBackups || !self.anchored || self.poisoned {
            return Err("setup_backups_pending".into());
        }
        if recovered != self.certified_vault_state()?.as_slice() {
            return Err("setup_backup".into());
        }
        let own = self.identity.public().id;
        if self.snapshot.backups.contains_key(&own) {
            return Ok(CeremonyStep {
                phase: self.phase(),
                missing_slots: Vec::new(),
                checkpoint: self.checkpoint(),
            });
        }
        let wire = self
            .identity
            .sign_backup(&self.accepted.roster().vault, &self.backup_body()?)
            .map_err(|_| ERROR)?;
        let mut next = Snapshot::decode(&self.snapshot.encode()?)?;
        next.outgoing.clear();
        next.backups.insert(own, wire.clone());
        for id in self.accepted.roster().members.keys() {
            next.outgoing.insert(*id, wire.clone());
        }
        self.save(next, prepare)
    }
    /// The caller supplies certified encrypted descriptors and captures the complete
    /// delivery intent before the checkpoint can authorize any network publication.
    pub fn begin_payment_handoff<F>(
        &mut self,
        outgoing: &BTreeMap<u16, Vec<u8>>,
        prepare: F,
    ) -> Result<CeremonyStep, String>
    where
        F: FnOnce(CeremonyPhase, &BTreeMap<u16, Vec<u8>>) -> Result<Vec<u8>, String>,
    {
        if !self.anchored || self.poisoned {
            return Err("setup_checkpoint_pending".into());
        }
        if outgoing.keys().copied().collect::<Vec<_>>()
            != self
                .accepted
                .roster()
                .members
                .keys()
                .copied()
                .collect::<Vec<_>>()
            || outgoing
                .values()
                .any(|wire| wire.is_empty() || wire.len() > MAX_WIRE)
        {
            return Err("setup_payment_audience".into());
        }
        if self.phase() == CeremonyPhase::PaymentHandoff {
            if outgoing != &self.snapshot.outgoing {
                return Err("setup_payment_conflict".into());
            }
            return Ok(CeremonyStep {
                phase: self.phase(),
                missing_slots: Vec::new(),
                checkpoint: self.checkpoint(),
            });
        }
        if self.phase() != CeremonyPhase::Certified {
            return Err("setup_backups_pending".into());
        }
        self.backup_receipts()?;
        let mut next = Snapshot::decode(&self.snapshot.encode()?)?;
        next.phase = CeremonyPhase::PaymentHandoff;
        next.outgoing = outgoing.clone();
        self.save(next, |phase, copies| {
            let prepared = prepare(phase, copies)?;
            if prepared.is_empty() {
                return Err("setup_payment_preparation".into());
            }
            Ok(prepared)
        })
    }
    pub(crate) fn begin_activation<F>(
        &mut self,
        outgoing: &BTreeMap<u16, Vec<u8>>,
        prepare: F,
    ) -> Result<CeremonyStep, String>
    where
        F: FnOnce(CeremonyPhase, &BTreeMap<u16, Vec<u8>>) -> Result<Vec<u8>, String>,
    {
        if !self.anchored || self.poisoned {
            return Err("setup_checkpoint_pending".into());
        }
        if outgoing.keys().copied().collect::<Vec<_>>()
            != self
                .accepted
                .roster()
                .members
                .keys()
                .copied()
                .collect::<Vec<_>>()
            || outgoing
                .values()
                .any(|wire| wire.is_empty() || wire.len() > MAX_WIRE)
        {
            return Err("setup_payment_audience".into());
        }
        if self.phase() == CeremonyPhase::Active {
            if outgoing != &self.snapshot.outgoing {
                return Err("setup_payment_conflict".into());
            }
            return Ok(CeremonyStep {
                phase: self.phase(),
                missing_slots: Vec::new(),
                checkpoint: self.checkpoint(),
            });
        }
        if self.phase() != CeremonyPhase::PaymentHandoff {
            return Err("setup_payment_pending".into());
        }
        self.backup_receipts()?;
        let mut next = Snapshot::decode(&self.snapshot.encode()?)?;
        next.phase = CeremonyPhase::Active;
        next.outgoing = outgoing.clone();
        self.save(next, |phase, copies| {
            let bytes = prepare(phase, copies)?;
            if bytes.is_empty() {
                return Err("setup_payment_preparation".into());
            }
            Ok(bytes)
        })
    }
    pub(crate) fn activation_marker(&self) -> Result<[u8; 32], String> {
        self.backup_receipts()?;
        self.backup_body()
    }
    pub fn backup_receipts(&self) -> Result<&BTreeMap<u16, Vec<u8>>, String> {
        if !self.anchored || self.poisoned || (self.phase() as u8) < CeremonyPhase::Certified as u8
        {
            return Err("setup_backups_pending".into());
        }
        Ok(&self.snapshot.backups)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pending_activation_terminal_retirement_preserves_history_and_protects_installed_vaults() {
        for count in [3u16, 4] {
            for kind in [1u16, 3, 4] {
                let mut random = [0u8; 32];
                rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut random);
                let root = std::env::temp_dir()
                    .canonicalize()
                    .unwrap()
                    .join(format!("loki-activation-terminal-{}", hex::encode(random)));
                let member = MemberDir::create(&root, "member").unwrap();
                let secrets = MemberDir::create(member.path(), "secrets").unwrap();
                let lock =
                    super::super::journal::lock_file(&secrets.path().join(".setup.lock")).unwrap();
                let context = [count as u8; 32];
                let mut snapshot = Snapshot::ready();
                snapshot.phase = CeremonyPhase::Active;
                snapshot.contribution.fill(37);
                snapshot.vs.fill(41);
                snapshot.dkg.extend_from_slice(&[43; 32]);
                snapshot.outgoing.insert(1, vec![47; 32]);
                snapshot.prepared = vec![53; 32];
                let journal_root = member.path().join("setup-ceremony");
                let mut journal = Journal::open(&journal_root, "pass", context, 1).unwrap();
                journal.append(&snapshot.encode().unwrap()).unwrap();
                drop(journal);
                let first = std::fs::read(journal_root.join("generation-00000001.sealed")).unwrap();
                for unconfirmed in [None, Some(0), Some(2)] {
                    assert!(SetupCeremony::abort_saved_checkpoint(
                        member.path(),
                        "pass",
                        context,
                        1,
                        &lock,
                        unconfirmed
                    )
                    .is_err());
                    assert!(!journal_root.join("generation-00000002.sealed").exists());
                }
                secrets
                    .write_sealed("activation.sealed", b"installed activation marker", "pass")
                    .unwrap();
                assert!(SetupCeremony::abort_saved_checkpoint(
                    member.path(),
                    "pass",
                    context,
                    1,
                    &lock,
                    Some(kind)
                )
                .is_err());
                assert!(!journal_root.join("generation-00000002.sealed").exists());
                std::fs::remove_file(secrets.path().join("activation.sealed")).unwrap();
                SetupCeremony::abort_saved_checkpoint(
                    member.path(),
                    "pass",
                    context,
                    1,
                    &lock,
                    Some(kind),
                )
                .unwrap();
                assert_eq!(
                    std::fs::read(journal_root.join("generation-00000001.sealed")).unwrap(),
                    first
                );
                assert_eq!(
                    SetupCeremony::saved_phase(member.path(), "pass", context, 1, &lock).unwrap(),
                    Some(CeremonyPhase::Aborted)
                );
                let journal = Journal::open(&journal_root, "pass", context, 1).unwrap();
                let retired = Snapshot::decode(&journal.latest().unwrap().payload).unwrap();
                assert!(
                    retired.dkg.is_empty()
                        && retired.outgoing.is_empty()
                        && retired.prepared.is_empty()
                );
                assert_eq!(*retired.vs, [0; 32]);
                assert_eq!(*retired.contribution, [0; 32]);
                drop(journal);
                SetupCeremony::abort_saved_checkpoint(
                    member.path(),
                    "pass",
                    context,
                    1,
                    &lock,
                    Some(kind),
                )
                .unwrap();
                assert!(!journal_root.join("generation-00000003.sealed").exists());
                drop(lock);
                std::fs::remove_dir_all(root).unwrap();
            }
        }
    }
    #[test]
    fn hosted_worker_shares_only_its_bound_member_lock() {
        for count in [3u16, 4] {
            let identities: Vec<_> = (1..=count).map(Identity::new).collect();
            let document = serde_json::to_vec(&serde_json::json!({
                "vault":hex::encode([71;32]),"threshold":2,
                "members":identities.iter().map(|i|{let p=i.public();serde_json::json!({
                    "id":p.id,"signing":hex::encode(p.signing),"encryption":hex::encode(p.encryption)
                })}).collect::<Vec<_>>()
            })).unwrap();
            let accepted = || AcceptedCeremonyRoster {
                roster: crate::member_state::Roster::from_bytes(&document).unwrap(),
                network: "regtest".into(),
                operator_digest: [73; 32],
                transport_required: false,
            };
            let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "loki-shared-worker-{}",
                hex::encode(identities[0].public().signing)
            ));
            let member = MemberDir::create(&root, "member").unwrap();
            MemberDir::create(member.path(), "secrets")
                .unwrap()
                .write_sealed("identity.sealed", &identities[0].to_secret_bytes(), "pass")
                .unwrap();
            let lock = super::super::journal::lock_file(&member.path().join("secrets/.setup.lock"))
                .unwrap();
            assert!(SetupCeremony::open(member.path(), "pass", accepted()).is_err());
            let foreign = MemberDir::create(&root, "foreign").unwrap();
            MemberDir::create(foreign.path(), "secrets")
                .unwrap()
                .write_sealed("identity.sealed", &identities[0].to_secret_bytes(), "pass")
                .unwrap();
            assert!(SetupCeremony::open_with_member_lock(
                foreign.path(),
                "pass",
                accepted(),
                &lock
            )
            .is_err());
            assert!(!foreign.path().join("setup-ceremony").exists());
            let engine =
                SetupCeremony::open_with_member_lock(member.path(), "pass", accepted(), &lock)
                    .unwrap();
            drop(lock);
            assert!(SetupCeremony::open(member.path(), "pass", accepted()).is_err());
            drop(engine);
            let reopened = SetupCeremony::open(member.path(), "pass", accepted()).unwrap();
            drop(reopened);
            std::fs::remove_dir_all(root).unwrap();
        }
    }
    #[test]
    fn hosted_core_refuses_to_commit_dkg_without_prepared_outer_ciphertext() {
        struct Owned;
        impl CheckpointAuthority for Owned {
            fn reconcile(&mut self, c: &SavedCheckpoint) -> Result<CheckpointState, String> {
                Ok(CheckpointState {
                    generation: c.generation,
                    digest: c.digest,
                    terminal: false,
                })
            }
        }
        for count in [3u16, 4] {
            let identities: Vec<_> = (1..=count).map(Identity::new).collect();
            let document=serde_json::to_vec(&serde_json::json!({"vault":hex::encode([71;32]),"threshold":2,"members":identities.iter().map(|i|{let p=i.public();serde_json::json!({"id":p.id,"signing":hex::encode(p.signing),"encryption":hex::encode(p.encryption)})}).collect::<Vec<_>>()})).unwrap();
            let accepted = AcceptedCeremonyRoster {
                roster: crate::member_state::Roster::from_bytes(&document).unwrap(),
                network: "regtest".into(),
                operator_digest: [73; 32],
                transport_required: true,
            };
            let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "loki-hosted-preparation-{}",
                hex::encode(identities[0].public().signing)
            ));
            let member = MemberDir::create(&root, "member").unwrap();
            MemberDir::create(member.path(), "secrets")
                .unwrap()
                .write_sealed("identity.sealed", &identities[0].to_secret_bytes(), "pass")
                .unwrap();
            let mut engine = SetupCeremony::open(member.path(), "pass", accepted).unwrap();
            let mut owned = Owned;
            engine.synchronize(&mut owned).unwrap();
            engine.step(&[]).unwrap();
            engine.synchronize(&mut owned).unwrap();
            assert!(engine.step(&[]).is_err());
            assert_eq!(engine.phase(), CeremonyPhase::Starting);
            assert!(engine.outgoing().is_err());
            let context = engine.accepted.context_digest();
            assert_eq!(
                AcceptedCeremonyRoster::hosted_context_digest(
                    engine.accepted.roster(),
                    engine.accepted.network(),
                    engine.accepted.operator_digest(),
                )
                .unwrap(),
                context,
            );
            let generation = engine.checkpoint().generation;
            drop(engine);
            let lock = super::super::journal::lock_file(&member.path().join("secrets/.setup.lock"))
                .unwrap();
            assert_eq!(
                SetupCeremony::saved_phase(member.path(), "pass", context, 1, &lock).unwrap(),
                Some(CeremonyPhase::Starting),
            );
            assert!(SetupCeremony::saved_phase(member.path(), "wrong", context, 1, &lock).is_err());
            SetupCeremony::abort_saved_checkpoint(member.path(), "pass", context, 1, &lock, None)
                .unwrap();
            assert_eq!(
                SetupCeremony::saved_phase(member.path(), "pass", context, 1, &lock).unwrap(),
                Some(CeremonyPhase::Aborted),
            );
            let terminal = super::super::journal::Journal::open(
                &member.path().join("setup-ceremony"),
                "pass",
                context,
                1,
            )
            .unwrap();
            let latest = terminal.latest().unwrap();
            assert_eq!(latest.number, generation + 1);
            let saved = Snapshot::decode(&latest.payload).unwrap();
            assert_eq!(saved.phase, CeremonyPhase::Aborted);
            assert!(saved.dkg.is_empty());
            assert!(saved.outgoing.is_empty());
            assert!(saved.prepared.is_empty());
            assert!(*saved.vs == [0; 32]);
            assert!(*saved.contribution == [0; 32]);
            drop(terminal);
            SetupCeremony::abort_saved_checkpoint(member.path(), "pass", context, 1, &lock, None)
                .unwrap();
            let terminal = super::super::journal::Journal::open(
                &member.path().join("setup-ceremony"),
                "pass",
                context,
                1,
            )
            .unwrap();
            assert_eq!(terminal.latest().unwrap().number, generation + 1);
            drop(terminal);
            drop(lock);
            std::fs::remove_dir_all(root).unwrap();
        }
    }
    #[test]
    fn restored_native_secret_package_must_match_saved_authenticated_round1() {
        let identities: Vec<_> = (1..=3).map(Identity::new).collect();
        let document=serde_json::to_vec(&serde_json::json!({"vault":hex::encode([71;32]),"threshold":2,"members":identities.iter().map(|i|{let p=i.public();serde_json::json!({"id":p.id,"signing":hex::encode(p.signing),"encryption":hex::encode(p.encryption)})}).collect::<Vec<_>>()})).unwrap();
        let accepted = AcceptedCeremonyRoster {
            roster: crate::member_state::Roster::from_bytes(&document).unwrap(),
            network: "regtest".into(),
            operator_digest: [73; 32],
            transport_required: false,
        };
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "loki-mixed-snapshot-{}",
            hex::encode(identities[0].public().signing)
        ));
        let member = MemberDir::create(&root, "member").unwrap();
        MemberDir::create(member.path(), "secrets")
            .unwrap()
            .write_sealed("identity.sealed", &identities[0].to_secret_bytes(), "pass")
            .unwrap();
        let mut engine = SetupCeremony::open(member.path(), "pass", accepted).unwrap();
        struct Owned;
        impl CheckpointAuthority for Owned {
            fn reconcile(&mut self, c: &SavedCheckpoint) -> Result<CheckpointState, String> {
                Ok(CheckpointState {
                    generation: c.generation,
                    digest: c.digest,
                    terminal: false,
                })
            }
        }
        let mut authority = Owned;
        engine.synchronize(&mut authority).unwrap();
        engine.step(&[]).unwrap();
        engine.synchronize(&mut authority).unwrap();
        engine.step(&[]).unwrap();
        let (different, _) = Member::start_with_policy(1, 2, 3).unwrap();
        engine.snapshot.dkg = different.checkpoint().unwrap();
        assert!(engine.validate_snapshot().is_err());
        drop(engine);
        std::fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn completed_restart_accepts_sdk_even_y_normalization_for_both_policies() {
        use reddsa_frost::frost::redpallas::{self as frost, keys::EvenY};
        for count in [3u16, 4] {
            let identities: Vec<_> = (1..=count).map(Identity::new).collect();
            let document = serde_json::to_vec(&serde_json::json!({
                "vault": hex::encode([81; 32]), "threshold": 2,
                "members": identities.iter().map(|i| {
                    let p = i.public();
                    serde_json::json!({"id":p.id,"signing":hex::encode(p.signing),"encryption":hex::encode(p.encryption)})
                }).collect::<Vec<_>>()
            })).unwrap();
            let accepted = AcceptedCeremonyRoster {
                roster: crate::member_state::Roster::from_bytes(&document).unwrap(),
                network: "regtest".into(),
                operator_digest: [83; 32],
                transport_required: false,
            };
            let mut chosen = None;
            for _ in 0..128 {
                let mut members = BTreeMap::new();
                let mut round1 = BTreeMap::new();
                for id in 1..=count {
                    let (member, public) = Member::start_with_policy(id, 2, count).unwrap();
                    members.insert(id, member);
                    round1.insert(id, public);
                }
                let decoded: BTreeMap<_, _> = round1
                    .iter()
                    .map(|(&id, bytes)| {
                        (
                            frost::Identifier::try_from(id).unwrap(),
                            frost::keys::dkg::round1::Package::deserialize(bytes).unwrap(),
                        )
                    })
                    .collect();
                let commitments = decoded
                    .iter()
                    .map(|(id, p)| (*id, p.commitment()))
                    .collect();
                let public =
                    frost::keys::PublicKeyPackage::from_dkg_commitments(&commitments).unwrap();
                if !public.has_even_y() {
                    chosen = Some((members, round1));
                    break;
                }
            }
            let (members, round1) =
                chosen.expect("fixture must exercise an odd pre-normalization group key");
            let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
                "loki-even-y-restart-{}",
                hex::encode(identities[0].public().signing)
            ));
            let member = MemberDir::create(&root, "member").unwrap();
            MemberDir::create(member.path(), "secrets")
                .unwrap()
                .write_sealed("identity.sealed", &identities[0].to_secret_bytes(), "pass")
                .unwrap();
            let mut engine = SetupCeremony::open(member.path(), "pass", accepted).unwrap();
            let mut snapshot = Snapshot::ready();
            snapshot.phase = CeremonyPhase::CertificateSaved;
            snapshot.contribution = Zeroizing::new([1; 32]);
            let mut own = None;
            let mut peer_shares = BTreeMap::new();
            for (id, member) in members {
                let contribution = [id as u8; 32];
                let mut body = digest(
                    b"Loki_vs_commit1",
                    &[
                        &engine.accepted.roster().vault,
                        &id.to_be_bytes(),
                        &contribution,
                    ],
                )
                .to_vec();
                body.extend_from_slice(&round1[&id]);
                snapshot.round1.insert(
                    id,
                    identities[id as usize - 1]
                        .sign_round1(&engine.accepted.roster().vault, &body)
                        .unwrap(),
                );
                let (member, shares) = member.advance(&round1).unwrap();
                if id == 1 {
                    own = Some(member);
                } else {
                    peer_shares.insert(id, shares[&1].clone());
                    let mut body = contribution.to_vec();
                    body.extend_from_slice(&shares[&1]);
                    snapshot.round2.insert(
                        id,
                        identities[id as usize - 1]
                            .seal_round2(
                                &identities[0].public(),
                                &engine.accepted.roster().vault,
                                &body,
                            )
                            .unwrap(),
                    );
                }
            }
            let completed = own.unwrap().finish(&peer_shares).unwrap();
            snapshot.dkg = completed.checkpoint().unwrap();
            let mut hash = blake2b_simd::Params::new()
                .hash_length(32)
                .personal(b"Loki_vs_v1")
                .to_state();
            hash.update(&completed.certificate_digest());
            for id in 1..=count {
                hash.update(&[id as u8; 32]);
            }
            snapshot.vs = Zeroizing::new(hash.finalize().as_bytes().try_into().unwrap());
            engine.snapshot = snapshot;
            engine.validate_snapshot().unwrap();
            drop(engine);
            std::fs::remove_dir_all(root).unwrap();
        }
    }
    #[test]
    fn bad_native_signature_is_terminal_across_reopen() {
        let identities: Vec<_> = (1..=3).map(Identity::new).collect();
        let document=serde_json::to_vec(&serde_json::json!({"vault":hex::encode([71;32]),"threshold":2,"members":identities.iter().map(|i|{let p=i.public();serde_json::json!({"id":p.id,"signing":hex::encode(p.signing),"encryption":hex::encode(p.encryption)})}).collect::<Vec<_>>()})).unwrap();
        let accepted = || AcceptedCeremonyRoster {
            roster: crate::member_state::Roster::from_bytes(&document).unwrap(),
            network: "regtest".into(),
            operator_digest: [73; 32],
            transport_required: false,
        };
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "loki-terminal-native-{}",
            hex::encode(identities[0].public().signing)
        ));
        let member = MemberDir::create(&root, "member").unwrap();
        MemberDir::create(member.path(), "secrets")
            .unwrap()
            .write_sealed("identity.sealed", &identities[0].to_secret_bytes(), "pass")
            .unwrap();
        let mut engine = SetupCeremony::open(member.path(), "pass", accepted()).unwrap();
        struct Owned;
        impl CheckpointAuthority for Owned {
            fn reconcile(&mut self, c: &SavedCheckpoint) -> Result<CheckpointState, String> {
                Ok(CheckpointState {
                    generation: c.generation,
                    digest: c.digest,
                    terminal: false,
                })
            }
        }
        let mut authority = Owned;
        engine.synchronize(&mut authority).unwrap();
        engine.step(&[]).unwrap();
        engine.synchronize(&mut authority).unwrap();
        engine.step(&[]).unwrap();
        engine.synchronize(&mut authority).unwrap();
        let incoming: Vec<_> = (2..=3)
            .map(|author| CeremonyRecord {
                phase: CeremonyPhase::Round1Saved,
                author,
                bytes: vec![0; 80],
            })
            .collect();
        assert!(engine.step(&incoming).is_err());
        assert!(engine.outgoing().is_err());
        drop(engine);
        assert!(SetupCeremony::open(member.path(), "pass", accepted()).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
