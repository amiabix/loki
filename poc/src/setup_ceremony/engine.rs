use super::{
    journal::{Journal, MemberLock},
    AcceptedCeremonyRoster,
};
use crate::{
    dkg_core::{encode_map, DkgCore, DkgPhase, DkgState, Reader},
    setup_transport::Identity,
    state::MemberDir,
    zip2005,
};
use std::{collections::BTreeMap, path::Path};
use zeroize::Zeroizing;

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
struct Snapshot {
    phase: CeremonyPhase,
    /// The shared DKG core state: contribution, fresh key (rounds one and two only),
    /// FROST checkpoint, received messages, certificates and `vs`.
    core: DkgState,
    outgoing: BTreeMap<u16, Vec<u8>>,
    backups: BTreeMap<u16, Vec<u8>>,
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
fn field(out: &mut Vec<u8>, value: &[u8]) -> Result<(), String> {
    if value.len() > MAX_PREPARED || out.len().saturating_add(value.len() + 4) > 16 * 1024 * 1024 {
        return Err(ERROR.into());
    }
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}
/// The core phase each engine phase must carry.
fn core_phase(phase: CeremonyPhase) -> DkgPhase {
    match phase {
        CeremonyPhase::AwaitingRoster | CeremonyPhase::Starting | CeremonyPhase::Aborted => {
            DkgPhase::Empty
        }
        CeremonyPhase::Round1Saved => DkgPhase::Round1,
        CeremonyPhase::Round2Saved => DkgPhase::Round2,
        CeremonyPhase::CertificateSaved => DkgPhase::Certificate,
        CeremonyPhase::AwaitingBackups
        | CeremonyPhase::Certified
        | CeremonyPhase::PaymentHandoff
        | CeremonyPhase::Active => DkgPhase::Certified,
    }
}
impl Snapshot {
    fn ready() -> Self {
        Self {
            phase: CeremonyPhase::AwaitingRoster,
            core: DkgState::empty(),
            outgoing: BTreeMap::new(),
            backups: BTreeMap::new(),
            prepared: Vec::new(),
        }
    }
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        let mut out = Zeroizing::new(b"LOKIENG2".to_vec());
        out.push(self.phase as u8);
        field(&mut out, &self.core.encode()?)?;
        encode_map(&mut out, &self.outgoing)?;
        encode_map(&mut out, &self.backups)?;
        field(&mut out, &self.prepared)?;
        Ok(out)
    }
    fn decode(raw: &[u8]) -> Result<Self, String> {
        let mut reader = Reader::new(raw);
        if reader.take(8)? != b"LOKIENG2" {
            return Err(ERROR.into());
        }
        let phase = CeremonyPhase::decode(reader.take(1)?[0])?;
        let core = DkgState::decode(&Zeroizing::new(reader.field(MAX_PREPARED)?.to_vec()))?;
        let outgoing = reader.map()?;
        let backups = reader.map()?;
        let prepared = reader.field(MAX_PREPARED)?.to_vec();
        reader.finish()?;
        if core.phase() != core_phase(phase) {
            return Err(ERROR.into());
        }
        Ok(Self {
            phase,
            core,
            outgoing,
            backups,
            prepared,
        })
    }
    /// A deep copy to build the next generation from.
    fn duplicate(&self) -> Self {
        Self {
            phase: self.phase,
            core: self.core.duplicate(),
            outgoing: self.outgoing.clone(),
            backups: self.backups.clone(),
            prepared: self.prepared.clone(),
        }
    }
    /// The phase of a saved generation. A `LOKIENG1` generation, written before the v2
    /// round two, is only ever read for its phase: it is never turned into a v2 state and
    /// its round-two messages are never reused.
    fn saved_phase(raw: &[u8]) -> Result<(CeremonyPhase, bool), String> {
        if raw.starts_with(b"LOKIENG1") {
            return Ok((CeremonyPhase::decode(*raw.get(8).ok_or(ERROR)?)?, true));
        }
        Ok((Self::decode(raw)?.phase, false))
    }
    /// Terminal state: keep the received history, drop every secret and the fresh key.
    fn retire(&mut self) {
        self.phase = CeremonyPhase::Aborted;
        self.outgoing.clear();
        self.prepared.clear();
        self.core.wipe();
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
        if Snapshot::saved_phase(&journal.latest().ok_or(ERROR)?.payload)?.1 {
            // A setup begun before the v2 round two cannot continue; it is retired with
            // `abort_saved_checkpoint` and a new setup starts.
            return Err("setup_fresh_vault_required".into());
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
    #[cfg(any(feature = "relay-communication", test))]
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
            Snapshot::saved_phase(&journal.latest().ok_or(ERROR)?.payload)?.0,
        ))
    }
    #[cfg(any(feature = "relay-communication", test))]
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
        let payload = journal.latest().ok_or(ERROR)?.payload.clone();
        let (phase, legacy) = Snapshot::saved_phase(&payload)?;
        if phase == CeremonyPhase::Aborted {
            return Ok(());
        }
        // A legacy generation is retired with an empty v2 snapshot; the legacy
        // generations stay in the journal.
        let mut snapshot = if legacy {
            Snapshot::ready()
        } else {
            Snapshot::decode(&payload)?
        };
        if phase == CeremonyPhase::Active {
            if !matches!(confirmed_terminal, Some(1 | 3 | 4)) {
                return Err("setup_already_active".into());
            }
            let marker = member_root.join("secrets/activation.sealed");
            if marker.try_exists().map_err(|_| ERROR)? {
                super::journal::checked_file(&marker)?;
                return Err("setup_already_active".into());
            }
        }
        snapshot.retire();
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
    fn core(&self) -> Result<DkgCore<'_>, String> {
        DkgCore::new(self.accepted.validated(), &self.identity)
    }
    fn validate_snapshot(&self) -> Result<(), String> {
        let s = &self.snapshot;
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
        for values in [&s.outgoing, &s.backups] {
            if values.keys().any(|id| !roster.members.contains_key(id)) {
                return Err(ERROR.into());
            }
        }
        match s.phase {
            CeremonyPhase::AwaitingRoster => {
                if !s.outgoing.is_empty() || !s.backups.is_empty() || !s.prepared.is_empty() {
                    return Err(ERROR.into());
                }
            }
            CeremonyPhase::Starting | CeremonyPhase::Aborted => {
                return Err("setup_fresh_vault_required".into())
            }
            _ => {}
        }
        // Rounds, transcript, envelopes, certificates, even-Y group key and the fresh key's
        // presence (rounds one and two) or absence (from the certificate state on).
        self.core()?.validate(&s.core)?;
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
        } else if !s.backups.is_empty() {
            return Err(ERROR.into());
        }
        Ok(())
    }
    fn persist_terminal(&mut self) -> Result<(), String> {
        self.anchored = false;
        self.poisoned = true;
        self.live_start = false;
        let mut next = self.snapshot.duplicate();
        next.retire();
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
            // The fresh key is created here and saved in the same generation as our signed
            // round one, so both are saved or neither is.
            let (core, outgoing) = self.core()?.start()?;
            next.core = core;
            next.outgoing = outgoing;
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
            let mut next = self.snapshot.duplicate();
            next.outgoing.clear();
            next.prepared.clear();
            match phase {
                CeremonyPhase::Round1Saved
                | CeremonyPhase::Round2Saved
                | CeremonyPhase::CertificateSaved => {
                    let records: BTreeMap<u16, Vec<u8>> = records
                        .iter()
                        .map(|(id, wire)| (*id, wire.to_vec()))
                        .collect();
                    let (core, outgoing) = self.core()?.advance(&self.snapshot.core, &records)?;
                    next.core = core;
                    next.outgoing = outgoing;
                    next.phase = match phase {
                        CeremonyPhase::Round1Saved => CeremonyPhase::Round2Saved,
                        CeremonyPhase::Round2Saved => CeremonyPhase::CertificateSaved,
                        _ => CeremonyPhase::AwaitingBackups,
                    };
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
        self.core()?.address(&self.snapshot.core)
    }
    #[cfg(feature = "relay-communication")]
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
        self.core()?.certified(&self.snapshot.core)
    }
    fn backup_body(&self) -> Result<[u8; 32], String> {
        self.core()?.backup_body(&self.snapshot.core)
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
            serde_json::json!({"version":2,"backup_version":2,"network":self.accepted.roster().network.label(),"key_derivation":zip2005::VERSION,"vault":hex::encode(self.accepted.roster().vault),"threshold":self.accepted.roster().threshold,"members":self.accepted.roster().members.len(),"roster_fingerprint":hex::encode(self.accepted.roster().fingerprint()),"identity_secret":hex::encode(&*identity),"key_package":hex::encode(&*secret),"vault_secret":hex::encode(self.snapshot.core.vault_secret()),"public_package":hex::encode(&certified.public_package),"group_ak":hex::encode(certified.group_ak),"address":address}),
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
        let mut next = self.snapshot.duplicate();
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
        let mut next = self.snapshot.duplicate();
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
    #[cfg(feature = "relay-communication")]
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
        let mut next = self.snapshot.duplicate();
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
    #[cfg(feature = "relay-communication")]
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
                snapshot.core = DkgState::filled_for_tests(DkgPhase::Certified, 37);
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
                    retired.core.is_wiped()
                        && retired.outgoing.is_empty()
                        && retired.prepared.is_empty()
                );
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
                roster: crate::member_state::ValidatedRoster::new(
                    crate::member_state::Roster::from_bytes(&document).unwrap(),
                )
                .unwrap(),
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
    fn engine_accepted(document: &[u8]) -> AcceptedCeremonyRoster {
        AcceptedCeremonyRoster {
            roster: crate::member_state::ValidatedRoster::new(
                crate::member_state::Roster::from_bytes(document).unwrap(),
            )
            .unwrap(),
            network: "regtest".into(),
            operator_digest: [73; 32],
            transport_required: true,
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
                roster: crate::member_state::ValidatedRoster::new(
                    crate::member_state::Roster::from_bytes(&document).unwrap(),
                )
                .unwrap(),
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
            assert!(saved.core.is_wiped());
            assert!(saved.outgoing.is_empty());
            assert!(saved.prepared.is_empty());
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

            // A setup saved before the v2 round two (a `LOKIENG1` generation in round two)
            // does not reopen, reports its saved phase, and is retired with a wiped v2
            // snapshot while its legacy generation stays in the journal.
            let mut legacy = super::super::journal::Journal::open(
                &member.path().join("setup-ceremony"),
                "pass",
                context,
                1,
            )
            .unwrap();
            let mut payload = b"LOKIENG1".to_vec();
            payload.push(CeremonyPhase::Round2Saved as u8);
            payload.extend_from_slice(&[0x5a; 64]);
            let legacy_number = legacy.append(&payload).unwrap().number;
            drop(legacy);
            assert_eq!(
                SetupCeremony::saved_phase(member.path(), "pass", context, 1, &lock).unwrap(),
                Some(CeremonyPhase::Round2Saved),
            );
            assert_eq!(
                SetupCeremony::open_with_member_lock(
                    member.path(),
                    "pass",
                    engine_accepted(&document),
                    &lock
                )
                .err()
                .as_deref(),
                Some("setup_fresh_vault_required"),
            );
            SetupCeremony::abort_saved_checkpoint(member.path(), "pass", context, 1, &lock, None)
                .unwrap();
            let terminal = super::super::journal::Journal::open(
                &member.path().join("setup-ceremony"),
                "pass",
                context,
                1,
            )
            .unwrap();
            let latest = terminal.latest().unwrap();
            assert_eq!(latest.number, legacy_number + 1);
            let saved = Snapshot::decode(&latest.payload).unwrap();
            assert_eq!(saved.phase, CeremonyPhase::Aborted);
            assert!(saved.core.is_wiped());
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
            roster: crate::member_state::ValidatedRoster::new(
                crate::member_state::Roster::from_bytes(&document).unwrap(),
            )
            .unwrap(),
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
        let (different, _) =
            crate::distributed_setup::Member::start_with_policy(1, 2, 3).unwrap();
        engine
            .snapshot
            .core
            .replace_dkg_for_tests(different.checkpoint().unwrap());
        assert!(engine.validate_snapshot().is_err());
        drop(engine);
        std::fs::remove_dir_all(root).unwrap();
    }
    /// Reopen from the certificate state recomputes the group key from the signed
    /// round-one commitments without decrypting anything. Part 3 normalizes the key to
    /// even Y, so the recomputation must too: cover vaults whose key needed the flip and
    /// vaults whose key did not.
    #[test]
    fn certificate_reopen_without_decryption_accepts_both_even_y_parities() {
        use crate::dkg_core::{DkgCore, DkgPhase};
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
            let roster = || {
                crate::member_state::ValidatedRoster::new(
                    crate::member_state::Roster::from_bytes(&document).unwrap(),
                )
                .unwrap()
            };
            let validated = roster();
            let mut seen = [false; 2];
            for _ in 0..256 {
                if seen == [true, true] {
                    break;
                }
                let cores: Vec<_> = identities
                    .iter()
                    .map(|identity| DkgCore::new(&validated, identity).unwrap())
                    .collect();
                let mut states = Vec::new();
                let mut round1 = BTreeMap::new();
                for (i, core) in cores.iter().enumerate() {
                    let (state, out) = core.start().unwrap();
                    round1.insert(i as u16 + 1, out[&1].clone());
                    states.push(state);
                }
                let mut commitments = BTreeMap::new();
                for (id, wire) in &round1 {
                    let body = identities[0]
                        .verify_round1(&identities[*id as usize - 1].public(), &[81; 32], wire)
                        .unwrap();
                    commitments.insert(
                        frost::Identifier::try_from(*id).unwrap(),
                        frost::keys::dkg::round1::Package::deserialize(&body[64..]).unwrap(),
                    );
                }
                let commitments = commitments
                    .iter()
                    .map(|(id, p)| (*id, p.commitment()))
                    .collect();
                let odd = !frost::keys::PublicKeyPackage::from_dkg_commitments(&commitments)
                    .unwrap()
                    .has_even_y();
                if seen[usize::from(odd)] {
                    continue;
                }
                seen[usize::from(odd)] = true;
                let mut round2 = Vec::new();
                for (core, state) in cores.iter().zip(&states) {
                    round2.push(core.advance(state, &round1).unwrap());
                }
                let to_first: BTreeMap<u16, Vec<u8>> = round2
                    .iter()
                    .enumerate()
                    .map(|(i, (_, out))| (i as u16 + 1, out[&1].clone()))
                    .collect();
                let (certificate, _) = cores[0].advance(&round2[0].0, &to_first).unwrap();
                assert_eq!(certificate.phase(), DkgPhase::Certificate);
                assert!(!certificate.has_fresh_key());

                let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
                    "loki-even-y-restart-{}-{odd}",
                    hex::encode(identities[0].public().signing)
                ));
                let member = MemberDir::create(&root, "member").unwrap();
                MemberDir::create(member.path(), "secrets")
                    .unwrap()
                    .write_sealed("identity.sealed", &identities[0].to_secret_bytes(), "pass")
                    .unwrap();
                let accepted = AcceptedCeremonyRoster {
                    roster: roster(),
                    network: "regtest".into(),
                    operator_digest: [83; 32],
                    transport_required: false,
                };
                let mut engine = SetupCeremony::open(member.path(), "pass", accepted).unwrap();
                let mut snapshot = Snapshot::ready();
                snapshot.phase = CeremonyPhase::CertificateSaved;
                snapshot.core = certificate;
                engine.snapshot = snapshot;
                engine.validate_snapshot().unwrap();
                drop(engine);
                std::fs::remove_dir_all(root).unwrap();
            }
            assert_eq!(seen, [true, true], "both group-key parities must be exercised");
        }
    }
    #[test]
    fn bad_native_signature_is_terminal_across_reopen() {
        let identities: Vec<_> = (1..=3).map(Identity::new).collect();
        let document=serde_json::to_vec(&serde_json::json!({"vault":hex::encode([71;32]),"threshold":2,"members":identities.iter().map(|i|{let p=i.public();serde_json::json!({"id":p.id,"signing":hex::encode(p.signing),"encryption":hex::encode(p.encryption)})}).collect::<Vec<_>>()})).unwrap();
        let accepted = || AcceptedCeremonyRoster {
            roster: crate::member_state::ValidatedRoster::new(
                crate::member_state::Roster::from_bytes(&document).unwrap(),
            )
            .unwrap(),
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
