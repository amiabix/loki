//! Shared DKG core for the hosted setup engine and the new signer (v2 setup format).
//!
//! A pure state machine: no storage, no I/O. It takes a [`ValidatedRoster`] and this
//! member's [`Identity`], consumes the peers' messages for the current phase and returns
//! the next state together with the exact outgoing messages, keyed by recipient. Callers
//! save the returned state before they release any outgoing message, and resend saved
//! bytes on a repeated request instead of calling the core again.
//!
//! Phases and messages:
//! 1. **Round 1.** A random contribution, a [`FreshKey`] and FROST part 1. The body is
//!    `commitment(contribution) || fresh public key || FROST round-one package`, signed
//!    with the identity key (`LOKIR1V1`) and sent to every member.
//! 2. **Round 2.** Every peer's round-one signature is verified against the roster. The
//!    round-one transcript is `Round2Member::transcript` (FROST packages only). For each
//!    peer, `contribution || FROST round-two package` is sealed in a v2 envelope
//!    ([`Identity::seal_round2_v2`]) between the two fresh keys, binding the transcript.
//! 3. **Finish.** Each envelope is verified and opened, its transcript must equal ours,
//!    each contribution must match its round-one commitment, FROST part 3 runs and the
//!    vault secret `vs` is computed. The certificate is signed and sent to every member.
//!    The fresh key is not carried into this state.
//! 4. **Certified.** Every member's certificate must equal ours.
//!
//! Any mismatch is final: the caller aborts and never re-fetches and retries.
//!
//! What the transcript catches: a member that equivocates on its FROST round-one package
//! is caught at round two. Equivocation on the contribution commitment is caught at
//! certificates through the `vs` hash. Equivocation on the fresh public key only makes the
//! setup fail.

use std::collections::BTreeMap;

use reddsa_frost::frost::redpallas::{self as frost, keys::EvenY};
use zcash_protocol::consensus::Parameters;
use zeroize::Zeroizing;

use crate::{
    distributed_setup::{Certified, Completed, Member, Round2Member},
    member_state::{ValidatedRoster, MAX_MEMBERS},
    setup_transport::{FreshKey, Identity, PublicIdentity},
    vault, zip2005,
};

const ERROR: &str = "setup_ceremony";
const STATE_MAGIC: &[u8; 8] = b"LOKIDKS2";
const MAX_WIRE: usize = 66 * 1024;
/// Commitment plus fresh public key, in front of the FROST round-one package.
const ROUND1_PREFIX: usize = 64;

/// Where one member's DKG is. `Empty` is the state before round one and after a wipe.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum DkgPhase {
    Empty = 0,
    Round1 = 1,
    Round2 = 2,
    Certificate = 3,
    Certified = 4,
}

impl DkgPhase {
    fn decode(value: u8) -> Result<Self, String> {
        Ok(match value {
            0 => Self::Empty,
            1 => Self::Round1,
            2 => Self::Round2,
            3 => Self::Certificate,
            4 => Self::Certified,
            _ => return Err(ERROR.into()),
        })
    }
}

/// One member's saved DKG state. Secret fields are zeroized on drop.
pub struct DkgState {
    phase: DkgPhase,
    contribution: Zeroizing<[u8; 32]>,
    fresh: Option<FreshKey>,
    dkg: Zeroizing<Vec<u8>>,
    /// Signed round-one wires, ours included.
    round1: BTreeMap<u16, Vec<u8>>,
    /// The v2 envelopes each peer addressed to us, as received (encrypted).
    round2: BTreeMap<u16, Vec<u8>>,
    /// Signed certificates, ours included.
    certificates: BTreeMap<u16, Vec<u8>>,
    vs: Zeroizing<[u8; 32]>,
}

/// Outgoing messages keyed by recipient member id.
pub type Outgoing = BTreeMap<u16, Vec<u8>>;

pub(crate) fn digest(personal: &[u8], parts: &[&[u8]]) -> [u8; 32] {
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

fn field(out: &mut Vec<u8>, value: &[u8], limit: usize) -> Result<(), String> {
    if value.len() > limit {
        return Err(ERROR.into());
    }
    out.extend_from_slice(&(value.len() as u32).to_be_bytes());
    out.extend_from_slice(value);
    Ok(())
}

/// Encode a member-id map with at most [`MAX_MEMBERS`] entries and ids `1..=MAX_MEMBERS`.
pub fn encode_map(out: &mut Vec<u8>, values: &BTreeMap<u16, Vec<u8>>) -> Result<(), String> {
    if values.len() > usize::from(MAX_MEMBERS) {
        return Err(ERROR.into());
    }
    out.push(values.len() as u8);
    for (id, bytes) in values {
        if !(1..=MAX_MEMBERS).contains(id) {
            return Err(ERROR.into());
        }
        out.extend_from_slice(&id.to_be_bytes());
        field(out, bytes, MAX_WIRE)?;
    }
    Ok(())
}

/// A bounds-checked reader for the state and snapshot encodings.
pub struct Reader<'a> {
    raw: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    pub fn new(raw: &'a [u8]) -> Self {
        Self { raw, offset: 0 }
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(n)
            .filter(|n| *n <= self.raw.len())
            .ok_or(ERROR)?;
        let bytes = &self.raw[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }
    pub fn field(&mut self, limit: usize) -> Result<&'a [u8], String> {
        let size = u32::from_be_bytes(self.take(4)?.try_into().map_err(|_| ERROR)?) as usize;
        if size > limit {
            return Err(ERROR.into());
        }
        self.take(size)
    }
    pub fn map(&mut self) -> Result<BTreeMap<u16, Vec<u8>>, String> {
        let count = self.take(1)?[0];
        if u16::from(count) > MAX_MEMBERS {
            return Err(ERROR.into());
        }
        let mut map = BTreeMap::new();
        let mut previous = 0;
        for _ in 0..count {
            let id = u16::from_be_bytes(self.take(2)?.try_into().map_err(|_| ERROR)?);
            if id <= previous || id > MAX_MEMBERS {
                return Err(ERROR.into());
            }
            previous = id;
            map.insert(id, self.field(MAX_WIRE)?.to_vec());
        }
        Ok(map)
    }
    pub fn finish(&self) -> Result<(), String> {
        if self.offset == self.raw.len() {
            Ok(())
        } else {
            Err(ERROR.into())
        }
    }
}

impl DkgState {
    pub fn empty() -> Self {
        Self {
            phase: DkgPhase::Empty,
            contribution: Zeroizing::new([0; 32]),
            fresh: None,
            dkg: Zeroizing::new(Vec::new()),
            round1: BTreeMap::new(),
            round2: BTreeMap::new(),
            certificates: BTreeMap::new(),
            vs: Zeroizing::new([0; 32]),
        }
    }

    pub fn phase(&self) -> DkgPhase {
        self.phase
    }

    /// Whether this state still holds the fresh setup key.
    pub fn has_fresh_key(&self) -> bool {
        self.fresh.is_some()
    }

    pub fn round1(&self) -> &BTreeMap<u16, Vec<u8>> {
        &self.round1
    }

    pub fn round2(&self) -> &BTreeMap<u16, Vec<u8>> {
        &self.round2
    }

    pub fn certificates(&self) -> &BTreeMap<u16, Vec<u8>> {
        &self.certificates
    }

    /// The FROST `Completed` checkpoint (share and group key), from the certificate phase on.
    pub(crate) fn completed_checkpoint(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        if (self.phase as u8) < DkgPhase::Certificate as u8 {
            return Err(ERROR.into());
        }
        Ok(self.dkg.clone())
    }

    /// The vault viewing secret agreed at finish. Zero before then.
    pub fn vault_secret(&self) -> &[u8; 32] {
        &self.vs
    }

    /// Zeroize every secret and drop the fresh key, keeping the received messages as
    /// history. Used on abort, cancel, timeout and terminal states.
    pub fn wipe(&mut self) {
        self.phase = DkgPhase::Empty;
        zeroize::Zeroize::zeroize(&mut *self.dkg);
        self.dkg.clear();
        zeroize::Zeroize::zeroize(&mut *self.contribution);
        zeroize::Zeroize::zeroize(&mut *self.vs);
        self.fresh = None;
    }

    /// A deep copy, for transitions that must not touch the saved state on failure.
    pub fn duplicate(&self) -> Self {
        Self {
            phase: self.phase,
            contribution: self.contribution.clone(),
            fresh: self
                .fresh
                .as_ref()
                .map(|key| FreshKey::from_secret_bytes(&key.to_secret_bytes())),
            dkg: self.dkg.clone(),
            round1: self.round1.clone(),
            round2: self.round2.clone(),
            certificates: self.certificates.clone(),
            vs: self.vs.clone(),
        }
    }

    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        let mut out = Zeroizing::new(STATE_MAGIC.to_vec());
        out.push(self.phase as u8);
        out.extend_from_slice(&*self.contribution);
        match &self.fresh {
            Some(key) => out.extend_from_slice(&*key.to_secret_bytes()),
            None => out.extend_from_slice(&[0; 32]),
        }
        field(&mut out, &self.dkg, 64 * 1024)?;
        encode_map(&mut out, &self.round1)?;
        encode_map(&mut out, &self.round2)?;
        encode_map(&mut out, &self.certificates)?;
        out.extend_from_slice(&*self.vs);
        Ok(out)
    }

    pub fn decode(raw: &[u8]) -> Result<Self, String> {
        let mut reader = Reader::new(raw);
        if reader.take(8)? != STATE_MAGIC {
            return Err(ERROR.into());
        }
        let phase = DkgPhase::decode(reader.take(1)?[0])?;
        let contribution =
            Zeroizing::new(<[u8; 32]>::try_from(reader.take(32)?).map_err(|_| ERROR)?);
        let fresh_bytes =
            Zeroizing::new(<[u8; 32]>::try_from(reader.take(32)?).map_err(|_| ERROR)?);
        // An all-zero field means the fresh key was removed (or never created).
        let fresh = (*fresh_bytes != [0; 32]).then(|| FreshKey::from_secret_bytes(&fresh_bytes));
        let dkg = Zeroizing::new(reader.field(64 * 1024)?.to_vec());
        let round1 = reader.map()?;
        let round2 = reader.map()?;
        let certificates = reader.map()?;
        let vs = Zeroizing::new(<[u8; 32]>::try_from(reader.take(32)?).map_err(|_| ERROR)?);
        reader.finish()?;
        Ok(Self {
            phase,
            contribution,
            fresh,
            dkg,
            round1,
            round2,
            certificates,
            vs,
        })
    }
}

#[cfg(any(test, feature = "test-support"))]
impl DkgState {
    /// A state filled with recognizable non-zero bytes, for storage-format tests.
    pub fn filled_for_tests(phase: DkgPhase, fill: u8) -> Self {
        let mut state = Self::empty();
        state.phase = phase;
        state.contribution = Zeroizing::new([fill; 32]);
        state.vs = Zeroizing::new([fill.wrapping_add(1); 32]);
        state.dkg = Zeroizing::new(vec![fill.wrapping_add(2); 32]);
        state.fresh = Some(FreshKey::generate());
        state
    }

    /// Whether every secret is gone (zeroized contribution, `vs`, FROST state, fresh key).
    pub fn is_wiped(&self) -> bool {
        self.dkg.is_empty()
            && *self.contribution == [0; 32]
            && *self.vs == [0; 32]
            && self.fresh.is_none()
    }

    pub fn replace_dkg_for_tests(&mut self, dkg: Zeroizing<Vec<u8>>) {
        self.dkg = dkg;
    }
}

/// A verified round-one body.
struct Round1Body {
    commitment: [u8; 32],
    fresh: [u8; 32],
    frost: Vec<u8>,
}

/// The DKG core for one member of one validated roster.
pub struct DkgCore<'a> {
    roster: &'a ValidatedRoster,
    identity: &'a Identity,
}

impl<'a> DkgCore<'a> {
    /// The identity must appear in the roster, keys and all, under its member number.
    pub fn new(roster: &'a ValidatedRoster, identity: &'a Identity) -> Result<Self, String> {
        if roster.members.get(&identity.public().id) != Some(&identity.public()) {
            return Err(ERROR.into());
        }
        Ok(Self { roster, identity })
    }

    fn own(&self) -> u16 {
        self.identity.public().id
    }

    fn vault(&self) -> &[u8; 32] {
        &self.roster.vault
    }

    fn member(&self, id: u16) -> Result<&PublicIdentity, String> {
        self.roster.members.get(&id).ok_or_else(|| ERROR.into())
    }

    fn peers(&self) -> Vec<u16> {
        let own = self.own();
        self.roster
            .members
            .keys()
            .copied()
            .filter(|id| *id != own)
            .collect()
    }

    fn broadcast(&self, wire: &[u8]) -> Outgoing {
        self.roster
            .members
            .keys()
            .map(|id| (*id, wire.to_vec()))
            .collect()
    }

    fn commitment(&self, id: u16, contribution: &[u8; 32]) -> [u8; 32] {
        digest(
            b"Loki_vs_commit1",
            &[self.vault(), &id.to_be_bytes(), contribution],
        )
    }

    fn round1_body(&self, id: u16, wire: &[u8]) -> Result<Round1Body, String> {
        let body = self
            .identity
            .verify_round1(self.member(id)?, self.vault(), wire)
            .map_err(|_| ERROR)?;
        if body.len() <= ROUND1_PREFIX {
            return Err(ERROR.into());
        }
        Ok(Round1Body {
            commitment: body[..32].try_into().map_err(|_| ERROR)?,
            fresh: body[32..64].try_into().map_err(|_| ERROR)?,
            frost: body[ROUND1_PREFIX..].to_vec(),
        })
    }

    fn round1_bodies(&self, state: &DkgState) -> Result<BTreeMap<u16, Round1Body>, String> {
        state
            .round1
            .iter()
            .map(|(id, wire)| Ok((*id, self.round1_body(*id, wire)?)))
            .collect()
    }

    /// Keep exactly one message from every peer; our own entry, if present, must already
    /// have been compared with what we sent.
    fn peer_records<'r>(
        &self,
        records: &'r BTreeMap<u16, Vec<u8>>,
    ) -> Result<BTreeMap<u16, &'r [u8]>, String> {
        let own = self.own();
        let peers: BTreeMap<u16, &[u8]> = records
            .iter()
            .filter(|(id, _)| **id != own)
            .map(|(id, wire)| (*id, wire.as_slice()))
            .collect();
        if peers.keys().copied().collect::<Vec<_>>() != self.peers()
            || peers.values().any(|wire| wire.len() > MAX_WIRE)
        {
            return Err(ERROR.into());
        }
        Ok(peers)
    }

    /// Round one: contribution, fresh key and FROST part 1. Returns the state to save
    /// and the signed round-one wire for every member.
    pub fn start(&self) -> Result<(DkgState, Outgoing), String> {
        let mut state = DkgState::empty();
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut *state.contribution);
        let fresh = FreshKey::generate();
        let (member, public) = Member::start_with_policy(
            self.own(),
            self.roster.threshold,
            self.roster.member_count(),
        )?;
        state.dkg = member.checkpoint()?;
        let mut body = self.commitment(self.own(), &state.contribution).to_vec();
        body.extend_from_slice(&fresh.public());
        body.extend_from_slice(&public);
        let wire = self
            .identity
            .sign_round1(self.vault(), &body)
            .map_err(|_| ERROR)?;
        state.round1.insert(self.own(), wire.clone());
        state.fresh = Some(fresh);
        state.phase = DkgPhase::Round1;
        Ok((state, self.broadcast(&wire)))
    }

    /// Advance by one phase with every peer's message for the current phase.
    pub fn advance(
        &self,
        state: &DkgState,
        records: &BTreeMap<u16, Vec<u8>>,
    ) -> Result<(DkgState, Outgoing), String> {
        let records = self.peer_records(records)?;
        match state.phase {
            DkgPhase::Round1 => self.round2(state, &records),
            DkgPhase::Round2 => self.finish(state, &records),
            DkgPhase::Certificate => Ok((self.certify(state, &records)?, Outgoing::new())),
            DkgPhase::Empty | DkgPhase::Certified => Err(ERROR.into()),
        }
    }

    fn round2(
        &self,
        state: &DkgState,
        records: &BTreeMap<u16, &[u8]>,
    ) -> Result<(DkgState, Outgoing), String> {
        let mut next = state.duplicate();
        for (id, wire) in records {
            next.round1.insert(*id, wire.to_vec());
        }
        let bodies = self.round1_bodies(&next)?;
        let frost_packages = bodies
            .iter()
            .map(|(id, body)| (*id, body.frost.clone()))
            .collect();
        let (member, outgoing) = Member::restore_checkpoint(&next.dkg)?.advance(&frost_packages)?;
        let outgoing = SecretPackages(outgoing);
        let fresh = next.fresh.as_ref().ok_or(ERROR)?;
        let mut wires = Outgoing::new();
        for (&id, package) in &outgoing.0 {
            let mut plaintext = Zeroizing::new(next.contribution.to_vec());
            plaintext.extend_from_slice(package);
            wires.insert(
                id,
                self.identity
                    .seal_round2_v2(
                        fresh,
                        self.member(id)?,
                        &bodies[&id].fresh,
                        self.vault(),
                        &member.transcript,
                        &plaintext,
                    )
                    .map_err(|_| ERROR)?,
            );
        }
        // Our own copy is a signed transcript, so the hosted relay sees one record per
        // member in every phase.
        wires.insert(
            self.own(),
            self.identity
                .sign_round2_self(self.vault(), &member.transcript)
                .map_err(|_| ERROR)?,
        );
        next.dkg = member.checkpoint()?;
        next.phase = DkgPhase::Round2;
        Ok((next, wires))
    }

    fn finish(
        &self,
        state: &DkgState,
        records: &BTreeMap<u16, &[u8]>,
    ) -> Result<(DkgState, Outgoing), String> {
        let member = Round2Member::restore_checkpoint(&state.dkg)?;
        let bodies = self.round1_bodies(state)?;
        let fresh = state.fresh.as_ref().ok_or(ERROR)?;
        let mut incoming = SecretPackages(BTreeMap::new());
        let mut contributions = BTreeMap::new();
        contributions.insert(self.own(), state.contribution.clone());
        for (&id, wire) in records {
            let body = self
                .identity
                .open_round2_v2(
                    fresh,
                    self.member(id)?,
                    &bodies.get(&id).ok_or(ERROR)?.fresh,
                    self.vault(),
                    &member.transcript,
                    wire,
                )
                .map_err(|_| ERROR)?;
            if body.len() <= 32 {
                return Err(ERROR.into());
            }
            let contribution =
                Zeroizing::new(<[u8; 32]>::try_from(&body[..32]).map_err(|_| ERROR)?);
            if self.commitment(id, &contribution) != bodies[&id].commitment {
                return Err("setup_contribution".into());
            }
            contributions.insert(id, contribution);
            incoming.0.insert(id, body[32..].to_vec());
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
        let mut next = DkgState::empty();
        next.phase = DkgPhase::Certificate;
        next.contribution = state.contribution.clone();
        next.vs = Zeroizing::new(hash.finalize().as_bytes().try_into().map_err(|_| ERROR)?);
        next.dkg = completed.checkpoint()?;
        next.round1 = state.round1.clone();
        next.round2 = records.iter().map(|(id, w)| (*id, w.to_vec())).collect();
        // The fresh key is not carried forward: the certificate state never holds it.
        let body = self.certificate_body_for(&completed, &next.vs);
        let wire = self
            .identity
            .sign_certificate(self.vault(), &body)
            .map_err(|_| ERROR)?;
        next.certificates.insert(self.own(), wire.clone());
        Ok((next, self.broadcast(&wire)))
    }

    fn certify(
        &self,
        state: &DkgState,
        records: &BTreeMap<u16, &[u8]>,
    ) -> Result<DkgState, String> {
        let expected = self.certificate_body(state)?;
        let completed = Completed::restore_checkpoint(&state.dkg)?;
        let mut digests = BTreeMap::new();
        digests.insert(self.own(), completed.certificate_digest());
        let mut next = state.duplicate();
        for (&id, wire) in records {
            if self
                .identity
                .verify_certificate(self.member(id)?, self.vault(), wire)
                .map_err(|_| ERROR)?
                != expected
            {
                return Err("setup_certificate".into());
            }
            next.certificates.insert(id, wire.to_vec());
            digests.insert(id, expected[..32].try_into().map_err(|_| ERROR)?);
        }
        let mut certified = completed.certify(&digests)?;
        let _secret = Zeroizing::new(std::mem::take(&mut certified.key_package));
        next.phase = DkgPhase::Certified;
        Ok(next)
    }

    fn certificate_body_for(&self, completed: &Completed, vs: &[u8; 32]) -> Vec<u8> {
        let mut body = completed.certificate_digest().to_vec();
        body.extend_from_slice(&digest(b"Loki_vs_cert_v1", &[vs]));
        body.extend_from_slice(&self.roster.fingerprint());
        body.extend_from_slice(zip2005::VERSION.as_bytes());
        body
    }

    /// The body every member's certificate must carry: certificate digest, `vs` digest,
    /// roster fingerprint and ZIP 2005 version.
    pub fn certificate_body(&self, state: &DkgState) -> Result<Vec<u8>, String> {
        if (state.phase as u8) < DkgPhase::Certificate as u8 {
            return Err(ERROR.into());
        }
        let completed = Completed::restore_checkpoint(&state.dkg)?;
        Ok(self.certificate_body_for(&completed, &state.vs))
    }

    /// The certified share and group key. Available once every certificate matched.
    pub fn certified(&self, state: &DkgState) -> Result<Certified, String> {
        if state.phase != DkgPhase::Certified {
            return Err("setup_certificates_pending".into());
        }
        let completed = Completed::restore_checkpoint(&state.dkg)?;
        let digest = completed.certificate_digest();
        let digests = self.roster.members.keys().map(|id| (*id, digest)).collect();
        completed.certify(&digests)
    }

    /// The vault's unified receive address, derived from the group key and `vs`.
    pub fn address(&self, state: &DkgState) -> Result<String, String> {
        let mut certified = self.certified(state)?;
        let _secret = Zeroizing::new(std::mem::take(&mut certified.key_package));
        let key = zip2005::frost_viewing_key(&certified.group_ak, &state.vs).map_err(|_| ERROR)?;
        Ok(vault::unified_address(
            &key,
            self.roster.network.network_type(),
        ))
    }

    /// The 32-byte body each member signs as its backup receipt (`sign_backup`): vault,
    /// roster fingerprint, group key, ZIP 2005 version, `vs` and the receive address.
    pub fn backup_body(&self, state: &DkgState) -> Result<[u8; 32], String> {
        let mut certified = self.certified(state)?;
        let _secret = Zeroizing::new(std::mem::take(&mut certified.key_package));
        let address = self.address(state)?;
        Ok(digest(
            b"Loki_bkup_v2",
            &[
                self.vault(),
                &self.roster.fingerprint(),
                &certified.group_ak,
                zip2005::VERSION.as_bytes(),
                &*state.vs,
                address.as_bytes(),
            ],
        ))
    }

    /// Reopen checks for a saved state. From the certificate phase on nothing is
    /// decrypted: the fresh key no longer exists there.
    pub fn validate(&self, state: &DkgState) -> Result<(), String> {
        let own = self.own();
        for values in [&state.round1, &state.round2, &state.certificates] {
            if values
                .keys()
                .any(|id| !self.roster.members.contains_key(id))
            {
                return Err(ERROR.into());
            }
        }
        if state.phase == DkgPhase::Empty {
            if !state.dkg.is_empty()
                || !state.round1.is_empty()
                || !state.round2.is_empty()
                || !state.certificates.is_empty()
                || *state.contribution != [0; 32]
                || *state.vs != [0; 32]
                || state.fresh.is_some()
            {
                return Err(ERROR.into());
            }
            return Ok(());
        }
        if state.dkg.len() < 13
            || state.dkg[9..11] != own.to_be_bytes()
            || state.dkg[11..13] != self.roster.member_count().to_be_bytes()
        {
            return Err(ERROR.into());
        }
        let bodies = self.round1_bodies(state)?;
        let own_body = bodies.get(&own).ok_or(ERROR)?;
        if own_body.commitment != self.commitment(own, &state.contribution) {
            return Err(ERROR.into());
        }
        let holds_fresh = matches!(state.phase, DkgPhase::Round1 | DkgPhase::Round2);
        match (&state.fresh, holds_fresh) {
            (Some(key), true) if key.public() == own_body.fresh => {}
            (None, false) => {}
            _ => return Err(ERROR.into()),
        }
        if state.phase != DkgPhase::Round1 && state.round1.len() != self.roster.members.len() {
            return Err(ERROR.into());
        }
        let frost_packages: BTreeMap<u16, Vec<u8>> = bodies
            .iter()
            .map(|(id, body)| (*id, body.frost.clone()))
            .collect();
        match state.phase {
            DkgPhase::Empty => unreachable!(),
            DkgPhase::Round1 => {
                let member = Member::restore_checkpoint(&state.dkg)?;
                if frost_packages.get(&own).map(Vec::as_slice) != Some(member.own_round1())
                    || state.round1.len() != 1
                    || !state.round2.is_empty()
                    || !state.certificates.is_empty()
                    || *state.vs != [0; 32]
                {
                    return Err(ERROR.into());
                }
            }
            DkgPhase::Round2 => {
                let member = Round2Member::restore_checkpoint(&state.dkg)?;
                if member.round1_packages()? != frost_packages
                    || !state.round2.is_empty()
                    || !state.certificates.is_empty()
                    || *state.vs != [0; 32]
                {
                    return Err(ERROR.into());
                }
            }
            DkgPhase::Certificate | DkgPhase::Certified => {
                let completed = Completed::restore_checkpoint(&state.dkg)?;
                let mut commitments = BTreeMap::new();
                for (&id, bytes) in &frost_packages {
                    commitments.insert(
                        frost::Identifier::try_from(id).map_err(|_| ERROR)?,
                        frost::keys::dkg::round1::Package::deserialize(bytes).map_err(|_| ERROR)?,
                    );
                }
                let commitments = commitments
                    .iter()
                    .map(|(id, package)| (*id, package.commitment()))
                    .collect();
                // Even-Y is mandatory: part 3 normalizes the group key, so the recomputed
                // key must be normalized the same way or half of all vaults fail here.
                let public = frost::keys::PublicKeyPackage::from_dkg_commitments(&commitments)
                    .map_err(|_| ERROR)?
                    .into_even_y(None);
                if public.serialize().map_err(|_| ERROR)?.as_slice() != completed.public_package() {
                    return Err(ERROR.into());
                }
                let transcript = round1_transcript(&frost_packages);
                if &transcript != completed.transcript() {
                    return Err(ERROR.into());
                }
                if state.round2.keys().copied().collect::<Vec<_>>() != self.peers() {
                    return Err(ERROR.into());
                }
                for (&id, wire) in &state.round2 {
                    Identity::verify_round2_v2(
                        self.member(id)?,
                        own,
                        self.vault(),
                        &transcript,
                        wire,
                    )
                    .map_err(|_| ERROR)?;
                }
                let body = self.certificate_body_for(&completed, &state.vs);
                if !state.certificates.contains_key(&own) {
                    return Err(ERROR.into());
                }
                for (&id, wire) in &state.certificates {
                    if self
                        .identity
                        .verify_certificate(self.member(id)?, self.vault(), wire)
                        .map_err(|_| ERROR)?
                        != body
                    {
                        return Err(ERROR.into());
                    }
                }
                if state.phase == DkgPhase::Certified
                    && state.certificates.len() != self.roster.members.len()
                {
                    return Err(ERROR.into());
                }
            }
        }
        Ok(())
    }
}

/// `Round2Member::transcript`, recomputed from the authenticated FROST round-one packages.
fn round1_transcript(packages: &BTreeMap<u16, Vec<u8>>) -> [u8; 32] {
    let mut hash = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"Loki_dkg_r1_v1")
        .to_state();
    for (id, package) in packages {
        hash.update(&id.to_be_bytes());
        hash.update(&(package.len() as u32).to_be_bytes());
        hash.update(package);
    }
    hash.finalize()
        .as_bytes()
        .try_into()
        .expect("32 byte digest")
}

/// Plaintext FROST round-two packages, wiped on drop.
struct SecretPackages(BTreeMap<u16, Vec<u8>>);

impl Drop for SecretPackages {
    fn drop(&mut self) {
        for bytes in self.0.values_mut() {
            zeroize::Zeroize::zeroize(bytes);
        }
    }
}
