//! Keyless, one-note PCZT signing over a public-message transport.

use std::{collections::BTreeMap, time::{Duration, Instant, SystemTime, UNIX_EPOCH}};

use rand_core::SeedableRng;
use serde::{Deserialize, Serialize};

use reddsa_frost::frost::redpallas as frost;

use crate::{
    signer::{CandidateRef, PublicPaymentParams, Session, Signer},
    transport::{decode_batch, Incoming, Outbound, Peer, Transport},
};

/// Per-lane candidate id: lane 0 is the original ref (byte-identical to single-note), lanes 1..
/// get a distinct `attempt_id`, hence a distinct single-use nonce, from the same signer.
pub(crate) fn lane_cand(cand: &CandidateRef, lane: usize) -> CandidateRef {
    let mut c = *cand;
    c.attempt_id[0] ^= lane as u8;
    c
}

/// Absolute lifetime of a payment exchange, also bounded by the host's chain-expiry check.
pub const SIGNING_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);
pub const DRIVE_YIELDED: &str = "payment signing drive yielded";

/// Private payment transcript, sealed by the host. Nonce secrets remain in NonceStore.
/// Replaying this transcript preserves the original commitment, candidate and randomizers.
#[derive(Default, Serialize, Deserialize)]
pub struct Progress {
    started_ms: Option<u64>,
    commitments: Vec<Vec<u8>>,
    candidate: Option<Vec<u8>>,
    randomizer_seed: Option<[u8; 32]>,
    received: Vec<([u8; 32], Vec<u8>)>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum MessageKind { Commitments, Alphas, Candidate, Packages, Scalars }

fn message_kind(bytes: &[u8]) -> Option<MessageKind> {
    if bytes.starts_with(b"LOKIALP1") { return Some(MessageKind::Alphas); }
    if pczt::Pczt::parse(bytes).is_ok() { return Some(MessageKind::Candidate); }
    let blobs = decode_batch(bytes).ok()?;
    if blobs.is_empty() || crate::transport::encode_batch(&blobs) != bytes { return None; }
    if blobs.iter().all(|b| b.len() == 32) { return Some(MessageKind::Scalars); }
    if blobs.iter().all(|b| frost::round1::SigningCommitments::deserialize(b).is_ok()) { return Some(MessageKind::Commitments); }
    if blobs.iter().all(|b| frost::SigningPackage::deserialize(b).is_ok()) { return Some(MessageKind::Packages); }
    None
}

pub struct SigningRun<'a> {
    progress: Progress,
    save: Box<dyn FnMut(&Progress) -> Result<(), String> + 'a>,
    check_expiry: Box<dyn FnMut() -> Result<(), String> + 'a>,
    deadline: Instant,
    checked: Instant,
    sent: Vec<(Vec<Peer>, Outbound)>,
    redelivered: Instant,
    yield_at: Option<Instant>,
}

impl<'a> SigningRun<'a> {
    pub fn new(
        mut progress: Progress, window: Duration,
        mut save: impl FnMut(&Progress) -> Result<(), String> + 'a,
        check_expiry: impl FnMut() -> Result<(), String> + 'a,
    ) -> Result<Self, String> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).map_err(|e| e.to_string())?;
        let start = *progress.started_ms.get_or_insert(now.as_millis() as u64);
        let remaining = window.min(SIGNING_WINDOW).saturating_sub(now.saturating_sub(Duration::from_millis(start)));
        save(&progress)?;
        let mut run = Self { progress, save: Box::new(save), check_expiry: Box::new(check_expiry),
            deadline: Instant::now() + remaining, checked: Instant::now(),
            sent: Vec::new(), redelivered: Instant::now(), yield_at: None };
        run.check_now()?;
        Ok(run)
    }

    /// Bound one host drive without shortening the persisted signing lifetime.
    pub fn with_drive_limit(mut self, limit: Duration) -> Self {
        self.yield_at = Some(Instant::now() + limit);
        self
    }

    fn checkpoint(&mut self) -> Result<(), String> { (self.save)(&self.progress) }

    fn check_time(&self) -> Result<(), String> {
        if Instant::now() >= self.deadline { return Err("signing window expired".into()); }
        if self.yield_at.is_some_and(|deadline| Instant::now() >= deadline) { return Err(DRIVE_YIELDED.into()); }
        Ok(())
    }

    fn prepare_io<T: Transport>(&self, transport: &T) -> Result<(), String> {
        self.check_time()?;
        if !transport.set_deadline(self.yield_at.map(|deadline| deadline.min(self.deadline))) {
            return Err("transport does not support bounded payment drives".into());
        }
        Ok(())
    }

    fn io_error(&self, operation: &str, error: impl std::fmt::Display) -> String {
        self.check_time().err().unwrap_or_else(|| format!("relay {operation}: {error}"))
    }

    fn check_now(&mut self) -> Result<(), String> {
        self.check_time()?;
        (self.check_expiry)()?;
        self.checked = Instant::now();
        self.check_time()
    }

    fn send<T: Transport>(&mut self, transport: &T, channel: &T::Channel, to: &[Peer], message: Outbound)
        -> Result<(), String> where T::Error: std::fmt::Display
    {
        self.prepare_io(transport)?;
        transport.send(channel, to, &message).map_err(|e| self.io_error("send", e))?;
        self.sent.push((to.to_vec(), message));
        Ok(())
    }

    fn recv<T: Transport>(&mut self, transport: &T, channel: &T::Channel, coordinator: bool, want: usize, kinds: &[MessageKind])
        -> Result<Vec<Incoming>, String> where T::Error: std::fmt::Display
    {
        loop {
            self.check_time()?;
            if Instant::now() >= self.deadline || self.checked.elapsed() >= Duration::from_secs(5) {
                self.check_now()?;
            }
            let messages: Vec<_> = self.progress.received.iter()
                .filter(|(_, message)| message_kind(message).is_some_and(|kind| kinds.contains(&kind)))
                .map(|(from, message)| Incoming { from: Peer(*from), message: message.clone() }).collect();
            if messages.len() > want { return Err("conflicting payment messages".into()); }
            if messages.len() == want { return Ok(messages); }
            // Re-delivery covers a lost response from the relay's destructive receive.
            // Exact duplicates are ignored across phases, never counted toward the quorum.
            if self.redelivered.elapsed() >= Duration::from_secs(5) {
                for (to, message) in &self.sent {
                    self.prepare_io(transport)?;
                    transport.send(channel, to, message).map_err(|e| self.io_error("resend", e))?;
                }
                self.redelivered = Instant::now();
            }
            let mut changed = false;
            self.prepare_io(transport)?;
            for incoming in transport.recv(channel, coordinator).map_err(|e| self.io_error("recv", e))? {
                let record = (incoming.from.0, incoming.message);
                if !self.progress.received.contains(&record) {
                    if self.progress.received.len() >= 1024 { return Err("too many payment messages".into()); }
                    self.progress.received.push(record);
                    changed = true;
                }
            }
            if changed { self.checkpoint()?; }
            let pause = self.yield_at.map_or(Duration::from_millis(25), |deadline|
                deadline.saturating_duration_since(Instant::now()).min(Duration::from_millis(25)));
            std::thread::sleep(pause);
        }
    }
}

/// Commit, optionally build the candidate as proposer, then sign the candidate-bound package.
/// The nonce, key package, viewing key, and selected note stay inside this process.
#[allow(clippy::too_many_arguments)]
pub fn signer_loop<T: Transport, S: Signer>(
    transport: &T,
    channel: &T::Channel,
    signer: &mut S,
    session: &Session,
    candidate_ref: &CandidateRef,
    group_vk: &frost::keys::PublicKeyPackage,
    own_id: frost::Identifier,
    proposer_inputs: Option<&PublicPaymentParams>,
    proposer_peer: &Peer,
    other_signers: &[Peer],
    lanes: usize,
) -> Result<(), String>
where
    T::Error: std::fmt::Display,
    S::Error: std::fmt::Display,
{
    let mut run = SigningRun::new(Progress::default(), SIGNING_WINDOW, |_| Ok(()), || Ok(()))?;
    signer_loop_resumable(transport, channel, signer, session, candidate_ref, group_vk, own_id,
        proposer_inputs, proposer_peer, other_signers, lanes, &mut run)
}

#[allow(clippy::too_many_arguments)]
pub fn signer_loop_resumable<T: Transport, S: Signer>(
    transport: &T,
    channel: &T::Channel,
    signer: &mut S,
    session: &Session,
    candidate_ref: &CandidateRef,
    group_vk: &frost::keys::PublicKeyPackage,
    own_id: frost::Identifier,
    proposer_inputs: Option<&PublicPaymentParams>,
    proposer_peer: &Peer,
    other_signers: &[Peer],
    lanes: usize,
    run: &mut SigningRun<'_>,
) -> Result<(), String>
where
    T::Error: std::fmt::Display,
    S::Error: std::fmt::Display,
{
    if lanes == 0 || lanes > 256 {
        return Err("invalid signing lane count".into());
    }
    run.check_now()?;
    // Persist each public commitment before sending; NonceStore already sealed its nonce.
    for i in run.progress.commitments.len()..lanes {
        run.check_time()?;
        let commitment = signer.sign_commit(session, &lane_cand(candidate_ref, i))
            .map_err(|e| format!("sign_commit lane {i}: {e}"))?;
        run.progress.commitments.push(commitment.serialize().map_err(|e| e.to_string())?);
        run.checkpoint()?;
    }
    let commitments = run.progress.commitments.iter()
        .map(|bytes| frost::round1::SigningCommitments::deserialize(bytes).map_err(|e| e.to_string()))
        .collect::<Result<Vec<_>, _>>()?;
    if commitments.len() != lanes { return Err("saved commitment lane count differs".into()); }
    run.send(transport, channel, &[], Outbound::Commitments(commitments.clone()))?;

    let mut coordinator = None;
    let local_candidate = if let Some(inputs) = proposer_inputs {
        let alpha_message = run.recv(transport, channel, false, 1, &[MessageKind::Alphas])?.remove(0);
        let alphas: Vec<[u8; 32]> = decode_batch(&alpha_message.message[8..])
            .map_err(|e| format!("decode alphas: {e}"))?
            .into_iter()
            .map(|b| b.try_into().map_err(|_| "alpha must be 32 bytes".to_string()))
            .collect::<Result<_, _>>()?;
        coordinator = Some(alpha_message.from);
        if run.progress.candidate.is_none() {
            let candidate = signer.build_candidate(session, candidate_ref, inputs, &alphas)
                .map_err(|e| format!("build_candidate: {e}"))?;
            run.progress.candidate = Some(candidate.as_bytes().to_vec());
            run.checkpoint()?;
        }
        let bytes = run.progress.candidate.clone().ok_or("missing saved candidate")?;
        let candidate = crate::signer::CandidatePczt(bytes.clone());
        run.send(transport, channel, &[], Outbound::Candidate(candidate.clone()))?;
        for peer in other_signers {
            run.send(transport, channel, std::slice::from_ref(peer), Outbound::Candidate(candidate.clone()))?;
        }
        Some(bytes)
    } else {
        None
    };

    let kinds = if local_candidate.is_some() {
        vec![MessageKind::Packages, MessageKind::Scalars]
    } else { vec![MessageKind::Candidate, MessageKind::Packages, MessageKind::Scalars] };
    let got = run.recv(transport, channel, false, kinds.len(), &kinds)?;
    let package_index = got.iter().position(|m| message_kind(&m.message) == Some(MessageKind::Packages)).ok_or("missing signing packages")?;
    let seed_index = got.iter().position(|m| message_kind(&m.message) == Some(MessageKind::Scalars)).ok_or("missing randomizer seeds")?;
    let candidate_bytes = if let Some(bytes) = local_candidate.as_deref() {
        bytes
    } else {
        let candidate_index = got
            .iter()
            .position(|incoming| incoming.from == *proposer_peer && message_kind(&incoming.message) == Some(MessageKind::Candidate))
            .ok_or("candidate came from a non-proposer")?;
        got[candidate_index].message.as_slice()
    };
    if got[package_index].from != got[seed_index].from
        || coordinator.is_some_and(|peer| peer != got[package_index].from)
    {
        return Err("signing messages came from different senders".into());
    }
    let candidate = pczt::Pczt::parse(candidate_bytes).map_err(|e| format!("parse candidate: {e:?}"))?;
    let sighash = pczt::roles::signer::Signer::new(candidate.clone())
        .map_err(|e| format!("candidate signer: {e:?}"))?
        .shielded_sighash();

    let packages = decode_batch(&got[package_index].message).map_err(|e| format!("decode packages: {e}"))?;
    let seeds = decode_batch(&got[seed_index].message).map_err(|e| format!("decode seeds: {e}"))?;
    if packages.len() != lanes || seeds.len() != lanes {
        return Err("relay delivered the wrong number of signing lanes".into());
    }
    // Round 2, per lane: verify this lane's package binds the shared sighash and this member's
    // lane commitment, then sign under that lane's nonce.
    let mut shares = Vec::with_capacity(lanes);
    for i in 0..lanes {
        let package = frost::SigningPackage::deserialize(&packages[i])
            .map_err(|e| format!("decode package lane {i}: {e}"))?;
        let seed: [u8; 32] = seeds[i]
            .as_slice()
            .try_into()
            .map_err(|_| "randomizer seed must be 32 bytes")?;
        if package.message().as_slice() != sighash
            || package.signing_commitments().get(&own_id) != Some(&commitments[i])
        {
            return Err("signing package differs from candidate or own commitment".into());
        }
        let params = frost_rerandomized::RandomizedParams::regenerate_from_seed_and_commitments(
            group_vk.verifying_key(),
            &seed,
            package.signing_commitments(),
        )
        .map_err(|e| format!("regenerate randomizer lane {i}: {e}"))?;
        let rk: [u8; 32] = params
            .randomized_verifying_key()
            .serialize()
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "randomized key is not 32 bytes")?;
        if !candidate.ironwood().actions().iter().any(|action| action.spend().rk() == &rk) {
            return Err(format!("candidate has no spend under lane {i}'s randomized group key"));
        }
        run.check_now()?;
        shares.push(
            signer
                .sign_approve(session, &lane_cand(candidate_ref, i), candidate_bytes, &package, &seed)
                .map_err(|e| format!("sign_approve lane {i}: {e}"))?,
        );
    }
    run.send(transport, channel, &[], Outbound::Share(shares))
}

/// Gather a threshold of commitments, request the proposer candidate, aggregate, and apply.
/// `peer_ids[0]` is the designated proposer. Only public artifacts reach this coordinator.
#[allow(clippy::too_many_arguments)]
pub fn coordinate<T: Transport>(
    transport: &T,
    channel: &T::Channel,
    group_vk: &frost::keys::PublicKeyPackage,
    peer_ids: &[frost::Identifier],
    peer_of: &BTreeMap<frost::Identifier, Peer>,
    threshold: u16,
    lanes: usize,
    rng: impl rand_core::CryptoRngCore,
) -> Result<Vec<u8>, String>
where
    T::Error: std::fmt::Display,
{
    let mut run = SigningRun::new(Progress::default(), SIGNING_WINDOW, |_| Ok(()), || Ok(()))?;
    coordinate_resumable(transport, channel, group_vk, peer_ids, peer_of, threshold, lanes, rng, &mut run)
}

#[allow(clippy::too_many_arguments)]
pub fn coordinate_resumable<T: Transport>(
    transport: &T,
    channel: &T::Channel,
    group_vk: &frost::keys::PublicKeyPackage,
    peer_ids: &[frost::Identifier],
    peer_of: &BTreeMap<frost::Identifier, Peer>,
    threshold: u16,
    lanes: usize,
    mut rng: impl rand_core::CryptoRngCore,
    run: &mut SigningRun<'_>,
) -> Result<Vec<u8>, String>
where
    T::Error: std::fmt::Display,
{
    if lanes == 0 || lanes > 256 {
        return Err("invalid signing lane count".into());
    }
    if threshold == 0
        || peer_ids.len() != usize::from(threshold)
        || group_vk.min_signers() != Some(threshold)
        || peer_ids
            .iter()
            .any(|id| !group_vk.verifying_shares().contains_key(id) || !peer_of.contains_key(id))
    {
        return Err("invalid signing quorum".into());
    }
    let sender_id = |peer: &Peer| {
        peer_ids
            .iter()
            .find(|id| peer_of.get(id) == Some(peer))
            .copied()
    };
    // Round 1: collect one Commitments(Vec of N) per member → N per-lane commitment sets.
    let mut lane_commits: Vec<BTreeMap<frost::Identifier, frost::round1::SigningCommitments>> =
        vec![BTreeMap::new(); lanes];
    for incoming in run.recv(transport, channel, true, peer_ids.len(), &[MessageKind::Commitments])? {
        let id = sender_id(&incoming.from).ok_or("commitment from a non-signer")?;
        let blobs = decode_batch(&incoming.message).map_err(|e| format!("decode commitments: {e}"))?;
        if blobs.len() != lanes {
            return Err("commitment batch has the wrong number of lanes".into());
        }
        for (i, blob) in blobs.iter().enumerate() {
            let c = frost::round1::SigningCommitments::deserialize(blob)
                .map_err(|e| format!("decode commitment lane {i}: {e}"))?;
            if lane_commits[i].insert(id, c).is_some() {
                return Err("duplicate commitment".into());
            }
        }
    }
    // Fix the RNG stream before emitting alphas so a resumed coordinator cannot change them.
    if run.progress.randomizer_seed.is_none() {
        let mut seed = [0u8; 32];
        rng.fill_bytes(&mut seed);
        run.progress.randomizer_seed = Some(seed);
        run.checkpoint()?;
    }
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(run.progress.randomizer_seed.unwrap());
    // One rerandomizer per lane, each bound to that lane's commitments.
    let mut lane_params = Vec::with_capacity(lanes);
    let mut lane_seeds: Vec<[u8; 32]> = Vec::with_capacity(lanes);
    let mut alphas: Vec<[u8; 32]> = Vec::with_capacity(lanes);
    for i in 0..lanes {
        let (params, seed) = frost_rerandomized::RandomizedParams::new_from_commitments(
            group_vk.verifying_key(),
            &lane_commits[i],
            &mut rng,
        )
        .map_err(|e| format!("randomizer lane {i}: {e}"))?;
        alphas.push(
            params
                .randomizer()
                .serialize()
                .try_into()
                .map_err(|_| "alpha is not 32 bytes")?,
        );
        lane_seeds.push(
            seed.as_slice()
                .try_into()
                .map_err(|_| "randomizer seed must be 32 bytes")?,
        );
        lane_params.push(params);
    }
    let proposer = peer_of
        .get(&peer_ids[0])
        .ok_or("proposer has no relay address")?;
    run.send(transport, channel, std::slice::from_ref(proposer), Outbound::Randomizers(alphas))?;
    let candidate_message = run.recv(transport, channel, true, 1, &[MessageKind::Candidate])?.remove(0);
    if candidate_message.from != *proposer {
        return Err("candidate came from a non-proposer".into());
    }
    let candidate = pczt::Pczt::parse(&candidate_message.message)
        .map_err(|e| format!("parse candidate: {e:?}"))?;
    let sighash = pczt::roles::signer::Signer::new(candidate.clone())
        .map_err(|e| format!("candidate signer: {e:?}"))?
        .shielded_sighash();
    // One package per lane over the shared sighash; ship all N (+ their seeds) to each member.
    let packages: Vec<frost::SigningPackage> = (0..lanes)
        .map(|i| frost::SigningPackage::new(lane_commits[i].clone(), &sighash))
        .collect();
    for id in peer_ids {
        let peer = peer_of.get(id).ok_or("signer has no relay address")?;
        run.send(transport, channel, std::slice::from_ref(peer), Outbound::Package(packages.clone()))?;
        run.send(transport, channel, std::slice::from_ref(peer), Outbound::RandomizerSeed(lane_seeds.clone()))?;
    }
    // Collect one Share(Vec of N) per member → N per-lane share sets.
    let mut lane_shares: Vec<BTreeMap<frost::Identifier, frost::round2::SignatureShare>> =
        vec![BTreeMap::new(); lanes];
    for incoming in run.recv(transport, channel, true, peer_ids.len(), &[MessageKind::Scalars])? {
        let id = sender_id(&incoming.from).ok_or("share from a non-signer")?;
        let blobs = decode_batch(&incoming.message).map_err(|e| format!("decode shares: {e}"))?;
        if blobs.len() != lanes {
            return Err("share batch has the wrong number of lanes".into());
        }
        for (i, blob) in blobs.iter().enumerate() {
            let s = frost::round2::SignatureShare::deserialize(blob)
                .map_err(|e| format!("decode share lane {i}: {e}"))?;
            if lane_shares[i].insert(id, s).is_some() {
                return Err("duplicate share".into());
            }
        }
    }
    // Aggregate each lane and apply its signature to the spend under its randomized key.
    let actions_rk: Vec<[u8; 32]> = candidate
        .ironwood()
        .actions()
        .iter()
        .map(|a| *a.spend().rk())
        .collect();
    let mut signer = pczt::roles::signer::Signer::new(candidate)
        .map_err(|e| format!("candidate signer: {e:?}"))?;
    let mut applied: Vec<usize> = Vec::with_capacity(lanes);
    for i in 0..lanes {
        let signature =
            frost_rerandomized::aggregate(&packages[i], &lane_shares[i], group_vk, &lane_params[i])
                .map_err(|e| format!("aggregate lane {i}: {e}"))?;
        lane_params[i]
            .randomized_verifying_key()
            .verify(&sighash, &signature)
            .map_err(|e| format!("verify aggregate lane {i}: {e}"))?;
        let rk: [u8; 32] = lane_params[i]
            .randomized_verifying_key()
            .serialize()
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "randomized key is not 32 bytes")?;
        let index = actions_rk
            .iter()
            .position(|a| a == &rk)
            .ok_or_else(|| format!("no spend under lane {i}'s randomized group key"))?;
        if applied.contains(&index) {
            return Err(format!("two lanes matched the same spend (index {index})"));
        }
        applied.push(index);
        let bytes: [u8; 64] = signature
            .serialize()
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "signature is not 64 bytes")?;
        let orchard_sig = orchard::primitives::redpallas::Signature::<
            orchard::primitives::redpallas::SpendAuth,
        >::from(bytes);
        signer
            .apply_ironwood_signature(index, orchard_sig)
            .map_err(|e| format!("apply signature lane {i}: {e:?}"))?;
    }
    signer
        .finish()
        .serialize()
        .map_err(|e| format!("serialize signed: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct EmptyTransport;
    impl Transport for EmptyTransport {
        type Error = String;
        type Channel = ();
        fn open(&mut self, _: &[Peer], _: u8) -> Result<(), String> { Ok(()) }
        fn join(&mut self, _: uuid::Uuid) -> Result<(), String> { Ok(()) }
        fn send(&self, _: &(), _: &[Peer], _: &Outbound) -> Result<(), String> { Ok(()) }
        fn recv(&self, _: &(), _: bool) -> Result<Vec<Incoming>, String> { Ok(vec![]) }
        fn close(&self, _: ()) -> Result<(), String> { Ok(()) }
    }

    #[test]
    fn waiting_drive_yields_and_resumes_the_same_transcript() {
        let mut saved = Vec::new();
        let mut run = SigningRun::new(Progress::default(), Duration::from_millis(100),
            |p| { saved = serde_json::to_vec(p).unwrap(); Ok(()) }, || Ok(())).unwrap()
            .with_drive_limit(Duration::ZERO);
        assert_eq!(run.recv(&EmptyTransport, &(), true, 2, &[MessageKind::Commitments]).unwrap_err(), DRIVE_YIELDED);
        drop(run);
        let progress: Progress = serde_json::from_slice(&saved).unwrap();
        let started = progress.started_ms;
        let mut resumed = SigningRun::new(progress, SIGNING_WINDOW, |_| Ok(()), || Ok(())).unwrap();
        assert_eq!(resumed.progress.started_ms, started);
        let (shares, _) = frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, &mut rand_core::OsRng).unwrap();
        for (slot, share) in shares.values().take(2).enumerate() {
            let key = frost::keys::KeyPackage::try_from(share.clone()).unwrap();
            let (_, commitment) = frost::round1::commit(key.signing_share(), &mut rand_core::OsRng);
            resumed.progress.received.push(([slot as u8; 32], Outbound::Commitments(vec![commitment]).to_bytes().unwrap()));
        }
        assert_eq!(resumed.recv(&EmptyTransport, &(), true, 2, &[MessageKind::Commitments]).unwrap().len(), 2);
    }

    #[test]
    fn drive_deadline_interrupts_a_stalled_receive() {
        struct StalledTransport(std::cell::Cell<Option<Instant>>);
        impl Transport for StalledTransport {
            type Error = crate::transport::TransportError;
            type Channel = ();
            fn set_deadline(&self, deadline: Option<Instant>) -> bool { self.0.set(deadline); true }
            fn open(&mut self, _: &[Peer], _: u8) -> Result<(), Self::Error> { Ok(()) }
            fn join(&mut self, _: uuid::Uuid) -> Result<(), Self::Error> { Ok(()) }
            fn send(&self, _: &(), _: &[Peer], _: &Outbound) -> Result<(), Self::Error> { Ok(()) }
            fn recv(&self, _: &(), _: bool) -> Result<Vec<Incoming>, Self::Error> {
                // The same wrapper encloses frostd's HTTP request and response body read.
                tokio::runtime::Runtime::new().unwrap().block_on(async {
                    crate::transport::before_deadline(self.0.get(), async {
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        Ok(vec![])
                    }).await
                })
            }
            fn close(&self, _: ()) -> Result<(), Self::Error> { Ok(()) }
        }
        let transport = StalledTransport(std::cell::Cell::new(None));
        let mut run = SigningRun::new(Progress::default(), SIGNING_WINDOW, |_| Ok(()), || Ok(())).unwrap()
            .with_drive_limit(Duration::from_millis(100));
        let started = Instant::now();
        let result = run.recv(&transport, &(), true, 2, &[MessageKind::Commitments]);
        assert_eq!(result.unwrap_err(), DRIVE_YIELDED);
        assert!(started.elapsed() < Duration::from_secs(1), "receive ignored drive deadline");
    }

    #[test]
    fn signing_cap_is_absolute_across_resume() {
        let progress = Progress { started_ms: Some(0), ..Progress::default() };
        assert!(matches!(SigningRun::new(progress, SIGNING_WINDOW, |_| Ok(()), || Ok(())),
            Err(error) if error == "signing window expired"));
    }

    #[test]
    fn chain_expiry_prevents_start_and_round_two() {
        let expired = std::cell::Cell::new(false);
        let check = || if expired.get() { Err("payment expired".into()) } else { Ok(()) };
        let mut run = SigningRun::new(Progress::default(), SIGNING_WINDOW, |_| Ok(()), check).unwrap();
        expired.set(true);
        assert_eq!(run.check_now().unwrap_err(), "payment expired");
        assert!(matches!(SigningRun::new(Progress::default(), SIGNING_WINDOW, |_| Ok(()), check),
            Err(error) if error == "payment expired"));
    }
}
