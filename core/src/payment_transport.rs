//! Keyless, one-note PCZT signing over a public-message transport.

use std::{collections::BTreeMap, time::{Duration, Instant}};

use reddsa_frost::frost::redpallas as frost;

use crate::{
    setup_transport::{Identity, PublicIdentity},
    signer::{CandidateRef, PublicPaymentParams, Session, Signer},
    signing_session::SessionContext,
    transport::{Incoming, Outbound, Peer, SealedCandidate, Transport},
};

#[derive(Clone, Debug)]
pub enum RoundError {
    Other(String),
    ReceiveDeadline { received: usize, expected: usize, shares: bool },
}

impl From<&str> for RoundError {
    fn from(error: &str) -> Self { Self::Other(error.into()) }
}

impl From<String> for RoundError {
    fn from(error: String) -> Self { Self::Other(error) }
}

impl From<RoundError> for String {
    fn from(error: RoundError) -> Self {
        match error {
            RoundError::Other(error) => error,
            RoundError::ReceiveDeadline { received, expected, .. } =>
                format!("relay delivered {received} of {expected} expected messages"),
        }
    }
}

fn recv_until<T: Transport>(
    transport: &T,
    channel: &T::Channel,
    as_coordinator: bool,
    want: usize,
    attempt: &str,
    kind: impl Fn(&Incoming) -> &'static str,
    check_running: &dyn Fn() -> Result<(), String>,
    deadline: Instant,
) -> Result<Vec<Incoming>, RoundError>
where
    T::Error: std::fmt::Display,
{
    let mut got = Vec::new();
    while Instant::now() < deadline {
        check_running()?;
        let batch = transport.recv(channel, as_coordinator).map_err(|e| {
            eprintln!("payment {attempt}: frostd signing receive error");
            format!("relay recv: {e}")
        })?;
        for msg in &batch {
            eprintln!("payment {attempt}: frostd received {}", kind(msg));
        }
        got.extend(batch);
        if got.len() >= want {
            return Ok(got);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    eprintln!("payment {attempt}: frostd signing receive timeout ({}/{want})", got.len());
    Err(RoundError::ReceiveDeadline { received: got.len(), expected: want, shares: false })
}

fn receive_deadline() -> Instant { Instant::now() + Duration::from_secs(120) }

fn send<T: Transport>(
    transport: &T,
    channel: &T::Channel,
    attempt: &str,
    kind: &str,
    peers: &[Peer],
    message: Outbound,
) -> Result<(), String>
where
    T::Error: std::fmt::Display,
{
    match transport.send(channel, peers, &message) {
        Ok(()) => { eprintln!("payment {attempt}: frostd sent {kind}"); Ok(()) }
        Err(e) => {
            eprintln!("payment {attempt}: frostd send {kind} error");
            Err(format!("send {kind}: {e}"))
        }
    }
}

/// Commit, optionally build the candidate as proposer, then sign the candidate-bound package.
/// The nonce, key package, viewing key, and selected note stay inside this process. The
/// candidate crosses the relay only sealed from the proposer to each other selected signer;
/// every signer passes it to `accept_candidate` (review, and for the proposer the local
/// hand-off to its coordinator) before using it.
#[allow(clippy::too_many_arguments)]
pub fn signer_loop<T: Transport, S: Signer>(
    transport: &T,
    channel: &T::Channel,
    signer: &mut S,
    session: &Session,
    candidate_ref: &CandidateRef,
    group_vk: &frost::keys::PublicKeyPackage,
    own_id: frost::Identifier,
    params: &PublicPaymentParams,
    is_proposer: bool,
    own: &Identity,
    context: &SessionContext,
    proposer: &PublicIdentity,
    other_signers: &[PublicIdentity],
    check_running: &dyn Fn() -> Result<(), String>,
    before_share: &dyn Fn() -> Result<(), String>,
    accept_candidate: &mut dyn FnMut(&[u8]) -> Result<(), String>,
) -> Result<(), RoundError>
where
    T::Error: std::fmt::Display,
    S::Error: std::fmt::Display,
{
    let attempt = hex::encode(candidate_ref.attempt_id);
    check_running()?;
    let commitment = signer.sign_commit(session, candidate_ref).map_err(|e| format!("sign_commit: {e}"))?;
    send(transport, channel, &attempt, "commitment", &[], Outbound::Commitments(commitment))?;

    let mut coordinator = None;
    let local_candidate = if is_proposer {
        let alpha_message = recv_until(transport, channel, false, 1, &attempt, |_| "alpha", check_running, receive_deadline())?.remove(0);
        let alpha_bytes: [u8; 32] = alpha_message
            .message
            .try_into()
            .map_err(|_| "alpha must be 32 bytes")?;
        coordinator = Some(alpha_message.from);
        let candidate = signer.build_candidate(session, candidate_ref, params, &alpha_bytes)
            .map_err(|e| format!("build_candidate: {e}"))?;
        accept_candidate(candidate.as_bytes())?;
        for peer in other_signers {
            let sealed = SealedCandidate::seal(own, peer, context, &candidate)?;
            send(transport, channel, &attempt, "candidate", &[Peer(peer.encryption)], Outbound::Candidate(sealed))?;
        }
        Some(candidate.into_bytes())
    } else { None };

    let got = recv_until(transport, channel, false, if local_candidate.is_some() { 2 } else { 3 }, &attempt, |msg| {
        if local_candidate.is_none() && msg.from == Peer(proposer.encryption) {
            "candidate"
        } else if msg.message.len() == 32 {
            "randomizer seed"
        } else {
            "signing package"
        }
    }, check_running, receive_deadline())?;
    let (candidate_bytes, package_index, seed_index) = if let Some(bytes) = local_candidate {
        (bytes, 0, 1)
    } else {
        let candidate_index = got.iter().position(|incoming| incoming.from == Peer(proposer.encryption))
            .ok_or("candidate came from a non-proposer")?;
        let bytes = SealedCandidate::open(own, proposer, context, &got[candidate_index].message)?;
        accept_candidate(&bytes)?;
        let other = (0..got.len()).filter(|index| *index != candidate_index).collect::<Vec<_>>();
        (bytes, other[0], other[1])
    };
    let candidate_bytes = candidate_bytes.as_slice();
    if got[package_index].from != got[seed_index].from
        || coordinator.is_some_and(|peer| peer != got[package_index].from)
    {
        return Err("signing messages came from different senders".into());
    }
    let candidate = pczt::Pczt::parse(candidate_bytes).map_err(|e| format!("parse candidate: {e:?}"))?;
    let sighash = pczt::roles::signer::Signer::new(candidate.clone())
        .map_err(|e| format!("candidate signer: {e:?}"))?
        .shielded_sighash();
    let package = frost::SigningPackage::deserialize(&got[package_index].message)
        .map_err(|e| format!("decode package: {e}"))?;
    let seed: [u8; 32] = got[seed_index]
        .message
        .as_slice()
        .try_into()
        .map_err(|_| "randomizer seed must be 32 bytes")?;
    if package.message().as_slice() != sighash
        || package.signing_commitments().get(&own_id) != Some(&commitment)
    {
        return Err("signing package differs from candidate or own commitment".into());
    }
    let randomized = frost_rerandomized::RandomizedParams::regenerate_from_seed_and_commitments(
        group_vk.verifying_key(), &seed, package.signing_commitments(),
    ).map_err(|e| format!("regenerate randomizer: {e}"))?;
    let rk: [u8; 32] = randomized.randomized_verifying_key().serialize()
        .map_err(|e| e.to_string())?.try_into()
        .map_err(|_| "randomized key is not 32 bytes")?;
    if !candidate.ironwood().actions().iter().any(|action| action.spend().rk() == &rk) {
        return Err("candidate has no spend under the randomized group key".into());
    }
    check_running()?;
    let share = signer.sign_approve(session, candidate_ref, params, candidate_bytes, &package, &seed)
        .map_err(|e| format!("sign_approve: {e}"))?;
    before_share()?;
    Ok(send(transport, channel, &attempt, "share", &[], Outbound::Share(share))?)
}

/// Gather a threshold of commitments, request the proposer candidate, aggregate, and apply.
/// `peer_ids[0]` is the designated proposer. The candidate never comes over the relay:
/// `local_candidate` polls the proposer's local hand-off and returns `None` until it exists.
pub fn coordinate<T: Transport>(
    transport: &T,
    channel: &T::Channel,
    group_vk: &frost::keys::PublicKeyPackage,
    peer_ids: &[frost::Identifier],
    peer_of: &BTreeMap<frost::Identifier, Peer>,
    threshold: u16,
    rng: impl rand_core::CryptoRngCore,
    attempt: &str,
    check_running: &dyn Fn() -> Result<(), String>,
    mut local_candidate: impl FnMut() -> Result<Option<Vec<u8>>, String>,
) -> Result<Vec<u8>, RoundError>
where
    T::Error: std::fmt::Display,
{
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
    let mut commitments = BTreeMap::new();
    for incoming in recv_until(transport, channel, true, peer_ids.len(), attempt, |_| "commitment", check_running, receive_deadline())? {
        let id = sender_id(&incoming.from).ok_or("commitment from a non-signer")?;
        let commitment = frost::round1::SigningCommitments::deserialize(&incoming.message)
            .map_err(|e| format!("decode commitment: {e}"))?;
        if commitments.insert(id, commitment).is_some() {
            return Err("duplicate commitment".into());
        }
    }
    let (params, seed) = frost_rerandomized::RandomizedParams::new_from_commitments(
        group_vk.verifying_key(),
        &commitments,
        rng,
    )
    .map_err(|e| format!("randomizer: {e}"))?;
    let alpha: [u8; 32] = params
        .randomizer()
        .serialize()
        .try_into()
        .map_err(|_| "alpha is not 32 bytes")?;
    let proposer = peer_of
        .get(&peer_ids[0])
        .ok_or("proposer has no relay address")?;
    send(transport, channel, attempt, "alpha", std::slice::from_ref(proposer), Outbound::RandomizerSeed(alpha))?;
    let mut candidate_bytes = None;
    let deadline = Instant::now() + Duration::from_secs(120);
    while Instant::now() < deadline {
        check_running()?;
        candidate_bytes = local_candidate()?;
        if candidate_bytes.is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let candidate_bytes = candidate_bytes.ok_or("the proposer built no candidate")?;
    let candidate = pczt::Pczt::parse(&candidate_bytes)
        .map_err(|e| format!("parse candidate: {e:?}"))?;
    let sighash = pczt::roles::signer::Signer::new(candidate.clone())
        .map_err(|e| format!("candidate signer: {e:?}"))?
        .shielded_sighash();
    let package = frost::SigningPackage::new(commitments, &sighash);
    for id in peer_ids {
        let peer = peer_of.get(id).ok_or("signer has no relay address")?;
        send(transport, channel, attempt, "signing package", std::slice::from_ref(peer), Outbound::Package(package.clone()))?;
        send(transport, channel, attempt, "randomizer seed", std::slice::from_ref(peer), Outbound::RandomizerSeed(seed.as_slice().try_into().map_err(|_| "randomizer seed must be 32 bytes")?))?;
    }
    let mut shares = BTreeMap::new();
    let incoming_shares = recv_until(transport, channel, true, peer_ids.len(), attempt, |_| "share", check_running, receive_deadline())
        .map_err(|error| match error {
            RoundError::ReceiveDeadline { received, expected, .. } => RoundError::ReceiveDeadline { received, expected, shares: true },
            other => other,
        })?;
    for incoming in incoming_shares {
        let id = sender_id(&incoming.from).ok_or("share from a non-signer")?;
        let share = frost::round2::SignatureShare::deserialize(&incoming.message)
            .map_err(|e| format!("decode share: {e}"))?;
        if shares.insert(id, share).is_some() {
            return Err("duplicate share".into());
        }
    }
    let signature = frost_rerandomized::aggregate(&package, &shares, group_vk, &params)
        .map_err(|e| format!("aggregate: {e}"))?;
    params
        .randomized_verifying_key()
        .verify(&sighash, &signature)
        .map_err(|e| format!("verify aggregate: {e}"))?;
    let rk: [u8; 32] = params
        .randomized_verifying_key()
        .serialize()
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "randomized key is not 32 bytes")?;
    let index = candidate
        .ironwood()
        .actions()
        .iter()
        .position(|action| action.spend().rk() == &rk)
        .ok_or("candidate has no spend under the randomized group key")?;
    let bytes: [u8; 64] = signature
        .serialize()
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "signature is not 64 bytes")?;
    let orchard_sig = orchard::primitives::redpallas::Signature::<
        orchard::primitives::redpallas::SpendAuth,
    >::from(bytes);
    let mut signer = pczt::roles::signer::Signer::new(candidate)
        .map_err(|e| format!("candidate signer: {e:?}"))?;
    signer
        .apply_ironwood_signature(index, orchard_sig)
        .map_err(|e| format!("apply signature: {e:?}"))?;
    Ok(signer.finish().serialize().map_err(|e| format!("serialize signed: {e:?}"))?)
}
