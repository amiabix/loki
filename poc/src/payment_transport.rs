//! Keyless, one-note PCZT signing over a public-message transport.

use std::{collections::BTreeMap, time::Duration};

use reddsa_frost::frost::redpallas as frost;

use crate::{
    signer::{CandidateRef, PublicPaymentParams, Session, Signer},
    transport::{Incoming, Outbound, Peer, Transport},
};

fn recv_until<T: Transport>(
    transport: &T,
    channel: &T::Channel,
    as_coordinator: bool,
    want: usize,
) -> Result<Vec<Incoming>, String>
where
    T::Error: std::fmt::Display,
{
    let mut got = Vec::new();
    for _ in 0..400 {
        got.extend(
            transport
                .recv(channel, as_coordinator)
                .map_err(|e| format!("relay recv: {e}"))?,
        );
        if got.len() >= want {
            return Ok(got);
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    Err(format!(
        "relay delivered {} of {want} expected messages",
        got.len()
    ))
}

/// Commit, optionally build the candidate as proposer, then sign the candidate-bound package.
/// The nonce, key package, viewing key, and selected note stay inside this process.
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
) -> Result<(), String>
where
    T::Error: std::fmt::Display,
    S::Error: std::fmt::Display,
{
    let commitment = signer.sign_commit(session, candidate_ref).map_err(|e| format!("sign_commit: {e}"))?;
    transport
        .send(channel, &[], &Outbound::Commitments(commitment))
        .map_err(|e| format!("send commitment: {e}"))?;

    let mut coordinator = None;
    let local_candidate = if let Some(inputs) = proposer_inputs {
        let alpha_message = recv_until(transport, channel, false, 1)?.remove(0);
        let alpha_bytes: [u8; 32] = alpha_message
            .message
            .try_into()
            .map_err(|_| "alpha must be 32 bytes")?;
        coordinator = Some(alpha_message.from);
        let candidate = signer.build_candidate(session, candidate_ref, inputs, &alpha_bytes)
            .map_err(|e| format!("build_candidate: {e}"))?;
        let bytes = candidate.as_bytes().to_vec();
        transport
            .send(channel, &[], &Outbound::Candidate(candidate.clone()))
            .map_err(|e| format!("send candidate: {e}"))?;
        for peer in other_signers {
            transport.send(channel, std::slice::from_ref(peer), &Outbound::Candidate(candidate.clone()))
                .map_err(|e| format!("send candidate: {e}"))?;
        }
        Some(bytes)
    } else { None };

    let got = recv_until(transport, channel, false, if local_candidate.is_some() { 2 } else { 3 })?;
    let (candidate_bytes, package_index, seed_index) = if let Some(bytes) = local_candidate.as_deref() {
        (bytes, 0, 1)
    } else {
        let candidate_index = got.iter().position(|incoming| incoming.from == *proposer_peer)
            .ok_or("candidate came from a non-proposer")?;
        let other = (0..got.len()).filter(|index| *index != candidate_index).collect::<Vec<_>>();
        (got[candidate_index].message.as_slice(), other[0], other[1])
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
    let params = frost_rerandomized::RandomizedParams::regenerate_from_seed_and_commitments(
        group_vk.verifying_key(), &seed, package.signing_commitments(),
    ).map_err(|e| format!("regenerate randomizer: {e}"))?;
    let rk: [u8; 32] = params.randomized_verifying_key().serialize()
        .map_err(|e| e.to_string())?.try_into()
        .map_err(|_| "randomized key is not 32 bytes")?;
    if !candidate.ironwood().actions().iter().any(|action| action.spend().rk() == &rk) {
        return Err("candidate has no spend under the randomized group key".into());
    }
    let share = signer.sign_approve(session, candidate_ref, candidate_bytes, &package, &seed)
        .map_err(|e| format!("sign_approve: {e}"))?;
    transport
        .send(channel, &[], &Outbound::Share(share))
        .map_err(|e| format!("send share: {e}"))
}

/// Gather a threshold of commitments, request the proposer candidate, aggregate, and apply.
/// `peer_ids[0]` is the designated proposer. Only public artifacts reach this coordinator.
pub fn coordinate<T: Transport>(
    transport: &T,
    channel: &T::Channel,
    group_vk: &frost::keys::PublicKeyPackage,
    peer_ids: &[frost::Identifier],
    peer_of: &BTreeMap<frost::Identifier, Peer>,
    threshold: u16,
    rng: impl rand_core::CryptoRngCore,
) -> Result<Vec<u8>, String>
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
    for incoming in recv_until(transport, channel, true, peer_ids.len())? {
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
    transport
        .send(channel, std::slice::from_ref(proposer), &Outbound::RandomizerSeed(alpha))
        .map_err(|e| format!("send alpha: {e}"))?;
    let candidate_message = recv_until(transport, channel, true, 1)?.remove(0);
    if candidate_message.from != *proposer {
        return Err("candidate came from a non-proposer".into());
    }
    let candidate = pczt::Pczt::parse(&candidate_message.message)
        .map_err(|e| format!("parse candidate: {e:?}"))?;
    let sighash = pczt::roles::signer::Signer::new(candidate.clone())
        .map_err(|e| format!("candidate signer: {e:?}"))?
        .shielded_sighash();
    let package = frost::SigningPackage::new(commitments, &sighash);
    for id in peer_ids {
        let peer = peer_of.get(id).ok_or("signer has no relay address")?;
        transport.send(channel, std::slice::from_ref(peer), &Outbound::Package(package.clone()))
            .map_err(|e| format!("send signing package: {e}"))?;
        transport.send(channel, std::slice::from_ref(peer), &Outbound::RandomizerSeed(seed.as_slice().try_into().map_err(|_| "randomizer seed must be 32 bytes")?))
            .map_err(|e| format!("send randomizer seed: {e}"))?;
    }
    let mut shares = BTreeMap::new();
    for incoming in recv_until(transport, channel, true, peer_ids.len())? {
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
    signer
        .finish()
        .serialize()
        .map_err(|e| format!("serialize signed: {e:?}"))
}
