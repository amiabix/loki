use std::collections::BTreeMap;
use std::time::Duration;

use reddsa_frost::frost::redpallas as frost;

use crate::transport::{Incoming, Outbound, Peer, Transport};

const POLL_TRIES: usize = 400;
const POLL_WAIT: Duration = Duration::from_millis(25);

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
    for _ in 0..POLL_TRIES {
        got.extend(transport.recv(channel, as_coordinator).map_err(|e| format!("relay recv: {e}"))?);
        if got.len() >= want {
            return Ok(got);
        }
        std::thread::sleep(POLL_WAIT);
    }
    Err(format!("relay delivered {} of {want} expected messages", got.len()))
}

pub fn sign_as_participant<T: Transport>(
    transport: &T,
    channel: &T::Channel,
    key_package: &frost::keys::KeyPackage,
) -> Result<(), String>
where
    T::Error: std::fmt::Display,
{
    let (nonce, commitment) = frost::round1::commit(key_package.signing_share(), &mut rand_core::OsRng);
    transport
        .send(channel, &[], &Outbound::Commitments(commitment))
        .map_err(|e| format!("send commitment: {e}"))?;

    let got = recv_until(transport, channel, false, 2)?;
    let package = frost::SigningPackage::deserialize(&got[0].message).map_err(|e| format!("decode package: {e}"))?;
    let seed: [u8; 32] = got[1].message.clone().try_into().map_err(|_| "randomizer seed must be 32 bytes")?;
    let share = frost_rerandomized::sign_with_randomizer_seed(&package, &nonce, key_package, &seed)
        .map_err(|e| format!("sign: {e}"))?;
    transport
        .send(channel, &[], &Outbound::Share(share))
        .map_err(|e| format!("send share: {e}"))?;
    Ok(())
}

pub fn coordinate<T: Transport>(
    transport: &T,
    channel: &T::Channel,
    signers: &[frost::Identifier],
    peer_of: &BTreeMap<frost::Identifier, Peer>,
    pubkeys: &frost::keys::PublicKeyPackage,
    message: &[u8],
) -> Result<(frost::Signature, frost_rerandomized::RandomizedParams<frost::PallasBlake2b512>), String>
where
    T::Error: std::fmt::Display,
{
    let signer_id = |peer: &Peer| peer_of.iter().find(|(_, p)| *p == peer).map(|(id, _)| *id);

    let mut commitments = BTreeMap::new();
    for incoming in recv_until(transport, channel, true, signers.len())? {
        let id = signer_id(&incoming.from).ok_or("commitment from a non-signer")?;
        let commitment = frost::round1::SigningCommitments::deserialize(&incoming.message)
            .map_err(|e| format!("decode commitment: {e}"))?;
        commitments.insert(id, commitment);
    }

    let package = frost::SigningPackage::new(commitments.clone(), message);
    let (params, seed) = frost_rerandomized::RandomizedParams::new_from_commitments(
        pubkeys.verifying_key(),
        &commitments,
        rand_core::OsRng,
    )
    .map_err(|e| format!("randomizer: {e}"))?;
    for id in signers {
        let peer = peer_of.get(id).ok_or("signer has no relay address")?;
        transport
            .send(channel, std::slice::from_ref(peer), &Outbound::Package(package.clone()))
            .map_err(|e| format!("send package: {e}"))?;
        transport
            .send(channel, std::slice::from_ref(peer), &Outbound::RandomizerSeed(seed.as_slice().try_into().map_err(|_| "randomizer seed must be 32 bytes")?))
            .map_err(|e| format!("send randomizer seed: {e}"))?;
    }

    let mut shares = BTreeMap::new();
    for incoming in recv_until(transport, channel, true, signers.len())? {
        let id = signer_id(&incoming.from).ok_or("share from a non-signer")?;
        let share = frost::round2::SignatureShare::deserialize(&incoming.message)
            .map_err(|e| format!("decode share: {e}"))?;
        shares.insert(id, share);
    }

    let signature = frost_rerandomized::aggregate(&package, &shares, pubkeys, &params)
        .map_err(|e| format!("aggregate: {e}"))?;
    Ok((signature, params))
}
