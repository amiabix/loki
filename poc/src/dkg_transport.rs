//! Run the FROST DKG for one member over a WS3 [`Transport`] (frostd). Productionises the
//! hand-wired flow in `tests/frostd_transport.rs` into a reusable, transport-generic driver:
//! round-1 packages are broadcast to the other members; round-2 packages are sealed to each
//! recipient's encryption key BEFORE they touch the relay (frostd never sees a plaintext
//! share); `part3` yields this member's key package and the shared public package.
//!
//! Blocking per member — it polls the store-and-forward relay between rounds, so the N
//! members run concurrently (one process each, or one thread each in tests). The coordinator
//! opens the session and shares its id out of band (the thin roster layer, ws3 §4); it is not
//! a DKG participant.

use std::collections::BTreeMap;
use std::time::Duration;

use reddsa_frost::frost::redpallas as frost;

use crate::setup_transport::{Identity, PublicIdentity};
use crate::transport::{Incoming, Peer, Transport};

const POLL_TRIES: usize = 400;
const POLL_WAIT: Duration = Duration::from_millis(25);

/// This member's DKG result: its secret key package and the vault's shared public package.
pub type DkgOutput = (frost::keys::KeyPackage, frost::keys::PublicKeyPackage);

/// Drive this member through the three DKG rounds over `channel` (already opened/joined).
///
/// `roster` and `peer_of` are the full membership (including this member), keyed by FROST
/// identifier; `peer_of` maps each identifier to its frostd address. `vault` binds the
/// round-2 seals to this ceremony.
pub fn run_dkg<T: Transport>(
    transport: &T,
    channel: &T::Channel,
    me: &Identity,
    my_id: frost::Identifier,
    roster: &BTreeMap<frost::Identifier, PublicIdentity>,
    peer_of: &BTreeMap<frost::Identifier, Peer>,
    vault: &[u8; 32],
    threshold: u16,
) -> Result<DkgOutput, String>
where
    T::Error: std::fmt::Display,
{
    let members = roster.len() as u16;
    let sender_id = |peer: &Peer| peer_of.iter().find(|(_, p)| *p == peer).map(|(id, _)| *id);
    let others: Vec<Peer> = peer_of
        .iter()
        .filter(|(id, _)| **id != my_id)
        .map(|(_, peer)| peer.clone())
        .collect();

    // Round 1 — broadcast our public package to the other members.
    let (r1_secret, r1_package) = frost::keys::dkg::part1(my_id, members, threshold, rand_core::OsRng)
        .map_err(|e| format!("dkg part1: {e}"))?;
    let r1_bytes = r1_package.serialize().map_err(|e| format!("serialize round1: {e}"))?;
    transport.send(channel, &others, &r1_bytes).map_err(|e| format!("send round1: {e}"))?;

    // Collect the others' round-1 packages. A fast peer's sealed round-2 can arrive before we
    // finish here (timing skew over a store-and-forward relay); set those aside instead of
    // mis-parsing them as round 1.
    let need = (members - 1) as usize;
    let mut r1_received = BTreeMap::new();
    let mut r2_buffer: Vec<Incoming> = Vec::new();
    let mut tries = 0usize;
    while r1_received.len() < need {
        for incoming in transport.recv(channel, false).map_err(|e| format!("relay recv: {e}"))? {
            if crate::setup_transport::is_sealed_round2(&incoming.message) {
                r2_buffer.push(incoming);
                continue;
            }
            let from = sender_id(&incoming.from).ok_or("round1 from a non-member")?;
            let package = frost::keys::dkg::round1::Package::deserialize(&incoming.message)
                .map_err(|e| format!("decode round1: {e}"))?;
            r1_received.insert(from, package);
        }
        if r1_received.len() < need {
            tries += 1;
            if tries > POLL_TRIES {
                return Err(format!("relay delivered {} of {need} round-1 packages", r1_received.len()));
            }
            std::thread::sleep(POLL_WAIT);
        }
    }

    // Round 2 — seal each per-recipient package to that recipient before it crosses the relay.
    let (r2_secret, r2_packages) = frost::keys::dkg::part2(r1_secret, &r1_received)
        .map_err(|e| format!("dkg part2: {e}"))?;
    for (recipient, package) in &r2_packages {
        let recipient_public = roster.get(recipient).ok_or("round2 recipient not in roster")?;
        let recipient_peer = peer_of.get(recipient).ok_or("round2 recipient has no relay address")?;
        let plaintext = package.serialize().map_err(|e| format!("serialize round2: {e}"))?;
        let sealed = me.seal_round2(recipient_public, vault, &plaintext)?;
        transport
            .send(channel, std::slice::from_ref(recipient_peer), &sealed)
            .map_err(|e| format!("send round2: {e}"))?;
    }

    // Collect round-2 packages, starting with any buffered during round-1 collection.
    let mut r2_received = BTreeMap::new();
    let mut tries = 0usize;
    loop {
        for incoming in r2_buffer.drain(..) {
            let from = sender_id(&incoming.from).ok_or("round2 from a non-member")?;
            let from_public = roster.get(&from).ok_or("round2 sender not in roster")?;
            let plaintext = me.open_round2(from_public, vault, &incoming.message)?;
            let package = frost::keys::dkg::round2::Package::deserialize(&plaintext)
                .map_err(|e| format!("decode round2: {e}"))?;
            r2_received.insert(from, package);
        }
        if r2_received.len() >= need {
            break;
        }
        tries += 1;
        if tries > POLL_TRIES {
            return Err(format!("relay delivered {} of {need} round-2 packages", r2_received.len()));
        }
        std::thread::sleep(POLL_WAIT);
        r2_buffer = transport.recv(channel, false).map_err(|e| format!("relay recv: {e}"))?;
    }

    frost::keys::dkg::part3(&r2_secret, &r1_received, &r2_received).map_err(|e| format!("dkg part3: {e}"))
}
