//! Combine every DKG member's sealed contribution into one vault viewing secret.

use std::{collections::BTreeMap, time::Duration};

use blake2b_simd::Params;
use rand_core::{OsRng, RngCore};
use reddsa_frost::frost::redpallas as frost;
use zeroize::Zeroizing;

use crate::{
    setup_transport::{is_sealed_round2, Identity, PublicIdentity},
    transport::{Incoming, Peer, Transport},
};

const POLL_TRIES: usize = 400;
const POLL_WAIT: Duration = Duration::from_millis(25);

fn commitment(vault: &[u8; 32], id: u16, contribution: &[u8; 32]) -> [u8; 32] {
    Params::new()
        .hash_length(32)
        .personal(b"Loki_frostvs_c1")
        .to_state()
        .update(vault)
        .update(&id.to_be_bytes())
        .update(contribution)
        .finalize()
        .as_bytes()
        .try_into()
        .unwrap()
}

/// Exchange commitments and sealed reveals on the DKG channel, then derive the shared secret.
pub fn contribute<T: Transport>(
    transport: &T,
    channel: &T::Channel,
    me: &Identity,
    my_id: frost::Identifier,
    roster: &BTreeMap<frost::Identifier, PublicIdentity>,
    peer_of: &BTreeMap<frost::Identifier, Peer>,
    vault: &[u8; 32],
    group_ak: &[u8; 32],
) -> Result<[u8; 32], String>
where
    T::Error: std::fmt::Display,
{
    if roster.get(&my_id) != Some(&me.public())
        || peer_of.len() != roster.len()
        || peer_of.iter().any(|(id, peer)| {
            roster.get(id).map(|public| Peer(public.encryption)) != Some(peer.clone())
        })
    {
        return Err("vault secret roster mismatch".into());
    }
    let sender_id = |peer: &Peer| peer_of.iter().find(|(_, p)| *p == peer).map(|(id, _)| *id);
    let others: Vec<Peer> = peer_of
        .iter()
        .filter(|(id, _)| **id != my_id)
        .map(|(_, peer)| peer.clone())
        .collect();
    let need = roster.len();
    let mut own = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *own);
    let my_commitment = commitment(vault, me.public().id, &own);
    transport
        .send(channel, &others, &my_commitment)
        .map_err(|e| format!("send vault secret commitment: {e}"))?;

    let mut commitments = BTreeMap::from([(my_id, my_commitment)]);
    let mut reveals: Vec<Incoming> = Vec::new();
    let mut tries = 0;
    while commitments.len() < need {
        for incoming in transport
            .recv(channel, false)
            .map_err(|e| format!("relay recv: {e}"))?
        {
            if is_sealed_round2(&incoming.message) {
                reveals.push(incoming);
                continue;
            }
            let from = sender_id(&incoming.from).ok_or("commitment from a non-member")?;
            let bytes: [u8; 32] = incoming
                .message
                .try_into()
                .map_err(|_| "invalid vault secret commitment length")?;
            if from == my_id || commitments.insert(from, bytes).is_some() {
                return Err("duplicate vault secret commitment".into());
            }
        }
        if commitments.len() < need {
            tries += 1;
            if tries > POLL_TRIES {
                return Err(format!(
                    "relay delivered {} of {need} vault secret commitments",
                    commitments.len()
                ));
            }
            std::thread::sleep(POLL_WAIT);
        }
    }

    for (id, peer) in peer_of.iter().filter(|(id, _)| **id != my_id) {
        let public = roster.get(id).ok_or("reveal recipient not in roster")?;
        let sealed = me.seal_round2(public, vault, &own[..])?;
        transport
            .send(channel, std::slice::from_ref(peer), &sealed)
            .map_err(|e| format!("send vault secret reveal: {e}"))?;
    }

    let mut contributions = BTreeMap::from([(my_id, *own)]);
    let mut tries = 0;
    loop {
        for incoming in reveals.drain(..) {
            if !is_sealed_round2(&incoming.message) {
                return Err("invalid vault secret reveal envelope".into());
            }
            let from = sender_id(&incoming.from).ok_or("reveal from a non-member")?;
            let public = roster.get(&from).ok_or("reveal sender not in roster")?;
            let plaintext = Zeroizing::new(me.open_round2(public, vault, &incoming.message)?);
            let value: [u8; 32] = plaintext
                .as_slice()
                .try_into()
                .map_err(|_| "invalid vault secret reveal length")?;
            if commitment(vault, public.id, &value) != commitments[&from] {
                return Err("vault secret contribution changed".into());
            }
            if contributions.insert(from, value).is_some() {
                return Err("duplicate vault secret reveal".into());
            }
        }
        if contributions.len() == need {
            break;
        }
        tries += 1;
        if tries > POLL_TRIES {
            return Err(format!(
                "relay delivered {} of {need} vault secret reveals",
                contributions.len()
            ));
        }
        std::thread::sleep(POLL_WAIT);
        reveals = transport
            .recv(channel, false)
            .map_err(|e| format!("relay recv: {e}"))?;
    }

    let mut hash = Params::new()
        .hash_length(32)
        .personal(b"Loki_frostvs_v1")
        .to_state();
    hash.update(group_ak);
    for (id, value) in contributions {
        hash.update(&roster[&id].id.to_be_bytes());
        hash.update(&value);
    }
    Ok(hash.finalize().as_bytes().try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{collections::VecDeque, sync::Mutex};
    use uuid::Uuid;

    struct ScriptedTransport {
        inbox: Mutex<VecDeque<Vec<Incoming>>>,
        sent: Mutex<Vec<Vec<u8>>>,
    }

    impl Transport for ScriptedTransport {
        type Error = String;
        type Channel = ();

        fn open(&mut self, _: &[Peer], _: u8) -> Result<(), String> {
            unreachable!()
        }
        fn join(&mut self, _: Uuid) -> Result<(), String> {
            unreachable!()
        }
        fn send(&self, _: &(), _: &[Peer], message: &[u8]) -> Result<(), String> {
            self.sent.lock().unwrap().push(message.to_vec());
            Ok(())
        }
        fn recv(&self, _: &(), _: bool) -> Result<Vec<Incoming>, String> {
            Ok(self.inbox.lock().unwrap().pop_front().unwrap_or_default())
        }
        fn close(&self, _: ()) -> Result<(), String> {
            unreachable!()
        }
    }

    fn scripted_exchange(
        revealed: [u8; 32],
        committed: [u8; 32],
    ) -> (Result<[u8; 32], String>, ScriptedTransport) {
        let me = Identity::new(1);
        let peer = Identity::new(2);
        let vault = [7u8; 32];
        let ak = [3u8; 32];
        let one = frost::Identifier::try_from(1u16).unwrap();
        let two = frost::Identifier::try_from(2u16).unwrap();
        let roster = BTreeMap::from([(one, me.public()), (two, peer.public())]);
        let peer_of = BTreeMap::from([
            (one, Peer(me.public().encryption)),
            (two, Peer(peer.public().encryption)),
        ]);
        let transport = ScriptedTransport {
            // A fast peer's sealed reveal arrives before its public commitment.
            inbox: Mutex::new(VecDeque::from([vec![
                Incoming {
                    from: peer_of[&two].clone(),
                    message: peer.seal_round2(&me.public(), &vault, &revealed).unwrap(),
                },
                Incoming {
                    from: peer_of[&two].clone(),
                    message: commitment(&vault, 2, &committed).to_vec(),
                },
            ]])),
            sent: Mutex::new(Vec::new()),
        };
        let result = contribute(&transport, &(), &me, one, &roster, &peer_of, &vault, &ak);
        (result, transport)
    }

    #[test]
    fn buffers_early_sealed_reveal() {
        let (result, transport) = scripted_exchange([8; 32], [8; 32]);
        assert!(result.is_ok());
        let sent = transport.sent.lock().unwrap();
        assert_eq!(sent.len(), 2);
        assert_eq!(sent[0].len(), 32);
        assert!(is_sealed_round2(&sent[1]));
    }

    #[test]
    fn rejects_reveal_that_does_not_match_commitment() {
        let (result, _) = scripted_exchange([8; 32], [9; 32]);
        assert_eq!(result.unwrap_err(), "vault secret contribution changed");
    }
}
