use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use loki_poc::member_state::valid_policy;
use loki_poc::signer::backup::BackupArtifact;
use loki_poc::signer::coordination::{
    drive_to_signed_pczt, member_dkg_step, relay_dkg, PaymentIntent, QuorumMember,
};
use loki_poc::signer::local::{BackupDevice, DevicePrompts, LocalSigner, RosterDecision};
use loki_poc::signer::secure_element::SoftwareSecureElement;
use loki_poc::signer::{CandidateRef, Network, Session, Signer, VaultRef};
use loki_poc::transport::{Incoming, Outbound, Peer, RelayLog, Transport};
use orchard::note::{RandomSeed, Rho};
use orchard::value::NoteValue;
use orchard::NoteVersion;
use reddsa_frost::frost::redpallas as frost;
use tempfile::TempDir;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::secret::SecretString;

const ORIGIN: &str = "https://coordinator.test";
const VAULT: [u8; 32] = [0x5a; 32];

#[derive(Debug)]
pub struct Measurements {
    pub round1: Duration,
    pub round2: Duration,
    pub finalize: Duration,
    pub signing: Duration,
}

#[derive(Default)]
struct SessionQueues {
    coordinator: [u8; 32],
    peers: Vec<[u8; 32]>,
    inboxes: BTreeMap<([u8; 32], bool), Vec<Incoming>>,
}

#[derive(Clone, Default)]
struct MemoryRelay(Arc<Mutex<BTreeMap<Uuid, SessionQueues>>>);

struct MemoryTransport {
    relay: MemoryRelay,
    me: Peer,
}

impl Transport for MemoryTransport {
    type Error = String;
    type Channel = Uuid;

    fn open(&mut self, peers: &[Peer], _: u8) -> Result<Uuid, String> {
        let id = Uuid::new_v4();
        let session = SessionQueues {
            coordinator: self.me.0,
            peers: peers.iter().map(|peer| peer.0).collect(),
            ..SessionQueues::default()
        };
        self.relay.0.lock().unwrap().insert(id, session);
        Ok(id)
    }

    fn join(&mut self, session: Uuid) -> Result<Uuid, String> {
        let sessions = self.relay.0.lock().unwrap();
        let queue = sessions.get(&session).ok_or("unknown session")?;
        if !queue.peers.contains(&self.me.0) {
            return Err("peer is outside session".into());
        }
        Ok(session)
    }

    fn send(&self, channel: &Uuid, to: &[Peer], message: &Outbound) -> Result<(), String> {
        let bytes = message.to_bytes().map_err(|e| e.to_string())?;
        let mut sessions = self.relay.0.lock().unwrap();
        let queue = sessions.get_mut(channel).ok_or("unknown session")?;
        if self.me.0 != queue.coordinator && !queue.peers.contains(&self.me.0) {
            return Err("sender is outside session".into());
        }
        let recipients: Vec<_> = if to.is_empty() {
            vec![(queue.coordinator, true)]
        } else {
            to.iter().map(|peer| (peer.0, false)).collect()
        };
        if recipients
            .iter()
            .any(|(peer, _)| *peer != queue.coordinator && !queue.peers.contains(peer))
        {
            return Err("recipient is outside session".into());
        }
        for &(peer, coordinator) in &recipients {
            queue
                .inboxes
                .entry((peer, coordinator))
                .or_default()
                .push(Incoming {
                    from: self.me.clone(),
                    message: bytes.clone(),
                });
        }
        Ok(())
    }

    fn recv(&self, channel: &Uuid, as_coordinator: bool) -> Result<Vec<Incoming>, String> {
        let mut sessions = self.relay.0.lock().unwrap();
        let queue = sessions.get_mut(channel).ok_or("unknown session")?;
        if as_coordinator && self.me.0 != queue.coordinator {
            return Err("peer is not coordinator".into());
        }
        if self.me.0 != queue.coordinator && !queue.peers.contains(&self.me.0) {
            return Err("peer is outside session".into());
        }
        Ok(queue
            .inboxes
            .remove(&(self.me.0, as_coordinator))
            .unwrap_or_default())
    }

    fn close(&self, channel: Uuid) -> Result<(), String> {
        let mut sessions = self.relay.0.lock().unwrap();
        if sessions.get(&channel).map(|s| s.coordinator) != Some(self.me.0) {
            return Err("peer is not coordinator".into());
        }
        sessions.remove(&channel);
        Ok(())
    }
}

struct MemoryBackup {
    passphrase: SecretString,
    artifact: Option<BackupArtifact>,
}

impl BackupDevice for MemoryBackup {
    fn passphrase(&mut self) -> Option<Zeroizing<String>> {
        Some(Zeroizing::new(self.passphrase.expose().to_owned()))
    }

    fn save(&mut self, artifact: &BackupArtifact) -> Result<(), String> {
        self.artifact = Some(BackupArtifact(artifact.0.clone()));
        Ok(())
    }

    fn load(&mut self) -> Result<BackupArtifact, String> {
        self.artifact
            .as_ref()
            .map(|a| BackupArtifact(a.0.clone()))
            .ok_or_else(|| "backup missing".into())
    }
}

struct Member {
    signer: LocalSigner<SoftwareSecureElement>,
    session: Session,
    vault: VaultRef,
    transport: MemoryTransport,
    channel: Uuid,
    backed_up: bool,
}

fn prompts() -> DevicePrompts {
    DevicePrompts {
        connect: Box::new(|origin, network| origin == ORIGIN && network == Network::Regtest),
        roster: Box::new(|_| RosterDecision::Match),
        roster_deadline: Duration::from_secs(60),
        backup: Box::new(MemoryBackup {
            passphrase: SecretString::new(Uuid::new_v4().to_string()),
            artifact: None,
        }),
        approval: Box::new(|_| true),
    }
}

pub fn ceremony_and_sign(count: u16, threshold: u16) -> Result<Measurements, String> {
    if !valid_policy(threshold, usize::from(count)) {
        return Err("invalid threshold or member count".into());
    }
    let root = TempDir::new().map_err(|e| e.to_string())?;
    let relay = MemoryRelay::default();
    let coordinator_peer = Peer([0xf0; 32]);
    let mut coordinator = MemoryTransport {
        relay: relay.clone(),
        me: coordinator_peer.clone(),
    };
    let mut members = Vec::with_capacity(usize::from(count));
    let mut peers = BTreeMap::new();
    let mut roster_members = Vec::new();
    for id in 1..=count {
        let dir = root.path().join(format!("member-{id}"));
        let mut signer = LocalSigner::create(
            &dir,
            SoftwareSecureElement::generate(),
            Network::Regtest,
            VAULT,
            id,
            "harness vault".into(),
            prompts(),
        )
        .map_err(|e| e.to_string())?;
        let connected = signer
            .connect(ORIGIN, Network::Regtest, b"harness roster")
            .map_err(|e| e.to_string())?;
        peers.insert(id, Peer(connected.member.encryption));
        roster_members.push(serde_json::json!({
            "id": connected.member.id,
            "signing": hex::encode(connected.member.signing),
            "encryption": hex::encode(connected.member.encryption),
        }));
        members.push((signer, connected.session));
    }
    let channel = coordinator.open(&peers.values().cloned().collect::<Vec<_>>(), 4)?;
    let document = serde_json::to_vec(&serde_json::json!({
        "vault": hex::encode(VAULT),
        "threshold": threshold,
        "setup_version": 2,
        "members": roster_members,
    }))
    .map_err(|e| e.to_string())?;
    let mut members: Vec<Member> = members
        .into_iter()
        .enumerate()
        .map(|(i, (mut signer, session))| {
            let vault = signer
                .dkg_begin(&session, &document)
                .map_err(|e| e.to_string())?;
            let mut transport = MemoryTransport {
                relay: relay.clone(),
                me: peers[&(i as u16 + 1)].clone(),
            };
            let joined = transport.join(channel)?;
            Ok(Member {
                signer,
                session,
                vault,
                transport,
                channel: joined,
                backed_up: false,
            })
        })
        .collect::<Result<_, String>>()?;
    let mut log =
        RelayLog::open(&root.path().join("relay-log"), count).map_err(|e| e.to_string())?;
    let mut round1 = Duration::ZERO;
    let mut round2 = Duration::ZERO;
    let mut finalize = Duration::ZERO;
    for pass in 0..8 {
        let start = Instant::now();
        for member in &mut members {
            member_dkg_step(
                &mut member.signer,
                &member.session,
                &member.vault,
                &member.transport,
                &member.channel,
                &coordinator_peer,
            )?;
            if !member.backed_up {
                if let Ok(receipts) = member.signer.backup(&member.session) {
                    for wire in receipts {
                        member
                            .transport
                            .send(&member.channel, &[], &Outbound::Dkg(wire))?;
                    }
                    member.backed_up = true;
                }
            }
        }
        relay_dkg(&mut log, &coordinator, &channel, &peers)?;
        match pass {
            0 => round1 += start.elapsed(),
            1 => round2 += start.elapsed(),
            _ => finalize += start.elapsed(),
        }
        if members.iter().all(|m| {
            m.signer
                .list_vaults(&m.session)
                .map(|v| v[0].ready)
                .unwrap_or(false)
        }) {
            break;
        }
    }
    if !members.iter().all(|m| {
        m.signer
            .list_vaults(&m.session)
            .map(|v| v[0].ready)
            .unwrap_or(false)
    }) {
        return Err("DKG did not finish".into());
    }
    if !log.active() {
        return Err("backup receipts missing".into());
    }
    let addresses = members
        .iter_mut()
        .map(|m| {
            m.signer
                .release_address(&m.session)
                .map(|a| a.address)
                .map_err(|e| e.to_string())
        })
        .collect::<Result<Vec<_>, _>>()?;
    if !addresses.iter().all(|address| address == &addresses[0]) {
        return Err("members derived different group addresses".into());
    }
    let public_bytes = members[0]
        .signer
        .public_package_bytes()
        .ok_or("no public package")?;
    if !members
        .iter()
        .all(|m| m.signer.public_package_bytes() == Some(public_bytes))
    {
        return Err("members derived different group public packages".into());
    }
    let public =
        frost::keys::PublicKeyPackage::deserialize(public_bytes).map_err(|e| e.to_string())?;
    let recipient = loki_poc::vault::orchard_receiver_from_ua(
        &addresses[0],
        zcash_protocol::consensus::NetworkType::Regtest,
    )
    .map_err(|e| e.to_string())?;
    let rho = Option::<Rho>::from(Rho::from_bytes(&[1; 32])).ok_or("invalid rho")?;
    let note = orchard::Note::from_parts(
        recipient,
        NoteValue::from_raw(625_000_000),
        rho,
        Option::<RandomSeed>::from(RandomSeed::from_bytes([2; 32], &rho))
            .ok_or("invalid note seed")?,
        NoteVersion::V3,
    );
    let note = Option::<orchard::Note>::from(note).ok_or("invalid note")?;
    let signing_start = Instant::now();
    let intent = PaymentIntent {
        recipient,
        amount: zcash_protocol::value::Zatoshis::const_from_u64(40_000_000),
        memo: zcash_protocol::memo::MemoBytes::from_bytes(b"harness")
            .map_err(|e| format!("memo: {e:?}"))?,
        target_height: 700,
        expiry_height: 1_152,
    };
    let candidate = CandidateRef {
        vault_id: VAULT,
        payment_id: [7; 32],
        attempt_id: [9; 32],
    };
    let mut quorum = members
        .iter_mut()
        .take(usize::from(threshold))
        .enumerate()
        .map(|(i, member)| {
            member.signer.set_candidate_notes(vec![note]);
            Ok(QuorumMember {
                id: frost::Identifier::try_from(i as u16 + 1).map_err(|e| e.to_string())?,
                session: member.session.clone(),
                signer: &mut member.signer,
            })
        })
        .collect::<Result<Vec<_>, String>>()?;
    let signed = drive_to_signed_pczt(&public, &intent, &candidate, &mut quorum)?;
    let parsed = pczt::Pczt::parse(&signed).map_err(|e| format!("signed PCZT: {e:?}"))?;
    if !parsed
        .ironwood()
        .actions()
        .iter()
        .any(|a| a.spend().spend_auth_sig().is_some())
    {
        return Err("signed PCZT lacks spend authorization".into());
    }
    let signing = signing_start.elapsed();
    coordinator.close(channel)?;
    // TempDir removes encrypted signer files; deletion is not secure erasure.
    Ok(Measurements {
        round1,
        round2,
        finalize,
        signing,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relay_drains_only_the_requested_session() {
        let relay = MemoryRelay::default();
        let mut coordinator = MemoryTransport {
            relay: relay.clone(),
            me: Peer([1; 32]),
        };
        let mut member = MemoryTransport {
            relay,
            me: Peer([2; 32]),
        };
        let first = coordinator.open(&[member.me.clone()], 1).unwrap();
        let second = coordinator.open(&[member.me.clone()], 1).unwrap();
        member.join(first).unwrap();
        member.join(second).unwrap();
        member
            .send(&first, &[], &Outbound::RandomizerSeed([7; 32]))
            .unwrap();
        assert!(coordinator.recv(&second, true).unwrap().is_empty());
        assert_eq!(coordinator.recv(&first, true).unwrap().len(), 1);
        assert!(coordinator.recv(&first, true).unwrap().is_empty());
    }
}
