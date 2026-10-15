#![cfg(feature = "relay-communication")]
use ed25519_dalek::{Signer, SigningKey};
use loki_poc::{
    setup_ceremony::{
        AcceptedCeremonyRoster, CeremonyPhase, CeremonyRecord, CheckpointAuthority,
        CheckpointState, SavedCheckpoint, SetupCeremony,
    },
    setup_transport::Identity,
    state::MemberDir,
};
use loki_relay_client::{
    sign_roster_acceptance, AcceptedSetupRoster, BootstrapContext, CommIdentity, OperatorSet,
    SetupAuthority, SetupPolicy, SetupStore, SetupTransport,
};
use loki_relay_protocol::{
    canonical::{self, Value},
    setup::{SetupCapabilities, SetupKey, SetupPhase, SetupRecord},
    types::Roster,
};
use std::collections::BTreeMap;
fn operators() -> OperatorSet {
    let key = SigningKey::from_bytes(&[91; 32]);
    let mut relays: Vec<_> = (1u8..=3)
        .map(|i| {
            Value::Array(vec![
                Value::Bytes(
                    SigningKey::from_bytes(&[i; 32])
                        .verifying_key()
                        .to_bytes()
                        .to_vec(),
                ),
                Value::Bytes(vec![i + 10; 32]),
                Value::Bytes(format!("https://relay{i}.example").into_bytes()),
            ])
        })
        .collect();
    relays.sort_by_key(|r| canonical::encode(r).unwrap());
    let body = canonical::encode(&Value::Array(vec![
        Value::Integer(1.into()),
        Value::Array(relays),
        Value::Array(vec![
            Value::Bytes(b"https://admission.example".to_vec()),
            Value::Bytes(
                SigningKey::from_bytes(&[8; 32])
                    .verifying_key()
                    .to_bytes()
                    .to_vec(),
            ),
        ]),
        Value::Array(vec![Value::Integer(1.into())]),
        Value::Array(
            [86400u64, 2592000, 1048576, 67108864, 30, 1, 60]
                .into_iter()
                .map(|n| Value::Integer(n.into()))
                .collect(),
        ),
    ]))
    .unwrap();
    let mut input = b"Loki_Operator_Config_v1\0".to_vec();
    input.extend_from_slice(&(body.len() as u32).to_be_bytes());
    input.extend_from_slice(&body);
    let bytes = canonical::encode(&Value::Array(vec![
        Value::Bytes(body),
        Value::Bytes(key.sign(&input).to_bytes().to_vec()),
    ]))
    .unwrap();
    OperatorSet::verify(&bytes, &key.verifying_key().to_bytes()).unwrap()
}
fn phase(phase: CeremonyPhase) -> SetupPhase {
    match phase {
        CeremonyPhase::Round1Saved => SetupPhase::Round1,
        CeremonyPhase::Round2Saved => SetupPhase::Round2,
        CeremonyPhase::CertificateSaved => SetupPhase::Certificate,
        _ => panic!("phase"),
    }
}
fn prepare(
    t: &SetupTransport<'_>,
    accepted: &AcceptedSetupRoster,
    phase_native: CeremonyPhase,
    outgoing: &BTreeMap<u16, Vec<u8>>,
    pred: &BTreeMap<u16, Vec<[u8; 32]>>,
) -> Result<Vec<u8>, String> {
    if outgoing.is_empty() {
        return Ok(vec![]);
    }
    let p = accepted.context().policy();
    // Each callback is supplied its own author's ID by the authenticated native envelope.
    let author = u16::from_be_bytes(
        outgoing.values().next().ok_or("empty")?[40..42]
            .try_into()
            .map_err(|_| "author")?,
    );
    let records: Vec<_> = outgoing
        .iter()
        .map(|(recipient, payload)| SetupRecord {
            version: 1,
            key: SetupKey {
                ceremony: p.ceremony,
                phase: phase(phase_native),
                author,
                recipient: *recipient,
                revision: 1,
            },
            network: p.network.clone(),
            threshold: p.threshold,
            member_count: p.member_count,
            roster_digest: Some(*accepted.digest()),
            prerequisites: pred.get(recipient).cloned().unwrap_or_default(),
            payload: payload.clone(),
        })
        .collect();
    t.checkpoint_prepared(&t.prepare(&records).map_err(|_| "prepare")?)
        .map_err(|_| "checkpoint".into())
}
struct OwnedAnchor;
impl CheckpointAuthority for OwnedAnchor {
    fn reconcile(&mut self, c: &SavedCheckpoint) -> Result<CheckpointState, String> {
        Ok(CheckpointState {
            generation: c.generation,
            digest: c.digest,
            terminal: false,
        })
    }
}
#[test]
fn real_outer_ciphertext_and_prerequisites_survive_native_phase_restarts() {
    for count in [3u16, 4] {
        let operators = operators();
        let identities: Vec<_> = (1..=count).map(Identity::new).collect();
        let communication: Vec<_> = identities
            .iter()
            .map(|i| CommIdentity::from_serialized(&i.to_secret_bytes()).unwrap())
            .collect();
        let roster = Roster {
            vault: [74; 32],
            members: communication.iter().map(CommIdentity::public).collect(),
        };
        let policy = SetupPolicy {
            ceremony: roster.vault,
            network: "regtest".into(),
            threshold: 2,
            member_count: count,
            config_digest: *operators.digest(),
        };
        let context =
            BootstrapContext::creator(policy.clone(), communication[0].public(), &operators)
                .unwrap();
        let acceptances: Vec<_> = communication
            .iter()
            .map(|i| {
                sign_roster_acceptance(i, &context, &roster, &SetupCapabilities::current()).unwrap()
            })
            .collect();
        let accepted = AcceptedSetupRoster::verify(&context, roster, &acceptances).unwrap();
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "loki-real-prepared-{}",
            hex::encode(identities[0].public().signing)
        ));
        let mut engines = BTreeMap::new();
        let mut stores = BTreeMap::new();
        let mut paths = BTreeMap::new();
        let mut anchor = OwnedAnchor;
        for id in 1..=count {
            let member = MemberDir::create(&root, &format!("member-{id}")).unwrap();
            MemberDir::create(member.path(), "secrets")
                .unwrap()
                .write_sealed(
                    "identity.sealed",
                    &identities[id as usize - 1].to_secret_bytes(),
                    "pass",
                )
                .unwrap();
            let mut engine = SetupCeremony::open(
                member.path(),
                "pass",
                AcceptedCeremonyRoster::from_transport(&accepted).unwrap(),
            )
            .unwrap();
            engine.synchronize(&mut anchor).unwrap();
            engine.step(&[]).unwrap();
            engine.synchronize(&mut anchor).unwrap();
            let transport = SetupTransport::new(
                &communication[id as usize - 1],
                &operators,
                SetupAuthority::Accepted(&accepted),
                false,
            )
            .unwrap();
            engine
                .step_with_preparation(&[], |phase, outgoing| {
                    prepare(&transport, &accepted, phase, outgoing, &BTreeMap::new())
                })
                .unwrap();
            assert!(engine.prepared_delivery().is_err());
            engine.synchronize(&mut anchor).unwrap();
            let prepared = transport
                .restore_prepared(engine.prepared_delivery().unwrap())
                .unwrap();
            let mut store =
                SetupStore::open(&member.path().join("communication"), &transport).unwrap();
            store.commit_outgoing(&transport, &prepared).unwrap();
            paths.insert(id, member.path().to_owned());
            stores.insert(id, store);
            engines.insert(id, engine);
        }
        for phase_native in [
            CeremonyPhase::Round1Saved,
            CeremonyPhase::Round2Saved,
            CeremonyPhase::CertificateSaved,
        ] {
            let mut incoming: BTreeMap<u16, Vec<CeremonyRecord>> = BTreeMap::new();
            let mut predecessors: BTreeMap<u16, Vec<[u8; 32]>> = BTreeMap::new();
            for author in 1..=count {
                let sender = SetupTransport::new(
                    &communication[author as usize - 1],
                    &operators,
                    SetupAuthority::Accepted(&accepted),
                    false,
                )
                .unwrap();
                let engine = engines.remove(&author).unwrap();
                let saved = engine.prepared_delivery().unwrap().to_vec();
                let checkpoint = engine.checkpoint();
                drop(engine);
                let mut engine = SetupCeremony::open(
                    &paths[&author],
                    "pass",
                    AcceptedCeremonyRoster::from_transport(&accepted).unwrap(),
                )
                .unwrap_or_else(|error| panic!("reopen {phase_native:?} member {author}: {error}"));
                engine.synchronize(&mut anchor).unwrap();
                assert_eq!(engine.checkpoint(), checkpoint);
                assert_eq!(engine.prepared_delivery().unwrap(), saved);
                let prepared = sender.restore_prepared(&saved).unwrap();
                assert_eq!(sender.checkpoint_prepared(&prepared).unwrap(), saved);
                for recipient in 1..=count {
                    let receiver = SetupTransport::new(
                        &communication[recipient as usize - 1],
                        &operators,
                        SetupAuthority::Accepted(&accepted),
                        false,
                    )
                    .unwrap();
                    let (object, objects) = prepared.recipient_objects(recipient).unwrap();
                    stores
                        .get_mut(&recipient)
                        .unwrap()
                        .commit_incoming(&receiver, &object, &objects)
                        .unwrap();
                    let key = SetupKey {
                        ceremony: policy.ceremony,
                        phase: phase(phase_native),
                        author,
                        recipient,
                        revision: 1,
                    };
                    let record = stores[&recipient]
                        .receive(&receiver, &key)
                        .unwrap()
                        .unwrap();
                    predecessors
                        .entry(recipient)
                        .or_default()
                        .push(*record.digest());
                    incoming.entry(recipient).or_default().push(CeremonyRecord {
                        phase: phase_native,
                        author,
                        bytes: record.body().payload.clone(),
                    });
                }
                engines.insert(author, engine);
            }
            for digests in predecessors.values_mut() {
                digests.sort();
            }
            for id in 1..=count {
                let transport = SetupTransport::new(
                    &communication[id as usize - 1],
                    &operators,
                    SetupAuthority::Accepted(&accepted),
                    false,
                )
                .unwrap();
                let engine = engines.get_mut(&id).unwrap();
                engine
                    .step_with_preparation(&incoming[&id], |next, outgoing| {
                        prepare(&transport, &accepted, next, outgoing, &predecessors)
                    })
                    .unwrap();
                engine.synchronize(&mut anchor).unwrap();
                if !engine.outgoing().unwrap().is_empty() {
                    let prepared = transport
                        .restore_prepared(engine.prepared_delivery().unwrap())
                        .unwrap();
                    stores
                        .get_mut(&id)
                        .unwrap()
                        .commit_outgoing(&transport, &prepared)
                        .unwrap();
                }
            }
        }
        assert!(engines
            .values()
            .all(|e| e.phase() == CeremonyPhase::AwaitingBackups));
        let address = engines[&1].certified_address().unwrap();
        assert!(engines
            .values()
            .all(|e| e.certified_address().unwrap() == address));
        drop(engines);
        drop(stores);
        std::fs::remove_dir_all(root).unwrap();
    }
}
