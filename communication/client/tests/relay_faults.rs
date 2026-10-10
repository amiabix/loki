#[allow(dead_code)]
mod support;

use ed25519_dalek::{Signer, SigningKey};
use loki_relay_client::{
    authenticate_staged, seal_record, ClientStore, DownloadOutcome, SealContext, SealDomain,
};
use loki_relay_protocol::{
    canonical::{self, Value},
    http::encode_creation,
    types::{
        encode_message, roster_digest, Creation, Entry, LogicalKey, MessageBody, Page, Payload,
        RelayPin, RelayRoute,
    },
};
use loki_relay_server::{
    capability::{provisioning_verifier, verifier},
    Capability, Limits, RelayStore, Role,
};

#[test]
fn forged_inner_sender_is_stored_with_append_but_never_received() {
    let roster = support::roster();
    let digest = roster_digest(&roster).unwrap();
    let body = MessageBody {
        key: LogicalKey {
            vault: roster.vault,
            roster: digest,
            sender: 1,
            message: [44; 32],
        },
        audience: vec![1, 2, 3],
        session: None,
        prerequisites: vec![],
        payload: Payload::Test(vec![23; 64]),
    };
    let encoded = encode_message(&body).unwrap();
    let mut input = b"Loki_Relay_Message_v1\0".to_vec();
    input.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
    input.extend_from_slice(&encoded);
    let signature = SigningKey::from_bytes(&[2; 32]).sign(&input);
    let package = canonical::encode(&Value::Array(vec![
        Value::Bytes(encoded),
        Value::Bytes(signature.to_bytes().to_vec()),
    ]))
    .unwrap();
    let record = canonical::encode(&Value::Array(vec![
        Value::Integer(1.into()),
        Value::Bytes(package),
    ]))
    .unwrap();
    let object = seal_record(
        &SealContext {
            domain: SealDomain::Message,
            vault: roster.vault,
            roster: digest,
            recipient: roster.members[1].clone(),
        },
        &record,
    )
    .unwrap();
    let root = support::root();
    let relay_root = root.parent().unwrap().join("relay");
    let limits = Limits {
        total_bytes: 1048576,
        mailbox_bytes: 1048576,
        mailbox_count: 3,
    };
    let mut relay = RelayStore::init(
        &relay_root,
        [7; 32],
        "http://127.0.0.1:9000",
        &[8; 32],
        provisioning_verifier([7; 32], &[8; 32]),
        limits,
    )
    .unwrap();
    let mailbox = [1; 32];
    let creation = encode_creation(&Creation {
        read_verifier: verifier(Role::Read, mailbox, &[2; 32]),
        append_verifier: verifier(Role::Append, mailbox, &[3; 32]),
        admin_verifier: verifier(Role::Admin, mailbox, &[4; 32]),
        quota: 1048576,
    })
    .unwrap();
    relay
        .create(mailbox, &creation, &Capability::new([8; 32]))
        .unwrap();
    let saved = relay
        .put(mailbox, &object, &Capability::new([3; 32]))
        .unwrap();
    assert!(saved.created);
    let retry = relay
        .put(mailbox, &object, &Capability::new([3; 32]))
        .unwrap();
    assert!(!retry.created);
    assert_eq!(retry.receipt, saved.receipt);
    assert_eq!(retry.sequence, saved.sequence);
    assert_eq!(
        relay
            .get(mailbox, object.hash, &Capability::new([2; 32]))
            .unwrap(),
        object.wire
    );
    let route = RelayRoute {
        pin: RelayPin {
            key: relay.public_key(),
            run: relay.run_id(),
        },
        endpoint: "http://127.0.0.1:9000".into(),
        mailbox,
        append_revision: 1,
    };
    let mut store = ClientStore::open(&root, &roster, 2).unwrap();
    store
        .capture_page(
            &route,
            &Page {
                mailbox,
                after: 0,
                next: 1,
                high_water: 1,
                entries: vec![Entry {
                    sequence: 1,
                    hash: object.hash,
                    wire_length: object.wire.len() as u64,
                    receipt: saved.receipt,
                }],
            },
            &[DownloadOutcome::Cached(object.clone())],
        )
        .unwrap();
    assert!(
        authenticate_staged(&mut store, &roster, &support::identity(2))
            .unwrap()
            .is_empty()
    );
    assert!(store.recover_incoming_originals(0, 100).unwrap().is_empty());
    assert!(store.recover_ack_links(0, 100).unwrap().is_empty());
    let rejected = store.recover_source_rejections(0, 100).unwrap();
    assert!(rejected
        .iter()
        .any(|r| r.root_hash == object.hash && r.reason == "signature"));
    drop(store);
    let store = ClientStore::open(&root, &roster, 2).unwrap();
    assert_eq!(
        store.saved_object(&object.hash).unwrap().unwrap().wire,
        object.wire
    );
    assert!(store.recover_incoming_originals(0, 100).unwrap().is_empty());
    assert!(store.recover_ack_links(0, 100).unwrap().is_empty());
    println!(
        "fault-observation={}",
        serde_json::json!({"hash": hex::encode(object.hash), "length": object.wire.len(), "relay_key": hex::encode(route.pin.key), "run": hex::encode(route.pin.run), "sequence": saved.sequence, "originals": 0, "acknowledgements": 0, "rejection": "signature"})
    );
}
