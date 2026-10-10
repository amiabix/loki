mod support;

use ed25519_dalek::{Signer, SigningKey};
use loki_relay_client::{
    open_descriptor, poll_once_observed, prepare_outbox, seal_descriptor, ClientConfig, ClientError,
    ClientStore, CommitDisposition, Descriptor, DescriptorRelay, DownloadOutcome, Observation,
    ObservationKind, ObservationSink, RelayHttp, RelayRuntime, Secret32, TransferAssembler,
};
use loki_relay_protocol::{
    canonical::{self, Value},
    receipt,
    types::{roster_digest, Entry, Id32, LogicalKey, MessageBody, Object, Page, Payload, ReceiptBody, RelayPin, RelayRoute},
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::TcpListener,
    thread,
    time::Duration,
};

fn signer() -> SigningKey {
    SigningKey::from_bytes(&[9; 32])
}

fn route(endpoint: &str) -> RelayRoute {
    RelayRoute {
        pin: RelayPin {
            key: signer().verifying_key().to_bytes(),
            run: [2; 32],
        },
        endpoint: endpoint.to_string(),
        mailbox: [3; 32],
        append_revision: 1,
    }
}

fn object() -> Object {
    let mut wire = vec![7; 1024];
    wire[..8].copy_from_slice(b"LOKIRLY1");
    wire[8] = 1;
    Object {
        hash: Sha256::digest(&wire).into(),
        wire,
    }
}

fn receipt_bytes(route: &RelayRoute, hash: Id32, wire_length: u64, sequence: u64) -> Vec<u8> {
    let body = ReceiptBody {
        pin: route.pin.clone(),
        mailbox: route.mailbox,
        hash,
        wire_length,
        sequence,
        retention: 1,
    };
    let encoded = receipt::encode_body(&body).unwrap();
    let mut input = b"Loki_Relay_Stored_v1\0".to_vec();
    input.extend_from_slice(&u32::try_from(encoded.len()).unwrap().to_be_bytes());
    input.extend_from_slice(&encoded);
    canonical::encode(&Value::Array(vec![
        Value::Bytes(encoded),
        Value::Bytes(signer().sign(&input).to_bytes().to_vec()),
    ]))
    .unwrap()
}

fn error_code<T>(result: Result<T, ClientError>) -> &'static str {
    match result {
        Ok(_) => panic!("expected a transport error"),
        Err(error) => error.code(),
    }
}

fn serve(status: u16, content_type: &str, body: Vec<u8>) -> String {
    let content_type = content_type.to_string();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    thread::spawn(move || {
        for _ in 0..8 {
            let Ok((mut stream, _)) = listener.accept() else {
                break;
            };
            let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
            let mut buf = [0; 8192];
            let _ = stream.read(&mut buf);
            let header = format!(
                "HTTP/1.1 {status} X\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(&body);
        }
    });
    format!("http://127.0.0.1:{port}")
}

fn drain(receiver: &std::sync::mpsc::Receiver<Observation>) -> Vec<Observation> {
    let mut events = Vec::new();
    while let Ok(event) = receiver.try_recv() {
        events.push(event);
    }
    events
}

fn runtime() -> RelayRuntime {
    RelayRuntime::new().unwrap()
}

fn message(sender: u16, id: u8, payload: Vec<u8>) -> MessageBody {
    let roster = support::roster();
    MessageBody {
        key: LogicalKey {
            vault: roster.vault,
            roster: roster_digest(&roster).unwrap(),
            sender,
            message: [id; 32],
        },
        audience: vec![1, 2, 3],
        session: Some([44; 32]),
        prerequisites: Vec::new(),
        payload: Payload::Test(payload),
    }
}

fn framed_route() -> RelayRoute {
    route("http://127.0.0.1:9")
}

fn journal_page(route: &RelayRoute, object: &Object) -> Page {
    let entry = Entry {
        sequence: 1,
        hash: object.hash,
        wire_length: object.wire.len() as u64,
        receipt: receipt_bytes(route, object.hash, object.wire.len() as u64, 1),
    };
    Page {
        mailbox: route.mailbox,
        after: 0,
        next: 1,
        high_water: 1,
        entries: vec![entry],
    }
}

fn descriptor_for(owner: u16) -> loki_relay_client::AuthenticatedDescriptor {
    let roster = support::roster();
    let identity = support::identity(owner);
    let sealed = seal_descriptor(
        &identity,
        &roster,
        &Descriptor::new(
            roster.vault,
            roster_digest(&roster).unwrap(),
            owner,
            1,
            (0u8..3)
                .map(|index| DescriptorRelay {
                    route: RelayRoute {
                        pin: RelayPin {
                            key: [index + 1; 32],
                            run: [index + 4; 32],
                        },
                        endpoint: format!("http://127.0.0.1:{}", 9000 + u16::from(index)),
                        mailbox: [index + 8; 32],
                        append_revision: 1,
                    },
                    append: Secret32::from_bytes([index + 11; 32]),
                })
                .collect(),
        ),
        &identity.public(),
    )
    .unwrap();
    open_descriptor(&identity, &roster, &sealed.wire).unwrap()
}

#[test]
fn disabled_sink_drops_nothing_and_changes_no_result() {
    let sink = ObservationSink::disabled();
    sink.emit(Observation::new(ObservationKind::RequestStart, 1));
    assert_eq!(sink.dropped(), 0);
}

#[test]
fn full_or_disconnected_queue_counts_a_gap_and_keeps_going() {
    let (sink, receiver) = ObservationSink::bounded(1);
    sink.emit(sink.begin(ObservationKind::RequestStart));
    sink.emit(sink.begin(ObservationKind::RequestEnd));
    assert_eq!(sink.dropped(), 1);
    let first = receiver.recv().unwrap();
    assert_eq!(first.kind, ObservationKind::RequestStart);
    assert!(first.request >= 1);
    drop(receiver);
    sink.emit(Observation::new(ObservationKind::Quarantine, 9));
    assert_eq!(sink.dropped(), 2);
    let rendered = format!("{first:?}");
    assert!(!rendered.contains("secret"));
    assert!(rendered.contains("RequestStart"));
}

#[test]
fn repeated_puts_keep_distinct_request_ids_and_the_same_outcome() {
    let saved = object();
    let endpoint = serve(500, "application/cbor", b"nope".to_vec());
    let relay = route(&endpoint);
    let append = Secret32::from_bytes([4; 32]);
    let runtime = runtime();
    let disabled = RelayHttp::new().unwrap();
    let plain = error_code(runtime.block_on(disabled.put(&relay, &append, &saved)));
    let (sink, receiver) = ObservationSink::bounded(8);
    let http = RelayHttp::with_observer(sink.clone()).unwrap();
    http.set_actor(Some(1));
    let observed = runtime.block_on(http.put(&relay, &append, &saved));
    let again = runtime.block_on(http.put(&relay, &append, &saved));
    assert_eq!(plain, error_code(observed));
    assert_eq!(plain, error_code(again));
    let events = drain(&receiver);
    let starts: Vec<_> = events
        .iter()
        .filter(|event| event.kind == ObservationKind::RequestStart)
        .collect();
    assert_eq!(starts.len(), 2);
    assert_ne!(starts[0].request, starts[1].request);
    assert_eq!(starts[0].object_hash, Some(saved.hash));
    assert_eq!(starts[1].object_hash, Some(saved.hash));
    assert!(events.iter().all(|event| event.kind != ObservationKind::ReceiptPersisted));
    let (full, blocked) = ObservationSink::bounded(1);
    full.emit(full.begin(ObservationKind::RequestStart));
    let crowded = RelayHttp::with_observer(full.clone()).unwrap();
    let crowded_result = runtime.block_on(crowded.put(&relay, &append, &saved));
    assert_eq!(error_code(crowded_result), plain);
    assert!(full.dropped() >= 1);
    let _ = blocked;
}

#[test]
fn get_actor_is_the_recipient_and_fields_carry_no_secret_bytes() {
    let endpoint = serve(404, "application/cbor", b"missing".to_vec());
    let relay = route(&endpoint);
    let (sink, receiver) = ObservationSink::bounded(4);
    let http = RelayHttp::with_observer(sink).unwrap();
    http.set_actor(Some(2));
    let error = error_code(runtime().block_on(http.get(&relay, &Secret32::from_bytes([5; 32]), &[9; 32])));
    assert_eq!(error, "transport");
    let events = drain(&receiver);
    let start = events
        .iter()
        .find(|event| event.kind == ObservationKind::RequestStart)
        .unwrap();
    assert_eq!(start.actor, Some(2));
    assert_eq!(start.sender, None);
    assert_eq!(start.mailbox, Some(relay.mailbox));
    for event in &events {
        let rendered = format!("{event:?}");
        for forbidden in ["authorization", "passphrase", "payload", "share", "secret", "capability"] {
            assert!(!rendered.contains(forbidden), "{rendered}");
        }
    }
}

#[test]
fn http_success_validates_a_receipt_without_persisting_it() {
    let saved = object();
    let endpoint = serve(200, "application/cbor", receipt_bytes(&route("http://127.0.0.1:9"), saved.hash, saved.wire.len() as u64, 1));
    let relay = route(&endpoint);
    let (sink, receiver) = ObservationSink::bounded(8);
    let http = RelayHttp::with_observer(sink).unwrap();
    let receipt = runtime()
        .block_on(http.put(&relay, &Secret32::from_bytes([4; 32]), &saved))
        .unwrap();
    assert_eq!(receipt.body().hash, saved.hash);
    let events = drain(&receiver);
    assert!(events.iter().any(|event| event.kind == ObservationKind::ReceiptValidated));
    assert!(events.iter().all(|event| event.kind != ObservationKind::ReceiptPersisted));
    assert!(events.iter().all(|event| event.kind != ObservationKind::ReceiptRejected));
}

#[test]
fn malformed_receipt_is_distinct_from_an_http_error() {
    let saved = object();
    let good_endpoint = serve(200, "application/cbor", b"not-a-receipt".to_vec());
    let bad_relay = route(&good_endpoint);
    let (sink, receiver) = ObservationSink::bounded(8);
    let http = RelayHttp::with_observer(sink).unwrap();
    let rejected = error_code(runtime().block_on(http.put(&bad_relay, &Secret32::from_bytes([4; 32]), &saved)));
    assert_eq!(rejected, "receipt");
    let events = drain(&receiver);
    assert!(events.iter().any(|event| {
        event.kind == ObservationKind::ReceiptRejected && event.result == Some("receipt")
    }));
    assert!(events.iter().all(|event| event.kind != ObservationKind::ReceiptPersisted));
    let http_endpoint = serve(503, "application/cbor", b"busy".to_vec());
    let (other, other_receiver) = ObservationSink::bounded(8);
    let transport = RelayHttp::with_observer(other).unwrap();
    let status = error_code(runtime().block_on(transport.put(
        &route(&http_endpoint),
        &Secret32::from_bytes([4; 32]),
        &saved,
    )));
    assert_ne!(status, "receipt");
    let transport_events = drain(&other_receiver);
    assert!(transport_events.iter().any(|event| event.kind == ObservationKind::RequestEnd));
    assert!(transport_events
        .iter()
        .all(|event| event.kind != ObservationKind::ReceiptRejected && event.kind != ObservationKind::ReceiptPersisted));
}

#[test]
fn foreign_poll_links_received_once_and_a_failed_commit_does_not() {
    let roster = support::roster();
    let alice = support::identity(1);
    let bob = support::identity(2);
    let prepared = prepare_outbox(&alice, &roster, &message(1, 40, vec![19, 29, 39])).unwrap();
    let bob_object = prepared
        .recipients()
        .iter()
        .find(|recipient| recipient.recipient() == 2)
        .unwrap()
        .objects()[0]
        .clone();
    let root = support::root();
    let mut store = ClientStore::open(&root, &roster, 2).unwrap();
    let relay = framed_route();
    store
        .capture_page(&relay, &journal_page(&relay, &bob_object), &[DownloadOutcome::Cached(bob_object.clone())])
        .unwrap();
    let http = RelayHttp::new().unwrap();
    let config = ClientConfig { own: Vec::new(), peers: Vec::new() };
    let descriptor = descriptor_for(2);
    let (sink, receiver) = ObservationSink::bounded(32);
    let runtime = runtime();
    let first = runtime.block_on(poll_once_observed(
        &mut store,
        &http,
        &bob,
        &roster,
        &config,
        &descriptor,
        1,
        &sink,
    ));
    assert_eq!(first.unwrap_err().code(), "config");
    let second = runtime.block_on(poll_once_observed(
        &mut store,
        &http,
        &bob,
        &roster,
        &config,
        &descriptor,
        1,
        &sink,
    ));
    assert_eq!(second.unwrap_err().code(), "config");
    let events = drain(&receiver);
    assert_eq!(
        events.iter().filter(|event| event.kind == ObservationKind::ReceivedLinked).count(),
        1
    );
    assert!(events.iter().any(|event| event.kind == ObservationKind::OriginalCommitted));
    assert!(events.iter().any(|event| event.kind == ObservationKind::OriginalAuthenticated));
    let rendered = format!("{events:?}");
    assert!(!rendered.contains("payload"));
    assert!(!rendered.contains(&hex::encode(vec![19, 29, 39])));

    let other = prepare_outbox(&alice, &roster, &message(1, 41, vec![1, 2, 3])).unwrap();
    let other_object = other.recipients().iter().find(|recipient| recipient.recipient() == 2).unwrap().objects()[0].clone();
    let opened = TransferAssembler::open(&roster, &bob, &bob_object, &BTreeMap::new()).unwrap();
    let mismatched = TransferAssembler::open(&roster, &bob, &other_object, &BTreeMap::new()).unwrap();
    let (message, _) = opened.into_parts();
    let (_, source) = mismatched.into_parts();
    let (failed_sink, failed_receiver) = ObservationSink::bounded(8);
    let failed = runtime.block_on(failed_sink.drive(async {
        store.commit_incoming(&roster, &bob, &source, &message, None)
    }));
    assert_eq!(failed.unwrap_err().code(), "identity");
    assert!(drain(&failed_receiver)
        .iter()
        .all(|event| event.kind != ObservationKind::OriginalCommitted && event.kind != ObservationKind::ReceivedLinked));
}

#[test]
fn self_commit_does_not_link_received() {
    let roster = support::roster();
    let alice = support::identity(1);
    let prepared = prepare_outbox(&alice, &roster, &message(1, 42, vec![4, 5, 6])).unwrap();
    let root = support::root();
    let mut store = ClientStore::open(&root, &roster, 1).unwrap();
    store
        .commit_outbox(&roster, &alice, &[7; 32], &prepared)
        .unwrap();
    let own = prepared
        .recipients()
        .iter()
        .find(|recipient| recipient.recipient() == 1)
        .unwrap()
        .objects()[0]
        .clone();
    let opened = TransferAssembler::open(&roster, &alice, &own, &BTreeMap::new()).unwrap();
    let (message, source) = opened.into_parts();
    let (sink, receiver) = ObservationSink::bounded(8);
    let disposition = runtime()
        .block_on(sink.drive(async {
            store.commit_incoming(&roster, &alice, &source, &message, None)
        }))
        .unwrap();
    assert_eq!(disposition, CommitDisposition::Duplicate);
    let events = drain(&receiver);
    assert!(events.iter().any(|event| event.kind == ObservationKind::OriginalCommitted));
    assert!(events.iter().all(|event| event.kind != ObservationKind::ReceivedLinked));
}
