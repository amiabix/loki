mod support;

use ed25519_dalek::{Signer, SigningKey};
use loki_relay_client::{
    authenticate_staged, open_descriptor, prepare_outbox, prepare_received, received_status,
    reconcile_received, seal_descriptor, upload_pending, AuthenticatedCandidate, ClientConfig,
    ClientStore, CommitDisposition, ConfigReference, Descriptor, DescriptorRelay, DownloadOutcome,
    OwnerInbox, ReferencePhase, RelayHttp, RelayRuntime, Secret32, ThirdPass,
};
use loki_relay_protocol::{
    canonical::{self, Value},
    receipt,
    types::{
        roster_digest, Entry, Id32, LogicalKey, MessageBody, MessageRef, Object, Page, Payload,
        ReceiptBody, RelayPin, RelayRoute, Roster,
    },
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs::File,
    io::{Read, Write},
    net::{Shutdown, TcpListener, TcpStream},
    os::unix::process::ExitStatusExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

fn evidence(name: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    let directory = PathBuf::from("/private/tmp/relay-7.7-evidence").join(format!(
        "{name}-{}-{stamp}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&directory).unwrap();
    directory
}

fn roster() -> Roster {
    support::roster()
}

fn test_body(message: Id32, prerequisites: Vec<MessageRef>, payload: Vec<u8>) -> MessageBody {
    let roster = roster();
    MessageBody {
        key: LogicalKey {
            vault: roster.vault,
            roster: roster_digest(&roster).unwrap(),
            sender: 1,
            message,
        },
        audience: vec![1, 2, 3],
        session: Some([44; 32]),
        prerequisites,
        payload: Payload::Test(payload),
    }
}

fn relay_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn mailbox(owner: u8, relay: u8) -> Id32 {
    let mut id = [0; 32];
    id[0] = owner;
    id[1] = relay;
    id
}

fn run_id(relay: u8) -> Id32 {
    let mut id = [100; 32];
    id[0] = relay;
    id
}

fn route_for(owner: u8, relay: u8, port: u16, key: &SigningKey) -> RelayRoute {
    RelayRoute {
        pin: RelayPin {
            key: key.verifying_key().to_bytes(),
            run: run_id(relay),
        },
        endpoint: format!("http://127.0.0.1:{port}"),
        mailbox: mailbox(owner, relay),
        append_revision: 1,
    }
}

fn signed_receipt(
    key: &SigningKey,
    route: &RelayRoute,
    hash: Id32,
    wire_length: u64,
    sequence: u64,
) -> Vec<u8> {
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
        Value::Bytes(key.sign(&input).to_bytes().to_vec()),
    ]))
    .unwrap()
}

fn capture_cached(
    store: &mut ClientStore,
    route: &RelayRoute,
    key: &SigningKey,
    object: &Object,
    sequence: u64,
) {
    let entry = Entry {
        sequence,
        hash: object.hash,
        wire_length: object.wire.len() as u64,
        receipt: signed_receipt(key, route, object.hash, object.wire.len() as u64, sequence),
    };
    store
        .capture_page(
            route,
            &Page {
                mailbox: route.mailbox,
                after: sequence - 1,
                next: sequence,
                high_water: sequence,
                entries: vec![entry],
            },
            &[DownloadOutcome::Cached(object.clone())],
        )
        .expect("cached directory entry");
}

fn same_wire(left: &[u8], right: &[u8]) -> bool {
    left == right
}

fn scrub_library_output(text: &str) -> String {
    let tail = text.chars().rev().take(2000).collect::<String>();
    let tail = tail.chars().rev().collect::<String>();
    tail.lines()
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            !lower.contains("bearer ") && !lower.contains("authorization:")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn library_case(name: &str) {
    let output = Command::new(env!("CARGO"))
        .args([
            "test",
            "--manifest-path",
            concat!(env!("CARGO_MANIFEST_DIR"), "/../Cargo.toml"),
            "-p",
            "loki-relay-client",
            "--locked",
            "--offline",
            "--lib",
            name,
            "--",
            "--exact",
            "--nocapture",
        ])
        .env("CARGO_TERM_COLOR", "never")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let result = stdout
        .lines()
        .rev()
        .find(|line| line.contains("test result:"))
        .unwrap_or("missing test result");
    if output.status.success() && stdout.contains("1 passed; 0 failed") {
        println!("{result}");
        return;
    }
    panic!(
        "library fault case failed: {name}\n{}\n{}",
        scrub_library_output(&stdout),
        scrub_library_output(&stderr)
    );
}

#[test]
fn incoming_crash_partial_and_quarantine_create_no_received() {
    let roster = roster();
    let alice = support::identity(1);
    let bob = support::identity(2);
    let prepared = prepare_outbox(
        &alice,
        &roster,
        &test_body([35; 32], Vec::new(), vec![7; 80_000]),
    )
    .unwrap();
    let bob_copy = prepared
        .recipients()
        .iter()
        .find(|recipient| recipient.recipient() == 2)
        .unwrap();
    assert!(
        bob_copy.objects().len() > 1,
        "80_000-byte payload stayed a single object"
    );
    let chunk = &bob_copy.objects()[0];
    let route = route_for(2, 0, 9, &relay_key(9));
    let key = relay_key(9);
    let mut store = ClientStore::open(&evidence("partial").join("client"), &roster, 2).unwrap();
    let bad = Entry {
        sequence: 2,
        hash: [45; 32],
        wire_length: 100,
        receipt: vec![1, 2, 3],
    };
    let good = Entry {
        sequence: 1,
        hash: chunk.hash,
        wire_length: chunk.wire.len() as u64,
        receipt: signed_receipt(&key, &route, chunk.hash, chunk.wire.len() as u64, 1),
    };
    store
        .capture_page(
            &route,
            &Page {
                mailbox: route.mailbox,
                after: 0,
                next: 2,
                high_water: 2,
                entries: vec![good, bad],
            },
            &[DownloadOutcome::Cached(chunk.clone())],
        )
        .unwrap();
    let journal = store.recover_journal(&route, 0, 100).unwrap();
    assert_eq!(journal[0].disposition, "cached");
    assert_eq!(journal[1].disposition, "quarantine");
    assert_eq!(journal[1].reason, "length");
    assert!(store.saved_object(&[45; 32]).unwrap().is_none());
    assert!(
        authenticate_staged(&mut store, &roster, &bob).unwrap().is_empty(),
        "partial chunk or quarantined length produced a Received candidate"
    );
    assert!(store.recover_ack_links(0, 100).unwrap().is_empty());
    assert!(store.recover_incoming_originals(0, 100).unwrap().is_empty());
}

#[test]
fn incoming_crash_self_and_received_create_no_ack_received_atomic() {
    let roster = roster();
    let alice = support::identity(1);
    let carol = support::identity(3);
    let own_body = test_body([36; 32], Vec::new(), vec![19, 29, 39]);
    let own = prepare_outbox(&alice, &roster, &own_body).unwrap();
    let alice_object = own
        .recipients()
        .iter()
        .find(|recipient| recipient.recipient() == 1)
        .unwrap()
        .objects()[0]
        .clone();
    let mut alice_store = ClientStore::open(&evidence("self").join("client"), &roster, 1).unwrap();
    let route = route_for(1, 0, 9, &relay_key(9));
    capture_cached(&mut alice_store, &route, &relay_key(9), &alice_object, 1);
    let candidates = authenticate_staged(&mut alice_store, &roster, &alice).unwrap();
    assert_eq!(candidates.len(), 1);
    assert!(
        prepare_received(
            &alice_store,
            &alice,
            &roster,
            candidates[0].message(),
            candidates[0].source()
        )
        .unwrap()
        .is_none(),
        "author self-copy prepared an acknowledgement"
    );
    alice_store
        .commit_outbox(&roster, &alice, &[21; 32], &own)
        .unwrap();
    assert_eq!(
        alice_store
            .commit_incoming(&roster, &alice, candidates[0].source(), candidates[0].message(), None)
            .unwrap(),
        CommitDisposition::Duplicate
    );
    assert!(
        alice_store.recover_ack_links(0, 100).unwrap().is_empty(),
        "author self-copy wrote an acknowledgement link"
    );

    let target = MessageRef {
        sender: 1,
        message: [38; 32],
        digest: [39; 32],
    };
    let received = MessageBody {
        key: LogicalKey {
            vault: roster.vault,
            roster: roster_digest(&roster).unwrap(),
            sender: 2,
            message: [37; 32],
        },
        audience: vec![1, 2, 3],
        session: Some([44; 32]),
        prerequisites: vec![target.clone()],
        payload: Payload::Received(target),
    };
    let prepared = prepare_outbox(&support::identity(2), &roster, &received).unwrap();
    let carol_object = prepared
        .recipients()
        .iter()
        .find(|recipient| recipient.recipient() == 3)
        .unwrap()
        .objects()[0]
        .clone();
    let mut carol_store = ClientStore::open(&evidence("received-kind").join("client"), &roster, 3).unwrap();
    let carol_route = route_for(3, 0, 9, &relay_key(10));
    capture_cached(&mut carol_store, &carol_route, &relay_key(10), &carol_object, 1);
    let candidates = authenticate_staged(&mut carol_store, &roster, &carol).unwrap();
    assert_eq!(candidates.len(), 1);
    assert!(prepare_received(
        &carol_store,
        &carol,
        &roster,
        candidates[0].message(),
        candidates[0].source()
    )
    .unwrap()
    .is_none());
    assert_eq!(
        carol_store
            .commit_incoming(&roster, &carol, candidates[0].source(), candidates[0].message(), None)
            .unwrap(),
        CommitDisposition::New
    );
    let originals = carol_store.recover_incoming_originals(0, 100).unwrap();
    assert_eq!(originals.len(), 1);
    assert_eq!(originals[0].kind, 2);
    assert!(
        carol_store.recover_ack_links(0, 100).unwrap().is_empty(),
        "an incoming Received message generated another acknowledgement"
    );
}

#[test]
fn incoming_crash_missing_prerequisite_still_commits_ack_received_atomic() {
    let roster = roster();
    let alice = support::identity(1);
    let bob = support::identity(2);
    let missing = MessageRef {
        sender: 3,
        message: [32; 32],
        digest: [33; 32],
    };
    let prepared = prepare_outbox(
        &alice,
        &roster,
        &test_body([31; 32], vec![missing.clone()], vec![19, 29, 39]),
    )
    .unwrap();
    let object = prepared
        .recipients()
        .iter()
        .find(|recipient| recipient.recipient() == 2)
        .unwrap()
        .objects()[0]
        .clone();
    let mut store = ClientStore::open(&evidence("prereq").join("client"), &roster, 2).unwrap();
    let route = route_for(2, 0, 9, &relay_key(9));
    capture_cached(&mut store, &route, &relay_key(9), &object, 1);
    let candidates = authenticate_staged(&mut store, &roster, &bob).unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].readiness(), loki_relay_client::CandidateReadiness::Pending);
    let ack = prepare_received(&store, &bob, &roster, candidates[0].message(), candidates[0].source())
        .unwrap()
        .expect("complete foreign test with a missing application prerequisite");
    assert_eq!(
        store
            .commit_incoming(&roster, &bob, candidates[0].source(), candidates[0].message(), Some(&ack))
            .unwrap(),
        CommitDisposition::New
    );
    let links = store.recover_ack_links(0, 100).unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].ack_author, 2);
    assert_eq!(links[0].ack_message, ack.key().message);
    let dependencies = store.recover_dependencies(0, 100).unwrap();
    assert_eq!(dependencies.len(), 1);
    assert_eq!(dependencies[0].prerequisite.message, missing.message);
    assert_eq!(dependencies[0].prerequisite.digest, missing.digest);
    assert_eq!(dependencies[0].prerequisite_source, None);
    assert_eq!(dependencies[0].phase, ReferencePhase::Pending);
    let recipients = store.recover_recipients(ack.key()).unwrap();
    assert!(recipients.iter().all(|recipient| recipient.needs_route));
    assert_eq!(
        recipients
            .iter()
            .map(|recipient| recipient.recipient)
            .collect::<Vec<_>>(),
        vec![1, 2, 3],
        "missing prerequisite withheld one of the three acknowledgement copies"
    );
    assert_eq!(ack.recipients().len(), 3);
    assert!(store.recover_uploads(0, 100).unwrap().is_empty());
    for recipient in ack.recipients() {
        let saved_recipient = recipients
            .iter()
            .find(|row| row.recipient == recipient.recipient())
            .expect("acknowledgement recipient missing");
        assert!(saved_recipient.needs_route);
        assert!(saved_recipient.transfer.is_none());
        assert_eq!(saved_recipient.root_hash, *recipient.root_hash());
        for object in recipient.objects() {
            let saved = store.saved_object(&object.hash).unwrap().unwrap();
            assert!(same_wire(&saved.wire, &object.wire));
        }
    }
}

#[test]
fn incoming_crash_reordered_relays_one_ack_link_received_atomic() {
    let roster = roster();
    let alice = support::identity(1);
    let bob = support::identity(2);
    let prepared = prepare_outbox(&alice, &roster, &test_body([34; 32], Vec::new(), vec![19, 29, 39])).unwrap();
    let object = prepared
        .recipients()
        .iter()
        .find(|recipient| recipient.recipient() == 2)
        .unwrap()
        .objects()[0]
        .clone();
    let mut store = ClientStore::open(&evidence("reorder").join("client"), &roster, 2).unwrap();
    for relay in [11u8, 9, 10] {
        let key = relay_key(relay);
        let route = route_for(2, relay - 9, 9, &key);
        capture_cached(&mut store, &route, &key, &object, 1);
        let journal = store.recover_journal(&route, 0, 100).unwrap();
        assert_eq!(journal.len(), 1);
        assert_eq!(journal[0].source_hash, object.hash);
        assert_eq!(journal[0].disposition, "cached");
    }
    let saved = store.saved_object(&object.hash).unwrap().unwrap();
    assert!(same_wire(&saved.wire, &object.wire));
    let candidates = authenticate_staged(&mut store, &roster, &bob).unwrap();
    assert_eq!(candidates.len(), 1, "three relay deliveries became several candidates");
    let ack = prepare_received(&store, &bob, &roster, candidates[0].message(), candidates[0].source())
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .commit_incoming(&roster, &bob, candidates[0].source(), candidates[0].message(), Some(&ack))
            .unwrap(),
        CommitDisposition::New
    );
    assert!(
        prepare_received(&store, &bob, &roster, candidates[0].message(), candidates[0].source())
            .unwrap()
            .is_none(),
        "duplicate original sealed a second acknowledgement"
    );
    let recipients = store.recover_recipients(ack.key()).unwrap();
    assert_eq!(
        recipients
            .iter()
            .map(|row| row.recipient)
            .collect::<Vec<_>>(),
        vec![1, 2, 3],
        "unbound routes withheld an acknowledgement copy"
    );
    assert!(recipients
        .iter()
        .all(|row| row.needs_route && row.transfer.is_none()));
    assert!(
        store.recover_dependencies(0, 100).unwrap().is_empty(),
        "empty prerequisites were stored as a missing application dependency"
    );
    assert!(store.recover_uploads(0, 100).unwrap().is_empty());
    assert_eq!(
        store
            .commit_incoming(&roster, &bob, candidates[0].source(), candidates[0].message(), Some(&ack))
            .unwrap(),
        CommitDisposition::Duplicate
    );
    assert_eq!(
        store
            .commit_incoming(&roster, &bob, candidates[0].source(), candidates[0].message(), None)
            .unwrap(),
        CommitDisposition::Duplicate
    );
    let links = store.recover_ack_links(0, 100).unwrap();
    assert_eq!(links.len(), 1, "reordered relay deliveries wrote a second acknowledgement");
    assert_eq!(links[0].ack_message, ack.key().message);
    assert_eq!(store.recover_incoming_originals(0, 100).unwrap().len(), 1);
    assert_eq!(store.recover_logical(0, 100).unwrap().len(), 1);
    for recipient in ack.recipients() {
        for object in recipient.objects() {
            let saved = store.saved_object(&object.hash).unwrap().unwrap();
            assert!(same_wire(&saved.wire, &object.wire));
        }
    }
}

#[test]
fn incoming_crash_original_ack_sqlite_full_received_atomic() {
    // Genuine SQLITE_FULL is the writer connection's max_page_count, observed on the
    // acknowledgement ciphertext insert before ClientError mapping. The library owns that case.
    library_case("store::incoming_crash_tests::incoming_crash_original_ack_sqlite_full");
}

fn write_identity(directory: &Path, lines: &[String]) {
    let mut file = File::create(directory.join("identity.txt")).unwrap();
    for line in lines {
        writeln!(file, "{line}").unwrap();
    }
    file.sync_all().unwrap();
}

fn commit_foreign(root: &Path) -> (ClientStore, [u8; 32], [u8; 32], [u8; 32], Vec<(Id32, Vec<u8>)>) {
    let roster = roster();
    let alice = support::identity(1);
    let bob = support::identity(2);
    let prepared = prepare_outbox(&alice, &roster, &test_body([40; 32], Vec::new(), vec![19, 29, 39])).unwrap();
    let object = prepared
        .recipients()
        .iter()
        .find(|recipient| recipient.recipient() == 2)
        .unwrap()
        .objects()[0]
        .clone();
    let mut store = ClientStore::open(root, &roster, 2).unwrap();
    let key = relay_key(9);
    capture_cached(&mut store, &route_for(2, 0, 9, &key), &key, &object, 1);
    let candidates = authenticate_staged(&mut store, &roster, &bob).unwrap();
    let ack = prepare_received(&store, &bob, &roster, candidates[0].message(), candidates[0].source())
        .unwrap()
        .unwrap();
    assert_eq!(
        store
            .commit_incoming(&roster, &bob, candidates[0].source(), candidates[0].message(), Some(&ack))
            .unwrap(),
        CommitDisposition::New
    );
    let link = store.recover_ack_links(0, 100).unwrap().pop().unwrap();
    let mut wires = Vec::new();
    for recipient in ack.recipients() {
        for object in recipient.objects() {
            let saved = store.saved_object(&object.hash).unwrap().unwrap();
            assert!(same_wire(&saved.wire, &object.wire));
            wires.push((object.hash, object.wire.clone()));
        }
    }
    (store, link.ack_message, link.request_id, link.digest, wires)
}

#[test]
#[ignore]
fn incoming_crash_postcommit_child() {
    let root = PathBuf::from(std::env::var("INCOMING_CRASH_ROOT").unwrap());
    let directory = root.parent().unwrap().to_path_buf();
    let (_store, ack_message, request_id, digest, wires) = commit_foreign(&root);
    let wire_dir = directory.join("wires");
    std::fs::create_dir_all(&wire_dir).unwrap();
    for (hash, wire) in &wires {
        let mut file = File::create(wire_dir.join(hex::encode(hash))).unwrap();
        file.write_all(wire).unwrap();
        file.sync_all().unwrap();
    }
    write_identity(
        &directory,
        &[
            "process-termination-after-original-ack-commit".to_string(),
            hex::encode(ack_message),
            hex::encode(request_id),
            hex::encode(digest),
            wires.len().to_string(),
        ],
    );
    let mut barrier = File::create(directory.join("barrier")).unwrap();
    writeln!(barrier, "process-termination-after-original-ack-commit").unwrap();
    barrier.sync_all().unwrap();
    thread::sleep(Duration::from_secs(30));
}

const REAP_WAIT: Duration = Duration::from_secs(5);

struct OwnedChild(Child);

impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = wait_bounded(&mut self.0, REAP_WAIT);
    }
}

fn wait_bounded(child: &mut Child, limit: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + limit;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
            _ => return None,
        }
    }
}

fn scrub_log(path: &Path) -> String {
    let bytes = std::fs::read(path).unwrap_or_default();
    let start = bytes.len().saturating_sub(2000);
    String::from_utf8_lossy(&bytes[start..])
        .lines()
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            !lower.contains("bearer ") && !lower.contains("authorization:")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn incoming_crash_postcommit_reopens_same_ack() {
    let directory = evidence("postcommit");
    let root = directory.join("client");
    let log_path = directory.join("child.log");
    let log = File::create(&log_path).unwrap();
    let child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "incoming_crash_postcommit_child",
            "--ignored",
            "--nocapture",
        ])
        .env("INCOMING_CRASH_ROOT", &root)
        .stdout(Stdio::from(log.try_clone().unwrap()))
        .stderr(Stdio::from(log))
        .spawn()
        .unwrap();
    let mut child = OwnedChild(child);
    let started = Instant::now();
    let barrier = directory.join("barrier");
    loop {
        if barrier.is_file() {
            break;
        }
        if child.0.try_wait().unwrap().is_some() {
            panic!(
                "process-termination child exited before the barrier\n{}",
                scrub_log(&log_path)
            );
        }
        if started.elapsed() > Duration::from_secs(20) {
            panic!(
                "postcommit barrier was not reached\n{}",
                scrub_log(&log_path)
            );
        }
        thread::sleep(Duration::from_millis(50));
    }
    child.0.kill().unwrap();
    let status = wait_bounded(&mut child.0, REAP_WAIT).expect("fixture child was not reaped");
    assert_eq!(
        status.signal(),
        Some(9),
        "process-termination-after-original-ack-commit did not kill the fixture child"
    );
    let identity = std::fs::read_to_string(directory.join("identity.txt")).unwrap();
    let mut lines = identity.lines();
    assert_eq!(lines.next(), Some("process-termination-after-original-ack-commit"));
    let ack_message = hex::decode(lines.next().unwrap()).unwrap();
    let request_id = hex::decode(lines.next().unwrap()).unwrap();
    let digest = hex::decode(lines.next().unwrap()).unwrap();
    let count: usize = lines.next().unwrap().parse().unwrap();
    let store = ClientStore::open(&root, &roster(), 2).unwrap();
    let links = store.recover_ack_links(0, 100).unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].ack_message.as_slice(), ack_message.as_slice());
    assert_eq!(links[0].request_id.as_slice(), request_id.as_slice());
    assert_eq!(links[0].digest.as_slice(), digest.as_slice());
    assert_eq!(store.recover_incoming_originals(0, 100).unwrap().len(), 1);
    let mut seen = 0;
    for entry in std::fs::read_dir(directory.join("wires")).unwrap() {
        let entry = entry.unwrap();
        let hash = hex::decode(entry.file_name().to_string_lossy().as_bytes()).unwrap();
        let expected = std::fs::read(entry.path()).unwrap();
        let saved = store
            .saved_object(&hash.try_into().unwrap())
            .unwrap()
            .unwrap();
        assert!(
            same_wire(&saved.wire, &expected),
            "process-termination-after-original-ack-commit changed an acknowledgement wire"
        );
        seen += 1;
    }
    assert_eq!(seen, count);
}

const HEADER_CAP: usize = 8192;
const BODY_CAP: usize = 65536;
const SOCKET_WAIT: Duration = Duration::from_secs(2);

struct SavedPut {
    body: Vec<u8>,
    receipt: Vec<u8>,
    sequence: u64,
    hits: u64,
}

struct PeerState {
    saved: HashMap<(Id32, Id32), SavedPut>,
    sequences: HashMap<Id32, u64>,
    quota: u64,
}

struct PeerShot {
    sequence: u64,
    hits: u64,
    receipt: Vec<u8>,
    wire_len: u64,
}

/// Scripted HTTP peer. It is not a relay process.
struct LossyServer {
    port: u16,
    stop: Arc<AtomicBool>,
    state: Arc<Mutex<PeerState>>,
    thread: Option<thread::JoinHandle<()>>,
}

impl LossyServer {
    fn start(seeds: [[u8; 32]; 3]) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let state = Arc::new(Mutex::new(PeerState {
            saved: HashMap::new(),
            sequences: HashMap::new(),
            quota: 0,
        }));
        let thread_stop = Arc::clone(&stop);
        let thread_state = Arc::clone(&state);
        let thread = thread::spawn(move || serve(listener, seeds, thread_stop, thread_state));
        Self {
            port,
            stop,
            state,
            thread: Some(thread),
        }
    }

    fn entries(&self) -> u64 {
        self.state.lock().unwrap().saved.len() as u64
    }

    fn quota(&self) -> u64 {
        self.state.lock().unwrap().quota
    }

    fn shot(&self, mailbox: &Id32, hash: &Id32) -> Option<PeerShot> {
        let state = self.state.lock().unwrap();
        state.saved.get(&(*mailbox, *hash)).map(|saved| PeerShot {
            sequence: saved.sequence,
            hits: saved.hits,
            receipt: saved.receipt.clone(),
            wire_len: saved.body.len() as u64,
        })
    }

    fn body_matches(&self, mailbox: &Id32, hash: &Id32, body: &[u8]) -> bool {
        self.state
            .lock()
            .unwrap()
            .saved
            .get(&(*mailbox, *hash))
            .is_some_and(|saved| saved.body == body)
    }
}

impl Drop for LossyServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn header_value<'a>(headers: &'a str, name: &str) -> Option<&'a str> {
    headers.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

fn read_put(stream: &mut TcpStream) -> Option<(Id32, Id32, Vec<u8>)> {
    stream.set_nonblocking(false).ok()?;
    stream.set_read_timeout(Some(SOCKET_WAIT)).ok()?;
    stream.set_write_timeout(Some(SOCKET_WAIT)).ok()?;
    let mut header = Vec::new();
    let mut byte = [0u8; 1];
    while header.len() < HEADER_CAP {
        if stream.read(&mut byte).ok()? == 0 {
            return None;
        }
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if !header.ends_with(b"\r\n\r\n") {
        return None;
    }
    let headers = String::from_utf8_lossy(&header);
    let content_length = header_value(&headers, "content-length")?.parse::<usize>().ok()?;
    if content_length > BODY_CAP {
        return None;
    }
    let mut body = vec![0u8; content_length];
    stream.read_exact(&mut body).ok()?;
    let path = headers.lines().next()?.split_whitespace().nth(1)?;
    let mut parts = path.split('/');
    if parts.next() != Some("") || parts.next() != Some("v1") || parts.next() != Some("mailboxes") {
        return None;
    }
    let mailbox = hex::decode(parts.next()?).ok()?;
    if parts.next() != Some("objects") {
        return None;
    }
    let hash = hex::decode(parts.next()?).ok()?;
    Some((mailbox.try_into().ok()?, hash.try_into().ok()?, body))
}

fn write_receipt(stream: &mut TcpStream, receipt: &[u8]) {
    let response = format!(
        "HTTP/1.1 201 Created\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        receipt.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.write_all(receipt);
    let _ = stream.shutdown(Shutdown::Both);
}

fn serve(
    listener: TcpListener,
    seeds: [[u8; 32]; 3],
    stop: Arc<AtomicBool>,
    state: Arc<Mutex<PeerState>>,
) {
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((mut stream, _)) => {
                let Some((mailbox, hash, body)) = read_put(&mut stream) else {
                    continue;
                };
                if Sha256::digest(&body).as_slice() != hash {
                    let _ = stream.shutdown(Shutdown::Both);
                    continue;
                }
                let relay = usize::from(mailbox[1]);
                if relay >= seeds.len() {
                    let _ = stream.shutdown(Shutdown::Both);
                    continue;
                }
                let mut peer = state.lock().unwrap();
                let key = (mailbox, hash);
                if let Some(saved) = peer.saved.get_mut(&key) {
                    if saved.body != body {
                        drop(peer);
                        let _ = stream.shutdown(Shutdown::Both);
                        continue;
                    }
                    saved.hits += 1;
                    let receipt = saved.receipt.clone();
                    drop(peer);
                    write_receipt(&mut stream, &receipt);
                    continue;
                }
                let sequence = peer.sequences.entry(mailbox).or_insert(0);
                *sequence += 1;
                let sequence = *sequence;
                let signer = SigningKey::from_bytes(&seeds[relay]);
                let route = RelayRoute {
                    pin: RelayPin {
                        key: signer.verifying_key().to_bytes(),
                        run: run_id(mailbox[1]),
                    },
                    endpoint: "http://127.0.0.1:9".to_string(),
                    mailbox,
                    append_revision: 1,
                };
                let receipt = signed_receipt(&signer, &route, hash, body.len() as u64, sequence);
                peer.quota += body.len() as u64;
                peer.saved.insert(
                    key,
                    SavedPut {
                        body,
                        receipt,
                        sequence,
                        hits: 1,
                    },
                );
                drop(peer);
                let _ = stream.shutdown(Shutdown::Both);
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(20));
            }
            Err(_) => break,
        }
    }
}

fn descriptor_for(owner: u16, port: u16, seeds: &[[u8; 32]; 3]) -> Descriptor {
    let roster = roster();
    Descriptor::new(
        roster.vault,
        roster_digest(&roster).unwrap(),
        owner,
        1,
        {
            let mut relays: Vec<_> = (0..3)
                .map(|relay| {
                    let key = SigningKey::from_bytes(&seeds[relay]);
                    DescriptorRelay {
                        route: route_for(owner as u8, relay as u8, port, &key),
                        append: Secret32::from_bytes([180 + relay as u8; 32]),
                    }
                })
                .collect();
            relays.sort_by(|left, right| left.route.pin.key.cmp(&right.route.pin.key));
            relays
        },
    )
}

fn opened(owner: u16, recipient: u16, port: u16, seeds: &[[u8; 32]; 3]) -> loki_relay_client::AuthenticatedDescriptor {
    let roster = roster();
    let sealed = seal_descriptor(
        &support::identity(owner),
        &roster,
        &descriptor_for(owner, port, seeds),
        &support::identity(recipient).public(),
    )
    .unwrap();
    open_descriptor(&support::identity(recipient), &roster, &sealed.wire).unwrap()
}

#[test]
fn incoming_crash_ack_upload_retries_same_wire_after_response_loss() {
    let roster = roster();
    let alice = support::identity(1);
    let bob = support::identity(2);
    let prepared = prepare_outbox(&alice, &roster, &test_body([41; 32], Vec::new(), vec![19, 29, 39])).unwrap();
    let object = prepared
        .recipients()
        .iter()
        .find(|recipient| recipient.recipient() == 2)
        .unwrap()
        .objects()[0]
        .clone();
    let seeds = [[21; 32], [22; 32], [23; 32]];
    let server = LossyServer::start(seeds);
    let mut store = ClientStore::open(&evidence("upload").join("client"), &roster, 2).unwrap();
    let capture_key = relay_key(9);
    capture_cached(
        &mut store,
        &route_for(2, 0, 9, &capture_key),
        &capture_key,
        &object,
        1,
    );
    let candidates = authenticate_staged(&mut store, &roster, &bob).unwrap();
    let ack = prepare_received(&store, &bob, &roster, candidates[0].message(), candidates[0].source())
        .unwrap()
        .unwrap();
    assert!(ack.recipients().iter().all(|recipient| recipient.objects().len() == 1));
    store
        .commit_incoming(&roster, &bob, candidates[0].source(), candidates[0].message(), Some(&ack))
        .unwrap();
    let mut before = HashMap::new();
    for recipient in ack.recipients() {
        for object in recipient.objects() {
            let saved = store.saved_object(&object.hash).unwrap().unwrap();
            assert!(same_wire(&saved.wire, &object.wire));
            before.insert(object.hash, object.wire.clone());
        }
    }
    let self_route = opened(2, 2, server.port, &seeds);
    let peers = vec![opened(1, 2, server.port, &seeds), opened(3, 2, server.port, &seeds)];
    let own = self_route
        .body()
        .relays
        .iter()
        .map(|relay| OwnerInbox {
            route: relay.route.clone(),
            read: Secret32::from_bytes([210; 32]),
            append: Secret32::from_bytes(*relay.append.as_bytes()),
            admin: Secret32::from_bytes([211; 32]),
        })
        .collect();
    let sealed = seal_descriptor(&bob, &roster, &descriptor_for(2, server.port, &seeds), &bob.public()).unwrap();
    store
        .record_config_revision(&ConfigReference::from_ciphertext(1, &sealed.wire).unwrap())
        .unwrap();
    let third = self_route.body().relays[2].route.pin.key;
    let config = ClientConfig { own, peers };
    let logical = store.recover_logical(0, 100).unwrap().pop().unwrap();
    store
        .bind_upload_routes(&roster, &bob, &logical, &config, &self_route)
        .unwrap();
    assert!(store
        .recover_recipients(&logical.key)
        .unwrap()
        .iter()
        .all(|recipient| !recipient.needs_route));
    let http = RelayHttp::new().unwrap();
    let runtime = RelayRuntime::new().unwrap();
    let first = runtime
        .block_on(upload_pending(
            &mut store,
            &http,
            &logical,
            &roster,
            &bob,
            &config,
            &self_route,
            10_000,
            ThirdPass::StopAfterStored,
        ))
        .unwrap();
    assert!(
        !first.stopped_third,
        "response-loss pass stopped the third relay before any receipt"
    );
    let after_loss = store.recover_uploads(0, 100).unwrap();
    assert_eq!(after_loss.len(), 9);
    let mut retry_at = 0;
    let mut retained = HashMap::new();
    let mut expected_quota = 0u64;
    for upload in &after_loss {
        let saved = store.saved_object(&upload.hash).unwrap().unwrap();
        assert!(
            same_wire(&saved.wire, &before[&upload.hash]),
            "response-loss-before-receipt changed the acknowledgement wire"
        );
        assert!(store.saved_receipt(upload).unwrap().is_none());
        assert!(!upload.acknowledged);
        assert!(
            upload.attempts >= 1,
            "response-loss-before-receipt did not schedule the original upload"
        );
        retry_at = retry_at.max(upload.retry_at);
        let shot = server
            .shot(&upload.mailbox, &upload.hash)
            .expect("scripted peer lost the first accepted put");
        assert!(
            server.body_matches(&upload.mailbox, &upload.hash, &before[&upload.hash]),
            "scripted peer stored a different body"
        );
        assert_eq!(shot.wire_len, before[&upload.hash].len() as u64);
        assert_eq!(shot.hits, 1, "response loss counted a returned duplicate");
        assert!(shot.sequence >= 1, "scripted peer did not assign a mailbox sequence");
        retained.insert((upload.mailbox, upload.hash), shot);
        expected_quota += before[&upload.hash].len() as u64;
    }
    assert_eq!(server.entries(), retained.len() as u64, "scripted peer entry count");
    assert_eq!(server.quota(), expected_quota, "scripted peer quota before retry");
    let second = runtime
        .block_on(upload_pending(
            &mut store,
            &http,
            &logical,
            &roster,
            &bob,
            &config,
            &self_route,
            retry_at,
            ThirdPass::StopAfterStored,
        ))
        .unwrap();
    assert!(second.stopped_third);
    let finished = store.recover_uploads(0, 100).unwrap();
    assert_eq!(finished.len(), 9, "retry inserted another upload row");
    for upload in &finished {
        let saved = store.saved_object(&upload.hash).unwrap().unwrap();
        assert!(
            same_wire(&saved.wire, &before[&upload.hash]),
            "acknowledgement retry changed the original wire"
        );
        if upload.relay_key == third {
            assert!(!upload.acknowledged);
            assert!(store.saved_receipt(upload).unwrap().is_none());
            let original = &retained[&(upload.mailbox, upload.hash)];
            let again = server
                .shot(&upload.mailbox, &upload.hash)
                .expect("scripted peer lost the first accepted third put");
            assert!(
                server.body_matches(&upload.mailbox, &upload.hash, &before[&upload.hash]),
                "second pass replaced the third wire"
            );
            assert_eq!(again.sequence, original.sequence, "second pass assigned a new third sequence");
            assert_eq!(again.hits, original.hits, "second pass retried the stored third pin");
            assert_eq!(again.wire_len, original.wire_len);
            assert!(
                same_wire(&again.receipt, &original.receipt),
                "second pass replaced the third receipt"
            );
        } else {
            assert!(upload.acknowledged, "retry left the original upload pending");
            let receipt = store.saved_receipt(upload).unwrap().unwrap();
            let original = &retained[&(upload.mailbox, upload.hash)];
            let again = server
                .shot(&upload.mailbox, &upload.hash)
                .expect("scripted peer lost the committed entry");
            assert_eq!(again.sequence, original.sequence, "retry assigned a new sequence");
            assert_eq!(again.hits, original.hits + 1, "duplicate did not increment only hits");
            assert_eq!(again.wire_len, original.wire_len);
            assert!(
                same_wire(&again.receipt, &original.receipt),
                "retry replaced the originally committed receipt"
            );
            assert!(
                same_wire(&receipt, &original.receipt),
                "saved receipt differs from the originally committed receipt"
            );
        }
    }
    assert_eq!(server.entries(), retained.len() as u64, "duplicate added an entry");
    assert_eq!(server.quota(), expected_quota, "duplicate consumed more quota");
    let links = store.recover_ack_links(0, 100).unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].ack_message, ack.key().message);
}

fn durable_files_hide(root: &Path, marker: &[u8]) {
    for name in [
        "client.sqlite3",
        "client.sqlite3-wal",
        "client.sqlite3-shm",
        "client.sqlite3-journal",
    ] {
        let path = root.join(name);
        if !path.exists() {
            continue;
        }
        let bytes = std::fs::read(&path).unwrap();
        assert!(
            bytes.windows(marker.len()).all(|window| window != marker),
            "durable client file kept the conflict payload"
        );
    }
}

#[test]
fn received_atomic_conflict_keeps_encrypted_source() {
    let roster = roster();
    let alice = support::identity(1);
    let bob = support::identity(2);
    let message = [51u8; 32];
    let prepared = prepare_outbox(
        &alice,
        &roster,
        &test_body(message, Vec::new(), vec![19, 29, 39]),
    )
    .unwrap();
    let object = prepared
        .recipients()
        .iter()
        .find(|recipient| recipient.recipient() == 2)
        .unwrap()
        .objects()[0]
        .clone();
    let root = evidence("conflict").join("client");
    let mut store = ClientStore::open(&root, &roster, 2).unwrap();
    let key = relay_key(9);
    let route = route_for(2, 0, 9, &key);
    capture_cached(&mut store, &route, &key, &object, 1);
    let candidates = authenticate_staged(&mut store, &roster, &bob).unwrap();
    assert_eq!(candidates.len(), 1);
    let ack = prepare_received(
        &store,
        &bob,
        &roster,
        candidates[0].message(),
        candidates[0].source(),
    )
    .unwrap()
    .expect("foreign test prepares the complete acknowledgement");
    let mut ack_members: Vec<_> = ack.recipients().iter().map(|recipient| recipient.recipient()).collect();
    ack_members.sort_unstable();
    assert_eq!(ack_members, vec![1, 2, 3]);
    assert_eq!(
        store
            .commit_incoming(
                &roster,
                &bob,
                candidates[0].source(),
                candidates[0].message(),
                Some(&ack),
            )
            .unwrap(),
        CommitDisposition::New
    );
    let originals = store.recover_incoming_originals(0, 100).unwrap();
    assert_eq!(originals.len(), 1);
    assert_eq!(originals[0].kind, 1);
    assert_eq!(originals[0].digest, *prepared.digest());
    assert_eq!(originals[0].source_root, object.hash);
    let link = store.recover_ack_links(0, 100).unwrap().pop().unwrap();
    assert_eq!(link.ack_message, ack.key().message);
    assert_eq!(link.digest, *prepared.digest());
    let recipients = store.recover_recipients(ack.key()).unwrap();
    assert_eq!(
        recipients
            .iter()
            .map(|row| row.recipient)
            .collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert!(recipients.iter().all(|row| row.needs_route));
    let ack_wires: Vec<(Id32, Vec<u8>)> = ack
        .recipients()
        .iter()
        .flat_map(|recipient| recipient.objects().iter().map(|object| (object.hash, object.wire.clone())))
        .collect();

    let marker = [0xA5u8; 32];
    let conflicted = prepare_outbox(&alice, &roster, &test_body(message, Vec::new(), marker.to_vec())).unwrap();
    assert_ne!(conflicted.digest(), prepared.digest());
    let conflict_object = conflicted
        .recipients()
        .iter()
        .find(|recipient| recipient.recipient() == 2)
        .unwrap()
        .objects()[0]
        .clone();
    assert_ne!(conflict_object.hash, object.hash);
    capture_cached(&mut store, &route, &key, &conflict_object, 2);
    let candidates = authenticate_staged(&mut store, &roster, &bob).unwrap();
    let candidate = candidates
        .iter()
        .find(|candidate| candidate.message().digest() == conflicted.digest())
        .expect("different authenticated digest");
    assert!(
        prepare_received(&store, &bob, &roster, candidate.message(), candidate.source())
            .unwrap()
            .is_none(),
        "conflicting digest prepared a replacement acknowledgement"
    );
    assert_eq!(
        store
            .commit_incoming(&roster, &bob, candidate.source(), candidate.message(), None)
            .unwrap(),
        CommitDisposition::Conflict
    );
    let originals = store.recover_incoming_originals(0, 100).unwrap();
    assert_eq!(originals.len(), 1);
    assert_eq!(originals[0].digest, *prepared.digest());
    assert_eq!(originals[0].source_root, object.hash);
    let links = store.recover_ack_links(0, 100).unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].ack_message, link.ack_message);
    assert_eq!(links[0].request_id, link.request_id);
    assert_eq!(links[0].digest, *prepared.digest());
    assert_eq!(store.recover_logical(0, 100).unwrap().len(), 1);
    for (hash, wire) in &ack_wires {
        let saved = store.saved_object(hash).unwrap().unwrap();
        assert!(same_wire(&saved.wire, wire));
    }
    let saved_original = store.saved_object(&object.hash).unwrap().unwrap();
    assert!(same_wire(&saved_original.wire, &object.wire));
    let saved_conflict = store.saved_object(&conflict_object.hash).unwrap().unwrap();
    assert!(same_wire(&saved_conflict.wire, &conflict_object.wire));
    assert!(!same_wire(&saved_conflict.wire, &object.wire));
    drop(store);

    let store = ClientStore::open(&root, &roster, 2).unwrap();
    let reopened_original = store.saved_object(&object.hash).unwrap().unwrap();
    assert!(
        same_wire(&reopened_original.wire, &object.wire),
        "reopen changed the original encrypted object"
    );
    let reopened_conflict = store.saved_object(&conflict_object.hash).unwrap().unwrap();
    assert!(
        same_wire(&reopened_conflict.wire, &conflict_object.wire),
        "reopen changed the conflict encrypted object"
    );
    assert!(!same_wire(&reopened_conflict.wire, &object.wire));
    let originals = store.recover_incoming_originals(0, 100).unwrap();
    assert_eq!(originals.len(), 1);
    assert_eq!(originals[0].digest, *prepared.digest());
    assert_eq!(originals[0].source_root, object.hash);
    let links = store.recover_ack_links(0, 100).unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].ack_message, link.ack_message);
    assert_eq!(links[0].request_id, link.request_id);
    assert_eq!(links[0].digest, *prepared.digest());
    for (hash, wire) in &ack_wires {
        let saved = store.saved_object(hash).unwrap().unwrap();
        assert!(same_wire(&saved.wire, wire));
    }
    drop(store);

    durable_files_hide(&root, &marker);
    let sql = support::sql(&root);
    let conflicts: i64 = sql
        .query_row("SELECT count(*) FROM incoming_conflicts", [], |row| row.get(0))
        .unwrap();
    assert_eq!(conflicts, 1);
    let (digest, source_root): (Vec<u8>, Vec<u8>) = sql
        .query_row(
            "SELECT digest, source_root FROM incoming_conflicts",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!(digest.as_slice(), conflicted.digest().as_slice());
    assert_eq!(source_root.as_slice(), conflict_object.hash.as_slice());
    let (ordinal, hash, wire_length): (i64, Vec<u8>, i64) = sql
        .query_row(
            "SELECT ordinal, hash, wire_length FROM incoming_conflict_objects",
            [],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
        )
        .unwrap();
    assert_eq!(ordinal, 0);
    assert_eq!(hash.as_slice(), conflict_object.hash.as_slice());
    assert_eq!(wire_length as usize, conflict_object.wire.len());
    let retained: Vec<u8> = sql
        .query_row(
            "SELECT wire FROM ciphertext_objects WHERE hash=?1",
            [conflict_object.hash.as_slice()],
            |row| row.get(0),
        )
        .unwrap();
    assert!(same_wire(&retained, &conflict_object.wire));
    let original_digest: Vec<u8> = sql
        .query_row("SELECT digest FROM incoming_originals", [], |row| row.get(0))
        .unwrap();
    assert_eq!(original_digest.as_slice(), prepared.digest().as_slice());
}

fn received_for(sender: u16, message: Id32, session: Option<Id32>, target: MessageRef) -> MessageBody {
    let roster = roster();
    MessageBody {
        key: LogicalKey {
            vault: roster.vault,
            roster: roster_digest(&roster).unwrap(),
            sender,
            message,
        },
        audience: vec![1, 2, 3],
        session,
        prerequisites: vec![target.clone()],
        payload: Payload::Received(target),
    }
}

fn only_message<'a>(candidates: &'a [AuthenticatedCandidate], message_id: &Id32) -> &'a AuthenticatedCandidate {
    let matched: Vec<_> = candidates
        .iter()
        .filter(|item| &item.message().body().key.message == message_id)
        .collect();
    assert_eq!(matched.len(), 1, "one logical message became several candidates");
    matched[0]
}

fn cache_object(store: &mut ClientStore, owner: u8, slot: u8, seed: u8, sequence: u64, object: &Object) {
    let key = relay_key(seed);
    let route = route_for(owner, slot, 9, &key);
    capture_cached(store, &route, &key, object, sequence);
    let journal = store.recover_journal(&route, 0, 100).unwrap();
    assert!(
        journal
            .iter()
            .any(|row| row.source_hash == object.hash && row.disposition == "cached"),
        "relay cache lost the exact object"
    );
    let saved = store.saved_object(&object.hash).unwrap().unwrap();
    assert!(same_wire(&saved.wire, &object.wire), "saved object bytes changed");
}

fn recipient_object(prepared: &loki_relay_client::PreparedOutbox, recipient: u16) -> Object {
    prepared
        .recipients()
        .iter()
        .find(|item| item.recipient() == recipient)
        .unwrap()
        .objects()[0]
        .clone()
}

fn alice_routes() -> (ClientConfig, loki_relay_client::AuthenticatedDescriptor) {
    let seeds = [[21; 32], [22; 32], [23; 32]];
    let self_route = opened(1, 1, 9, &seeds);
    let peers = vec![opened(2, 1, 9, &seeds), opened(3, 1, 9, &seeds)];
    let own = self_route
        .body()
        .relays
        .iter()
        .map(|relay| OwnerInbox {
            route: relay.route.clone(),
            read: Secret32::from_bytes([210; 32]),
            append: Secret32::from_bytes(*relay.append.as_bytes()),
            admin: Secret32::from_bytes([211; 32]),
        })
        .collect();
    (ClientConfig { own, peers }, self_route)
}

#[test]
fn received_reference_exact_bob_carol_independent_of_stored() {
    let roster = roster();
    let alice = support::identity(1);
    let bob = support::identity(2);
    let carol = support::identity(3);
    let original_id = [70; 32];
    let original = prepare_outbox(
        &alice,
        &roster,
        &test_body(original_id, Vec::new(), vec![7, 6, 5]),
    )
    .unwrap();
    let target = MessageRef {
        sender: 1,
        message: original_id,
        digest: *original.digest(),
    };
    let session = Some([44; 32]);
    let bob_id = [71; 32];
    let bob_received = prepare_outbox(
        &bob,
        &roster,
        &received_for(2, bob_id, session, target.clone()),
    )
    .unwrap();
    assert_eq!(bob_received.recipients().len(), 3);
    let bob_object = recipient_object(&bob_received, 1);
    let root = evidence("reference-exact").join("client");
    let mut store = ClientStore::open(&root, &roster, 1).unwrap();
    cache_object(&mut store, 1, 0, 9, 1, &bob_object);
    let staged = authenticate_staged(&mut store, &roster, &alice).unwrap();
    let bob_candidate = only_message(&staged, &bob_id);
    assert_eq!(bob_candidate.message().body().session, session);
    assert_eq!(bob_candidate.message().digest(), bob_received.digest());
    assert!(
        prepare_received(
            &store,
            &alice,
            &roster,
            bob_candidate.message(),
            bob_candidate.source()
        )
        .unwrap()
        .is_none(),
        "a Received message prepared an acknowledgement"
    );
    assert_eq!(
        store
            .commit_incoming(
                &roster,
                &alice,
                bob_candidate.source(),
                bob_candidate.message(),
                None
            )
            .unwrap(),
        CommitDisposition::New
    );
    assert_eq!(
        store
            .commit_incoming(
                &roster,
                &alice,
                bob_candidate.source(),
                bob_candidate.message(),
                None
            )
            .unwrap(),
        CommitDisposition::Duplicate
    );
    reconcile_received(&mut store, &roster, &alice).unwrap();
    let pending = received_status(&store, &roster, &alice, original.key(), original.digest()).unwrap();
    assert!(!pending.author_committed(), "missing original was already committed");
    assert!(!pending.member_received(2), "Received counted before its original");
    assert!(!pending.member_received(3));
    assert!(!pending.whole_vault());
    assert!(pending.session().is_none());
    assert!(
        store
            .recover_early_received(&roster, 1, 0, 100)
            .unwrap()
            .is_empty(),
        "a pending Received occupied the reference index"
    );
    assert!(store.recover_ack_links(0, 100).unwrap().is_empty());

    let logical = store
        .commit_outbox(&roster, &alice, &[0x76; 32], &original)
        .unwrap();
    assert_eq!(logical.key.message, original_id);
    assert_eq!(logical.digest, *original.digest());
    assert_eq!(logical.kind, 1);
    for recipient in original.recipients() {
        for object in recipient.objects() {
            let saved = store.saved_object(&object.hash).unwrap().unwrap();
            assert!(same_wire(&saved.wire, &object.wire));
        }
    }
    reconcile_received(&mut store, &roster, &alice).unwrap();
    let bob_only = received_status(&store, &roster, &alice, original.key(), original.digest()).unwrap();
    assert!(bob_only.author_committed(), "outgoing author state did not count");
    assert_eq!(bob_only.session(), session);
    assert_eq!(bob_only.digest(), original.digest());
    assert!(bob_only.member_received(2), "exact Bob Received did not activate");
    assert!(!bob_only.member_received(1), "the author counted as a peer");
    assert!(!bob_only.member_received(3));
    assert!(!bob_only.whole_vault(), "one peer completed whole-vault Received");
    let bob_history = store.recover_early_received(&roster, 1, 0, 100).unwrap();
    assert_eq!(bob_history.len(), 1);
    assert_eq!(bob_history[0].from_member, 2);
    assert_eq!(bob_history[0].digest, *original.digest());
    assert_eq!(bob_history[0].source_root, bob_object.hash);
    assert_eq!(bob_history[0].phase, ReferencePhase::Resolved);

    let carol_id = [72; 32];
    let carol_received = prepare_outbox(
        &carol,
        &roster,
        &received_for(3, carol_id, session, target.clone()),
    )
    .unwrap();
    let carol_object = recipient_object(&carol_received, 1);
    assert_ne!(carol_object.hash, bob_object.hash);
    for (slot, seed, sequence) in [(2u8, 11u8, 1u64), (0, 9, 2), (1, 10, 1)] {
        cache_object(&mut store, 1, slot, seed, sequence, &carol_object);
    }
    let staged = authenticate_staged(&mut store, &roster, &alice).unwrap();
    let carol_candidate = only_message(&staged, &carol_id);
    assert_eq!(carol_candidate.message().digest(), carol_received.digest());
    assert!(
        prepare_received(
            &store,
            &alice,
            &roster,
            carol_candidate.message(),
            carol_candidate.source()
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(
        store
            .commit_incoming(
                &roster,
                &alice,
                carol_candidate.source(),
                carol_candidate.message(),
                None
            )
            .unwrap(),
        CommitDisposition::New
    );
    assert_eq!(
        store
            .commit_incoming(
                &roster,
                &alice,
                carol_candidate.source(),
                carol_candidate.message(),
                None
            )
            .unwrap(),
        CommitDisposition::Duplicate
    );
    let originals = store.recover_incoming_originals(0, 100).unwrap();
    assert_eq!(originals.len(), 2, "relay reorder or duplicate added a logical Received");
    assert_eq!(
        originals.iter().filter(|row| row.key.message == bob_id).count(),
        1
    );
    assert_eq!(
        originals.iter().filter(|row| row.key.message == carol_id).count(),
        1
    );
    assert_eq!(
        originals
            .iter()
            .find(|row| row.key.message == carol_id)
            .unwrap()
            .source_root,
        carol_object.hash
    );
    assert!(store.recover_ack_links(0, 100).unwrap().is_empty(), "Received opened an ack loop");
    let saved_carol = store.saved_object(&carol_object.hash).unwrap().unwrap();
    assert!(same_wire(&saved_carol.wire, &carol_object.wire));

    reconcile_received(&mut store, &roster, &alice).unwrap();
    let received = received_status(&store, &roster, &alice, original.key(), original.digest()).unwrap();
    assert!(received.author_committed());
    assert!(received.member_received(2));
    assert!(received.member_received(3), "exact Carol Received did not activate");
    assert!(!received.member_received(1));
    assert!(received.whole_vault(), "Bob and Carol did not complete whole-vault Received");
    assert_eq!(received.session(), session);
    let history = store.recover_early_received(&roster, 1, 0, 100).unwrap();
    assert_eq!(history.len(), 2);
    assert!(history.iter().all(|row| row.phase == ReferencePhase::Resolved));

    let (config, self_route) = alice_routes();
    let sealed = seal_descriptor(
        &alice,
        &roster,
        &descriptor_for(1, 9, &[[21; 32], [22; 32], [23; 32]]),
        &alice.public(),
    )
    .unwrap();
    store
        .record_config_revision(&ConfigReference::from_ciphertext(1, &sealed.wire).unwrap())
        .unwrap();
    store
        .bind_upload_routes(&roster, &alice, &logical, &config, &self_route)
        .unwrap();
    let stored = store
        .delivery_report(&roster, &alice, &logical, &config, &self_route)
        .unwrap();
    assert!(!stored.whole_vault(), "original Stored became true with no receipts");
    assert_eq!(stored.key().message, original_id);
    for member in 1..=3 {
        assert!(!stored.member_stored(member), "a member Stored without a receipt");
    }
    let uploads = store.recover_uploads(0, 100).unwrap();
    assert!(!uploads.is_empty(), "original delivery had no bound routes");
    for upload in &uploads {
        assert_eq!(upload.key.message, original_id);
        assert!(!upload.acknowledged);
        assert!(store.saved_receipt(upload).unwrap().is_none());
    }
    let still = received_status(&store, &roster, &alice, original.key(), original.digest()).unwrap();
    assert!(still.whole_vault(), "Stored reporting cleared Received");
    drop(store);

    let mut store = ClientStore::open(&root, &roster, 1).unwrap();
    let (config, self_route) = alice_routes();
    let reopened_received = received_status(&store, &roster, &alice, original.key(), original.digest()).unwrap();
    assert!(reopened_received.whole_vault(), "reopen lost whole-vault Received");
    assert!(reopened_received.member_received(2));
    assert!(reopened_received.member_received(3));
    let reopened_stored = store
        .delivery_report(&roster, &alice, &logical, &config, &self_route)
        .unwrap();
    assert!(!reopened_stored.whole_vault(), "reopen invented original Stored");
    let saved_bob = store.saved_object(&bob_object.hash).unwrap().unwrap();
    assert!(same_wire(&saved_bob.wire, &bob_object.wire));
    let saved_carol = store.saved_object(&carol_object.hash).unwrap().unwrap();
    assert!(same_wire(&saved_carol.wire, &carol_object.wire));
    for recipient in original.recipients() {
        for object in recipient.objects() {
            let saved = store.saved_object(&object.hash).unwrap().unwrap();
            assert!(same_wire(&saved.wire, &object.wire));
        }
    }
}

#[test]
fn received_reference_invalid_then_same_signer_counts() {
    let roster = roster();
    let alice = support::identity(1);
    let bob = support::identity(2);
    let carol = support::identity(3);
    let original_id = [73; 32];
    let session = Some([44; 32]);
    let original = prepare_outbox(
        &alice,
        &roster,
        &test_body(original_id, Vec::new(), vec![8, 8, 8]),
    )
    .unwrap();
    let target = MessageRef {
        sender: 1,
        message: original_id,
        digest: *original.digest(),
    };
    let root = evidence("reference-invalid").join("client");
    let mut store = ClientStore::open(&root, &roster, 1).unwrap();

    let mut wrong_digest = target.clone();
    wrong_digest.digest = [0x5A; 32];
    assert_ne!(wrong_digest.digest, target.digest);
    let digest_id = [81; 32];
    let digest_received = prepare_outbox(
        &bob,
        &roster,
        &received_for(2, digest_id, session, wrong_digest),
    )
    .unwrap();
    let digest_object = recipient_object(&digest_received, 1);
    cache_object(&mut store, 1, 0, 9, 1, &digest_object);

    let decoy_id = [84; 32];
    let decoy = prepare_outbox(
        &carol,
        &roster,
        &received_for(
            3,
            decoy_id,
            session,
            MessageRef {
                sender: 3,
                message: [83; 32],
                digest: [0x11; 32],
            },
        ),
    )
    .unwrap();
    let decoy_object = recipient_object(&decoy, 1);
    cache_object(&mut store, 1, 0, 9, 2, &decoy_object);
    let type_target = MessageRef {
        sender: 3,
        message: decoy_id,
        digest: *decoy.digest(),
    };
    let type_id = [85; 32];
    let type_received = prepare_outbox(&bob, &roster, &received_for(2, type_id, session, type_target)).unwrap();
    let type_object = recipient_object(&type_received, 1);
    cache_object(&mut store, 1, 1, 10, 1, &type_object);

    let session_id = [82; 32];
    let session_received = prepare_outbox(
        &bob,
        &roster,
        &received_for(2, session_id, Some([99; 32]), target.clone()),
    )
    .unwrap();
    assert_ne!(session_received.digest(), digest_received.digest());
    let session_object = recipient_object(&session_received, 1);
    cache_object(&mut store, 1, 2, 11, 1, &session_object);

    let staged = authenticate_staged(&mut store, &roster, &alice).unwrap();
    for (message_id, prepared) in [
        (digest_id, &digest_received),
        (decoy_id, &decoy),
        (type_id, &type_received),
        (session_id, &session_received),
    ] {
        let candidate = only_message(&staged, &message_id);
        assert_eq!(candidate.message().digest(), prepared.digest());
        assert!(
            prepare_received(&store, &alice, &roster, candidate.message(), candidate.source())
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store
                .commit_incoming(&roster, &alice, candidate.source(), candidate.message(), None)
                .unwrap(),
            CommitDisposition::New
        );
    }
    reconcile_received(&mut store, &roster, &alice).unwrap();
    let absent = received_status(&store, &roster, &alice, original.key(), original.digest()).unwrap();
    assert!(!absent.author_committed(), "absent original was certified");
    assert!(!absent.member_received(2), "unknown target certified Bob");
    assert!(!absent.member_received(3), "unknown target certified Carol");
    assert!(!absent.whole_vault());
    assert!(absent.session().is_none(), "unknown target gained a session");
    assert!(
        store
            .recover_early_received(&roster, 1, 0, 100)
            .unwrap()
            .iter()
            .all(|row| row.digest != *original.digest()),
        "exact reference index recorded a Received before the original"
    );
    let pending_rejections = store.recover_source_rejections(0, 100).unwrap();
    for root_hash in [digest_object.hash, session_object.hash] {
        assert!(
            pending_rejections.iter().all(|row| row.root_hash != root_hash),
            "unknown target was rejected instead of staying pending"
        );
    }

    let logical = store
        .commit_outbox(&roster, &alice, &[0x77; 32], &original)
        .unwrap();
    assert_eq!(logical.digest, *original.digest());
    reconcile_received(&mut store, &roster, &alice).unwrap();
    let blocked = received_status(&store, &roster, &alice, original.key(), original.digest()).unwrap();
    assert!(blocked.author_committed());
    assert!(!blocked.member_received(2), "a mismatched Bob reference counted");
    assert!(!blocked.member_received(3), "a non-test target counted as Carol");
    assert!(!blocked.whole_vault());
    let rejections = store.recover_source_rejections(0, 100).unwrap();
    for (root, reason) in [
        (digest_object.hash, "digest"),
        (type_object.hash, "type"),
        (session_object.hash, "session"),
    ] {
        assert!(
            rejections
                .iter()
                .any(|row| row.root_hash == root && row.reason == reason),
            "missing {reason} rejection"
        );
    }
    assert!(
        store
            .recover_early_received(&roster, 1, 0, 100)
            .unwrap()
            .iter()
            .all(|row| row.digest != *original.digest() || row.from_member != 2),
        "invalid Bob association occupied the exact reference index"
    );

    let good_id = [86; 32];
    let good = prepare_outbox(&bob, &roster, &received_for(2, good_id, session, target.clone())).unwrap();
    let good_object = recipient_object(&good, 1);
    cache_object(&mut store, 1, 0, 9, 3, &good_object);
    let staged = authenticate_staged(&mut store, &roster, &alice).unwrap();
    let good_candidate = only_message(&staged, &good_id);
    assert_eq!(good_candidate.message().digest(), good.digest());
    assert_eq!(
        store
            .commit_incoming(
                &roster,
                &alice,
                good_candidate.source(),
                good_candidate.message(),
                None
            )
            .unwrap(),
        CommitDisposition::New
    );
    assert_eq!(
        store
            .commit_incoming(
                &roster,
                &alice,
                good_candidate.source(),
                good_candidate.message(),
                None
            )
            .unwrap(),
        CommitDisposition::Duplicate
    );
    reconcile_received(&mut store, &roster, &alice).unwrap();
    let status = received_status(&store, &roster, &alice, original.key(), original.digest()).unwrap();
    assert!(
        status.member_received(2),
        "earlier invalid Bob association poisoned the later Received"
    );
    assert!(!status.member_received(3));
    assert!(!status.whole_vault());
    assert_eq!(status.session(), session);
    let history = store.recover_early_received(&roster, 1, 0, 100).unwrap();
    let bob_rows: Vec<_> = history
        .iter()
        .filter(|row| row.from_member == 2 && row.digest == *original.digest())
        .collect();
    assert_eq!(bob_rows.len(), 1);
    assert_eq!(bob_rows[0].source_root, good_object.hash);
    assert_eq!(bob_rows[0].phase, ReferencePhase::Resolved);
    reconcile_received(&mut store, &roster, &alice).unwrap();
    let again = received_status(&store, &roster, &alice, original.key(), original.digest()).unwrap();
    assert!(again.member_received(2));
    assert_eq!(
        store
            .recover_incoming_originals(0, 100)
            .unwrap()
            .iter()
            .filter(|row| row.key.message == good_id)
            .count(),
        1
    );
    assert!(store.recover_ack_links(0, 100).unwrap().is_empty());

    let mut bob_store = ClientStore::open(&evidence("reference-author").join("client"), &roster, 2).unwrap();
    let alice_object = recipient_object(&original, 2);
    cache_object(&mut bob_store, 2, 0, 9, 1, &alice_object);
    let staged = authenticate_staged(&mut bob_store, &roster, &bob).unwrap();
    let alice_candidate = only_message(&staged, &original_id);
    let ack = prepare_received(
        &bob_store,
        &bob,
        &roster,
        alice_candidate.message(),
        alice_candidate.source(),
    )
    .unwrap()
    .expect("foreign test");
    assert_eq!(
        bob_store
            .commit_incoming(
                &roster,
                &bob,
                alice_candidate.source(),
                alice_candidate.message(),
                Some(&ack)
            )
            .unwrap(),
        CommitDisposition::New
    );
    let author_id = [91; 32];
    let author_received = prepare_outbox(
        &alice,
        &roster,
        &received_for(1, author_id, session, target.clone()),
    )
    .unwrap();
    let author_object = recipient_object(&author_received, 2);
    cache_object(&mut bob_store, 2, 0, 9, 2, &author_object);
    let staged = authenticate_staged(&mut bob_store, &roster, &bob).unwrap();
    let author_candidate = only_message(&staged, &author_id);
    assert_eq!(author_candidate.message().digest(), author_received.digest());
    assert!(
        prepare_received(
            &bob_store,
            &bob,
            &roster,
            author_candidate.message(),
            author_candidate.source()
        )
        .unwrap()
        .is_none()
    );
    assert_eq!(
        bob_store
            .commit_incoming(
                &roster,
                &bob,
                author_candidate.source(),
                author_candidate.message(),
                None
            )
            .unwrap(),
        CommitDisposition::New
    );
    reconcile_received(&mut bob_store, &roster, &bob).unwrap();
    let author_status = received_status(
        &bob_store,
        &roster,
        &bob,
        &alice_candidate.message().body().key,
        alice_candidate.message().digest(),
    )
    .unwrap();
    assert!(author_status.author_committed());
    assert!(!author_status.member_received(1), "original author counted as Received");
    assert!(author_status.member_received(2), "Bob's committed acknowledgement did not count");
    assert!(!author_status.member_received(3));
    assert!(!author_status.whole_vault());
    assert!(
        bob_store
            .recover_source_rejections(0, 100)
            .unwrap()
            .iter()
            .any(|row| row.root_hash == author_object.hash && row.reason == "author")
    );
    assert_eq!(bob_store.recover_ack_links(0, 100).unwrap().len(), 1);
    let saved_author = bob_store.saved_object(&author_object.hash).unwrap().unwrap();
    assert!(same_wire(&saved_author.wire, &author_object.wire));
    drop(store);

    let store = ClientStore::open(&root, &roster, 1).unwrap();
    let reopened = received_status(&store, &roster, &alice, original.key(), original.digest()).unwrap();
    assert!(reopened.author_committed());
    assert!(reopened.member_received(2), "reopen lost the later good Bob Received");
    assert!(!reopened.member_received(3));
    assert!(!reopened.whole_vault());
    assert_eq!(reopened.session(), session);
    let saved_good = store.saved_object(&good_object.hash).unwrap().unwrap();
    assert!(same_wire(&saved_good.wire, &good_object.wire), "reopen changed the good Received");
    let reopened_rejections = store.recover_source_rejections(0, 100).unwrap();
    for (root_hash, reason) in [
        (digest_object.hash, "digest"),
        (type_object.hash, "type"),
        (session_object.hash, "session"),
    ] {
        assert!(
            reopened_rejections
                .iter()
                .any(|row| row.root_hash == root_hash && row.reason == reason),
            "reopen lost the {reason} rejection"
        );
    }
    let reopened_history = store.recover_early_received(&roster, 1, 0, 100).unwrap();
    let reopened_bob: Vec<_> = reopened_history
        .iter()
        .filter(|row| row.from_member == 2 && row.digest == *original.digest())
        .collect();
    assert_eq!(reopened_bob.len(), 1);
    assert_eq!(reopened_bob[0].source_root, good_object.hash);
}
