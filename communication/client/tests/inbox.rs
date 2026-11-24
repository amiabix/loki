mod support;

use ed25519_dalek::{Signer, SigningKey};
use loki_relay_client::{ClientError, ClientStore, DownloadOutcome};
use loki_relay_protocol::{
    canonical::{self, Value},
    receipt,
    types::{Entry, Id32, Object, Page, ReceiptBody, RelayPin, RelayRoute},
};
use sha2::{Digest, Sha256};
use std::{
    fs,
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
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
    fs::create_dir_all(&directory).unwrap();
    directory.join("client")
}

fn signer() -> SigningKey {
    SigningKey::from_bytes(&[9; 32])
}

fn route() -> RelayRoute {
    RelayRoute {
        pin: RelayPin {
            key: signer().verifying_key().to_bytes(),
            run: [2; 32],
        },
        endpoint: "http://127.0.0.1:9".to_string(),
        mailbox: [3; 32],
        append_revision: 1,
    }
}

fn framed(mark: u8) -> Object {
    let mut wire = vec![mark; 1024];
    wire[..8].copy_from_slice(b"LOKIRLY1");
    wire[8] = 1;
    wire[9] = mark;
    Object {
        hash: Sha256::digest(&wire).into(),
        wire,
    }
}

fn receipt(route: &RelayRoute, hash: Id32, wire_length: u64, sequence: u64) -> Vec<u8> {
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

fn entry(route: &RelayRoute, object: &Object, sequence: u64) -> Entry {
    Entry {
        sequence,
        hash: object.hash,
        wire_length: object.wire.len() as u64,
        receipt: receipt(route, object.hash, object.wire.len() as u64, sequence),
    }
}

fn page(route: &RelayRoute, after: u64, entries: Vec<Entry>) -> Page {
    let next = entries.last().map(|entry| entry.sequence).unwrap_or(after);
    Page {
        mailbox: route.mailbox,
        after,
        next,
        high_water: next,
        entries,
    }
}

fn open_owner() -> (PathBuf, ClientStore) {
    let root = evidence("inbox");
    let store = ClientStore::open(&root, &support::roster(), 2).unwrap();
    (root, store)
}

fn cursor(store: &ClientStore, route: &RelayRoute) -> Option<u64> {
    store
        .recover_route_cursors(0, 100)
        .unwrap()
        .into_iter()
        .find(|cursor| {
            cursor.relay_key == route.pin.key
                && cursor.run == route.pin.run
                && cursor.mailbox == route.mailbox
        })
        .map(|cursor| cursor.position)
}

fn wires_match(store: &ClientStore, object: &Object) {
    let saved = store
        .saved_object(&object.hash)
        .unwrap()
        .expect("cached ciphertext missing");
    assert_eq!(saved.hash, object.hash);
    assert!(
        saved.wire == object.wire,
        "cached wire differs from the captured object"
    );
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
fn incoming_crash_capture_atomic_gap_page_leaves_cursor_zero() {
    let route = route();
    let first = framed(1);
    let third = framed(3);
    let skipped = page(
        &route,
        0,
        vec![entry(&route, &first, 1), entry(&route, &third, 3)],
    );
    let (_root, mut store) = open_owner();
    let error = store.capture_page(
        &route,
        &skipped,
        &[
            DownloadOutcome::Cached(first.clone()),
            DownloadOutcome::Cached(third.clone()),
        ],
    );
    assert!(
        matches!(error, Err(ClientError::Wire(_))),
        "a gap between directory positions 1 and 3 advanced capture"
    );
    assert_eq!(cursor(&store, &route), None, "gap capture moved the cursor");
    assert!(
        store.recover_journal(&route, 0, 100).unwrap().is_empty(),
        "gap capture wrote a journal row"
    );
    assert!(
        store.recover_pending_downloads(0, 100).unwrap().is_empty(),
        "gap capture wrote a download task"
    );
    assert!(store.saved_object(&first.hash).unwrap().is_none());
    assert!(store.saved_object(&third.hash).unwrap().is_none());
}

#[test]
fn incoming_crash_capture_atomic_missing_position_survives_restart() {
    let route = route();
    let first = framed(1);
    let missing = framed(2);
    let third = framed(3);
    let later = framed(4);
    let (root, mut store) = open_owner();
    store
        .capture_page(
            &route,
            &page(
                &route,
                0,
                vec![
                    entry(&route, &first, 1),
                    entry(&route, &missing, 2),
                    entry(&route, &third, 3),
                ],
            ),
            &[
                DownloadOutcome::Cached(first.clone()),
                DownloadOutcome::Missing(missing.hash),
                DownloadOutcome::Cached(third.clone()),
            ],
        )
        .expect("contiguous capture of positions 1..3");
    let journal = store.recover_journal(&route, 0, 100).unwrap();
    assert_eq!(
        journal
            .iter()
            .map(|row| (row.sequence, row.disposition.as_str(), row.source_hash))
            .collect::<Vec<_>>(),
        vec![
            (1, "cached", first.hash),
            (2, "missing", missing.hash),
            (3, "cached", third.hash),
        ]
    );
    assert_eq!(cursor(&store, &route), Some(3));
    wires_match(&store, &first);
    wires_match(&store, &third);
    assert!(store.saved_object(&missing.hash).unwrap().is_none());
    let pending = store.recover_pending_downloads(0, 100).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].source_hash, missing.hash);
    assert_eq!(pending[0].wire_length, 1024);
    drop(store);

    let mut store = ClientStore::open(&root, &support::roster(), 2).unwrap();
    assert_eq!(
        cursor(&store, &route),
        Some(3),
        "restart lost cursor 3 while position 2 was still missing"
    );
    let pending = store.recover_pending_downloads(0, 100).unwrap();
    assert_eq!(pending.len(), 1, "restart dropped the missing position 2 task");
    assert_eq!(pending[0].source_hash, missing.hash);
    assert!(store.saved_object(&missing.hash).unwrap().is_none());
    wires_match(&store, &third);
    store
        .capture_page(
            &route,
            &page(&route, 3, vec![entry(&route, &later, 4)]),
            &[DownloadOutcome::Cached(later.clone())],
        )
        .expect("later valid position after the retained missing task");
    assert_eq!(cursor(&store, &route), Some(4));
    wires_match(&store, &later);
    let pending = store.recover_pending_downloads(0, 100).unwrap();
    assert_eq!(
        pending.len(),
        1,
        "progress past position 3 removed the missing position 2 task"
    );
    assert_eq!(pending[0].source_hash, missing.hash);

    let old_cursor = cursor(&store, &route);
    assert_eq!(old_cursor, Some(4));
    let journal_before = store.recover_journal(&route, 0, 100).unwrap();
    let receipts_before: Vec<_> = journal_before.iter().map(|row| row.receipt.clone()).collect();
    let stale = store.capture_page(
        &route,
        &page(&route, 0, vec![entry(&route, &first, 1)]),
        &[DownloadOutcome::Cached(first.clone())],
    );
    assert!(
        matches!(stale, Err(ClientError::Cursor)),
        "a stale page replaced the old cursor"
    );
    assert_eq!(
        cursor(&store, &route),
        old_cursor,
        "rolled-back capture advanced the old cursor"
    );
    let journal_after = store.recover_journal(&route, 0, 100).unwrap();
    assert_eq!(journal_after.len(), journal_before.len());
    assert_eq!(
        journal_after
            .iter()
            .map(|row| row.receipt.clone())
            .collect::<Vec<_>>(),
        receipts_before
    );
    let pending = store.recover_pending_downloads(0, 100).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].source_hash, missing.hash);
    wires_match(&store, &first);
    wires_match(&store, &third);
    wires_match(&store, &later);
    assert!(store.saved_object(&missing.hash).unwrap().is_none());

    let rejected = framed(5);
    let mut forged = receipt(&route, rejected.hash, rejected.wire.len() as u64, 5);
    let end = forged.len() - 1;
    forged[end] ^= 0xff;
    store
        .capture_page(
            &route,
            &page(
                &route,
                4,
                vec![Entry {
                    sequence: 5,
                    hash: rejected.hash,
                    wire_length: rejected.wire.len() as u64,
                    receipt: forged.clone(),
                }],
            ),
            &[DownloadOutcome::Cached(rejected.clone())],
        )
        .expect("malformed receipt is a tombstone");
    assert_eq!(cursor(&store, &route), Some(5));
    let journal = store.recover_journal(&route, 0, 100).unwrap();
    assert_eq!(journal.len(), 5);
    assert_eq!(journal[1].disposition, "missing");
    assert_eq!(journal[1].source_hash, missing.hash);
    assert_eq!(journal[4].sequence, 5);
    assert_eq!(journal[4].source_hash, rejected.hash);
    assert_eq!(journal[4].disposition, "quarantine");
    assert_ne!(journal[4].disposition, "cached");
    assert_eq!(journal[4].reason, "receipt");
    assert_eq!(journal[4].receipt, forged);
    assert!(journal[4].body_digest.is_none());
    assert!(
        store.saved_object(&rejected.hash).unwrap().is_none(),
        "malformed receipt stored ciphertext"
    );
    let pending = store.recover_pending_downloads(0, 100).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].source_hash, missing.hash);
    wires_match(&store, &first);
    wires_match(&store, &third);
    wires_match(&store, &later);
    assert!(store.recover_incoming_originals(0, 100).unwrap().is_empty());
    assert!(store.recover_ack_links(0, 100).unwrap().is_empty());
    assert!(
        authenticate_staged(&mut store, &support::roster(), &support::identity(2))
            .unwrap()
            .is_empty(),
        "malformed receipt authenticated an incoming message"
    );
}

#[test]
fn incoming_crash_capture_atomic_sqlite_full() {
    library_case("store::incoming_crash_tests::incoming_crash_capture_sqlite_full");
}

use loki_relay_client::{
    authenticate_staged, prepare_outbox, prepare_received, CommitDisposition,
};
use loki_relay_protocol::types::{roster_digest, LogicalKey, MessageBody, Payload};

fn test_message(message: Id32, payload: Vec<u8>) -> MessageBody {
    let roster = support::roster();
    MessageBody {
        key: LogicalKey {
            vault: roster.vault,
            roster: roster_digest(&roster).unwrap(),
            sender: 1,
            message,
        },
        audience: vec![1, 2, 3],
        session: Some([44; 32]),
        prerequisites: Vec::new(),
        payload: Payload::Test(payload),
    }
}

fn rewind_cursor(root: &std::path::Path, route: &RelayRoute) {
    let sql = support::sql(root);
    let updated = sql
        .execute(
            "UPDATE route_cursors SET position=0 WHERE relay_key=?1 AND run=?2 AND mailbox=?3",
            rusqlite::params![route.pin.key, route.pin.run, route.mailbox],
        )
        .unwrap();
    assert_eq!(updated, 1, "scripted cursor rewind missed the route");
}

fn expect_primary_key(result: rusqlite::Result<usize>, table: &str) {
    let message = result
        .expect_err("duplicate primary key was inserted")
        .to_string();
    assert!(
        message.contains("UNIQUE constraint failed") && message.contains(table),
        "real SQLite primary-key failure for {table}: {message}"
    );
}

#[test]
fn incoming_schema() {
    let route_a = route();
    let mut route_b = route();
    route_b.mailbox = [4; 32];
    let missing = framed(2);
    let forged = framed(7);
    let other = framed(8);
    let missing_receipt = receipt(&route_a, missing.hash, 1024, 1);
    let forged_receipt = b"forged-receipt".to_vec();
    let page_a = || {
        page(
            &route_a,
            0,
            vec![
                Entry {
                    sequence: 1,
                    hash: missing.hash,
                    wire_length: 1024,
                    receipt: missing_receipt.clone(),
                },
                Entry {
                    sequence: 2,
                    hash: forged.hash,
                    wire_length: 1024,
                    receipt: forged_receipt.clone(),
                },
            ],
        )
    };
    let (root, mut store) = {
        let root = evidence("incoming-schema");
        let store = ClientStore::open(&root, &support::roster(), 2).unwrap();
        (root, store)
    };
    store
        .capture_page(
            &route_a,
            &page_a(),
            &[DownloadOutcome::Missing(missing.hash)],
        )
        .expect("scripted route A positions 1 and 2");
    store
        .capture_page(
            &route_b,
            &page(&route_b, 0, vec![entry(&route_b, &other, 1)]),
            &[DownloadOutcome::Missing(other.hash)],
        )
        .expect("scripted route B reuses sequence 1");
    assert_eq!(cursor(&store, &route_a), Some(2));
    assert_eq!(cursor(&store, &route_b), Some(1));
    let journal_a = store.recover_journal(&route_a, 0, 100).unwrap();
    assert_eq!(
        journal_a
            .iter()
            .map(|row| (row.sequence, row.disposition.as_str(), row.reason.as_str(), row.source_hash))
            .collect::<Vec<_>>(),
        vec![
            (1, "missing", "missing", missing.hash),
            (2, "quarantine", "receipt", forged.hash),
        ]
    );
    assert_eq!(journal_a[0].receipt, missing_receipt);
    assert_eq!(journal_a[1].receipt, forged_receipt);
    assert!(journal_a.iter().all(|row| row.body_digest.is_none()));
    let journal_b = store.recover_journal(&route_b, 0, 100).unwrap();
    assert_eq!(journal_b.len(), 1);
    assert_eq!(journal_b[0].sequence, 1);
    assert_ne!(journal_b[0].mailbox, journal_a[0].mailbox);
    assert!(store.saved_object(&missing.hash).unwrap().is_none());
    assert!(store.saved_object(&forged.hash).unwrap().is_none());
    assert!(store.recover_incoming_originals(0, 100).unwrap().is_empty());

    rewind_cursor(&root, &route_a);
    store
        .capture_page(&route_a, &page_a(), &[DownloadOutcome::Missing(missing.hash)])
        .expect("exact route/sequence replay");
    assert_eq!(cursor(&store, &route_a), Some(2));
    assert_eq!(store.recover_journal(&route_a, 0, 100).unwrap().len(), 2);
    let mut altered = missing_receipt.clone();
    altered.push(0);
    let changed = page(
        &route_a,
        0,
        vec![
            Entry {
                sequence: 1,
                hash: missing.hash,
                wire_length: 1024,
                receipt: altered,
            },
            Entry {
                sequence: 2,
                hash: forged.hash,
                wire_length: 1024,
                receipt: forged_receipt.clone(),
            },
        ],
    );
    rewind_cursor(&root, &route_a);
    let error = store.capture_page(
        &route_a,
        &changed,
        &[DownloadOutcome::Missing(missing.hash)],
    );
    assert!(
        matches!(error, Err(ClientError::Conflict)),
        "a second route/sequence identity replaced the saved receipt"
    );
    store
        .capture_page(&route_a, &page_a(), &[DownloadOutcome::Missing(missing.hash)])
        .expect("restore the cursor after the conflicting replay");
    let journal_a = store.recover_journal(&route_a, 0, 100).unwrap();
    assert_eq!(journal_a[0].receipt, missing_receipt);
    assert_eq!(journal_a[0].reason, "missing");
    assert_eq!(journal_a[1].reason, "receipt");
    drop(store);

    let mut store = ClientStore::open(&root, &support::roster(), 2).unwrap();
    assert_eq!(cursor(&store, &route_a), Some(2));
    assert_eq!(cursor(&store, &route_b), Some(1));
    let pending = store.recover_pending_downloads(0, 100).unwrap();
    assert_eq!(pending.len(), 2, "reopen dropped a pending download");
    assert!(pending.iter().any(|row| {
        row.mailbox == route_a.mailbox && row.source_hash == missing.hash && row.wire_length == 1024
    }));
    assert!(pending.iter().any(|row| {
        row.mailbox == route_b.mailbox && row.source_hash == other.hash && row.wire_length == 1024
    }));
    let journal_a = store.recover_journal(&route_a, 0, 100).unwrap();
    assert_eq!(journal_a[0].reason, "missing");
    assert_eq!(journal_a[1].reason, "receipt");
    assert_eq!(journal_a[0].receipt, missing_receipt);
    assert!(journal_a.iter().all(|row| row.body_digest.is_none()));
    let samples = store.recover_diagnostic_samples(0, 100).unwrap();
    assert_eq!(samples.len(), 1);
    assert_eq!(samples[0].sample_len, forged_receipt.len() as u64);
    assert_eq!(samples[0].sequence, 2);
    let roster = support::roster();
    let bob = support::identity(2);
    assert!(
        authenticate_staged(&mut store, &roster, &bob).unwrap().is_empty(),
        "a storage receipt authenticated an incoming message"
    );
    assert!(store.recover_incoming_originals(0, 100).unwrap().is_empty());

    let alice = support::identity(1);
    let prepared = prepare_outbox(&alice, &roster, &test_message([40; 32], vec![19, 29, 39])).unwrap();
    let bob_copy = prepared
        .recipients()
        .iter()
        .find(|recipient| recipient.recipient() == 2)
        .unwrap();
    assert_eq!(bob_copy.objects().len(), 1, "Bob's sealed copy was not one object");
    let object = bob_copy.objects()[0].clone();
    store
        .capture_page(
            &route_a,
            &page(&route_a, 2, vec![entry(&route_a, &object, 3)]),
            &[DownloadOutcome::Cached(object.clone())],
        )
        .expect("cached sealed object");
    let staged = store.recover_journal(&route_a, 0, 100).unwrap();
    assert!(staged.iter().all(|row| row.body_digest.is_none()));
    assert_ne!(staged[2].receipt, prepared.digest().to_vec());
    let candidates = authenticate_staged(&mut store, &roster, &bob).unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].message().digest(), prepared.digest());
    assert!(
        store.recover_incoming_originals(0, 100).unwrap().is_empty(),
        "authentication wrote an original before durable commit"
    );
    let ack = prepare_received(
        &store,
        &bob,
        &roster,
        candidates[0].message(),
        candidates[0].source(),
    )
    .unwrap()
    .expect("Received outbox for the foreign test message");
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
    assert_eq!(originals[0].digest, *prepared.digest());
    assert_eq!(originals[0].key.sender, 1);
    assert_eq!(originals[0].key.message, [40; 32]);
    assert_eq!(originals[0].source_root, object.hash);
    assert_eq!(originals[0].kind, 1);
    let links = store.recover_ack_links(0, 100).unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].ack_author, 2);
    assert_eq!(links[0].digest, *prepared.digest());
    assert_eq!(links[0].key.message, [40; 32]);
    let ack_message = links[0].ack_message;
    let request_id = links[0].request_id;
    let noted = store.recover_journal(&route_a, 0, 100).unwrap();
    assert_eq!(noted[0].body_digest, None);
    assert_eq!(noted[1].body_digest, None);
    assert_eq!(noted[2].body_digest, Some(*prepared.digest()));
    assert_eq!(noted[2].receipt, receipt(&route_a, object.hash, object.wire.len() as u64, 3));
    assert_ne!(noted[2].receipt.as_slice(), candidates[0].message().canonical_body());
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
        CommitDisposition::Duplicate
    );
    let links = store.recover_ack_links(0, 100).unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].ack_message, ack_message);
    assert_eq!(links[0].request_id, request_id);
    assert_eq!(store.recover_incoming_originals(0, 100).unwrap().len(), 1);

    let conflicted = prepare_outbox(&alice, &roster, &test_message([40; 32], vec![19, 29, 40])).unwrap();
    assert_ne!(conflicted.digest(), prepared.digest());
    let conflict_object = conflicted
        .recipients()
        .iter()
        .find(|recipient| recipient.recipient() == 2)
        .unwrap()
        .objects()[0]
        .clone();
    store
        .capture_page(
            &route_a,
            &page(&route_a, 3, vec![entry(&route_a, &conflict_object, 4)]),
            &[DownloadOutcome::Cached(conflict_object.clone())],
        )
        .expect("cached conflicting sealed object");
    let candidates = authenticate_staged(&mut store, &roster, &bob).unwrap();
    let candidate = candidates
        .iter()
        .find(|candidate| candidate.message().digest() == conflicted.digest())
        .expect("conflicting authenticated digest");
    assert_eq!(
        store
            .commit_incoming(
                &roster,
                &bob,
                candidate.source(),
                candidate.message(),
                Some(&ack),
            )
            .unwrap(),
        CommitDisposition::Conflict
    );
    let originals = store.recover_incoming_originals(0, 100).unwrap();
    assert_eq!(originals.len(), 1);
    assert_eq!(originals[0].digest, *prepared.digest());
    let links = store.recover_ack_links(0, 100).unwrap();
    assert_eq!(links.len(), 1);
    assert_eq!(links[0].ack_author, 2);
    assert_eq!(links[0].digest, *prepared.digest());
    assert_eq!(links[0].ack_message, ack_message);
    drop(store);

    let store = ClientStore::open(&root, &support::roster(), 2).unwrap();
    assert_eq!(store.recover_pending_downloads(0, 100).unwrap().len(), 2);
    let journal_a = store.recover_journal(&route_a, 0, 100).unwrap();
    assert_eq!(journal_a.len(), 4);
    assert_eq!(journal_a[0].reason, "missing");
    assert_eq!(journal_a[1].reason, "receipt");
    assert_eq!(journal_a[0].receipt, missing_receipt);
    assert_eq!(store.recover_incoming_originals(0, 100).unwrap().len(), 1);
    assert_eq!(store.recover_ack_links(0, 100).unwrap().len(), 1);
    assert_eq!(cursor(&store, &route_a), Some(4));
    drop(store);

    let sql = support::sql(&root);
    expect_primary_key(
        sql.execute(
            "INSERT INTO incoming_journal SELECT * FROM incoming_journal WHERE mailbox=?1 AND sequence=1",
            rusqlite::params![route_a.mailbox],
        ),
        "incoming_journal",
    );
    expect_primary_key(
        sql.execute(
            "INSERT INTO incoming_originals SELECT * FROM incoming_originals",
            [],
        ),
        "incoming_originals",
    );
    expect_primary_key(
        sql.execute(
            "INSERT INTO incoming_originals SELECT vault,roster,sender,message_id,?1,kind,session,source_root FROM incoming_originals",
            rusqlite::params![[0xABu8; 32]],
        ),
        "incoming_originals",
    );
    expect_primary_key(
        sql.execute("INSERT INTO ack_links SELECT * FROM ack_links", []),
        "ack_links",
    );
    let mut sql = sql;
    let tx = sql.transaction().unwrap();
    let inserted = tx
        .execute(
            "INSERT INTO ack_links SELECT vault,roster,sender,message_id,?1,ack_author,ack_message,request_id FROM ack_links",
            rusqlite::params![[0xABu8; 32]],
        )
        .expect("a different digest is a different ack-author key");
    assert_eq!(inserted, 1);
    tx.rollback().unwrap();
    let links: i64 = sql
        .query_row("SELECT count(*) FROM ack_links", [], |row| row.get(0))
        .unwrap();
    let conflicts: i64 = sql
        .query_row("SELECT count(*) FROM incoming_conflicts", [], |row| row.get(0))
        .unwrap();
    assert_eq!(links, 1);
    assert_eq!(conflicts, 1);
}

use loki_relay_client::{
    open_descriptor, poll_transport, seal_descriptor, ClientConfig, ConfigReference, Descriptor, DescriptorRelay,
    OwnerInbox, QuarantineReason, RelayHttp, RelayRuntime, Secret32,
};
use loki_relay_protocol::http::{encode_error, encode_page, ErrorCode};
use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::{Arc, Mutex},
    thread,
};

fn recovery_root(name: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    let directory = PathBuf::from("/private/tmp/relay-7.3a-evidence").join(format!(
        "{name}-{}-{stamp}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&directory).unwrap();
    directory.join("client")
}

fn sample_rows(store: &ClientStore) -> Vec<loki_relay_client::DiagnosticSample> {
    let mut after = 0u64;
    let mut rows = Vec::new();
    loop {
        let page = store.recover_diagnostic_samples(after, 100).unwrap();
        let Some(last) = page.last() else {
            break;
        };
        let next = u64::try_from(last.id).unwrap();
        let short = page.len() < 100;
        rows.extend(page);
        if short || next <= after {
            break;
        }
        after = next;
    }
    rows
}

struct ScriptedPeer {
    port: u16,
    stop: Arc<std::sync::atomic::AtomicBool>,
    misses: Arc<std::sync::atomic::AtomicUsize>,
    thread: Option<thread::JoinHandle<()>>,
}

impl ScriptedPeer {
    fn start(first: Vec<u8>, later: Vec<u8>, objects: Vec<(Id32, Vec<u8>)>, missing: Id32) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let misses = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let thread_stop = Arc::clone(&stop);
        let thread_misses = Arc::clone(&misses);
        let thread = thread::spawn(move || {
            let objects = Arc::new(Mutex::new(objects));
            while !thread_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(2)));
                        let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(2)));
                        let Some(path) = request_path(&mut stream) else {
                            let _ = stream.shutdown(std::net::Shutdown::Both);
                            continue;
                        };
                        let response = if path.contains("/entries?") {
                            let after = path
                                .split("after=")
                                .nth(1)
                                .and_then(|value| value.split(['&', ' ']).next())
                                .and_then(|value| value.parse::<u64>().ok())
                                .unwrap_or(u64::MAX);
                            let body = if after == 0 { &first } else { &later };
                            http_response(200, "application/cbor", body)
                        } else if let Some(hash) = path.rsplit('/').next().and_then(|hex| parse_hash(hex)) {
                            if hash == missing
                                && thread_misses.fetch_add(1, Ordering::Relaxed) < 2
                            {
                                http_response(
                                    404,
                                    "application/cbor",
                                    &encode_error(ErrorCode::ObjectNotFound).unwrap(),
                                )
                            } else {
                                let objects = objects.lock().unwrap();
                                match objects.iter().find(|(id, _)| *id == hash) {
                                    Some((_, wire)) => http_response(200, "application/octet-stream", wire),
                                    None => http_response(
                                        404,
                                        "application/cbor",
                                        &encode_error(ErrorCode::ObjectNotFound).unwrap(),
                                    ),
                                }
                            }
                        } else {
                            http_response(
                                404,
                                "application/cbor",
                                &encode_error(ErrorCode::ObjectNotFound).unwrap(),
                            )
                        };
                        let _ = stream.write_all(&response);
                        let _ = stream.shutdown(std::net::Shutdown::Both);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(std::time::Duration::from_millis(20));
                    }
                    Err(_) => break,
                }
            }
        });
        Self {
            port,
            stop,
            misses,
            thread: Some(thread),
        }
    }
}

impl Drop for ScriptedPeer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = TcpStream::connect(("127.0.0.1", self.port));
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn request_path(stream: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while buf.len() < 8192 {
        if stream.read(&mut byte).ok()? == 0 {
            break;
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let header = String::from_utf8_lossy(&buf);
    let mut parts = header.lines().next()?.split(' ');
    if parts.next() != Some("GET") {
        return None;
    }
    Some(parts.next()?.to_string())
}

fn parse_hash(text: &str) -> Option<Id32> {
    let hex = text.split(['?', ' ']).next()?;
    if hex.len() != 64 {
        return None;
    }
    let mut hash = [0u8; 32];
    for (index, byte) in hash.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(index * 2..index * 2 + 2)?, 16).ok()?;
    }
    Some(hash)
}

fn http_response(status: u16, media: &str, body: &[u8]) -> Vec<u8> {
    let head = format!(
        "HTTP/1.1 {status} OK\r\nContent-Type: {media}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut response = head.into_bytes();
    response.extend_from_slice(body);
    response
}

fn member_config(port: u16) -> (ClientConfig, loki_relay_client::AuthenticatedDescriptor, Vec<u8>) {
    let roster = support::roster();
    let owner = support::identity(2);
    let mut relays = vec![
        DescriptorRelay {
            route: RelayRoute {
                pin: RelayPin {
                    key: signer().verifying_key().to_bytes(),
                    run: [2; 32],
                },
                endpoint: format!("http://127.0.0.1:{port}"),
                mailbox: [3; 32],
                append_revision: 1,
            },
            append: Secret32::from_bytes([180; 32]),
        },
        DescriptorRelay {
            route: RelayRoute {
                pin: RelayPin {
                    key: SigningKey::from_bytes(&[10; 32]).verifying_key().to_bytes(),
                    run: [4; 32],
                },
                endpoint: "http://127.0.0.1:9".to_string(),
                mailbox: [4; 32],
                append_revision: 1,
            },
            append: Secret32::from_bytes([181; 32]),
        },
        DescriptorRelay {
            route: RelayRoute {
                pin: RelayPin {
                    key: SigningKey::from_bytes(&[11; 32]).verifying_key().to_bytes(),
                    run: [5; 32],
                },
                endpoint: "http://127.0.0.1:9".to_string(),
                mailbox: [5; 32],
                append_revision: 1,
            },
            append: Secret32::from_bytes([182; 32]),
        },
    ];
    relays.sort_by(|left, right| left.route.pin.key.cmp(&right.route.pin.key));
    let descriptor = Descriptor::new(
        roster.vault,
        roster_digest(&roster).unwrap(),
        2,
        1,
        relays,
    );
    let sealed = seal_descriptor(&owner, &roster, &descriptor, &owner.public()).unwrap();
    let self_route = open_descriptor(&owner, &roster, &sealed.wire).unwrap();
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
    (ClientConfig { own, peers: Vec::new() }, self_route, sealed.wire)
}

#[test]
fn incoming_crash_download_recovery_restarts_and_caches_before_retire() {
    let route = route();
    let first = framed(1);
    let missing = framed(2);
    let later = framed(3);
    let first_page = encode_page(&page(
        &route,
        0,
        vec![entry(&route, &first, 1), entry(&route, &missing, 2)],
    ))
    .unwrap();
    let later_page = encode_page(&page(&route, 2, vec![entry(&route, &later, 3)])).unwrap();
    let server = ScriptedPeer::start(
        first_page,
        later_page,
        vec![
            (first.hash, first.wire.clone()),
            (missing.hash, missing.wire.clone()),
            (later.hash, later.wire.clone()),
        ],
        missing.hash,
    );
    let (config, self_route, sealed) = member_config(server.port);
    let roster = support::roster();
    let owner = support::identity(2);
    let root = recovery_root("http-resume");
    let mut store = ClientStore::open(&root, &roster, 2).unwrap();
    store
        .record_config_revision(&ConfigReference::from_ciphertext(1, &sealed).unwrap())
        .unwrap();
    let http = RelayHttp::new().unwrap();
    let runtime = RelayRuntime::new().unwrap();
    runtime
        .block_on(poll_transport(
            &mut store,
            &http,
            &roster,
            &owner,
            &config,
            &self_route,
            1_000,
        ))
        .unwrap();
    assert_eq!(cursor(&store, &route), Some(2));
    wires_match(&store, &first);
    assert!(store.saved_object(&missing.hash).unwrap().is_none());
    let pending = store.recover_pending_downloads(0, 100).unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].source_hash, missing.hash);
    assert!(pending[0].attempts >= 1, "missing object was not scheduled");
    assert!(pending[0].retry_at > 1_000);
    drop(store);

    let mut store = ClientStore::open(&root, &roster, 2).unwrap();
    assert_eq!(cursor(&store, &route), Some(2), "restart regressed cursor 2");
    let pending = store.recover_pending_downloads(0, 100).unwrap();
    assert_eq!(pending.len(), 1, "restart dropped download 2");
    assert_eq!(pending[0].source_hash, missing.hash);
    assert!(store.saved_object(&missing.hash).unwrap().is_none());
    runtime
        .block_on(poll_transport(
            &mut store,
            &http,
            &roster,
            &owner,
            &config,
            &self_route,
            1_250,
        ))
        .unwrap();
    assert!(cursor(&store, &route).unwrap() >= 2, "resume moved the cursor backward");
    assert_eq!(cursor(&store, &route), Some(3));
    wires_match(&store, &missing);
    wires_match(&store, &later);
    assert!(
        store.recover_pending_downloads(0, 100).unwrap().is_empty(),
        "cached download 2 left its task"
    );
    let journal = store.recover_journal(&route, 0, 100).unwrap();
    assert_eq!(journal[1].sequence, 2);
    assert_eq!(journal[1].disposition, "cached");
    assert_eq!(journal[1].source_hash, missing.hash);
    assert!(server.misses.load(Ordering::Relaxed) >= 3);
    drop(store);

    let store = ClientStore::open(&root, &roster, 2).unwrap();
    assert_eq!(cursor(&store, &route), Some(3), "reopen changed the resumed cursor");
    wires_match(&store, &first);
    wires_match(&store, &missing);
    wires_match(&store, &later);
    assert!(
        store.recover_pending_downloads(0, 100).unwrap().is_empty(),
        "reopen restored a retired download task"
    );
    let journal = store.recover_journal(&route, 0, 100).unwrap();
    assert_eq!(journal.len(), 3);
    assert_eq!(journal[1].sequence, 2);
    assert_eq!(journal[1].disposition, "cached");
    assert_eq!(journal[1].source_hash, missing.hash);
}

#[test]
fn incoming_crash_download_recovery_sample_cap_lets_later_entry_progress() {
    let route = route();
    let root = recovery_root("sample-cap");
    let mut store = ClientStore::open(&root, &support::roster(), 2).unwrap();
    let mut start = 0u64;
    while start < 1025 {
        let count = (1025 - start).min(100);
        let mut entries = Vec::new();
        let mut downloads = Vec::new();
        for offset in 0..count {
            let sequence = start + offset + 1;
            let mut hash = [0u8; 32];
            hash[..8].copy_from_slice(&sequence.to_le_bytes());
            entries.push(Entry {
                sequence,
                hash,
                wire_length: 1024,
                receipt: receipt(&route, hash, 1024, sequence),
            });
            downloads.push(DownloadOutcome::Rejected {
                hash,
                reason: QuarantineReason::Hash,
                sample: sequence.to_le_bytes().to_vec(),
            });
        }
        store
            .capture_page(&route, &page(&route, start, entries), &downloads)
            .unwrap();
        start += count;
    }
    let samples = sample_rows(&store);
    assert_eq!(samples.len(), 1024, "diagnostic samples grew past 1024");
    assert!(samples.iter().all(|sample| sample.sample_len == 8 && sample.sample_len <= 4096));
    assert!(samples.iter().all(|sample| sample.sequence != 1));
    assert!(samples.iter().any(|sample| sample.sequence == 1025));
    assert_eq!(cursor(&store, &route), Some(1025));
    let later = framed(4);
    store
        .capture_page(
            &route,
            &page(&route, 1025, vec![entry(&route, &later, 1026)]),
            &[DownloadOutcome::Cached(later.clone())],
        )
        .unwrap();
    assert_eq!(cursor(&store, &route), Some(1026));
    wires_match(&store, &later);
    let samples = sample_rows(&store);
    assert_eq!(samples.len(), 1024);
    assert!(store.recover_pending_downloads(0, 100).unwrap().is_empty());
    let tomb = store
        .recover_journal(&route, 0, 100)
        .unwrap()
        .into_iter()
        .find(|row| row.sequence == 1)
        .expect("evicted sample sequence lost its journal row");
    assert_eq!(tomb.disposition, "quarantine");
    assert_eq!(tomb.reason, "hash");

    let mut oversized = vec![0u8; 4096 + 128];
    for (index, byte) in oversized.iter_mut().enumerate() {
        *byte = u8::try_from(index % 251).unwrap();
    }
    let mut hash = [9u8; 32];
    hash[..8].copy_from_slice(&1027u64.to_le_bytes());
    store
        .capture_page(
            &route,
            &page(
                &route,
                1026,
                vec![Entry {
                    sequence: 1027,
                    hash,
                    wire_length: 1024,
                    receipt: receipt(&route, hash, 1024, 1027),
                }],
            ),
            &[DownloadOutcome::Rejected {
                hash,
                reason: QuarantineReason::Hash,
                sample: oversized.clone(),
            }],
        )
        .unwrap();
    let samples = sample_rows(&store);
    assert_eq!(samples.len(), 1024, "oversized sample grew the diagnostic cap");
    assert!(samples.iter().all(|sample| sample.sequence != 1));
    let truncated = samples
        .iter()
        .find(|sample| sample.sequence == 1027)
        .expect("oversized rejection stored no sample");
    assert_eq!(truncated.sample_len, 4096, "rejected sample was not truncated to 4096");
    drop(store);

    let saved: Vec<u8> = support::sql(&root)
        .query_row(
            "SELECT sample FROM quarantine_samples WHERE sequence=1027",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(saved, oversized[..4096], "stored sample is not the 4096-byte prefix");
    let store = ClientStore::open(&root, &support::roster(), 2).unwrap();
    let tomb = store
        .recover_journal(&route, 0, 100)
        .unwrap()
        .into_iter()
        .find(|row| row.sequence == 1)
        .expect("reopen lost the tombstone for evicted sequence 1");
    assert_eq!(tomb.disposition, "quarantine");
    assert_eq!(tomb.reason, "hash");
    assert_eq!(cursor(&store, &route), Some(1027));
    wires_match(&store, &later);
    assert!(sample_rows(&store).iter().all(|sample| sample.sequence != 1));
    assert!(store.recover_pending_downloads(0, 100).unwrap().is_empty());
}

#[test]
fn incoming_crash_download_recovery_budget_keeps_outstanding_task() {
    library_case(
        "store::incoming_crash_tests::download_recovery_budget_keeps_pending_and_stops_admission",
    );
}

use loki_relay_client::{
    committed_readiness, seal_record, CandidateReadiness, SealContext, SealDomain,
};
use loki_relay_protocol::types::{encode_message, MessageRef};

fn auth_root(name: &str) -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let stamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    let directory = PathBuf::from("/private/tmp/relay-7.4a-evidence").join(format!(
        "{name}-{}-{stamp}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&directory).unwrap();
    directory.join("client")
}

fn payload_marker() -> [u8; 64] {
    let mut marker = [0u8; 64];
    for (index, byte) in marker.iter_mut().enumerate() {
        *byte = 0xA5 ^ (index as u8).wrapping_mul(17).wrapping_add(0x3C);
    }
    marker
}

fn message_body(
    roster: &loki_relay_protocol::types::Roster,
    sender: u16,
    message: Id32,
    prerequisites: Vec<MessageRef>,
    payload: Vec<u8>,
) -> MessageBody {
    MessageBody {
        key: LogicalKey {
            vault: roster.vault,
            roster: roster_digest(roster).unwrap(),
            sender,
            message,
        },
        audience: vec![1, 2, 3],
        session: Some([44; 32]),
        prerequisites,
        payload: Payload::Test(payload),
    }
}

fn member_signer(id: u8) -> SigningKey {
    SigningKey::from_bytes(&[id; 32])
}

fn seal_to(roster: &loki_relay_protocol::types::Roster, recipient: u16, record: &[u8]) -> Object {
    let member = roster
        .members
        .iter()
        .find(|member| member.id == recipient)
        .expect("roster recipient")
        .clone();
    seal_record(
        &SealContext {
            vault: roster.vault,
            roster: roster_digest(roster).unwrap(),
            recipient: member,
            domain: SealDomain::Message,
        },
        record,
    )
    .expect("seal")
}

fn orphan_chunk(roster: &loki_relay_protocol::types::Roster, n: u16, marker: &[u8]) -> Object {
    let mut transfer = [0u8; 32];
    transfer[..2].copy_from_slice(&n.to_be_bytes());
    let mut segment = marker.to_vec();
    segment.push(n as u8);
    let record = canonical::encode(&Value::Array(vec![
        Value::Integer(3.into()),
        Value::Bytes(transfer.to_vec()),
        Value::Integer(0.into()),
        Value::Bytes(segment),
    ]))
    .unwrap();
    seal_to(roster, 1, &record)
}

fn forged_sender_object(roster: &loki_relay_protocol::types::Roster, marker: &[u8]) -> Object {
    let body = message_body(roster, 1, [0xF1; 32], Vec::new(), marker.to_vec());
    let encoded = encode_message(&body).unwrap();
    let mut input = b"Loki_Relay_Message_v1\0".to_vec();
    input.extend_from_slice(&u32::try_from(encoded.len()).unwrap().to_be_bytes());
    input.extend_from_slice(&encoded);
    let signature = member_signer(2).sign(&input);
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
    seal_to(roster, 2, &record)
}

fn cache_objects(store: &mut ClientStore, route: &RelayRoute, after: u64, objects: &[Object]) -> u64 {
    assert!(!objects.is_empty() && objects.len() <= 40);
    let entries = objects
        .iter()
        .enumerate()
        .map(|(index, object)| entry(route, object, after + 1 + index as u64))
        .collect();
    store
        .capture_page(
            route,
            &page(route, after, entries),
            &objects
                .iter()
                .cloned()
                .map(DownloadOutcome::Cached)
                .collect::<Vec<_>>(),
        )
        .expect("scripted cached page");
    after + objects.len() as u64
}

fn assert_exact_wire(store: &ClientStore, object: &Object) {
    let saved = store
        .saved_object(&object.hash)
        .unwrap()
        .expect("cached ciphertext missing");
    assert_eq!(saved.hash, object.hash);
    assert_eq!(saved.wire.len(), object.wire.len());
    assert!(saved.wire == object.wire, "saved ciphertext bytes differ");
}

fn assert_test_payload(body: &MessageBody, expected: &[u8]) {
    match &body.payload {
        Payload::Test(found) if found.as_slice() == expected => {}
        Payload::Test(_) => panic!("authenticated test payload bytes differ"),
        Payload::Received(_) => panic!("authenticated payload was not a test message"),
    }
}

fn assert_marker_absent(root: &PathBuf, marker: &[u8]) {
    let mode: String = support::sql(root)
        .query_row("PRAGMA journal_mode", [], |row| row.get(0))
        .unwrap();
    let mut files = 0u32;
    let mut saw_wal = false;
    for entry in fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        files += 1;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.ends_with("-wal") {
            saw_wal = true;
        }
        let bytes = fs::read(&path).unwrap();
        assert!(
            marker.len() == 64 && !bytes.windows(marker.len()).any(|window| window == marker),
            "durable artifact {name} contains the payload marker"
        );
    }
    assert!(files > 0, "store directory has no durable artifacts");
    if mode.eq_ignore_ascii_case("wal") {
        assert!(
            saw_wal,
            "WAL mode hid recent writes from client.sqlite3-wal"
        );
    }
}

fn assert_no_ack_or_original(store: &ClientStore) {
    assert!(store.recover_incoming_originals(0, 100).unwrap().is_empty());
    assert!(store.recover_ack_links(0, 100).unwrap().is_empty());
    assert!(store.recover_uploads(0, 100).unwrap().is_empty());
}

fn journal_has_no_body_digest(store: &ClientStore, route: &RelayRoute) {
    let mut after = 0u64;
    let mut seen = false;
    loop {
        let page = store.recover_journal(route, after, 100).unwrap();
        let Some(last) = page.last() else {
            break;
        };
        seen = true;
        assert!(page.iter().all(|row| row.body_digest.is_none()));
        let next = last.sequence;
        if page.len() < 100 || next <= after {
            break;
        }
        after = next;
    }
    assert!(seen, "journal scan saw no rows");
}

fn collect_staged(store: &ClientStore) -> Vec<loki_relay_client::StagedSource> {
    let mut after = 0u64;
    let mut rows = Vec::new();
    loop {
        let page = store.recover_staged_sources(after, 100).unwrap();
        let Some(last) = page.last() else {
            break;
        };
        let next = last.cursor;
        let short = page.len() < 100;
        rows.extend(page);
        if short || next <= after {
            break;
        }
        after = next;
    }
    rows
}

#[test]
fn staged_auth() {
    let roster = support::roster();
    let alice = support::identity(1);
    let bob = support::identity(2);
    let route = route();
    let marker = payload_marker();
    let mut chunk_payload = vec![0u8; 70_000];
    chunk_payload[..marker.len()].copy_from_slice(&marker);
    let prepared = prepare_outbox(
        &alice,
        &roster,
        &message_body(&roster, 1, [74; 32], Vec::new(), chunk_payload.clone()),
    )
    .unwrap();
    let bob_copy = prepared
        .recipients()
        .iter()
        .find(|recipient| recipient.recipient() == 2)
        .expect("Bob copy");
    assert!(
        bob_copy.objects().len() >= 3,
        "package fit in one envelope, so the partial-chunk case did not run"
    );
    let manifest = bob_copy.objects().last().unwrap().clone();
    let present = bob_copy.objects()[0].clone();
    let missing = bob_copy.objects()[1].clone();
    let root = auth_root("staged-auth");
    let mut store = ClientStore::open(&root, &roster, 2).unwrap();
    let mut cursor = cache_objects(&mut store, &route, 0, &[present.clone()]);
    cursor = cache_objects(&mut store, &route, cursor, &[manifest.clone()]);
    assert!(
        authenticate_staged(&mut store, &roster, &bob).unwrap().is_empty(),
        "a partial chunk set emitted a candidate"
    );
    let staged = collect_staged(&store);
    assert_eq!(staged.len(), 1);
    assert_eq!(staged[0].root_hash, manifest.hash);
    let requirements = store
        .recover_staged_requirements(&manifest.hash, None, 100)
        .unwrap();
    assert!(requirements.iter().any(|requirement| {
        requirement.hash == missing.hash && requirement.wire_length == missing.wire.len() as u64
    }));
    let pending = store.recover_pending_downloads(0, 100).unwrap();
    assert!(pending.iter().any(|row| {
        row.source_hash == missing.hash && row.wire_length == missing.wire.len() as u64
    }));
    assert!(store.saved_object(&missing.hash).unwrap().is_none());
    assert_exact_wire(&store, &present);
    assert_exact_wire(&store, &manifest);
    assert_no_ack_or_original(&store);
    journal_has_no_body_digest(&store, &route);
    assert_marker_absent(&root, &marker);

    let forged = forged_sender_object(&roster, &marker);
    cursor = cache_objects(&mut store, &route, cursor, &[forged.clone()]);
    assert!(authenticate_staged(&mut store, &roster, &bob)
        .unwrap()
        .iter()
        .all(|candidate| candidate.source().required_hashes() != [forged.hash].as_slice()));
    let rejections = store.recover_source_rejections(0, 100).unwrap();
    assert!(
        rejections.iter().any(|row| row.root_hash == forged.hash && row.reason == "signature"),
        "forged sender was not refused by roster signature verification"
    );
    assert_exact_wire(&store, &forged);
    assert_no_ack_or_original(&store);
    assert_marker_absent(&root, &marker);

    let missing_ref = MessageRef {
        sender: 3,
        message: [32; 32],
        digest: [33; 32],
    };
    let mut missing_payload = marker.to_vec();
    missing_payload.extend_from_slice(&[19, 29, 39]);
    let missing_prepared = prepare_outbox(
        &alice,
        &roster,
        &message_body(&roster, 1, [0xF2; 32], vec![missing_ref.clone()], missing_payload.clone()),
    )
    .unwrap();
    let missing_object = missing_prepared
        .recipients()
        .iter()
        .find(|recipient| recipient.recipient() == 2)
        .unwrap()
        .objects()[0]
        .clone();
    cursor = cache_objects(&mut store, &route, cursor, &[missing_object.clone()]);
    let candidates = authenticate_staged(&mut store, &roster, &bob).unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].message().digest(), missing_prepared.digest());
    assert_eq!(candidates[0].readiness(), CandidateReadiness::Pending);
    assert_eq!(candidates[0].prerequisites().len(), 1);
    assert_eq!(candidates[0].prerequisites()[0].prerequisite(), &missing_ref);
    assert_eq!(candidates[0].prerequisites()[0].readiness(), CandidateReadiness::Pending);
    assert_test_payload(candidates[0].message().body(), &missing_payload);
    assert_exact_wire(&store, &missing_object);
    assert_no_ack_or_original(&store);
    assert_marker_absent(&root, &marker);

    cache_objects(&mut store, &route, cursor, &[missing.clone()]);
    let candidates = authenticate_staged(&mut store, &roster, &bob).unwrap();
    let complete = candidates
        .iter()
        .find(|candidate| candidate.message().digest() == prepared.digest())
        .expect("complete chunked package emitted no candidate");
    assert_eq!(complete.readiness(), CandidateReadiness::Ready);
    assert!(complete.prerequisites().is_empty());
    assert_eq!(complete.source().recipient(), 2);
    assert_test_payload(complete.message().body(), &chunk_payload);
    assert!(candidates.iter().any(|candidate| {
        candidate.message().digest() == missing_prepared.digest()
            && candidate.readiness() == CandidateReadiness::Pending
    }));
    assert_exact_wire(&store, &missing);
    assert_exact_wire(&store, &manifest);
    assert_no_ack_or_original(&store);
    journal_has_no_body_digest(&store, &route);
    assert_marker_absent(&root, &marker);
}

#[test]
fn staged_auth_synthetic_dependency_cycle() {
    let roster = support::roster();
    let alice = support::identity(1);
    let bob = support::identity(2);
    let route = route();
    let marker = payload_marker();
    let mut first_payload = marker.to_vec();
    first_payload.extend_from_slice(&[1]);
    let mut second_payload = marker.to_vec();
    second_payload.extend_from_slice(&[2]);
    let first = prepare_outbox(
        &alice,
        &roster,
        &message_body(&roster, 1, [0xC1; 32], Vec::new(), first_payload.clone()),
    )
    .unwrap();
    let second = prepare_outbox(
        &alice,
        &roster,
        &message_body(&roster, 1, [0xC2; 32], Vec::new(), second_payload.clone()),
    )
    .unwrap();
    let objects = [first.recipients(), second.recipients()].map(|recipients| {
        recipients
            .iter()
            .find(|recipient| recipient.recipient() == 2)
            .unwrap()
            .objects()[0]
            .clone()
    });
    let root = auth_root("staged-auth-cycle");
    let mut store = ClientStore::open(&root, &roster, 2).unwrap();
    cache_objects(&mut store, &route, 0, &objects);
    let candidates = authenticate_staged(&mut store, &roster, &bob).unwrap();
    assert_eq!(candidates.len(), 2);
    assert!(candidates.iter().all(|candidate| {
        candidate.prerequisites().is_empty() && candidate.readiness() == CandidateReadiness::Ready
    }));
    assert_marker_absent(&root, &marker);
    for (prepared, object) in [&first, &second].into_iter().zip(&objects) {
        assert_exact_wire(&store, object);
        let candidate = candidates
            .iter()
            .find(|candidate| candidate.message().digest() == prepared.digest())
            .unwrap();
        let ack = prepare_received(&store, &bob, &roster, candidate.message(), candidate.source())
            .unwrap()
            .expect("foreign test acknowledgement");
        assert_eq!(
            store
                .commit_incoming(
                    &roster,
                    &bob,
                    candidate.source(),
                    candidate.message(),
                    Some(&ack),
                )
                .unwrap(),
            CommitDisposition::New
        );
    }
    for prepared in [&first, &second] {
        assert_eq!(
            committed_readiness(&store, &roster, &bob, prepared.key(), prepared.digest()).unwrap(),
            CandidateReadiness::Ready
        );
    }
    let sql = support::sql(&root);
    for (prepared, other) in [(&first, &second), (&second, &first)] {
        let inserted = sql
            .execute(
                "INSERT INTO incoming_dependencies VALUES(?1,?2,?3,?4,?5,?6,?7,NULL)",
                rusqlite::params![
                    prepared.key().vault,
                    prepared.key().roster,
                    prepared.key().sender,
                    prepared.key().message,
                    other.key().sender,
                    other.key().message,
                    other.digest(),
                ],
            )
            .expect("simulated dependency edge");
        assert_eq!(inserted, 1);
    }
    drop(sql);
    for prepared in [&first, &second] {
        assert_eq!(
            committed_readiness(&store, &roster, &bob, prepared.key(), prepared.digest()).unwrap(),
            CandidateReadiness::Pending,
            "exact digest back-edge was treated as ready"
        );
    }
    assert_exact_wire(&store, &objects[0]);
    assert_exact_wire(&store, &objects[1]);
    assert_marker_absent(&root, &marker);
}

#[test]
fn staged_auth_orphan_chunks_leave_pending_count_zero() {
    let roster = support::roster();
    let alice = support::identity(1);
    let route = route();
    let marker = payload_marker();
    let orphans: Vec<_> = (0..128).map(|n| orphan_chunk(&roster, n, &marker)).collect();
    let root = auth_root("staged-auth-orphans");
    let mut store = ClientStore::open(&root, &roster, 1).unwrap();
    let mut cursor = 0u64;
    for batch in orphans.chunks(40) {
        cursor = cache_objects(&mut store, &route, cursor, batch);
    }
    assert_eq!(store.pending_transfer_count().unwrap(), 0);
    assert!(collect_staged(&store).is_empty());
    assert!(store.recover_source_rejections(0, 100).unwrap().is_empty());
    assert_no_ack_or_original(&store);
    for object in &orphans {
        assert_exact_wire(&store, object);
    }
    assert_marker_absent(&root, &marker);
    assert!(
        authenticate_staged(&mut store, &roster, &alice).unwrap().is_empty(),
        "orphan ciphertext authenticated an application message"
    );
    assert_eq!(store.pending_transfer_count().unwrap(), 0);
    drop(store);
    let store = ClientStore::open(&root, &roster, 1).unwrap();
    assert_eq!(store.pending_transfer_count().unwrap(), 0);
    assert!(collect_staged(&store).is_empty());
    for object in &orphans {
        assert_exact_wire(&store, object);
    }
    assert_marker_absent(&root, &marker);
}

#[test]
fn staged_auth_mixed_pending_admission() {
    let roster = support::roster();
    let alice = support::identity(1);
    let bob = support::identity(2);
    let route = route();
    let marker = payload_marker();
    let root = auth_root("staged-auth-mixed");
    let mut store = ClientStore::open(&root, &roster, 1).unwrap();
    let mut first = None;
    for n in 0u32..42 {
        let mut message = [0x11; 32];
        message[..4].copy_from_slice(&n.to_be_bytes());
        let prepared = prepare_outbox(
            &alice,
            &roster,
            &message_body(&roster, 1, message, Vec::new(), vec![7]),
        )
        .unwrap();
        let mut request = [0x21; 32];
        request[..4].copy_from_slice(&n.to_be_bytes());
        store.commit_outbox(&roster, &alice, &request, &prepared).unwrap();
        if n == 0 {
            first = Some(prepared);
        }
    }
    assert_eq!(store.pending_transfer_count().unwrap(), 126);
    let mut chunk_payload = vec![0u8; 70_000];
    chunk_payload[..marker.len()].copy_from_slice(&marker);
    let partial = prepare_outbox(
        &bob,
        &roster,
        &message_body(&roster, 2, [0xD1; 32], Vec::new(), chunk_payload),
    )
    .unwrap();
    let partial_copy = partial
        .recipients()
        .iter()
        .find(|recipient| recipient.recipient() == 1)
        .unwrap();
    assert!(partial_copy.objects().len() >= 3, "incoming package was not chunked");
    let partial_manifest = partial_copy.objects().last().unwrap().clone();
    let partial_present = partial_copy.objects()[0].clone();
    let partial_missing = partial_copy.objects()[1].clone();
    let mut cursor = cache_objects(&mut store, &route, 0, &[partial_present.clone()]);
    cursor = cache_objects(&mut store, &route, cursor, &[partial_manifest.clone()]);
    assert!(authenticate_staged(&mut store, &roster, &alice)
        .unwrap()
        .iter()
        .all(|candidate| candidate.message().digest() != partial.digest()));
    assert_eq!(store.pending_transfer_count().unwrap(), 127);
    assert!(store.recover_pending_downloads(0, 100).unwrap().iter().any(|row| {
        row.source_hash == partial_missing.hash && row.wire_length == partial_missing.wire.len() as u64
    }));

    let admitted = prepare_outbox(
        &bob,
        &roster,
        &message_body(&roster, 2, [0xD2; 32], Vec::new(), marker.to_vec()),
    )
    .unwrap();
    let admitted_object = admitted
        .recipients()
        .iter()
        .find(|recipient| recipient.recipient() == 1)
        .unwrap()
        .objects()[0]
        .clone();
    cursor = cache_objects(&mut store, &route, cursor, &[admitted_object.clone()]);
    let candidates = authenticate_staged(&mut store, &roster, &alice).unwrap();
    assert!(candidates.iter().any(|candidate| {
        candidate.message().digest() == admitted.digest() && candidate.readiness() == CandidateReadiness::Ready
    }));
    assert_eq!(store.pending_transfer_count().unwrap(), 128);

    let blocked_body = message_body(&roster, 1, [0xE4; 32], Vec::new(), marker.to_vec());
    let blocked = prepare_outbox(&alice, &roster, &blocked_body).unwrap();
    let blocked_request = [0xE5; 32];
    let blocked_intent = loki_relay_client::outbox_intent_digest(&blocked_body).unwrap();
    let count_rows = |table: &str| -> i64 {
        support::sql(&root)
            .query_row(&format!("SELECT count(*) FROM {table}"), [], |row| row.get(0))
            .unwrap()
    };
    let callers = count_rows("caller_requests");
    let logicals = count_rows("logical_records");
    let ciphertext = count_rows("ciphertext_objects");
    let outgoing = count_rows("outgoing_recipients");
    let pending_before = store.recover_pending_downloads(0, 100).unwrap();
    let staged_before = collect_staged(&store);
    assert_eq!(
        store
            .commit_outbox(&roster, &alice, &blocked_request, &blocked)
            .unwrap_err(),
        ClientError::Capacity
    );
    assert_eq!(store.pending_transfer_count().unwrap(), 128);
    assert_eq!(count_rows("caller_requests"), callers);
    assert_eq!(count_rows("logical_records"), logicals);
    assert_eq!(count_rows("ciphertext_objects"), ciphertext);
    assert_eq!(count_rows("outgoing_recipients"), outgoing);
    assert!(store
        .lookup_outbox_request(&blocked_request, &blocked_intent)
        .unwrap()
        .is_none());
    for recipient in blocked.recipients() {
        for object in recipient.objects() {
            assert!(
                store.saved_object(&object.hash).unwrap().is_none(),
                "blocked outbox published ciphertext"
            );
        }
    }
    assert_eq!(store.recover_pending_downloads(0, 100).unwrap(), pending_before);
    assert_eq!(collect_staged(&store), staged_before);
    assert_exact_wire(&store, &partial_manifest);
    assert_exact_wire(&store, &partial_present);
    assert_exact_wire(&store, &admitted_object);
    for recipient in first.as_ref().unwrap().recipients() {
        for object in recipient.objects() {
            assert_exact_wire(&store, object);
        }
    }

    let mut refused_payload = marker.to_vec();
    refused_payload.extend_from_slice(&[9]);
    let refused = prepare_outbox(
        &bob,
        &roster,
        &message_body(&roster, 2, [0xD3; 32], Vec::new(), refused_payload),
    )
    .unwrap();
    let refused_object = refused
        .recipients()
        .iter()
        .find(|recipient| recipient.recipient() == 1)
        .unwrap()
        .objects()[0]
        .clone();
    cache_objects(&mut store, &route, cursor, &[refused_object.clone()]);
    let staged_attempt = authenticate_staged(&mut store, &roster, &alice);
    if let Err(error) = &staged_attempt {
        assert!(
            matches!(error, ClientError::Capacity),
            "cap refusal was not capacity"
        );
    }
    let candidates = authenticate_staged(&mut store, &roster, &alice).expect("admission pass");
    assert!(candidates.iter().any(|candidate| candidate.message().digest() == admitted.digest()));
    assert!(candidates.iter().all(|candidate| candidate.message().digest() != refused.digest()));
    assert!(collect_staged(&store).iter().all(|source| source.root_hash != refused_object.hash));
    assert_eq!(store.pending_transfer_count().unwrap(), 128);
    assert_exact_wire(&store, &refused_object);
    assert_exact_wire(&store, &partial_manifest);
    assert_exact_wire(&store, &admitted_object);
    let saved_out = first.unwrap();
    for recipient in saved_out.recipients() {
        for object in recipient.objects() {
            assert_exact_wire(&store, object);
        }
    }
    assert_no_ack_or_original(&store);
    assert_marker_absent(&root, &marker);
    drop(store);

    let store = ClientStore::open(&root, &roster, 1).unwrap();
    assert_eq!(store.pending_transfer_count().unwrap(), 128);
    assert!(store.recover_pending_downloads(0, 100).unwrap().iter().any(|row| {
        row.source_hash == partial_missing.hash && row.wire_length == partial_missing.wire.len() as u64
    }));
    assert!(collect_staged(&store).iter().any(|source| source.root_hash == partial_manifest.hash));
    assert!(collect_staged(&store).iter().all(|source| source.root_hash != refused_object.hash));
    assert_exact_wire(&store, &refused_object);
    assert_exact_wire(&store, &partial_present);
    for recipient in saved_out.recipients() {
        for object in recipient.objects() {
            assert_exact_wire(&store, object);
        }
    }
    assert_marker_absent(&root, &marker);
    assert!(store.recover_incoming_originals(0, 100).unwrap().is_empty());
}
