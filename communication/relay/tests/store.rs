mod support;
use loki_relay_server::{Limits, RelayStore};
use support::Scratch;

fn limits() -> Limits {
    Limits {
        total_bytes: 1_000_000,
        mailbox_bytes: 100_000,
        mailbox_count: 10,
    }
}
fn init(root: &Scratch) -> RelayStore {
    RelayStore::init(
        root.path(),
        [7; 32],
        "http://127.0.0.1:8000",
        &[8; 32],
        [9; 32],
        limits(),
    )
    .unwrap()
}

#[test]
fn root_identity_init_new_private_root() {
    let root = Scratch::new();
    let store = init(&root);
    assert!(RelayStore::init(
        root.path(),
        [7; 32],
        "http://127.0.0.1:8000",
        &[8; 32],
        [9; 32],
        limits()
    )
    .is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let parent = std::fs::metadata(root.path().parent().unwrap()).unwrap();
        let metadata = std::fs::metadata(root.path()).unwrap();
        assert_eq!(metadata.uid(), parent.uid());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        for name in ["receipt.seed", "provision.secret"] {
            assert_eq!(
                std::fs::metadata(root.path().join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
            assert_eq!(std::fs::read(root.path().join(name)).unwrap().len(), 32);
        }
    }
    drop(store);
}

#[test]
fn root_identity_reopen_retains_run_key_and_singleton_metadata() {
    let root = Scratch::new();
    let store = init(&root);
    let key = store.public_key();
    let seed = std::fs::read(root.path().join("receipt.seed")).unwrap();
    drop(store);
    let reopened = RelayStore::open(root.path(), limits()).unwrap();
    assert_eq!(reopened.run_id(), [7; 32]);
    assert_eq!(reopened.public_key(), key);
    assert_eq!(
        std::fs::read(root.path().join("receipt.seed")).unwrap(),
        seed
    );
    let db = rusqlite::Connection::open(root.path().join("relay.sqlite3")).unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM metadata", [], |r| r.get::<_, i64>(0))
            .unwrap(),
        1
    );
    assert_eq!(
        db.query_row("SELECT used_bytes FROM metadata", [], |r| r
            .get::<_, i64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            [],
            |r| r.get::<_, i64>(0)
        )
        .unwrap(),
        1
    );
}

#[test]
#[ignore]
fn root_identity_lock_child() {
    let path = std::env::var_os("RELAY_TEST_ROOT").unwrap();
    let result = RelayStore::open(std::path::Path::new(&path), limits());
    assert_eq!(
        result.is_ok(),
        std::env::var("RELAY_TEST_OPEN").unwrap() == "yes"
    );
}

#[test]
fn root_identity_second_process_lock() {
    let root = Scratch::new();
    let store = init(&root);
    let child = |expected| {
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "root_identity_lock_child",
                "--ignored",
                "--nocapture",
            ])
            .env("RELAY_TEST_ROOT", root.path())
            .env("RELAY_TEST_OPEN", expected)
            .output()
            .unwrap()
    };
    let occupied = child("no");
    assert!(
        occupied.status.success(),
        "{}",
        String::from_utf8_lossy(&occupied.stdout)
    );
    drop(store);
    let released = child("yes");
    assert!(
        released.status.success(),
        "{}",
        String::from_utf8_lossy(&released.stdout)
    );
    let reopened = RelayStore::open(root.path(), limits()).unwrap();
    assert!(child("no").status.success());
    drop(reopened);
}

#[test]
fn root_identity_missing_database_fails_without_recreating() {
    let root = Scratch::new();
    drop(init(&root));
    let path = root.path().join("relay.sqlite3");
    std::fs::remove_file(&path).unwrap();
    assert!(RelayStore::open(root.path(), limits()).is_err());
    assert!(!path.exists());
}

fn corrupt(root: &Scratch, sql: &str) {
    let db = rusqlite::Connection::open(root.path().join("relay.sqlite3")).unwrap();
    db.execute_batch(sql).unwrap();
}

#[test]
fn root_identity_missing_metadata_fails() {
    let root = Scratch::new();
    drop(init(&root));
    corrupt(&root, "DELETE FROM metadata");
    assert!(RelayStore::open(root.path(), limits()).is_err());
}

#[test]
fn root_identity_missing_key_fails_without_replacement() {
    let root = Scratch::new();
    drop(init(&root));
    let seed = root.path().join("receipt.seed");
    std::fs::remove_file(&seed).unwrap();
    assert!(RelayStore::open(root.path(), limits()).is_err());
    assert!(!seed.exists());
}

#[test]
fn root_identity_mismatched_key_fails_without_replacement() {
    let root = Scratch::new();
    drop(init(&root));
    let seed = root.path().join("receipt.seed");
    std::fs::write(&seed, [42; 32]).unwrap();
    assert!(RelayStore::open(root.path(), limits()).is_err());
    assert_eq!(std::fs::read(seed).unwrap(), [42; 32]);
}

#[test]
fn root_identity_mismatched_metadata_run_fails() {
    let root = Scratch::new();
    drop(init(&root));
    corrupt(&root, "UPDATE metadata SET run_id = zeroblob(32)");
    assert!(RelayStore::open(root.path(), limits()).is_err());
}

#[test]
fn root_identity_mismatched_metadata_public_key_fails() {
    let root = Scratch::new();
    drop(init(&root));
    corrupt(
        &root,
        "UPDATE metadata SET receipt_public_key = zeroblob(32)",
    );
    assert!(RelayStore::open(root.path(), limits()).is_err());
}

#[test]
fn root_identity_wrong_schema_fails() {
    let root = Scratch::new();
    drop(init(&root));
    corrupt(
        &root,
        "PRAGMA ignore_check_constraints=ON; UPDATE metadata SET schema_version=2",
    );
    assert!(RelayStore::open(root.path(), limits()).is_err());
}

#[test]
fn root_identity_wrong_protocol_fails() {
    let root = Scratch::new();
    drop(init(&root));
    corrupt(
        &root,
        "PRAGMA ignore_check_constraints=ON; UPDATE metadata SET protocol_version=2",
    );
    assert!(RelayStore::open(root.path(), limits()).is_err());
}

#[test]
fn root_identity_configured_limits_mismatch_fails() {
    let root = Scratch::new();
    drop(init(&root));
    for changed in [
        Limits {
            total_bytes: 1_000_001,
            ..limits()
        },
        Limits {
            mailbox_bytes: 100_001,
            ..limits()
        },
        Limits {
            mailbox_count: 11,
            ..limits()
        },
        Limits {
            total_bytes: 999_999,
            ..limits()
        },
    ] {
        assert!(RelayStore::open(root.path(), changed).is_err());
    }
    assert!(RelayStore::open(root.path(), limits()).is_ok());
}

#[test]
fn root_identity_effective_pragmas_on_init_and_reopen() {
    let root = Scratch::new();
    let store = init(&root);
    let assert_pragmas = |store: &RelayStore| {
        let p = store.pragmas().unwrap();
        eprintln!("effective relay pragmas: {p:?}");
        assert_eq!(p.journal_mode, "wal");
        assert_eq!(p.synchronous, 2);
        assert_eq!(p.foreign_keys, 1);
        assert_eq!(p.busy_timeout, 5000);
        #[cfg(target_os = "macos")]
        assert_eq!(p.fullfsync, 1);
    };
    assert_pragmas(&store);
    drop(store);
    let store = RelayStore::open(root.path(), limits()).unwrap();
    assert_pragmas(&store);
}

#[test]
fn root_identity_partial_init_missing_provision_fails() {
    let root = Scratch::new();
    drop(init(&root));
    let provision = root.path().join("provision.secret");
    std::fs::remove_file(&provision).unwrap();
    assert!(RelayStore::open(root.path(), limits()).is_err());
    assert!(!provision.exists());
    assert!(RelayStore::init(
        root.path(),
        [7; 32],
        "http://127.0.0.1:8000",
        &[8; 32],
        [9; 32],
        limits()
    )
    .is_err());
}

#[test]
fn root_identity_counter_overflow_rejected_before_root_creation() {
    let root = Scratch::new();
    let oversized = Limits {
        total_bytes: i64::MAX as u64 + 1,
        ..limits()
    };
    assert!(RelayStore::init(
        root.path(),
        [7; 32],
        "http://127.0.0.1:8000",
        &[8; 32],
        [9; 32],
        oversized
    )
    .is_err());
    assert!(!root.path().exists());
    let boundary = Limits {
        total_bytes: i64::MAX as u64,
        mailbox_bytes: i64::MAX as u64,
        mailbox_count: i64::MAX as u64,
    };
    drop(
        RelayStore::init(
            root.path(),
            [7; 32],
            "http://127.0.0.1:8000",
            &[8; 32],
            [9; 32],
            boundary,
        )
        .unwrap(),
    );
    assert!(RelayStore::open(root.path(), boundary).is_ok());
}

#[test]
#[cfg(unix)]
fn root_identity_insecure_existing_root_or_secret_fails() {
    use std::os::unix::fs::PermissionsExt;
    let root = Scratch::new();
    drop(init(&root));
    for (path, unsafe_mode, safe_mode) in [
        (root.path().to_owned(), 0o755, 0o700),
        (root.path().join("receipt.seed"), 0o644, 0o600),
        (root.path().join("provision.secret"), 0o644, 0o600),
    ] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(unsafe_mode)).unwrap();
        assert!(RelayStore::open(root.path(), limits()).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(safe_mode)).unwrap();
    }
    assert!(RelayStore::open(root.path(), limits()).is_ok());
}

#[test]
fn root_identity_invalid_used_counter_fails() {
    let root = Scratch::new();
    drop(init(&root));
    corrupt(
        &root,
        "PRAGMA ignore_check_constraints=ON; UPDATE metadata SET used_bytes=-1",
    );
    assert!(RelayStore::open(root.path(), limits()).is_err());
}

#[test]
fn root_identity_malformed_provisioning_metadata_fails() {
    let root = Scratch::new();
    drop(init(&root));
    corrupt(&root, "PRAGMA ignore_check_constraints=ON; UPDATE metadata SET provisioning_verifier=zeroblob(31)");
    assert!(RelayStore::open(root.path(), limits()).is_err());
}

use ed25519_dalek::{Signature, VerifyingKey};
use loki_relay_protocol::{
    canonical::{self, Value},
    http::encode_creation,
    receipt::decode_body,
    types::{Creation, Object, ReceiptBody, RelayPin},
};
use loki_relay_server::{
    capability::{provisioning_verifier, verifier},
    Capability, RelayError, Role, StoredResult,
};
use sha2::{Digest, Sha256};

struct StoreFixture {
    store: RelayStore,
    root: Scratch,
    limits: Limits,
}
impl StoreFixture {
    fn new(limits: Limits) -> Self {
        let root = Scratch::new();
        let mut store = RelayStore::init(
            root.path(),
            [7; 32],
            "http://127.0.0.1:8000",
            &[8; 32],
            provisioning_verifier([7; 32], &[8; 32]),
            limits,
        )
        .unwrap();
        let creation = encode_creation(&Creation {
            read_verifier: verifier(Role::Read, [1; 32], &[2; 32]),
            append_verifier: verifier(Role::Append, [1; 32], &[3; 32]),
            admin_verifier: verifier(Role::Admin, [1; 32], &[4; 32]),
            quota: limits.mailbox_bytes.min(limits.total_bytes),
        })
        .unwrap();
        store
            .create([1; 32], &creation, &Capability::new([8; 32]))
            .unwrap();
        Self {
            store,
            root,
            limits,
        }
    }
    fn db(&self) -> rusqlite::Connection {
        rusqlite::Connection::open(self.root.path().join("relay.sqlite3")).unwrap()
    }
    fn counters(&self) -> (u64, u64, u64, u64) {
        self.db().query_row(
            "SELECT (SELECT used_bytes FROM metadata),used_bytes,next_sequence,(SELECT count(*) FROM objects) FROM mailboxes WHERE id=?1",
            [[1u8; 32].as_slice()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
        ).unwrap()
    }
    fn put(&mut self, object: &Object) -> Result<StoredResult, RelayError> {
        self.store.put([1; 32], object, &Capability::new([3; 32]))
    }
}
fn new_object(record_bytes: &[u8]) -> Object {
    let length = loki_relay_protocol::envelope::padded_wire_length(record_bytes.len()).unwrap();
    let mut wire = vec![0; length];
    wire[..8].copy_from_slice(b"LOKIRLY1");
    wire[8] = 1;
    wire[41..41 + record_bytes.len()].copy_from_slice(record_bytes);
    Object {
        hash: Sha256::digest(&wire).into(),
        wire,
    }
}
fn assert_receipt(receipt: &[u8], key: [u8; 32], object: &Object, sequence: u64) {
    assert_receipt_for(receipt, key, [1; 32], object, sequence);
}
fn assert_receipt_for(
    receipt: &[u8],
    key: [u8; 32],
    mailbox: [u8; 32],
    object: &Object,
    sequence: u64,
) {
    let Value::Array(fields) = canonical::decode(receipt, 512).unwrap() else {
        panic!("receipt array")
    };
    assert_eq!(fields.len(), 2);
    let Value::Bytes(body) = &fields[0] else {
        panic!("receipt body")
    };
    let Value::Bytes(signature) = &fields[1] else {
        panic!("receipt signature")
    };
    assert_eq!(signature.len(), 64);
    let mut signed = b"Loki_Relay_Stored_v1\0".to_vec();
    signed.extend_from_slice(&(body.len() as u32).to_be_bytes());
    signed.extend_from_slice(body);
    VerifyingKey::from_bytes(&key)
        .unwrap()
        .verify_strict(&signed, &Signature::from_slice(signature).unwrap())
        .unwrap();
    assert_eq!(
        decode_body(body).unwrap(),
        ReceiptBody {
            pin: RelayPin { key, run: [7; 32] },
            mailbox,
            hash: object.hash,
            wire_length: object.wire.len() as u64,
            sequence,
            retention: 1,
        }
    );
}

#[test]
fn immutable_put_commits_bytes_counters_and_signed_receipt() {
    let mut f = StoreFixture::new(limits());
    let object = new_object(b"opaque record");
    let saved = f.put(&object).unwrap();
    assert!(saved.created);
    assert_eq!(saved.sequence, 1);
    assert_eq!(f.counters(), (1024, 1024, 2, 1));
    let (wire, length, sequence, receipt): (Vec<u8>, u64, u64, Vec<u8>) = f
        .db()
        .query_row(
            "SELECT wire,wire_length,sequence,receipt FROM objects WHERE mailbox=?1 AND hash=?2",
            rusqlite::params![[1u8; 32].as_slice(), object.hash.as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap();
    assert_eq!(
        (wire, length, sequence, receipt),
        (object.wire.clone(), 1024, 1, saved.receipt.clone())
    );
    let key = f.store.public_key();
    drop(f.store);
    let mut reopened = RelayStore::open(f.root.path(), f.limits).unwrap();
    assert_receipt(&saved.receipt, reopened.public_key(), &object, 1);
    assert_eq!(reopened.public_key(), key);
    let second = new_object(b"second opaque record");
    let next = reopened
        .put([1; 32], &second, &Capability::new([3; 32]))
        .unwrap();
    assert_eq!(next.sequence, 2);
    assert_receipt(&next.receipt, key, &second, 2);
}

#[test]
fn immutable_put_exact_retry_at_quota_reopen() {
    let mut f = StoreFixture::new(Limits {
        total_bytes: 1024,
        mailbox_bytes: 1024,
        mailbox_count: 1,
    });
    let object = new_object(b"retry");
    let original = f.put(&object).unwrap();
    let expected = StoredResult {
        created: false,
        sequence: 1,
        receipt: original.receipt.clone(),
    };
    assert_eq!(f.put(&object).unwrap(), expected);
    assert_eq!(f.counters(), (1024, 1024, 2, 1));
    drop(f.store);
    let mut store = RelayStore::open(f.root.path(), f.limits).unwrap();
    assert_eq!(
        store
            .put([1; 32], &object, &Capability::new([3; 32]))
            .unwrap(),
        expected
    );
    let db = rusqlite::Connection::open(f.root.path().join("relay.sqlite3")).unwrap();
    let counters: (u64, u64, u64) = db
        .query_row(
            "SELECT (SELECT used_bytes FROM metadata),used_bytes,next_sequence FROM mailboxes",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(counters, (1024, 1024, 2));
}

#[test]
fn immutable_put_equal_hash_different_bytes_conflicts() {
    let mut f = StoreFixture::new(limits());
    let object = new_object(b"original");
    let original = f.put(&object).unwrap();
    let mut collision = object.clone();
    collision.wire[100] ^= 1;
    assert_eq!(f.put(&collision), Err(RelayError::Conflict));
    assert_eq!(f.counters(), (1024, 1024, 2, 1));
    let saved: (Vec<u8>, Vec<u8>) = f
        .db()
        .query_row("SELECT wire,receipt FROM objects", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .unwrap();
    assert_eq!(saved, (object.wire, original.receipt));
}

#[test]
fn immutable_put_get_is_private_exact_and_non_destructive() {
    let mut f = StoreFixture::new(limits());
    let object = new_object(b"private opaque object");
    f.put(&object).unwrap();
    let read = Capability::new([2; 32]);
    for _ in 0..2 {
        assert_eq!(
            f.store.get([1; 32], object.hash, &read).unwrap(),
            object.wire
        );
    }
    for secret in [[3; 32], [4; 32], [9; 32]] {
        assert_eq!(
            f.store.get([1; 32], object.hash, &Capability::new(secret)),
            Err(RelayError::Capability)
        );
        assert_eq!(
            f.store.get([1; 32], [0; 32], &Capability::new(secret)),
            Err(RelayError::Capability)
        );
    }
    assert_eq!(
        f.store.get([1; 32], [0; 32], &read),
        Err(RelayError::ObjectNotFound)
    );
    assert_eq!(
        f.store.get([0; 32], object.hash, &read),
        Err(RelayError::Capability)
    );
    assert_eq!(f.counters(), (1024, 1024, 2, 1));
    drop(f.store);
    let mut store = RelayStore::open(f.root.path(), f.limits).unwrap();
    assert_eq!(store.get([1; 32], object.hash, &read).unwrap(), object.wire);
}

#[test]
fn immutable_put_rejects_wrong_whole_wire_hash() {
    let mut f = StoreFixture::new(limits());
    let mut object = new_object(b"hash mismatch");
    object.hash = [0; 32];
    assert_eq!(f.put(&object), Err(RelayError::MalformedRequest));
    assert_eq!(f.counters(), (0, 0, 1, 0));
}

#[test]
fn immutable_put_validates_framing_version_padding_and_size() {
    let mut f = StoreFixture::new(limits());
    let mut magic = new_object(b"bad magic").wire;
    magic[0] ^= 1;
    let mut version = new_object(b"bad version").wire;
    version[8] = 2;
    let mut oversized = vec![0; 66560];
    oversized[..8].copy_from_slice(b"LOKIRLY1");
    oversized[8] = 1;
    for (wire, error) in [
        (magic, RelayError::MalformedRequest),
        (version, RelayError::MalformedRequest),
        (vec![], RelayError::MalformedRequest),
        (vec![0; 1023], RelayError::MalformedRequest),
        (vec![0; 1025], RelayError::MalformedRequest),
        (oversized, RelayError::ObjectTooLarge),
    ] {
        let object = Object {
            hash: Sha256::digest(&wire).into(),
            wire,
        };
        assert!(matches!(f.put(&object), Err(e) if e == error));
        assert_eq!(f.counters(), (0, 0, 1, 0));
    }
    let mut config = new_object(b"opaque configuration");
    config.wire[..8].copy_from_slice(b"LOKICFG1");
    config.hash = Sha256::digest(&config.wire).into();
    assert!(f.put(&config).unwrap().created);
    let largest = new_object(&vec![0xaa; 65400]);
    assert_eq!(largest.wire.len(), 65536);
    assert!(f.put(&largest).unwrap().created);
    assert_eq!(f.counters(), (66560, 66560, 3, 2));
}

#[test]
fn immutable_put_installs_objects_for_reviewed_existing_mailbox() {
    let mut f = StoreFixture::new(limits());
    f.db().execute_batch("DROP TABLE objects").unwrap();
    drop(f.store);
    f.store = RelayStore::open(f.root.path(), f.limits).unwrap();
    let object = new_object(b"existing mailbox");
    let saved = f.put(&object).unwrap();
    assert_eq!(saved.sequence, 1);
    assert_receipt(&saved.receipt, f.store.public_key(), &object, 1);
    assert_eq!(f.counters(), (1024, 1024, 2, 1));
}

#[test]
fn immutable_put_unprovisioned_root_hides_unknown_mailbox() {
    let root = Scratch::new();
    let mut store = init(&root);
    let object = new_object(b"unknown mailbox");
    let capability = Capability::new([3; 32]);
    assert_eq!(
        store.put([1; 32], &object, &capability),
        Err(RelayError::Capability)
    );
    assert_eq!(
        store.get([1; 32], object.hash, &capability),
        Err(RelayError::Capability)
    );
    let db = rusqlite::Connection::open(root.path().join("relay.sqlite3")).unwrap();
    let count: u64 = db
        .query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
}

#[test]
fn immutable_put_authenticates_current_append_before_retry_and_quota() {
    let mut f = StoreFixture::new(Limits {
        total_bytes: 1024,
        mailbox_bytes: 1024,
        mailbox_count: 1,
    });
    let object = new_object(b"authenticated retry");
    let original = f.put(&object).unwrap();
    for secret in [[2; 32], [4; 32], [9; 32]] {
        assert!(matches!(
            f.store.put([1; 32], &object, &Capability::new(secret)),
            Err(RelayError::Capability)
        ));
    }
    assert!(matches!(
        f.store.put([0; 32], &object, &Capability::new([3; 32])),
        Err(RelayError::Capability)
    ));
    f.db()
        .execute(
            "UPDATE mailboxes SET append_verifier=?1,append_revision=2",
            [verifier(Role::Append, [1; 32], &[5; 32]).as_slice()],
        )
        .unwrap();
    assert!(matches!(f.put(&object), Err(RelayError::Capability)));
    assert_eq!(
        f.store
            .put([1; 32], &object, &Capability::new([5; 32]))
            .unwrap(),
        StoredResult {
            created: false,
            sequence: 1,
            receipt: original.receipt
        }
    );
    assert_eq!(f.counters(), (1024, 1024, 2, 1));
}

#[test]
fn immutable_put_quota_guard_keeps_original_retry_and_counters() {
    for (total_bytes, mailbox_bytes) in [(1024, 2048), (2048, 1024)] {
        let mut f = StoreFixture::new(Limits {
            total_bytes,
            mailbox_bytes,
            mailbox_count: 1,
        });
        let object = new_object(b"first object");
        let original = f.put(&object).unwrap();
        assert!(matches!(
            f.put(&new_object(b"over quota")),
            Err(RelayError::QuotaExhausted)
        ));
        assert_eq!(f.counters(), (1024, 1024, 2, 1));
        assert_eq!(f.put(&object).unwrap().receipt, original.receipt);
        assert_eq!(
            f.store
                .get([1; 32], object.hash, &Capability::new([2; 32]))
                .unwrap(),
            object.wire
        );
    }
}

#[test]
fn immutable_put_total_quota_across_mailboxes() {
    let mut f = StoreFixture::new(Limits {
        total_bytes: 2048,
        mailbox_bytes: 2048,
        mailbox_count: 2,
    });
    let creation = encode_creation(&Creation {
        read_verifier: verifier(Role::Read, [6; 32], &[2; 32]),
        append_verifier: verifier(Role::Append, [6; 32], &[3; 32]),
        admin_verifier: verifier(Role::Admin, [6; 32], &[4; 32]),
        quota: 2048,
    })
    .unwrap();
    f.store
        .create([6; 32], &creation, &Capability::new([8; 32]))
        .unwrap();
    let object = new_object(b"shared bytes distinct mailbox");
    f.put(&object).unwrap();
    let second = f
        .store
        .put([6; 32], &object, &Capability::new([3; 32]))
        .unwrap();
    assert_receipt_for(&second.receipt, f.store.public_key(), [6; 32], &object, 1);
    assert!(matches!(
        f.put(&new_object(b"total full")),
        Err(RelayError::QuotaExhausted)
    ));
    assert_eq!(f.counters(), (2048, 1024, 2, 2));
    let saved: (u64, u64) = f
        .db()
        .query_row(
            "SELECT used_bytes,next_sequence FROM mailboxes WHERE id=?1",
            [[6u8; 32].as_slice()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(saved, (1024, 2));
    assert_eq!(
        f.store
            .put([6; 32], &object, &Capability::new([3; 32]))
            .unwrap()
            .receipt,
        second.receipt
    );
}

#[test]
fn immutable_put_sequence_overflow_rejects_without_mutation() {
    let mut f = StoreFixture::new(limits());
    let object = new_object(b"before overflow");
    let original = f.put(&object).unwrap();
    f.db()
        .execute("UPDATE mailboxes SET next_sequence=?1", [i64::MAX])
        .unwrap();
    assert!(matches!(
        f.put(&new_object(b"cannot allocate next")),
        Err(RelayError::StorageUnavailable)
    ));
    assert_eq!(f.counters(), (1024, 1024, i64::MAX as u64, 1));
    assert_eq!(f.put(&object).unwrap().receipt, original.receipt);
    assert_eq!(
        f.store
            .get([1; 32], object.hash, &Capability::new([2; 32]))
            .unwrap(),
        object.wire
    );
}

#[test]
fn immutable_put_sqlite_failure_after_insert_rolls_back_before_receipt() {
    let mut f = StoreFixture::new(limits());
    let object = new_object(b"transaction rollback");
    f.db().execute_batch("CREATE TRIGGER fail_counter BEFORE UPDATE OF used_bytes ON metadata BEGIN SELECT RAISE(ABORT,'injected storage failure'); END;").unwrap();
    assert!(matches!(
        f.put(&object),
        Err(RelayError::StorageUnavailable)
    ));
    assert_eq!(f.counters(), (0, 0, 1, 0));
    assert_eq!(
        f.store.get([1; 32], object.hash, &Capability::new([2; 32])),
        Err(RelayError::ObjectNotFound)
    );
    drop(f.store);
    f.store = RelayStore::open(f.root.path(), f.limits).unwrap();
    assert_eq!(f.counters(), (0, 0, 1, 0));
    f.db().execute_batch("DROP TRIGGER fail_counter").unwrap();
    let saved = f.put(&object).unwrap();
    assert!(saved.created);
    assert_eq!(saved.sequence, 1);
    assert_receipt(&saved.receipt, f.store.public_key(), &object, 1);
    assert_eq!(f.counters(), (1024, 1024, 2, 1));
}

#[test]
fn immutable_put_get_existing_empty_mailbox_returns_not_found() {
    let mut f = StoreFixture::new(limits());
    f.db().execute_batch("DROP TABLE objects").unwrap();
    let object = new_object(b"absent object table");
    assert_eq!(
        f.store.get([1; 32], object.hash, &Capability::new([2; 32])),
        Err(RelayError::ObjectNotFound)
    );
    assert_eq!(
        f.store.get([1; 32], object.hash, &Capability::new([3; 32])),
        Err(RelayError::Capability)
    );
    assert!(f.put(&object).unwrap().created);
}

fn capacity_snapshot(f: &StoreFixture) -> Vec<Vec<Vec<rusqlite::types::Value>>> {
    let db = f.db();
    [
        "SELECT * FROM metadata ORDER BY singleton",
        "SELECT * FROM mailboxes ORDER BY id",
        "SELECT * FROM objects ORDER BY mailbox,sequence",
    ]
    .into_iter()
    .map(|sql| {
        if sql.contains("FROM objects") && !db.query_row(
            "SELECT EXISTS (SELECT 1 FROM sqlite_master WHERE type='table' AND name='objects')",
            [], |row| row.get::<_, bool>(0),
        ).unwrap() {
            return Vec::new();
        }
        let mut statement = db.prepare(sql).unwrap();
        let columns = statement.column_count();
        statement
            .query_map([], |row| (0..columns).map(|i| row.get(i)).collect())
            .unwrap()
            .collect::<rusqlite::Result<Vec<_>>>()
            .unwrap()
    })
    .collect()
}

fn capacity_retry(f: &mut StoreFixture, object: &Object, saved: &StoredResult, secret: [u8; 32]) {
    let before = capacity_snapshot(f);
    assert_eq!(
        f.store.put([1; 32], object, &Capability::new(secret)),
        Ok(StoredResult {
            created: false,
            sequence: saved.sequence,
            receipt: saved.receipt.clone(),
        })
    );
    let wire = f
        .store
        .get([1; 32], object.hash, &Capability::new([2; 32]))
        .unwrap();
    assert_eq!(wire, object.wire);
    assert_eq!(<[u8; 32]>::from(Sha256::digest(&wire)), object.hash);
    assert_receipt(&saved.receipt, f.store.public_key(), object, saved.sequence);
    assert_eq!(capacity_snapshot(f), before);
}

#[test]
fn capacity_preserves_zero_and_subobject_quotas() {
    for (total_bytes, mailbox_bytes) in [(0, 2048), (2048, 0), (1023, 2048), (2048, 1023)] {
        let mut f = StoreFixture::new(Limits {
            total_bytes,
            mailbox_bytes,
            mailbox_count: 1,
        });
        let before = capacity_snapshot(&f);
        let object = new_object(b"one complete object");
        assert_eq!(f.put(&object), Err(RelayError::QuotaExhausted));
        let counters: (u64, u64, u64) = f
            .db()
            .query_row(
                "SELECT (SELECT used_bytes FROM metadata),used_bytes,next_sequence FROM mailboxes",
                [],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(counters, (0, 0, 1));
        assert_eq!(
            f.store.get([1; 32], object.hash, &Capability::new([2; 32])),
            Err(RelayError::ObjectNotFound)
        );
        assert_eq!(capacity_snapshot(&f), before);
    }
}

#[test]
fn capacity_preserves_exact_capacity_current_credentials_and_reopen() {
    let mut f = StoreFixture::new(Limits {
        total_bytes: 1024,
        mailbox_bytes: 1024,
        mailbox_count: 1,
    });
    let object = new_object(b"retained at exact capacity");
    let saved = f.put(&object).unwrap();
    let update = loki_relay_protocol::http::encode_append_update(
        &loki_relay_protocol::types::AppendUpdate {
            revision: 2,
            verifier: verifier(Role::Append, [1; 32], &[5; 32]),
        },
    )
    .unwrap();
    assert_eq!(
        f.store.rotate([1; 32], &update, &Capability::new([4; 32])),
        Ok(2)
    );
    let before = capacity_snapshot(&f);
    let extra = new_object(b"no room");
    assert_eq!(f.put(&object), Err(RelayError::Capability));
    assert_eq!(
        f.store.put([1; 32], &extra, &Capability::new([5; 32])),
        Err(RelayError::QuotaExhausted)
    );
    assert_eq!(f.counters(), (1024, 1024, 2, 1));
    assert_eq!(capacity_snapshot(&f), before);
    capacity_retry(&mut f, &object, &saved, [5; 32]);
    drop(f.store);
    f.store = RelayStore::open(f.root.path(), f.limits).unwrap();
    assert_eq!(capacity_snapshot(&f), before);
    assert_eq!(
        f.store.put([1; 32], &extra, &Capability::new([5; 32])),
        Err(RelayError::QuotaExhausted)
    );
    capacity_retry(&mut f, &object, &saved, [5; 32]);
}

#[test]
fn capacity_preserves_one_byte_short_of_second_object() {
    for (total_bytes, mailbox_bytes) in [(2047, 4096), (4096, 2047)] {
        let mut f = StoreFixture::new(Limits {
            total_bytes,
            mailbox_bytes,
            mailbox_count: 1,
        });
        let object = new_object(b"first complete object");
        let saved = f.put(&object).unwrap();
        let before = capacity_snapshot(&f);
        assert_eq!(
            f.put(&new_object(b"second complete object")),
            Err(RelayError::QuotaExhausted)
        );
        assert_eq!(f.counters(), (1024, 1024, 2, 1));
        assert_eq!(capacity_snapshot(&f), before);
        capacity_retry(&mut f, &object, &saved, [3; 32]);
    }
}

#[test]
fn capacity_preserves_independent_mailbox_and_total_accounting() {
    let mut f = StoreFixture::new(Limits {
        total_bytes: 3072,
        mailbox_bytes: 2048,
        mailbox_count: 2,
    });
    let creation = encode_creation(&Creation {
        read_verifier: verifier(Role::Read, [6; 32], &[2; 32]),
        append_verifier: verifier(Role::Append, [6; 32], &[3; 32]),
        admin_verifier: verifier(Role::Admin, [6; 32], &[4; 32]),
        quota: 2048,
    })
    .unwrap();
    f.store
        .create([6; 32], &creation, &Capability::new([8; 32]))
        .unwrap();
    let object = new_object(b"same hash in separate mailboxes");
    let saved = f.put(&object).unwrap();
    f.put(&new_object(b"fills first mailbox")).unwrap();
    let extra = new_object(b"another object");
    let before = capacity_snapshot(&f);
    assert_eq!(f.put(&extra), Err(RelayError::QuotaExhausted));
    assert_eq!(capacity_snapshot(&f), before);
    let second = f
        .store
        .put([6; 32], &object, &Capability::new([3; 32]))
        .unwrap();
    assert_eq!(f.counters(), (3072, 2048, 3, 3));
    assert_receipt_for(&second.receipt, f.store.public_key(), [6; 32], &object, 1);
    let before = capacity_snapshot(&f);
    assert_eq!(
        f.store.put([6; 32], &extra, &Capability::new([3; 32])),
        Err(RelayError::QuotaExhausted)
    );
    assert_eq!(capacity_snapshot(&f), before);
    capacity_retry(&mut f, &object, &saved, [3; 32]);
    assert_eq!(
        f.store.put([6; 32], &object, &Capability::new([3; 32])),
        Ok(StoredResult {
            created: false,
            ..second
        })
    );
    assert_eq!(
        f.store
            .get([6; 32], object.hash, &Capability::new([2; 32]))
            .unwrap(),
        object.wire
    );
    assert_eq!(capacity_snapshot(&f), before);
}

#[test]
fn capacity_preserves_checked_byte_counter_boundaries() {
    let max = i64::MAX as u64;
    for (total_used, mailbox_used) in [
        (max - 1024, 1024),
        (1024, max - 1024),
        (max - 1024, max - 1024),
    ] {
        let mut f = StoreFixture::new(Limits {
            total_bytes: max,
            mailbox_bytes: max,
            mailbox_count: 1,
        });
        let object = new_object(b"original before artificial boundary");
        let saved = f.put(&object).unwrap();
        f.db()
            .execute("UPDATE metadata SET used_bytes=?1", [total_used])
            .unwrap();
        f.db()
            .execute("UPDATE mailboxes SET used_bytes=?1", [mailbox_used])
            .unwrap();
        let boundary = new_object(b"one small allocation at signed maximum");
        let allocated = f.put(&boundary).unwrap();
        assert_eq!(allocated.sequence, 2);
        assert_eq!(f.counters(), (total_used + 1024, mailbox_used + 1024, 3, 2));
        let before = capacity_snapshot(&f);
        assert_eq!(
            f.put(&new_object(b"would exceed signed maximum")),
            Err(RelayError::QuotaExhausted)
        );
        assert_eq!(capacity_snapshot(&f), before);
        capacity_retry(&mut f, &object, &saved, [3; 32]);
        capacity_retry(&mut f, &boundary, &allocated, [3; 32]);
        drop(f.store);
        f.store = RelayStore::open(f.root.path(), f.limits).unwrap();
        assert_eq!(capacity_snapshot(&f), before);
        capacity_retry(&mut f, &boundary, &allocated, [3; 32]);
    }
}

#[test]
fn capacity_preserves_highest_allocatable_sequence() {
    let mut f = StoreFixture::new(limits());
    let original = new_object(b"earlier sequence");
    let saved = f.put(&original).unwrap();
    f.db()
        .execute("UPDATE mailboxes SET next_sequence=?1", [i64::MAX - 1])
        .unwrap();
    let boundary = new_object(b"highest allocatable sequence");
    let allocated = f.put(&boundary).unwrap();
    assert_eq!(allocated.sequence, i64::MAX as u64 - 1);
    assert_eq!(f.counters(), (2048, 2048, i64::MAX as u64, 2));
    let before = capacity_snapshot(&f);
    let extra = new_object(b"cannot persist next sequence");
    assert_eq!(f.put(&extra), Err(RelayError::StorageUnavailable));
    assert_eq!(capacity_snapshot(&f), before);
    capacity_retry(&mut f, &original, &saved, [3; 32]);
    capacity_retry(&mut f, &boundary, &allocated, [3; 32]);
    drop(f.store);
    f.store = RelayStore::open(f.root.path(), f.limits).unwrap();
    assert_eq!(f.put(&extra), Err(RelayError::StorageUnavailable));
    assert_eq!(capacity_snapshot(&f), before);
    capacity_retry(&mut f, &boundary, &allocated, [3; 32]);
}

#[test]
fn capacity_preserves_configured_limits_and_public_integer_bounds() {
    let mut f = StoreFixture::new(limits());
    let object = new_object(b"persisted limits");
    let saved = f.put(&object).unwrap();
    let before = capacity_snapshot(&f);
    drop(f.store);
    for index in 0..3 {
        for delta in [-1i64, 1] {
            let mut changed = f.limits;
            let field = match index {
                0 => &mut changed.total_bytes,
                1 => &mut changed.mailbox_bytes,
                _ => &mut changed.mailbox_count,
            };
            *field = (*field as i64 + delta) as u64;
            assert!(RelayStore::open(f.root.path(), changed).is_err());
        }
        let mut oversized = f.limits;
        let field = match index {
            0 => &mut oversized.total_bytes,
            1 => &mut oversized.mailbox_bytes,
            _ => &mut oversized.mailbox_count,
        };
        *field = i64::MAX as u64 + 1;
        assert!(matches!(
            RelayStore::open(f.root.path(), oversized),
            Err(RelayError::MalformedRequest)
        ));
        let root = Scratch::new();
        assert!(matches!(
            RelayStore::init(
                root.path(),
                [7; 32],
                "http://127.0.0.1:8000",
                &[8; 32],
                [9; 32],
                oversized
            ),
            Err(RelayError::MalformedRequest)
        ));
        assert!(!root.path().exists());
    }
    f.store = RelayStore::open(f.root.path(), f.limits).unwrap();
    assert_eq!(capacity_snapshot(&f), before);
    capacity_retry(&mut f, &object, &saved, [3; 32]);
}

#[test]
fn capacity_preserves_revision_maximum_and_canonical_bounds() {
    let mut f = StoreFixture::new(limits());
    let object = new_object(b"retained through maximum revision");
    let saved = f.put(&object).unwrap();
    f.db()
        .execute("UPDATE mailboxes SET append_revision=?1", [i64::MAX - 1])
        .unwrap();
    let request = loki_relay_protocol::http::encode_append_update(
        &loki_relay_protocol::types::AppendUpdate {
            revision: i64::MAX as u64,
            verifier: verifier(Role::Append, [1; 32], &[5; 32]),
        },
    )
    .unwrap();
    let admin = Capability::new([4; 32]);
    assert_eq!(
        f.store.rotate([1; 32], &request, &admin),
        Ok(i64::MAX as u64)
    );
    let before = capacity_snapshot(&f);
    let skipped = loki_relay_protocol::http::encode_append_update(
        &loki_relay_protocol::types::AppendUpdate {
            revision: 2,
            verifier: verifier(Role::Append, [1; 32], &[6; 32]),
        },
    )
    .unwrap();
    assert_eq!(
        f.store.rotate([1; 32], &skipped, &admin),
        Err(RelayError::Conflict)
    );
    for revision in [0, i64::MAX as u64 + 1, u64::MAX] {
        let request = canonical::encode(&Value::Array(vec![
            Value::Integer(1.into()),
            Value::Integer(revision.into()),
            Value::Bytes(verifier(Role::Append, [1; 32], &[6; 32]).to_vec()),
        ]))
        .unwrap();
        assert_eq!(
            f.store.rotate([1; 32], &request, &admin),
            Err(RelayError::MalformedRequest)
        );
        assert_eq!(capacity_snapshot(&f), before);
    }
    assert_eq!(
        f.store.rotate([1; 32], &request, &admin),
        Ok(i64::MAX as u64)
    );
    assert_eq!(capacity_snapshot(&f), before);
    drop(f.store);
    f.store = RelayStore::open(f.root.path(), f.limits).unwrap();
    assert_eq!(
        f.store.rotate([1; 32], &request, &admin),
        Ok(i64::MAX as u64)
    );
    assert_eq!(capacity_snapshot(&f), before);
    capacity_retry(&mut f, &object, &saved, [5; 32]);
}
