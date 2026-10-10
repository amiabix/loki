use loki_relay_protocol::{
    http::{encode_append_update, encode_creation},
    types::{AppendUpdate, Creation, CreationResult},
};
use loki_relay_server::capability::{verifier, Capability, Role};
use loki_relay_server::{Limits, RelayError, RelayStore};
mod support;
use support::Scratch;

fn update(revision: u64, secret: [u8; 32]) -> Vec<u8> {
    encode_append_update(&AppendUpdate {
        revision,
        verifier: verifier(Role::Append, [1; 32], &secret),
    })
    .unwrap()
}

#[test]
fn rotation_monotonic_accepts_next_and_persists() {
    let root = Scratch::new();
    let mut store = init(&root, limits());
    store
        .create([1; 32], &creation(50), &Capability::new([8; 32]))
        .unwrap();
    let request = update(2, [5; 32]);
    assert_eq!(
        store.rotate([1; 32], &request, &Capability::new([4; 32])),
        Ok(2)
    );
    drop(store);
    let _store = RelayStore::open(root.path(), limits()).unwrap();
    let db = rusqlite::Connection::open(root.path().join("relay.sqlite3")).unwrap();
    let saved: (u64, Vec<u8>, Option<Vec<u8>>) = db
        .query_row(
            "SELECT append_revision,append_verifier,append_update FROM mailboxes",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        saved,
        (
            2,
            verifier(Role::Append, [1; 32], &[5; 32]).to_vec(),
            Some(request)
        )
    );
}

#[test]
fn rotation_monotonic_authenticates_current_admin_before_retry() {
    let root = Scratch::new();
    let mut store = init(&root, limits());
    let admin = Capability::new([4; 32]);
    let request = update(2, [5; 32]);
    assert_eq!(
        store.rotate([1; 32], &[], &admin),
        Err(RelayError::Capability)
    );
    let db = rusqlite::Connection::open(root.path().join("relay.sqlite3")).unwrap();
    assert_eq!(
        db.query_row(
            "SELECT count(*) FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'",
            [],
            |r| r.get::<_, u64>(0)
        )
        .unwrap(),
        1
    );
    store
        .create([1; 32], &creation(50), &Capability::new([8; 32]))
        .unwrap();
    for secret in [[2; 32], [3; 32], [8; 32], [9; 32]] {
        for body in [&request[..], &[][..]] {
            assert_eq!(
                store.rotate([1; 32], body, &Capability::new(secret)),
                Err(RelayError::Capability)
            );
        }
    }
    assert_eq!(
        store.rotate([0; 32], &request, &admin),
        Err(RelayError::Capability)
    );
    assert_eq!(store.rotate([1; 32], &request, &admin), Ok(2));
    db.execute(
        "UPDATE mailboxes SET admin_verifier=?1",
        [verifier(Role::Admin, [1; 32], &[6; 32]).as_slice()],
    )
    .unwrap();
    assert_eq!(
        store.rotate([1; 32], &request, &admin),
        Err(RelayError::Capability)
    );
    assert_eq!(
        store.rotate([1; 32], &request, &Capability::new([6; 32])),
        Ok(2)
    );
    db.execute(
        "UPDATE mailboxes SET admin_verifier=?1",
        [verifier(Role::Admin, [0; 32], &[6; 32]).as_slice()],
    )
    .unwrap();
    assert_eq!(
        store.rotate([1; 32], &request, &Capability::new([6; 32])),
        Err(RelayError::Capability)
    );
    db.execute(
        "UPDATE mailboxes SET admin_verifier=?1",
        [verifier(Role::Append, [1; 32], &[6; 32]).as_slice()],
    )
    .unwrap();
    assert_eq!(
        store.rotate([1; 32], &request, &Capability::new([6; 32])),
        Err(RelayError::Capability)
    );
}

#[test]
fn rotation_monotonic_exact_retry_and_revision_conflicts() {
    let root = Scratch::new();
    let mut store = init(&root, limits());
    let admin = Capability::new([4; 32]);
    store
        .create([1; 32], &creation(50), &Capability::new([8; 32]))
        .unwrap();
    assert_eq!(
        store.rotate([1; 32], &update(1, [3; 32]), &admin),
        Err(RelayError::Conflict)
    );
    let request = update(2, [5; 32]);
    assert_eq!(store.rotate([1; 32], &request, &admin), Ok(2));
    drop(store);
    let mut store = RelayStore::open(root.path(), limits()).unwrap();
    for _ in 0..2 {
        assert_eq!(store.rotate([1; 32], &request, &admin), Ok(2));
    }
    for rejected in [update(1, [3; 32]), update(2, [6; 32]), update(4, [6; 32])] {
        assert_eq!(
            store.rotate([1; 32], &rejected, &admin),
            Err(RelayError::Conflict)
        );
    }
    assert_eq!(store.rotate([1; 32], &update(3, [6; 32]), &admin), Ok(3));
    assert_eq!(
        store.rotate([1; 32], &request, &admin),
        Err(RelayError::Conflict)
    );
    let db = rusqlite::Connection::open(root.path().join("relay.sqlite3")).unwrap();
    let state: (u64, Vec<u8>, Vec<u8>) = db
        .query_row(
            "SELECT append_revision,append_verifier,append_update FROM mailboxes",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        state,
        (
            3,
            verifier(Role::Append, [1; 32], &[6; 32]).to_vec(),
            update(3, [6; 32])
        )
    );
}

#[test]
fn rotation_monotonic_creation_retry_preserves_credentials_and_objects() {
    use loki_relay_protocol::types::Object;
    use loki_relay_server::StoredResult;
    use sha2::{Digest, Sha256};
    let root = Scratch::new();
    let limits = Limits {
        total_bytes: 2048,
        mailbox_bytes: 2048,
        mailbox_count: 1,
    };
    let mut store = init(&root, limits);
    let creation = creation(2048);
    let provision = Capability::new([8; 32]);
    let admin = Capability::new([4; 32]);
    store.create([1; 32], &creation, &provision).unwrap();
    let mut wire = vec![0; 1024];
    wire[..8].copy_from_slice(b"LOKIRLY1");
    wire[8] = 1;
    let object = Object {
        hash: Sha256::digest(&wire).into(),
        wire,
    };
    let original = store
        .put([1; 32], &object, &Capability::new([3; 32]))
        .unwrap();
    let request = update(2, [5; 32]);
    assert_eq!(store.rotate([1; 32], &request, &admin), Ok(2));
    let mut new_object = object.clone();
    new_object.wire[100] = 1;
    new_object.hash = Sha256::digest(&new_object.wire).into();
    for candidate in [&object, &new_object] {
        assert_eq!(
            store.put([1; 32], candidate, &Capability::new([3; 32])),
            Err(RelayError::Capability)
        );
    }
    assert_eq!(
        store
            .put([1; 32], &new_object, &Capability::new([5; 32]))
            .unwrap()
            .sequence,
        2
    );
    drop(store);
    let mut store = RelayStore::open(root.path(), limits).unwrap();
    for _ in 0..2 {
        assert_eq!(
            store.create([1; 32], &creation, &provision).unwrap(),
            CreationResult {
                created: false,
                run: [7; 32],
                quota: 2048,
                append_revision: 2
            }
        );
        assert_eq!(store.rotate([1; 32], &request, &admin), Ok(2));
        assert_eq!(
            store.put([1; 32], &object, &Capability::new([3; 32])),
            Err(RelayError::Capability)
        );
        assert_eq!(
            store
                .put([1; 32], &object, &Capability::new([5; 32]))
                .unwrap(),
            StoredResult {
                created: false,
                sequence: original.sequence,
                receipt: original.receipt.clone()
            }
        );
    }
    assert_eq!(
        store
            .get([1; 32], object.hash, &Capability::new([2; 32]))
            .unwrap(),
        object.wire
    );
    assert_eq!(
        store.get([1; 32], object.hash, &admin),
        Err(RelayError::Capability)
    );
    assert_eq!(
        store.put([1; 32], &object, &admin),
        Err(RelayError::Capability)
    );
    let db = rusqlite::Connection::open(root.path().join("relay.sqlite3")).unwrap();
    let counters: (u64, u64, u64, u64) = db.query_row("SELECT (SELECT used_bytes FROM metadata),used_bytes,next_sequence,(SELECT count(*) FROM objects) FROM mailboxes", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).unwrap();
    assert_eq!(counters, (2048, 2048, 3, 2));
    let credentials: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = db.query_row("SELECT creation_request,read_verifier,admin_verifier,append_verifier,append_update FROM mailboxes", [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).unwrap();
    assert_eq!(
        credentials,
        (
            creation,
            verifier(Role::Read, [1; 32], &[2; 32]).to_vec(),
            verifier(Role::Admin, [1; 32], &[4; 32]).to_vec(),
            verifier(Role::Append, [1; 32], &[5; 32]).to_vec(),
            request
        )
    );
}

#[test]
fn rotation_monotonic_rejects_malformed_update_without_mutation() {
    let root = Scratch::new();
    let mut store = init(&root, limits());
    store
        .create([1; 32], &creation(50), &Capability::new([8; 32]))
        .unwrap();
    let request = update(2, [5; 32]);
    let mut noncanonical = request.clone();
    noncanonical.splice(2..3, [0x18, 2]);
    let mut trailing = request.clone();
    trailing.push(0);
    for invalid in [vec![], noncanonical, trailing] {
        assert_eq!(
            store.rotate([1; 32], &invalid, &Capability::new([4; 32])),
            Err(RelayError::MalformedRequest)
        );
    }
    let db = rusqlite::Connection::open(root.path().join("relay.sqlite3")).unwrap();
    let state: (u64, Vec<u8>, Option<Vec<u8>>) = db
        .query_row(
            "SELECT append_revision,append_verifier,append_update FROM mailboxes",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    assert_eq!(
        state,
        (1, verifier(Role::Append, [1; 32], &[3; 32]).to_vec(), None)
    );
    assert_eq!(
        store.rotate([1; 32], &request, &Capability::new([4; 32])),
        Ok(2)
    );
}

#[test]
fn rotation_monotonic_serializes_before_admin_authentication() {
    let root = Scratch::new();
    let mut store = init(&root, limits());
    store
        .create([1; 32], &creation(50), &Capability::new([8; 32]))
        .unwrap();
    let db = rusqlite::Connection::open(root.path().join("relay.sqlite3")).unwrap();
    db.execute_batch("BEGIN IMMEDIATE").unwrap();
    assert_eq!(
        store.rotate([1; 32], &update(2, [5; 32]), &Capability::new([9; 32])),
        Err(RelayError::StorageUnavailable)
    );
    db.execute(
        "UPDATE mailboxes SET admin_verifier=?1",
        [verifier(Role::Admin, [1; 32], &[6; 32]).as_slice()],
    )
    .unwrap();
    db.execute_batch("COMMIT").unwrap();
    assert_eq!(
        store.rotate([1; 32], &update(2, [5; 32]), &Capability::new([4; 32])),
        Err(RelayError::Capability)
    );
    assert_eq!(
        store.rotate([1; 32], &update(2, [5; 32]), &Capability::new([6; 32])),
        Ok(2)
    );
}

#[test]
fn rotation_monotonic_checked_revision_guard() {
    let root = Scratch::new();
    let mut store = init(&root, limits());
    store
        .create([1; 32], &creation(50), &Capability::new([8; 32]))
        .unwrap();
    let admin = Capability::new([4; 32]);
    let db = rusqlite::Connection::open(root.path().join("relay.sqlite3")).unwrap();
    db.execute("UPDATE mailboxes SET append_revision=?1", [i64::MAX - 1])
        .unwrap();
    let request = update(i64::MAX as u64, [5; 32]);
    assert_eq!(store.rotate([1; 32], &request, &admin), Ok(i64::MAX as u64));
    assert_eq!(store.rotate([1; 32], &request, &admin), Ok(i64::MAX as u64));
    assert_eq!(
        store.rotate([1; 32], &update(2, [6; 32]), &admin),
        Err(RelayError::Conflict)
    );
    let saved: (u64, Vec<u8>) = db
        .query_row(
            "SELECT append_revision,append_update FROM mailboxes",
            [],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap();
    assert_eq!(saved, (i64::MAX as u64, request));
    db.execute_batch("PRAGMA ignore_check_constraints=ON; UPDATE mailboxes SET append_revision=0,append_update=NULL").unwrap();
    assert_eq!(
        store.rotate([1; 32], &update(1, [6; 32]), &admin),
        Err(RelayError::Conflict)
    );
    assert_eq!(
        db.query_row("SELECT append_revision FROM mailboxes", [], |r| r
            .get::<_, u64>(0))
            .unwrap(),
        0
    );
}

fn limits() -> Limits {
    Limits {
        total_bytes: 100,
        mailbox_bytes: 50,
        mailbox_count: 1,
    }
}

fn init(root: &Scratch, limits: Limits) -> RelayStore {
    RelayStore::init(
        root.path(),
        [7; 32],
        "http://127.0.0.1:8000",
        &[8; 32],
        loki_relay_server::capability::provisioning_verifier([7; 32], &[8; 32]),
        limits,
    )
    .unwrap()
}

fn creation(quota: u64) -> Vec<u8> {
    encode_creation(&Creation {
        read_verifier: verifier(Role::Read, [1; 32], &[2; 32]),
        append_verifier: verifier(Role::Append, [1; 32], &[3; 32]),
        admin_verifier: verifier(Role::Admin, [1; 32], &[4; 32]),
        quota,
    })
    .unwrap()
}

#[test]
fn create_mailbox_durable_initial_state() {
    let root = Scratch::new();
    let mut store = init(&root, limits());
    let request = creation(50);
    assert_eq!(
        store
            .create([1; 32], &request, &Capability::new([8; 32]))
            .unwrap(),
        CreationResult {
            created: true,
            run: [7; 32],
            quota: 50,
            append_revision: 1
        }
    );
    drop(store);
    let _reopened = RelayStore::open(root.path(), limits()).unwrap();
    let db = rusqlite::Connection::open(root.path().join("relay.sqlite3")).unwrap();
    let saved: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, u64, u64, u64, u64, Option<Vec<u8>>) = db.query_row(
        "SELECT creation_request,read_verifier,append_verifier,admin_verifier,byte_quota,used_bytes,next_sequence,append_revision,append_update FROM mailboxes WHERE id=?1",
        [[1u8; 32].as_slice()], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?,r.get(7)?,r.get(8)?))).unwrap();
    assert_eq!(
        saved,
        (
            request,
            verifier(Role::Read, [1; 32], &[2; 32]).to_vec(),
            verifier(Role::Append, [1; 32], &[3; 32]).to_vec(),
            verifier(Role::Admin, [1; 32], &[4; 32]).to_vec(),
            50,
            0,
            1,
            1,
            None
        )
    );
}

#[test]
fn create_mailbox_retry_preserves_current_revision() {
    let root = Scratch::new();
    let mut store = init(&root, limits());
    let request = creation(50);
    let capability = Capability::new([8; 32]);
    store.create([1; 32], &request, &capability).unwrap();
    let db = rusqlite::Connection::open(root.path().join("relay.sqlite3")).unwrap();
    db.execute("UPDATE mailboxes SET append_revision=2,append_verifier=?1,append_update=?2,used_bytes=50,next_sequence=9 WHERE id=?3",
        rusqlite::params![[9u8; 32].as_slice(), [10u8; 3].as_slice(), [1u8; 32].as_slice()]).unwrap();
    drop(store);
    let mut store = RelayStore::open(root.path(), limits()).unwrap();
    for _ in 0..2 {
        assert_eq!(
            store.create([1; 32], &request, &capability).unwrap(),
            CreationResult {
                created: false,
                run: [7; 32],
                quota: 50,
                append_revision: 2
            }
        );
    }
    let state: (Vec<u8>, Vec<u8>, u64, u64, u64) = db.query_row(
        "SELECT append_verifier,append_update,used_bytes,next_sequence,(SELECT count(*) FROM mailboxes) FROM mailboxes",
        [], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).unwrap();
    assert_eq!(state, (vec![9; 32], vec![10; 3], 50, 9, 1));
}

#[test]
fn create_mailbox_changed_creation_conflicts() {
    let root = Scratch::new();
    let mut store = init(&root, limits());
    let capability = Capability::new([8; 32]);
    let request = creation(50);
    store.create([1; 32], &request, &capability).unwrap();
    let original = loki_relay_protocol::http::decode_creation(&request).unwrap();
    for changed in [
        Creation {
            read_verifier: [9; 32],
            ..original.clone()
        },
        Creation {
            append_verifier: [9; 32],
            ..original.clone()
        },
        Creation {
            admin_verifier: [9; 32],
            ..original.clone()
        },
        Creation {
            quota: 49,
            ..original.clone()
        },
        Creation {
            quota: 51,
            ..original.clone()
        },
    ] {
        assert_eq!(
            store.create([1; 32], &encode_creation(&changed).unwrap(), &capability),
            Err(RelayError::Conflict)
        );
    }
    assert_eq!(
        store
            .create([1; 32], &request, &capability)
            .unwrap()
            .append_revision,
        1
    );
    let db = rusqlite::Connection::open(root.path().join("relay.sqlite3")).unwrap();
    assert_eq!(
        db.query_row("SELECT creation_request FROM mailboxes", [], |r| r
            .get::<_, Vec<u8>>(0))
            .unwrap(),
        request
    );
}

#[test]
fn create_mailbox_rejects_invalid_provision_capability() {
    let root = Scratch::new();
    let mut store = init(&root, limits());
    let request = creation(50);
    let wrong = Capability::new([9; 32]);
    assert_eq!(
        store.create([1; 32], &request, &wrong),
        Err(RelayError::Capability)
    );
    assert_eq!(
        store.create([1; 32], &[], &wrong),
        Err(RelayError::Capability)
    );
    let right = Capability::new([8; 32]);
    assert!(store.create([1; 32], &request, &right).unwrap().created);
    assert_eq!(
        store.create([1; 32], &request, &wrong),
        Err(RelayError::Capability)
    );
    assert_eq!(
        store.create([1; 32], &creation(49), &wrong),
        Err(RelayError::Capability)
    );
    assert!(!store.create([1; 32], &request, &right).unwrap().created);
}

#[test]
fn create_mailbox_enforces_mailbox_quota() {
    let root = Scratch::new();
    let mut store = init(&root, limits());
    let capability = Capability::new([8; 32]);
    assert_eq!(
        store.create([1; 32], &creation(51), &capability),
        Err(RelayError::QuotaExhausted)
    );
    assert!(
        store
            .create([1; 32], &creation(50), &capability)
            .unwrap()
            .created
    );
}

#[test]
fn create_mailbox_enforces_total_quota() {
    let root = Scratch::new();
    let mut store = init(
        &root,
        Limits {
            mailbox_bytes: 200,
            ..limits()
        },
    );
    let capability = Capability::new([8; 32]);
    assert_eq!(
        store.create([1; 32], &creation(101), &capability),
        Err(RelayError::QuotaExhausted)
    );
    assert!(
        store
            .create([1; 32], &creation(100), &capability)
            .unwrap()
            .created
    );
}

#[test]
fn create_mailbox_enforces_mailbox_count() {
    let root = Scratch::new();
    let mut store = init(&root, limits());
    let capability = Capability::new([8; 32]);
    let request = creation(0);
    assert!(
        store
            .create([1; 32], &request, &capability)
            .unwrap()
            .created
    );
    assert_eq!(
        store.create([2; 32], &request, &capability),
        Err(RelayError::QuotaExhausted)
    );
    assert!(
        !store
            .create([1; 32], &request, &capability)
            .unwrap()
            .created
    );
    let db = rusqlite::Connection::open(root.path().join("relay.sqlite3")).unwrap();
    assert_eq!(
        db.query_row("SELECT count(*) FROM mailboxes", [], |r| r.get::<_, u64>(0))
            .unwrap(),
        1
    );
    let zero = Scratch::new();
    let mut store = init(
        &zero,
        Limits {
            mailbox_count: 0,
            ..limits()
        },
    );
    assert_eq!(
        store.create([1; 32], &request, &capability),
        Err(RelayError::QuotaExhausted)
    );
}

#[test]
fn create_mailbox_rejects_malformed_creation() {
    let root = Scratch::new();
    let mut store = init(&root, limits());
    let capability = Capability::new([8; 32]);
    let request = creation(50);
    let mut trailing = request.clone();
    trailing.push(0xff);
    let mut version = request.clone();
    version[1] = 2;
    let mut overflow = creation(i64::MAX as u64);
    let first = overflow.len() - 8;
    overflow[first] = 0x80;
    for invalid in [
        trailing,
        version,
        overflow,
        vec![],
        request[..request.len() - 1].to_vec(),
    ] {
        assert_eq!(
            store.create([1; 32], &invalid, &capability),
            Err(RelayError::MalformedRequest)
        );
    }
    assert!(
        store
            .create([1; 32], &request, &capability)
            .unwrap()
            .created
    );
}

#[test]
fn create_mailbox_quota_signed_integer_boundaries() {
    let capability = Capability::new([8; 32]);
    for quota in [0, i64::MAX as u64] {
        let root = Scratch::new();
        let limits = Limits {
            total_bytes: quota,
            mailbox_bytes: quota,
            mailbox_count: 1,
        };
        let mut store = init(&root, limits);
        assert_eq!(
            store
                .create([1; 32], &creation(quota), &capability)
                .unwrap()
                .quota,
            quota
        );
    }
}

#[test]
fn create_mailbox_role_verifier_separation() {
    let capability = Capability::new([8; 32]);
    for (role, expected) in [
        (
            Role::Read,
            "27cacc76e43e303a79be1b72ce479db4a8863111fecdd278c06fad7bab067a1c",
        ),
        (
            Role::Append,
            "6b610711bd2e82d80380bd23050360f73c56b985eb4dec48b1d34f9d2e12b643",
        ),
        (
            Role::Admin,
            "96880a42aaf063089ccd3019a67065aeb1e62555c672d3804178029a0950b7bb",
        ),
    ] {
        let expected: [u8; 32] = hex::decode(expected).unwrap().try_into().unwrap();
        assert_eq!(verifier(role, [7; 32], &[8; 32]), expected);
        assert!(capability.verify(role, [7; 32], &expected));
        assert!(!capability.verify(role, [9; 32], &expected));
        for offset in 0..32 {
            let mut wrong = expected;
            wrong[offset] ^= 1;
            assert!(!capability.verify(role, [7; 32], &wrong));
        }
        assert!(!Capability::new([9; 32]).verify(role, [7; 32], &expected));
        for other in [Role::Read, Role::Append, Role::Admin] {
            if other != role {
                assert!(!capability.verify(other, [7; 32], &expected));
            }
        }
    }
}

#[test]
fn create_mailbox_provision_verifier_separation() {
    use loki_relay_server::capability::provisioning_verifier;
    let expected: [u8; 32] =
        hex::decode("397341969db5f7de032d193499c54c669094fbccdb1017ac84f80acff3921933")
            .unwrap()
            .try_into()
            .unwrap();
    let capability = Capability::new([8; 32]);
    assert_eq!(provisioning_verifier([7; 32], &[8; 32]), expected);
    assert!(capability.verify_provision([7; 32], &expected));
    assert!(!capability.verify_provision([9; 32], &expected));
    assert!(!Capability::new([9; 32]).verify_provision([7; 32], &expected));
    for role in [Role::Read, Role::Append, Role::Admin] {
        assert!(!capability.verify(role, [7; 32], &expected));
        assert!(!capability.verify_provision([7; 32], &verifier(role, [7; 32], &[8; 32])));
    }
    for offset in 0..32 {
        let mut wrong = expected;
        wrong[offset] ^= 1;
        assert!(!capability.verify_provision([7; 32], &wrong));
    }
}
