mod support;

use loki_relay_client::{reopen_committed, ClientStore};
use loki_relay_protocol::types::LogicalKey;
use rusqlite::params;

fn root_for(fixture: &support::Fixture, recipient: u16) -> [u8; 32] {
    *fixture
        .prepared
        .recipients()
        .iter()
        .find(|copy| copy.recipient() == recipient)
        .unwrap()
        .root_hash()
}

fn reopen_owner(fixture: &support::Fixture) -> loki_relay_client::AuthenticatedTransfer {
    let key = fixture.prepared.key();
    reopen_committed(
        &fixture.store,
        &support::roster(),
        &support::identity(1),
        key,
        fixture.prepared.digest(),
        &root_for(fixture, 1),
    )
    .unwrap()
}

#[test]
fn authored_copy_is_reauthenticated_and_digest_bound() {
    let fixture = support::fixture(32);
    let opened = reopen_owner(&fixture);
    assert_eq!(opened.message().body().key, *fixture.prepared.key());
    assert_eq!(opened.message().digest(), fixture.prepared.digest());
    let debug = format!("{:?}", opened);
    assert!(!debug.contains("19, 19"));
    assert!(reopen_committed(
        &fixture.store,
        &support::roster(),
        &support::identity(1),
        fixture.prepared.key(),
        &[0; 32],
        &root_for(&fixture, 1),
    )
    .is_err());
    assert!(reopen_committed(
        &fixture.store,
        &support::roster(),
        &support::identity(1),
        fixture.prepared.key(),
        fixture.prepared.digest(),
        &root_for(&fixture, 2),
    )
    .is_err());
    assert!(reopen_committed(
        &fixture.store,
        &support::roster(),
        &support::identity(2),
        fixture.prepared.key(),
        fixture.prepared.digest(),
        &root_for(&fixture, 1),
    )
    .is_err());
}

#[test]
fn reopen_after_close_does_not_write_or_move_cursors() {
    let fixture = support::fixture(32);
    let logical = fixture.store.recover_logical(0, 100).unwrap();
    let cursors = fixture.store.recover_route_cursors(0, 100).unwrap();
    let originals = fixture.store.recover_incoming_originals(0, 100).unwrap();
    let sql = support::sql(&fixture.root);
    let before: i64 = sql
        .query_row("SELECT count(*) FROM ciphertext_objects", [], |row| row.get(0))
        .unwrap();
    let opened = reopen_owner(&fixture);
    assert_eq!(
        opened.message().body().payload,
        loki_relay_protocol::types::Payload::Test(vec![19; 32])
    );
    assert_eq!(fixture.store.recover_logical(0, 100).unwrap(), logical);
    assert_eq!(fixture.store.recover_route_cursors(0, 100).unwrap(), cursors);
    assert_eq!(
        fixture.store.recover_incoming_originals(0, 100).unwrap(),
        originals
    );
    let after: i64 = sql
        .query_row("SELECT count(*) FROM ciphertext_objects", [], |row| row.get(0))
        .unwrap();
    assert_eq!(before, after);
    let root = fixture.root.clone();
    let key = fixture.prepared.key().clone();
    let digest = *fixture.prepared.digest();
    let source = root_for(&fixture, 1);
    drop(fixture);
    let store = ClientStore::open(&root, &support::roster(), 1).unwrap();
    let reopened = reopen_committed(
        &store,
        &support::roster(),
        &support::identity(1),
        &key,
        &digest,
        &source,
    )
    .unwrap();
    assert_eq!(reopened.message().digest(), &digest);
}

#[test]
fn chunked_copy_rejects_missing_gap_and_same_length_corruption() {
    let fixture = support::fixture(80_000);
    let copy = fixture
        .prepared
        .recipients()
        .iter()
        .find(|recipient| recipient.recipient() == 1)
        .unwrap();
    assert!(
        copy.objects().len() > 1,
        "payload still fit in one outer object"
    );
    let opened = reopen_owner(&fixture);
    assert_eq!(opened.source().required_hashes().len(), copy.objects().len());
    let key = fixture.prepared.key().clone();
    let digest = *fixture.prepared.digest();
    let source = *copy.root_hash();
    let chunk = copy
        .objects()
        .iter()
        .find(|object| object.hash != source)
        .unwrap()
        .clone();
    let mut wire = chunk.wire.clone();
    wire[200] ^= 0x5a;
    assert_eq!(wire.len(), chunk.wire.len());
    let sql = support::sql(&fixture.root);
    sql.execute_batch("DROP TRIGGER ciphertext_objects_no_update;").unwrap();
    sql.execute(
        "UPDATE ciphertext_objects SET wire=?1 WHERE hash=?2",
        params![&wire, chunk.hash],
    )
    .unwrap();
    assert!(reopen_committed(
        &fixture.store,
        &support::roster(),
        &support::identity(1),
        &key,
        &digest,
        &source,
    )
    .is_err());

    let gap = support::fixture(80_000);
    let gap_key = gap.prepared.key().clone();
    let gap_digest = *gap.prepared.digest();
    let gap_source = root_for(&gap, 1);
    let sql = support::sql(&gap.root);
    sql.execute_batch("DROP TRIGGER required_objects_no_update;").unwrap();
    sql.execute(
        "UPDATE required_objects SET ordinal = ordinal + 1 WHERE recipient=1 AND ordinal=(SELECT MAX(ordinal) FROM required_objects WHERE recipient=1)",
        [],
    )
    .unwrap();
    assert!(reopen_committed(
        &gap.store,
        &support::roster(),
        &support::identity(1),
        &gap_key,
        &gap_digest,
        &gap_source,
    )
    .is_err());

    let missing = support::fixture(80_000);
    let missing_key = missing.prepared.key().clone();
    let missing_digest = *missing.prepared.digest();
    let missing_source = root_for(&missing, 1);
    let victim = missing
        .prepared
        .recipients()
        .iter()
        .find(|recipient| recipient.recipient() == 1)
        .unwrap()
        .objects()
        .iter()
        .find(|object| object.hash != missing_source)
        .unwrap()
        .hash;
    let sql = support::sql(&missing.root);
    sql.execute_batch(
        "DROP TRIGGER required_objects_no_delete; DROP TRIGGER IF EXISTS verified_receipts_no_delete;",
    )
    .unwrap();
    sql.execute("DELETE FROM verified_receipts WHERE hash=?1", [victim])
        .unwrap();
    sql.execute(
        "DELETE FROM upload_work WHERE hash=?1 AND recipient=1",
        [victim],
    )
    .unwrap();
    assert_eq!(
        sql.execute(
            "DELETE FROM required_objects WHERE hash=?1 AND recipient=1",
            [victim],
        )
        .unwrap(),
        1
    );
    assert!(reopen_committed(
        &missing.store,
        &support::roster(),
        &support::identity(1),
        &missing_key,
        &missing_digest,
        &missing_source,
    )
    .is_err());
}

#[test]
fn incoming_copy_reauthenticates_for_its_recipient() {
    let authored = support::fixture(48);
    let copy = authored
        .prepared
        .recipients()
        .iter()
        .find(|recipient| recipient.recipient() == 2)
        .unwrap();
    let root = support::root();
    let store = ClientStore::open(&root, &support::roster(), 2).unwrap();
    let sql = support::sql(&root);
    for object in copy.objects() {
        sql.execute(
            "INSERT INTO ciphertext_objects VALUES(?1,?2,?3)",
            params![object.hash, object.wire, object.wire.len() as i64],
        )
        .unwrap();
    }
    let key: &LogicalKey = authored.prepared.key();
    sql.execute(
        "INSERT INTO incoming_originals VALUES(?1,?2,?3,?4,?5,1,?6,?7)",
        params![
            key.vault,
            key.roster,
            key.sender,
            key.message,
            authored.prepared.digest(),
            [92u8; 32],
            copy.root_hash()
        ],
    )
    .unwrap();
    for (ordinal, object) in copy.objects().iter().enumerate() {
        sql.execute(
            "INSERT INTO incoming_original_objects VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                key.vault,
                key.roster,
                key.sender,
                key.message,
                ordinal as i64,
                object.hash,
                object.wire.len() as i64
            ],
        )
        .unwrap();
    }
    let opened = reopen_committed(
        &store,
        &support::roster(),
        &support::identity(2),
        key,
        authored.prepared.digest(),
        copy.root_hash(),
    )
    .unwrap();
    assert_eq!(opened.source().recipient(), 2);
    assert_eq!(opened.message().body().key.sender, 1);
    assert_eq!(
        opened.message().body().payload,
        loki_relay_protocol::types::Payload::Test(vec![19; 48])
    );
    assert!(reopen_committed(
        &store,
        &support::roster(),
        &support::identity(2),
        key,
        authored.prepared.digest(),
        &[9; 32],
    )
    .is_err());
}
