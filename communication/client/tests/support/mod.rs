use loki_relay_client::CommIdentity;
use loki_relay_protocol::types::Roster;
use rusqlite::Connection;
use std::{
    fs,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};

pub fn roster() -> Roster {
    Roster {
        vault: [70; 32],
        members: (1u16..=3)
            .map(|id| {
                let mut seed = [0; 66];
                seed[..2].copy_from_slice(&id.to_be_bytes());
                seed[2..34].fill(id as u8);
                seed[34..].fill(id as u8 + 10);
                CommIdentity::from_serialized(&seed).unwrap().public()
            })
            .collect(),
    }
}

pub fn root() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let parent = PathBuf::from("/private/tmp/relay-6.1-evidence").join(format!(
        "fixture-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir_all(&parent).unwrap();
    parent.join("client")
}

pub fn sql(root: &std::path::Path) -> Connection {
    let sql = Connection::open(root.join("client.sqlite3")).unwrap();
    sql.execute_batch("PRAGMA foreign_keys=ON; PRAGMA busy_timeout=5000;")
        .unwrap();
    sql
}

pub fn prior_root() -> PathBuf {
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;
    let root = root();
    fs::create_dir(&root).unwrap();
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
    let database = root.join("client.sqlite3");
    fs::File::create(&database).unwrap();
    fs::set_permissions(&database, fs::Permissions::from_mode(0o600)).unwrap();
    let sql = sql(&root);
    let prior = include_str!("../../src/schema.sql")
        .split("CREATE TABLE ciphertext_objects")
        .next()
        .unwrap();
    assert_eq!(
        hex::encode(Sha256::digest(prior.as_bytes())),
        "5ab271137dd0728dbe9b5fad8c3feb6791423a4d0f45d243584a4390bd7260bc"
    );
    sql.execute_batch(prior).unwrap();
    let roster = roster();
    let digest = loki_relay_protocol::types::roster_digest(&roster).unwrap();
    sql.execute(
        "INSERT INTO metadata VALUES(1,1,?1,?2,1)",
        rusqlite::params![roster.vault, digest],
    )
    .unwrap();
    sql.execute("INSERT INTO config_versions VALUES(1,7,?1)", [[88u8; 32]])
        .unwrap();
    root
}

pub fn identity(id: u16) -> CommIdentity {
    let mut seed = [0; 66];
    seed[..2].copy_from_slice(&id.to_be_bytes());
    seed[2..34].fill(id as u8);
    seed[34..].fill(id as u8 + 10);
    CommIdentity::from_serialized(&seed).unwrap()
}

pub struct Fixture {
    pub root: PathBuf,
    pub store: loki_relay_client::ClientStore,
    pub prepared: loki_relay_client::PreparedOutbox,
}

pub fn fixture(payload_len: usize) -> Fixture {
    use loki_relay_client::{prepare_outbox, ClientStore};
    use loki_relay_protocol::types::{roster_digest, LogicalKey, MessageBody, Payload};
    use rusqlite::params;
    let roster = roster();
    let body = MessageBody {
        key: LogicalKey {
            vault: roster.vault,
            roster: roster_digest(&roster).unwrap(),
            sender: 1,
            message: [91; 32],
        },
        audience: vec![1, 2, 3],
        session: Some([92; 32]),
        prerequisites: vec![],
        payload: Payload::Test(vec![19; payload_len]),
    };
    let prepared = prepare_outbox(&identity(1), &roster, &body).unwrap();
    let root = root();
    let store = ClientStore::open(&root, &roster, 1).unwrap();
    let mut sql = sql(&root);
    let transaction = sql.transaction().unwrap();
    for recipient in prepared.recipients() {
        for object in recipient.objects() {
            transaction
                .execute(
                    "INSERT INTO ciphertext_objects VALUES(?1,?2,?3)",
                    params![object.hash, object.wire, object.wire.len()],
                )
                .unwrap();
        }
    }
    let key = prepared.key();
    transaction
        .execute(
            "INSERT INTO logical_records VALUES(?1,?2,?3,?4,?5,1,?6,'committed',?7)",
            params![
                key.vault,
                key.roster,
                key.sender,
                key.message,
                prepared.digest(),
                body.session,
                prepared.recipients()[0].root_hash()
            ],
        )
        .unwrap();
    for recipient in prepared.recipients() {
        transaction
            .execute(
                "INSERT INTO outgoing_recipients VALUES(?1,?2,?3,?4,?5,?6,?7,'needs_route')",
                params![
                    key.vault,
                    key.roster,
                    key.sender,
                    key.message,
                    recipient.recipient(),
                    recipient.transfer(),
                    recipient.root_hash()
                ],
            )
            .unwrap();
        for (ordinal, object) in recipient.objects().iter().enumerate() {
            transaction
                .execute(
                    "INSERT INTO required_objects VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                    params![
                        key.vault,
                        key.roster,
                        key.sender,
                        key.message,
                        recipient.recipient(),
                        ordinal,
                        object.hash,
                        object.wire.len()
                    ],
                )
                .unwrap();
            for relay in 1u8..=3 {
                transaction
                    .execute(
                        "INSERT INTO upload_work VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,'pending',0,0)",
                        params![
                            key.vault,
                            key.roster,
                            key.sender,
                            key.message,
                            recipient.recipient(),
                            object.hash,
                            [relay; 32],
                            [relay + 10; 32],
                            [relay + 20; 32]
                        ],
                    )
                    .unwrap();
            }
        }
    }
    transaction.execute_batch("INSERT INTO verified_receipts SELECT vault,roster,sender,message_id,recipient,hash,relay_key,run,mailbox,(SELECT length FROM ciphertext_objects WHERE hash=upload_work.hash),1,0,x'010203' FROM upload_work;").unwrap();
    transaction.commit().unwrap();
    Fixture {
        root,
        store,
        prepared,
    }
}

pub fn reject_insert(table: &str, columns: &str) {
    let fixture = fixture(10);
    let sql = sql(&fixture.root);
    let query = if (table == "verified_receipts"
        || (table == "required_objects" && !columns.contains("randomblob(32)")))
        && columns != "*"
    {
        let names = match table {
            "required_objects" => "vault,roster,sender,message_id,recipient,ordinal,hash,length",
            _ => "vault,roster,sender,message_id,recipient,hash,relay_key,run,mailbox,length,sequence,retention,receipt",
        };
        format!("UPDATE {table} SET ({names})=({columns}) WHERE rowid=(SELECT rowid FROM {table} LIMIT 1)")
    } else {
        format!("INSERT INTO {table} SELECT {columns} FROM {table} LIMIT 1")
    };
    assert!(
        sql.execute(&query, []).is_err(),
        "constraint accepted {table}: {columns}"
    );
}
