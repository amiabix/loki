use loki_relay_client::{
    authenticate, prepare_outbox, sign_message, ClientStore, CommIdentity, TransferAssembler,
};
use loki_relay_protocol::types::{roster_digest, LogicalKey, MessageBody, Payload, Roster};

fn identity(id: u16) -> CommIdentity {
    let mut raw = [0; 66];
    raw[..2].copy_from_slice(&id.to_be_bytes());
    raw[2..34].fill(id as u8);
    raw[34..].fill(id as u8 + 10);
    CommIdentity::from_serialized(&raw).unwrap()
}
fn roster(n: u16) -> Roster {
    Roster {
        vault: [70; 32],
        members: (1..=n).map(|id| identity(id).public()).collect(),
    }
}
fn body(roster: &Roster) -> MessageBody {
    MessageBody {
        key: LogicalKey {
            vault: roster.vault,
            roster: roster_digest(roster).unwrap(),
            sender: 1,
            message: [80; 32],
        },
        audience: roster.members.iter().map(|m| m.id).collect(),
        session: None,
        prerequisites: vec![],
        payload: Payload::Test(b"four member payload".to_vec()),
    }
}

#[test]
fn fourth_identity_is_supported_but_fifth_is_not() {
    assert_eq!(identity(4).public().id, 4);
    let mut raw = [5; 66];
    raw[..2].copy_from_slice(&5u16.to_be_bytes());
    assert!(CommIdentity::from_serialized(&raw).is_err());
}

#[test]
fn fourth_recipient_has_independent_encrypted_copy() {
    let roster = roster(4);
    let prepared = prepare_outbox(&identity(1), &roster, &body(&roster)).unwrap();
    assert_eq!(
        prepared
            .recipients()
            .iter()
            .map(|r| r.recipient())
            .collect::<Vec<_>>(),
        vec![1, 2, 3, 4]
    );
    for copy in prepared.recipients() {
        let owner = identity(copy.recipient());
        let objects = copy.objects().iter().map(|o| (o.hash, o.clone())).collect();
        let root = copy
            .objects()
            .iter()
            .find(|o| &o.hash == copy.root_hash())
            .unwrap();
        let opened = TransferAssembler::open(&roster, &owner, root, &objects).unwrap();
        assert_eq!(opened.message().body(), &body(&roster));
    }
}

#[test]
fn fourth_store_persists_complete_recipient_set_and_reopens() {
    let roster = roster(4);
    let prepared = prepare_outbox(&identity(4), &roster, &{
        let mut body = body(&roster);
        body.key.sender = 4;
        body
    })
    .unwrap();
    let parent = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "loki-four-store-{}-{}",
        std::process::id(),
        hex::encode(identity(4).public().signing)
    ));
    std::fs::create_dir_all(&parent).unwrap();
    let root = parent.join("client");
    let mut store = ClientStore::open(&root, &roster, 4).unwrap();
    store
        .commit_outbox(&roster, &identity(4), &[90; 32], &prepared)
        .unwrap();
    assert_eq!(
        store
            .recover_recipients(prepared.key())
            .unwrap()
            .iter()
            .map(|r| r.recipient)
            .collect::<Vec<_>>(),
        vec![1, 2, 3, 4]
    );
    drop(store);
    let store = ClientStore::open(&root, &roster, 4).unwrap();
    assert_eq!(store.recover_recipients(prepared.key()).unwrap().len(), 4);
    drop(store);
    std::fs::remove_dir_all(parent).unwrap();
}

#[test]
fn authenticated_four_member_message_refuses_missing_member_and_cross_roster() {
    let roster = roster(4);
    let message = body(&roster);
    let signed = sign_message(&identity(1), &roster, &message).unwrap();
    assert!(authenticate(&roster, &signed).is_ok());
    let mut other = roster.clone();
    other.vault = [71; 32];
    assert!(authenticate(&other, &signed).is_err());
    let mut missing = message.clone();
    missing.audience.pop();
    assert!(sign_message(&identity(1), &roster, &missing).is_err());
    let mut extra = message;
    extra.audience.push(5);
    assert!(sign_message(&identity(1), &roster, &extra).is_err());
}

fn cache(store: &mut ClientStore, object: &loki_relay_protocol::types::Object, sequence: u64) {
    use ed25519_dalek::{Signer, SigningKey};
    use loki_relay_protocol::{
        canonical::{self, Value},
        receipt,
        types::{Entry, Page, ReceiptBody, RelayPin, RelayRoute},
    };
    let signer = SigningKey::from_bytes(&[99; 32]);
    let route = RelayRoute {
        pin: RelayPin {
            key: signer.verifying_key().to_bytes(),
            run: [98; 32],
        },
        endpoint: "http://127.0.0.1:8000".into(),
        mailbox: [97; 32],
        append_revision: 1,
    };
    let body = receipt::encode_body(&ReceiptBody {
        pin: route.pin.clone(),
        mailbox: route.mailbox,
        hash: object.hash,
        wire_length: object.wire.len() as u64,
        sequence,
        retention: 1,
    })
    .unwrap();
    let mut signed = b"Loki_Relay_Stored_v1\0".to_vec();
    signed.extend_from_slice(&(body.len() as u32).to_be_bytes());
    signed.extend_from_slice(&body);
    let signature = signer.sign(&signed);
    let wire = canonical::encode(&Value::Array(vec![
        Value::Bytes(body),
        Value::Bytes(signature.to_bytes().to_vec()),
    ]))
    .unwrap();
    store
        .capture_page(
            &route,
            &Page {
                mailbox: route.mailbox,
                after: sequence - 1,
                next: sequence,
                high_water: sequence,
                entries: vec![Entry {
                    sequence,
                    hash: object.hash,
                    wire_length: object.wire.len() as u64,
                    receipt: wire,
                }],
            },
            &[loki_relay_client::DownloadOutcome::Cached(object.clone())],
        )
        .unwrap();
}

#[test]
fn fourth_received_requires_authenticated_acknowledgement_after_local_commit() {
    use loki_relay_client::{authenticate_staged, prepare_received, received_status};
    let roster = roster(4);
    let message = body(&roster);
    let prepared = prepare_outbox(&identity(1), &roster, &message).unwrap();
    let mut random = [0; 32];
    getrandom::fill(&mut random).unwrap();
    let parent = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("loki-four-received-{}", hex::encode(random)));
    std::fs::create_dir(&parent).unwrap();
    let mut author = ClientStore::open(&parent.join("member1"), &roster, 1).unwrap();
    author
        .commit_outbox(&roster, &identity(1), &[90; 32], &prepared)
        .unwrap();
    for member in 2..=4 {
        let mut recipient =
            ClientStore::open(&parent.join(format!("member{member}")), &roster, member).unwrap();
        let copy = prepared
            .recipients()
            .iter()
            .find(|c| c.recipient() == member)
            .unwrap();
        assert_eq!(copy.objects().len(), 1);
        cache(&mut recipient, &copy.objects()[0], 1);
        let candidate = authenticate_staged(&mut recipient, &roster, &identity(member))
            .unwrap()
            .pop()
            .unwrap();
        let acknowledgement = prepare_received(
            &recipient,
            &identity(member),
            &roster,
            candidate.message(),
            candidate.source(),
        )
        .unwrap()
        .unwrap();
        assert_eq!(acknowledgement.recipients().len(), 4);
        recipient
            .commit_incoming(
                &roster,
                &identity(member),
                candidate.source(),
                candidate.message(),
                Some(&acknowledgement),
            )
            .unwrap();
        let status = received_status(
            &author,
            &roster,
            &identity(1),
            &message.key,
            prepared.digest(),
        )
        .unwrap();
        assert!(!status.whole_vault());
        assert!(!status.member_received(member));
        let copy = acknowledgement
            .recipients()
            .iter()
            .find(|c| c.recipient() == 1)
            .unwrap();
        cache(&mut author, &copy.objects()[0], (member - 1) as u64);
        let candidate = authenticate_staged(&mut author, &roster, &identity(1))
            .unwrap()
            .pop()
            .unwrap();
        author
            .commit_incoming(
                &roster,
                &identity(1),
                candidate.source(),
                candidate.message(),
                None,
            )
            .unwrap();
        let status = received_status(
            &author,
            &roster,
            &identity(1),
            &message.key,
            prepared.digest(),
        )
        .unwrap();
        assert!(status.member_received(member));
        assert_eq!(status.whole_vault(), member == 4);
    }
    drop(author);
    std::fs::remove_dir_all(parent).unwrap();
}

#[tokio::test]
async fn four_copies_reach_two_real_relays_with_fourth_member_offline() {
    use loki_relay_client::{
        open_descriptor, seal_descriptor, upload_pending, ClientConfig, ConfigReference,
        Descriptor, DescriptorRelay, OwnerInbox, RelayHttp, Secret32, ThirdPass,
    };
    use loki_relay_protocol::{
        http::encode_creation,
        types::{Creation, RelayPin, RelayRoute},
    };
    use loki_relay_server::{
        capability::{provisioning_verifier, verifier},
        Capability, DbHandle, Limits, RelayStore, Role,
    };
    let roster = roster(4);
    let alice = identity(1);
    let mut random = [0; 32];
    getrandom::fill(&mut random).unwrap();
    let parent = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("loki-four-live-{}", hex::encode(random)));
    std::fs::create_dir(&parent).unwrap();
    let limits = Limits {
        total_bytes: 1000000,
        mailbox_bytes: 100000,
        mailbox_count: 4,
    };
    let mut routes = Vec::new();
    let mut owners = Vec::new();
    let mut servers = Vec::new();
    for index in 0u8..3 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let run = [index + 10; 32];
        let provision = [index + 20; 32];
        let root = parent.join(format!("relay{index}"));
        let mut relay = RelayStore::init(
            &root,
            run,
            &endpoint,
            &provision,
            provisioning_verifier(run, &provision),
            limits,
        )
        .unwrap();
        let pin = RelayPin {
            key: relay.public_key(),
            run,
        };
        for member in 1u8..=4 {
            let mut mailbox = [0; 32];
            mailbox[0] = member;
            mailbox[1] = index;
            relay
                .create(
                    mailbox,
                    &encode_creation(&Creation {
                        read_verifier: verifier(Role::Read, mailbox, &[member + 40; 32]),
                        append_verifier: verifier(
                            Role::Append,
                            mailbox,
                            &[member + index + 50; 32],
                        ),
                        admin_verifier: verifier(Role::Admin, mailbox, &[member + 60; 32]),
                        quota: 100000,
                    })
                    .unwrap(),
                    &Capability::new(provision),
                )
                .unwrap();
        }
        drop(relay);
        routes.push((pin, endpoint, index));
        let (db, owner) = DbHandle::open(root, limits).await.unwrap();
        owners.push(owner);
        servers.push(tokio::spawn(async move {
            axum::serve(listener, loki_relay_server::http::router(db))
                .await
                .unwrap();
        }));
    }
    routes.sort_by_key(|(pin, _, _)| pin.key);
    let descriptor = |member: u16| {
        Descriptor::new(
            roster.vault,
            roster_digest(&roster).unwrap(),
            member,
            1,
            routes
                .iter()
                .map(|(pin, endpoint, index)| {
                    let mut mailbox = [0; 32];
                    mailbox[0] = member as u8;
                    mailbox[1] = *index;
                    DescriptorRelay {
                        route: RelayRoute {
                            pin: pin.clone(),
                            endpoint: endpoint.clone(),
                            mailbox,
                            append_revision: 1,
                        },
                        append: Secret32::from_bytes([member as u8 + index + 50; 32]),
                    }
                })
                .collect(),
        )
    };
    let sealed = seal_descriptor(&alice, &roster, &descriptor(1), &alice.public()).unwrap();
    let self_route = open_descriptor(&alice, &roster, &sealed.wire).unwrap();
    let own = self_route
        .body()
        .relays
        .iter()
        .map(|r| OwnerInbox {
            route: r.route.clone(),
            read: Secret32::from_bytes([41; 32]),
            append: Secret32::from_bytes(*r.append.as_bytes()),
            admin: Secret32::from_bytes([61; 32]),
        })
        .collect();
    let peers = (2..=4)
        .map(|member| {
            let wire = seal_descriptor(
                &identity(member),
                &roster,
                &descriptor(member),
                &alice.public(),
            )
            .unwrap();
            open_descriptor(&alice, &roster, &wire.wire).unwrap()
        })
        .collect();
    let mut config = ClientConfig { own, peers };
    let mut store = ClientStore::open(&parent.join("author"), &roster, 1).unwrap();
    store
        .record_config_revision(&ConfigReference::from_ciphertext(1, &sealed.wire).unwrap())
        .unwrap();
    let prepared = prepare_outbox(&alice, &roster, &body(&roster)).unwrap();
    let logical = store
        .commit_outbox(&roster, &alice, &[90; 32], &prepared)
        .unwrap();
    let offline = servers.remove(0);
    offline.abort();
    let _ = offline.await;
    let http = RelayHttp::new().unwrap();
    let fourth_peer = config.peers.pop().unwrap();
    assert_eq!(fourth_peer.body().owner, 4);
    let incomplete = upload_pending(
        &mut store,
        &http,
        &logical,
        &roster,
        &alice,
        &config,
        &self_route,
        0,
        ThirdPass::StopAfterStored,
    )
    .await
    .unwrap();
    assert_eq!(incomplete.needs_route, vec![4]);
    let before = store
        .delivery_report(&roster, &alice, &logical, &config, &self_route)
        .unwrap();
    for member in 1..=3 {
        assert!(before.member_stored(member));
    }
    assert!(!before.member_stored(4));
    assert!(!before.whole_vault());
    config.peers.push(fourth_peer);
    upload_pending(
        &mut store,
        &http,
        &logical,
        &roster,
        &alice,
        &config,
        &self_route,
        2000,
        ThirdPass::StopAfterStored,
    )
    .await
    .unwrap();
    let report = store
        .delivery_report(&roster, &alice, &logical, &config, &self_route)
        .unwrap();
    assert!(report.whole_vault());
    assert_eq!(report.whole_pins().len(), 2);
    for member in 1..=4 {
        assert!(report.member_stored(member));
    }
    let fourth = prepared
        .recipients()
        .iter()
        .find(|c| c.recipient() == 4)
        .unwrap();
    let route = descriptor(4)
        .relays
        .into_iter()
        .find(|r| r.route.endpoint != routes.iter().find(|(_, _, index)| *index == 0).unwrap().1)
        .unwrap()
        .route;
    let mut fetched = std::collections::BTreeMap::new();
    for object in fourth.objects() {
        let saved = http
            .get(&route, &Secret32::from_bytes([44; 32]), &object.hash)
            .await
            .unwrap();
        assert_eq!(saved, *object);
        fetched.insert(saved.hash, saved);
    }
    let root = fetched.get(fourth.root_hash()).unwrap();
    let opened = TransferAssembler::open(&roster, &identity(4), root, &fetched).unwrap();
    assert_eq!(opened.message().body(), &body(&roster));
    drop(store);
    for server in &servers {
        server.abort();
    }
    for server in servers {
        let _ = server.await;
    }
    for owner in owners {
        owner.shutdown().await.unwrap();
    }
    std::fs::remove_dir_all(parent).unwrap();
}

#[test]
fn fourth_descriptor_owner_must_belong_to_exact_roster() {
    use ed25519_dalek::SigningKey;
    use loki_relay_client::{
        open_descriptor, seal_descriptor, Descriptor, DescriptorRelay, Secret32,
    };
    use loki_relay_protocol::types::{RelayPin, RelayRoute};
    let four = roster(4);
    let three = roster(3);
    let mut relays: Vec<_> = (1u8..=3)
        .map(|index| DescriptorRelay {
            route: RelayRoute {
                pin: RelayPin {
                    key: SigningKey::from_bytes(&[index + 70; 32])
                        .verifying_key()
                        .to_bytes(),
                    run: [index; 32],
                },
                endpoint: format!("http://127.0.0.1:{}", 8000 + index as u16),
                mailbox: [index + 10; 32],
                append_revision: 1,
            },
            append: Secret32::from_bytes([index + 20; 32]),
        })
        .collect();
    relays.sort_by_key(|r| r.route.pin.key);
    let mut descriptor = Descriptor::new(four.vault, roster_digest(&four).unwrap(), 4, 1, relays);
    let sealed = seal_descriptor(&identity(4), &four, &descriptor, &identity(1).public()).unwrap();
    let opened = open_descriptor(&identity(1), &four, &sealed.wire).unwrap();
    assert_eq!(opened.body().owner, 4);
    assert_eq!(opened.body().relays.len(), 3);
    assert!(open_descriptor(&identity(1), &three, &sealed.wire).is_err());
    descriptor.roster = roster_digest(&three).unwrap();
    assert!(seal_descriptor(&identity(4), &three, &descriptor, &identity(1).public()).is_err());
}

#[test]
fn saved_four_member_retry_refuses_missing_fourth_recipient() {
    let roster = roster(4);
    let alice = identity(1);
    let prepared = prepare_outbox(&alice, &roster, &body(&roster)).unwrap();
    let mut random = [0; 32];
    getrandom::fill(&mut random).unwrap();
    let parent = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("loki-four-corrupt-{}", hex::encode(random)));
    std::fs::create_dir(&parent).unwrap();
    let root = parent.join("client");
    let mut store = ClientStore::open(&root, &roster, 1).unwrap();
    store
        .commit_outbox(&roster, &alice, &[90; 32], &prepared)
        .unwrap();
    assert_eq!(store.pending_transfer_count().unwrap(), 4);
    let sql = rusqlite::Connection::open(root.join("client.sqlite3")).unwrap();
    sql.pragma_update(None, "foreign_keys", "OFF").unwrap();
    let trigger: String = sql
        .query_row(
            "SELECT sql FROM sqlite_master WHERE name='outgoing_recipients_no_delete'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    sql.execute_batch("DROP TRIGGER outgoing_recipients_no_delete;")
        .unwrap();
    sql.execute("DELETE FROM outgoing_recipients WHERE recipient=4", [])
        .unwrap();
    sql.execute_batch(&trigger).unwrap();
    assert!(store
        .commit_outbox(&roster, &alice, &[90; 32], &prepared)
        .is_err());
    drop(sql);
    drop(store);
    std::fs::remove_dir_all(parent).unwrap();
}
