#![cfg(feature = "relay-communication")]
//! Carrier codec and durable outbox bindings. Publication reuses the committed message.

use loki_poc::{
    relay_courier::{commit_carrier, Carrier, RelayCourier},
    relay_member::open_session,
    setup_transport::Identity,
    signing_session::{AttemptId, EnvelopeRoute, MessageKind, SessionContext, SessionCourier},
};
use loki_relay_client::{outbox_intent_digest, prepare_outbox, reopen_committed};
use loki_relay_protocol::types::{LogicalKey, MessageBody, Payload};
use rand_core::{OsRng, RngCore};
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::OnceLock,
    thread,
    time::{Duration, Instant},
};

const PASS: &str = " synthetic setup pass ";
const MAX_ENVELOPE: usize = 8 * 1024 * 1024 + 53;
static CERTIFIED: OnceLock<PathBuf> = OnceLock::new();

fn private(path: &Path, directory: bool) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(if directory { 0o700 } else { 0o600 }),
        )
        .unwrap();
    }
}

fn scratch() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "loki-relay-courier-{}-{}",
        std::process::id(),
        hex::encode(Identity::new(1).public().signing)
    ));
    fs::create_dir(&path).unwrap();
    private(&path, true);
    path.canonicalize().unwrap()
}

fn certified_setup() -> &'static PathBuf {
    CERTIFIED.get_or_init(|| {
        let root = scratch();
        let exchange = root.join("exchange");
        fs::create_dir(&exchange).unwrap();
        let exe = env!("CARGO_BIN_EXE_loki_setup_member");
        let mut public = Vec::new();
        for id in 1..=3 {
            let member = root.join(format!("member-{id}"));
            fs::create_dir(&member).unwrap();
            private(&member, true);
            let pass = member.join("pass");
            fs::write(&pass, format!("{PASS}\r\n")).unwrap();
            private(&pass, false);
            let out = Command::new(exe)
                .args([
                    "identity",
                    member.to_str().unwrap(),
                    &id.to_string(),
                    pass.to_str().unwrap(),
                ])
                .output()
                .unwrap();
            assert!(out.status.success(), "synthetic setup identity failed");
            public.push(serde_json::from_slice::<Value>(&out.stdout).unwrap());
        }
        let roster = root.join("roster.json");
        fs::write(
            &roster,
            serde_json::to_vec(&serde_json::json!({"vault":hex::encode([71;32]),"members":public}))
                .unwrap(),
        )
        .unwrap();
        let out = Command::new(exe)
            .args(["fingerprint", roster.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(out.status.success());
        let fingerprint = String::from_utf8(out.stdout).unwrap();
        let mut children = Vec::new();
        for id in 1..=3 {
            let member = root.join(format!("member-{id}"));
            children.push(
                Command::new(exe)
                    .args([
                        "run",
                        member.to_str().unwrap(),
                        member.join("pass").to_str().unwrap(),
                        roster.to_str().unwrap(),
                        exchange.to_str().unwrap(),
                        fingerprint.trim(),
                    ])
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap(),
            );
        }
        let deadline = Instant::now() + Duration::from_secs(25);
        for mut child in children {
            while child.try_wait().unwrap().is_none() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(20));
            }
            if child.try_wait().unwrap().is_none() {
                child.kill().unwrap();
            }
            let out = child.wait_with_output().unwrap();
            assert!(out.status.success(), "certificate exchange failed");
        }
        root
    })
}

fn member_root(id: u16) -> (PathBuf, PathBuf, PathBuf) {
    let base = certified_setup();
    let root = scratch();
    fs::create_dir(root.join("secrets")).unwrap();
    private(&root.join("secrets"), true);
    for file in ["identity.sealed", "vault.sealed"] {
        let dest = root.join("secrets").join(file);
        fs::copy(base.join(format!("member-{id}/secrets")).join(file), &dest).unwrap();
        private(&dest, false);
    }
    let pass = root.join("pass");
    fs::copy(base.join(format!("member-{id}/pass")), &pass).unwrap();
    private(&pass, false);
    let roster = root.join("roster.json");
    fs::copy(base.join("roster.json"), &roster).unwrap();
    (root, pass, roster)
}

fn context() -> SessionContext {
    SessionContext {
        vault: [9; 32],
        payment: [8; 32],
        attempt: AttemptId([7; 32]),
        pair: [1, 2],
    }
}

fn carrier(author: u16, recipient: u16, kind: MessageKind, envelope: Vec<u8>) -> Carrier {
    Carrier::new(context(), author, recipient, kind, envelope).unwrap()
}

#[test]
fn codec_rejects_tamper_trailing_version_and_bounds() {
    let package = carrier(1, 3, MessageKind::Package, vec![1, 2, 3, 4]);
    let share = carrier(1, 2, MessageKind::Share, vec![9, 9]);
    let encoded = package.encode().unwrap();
    let decoded = Carrier::decode(&encoded).unwrap();
    assert_eq!(decoded.envelope.as_slice(), package.envelope.as_slice());
    assert_eq!(
        decoded.request_binding().unwrap(),
        package.request_binding().unwrap()
    );
    assert_ne!(
        package.request_binding().unwrap(),
        share.request_binding().unwrap()
    );
    assert_ne!(package.encode().unwrap(), share.encode().unwrap());

    let mut trailing = encoded.clone();
    trailing.push(0xff);
    match Carrier::decode(&trailing) {
        Err(error) => assert_eq!(error, "carrier_trailing"),
        Ok(_) => panic!("trailing bytes accepted"),
    }

    let mut version = encoded.clone();
    assert_eq!(version[1], 1);
    version[1] = 2;
    match Carrier::decode(&version) {
        Err(error) => assert_eq!(error, "carrier_version"),
        Ok(_) => panic!("wrong version accepted"),
    }

    let mut tampered = encoded.clone();
    let last = tampered.len() - 1;
    tampered[last] ^= 0x5a;
    assert!(Carrier::decode(&tampered).is_err());

    assert!(Carrier::new(context(), 1, 1, MessageKind::Share, vec![1]).is_err());
    assert!(Carrier::new(context(), 1, 2, MessageKind::Share, Vec::new()).is_err());
    assert!(Carrier::new(
        context(),
        1,
        3,
        MessageKind::Package,
        vec![0; MAX_ENVELOPE + 1]
    )
    .is_err());
    let largest = carrier(1, 3, MessageKind::Package, vec![4; MAX_ENVELOPE]);
    let large_bytes = largest.encode().unwrap();
    assert_eq!(
        Carrier::decode(&large_bytes).unwrap().envelope.len(),
        MAX_ENVELOPE
    );

    let mut other = context();
    other.vault = [3; 32];
    let moved = Carrier::new(other, 1, 3, MessageKind::Package, vec![1, 2, 3, 4]).unwrap();
    assert_ne!(
        moved.request_binding().unwrap(),
        package.request_binding().unwrap()
    );
    other = context();
    other.payment = [3; 32];
    assert_ne!(
        Carrier::new(other, 1, 3, MessageKind::Package, vec![1, 2, 3, 4])
            .unwrap()
            .request_binding()
            .unwrap(),
        package.request_binding().unwrap()
    );
    other = context();
    other.attempt = AttemptId([3; 32]);
    assert_ne!(
        Carrier::new(other, 1, 3, MessageKind::Package, vec![1, 2, 3, 4])
            .unwrap()
            .request_binding()
            .unwrap(),
        package.request_binding().unwrap()
    );
    other = context();
    other.pair = [1, 3];
    assert_ne!(
        Carrier::new(other, 1, 3, MessageKind::Package, vec![1, 2, 3, 4])
            .unwrap()
            .request_binding()
            .unwrap(),
        package.request_binding().unwrap()
    );
    assert!(Carrier::decode(b"not-cbor").is_err());
    assert!(Carrier::decode(&[]).is_err());
}

#[test]
fn only_the_inner_recipient_opens_a_sealed_envelope() {
    let alice = Identity::new(1);
    let bob = Identity::new(2);
    let carol = Identity::new(3);
    let context = context();
    let package = alice
        .seal_session(&carol.public(), &context, MessageKind::Package, b"pczt")
        .unwrap();
    let share = alice
        .seal_session(&bob.public(), &context, MessageKind::Share, b"share")
        .unwrap();
    let package_carrier = carrier(1, 3, MessageKind::Package, package.clone());
    let share_carrier = carrier(1, 2, MessageKind::Share, share.clone());
    assert_ne!(
        package_carrier.recipient, share_carrier.recipient,
        "package and share use distinct recipient carriers"
    );
    let opened = carol
        .open_session(&alice.public(), &context, &package_carrier.envelope)
        .unwrap();
    assert_eq!(opened.recipient(), 3);
    assert_eq!(opened.kind(), MessageKind::Package);
    assert_eq!(opened.body(), b"pczt");
    assert!(bob
        .open_session(&alice.public(), &context, &package_carrier.envelope)
        .is_err());
    let opened_share = bob
        .open_session(&alice.public(), &context, &share_carrier.envelope)
        .unwrap();
    assert_eq!(opened_share.recipient(), 2);
    assert_eq!(opened_share.body(), b"share");
    assert!(carol
        .open_session(&alice.public(), &context, &share_carrier.envelope)
        .is_err());
    let mut wrong = context.clone();
    wrong.payment = [1; 32];
    assert!(carol
        .open_session(&alice.public(), &wrong, &package_carrier.envelope)
        .is_err());
}

#[test]
fn retry_reuses_message_id_and_outer_objects_conflict_fails_closed() {
    let (root, pass, roster_path) = member_root(1);
    let mut session = open_session(&root, &pass, &roster_path).unwrap();
    let sample = carrier(1, 2, MessageKind::Share, b"exact-share-wire".to_vec());
    let first = commit_carrier(
        &mut session.db,
        &session.member.identity,
        &session.member.roster,
        &sample,
    )
    .unwrap();
    let before = object_hashes(&session, &first);
    let second = commit_carrier(
        &mut session.db,
        &session.member.identity,
        &session.member.roster,
        &sample,
    )
    .unwrap();
    assert_eq!(first.message, second.message);
    assert_eq!(first.digest, second.digest);
    assert_eq!(first.request, second.request);
    assert_eq!(before, object_hashes(&session, &second));
    assert_eq!(session.db.recover_logical(0, 100).unwrap().len(), 1);

    let encoded = sample.encode().unwrap();
    let mut probe = MessageBody {
        key: LogicalKey {
            vault: session.member.roster.vault,
            roster: loki_relay_protocol::types::roster_digest(&session.member.roster).unwrap(),
            sender: 1,
            message: [0; 32],
        },
        audience: vec![1, 2, 3],
        session: None,
        prerequisites: Vec::new(),
        payload: Payload::Test(encoded.clone()),
    };
    let intent = outbox_intent_digest(&probe).unwrap();
    let found = session
        .db
        .lookup_outbox_request(&first.request, &intent)
        .unwrap()
        .unwrap();
    assert_eq!(found.key.message, first.message);
    assert_eq!(found.digest, first.digest);
    probe.payload = Payload::Test(b"other-body".to_vec());
    let wrong = outbox_intent_digest(&probe).unwrap();
    assert_eq!(
        session
            .db
            .lookup_outbox_request(&first.request, &wrong)
            .unwrap_err()
            .code(),
        "conflict"
    );

    let opened = reopen_committed(
        &session.db,
        &session.member.roster,
        &session.member.identity,
        &found.key,
        &found.digest,
        &session
            .db
            .recover_recipients(&found.key)
            .unwrap()
            .into_iter()
            .find(|recipient| recipient.recipient == 1)
            .unwrap()
            .root_hash,
    )
    .unwrap();
    match &opened.message().body().payload {
        Payload::Test(saved) => assert_eq!(saved, &encoded),
        Payload::Received(_) => panic!("carrier payload changed kind"),
    }
    let mut bad_digest = found.digest;
    bad_digest[0] ^= 0xff;
    assert!(reopen_committed(
        &session.db,
        &session.member.roster,
        &session.member.identity,
        &found.key,
        &bad_digest,
        &found.source_root,
    )
    .is_err());

    drop(session);
    let mut restarted = open_session(&root, &pass, &roster_path).unwrap();
    let third = commit_carrier(
        &mut restarted.db,
        &restarted.member.identity,
        &restarted.member.roster,
        &sample,
    )
    .unwrap();
    assert_eq!(third.message, first.message);
    assert_eq!(object_hashes(&restarted, &third), before);

    let conflict_root = member_root(1);
    let mut conflict = open_session(&conflict_root.0, &conflict_root.1, &conflict_root.2).unwrap();
    let binding = sample.request_binding().unwrap();
    let mut body = MessageBody {
        key: LogicalKey {
            vault: conflict.member.roster.vault,
            roster: loki_relay_protocol::types::roster_digest(&conflict.member.roster).unwrap(),
            sender: conflict.member.identity.public().id,
            message: [0; 32],
        },
        audience: vec![1, 2, 3],
        session: None,
        prerequisites: Vec::new(),
        payload: Payload::Test(b"different carrier body".to_vec()),
    };
    OsRng.try_fill_bytes(&mut body.key.message).unwrap();
    let prepared =
        prepare_outbox(&conflict.member.identity, &conflict.member.roster, &body).unwrap();
    conflict
        .db
        .commit_outbox(
            &conflict.member.roster,
            &conflict.member.identity,
            &binding,
            &prepared,
        )
        .unwrap();
    match commit_carrier(
        &mut conflict.db,
        &conflict.member.identity,
        &conflict.member.roster,
        &sample,
    ) {
        Err(error) => assert_eq!(error, "conflict"),
        Ok(_) => panic!("same binding with a different body committed"),
    }

    let foreign = member_root(2);
    let mut foreign_session = open_session(&foreign.0, &foreign.1, &foreign.2).unwrap();
    match commit_carrier(
        &mut foreign_session.db,
        &foreign_session.member.identity,
        &foreign_session.member.roster,
        &sample,
    ) {
        Err(error) => assert_eq!(error, "carrier_author"),
        Ok(_) => panic!("foreign author committed the carrier"),
    }
}

#[test]
fn attempt_budget_fits_one_max_envelope_and_refuses_a_tight_inbox() {
    let quotas = loki_poc::relay_courier::demo_quotas();
    let reserved = loki_poc::relay_courier::reserve_attempt(MAX_ENVELOPE, quotas).unwrap();
    assert!(reserved < quotas.member_bytes);
    assert!(reserved > MAX_ENVELOPE as u64);
    let tight = loki_poc::relay_courier::AttemptQuotas {
        inbox_bytes: 1024,
        relay_bytes: quotas.relay_bytes,
        member_bytes: quotas.member_bytes,
    };
    match loki_poc::relay_courier::reserve_attempt(MAX_ENVELOPE, tight) {
        Err(error) => assert_eq!(error, "capacity"),
        Ok(_) => panic!("8 MiB envelope fit a 1024-byte inbox"),
    }
    match loki_poc::relay_courier::reserve_attempt(0, quotas) {
        Err(error) => assert_eq!(error, "carrier_bounds"),
        Ok(_) => panic!("empty envelope reserved"),
    }
}

fn object_hashes(
    session: &loki_poc::relay_member::Session,
    committed: &loki_poc::relay_courier::CommittedCarrier,
) -> Vec<Vec<[u8; 32]>> {
    let logical = session
        .db
        .recover_logical(0, 100)
        .unwrap()
        .into_iter()
        .find(|row| row.key.message == committed.message)
        .unwrap();
    (1..=3)
        .map(|recipient| {
            session
                .db
                .recover_requirements(&logical.key, recipient, None, 100)
                .unwrap()
                .into_iter()
                .map(|requirement| requirement.hash)
                .collect()
        })
        .collect()
}

#[test]
fn publish_retries_saved_wire_without_a_mailbox_or_second_message() {
    let (root, pass, roster) = member_root(1);
    let mut courier = RelayCourier::open(&root, &pass, &roster).unwrap();
    assert!(courier.drive_once().is_err());
    assert!(courier
        .receive(
            &Identity::new(1),
            &std::collections::BTreeMap::new(),
            &context(),
            MessageKind::Share,
            2,
        )
        .unwrap()
        .is_none());
    let sample = carrier(1, 2, MessageKind::Share, b"saved-share".to_vec());
    let route = EnvelopeRoute {
        context: &sample.context,
        author: 1,
        recipient: 2,
        kind: MessageKind::Share,
    };
    let first = courier.publish(&route, sample.envelope.as_slice()).unwrap();
    let second = courier.publish(&route, sample.envelope.as_slice()).unwrap();
    assert_eq!(first, second);
    let expected: [u8; 32] = blake3::hash(sample.envelope.as_slice()).into();
    assert_eq!(first, expected);
    assert_eq!(courier.database().recover_logical(0, 100).unwrap().len(), 1);
    assert!(!root.join("mailbox").exists());
    assert!(!root.join("work").exists());
}

#[test]
fn control_pipe_pages_a_snapshot_and_a_broken_export_keeps_publication() {
    use std::io::{BufRead, BufReader, Write};
    use std::os::fd::IntoRawFd;
    let (root, pass, roster) = member_root(1);
    let mut courier = RelayCourier::open(&root, &pass, &roster).unwrap();
    let (observe_read, observe_write) = std::io::pipe().unwrap();
    let (control_read, mut control_write) = std::io::pipe().unwrap();
    let (response_read, response_write) = std::io::pipe().unwrap();
    courier
        .attach_inherited(
            observe_write.into_raw_fd(),
            control_read.into_raw_fd(),
            response_write.into_raw_fd(),
        )
        .unwrap();
    let mut response = BufReader::new(response_read);
    writeln!(
        control_write,
        r#"{{"version":1,"type":"snapshot_page","snapshot_id":"generation-1","section":"logical","after":"0","limit":10}}"#
    )
    .unwrap();
    courier.service_export();
    let mut line = String::new();
    response.read_line(&mut line).unwrap();
    let page: Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(page["version"], 1);
    assert_eq!(page["section"], "logical");
    assert_eq!(page["rows"].as_array().unwrap().len(), 0);
    assert!(courier
        .database()
        .recover_logical(0, 10)
        .unwrap()
        .is_empty());

    writeln!(
        control_write,
        r#"{{"version":1,"type":"sign","command":"approve"}}"#
    )
    .unwrap();
    courier.service_export();
    line.clear();
    response.read_line(&mut line).unwrap();
    let denied: Value = serde_json::from_str(line.trim()).unwrap();
    assert_eq!(denied["error"], "request");
    assert!(courier
        .database()
        .recover_logical(0, 10)
        .unwrap()
        .is_empty());

    drop(observe_read);
    courier.note_approved(&context(), 1, [3; 32]);
    assert!(courier.take_events().unwrap().disabled());
    let sample = carrier(1, 2, MessageKind::Share, b"saved-share".to_vec());
    let route = EnvelopeRoute {
        context: &sample.context,
        author: 1,
        recipient: 2,
        kind: MessageKind::Share,
    };
    let published = courier.publish(&route, sample.envelope.as_slice()).unwrap();
    let expected: [u8; 32] = blake3::hash(sample.envelope.as_slice()).into();
    assert_eq!(published, expected);
    assert_eq!(courier.database().recover_logical(0, 10).unwrap().len(), 1);
}

#[test]
fn reopened_couriers_start_distinct_observation_producers() {
    use std::io::{BufRead, BufReader};
    use std::os::fd::IntoRawFd;
    let (root, pass, roster) = member_root(1);
    let mut observations = Vec::new();
    for _ in 0..2 {
        let mut courier = RelayCourier::open(&root, &pass, &roster).unwrap();
        let (observe_read, observe_write) = std::io::pipe().unwrap();
        let (control_read, _control_write) = std::io::pipe().unwrap();
        let (_response_read, response_write) = std::io::pipe().unwrap();
        courier
            .attach_inherited(
                observe_write.into_raw_fd(),
                control_read.into_raw_fd(),
                response_write.into_raw_fd(),
            )
            .unwrap();
        courier.note_approved(&context(), 1, [3; 32]);
        let mut line = String::new();
        BufReader::new(observe_read).read_line(&mut line).unwrap();
        let event: Value = serde_json::from_str(&line).unwrap();
        assert_eq!(event["producer_sequence"], 1);
        assert_eq!(event["event_type"], "approved");
        let producer = event["producer_id"].as_str().unwrap();
        assert!(producer.starts_with("member-1-"));
        assert!(producer.len() <= 64);
        observations.push(event);
    }
    assert_eq!(observations[0]["run_id"], observations[1]["run_id"]);
    assert_ne!(
        observations[0]["producer_id"],
        observations[1]["producer_id"]
    );
}

#[test]
fn signing_observations_identify_the_local_actor_and_authenticated_sender() {
    let (root, pass, roster) = member_root(3);
    let mut courier = RelayCourier::open(&root, &pass, &roster).unwrap();
    courier.set_events(
        loki_poc::relay_member::PublicEventWriter::new("actor-test", "member-3-test").unwrap(),
    );
    let mut context = context();
    context.pair = [1, 3];
    courier.note_approved(&context, 3, [3; 32]);
    let events = courier.pop_events();
    assert_eq!(events.len(), 1);
    let approval: Value = serde_json::from_slice(&events[0]).unwrap();
    assert_eq!(approval["event_type"], "approved");
    assert_eq!(approval["actor_member"], 3);
    assert_eq!(approval["authenticated_sender"], 3);
    assert!(approval.get("recipient_member").is_none());
    assert!(approval.get("message_id").is_none());

    let identity_raw = loki_poc::state::MemberDir::open(&root, "secrets")
        .read_sealed("identity.sealed", PASS)
        .unwrap();
    let own = Identity::from_secret_bytes(&identity_raw).unwrap();
    let sender = Identity::new(1);
    let wire = sender
        .seal_session(
            &own.public(),
            &context,
            MessageKind::Package,
            b"reviewed package",
        )
        .unwrap();
    let opened = own.open_session(&sender.public(), &context, &wire).unwrap();
    courier.note_application(true, &opened);
    let events = courier.pop_events();
    assert_eq!(events.len(), 1);
    let application: Value = serde_json::from_slice(&events[0]).unwrap();
    assert_eq!(application["event_type"], "application_accepted");
    assert_eq!(application["actor_member"], 3);
    assert_eq!(application["authenticated_sender"], 1);
    assert_eq!(application["recipient_member"], 3);
    assert!(application.get("message_id").is_none());
}
