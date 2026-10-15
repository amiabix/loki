use super::*;
use ed25519_dalek::{Signer, SigningKey};
#[path = "../tests/support/hosted_services.rs"]
mod hosted_services;

#[test]
fn authenticated_transport_conflict_notifies_admission_for_both_policies() {
    let mut services = hosted_services::HostedServices::start();
    for count in [3u16, 4] {
        let identity = Identity::new(1);
        let member = MemberDir::create(&services.root, &format!("conflict-{count}")).unwrap();
        MemberDir::create(member.path(), "secrets")
            .unwrap()
            .write_sealed("identity.sealed", &identity.to_secret_bytes(), "pass")
            .unwrap();
        let operators =
            OperatorSet::verify_development(&services.bundle, &services.config_key).unwrap();
        let grant = enrollment(&identity, &operators, count);
        let mut setup = HostedSetup::create(
            member.path(),
            "pass",
            &services.bundle,
            &services.config_key,
            &grant,
            count,
            true,
        )
        .unwrap();
        let limit = std::time::Instant::now() + std::time::Duration::from_secs(60);
        while setup.step().unwrap().public_json()["phase"] != "invites_ready" {
            assert!(std::time::Instant::now() < limit);
        }
        let context = setup.bootstrap_context().unwrap();
        let peers = vec![setup.identity.public()];
        let transport = SetupTransport::new(
            &setup.identity,
            &setup.operators,
            SetupAuthority::Bootstrap(&context, &peers),
            true,
        )
        .unwrap();
        let mut store =
            SetupStore::open(&member.path().join("setup-relay-store"), &transport).unwrap();
        let record = |payload| SetupRecord {
            version: 1,
            key: SetupKey {
                ceremony: context.policy().ceremony,
                phase: SetupPhase::Join,
                author: 1,
                recipient: 1,
                revision: 1,
            },
            network: "regtest".into(),
            threshold: 2,
            member_count: count,
            roster_digest: None,
            prerequisites: vec![],
            payload: vec![payload],
        };
        let first = transport.prepare(&[record(1)]).unwrap();
        assert!(store.commit_outgoing(&transport, &first).unwrap());
        let conflicting = transport.prepare(&[record(2)]).unwrap();
        assert!(matches!(
            store.commit_outgoing(&transport, &conflicting),
            Err(loki_relay_client::ClientError::Conflict)
        ));
        assert!(store.is_terminal().unwrap());
        drop(store);
        services.stop_admission();
        assert_eq!(
            setup.step().unwrap().public_json()["phase"],
            "terminal_pending"
        );
        assert!(member
            .path()
            .join("secrets/setup-admission-retry.sealed")
            .exists());
        drop(setup);
        let mut setup = HostedSetup::open(member.path(), "pass").unwrap();
        assert_eq!(
            setup.step().unwrap().public_json()["phase"],
            "terminal_pending"
        );
        services.restart_admission();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let status = setup.step().unwrap().public_json();
            if status["phase"] == "aborted" {
                break;
            }
            assert_eq!(status["phase"], "terminal_pending");
            assert_eq!(status["retryable"], true);
            assert!(std::time::Instant::now() < deadline);
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert!(!member.path().join("setup-ceremony").exists());
        let state = setup.state().unwrap().unwrap();
        let AdmissionOutcome::Accepted(Value::Array(fields)) = state.outcome() else {
            panic!("signed terminal state required")
        };
        assert_eq!(fields[3], Value::Integer(1.into()));
        drop(setup);
        let mut resumed = HostedSetup::open(member.path(), "pass").unwrap();
        assert_eq!(resumed.step().unwrap().public_json()["phase"], "aborted");
    }
}

fn enrollment(identity: &Identity, operators: &OperatorSet, count: u16) -> Vec<u8> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    enrollment_at(identity, operators, count, now + 3600)
}
fn enrollment_at(
    identity: &Identity,
    operators: &OperatorSet,
    count: u16,
    expires: u64,
) -> Vec<u8> {
    let body = canonical::encode(&Value::Array(vec![
        Value::Integer(1.into()),
        Value::Bytes(vec![count as u8; 32]),
        Value::Bytes(identity.public().signing.to_vec()),
        Value::Integer(expires.into()),
        Value::Integer(1.into()),
        Value::Integer(24.into()),
        Value::Bytes(operators.digest().to_vec()),
    ]))
    .unwrap();
    let signature = SigningKey::from_bytes(&[9; 32]).sign(
        &loki_relay_protocol::admission::signature_input(b"Loki_Setup_Enrollment_v1\0", &body)
            .unwrap(),
    );
    let grant = canonical::encode(&Value::Array(vec![
        Value::Bytes(body),
        Value::Bytes(signature.to_bytes().to_vec()),
    ]))
    .unwrap();
    grant
}

#[test]
fn signed_ceremony_expiry_reconciles_and_notifies_for_both_policies() {
    let services = hosted_services::HostedServices::start_with_limits(2, 12);
    for count in [3u16, 4] {
        let identity = Identity::new(1);
        let member = MemberDir::create(&services.root, &format!("expiry-{count}")).unwrap();
        MemberDir::create(member.path(), "secrets")
            .unwrap()
            .write_sealed("identity.sealed", &identity.to_secret_bytes(), "pass")
            .unwrap();
        let operators =
            OperatorSet::verify_development(&services.bundle, &services.config_key).unwrap();
        let grant = enrollment(&identity, &operators, count);
        let mut setup = HostedSetup::create(
            member.path(),
            "pass",
            &services.bundle,
            &services.config_key,
            &grant,
            count,
            true,
        )
        .unwrap();
        let limit = std::time::Instant::now() + std::time::Duration::from_secs(45);
        loop {
            let status = setup.step().unwrap().public_json();
            if status["phase"] == "expired" {
                break;
            }
            assert!(
                std::time::Instant::now() < limit,
                "signed ceremony expiry must reconcile"
            );
            std::thread::sleep(std::time::Duration::from_millis(200));
        }
        assert!(!member.path().join("setup-ceremony").exists());
        assert!(setup.invitations().is_err());
        let state = setup.state().unwrap().unwrap();
        let AdmissionOutcome::Accepted(Value::Array(fields)) = state.outcome() else {
            panic!("signed expiry state required")
        };
        assert_eq!(fields[3], Value::Integer(4.into()));
        drop(setup);
        let mut resumed = HostedSetup::open(member.path(), "pass").unwrap();
        assert_eq!(resumed.step().unwrap().public_json()["phase"], "expired");
    }
}

#[test]
fn signed_checkpoint_conflict_reconciles_and_notifies_for_both_policies() {
    let services = hosted_services::HostedServices::start();
    for count in [3u16, 4] {
        let identity = Identity::new(1);
        let member = MemberDir::create(&services.root, &format!("checkpoint-{count}")).unwrap();
        MemberDir::create(member.path(), "secrets")
            .unwrap()
            .write_sealed("identity.sealed", &identity.to_secret_bytes(), "pass")
            .unwrap();
        let operators =
            OperatorSet::verify_development(&services.bundle, &services.config_key).unwrap();
        let grant = enrollment(&identity, &operators, count);
        let mut setup = HostedSetup::create(
            member.path(),
            "pass",
            &services.bundle,
            &services.config_key,
            &grant,
            count,
            true,
        )
        .unwrap();
        assert_eq!(setup.step().unwrap().public_json()["phase"], "provisioning");
        let request = sign_admission_request(
            &setup.identity,
            &AdmissionRequest {
                operation: random(),
                device: setup.identity.public(),
                command: AdmissionCommand::Checkpoint {
                    ceremony: setup.policy().unwrap().ceremony,
                    slot: 1,
                    generation: 2,
                    predecessor: [6; 32],
                    checkpoint: [7; 32],
                },
            },
        )
        .unwrap();
        let reply = setup
            .runtime
            .block_on(setup.http.execute(&request, None))
            .unwrap();
        assert!(matches!(
            reply.outcome(),
            AdmissionOutcome::Rejected("conflict")
        ));
        assert_eq!(
            setup.step().unwrap().public_json()["phase"],
            "checkpoint_conflict"
        );
        assert!(!member.path().join("setup-ceremony").exists());
        drop(setup);
        let mut resumed = HostedSetup::open(member.path(), "pass").unwrap();
        assert_eq!(
            resumed.step().unwrap().public_json()["phase"],
            "checkpoint_conflict"
        );
        assert!(resumed.invitations().is_err());
    }
}

#[test]
fn creator_provisions_two_relays_with_one_offline_for_both_policies() {
    let mut services = hosted_services::HostedServices::start();
    services.stop_relay(0);
    for count in [3u16, 4] {
        let identity = Identity::new(1);
        let member = MemberDir::create(&services.root, &format!("outage-{count}")).unwrap();
        MemberDir::create(member.path(), "secrets")
            .unwrap()
            .write_sealed("identity.sealed", &identity.to_secret_bytes(), "pass")
            .unwrap();
        let operators =
            OperatorSet::verify_development(&services.bundle, &services.config_key).unwrap();
        let grant = enrollment(&identity, &operators, count);
        let mut setup = HostedSetup::create(
            member.path(),
            "pass",
            &services.bundle,
            &services.config_key,
            &grant,
            count,
            true,
        )
        .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            let status = setup.step().unwrap().public_json();
            assert_eq!(status["handoff"], "pending");
            if status["phase"] == "invites_ready" {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "two-relay provisioning quorum required"
            );
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        assert_eq!(setup.invitations().unwrap().len(), (count - 1) as usize);
        let state = setup.state().unwrap().unwrap();
        let AdmissionOutcome::Accepted(Value::Array(fields)) = state.outcome() else {
            panic!("signed provisioning state required")
        };
        let Value::Array(mailboxes) = &fields[5] else {
            panic!("signed mailbox rows required")
        };
        assert_eq!(mailboxes.len(), 3);
        let provisioned = mailboxes
            .iter()
            .filter(
                |row| matches!(row, Value::Array(values) if values[3] == Value::Integer(1.into())),
            )
            .count();
        assert_eq!(provisioned, 2);
        assert!(!member.path().join("setup-ceremony").exists());
        drop(setup);
        let mut reopened = HostedSetup::open(member.path(), "pass").unwrap();
        assert_eq!(reopened.step().unwrap().public_json()["handoff"], "pending");
        assert_eq!(reopened.invitations().unwrap().len(), (count - 1) as usize);
    }
}

#[test]
fn rejected_expired_enrollment_stops_a_pending_abort_without_claiming_remote_termination() {
    let services = hosted_services::HostedServices::start();
    for count in [3u16, 4] {
        let identity = Identity::new(1);
        let member = MemberDir::create(&services.root, &format!("rejected-{count}")).unwrap();
        MemberDir::create(member.path(), "secrets")
            .unwrap()
            .write_sealed("identity.sealed", &identity.to_secret_bytes(), "pass")
            .unwrap();
        let operators =
            OperatorSet::verify_development(&services.bundle, &services.config_key).unwrap();
        let grant = enrollment_at(&identity, &operators, count, 1);
        let mut setup = HostedSetup::create(
            member.path(),
            "pass",
            &services.bundle,
            &services.config_key,
            &grant,
            count,
            true,
        )
        .unwrap();
        let public = setup.abort().unwrap().public_json();
        assert_eq!(public["phase"], "admission_rejected");
        assert_eq!(public["retryable"], false);
        assert_eq!(public["joined_slots"], serde_json::json!([]));
        assert_eq!(public["handoff"], "pending");
        assert_eq!(public.as_object().unwrap().len(), 8);
        assert_eq!(HostedSetup::cached_status(member.path()).unwrap()["phase"], "admission_rejected");
        assert!(!member.path().join("setup-relay-store").exists());
        assert!(!member.path().join("setup-ceremony").exists());
        let saved = setup.journal.latest().unwrap().digest;
        drop(setup);
        let mut reopened = HostedSetup::open(member.path(), "pass").unwrap();
        assert_eq!(
            reopened.step().unwrap().public_json()["phase"],
            "admission_rejected"
        );
        assert_eq!(reopened.journal.latest().unwrap().digest, saved);
        assert_eq!(
            reopened.abort().unwrap().public_json()["phase"],
            "admission_rejected"
        );
        assert!(reopened.invitations().is_err());
    }
}
