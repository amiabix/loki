#![cfg(feature = "relay-communication")]
use ed25519_dalek::{Signer, SigningKey};
use loki_poc::{setup_relay::HostedSetup, setup_transport::Identity, state::MemberDir};
use loki_relay_client::OperatorSet;
use loki_relay_protocol::{
    admission,
    canonical::{self, Value},
};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, path::Path};
fn operator_bundle(admission_origin: &str) -> (Vec<u8>, [u8; 32]) {
    let key = SigningKey::from_bytes(&[91; 32]);
    let mut relays: Vec<_> = (1u8..=3)
        .map(|i| {
            Value::Array(vec![
                Value::Bytes(
                    SigningKey::from_bytes(&[i; 32])
                        .verifying_key()
                        .to_bytes()
                        .to_vec(),
                ),
                Value::Bytes(vec![i + 10; 32]),
                Value::Bytes(format!("https://relay{i}.example").into_bytes()),
            ])
        })
        .collect();
    relays.sort_by_key(|r| canonical::encode(r).unwrap());
    let body = canonical::encode(&Value::Array(vec![
        Value::Integer(1.into()),
        Value::Array(relays),
        Value::Array(vec![
            Value::Bytes(admission_origin.as_bytes().to_vec()),
            Value::Bytes(
                SigningKey::from_bytes(&[8; 32])
                    .verifying_key()
                    .to_bytes()
                    .to_vec(),
            ),
        ]),
        Value::Array(vec![Value::Integer(1.into())]),
        Value::Array(
            [86400u64, 2592000, 1048576, 67108864, 1, 1, 60]
                .into_iter()
                .map(|n| Value::Integer(n.into()))
                .collect(),
        ),
    ]))
    .unwrap();
    let mut input = b"Loki_Operator_Config_v1\0".to_vec();
    input.extend_from_slice(&(body.len() as u32).to_be_bytes());
    input.extend_from_slice(&body);
    let bytes = canonical::encode(&Value::Array(vec![
        Value::Bytes(body),
        Value::Bytes(key.sign(&input).to_bytes().to_vec()),
    ]))
    .unwrap();
    (bytes, key.verifying_key().to_bytes())
}
fn private_input(path: &Path, bytes: &[u8]) {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
fn sealed_files(root: &Path) -> BTreeMap<String, [u8; 32]> {
    let mut result = BTreeMap::new();
    for entry in fs::read_dir(root).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            for (name, digest) in sealed_files(&entry.path()) {
                result.insert(
                    format!("{}/{}", entry.file_name().to_str().unwrap(), name),
                    digest,
                );
            }
        } else if entry.path().extension().is_some_and(|e| e == "sealed")
            && !(root.file_name().is_some_and(|name| name == "secrets")
                && entry.file_name() == "setup-admission-retry.sealed")
        {
            result.insert(
                entry.file_name().to_str().unwrap().to_owned(),
                Sha256::digest(fs::read(entry.path()).unwrap()).into(),
            );
        }
    }
    result
}
fn wait_phase(setup: &mut HostedSetup, expected: &str) -> serde_json::Value {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let status = setup.step().unwrap().public_json();
        if status["phase"] == expected {
            return status;
        }
        assert_eq!(status["retryable"], true);
        assert!(
            std::time::Instant::now() < deadline,
            "signed setup phase did not reconcile"
        );
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}
#[test]
fn offline_creation_reopens_the_exact_saved_intent_for_both_policies() {
    for count in [3u16, 4] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let (bundle, key) = operator_bundle(&origin);
        let operators = OperatorSet::verify_development(&bundle, &key).unwrap();
        let identity = Identity::new(1);
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "loki-hosted-create-{}",
            hex::encode(identity.public().signing)
        ));
        let member = MemberDir::create(&root, "member").unwrap();
        MemberDir::create(member.path(), "secrets")
            .unwrap()
            .write_sealed("identity.sealed", &identity.to_secret_bytes(), "pass")
            .unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let body = canonical::encode(&Value::Array(vec![
            Value::Integer(1.into()),
            Value::Bytes(vec![7; 32]),
            Value::Bytes(identity.public().signing.to_vec()),
            Value::Integer((now + 3600).into()),
            Value::Integer(1.into()),
            Value::Integer(24.into()),
            Value::Bytes(operators.digest().to_vec()),
        ]))
        .unwrap();
        let signature = SigningKey::from_bytes(&[9; 32])
            .sign(&admission::signature_input(b"Loki_Setup_Enrollment_v1\0", &body).unwrap());
        let grant = canonical::encode(&Value::Array(vec![
            Value::Bytes(body),
            Value::Bytes(signature.to_bytes().to_vec()),
        ]))
        .unwrap();
        let initial = sealed_files(member.path());
        assert!(
            HostedSetup::create(member.path(), "pass", &bundle, &key, &grant, count, false)
                .is_err()
        );
        assert!(HostedSetup::create(
            member.path(),
            "pass",
            &bundle,
            &[55; 32],
            &grant,
            count,
            true
        )
        .is_err());
        assert_eq!(sealed_files(member.path()), initial);
        let mut hosted =
            HostedSetup::create(member.path(), "pass", &bundle, &key, &grant, count, true).unwrap();
        let status = hosted.step().unwrap();
        assert_eq!(status.public_json()["phase"], "admission_pending");
        assert_eq!(status.public_json()["policy"], format!("2-of-{count}"));
        let saved = sealed_files(member.path());
        assert!(saved.len() >= 2);
        drop(hosted);
        let mut reopened = HostedSetup::open(member.path(), "pass").unwrap();
        let status = reopened.step().unwrap();
        assert_eq!(status.public_json()["phase"], "admission_pending");
        assert_eq!(sealed_files(member.path()), saved);
        assert!(HostedSetup::open(member.path(), "pass").is_err());
        drop(reopened);
        assert!(HostedSetup::open(member.path(), "wrong").is_err());
        for (name, bytes) in [
            ("pass", b"pass".as_slice()),
            ("operators", bundle.as_slice()),
            ("grant", grant.as_slice()),
        ] {
            let path = root.join(name);
            fs::write(&path, bytes).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_loki_setup_member"))
            .arg("setup-create")
            .arg(member.path())
            .arg(root.join("pass"))
            .arg(root.join("operators"))
            .arg(root.join("grant"))
            .arg(format!("2-of-{count}"))
            .arg("--operator-key")
            .arg(hex::encode(key))
            .arg("--development-http")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let public: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(public["phase"], "admission_pending");
        assert_eq!(public["policy"], format!("2-of-{count}"));
        assert!(!String::from_utf8_lossy(&output.stdout).contains(&hex::encode(&grant)));
        assert_eq!(sealed_files(member.path()), saved);
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_loki_setup_member"))
            .arg("setup-step")
            .arg(member.path())
            .arg(root.join("pass"))
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["phase"],
            "admission_pending"
        );
        assert_eq!(sealed_files(member.path()), saved);
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_loki_setup_member"))
            .arg("setup-status")
            .arg(member.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let cached: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(cached["phase"], "admission_pending");
        assert_eq!(cached["policy"], format!("2-of-{count}"));
        assert_eq!(cached["agreed_fingerprint"], serde_json::Value::Null);
        assert_eq!(cached.as_object().unwrap().len(), 8);
        let mut tampered = cached.clone();
        tampered["unexpected"] = serde_json::json!("private input");
        fs::write(
            member.path().join("setup-status.json"),
            serde_json::to_vec(&tampered).unwrap(),
        )
        .unwrap();
        assert!(HostedSetup::cached_status(member.path()).is_err());
        tampered = cached.clone();
        tampered["phase"] = serde_json::json!("arbitrary private text");
        fs::write(
            member.path().join("setup-status.json"),
            serde_json::to_vec(&tampered).unwrap(),
        )
        .unwrap();
        assert!(HostedSetup::cached_status(member.path()).is_err());
        fs::write(
            member.path().join("setup-status.json"),
            serde_json::to_vec(&cached).unwrap(),
        )
        .unwrap();
        assert_eq!(sealed_files(member.path()), saved);
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_loki_setup_member"))
            .arg("setup-backup-create")
            .arg(member.path())
            .arg(root.join("pass"))
            .arg(member.path().join("unavailable-card"))
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("setup_waiting"));
        assert!(!member.path().join("unavailable-card").exists());
        assert_eq!(sealed_files(member.path()), saved);
        let mut reopened = HostedSetup::open(member.path(), "pass").unwrap();
        assert_eq!(
            reopened.abort().unwrap().public_json()["phase"],
            "terminal_pending"
        );
        let abort_files = sealed_files(member.path());
        assert!(abort_files != saved);
        drop(reopened);
        let mut reopened = HostedSetup::open(member.path(), "pass").unwrap();
        assert_eq!(
            reopened.step().unwrap().public_json()["phase"],
            "terminal_pending"
        );
        assert_eq!(sealed_files(member.path()), abort_files);
        assert!(!member.path().join("setup-ceremony").exists());
        drop(reopened);
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_loki_setup_member"))
            .arg("setup-abort")
            .arg(member.path())
            .arg(root.join("pass"))
            .output()
            .unwrap();
        assert!(output.status.success());
        let public: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(public["phase"], "terminal_pending");
        assert_eq!(sealed_files(member.path()), abort_files);
        fs::remove_dir_all(root).unwrap();
    }
}

#[path = "support/hosted_services.rs"]
mod hosted_services;
#[test]
fn owned_real_services_provision_creator_inboxes_and_save_invites_for_both_policies() {
    run_owned_services_flow(OwnedFlow::Full);
}
#[test]
fn owned_private_invitation_exports_for_both_policies() {
    run_owned_services_flow(OwnedFlow::InviteExport);
}
#[test]
fn owned_pending_abort_reconciles_admission_before_any_provisioning_for_both_policies() {
    run_owned_services_flow(OwnedFlow::PendingAbort);
}
enum OwnedFlow {
    Full,
    InviteExport,
    PendingAbort,
}
fn drive_owned_cli(path: &Path, pass: &str) -> std::process::Output {
    let passfile = path.join("drive-pass");
    if !passfile.exists() {
        private_input(&passfile, pass.as_bytes());
    }
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_loki_setup_member"));
    command.arg("setup-step").arg(path).arg(passfile);
    let fault = std::env::var("LOKI_HOSTED_KILL_PHASE").ok();
    let is_creator = path
        .file_name()
        .unwrap()
        .to_string_lossy()
        .starts_with("creator-");
    if let Some(phase) = fault.filter(|_| is_creator) {
        command.env("LOKI_SETUP_TEST_PAUSE_ROOT", path.join("setup-ceremony"));
        command.env("LOKI_SETUP_TEST_PAUSE_PHASE", phase);
    }
    command
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command.spawn().unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
    let all = std::env::var("LOKI_HOSTED_KILL_PHASE").ok().as_deref() == Some("all");
    while child.try_wait().unwrap().is_none() {
        let phases = if all {
            vec![0, 2, 3, 4, 5, 6, 7, 8]
        } else {
            vec![255]
        };
        for phase in phases {
            let marker = path.join(if all {
                format!("checkpoint-paused-{phase}.json")
            } else {
                "checkpoint-paused.json".into()
            });
            let killed = path.join(if all {
                format!("checkpoint-killed-{phase}.json")
            } else {
                "checkpoint-killed.json".into()
            });
            if marker.exists() && !killed.exists() {
                child.kill().unwrap();
                let output = child.wait_with_output().unwrap();
                assert!(!output.status.success());
                let before = sealed_files(path);
                private_input(&killed, &fs::read(&marker).unwrap());
                let result = if all {
                    drive_owned_cli(path, pass)
                } else {
                    std::process::Command::new(env!("CARGO_BIN_EXE_loki_setup_member"))
                        .arg("setup-step")
                        .arg(path)
                        .arg(path.join("drive-pass"))
                        .output()
                        .unwrap()
                };
                let after = sealed_files(path);
                for (name, hash) in before {
                    assert_eq!(
                        after.get(&name),
                        Some(&hash),
                        "checkpoint ciphertext changed across actual process kill"
                    );
                }
                return result;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "owned setup CLI exceeded deadline"
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    child.wait_with_output().unwrap()
}
fn run_owned_services_flow(mode: OwnedFlow) {
    let mut services = hosted_services::HostedServices::start();
    if let Ok(relay) = std::env::var("LOKI_HOSTED_OFFLINE_RELAY") {
        let index: usize = relay.parse().unwrap();
        assert!((1..=3).contains(&index));
        services.stop_relay(index - 1);
    }
    for count in [3u16, 4] {
        if std::env::var("LOKI_HOSTED_MEMBERS")
            .ok()
            .is_some_and(|selected| selected != count.to_string())
        {
            continue;
        }
        if std::env::var_os("LOKI_HOSTED_RESUME_ROOT").is_some() {
            assert!(matches!(mode, OwnedFlow::Full));
            resume_owned_handoff(&mut services, count);
            continue;
        }
        let identity = Identity::new(1);
        let member = MemberDir::create(&services.root, &format!("creator-{count}")).unwrap();
        MemberDir::create(member.path(), "secrets")
            .unwrap()
            .write_sealed("identity.sealed", &identity.to_secret_bytes(), "pass")
            .unwrap();
        let operators =
            OperatorSet::verify_development(&services.bundle, &services.config_key).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let body = canonical::encode(&Value::Array(vec![
            Value::Integer(1.into()),
            Value::Bytes(vec![count as u8; 32]),
            Value::Bytes(identity.public().signing.to_vec()),
            Value::Integer((now + 3600).into()),
            Value::Integer(1.into()),
            Value::Integer(24.into()),
            Value::Bytes(operators.digest().to_vec()),
        ]))
        .unwrap();
        let signature = SigningKey::from_bytes(&[9; 32])
            .sign(&admission::signature_input(b"Loki_Setup_Enrollment_v1\0", &body).unwrap());
        let grant = canonical::encode(&Value::Array(vec![
            Value::Bytes(body),
            Value::Bytes(signature.to_bytes().to_vec()),
        ]))
        .unwrap();
        let mut setup = if matches!(mode, OwnedFlow::Full) {
            for (name, bytes) in [
                ("create-pass", b"pass".as_slice()),
                ("operators", services.bundle.as_slice()),
                ("enrollment", grant.as_slice()),
            ] {
                private_input(&member.path().join(name), bytes);
            }
            let output = std::process::Command::new(env!("CARGO_BIN_EXE_loki_setup_member"))
                .arg("setup-create")
                .arg(member.path())
                .arg(member.path().join("create-pass"))
                .arg(member.path().join("operators"))
                .arg(member.path().join("enrollment"))
                .arg(format!("2-of-{count}"))
                .arg("--operator-key")
                .arg(hex::encode(services.config_key))
                .arg("--development-http")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let public: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(public.as_object().unwrap().len(), 8);
            assert_eq!(public["handoff"], "pending");
            HostedSetup::open(member.path(), "pass").unwrap()
        } else {
            HostedSetup::create(
                member.path(),
                "pass",
                &services.bundle,
                &services.config_key,
                &grant,
                count,
                true,
            )
            .unwrap()
        };
        if matches!(mode, OwnedFlow::PendingAbort) {
            services.stop_admission();
            assert_eq!(
                setup.abort().unwrap().public_json()["phase"],
                "terminal_pending"
            );
            let saved = sealed_files(member.path());
            drop(setup);
            let mut setup = HostedSetup::open(member.path(), "pass").unwrap();
            assert_eq!(
                setup.step().unwrap().public_json()["phase"],
                "terminal_pending"
            );
            assert_eq!(sealed_files(member.path()), saved);
            services.restart_admission();
            assert_eq!(wait_phase(&mut setup, "aborted")["phase"], "aborted");
            assert!(!member.path().join("setup-relay-store").exists());
            assert!(!member.path().join("setup-ceremony").exists());
            assert!(setup.invitations().is_err());
            let terminal = sealed_files(member.path());
            drop(setup);
            let mut setup = HostedSetup::open(member.path(), "pass").unwrap();
            assert_eq!(setup.step().unwrap().public_json()["phase"], "aborted");
            assert_eq!(sealed_files(member.path()), terminal);
            continue;
        }
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let status = setup.step().unwrap();
            if status.public_json()["phase"] == "invites_ready" {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "creator provisioning did not finish"
            );
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let invites = setup.invitations().unwrap();
        assert_eq!(invites.len(), usize::from(count - 1));
        let invitation_path = member.path().join("member-2.invite");
        setup.export_invitation(2, &invitation_path).unwrap();
        assert_eq!(fs::read(&invitation_path).unwrap(), invites[&2].as_slice());
        setup.export_invitation(2, &invitation_path).unwrap();
        assert!(setup.export_invitation(1, &invitation_path).is_err());
        let saved = invites
            .iter()
            .map(|(slot, bytes)| (*slot, bytes.to_vec()))
            .collect::<BTreeMap<_, _>>();
        drop(setup);
        let reopened = HostedSetup::open(member.path(), "pass").unwrap();
        let restored = reopened.invitations().unwrap();
        assert_eq!(
            restored
                .iter()
                .map(|(slot, bytes)| (*slot, bytes.to_vec()))
                .collect::<BTreeMap<_, _>>(),
            saved
        );
        drop(reopened);
        let export_pass = member.path().join("export-pass");
        fs::write(&export_pass, "pass").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&export_pass, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let cli_invitation = member.path().join("cli-member-2.invite");
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_loki_setup_member"))
            .arg("setup-invite")
            .arg(member.path())
            .arg(&export_pass)
            .arg("2")
            .arg(&cli_invitation)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap(),
            serde_json::json!({"exported":true,"slot":2})
        );
        assert_eq!(fs::read(cli_invitation).unwrap(), saved[&2]);
        if matches!(mode, OwnedFlow::InviteExport) {
            continue;
        }
        for (slot, invitation) in &saved {
            let peer = MemberDir::create(&services.root, &format!("peer-{count}-{slot}")).unwrap();
            for (name, bytes) in [
                ("join-pass", b"peer-pass".as_slice()),
                ("invitation", invitation.as_slice()),
                ("operators", services.bundle.as_slice()),
            ] {
                private_input(&peer.path().join(name), bytes);
            }
            let output = std::process::Command::new(env!("CARGO_BIN_EXE_loki_setup_member"))
                .arg("setup-join")
                .arg(peer.path())
                .arg(peer.path().join("join-pass"))
                .arg(peer.path().join("invitation"))
                .arg(peer.path().join("operators"))
                .arg("--operator-key")
                .arg(hex::encode(services.config_key))
                .arg("--development-http")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let public: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(public.as_object().unwrap().len(), 8);
            assert_eq!(public["own_slot"], *slot);
            let mut joiner = HostedSetup::open(peer.path(), "peer-pass").unwrap();
            let limit = std::time::Instant::now() + std::time::Duration::from_secs(30);
            loop {
                let public = joiner.step().unwrap().public_json();
                assert_eq!(public["own_slot"], *slot);
                assert_eq!(public["policy"], format!("2-of-{count}"));
                if public["phase"] == "inbox_ready" {
                    break;
                }
                assert!(
                    std::time::Instant::now() < limit,
                    "independent joiner provisioning did not finish"
                );
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            if *slot == count {
                let mut creator = HostedSetup::open(member.path(), "pass").unwrap();
                let public = creator.step().unwrap().public_json();
                assert_eq!(public["phase"], "waiting_joins");
                assert_eq!(
                    public["joined_slots"].as_array().unwrap().len(),
                    usize::from(count - 1),
                    "admission claims alone must not complete delivered membership"
                );
            }
            let sealed = sealed_files(peer.path());
            drop(joiner);
            let mut joiner = HostedSetup::open(peer.path(), "peer-pass").unwrap();
            let limit = std::time::Instant::now() + std::time::Duration::from_secs(30);
            loop {
                let phase = joiner.step().unwrap().public_json()["phase"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                if phase == "join_published" {
                    break;
                }
                assert!(
                    std::time::Instant::now() < limit,
                    "saved Join did not reach two common relays"
                );
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            assert_eq!(sealed_files(peer.path()), sealed);
            drop(joiner);
            let saved_objects = saved_join_objects(
                peer.path(),
                "peer-pass",
                invitation,
                &services.bundle,
                &services.config_key,
                &identity,
            );
            assert_eq!(saved_objects.len(), 2);
            let mut joiner = HostedSetup::open(peer.path(), "peer-pass").unwrap();
            assert_eq!(
                joiner.step().unwrap().public_json()["phase"],
                "join_published"
            );
            drop(joiner);
            assert_eq!(
                saved_join_objects(
                    peer.path(),
                    "peer-pass",
                    invitation,
                    &services.bundle,
                    &services.config_key,
                    &identity
                ),
                saved_objects
            );
            if *slot == count {
                use loki_relay_client::{
                    CommIdentity, DescriptorRelay, Secret32, SetupInboxDescriptor, SetupInvite,
                };
                let original = SetupInvite::verify_development(
                    invitation,
                    &CommIdentity::from_serialized(&identity.to_secret_bytes())
                        .unwrap()
                        .public(),
                    &services.bundle,
                    &services.config_key,
                    now,
                )
                .unwrap();
                let impostor =
                    CommIdentity::from_serialized(&Identity::new(1).to_secret_bytes()).unwrap();
                let routes = original
                    .bootstrap_descriptor()
                    .unwrap()
                    .relays()
                    .iter()
                    .map(|r| DescriptorRelay {
                        route: r.route.clone(),
                        append: Secret32::from_bytes(*r.append.as_bytes()),
                    })
                    .collect();
                let descriptor = SetupInboxDescriptor::sign(
                    &impostor,
                    original.context().policy(),
                    &operators,
                    routes,
                )
                .unwrap();
                let forged = SetupInvite::create_with_bootstrap(
                    &impostor,
                    original.context().policy(),
                    *slot,
                    original.expires(),
                    *original.secret().as_bytes(),
                    &operators,
                    &descriptor,
                )
                .unwrap();
                let other =
                    MemberDir::create(&services.root, &format!("impostor-{count}-{slot}")).unwrap();
                let secrets = MemberDir::create(other.path(), "secrets").unwrap();
                fs::copy(
                    peer.path().join("secrets/identity.sealed"),
                    secrets.path().join("identity.sealed"),
                )
                .unwrap();
                let mut fake = HostedSetup::join(
                    other.path(),
                    "peer-pass",
                    &forged,
                    &services.bundle,
                    &services.config_key,
                    true,
                )
                .unwrap();
                assert!(
                    fake.step().is_err(),
                    "invitation creator must match the admission claim"
                );
            }
        }
        let mut reopened = HostedSetup::open(member.path(), "pass").unwrap();
        let public = reopened.step().unwrap().public_json();
        assert_eq!(public["phase"], "joins_received");
        assert_eq!(
            public["joined_slots"].as_array().unwrap().len(),
            usize::from(count)
        );
        assert!(public["missing_slots"].as_array().unwrap().is_empty());
        assert!(reopened.proposed_fingerprint().is_err());
        let limit = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            if reopened.step().unwrap().public_json()["phase"] == "roster_proposed" {
                break;
            }
            assert!(
                std::time::Instant::now() < limit,
                "roster proposal was not durably published"
            );
        }
        let fingerprint = reopened.proposed_fingerprint().unwrap();
        drop(reopened);
        for slot in 2..=count {
            let path = services.root.join(format!("peer-{count}-{slot}"));
            let mut peer = HostedSetup::open(&path, "peer-pass").unwrap();
            let limit = std::time::Instant::now() + std::time::Duration::from_secs(30);
            // A joiner must report the proposal from its own step, not only through
            // `setup-info`; the app refreshes the fingerprint on that phase change.
            loop {
                let public = peer.step().unwrap().public_json();
                if public["phase"] == "roster_proposed" {
                    assert_eq!(
                        public["joined_slots"],
                        serde_json::json!((1..=count).collect::<Vec<_>>())
                    );
                    break;
                }
                assert!(
                    matches!(public["phase"].as_str(), Some("join_published" | "join_pending")),
                    "unexpected joiner phase {public}"
                );
                assert!(
                    std::time::Instant::now() < limit,
                    "joiner step never reported the authenticated roster proposal"
                );
            }
            assert_eq!(peer.proposed_fingerprint().unwrap(), fingerprint);
            drop(peer);
            assert_eq!(
                HostedSetup::cached_status(&path).unwrap()["phase"],
                "roster_proposed"
            );
            let passfile = path.join("info-pass");
            private_input(&passfile, b"peer-pass");
            let info = loki_poc::setup_relay::command(
                "setup-info",
                &[path.display().to_string(), passfile.display().to_string()],
            )
            .unwrap();
            fs::remove_file(&passfile).unwrap();
            assert_eq!(info["fingerprint"], hex::encode(fingerprint));
        }
        let mut reopened = HostedSetup::open(member.path(), "pass").unwrap();
        let before_approval = sealed_files(member.path());
        assert!(!member.path().join("setup-ceremony").exists());
        assert!(reopened.agree([42; 32]).is_err());
        assert_eq!(sealed_files(member.path()), before_approval);
        let agreed = reopened.agree(fingerprint).unwrap().public_json();
        assert_eq!(agreed["phase"], "agreement_saved");
        assert_eq!(agreed["agreed_fingerprint"], hex::encode(fingerprint));
        let approved_files = sealed_files(member.path());
        assert!(approved_files.len() > before_approval.len());
        drop(reopened);
        let passfile = member.path().join("approval-pass");
        fs::write(&passfile, "pass").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&passfile, fs::Permissions::from_mode(0o600)).unwrap();
        }
        for command in ["setup-fingerprint", "setup-agree"] {
            let mut process = std::process::Command::new(env!("CARGO_BIN_EXE_loki_setup_member"));
            process.arg(command).arg(member.path()).arg(&passfile);
            if command == "setup-agree" {
                process.arg(hex::encode(fingerprint));
            }
            let output = process.output().unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let public: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(
                public[if command == "setup-fingerprint" {
                    "fingerprint"
                } else {
                    "agreed_fingerprint"
                }],
                hex::encode(fingerprint)
            );
            assert_eq!(sealed_files(member.path()), approved_files);
        }
        let mut reopened = HostedSetup::open(member.path(), "pass").unwrap();
        assert_eq!(
            reopened.step().unwrap().public_json()["agreed_fingerprint"],
            hex::encode(fingerprint)
        );
        assert_eq!(sealed_files(member.path()), approved_files);
        assert_eq!(
            reopened.agree(fingerprint).unwrap().public_json()["phase"],
            "agreement_saved"
        );
        assert_eq!(sealed_files(member.path()), approved_files);
        assert!(!reopened.roster_accepted().unwrap());
        drop(reopened);
        for slot in 2..=count {
            let path = services.root.join(format!("peer-{count}-{slot}"));
            let mut peer = HostedSetup::open(&path, "peer-pass").unwrap();
            assert!(!peer.roster_accepted().unwrap());
            peer.agree(fingerprint).unwrap();
            peer.step().unwrap();
            if slot != count {
                assert!(
                    !peer.roster_accepted().unwrap(),
                    "threshold approvals cannot replace all-member acceptance"
                );
                assert!(!path.join("setup-ceremony").exists());
                assert!(!member.path().join("setup-ceremony").exists());
            }
        }
        let limit = std::time::Instant::now() + std::time::Duration::from_secs(180);
        loop {
            let mut complete = true;
            for slot in 1..=count {
                let path = if slot == 1 {
                    member.path().to_owned()
                } else {
                    services.root.join(format!("peer-{count}-{slot}"))
                };
                let mut peer =
                    HostedSetup::open(&path, if slot == 1 { "pass" } else { "peer-pass" }).unwrap();
                if std::env::var_os("LOKI_HOSTED_KILL_PHASE").is_some() {
                    drop(peer);
                    let output =
                        drive_owned_cli(&path, if slot == 1 { "pass" } else { "peer-pass" });
                    assert!(
                        output.status.success(),
                        "{}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                    if slot == 1
                        && std::env::var("LOKI_HOSTED_KILL_PHASE").ok().as_deref() == Some("1")
                        && path.join("checkpoint-killed.json").exists()
                    {
                        let status: serde_json::Value =
                            serde_json::from_slice(&output.stdout).unwrap();
                        assert!(matches!(
                            status["phase"].as_str(),
                            Some("terminal_pending" | "aborted")
                        ));
                        return;
                    }
                    peer = HostedSetup::open(&path, if slot == 1 { "pass" } else { "peer-pass" })
                        .unwrap();
                } else {
                    peer.step().unwrap();
                }
                complete &= peer.roster_accepted().unwrap();
            }
            if complete {
                break;
            }
            assert!(
                std::time::Instant::now() < limit,
                "all-member acceptance did not complete through owned relays"
            );
        }
        if std::env::var_os("LOKI_HOSTED_KILL_PHASE").is_some() {
            let output = drive_owned_cli(member.path(), "pass");
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let public: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            if std::env::var("LOKI_HOSTED_KILL_PHASE").ok().as_deref() == Some("1") {
                assert!(member.path().join("checkpoint-killed.json").exists());
                assert!(matches!(
                    public["phase"].as_str(),
                    Some("terminal_pending" | "aborted")
                ));
                return;
            }
            assert_eq!(public["phase"], "round1_saved");
        } else {
            let mut reopened = HostedSetup::open(member.path(), "pass").unwrap();
            assert_eq!(
                reopened.step().unwrap().public_json()["phase"],
                "round1_saved"
            );
        }
        let limit = std::time::Instant::now() + std::time::Duration::from_secs(300);
        loop {
            let mut complete = true;
            for slot in 1..=count {
                let path = if slot == 1 {
                    member.path().to_owned()
                } else {
                    services.root.join(format!("peer-{count}-{slot}"))
                };
                let passfile = path.join("drive-pass");
                fs::write(&passfile, if slot == 1 { "pass" } else { "peer-pass" }).unwrap();
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&passfile, fs::Permissions::from_mode(0o600)).unwrap();
                }
                let output = drive_owned_cli(&path, if slot == 1 { "pass" } else { "peer-pass" });
                assert!(
                    output.status.success(),
                    "member {slot}: {}",
                    String::from_utf8_lossy(&output.stderr)
                );
                let public: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(public["handoff"], "pending");
                assert_eq!(public["agreed_fingerprint"], hex::encode(fingerprint));
                complete &= public["phase"] == "awaiting_backups";
            }
            if complete {
                break;
            }
            assert!(
                std::time::Instant::now() < limit,
                "native DKG/certificates did not complete for every member"
            );
        }
        let mut reopened = HostedSetup::open(member.path(), "pass").unwrap();
        let card = member.path().join("provisional-card");
        let mnemonic = reopened.backup_create(&card).unwrap();
        assert!(reopened.backup_verify(&card, "wrong words").is_err());
        reopened.backup_verify(&card, &mnemonic).unwrap();
        assert!(reopened
            .backup_finalize(&card, &member.path().join("final-card"), &mnemonic)
            .is_err());
        let waiting = reopened.step().unwrap().public_json();
        assert_eq!(waiting["phase"], "awaiting_backups");
        assert_eq!(
            waiting["missing_slots"],
            serde_json::json!((2..=count).collect::<Vec<_>>())
        );
        let mut backup_words = BTreeMap::new();
        backup_words.insert(1, mnemonic);
        drop(reopened);
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_loki_setup_member"))
            .arg("setup-backup-create")
            .arg(member.path())
            .arg(member.path().join("drive-pass"))
            .arg(&card)
            .output()
            .unwrap();
        assert!(output.status.success());
        let printed_words = zeroize::Zeroizing::new(String::from_utf8(output.stdout).unwrap());
        assert!(printed_words.trim() == backup_words[&1].as_str());
        let words_file = member.path().join("checked-words");
        fs::write(&words_file, backup_words[&1].as_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&words_file, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_loki_setup_member"))
            .arg("setup-backup-verify")
            .arg(member.path())
            .arg(member.path().join("drive-pass"))
            .arg(&card)
            .arg(&words_file)
            .output()
            .unwrap();
        assert!(output.status.success());
        let checked: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(checked["backup"], "checked");
        for slot in 2..=count {
            let path = services.root.join(format!("peer-{count}-{slot}"));
            let peer = HostedSetup::open(&path, "peer-pass").unwrap();
            let card = path.join("provisional-card");
            let words = peer.backup_create(&card).unwrap();
            peer.backup_verify(&card, &words).unwrap();
            backup_words.insert(slot, words);
        }
        let limit = std::time::Instant::now() + std::time::Duration::from_secs(300);
        loop {
            let mut complete = true;
            for slot in 1..=count {
                let path = if slot == 1 {
                    member.path().to_owned()
                } else {
                    services.root.join(format!("peer-{count}-{slot}"))
                };
                let mut peer =
                    HostedSetup::open(&path, if slot == 1 { "pass" } else { "peer-pass" }).unwrap();
                let public = if std::env::var_os("LOKI_HOSTED_KILL_PHASE").is_some() {
                    drop(peer);
                    let output =
                        drive_owned_cli(&path, if slot == 1 { "pass" } else { "peer-pass" });
                    assert!(
                        output.status.success(),
                        "{}",
                        String::from_utf8_lossy(&output.stderr)
                    );
                    serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()
                } else {
                    peer.step().unwrap().public_json()
                };
                complete &= matches!(
                    public["phase"].as_str(),
                    Some("certified" | "payment_handoff" | "active")
                );
            }
            if complete {
                break;
            }
            assert!(
                std::time::Instant::now() < limit,
                "all-member backup receipts did not become certified"
            );
        }
        let mut group = None;
        for slot in 1..=count {
            let path = if slot == 1 {
                member.path().to_owned()
            } else {
                services.root.join(format!("peer-{count}-{slot}"))
            };
            let provisional = path.join("provisional-card");
            let final_card = path.join("final-card");
            if slot == 1 {
                let output = std::process::Command::new(env!("CARGO_BIN_EXE_loki_setup_member"))
                    .arg("setup-backup-finalize")
                    .arg(&path)
                    .arg(path.join("drive-pass"))
                    .arg(&provisional)
                    .arg(&final_card)
                    .arg("-")
                    .output()
                    .unwrap();
                assert!(output.status.success());
                let checked: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
                assert_eq!(checked["final_card"], "checked");
            }
            let peer =
                HostedSetup::open(&path, if slot == 1 { "pass" } else { "peer-pass" }).unwrap();
            let words = &backup_words[&slot];
            if slot != 1 && std::env::var_os("LOKI_HOSTED_RUN_ROOT").is_some() {
                private_input(&path.join("checked-words"), words.as_bytes());
            }
            assert_eq!(
                peer.backup_finalize(&provisional, &final_card, words)
                    .unwrap()["final_card"],
                "checked"
            );
            assert!(!path.join("secrets/backup-words.sealed").exists());
            let final_bytes = fs::read(final_card.join("vault.card")).unwrap();
            peer.backup_finalize(&provisional, &final_card, words)
                .unwrap();
            assert!(fs::read(final_card.join("vault.card")).unwrap() == final_bytes);
            let raw = zeroize::Zeroizing::new(
                MemberDir::open(&path, "final-card")
                    .read_sealed("vault.card", words)
                    .unwrap(),
            );
            let evidence: serde_json::Value = serde_json::from_slice(&raw).unwrap();
            assert_eq!(evidence["recovery_version"], 2);
            assert_eq!(
                evidence["receipts"].as_object().unwrap().len(),
                count as usize
            );
            let public = (
                evidence["state"]["group_ak"].as_str().unwrap().to_owned(),
                evidence["state"]["address"].as_str().unwrap().to_owned(),
            );
            if let Some(expected) = &group {
                assert!(&public == expected);
            } else {
                group = Some(public);
            }
        }
        finish_owned_handoff(&mut services, count, &member, &backup_words, &group);
    }
}

fn finish_owned_handoff(
    services: &mut hosted_services::HostedServices,
    count: u16,
    member: &MemberDir,
    backup_words: &BTreeMap<u16, zeroize::Zeroizing<String>>,
    group: &Option<(String, String)>,
) {
    let card_bytes = zeroize::Zeroizing::new(
        MemberDir::open(member.path(), "final-card")
            .read_sealed("vault.card", &backup_words[&1])
            .unwrap(),
    );
    let card_value: serde_json::Value = serde_json::from_slice(&card_bytes).unwrap();
    let certified_roster = loki_poc::member_state::Roster::from_bytes(
        &serde_json::to_vec(&card_value["roster"]).unwrap(),
    )
    .unwrap();
    let limit = std::time::Instant::now() + std::time::Duration::from_secs(600);
    loop {
        let mut complete = true;
        for slot in 1..=count {
            let path = if slot == 1 {
                member.path().to_owned()
            } else {
                services.root.join(format!("peer-{count}-{slot}"))
            };
            let pass = if slot == 1 { "pass" } else { "peer-pass" };
            if slot == 1 && std::env::var_os("LOKI_HOSTED_KILL_PHASE").is_some() {
                let output = drive_owned_cli(&path, pass);
                assert!(
                    output.status.success(),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            let status = loki_poc::setup_relay::install_payment_configuration(&path, pass).unwrap();
            complete &= status.is_ready();
            let mut setup = HostedSetup::open(&path, pass).unwrap();
            let public = setup.step().unwrap().public_json();
            drop(setup);
            if status.is_ready() {
                assert_eq!(public["handoff"], "ready");
                assert_eq!(public["phase"], "active");
                assert!(path.join("secrets/activation.sealed").is_file());
                let address = std::process::Command::new(env!("CARGO_BIN_EXE_loki_setup_member"))
                    .arg("address")
                    .arg(&path)
                    .arg(path.join("drive-pass"))
                    .output()
                    .unwrap();
                assert!(address.status.success());
                assert_eq!(
                    String::from_utf8(address.stdout).unwrap().trim(),
                    group.as_ref().unwrap().1
                );
            }
            let roster = loki_relay_protocol::types::Roster {
                vault: certified_roster.vault,
                members: certified_roster
                    .members
                    .values()
                    .map(|peer| loki_relay_protocol::types::MemberPublic {
                        id: peer.id,
                        signing: peer.signing,
                        encryption: peer.encryption,
                    })
                    .collect(),
            };
            let raw = zeroize::Zeroizing::new(
                MemberDir::open(&path, "secrets")
                    .read_sealed("identity.sealed", pass)
                    .unwrap(),
            );
            let identity = loki_relay_client::CommIdentity::from_serialized(
                raw.as_slice().try_into().unwrap(),
            )
            .unwrap();
            let loaded = loki_poc::relay_member::LoadedMember { identity, roster };
            let db =
                loki_relay_client::ClientStore::open(&path.join("transport"), &loaded.roster, slot)
                    .unwrap();
            let store =
                loki_poc::relay_member::ConfigStore::open_with_passphrase(&path, pass).unwrap();
            let config = store.load(&db, &loaded).unwrap();
            complete &= config.is_some();
            if let Some(config) = config {
                let reference = db.config_reference().unwrap().unwrap();
                assert_eq!(
                    config.authenticated(&loaded).unwrap().peers.len(),
                    usize::from(count - 1)
                );
                assert_eq!(config.couriers.len(), usize::from(count - 1));
                let ciphertext = fs::read(path.join(reference.file_name())).unwrap();
                drop(db);
                loki_poc::setup_relay::install_payment_configuration(&path, pass).unwrap();
                assert!(fs::read(path.join(reference.file_name())).unwrap() == ciphertext);
            }
        }
        if complete {
            break;
        }
        assert!(
            std::time::Instant::now() < limit,
            "automatic scoped payment handoff did not activate for every member"
        );
    }
    if std::env::var_os("LOKI_HOSTED_RUN_ROOT").is_some() {
        let public = serde_json::json!({"policy":format!("2-of-{count}"),"vault":hex::encode(certified_roster.vault),"address":group.as_ref().unwrap().1,"group_ak":group.as_ref().unwrap().0,"ready_members":(1..=count).collect::<Vec<_>>(),"configuration_sha256":hex::encode(Sha256::digest(&services.bundle)),"config_key":hex::encode(services.config_key),"native_binary_sha256":hex::encode(Sha256::digest(fs::read(env!("CARGO_BIN_EXE_loki_setup_member")).unwrap())),"separate_host_https":false,"process_kill":fs::read_dir(member.path()).unwrap().filter_map(Result::ok).any(|entry|entry.file_name().to_string_lossy().starts_with("checkpoint-killed"))});
        private_input(
            &services.root.join("handoff-evidence.json"),
            &serde_json::to_vec(&public).unwrap(),
        );
    }
    let mut reopened = HostedSetup::open(member.path(), "pass").unwrap();
    services.stop_admission();
    for &slot in backup_words.keys() {
        let original = if slot == 1 {
            member.path().to_owned()
        } else {
            services.root.join(format!("peer-{count}-{slot}"))
        };
        let inputs =
            MemberDir::create(&services.root, &format!("restore-inputs-{count}-{slot}")).unwrap();
        let passfile = inputs.path().join("pass");
        let wordsfile = inputs.path().join("words");
        fs::write(&passfile, "restored-pass").unwrap();
        fs::write(&wordsfile, backup_words[&slot].as_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for path in [&passfile, &wordsfile] {
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        let restored = services.root.join(format!("restored-{count}-{slot}"));
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_loki_setup_member"))
            .arg("restore")
            .arg(&restored)
            .arg(&passfile)
            .arg(original.join("final-card"))
            .arg(&wordsfile)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "member {slot} restore: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::str::from_utf8(&output.stdout).unwrap().trim(),
            group.as_ref().unwrap().1
        );
    }
    let native_generations = || {
        fs::read_dir(member.path().join("setup-ceremony"))
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "sealed"))
            .count()
    };
    let before_abort = native_generations();
    let activated_files = sealed_files(member.path());
    assert!(
        reopened.abort().is_err(),
        "an activated vault cannot be retired as unfinished setup"
    );
    assert_eq!(native_generations(), before_abort);
    assert_eq!(sealed_files(member.path()), activated_files);
    drop(reopened);
    services.restart_admission();
    let mut reopened = HostedSetup::open(member.path(), "pass").unwrap();
    assert_eq!(reopened.step().unwrap().public_json()["handoff"], "ready");
    assert_eq!(sealed_files(member.path()), activated_files);
}
fn resume_owned_handoff(services: &mut hosted_services::HostedServices, count: u16) {
    let member = MemberDir::open(&services.root, &format!("creator-{count}"));
    let words =
        zeroize::Zeroizing::new(fs::read_to_string(member.path().join("checked-words")).unwrap());
    let raw = zeroize::Zeroizing::new(
        MemberDir::open(member.path(), "final-card")
            .read_sealed("vault.card", &words)
            .unwrap(),
    );
    let card: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    assert_eq!(card["recovery_version"], 2);
    assert_eq!(card["receipts"].as_object().unwrap().len(), count as usize);
    let group = Some((
        card["state"]["group_ak"].as_str().unwrap().to_owned(),
        card["state"]["address"].as_str().unwrap().to_owned(),
    ));
    let mut backup_words = BTreeMap::from([(1, words)]);
    for slot in 2..=count {
        let checked = services
            .root
            .join(format!("peer-{count}-{slot}/checked-words"));
        if checked.is_file() {
            let words = zeroize::Zeroizing::new(fs::read_to_string(checked).unwrap());
            backup_words.insert(slot, words);
        }
    }
    let saved_files: Vec<_> = (1..=count)
        .map(|slot| {
            let path = if slot == 1 {
                member.path().to_owned()
            } else {
                services.root.join(format!("peer-{count}-{slot}"))
            };
            (path.clone(), sealed_files(&path))
        })
        .collect();
    finish_owned_handoff(services, count, &member, &backup_words, &group);
    for (path, before) in saved_files {
        let after = sealed_files(&path);
        for (name, hash) in before {
            assert_eq!(
                after.get(&name),
                Some(&hash),
                "saved checkpoint changed during handoff recovery"
            );
        }
    }
}

#[test]
fn offline_join_cli_saves_a_fresh_identity_and_exact_claim_for_both_policies() {
    use loki_relay_client::{
        CommIdentity, DescriptorRelay, Secret32, SetupInboxDescriptor, SetupInvite, SetupPolicy,
    };
    for count in [3u16, 4] {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        drop(listener);
        let (bundle, key) = operator_bundle(&origin);
        let op = OperatorSet::verify_development(&bundle, &key).unwrap();
        let creator = CommIdentity::from_serialized(&Identity::new(1).to_secret_bytes()).unwrap();
        let policy = SetupPolicy {
            ceremony: [count as u8; 32],
            network: "regtest".into(),
            threshold: 2,
            member_count: count,
            config_digest: *op.digest(),
        };
        let routes = op
            .relay_routes()
            .iter()
            .enumerate()
            .map(|(i, route)| {
                let mut route = route.clone();
                route.mailbox = [i as u8 + 40; 32];
                route.append_revision = 1;
                DescriptorRelay {
                    route,
                    append: Secret32::from_bytes([i as u8 + 50; 32]),
                }
            })
            .collect();
        let descriptor = SetupInboxDescriptor::sign(&creator, &policy, &op, routes).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let invitation = SetupInvite::create_with_bootstrap(
            &creator,
            &policy,
            count,
            now + 3600,
            [count as u8 + 60; 32],
            &op,
            &descriptor,
        )
        .unwrap();
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "loki-hosted-join-{}",
            hex::encode(creator.public().signing)
        ));
        let member = MemberDir::create(&root, "member").unwrap();
        for (name, bytes) in [
            ("pass", b"peer-pass".as_slice()),
            ("bundle", bundle.as_slice()),
            ("invite", invitation.as_slice()),
        ] {
            let path = root.join(name);
            fs::write(&path, bytes).unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        let invoke = || {
            std::process::Command::new(env!("CARGO_BIN_EXE_loki_setup_member"))
                .arg("setup-join")
                .arg(member.path())
                .arg(root.join("pass"))
                .arg(root.join("invite"))
                .arg(root.join("bundle"))
                .arg("--operator-key")
                .arg(hex::encode(key))
                .arg("--development-http")
                .output()
                .unwrap()
        };
        let output = invoke();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let public: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(public["phase"], "admission_pending");
        assert_eq!(public["own_slot"], count);
        assert!(!String::from_utf8_lossy(&output.stdout).contains(&hex::encode(&invitation)));
        let sealed = sealed_files(member.path());
        assert!(member.path().join("secrets/identity.sealed").exists());
        let output = invoke();
        assert!(output.status.success());
        assert_eq!(sealed_files(member.path()), sealed);
        let mut reopened = HostedSetup::open(member.path(), "peer-pass").unwrap();
        assert_eq!(reopened.step().unwrap().public_json()["own_slot"], count);
        drop(reopened);
        assert_eq!(sealed_files(member.path()), sealed);
        fs::remove_dir_all(root).unwrap();
    }
}

fn saved_join_objects(
    root: &Path,
    passphrase: &str,
    invitation: &[u8],
    bundle: &[u8],
    key: &[u8; 32],
    creator: &Identity,
) -> Vec<([u8; 32], Vec<u8>)> {
    use loki_relay_client::{
        CommIdentity, SetupAuthority, SetupInboxDescriptor, SetupInvite, SetupStore, SetupTransport,
    };
    use loki_relay_protocol::setup::{SetupKey, SetupPhase};
    let secret = zeroize::Zeroizing::new(
        MemberDir::open(root, "secrets")
            .read_sealed("identity.sealed", passphrase)
            .unwrap(),
    );
    let own = CommIdentity::from_serialized(secret.as_slice().try_into().unwrap()).unwrap();
    let creator = CommIdentity::from_serialized(&creator.to_secret_bytes()).unwrap();
    let op = OperatorSet::verify_development(bundle, key).unwrap();
    let invite =
        SetupInvite::verify_development(invitation, &creator.public(), bundle, key, 0).unwrap();
    let peers = vec![creator.public(), own.public()];
    let transport = SetupTransport::new(
        &own,
        &op,
        SetupAuthority::Bootstrap(invite.context(), &peers),
        true,
    )
    .unwrap();
    let store = SetupStore::open(&root.join("setup-relay-store"), &transport).unwrap();
    let record = store
        .receive(
            &transport,
            &SetupKey {
                ceremony: invite.context().policy().ceremony,
                phase: SetupPhase::Join,
                author: own.public().id,
                recipient: own.public().id,
                revision: 1,
            },
        )
        .unwrap()
        .unwrap();
    let Value::Array(payload) = canonical::decode(&record.body().payload, 4096).unwrap() else {
        panic!()
    };
    assert_eq!(payload.len(), 4);
    assert_eq!(payload[0], Value::Integer(1.into()));
    assert_eq!(payload[1], Value::Array(vec![Value::Integer(1.into())]));
    assert_eq!(
        payload[2],
        Value::Array(vec![Value::Integer(3.into()), Value::Integer(4.into())])
    );
    let Value::Bytes(package) = &payload[3] else {
        panic!()
    };
    let descriptor =
        SetupInboxDescriptor::verify(package, invite.context().policy(), &op, &own.public())
            .unwrap();
    assert_eq!(descriptor.owner(), own.public().id);
    let database = fs::read(root.join("setup-relay-store/setup.sqlite3")).unwrap();
    for relay in descriptor.relays() {
        assert!(!database.windows(32).any(|w| w == relay.append.as_bytes()));
    }
    store.saved_objects().unwrap()
}

#[test]
fn cached_backup_status_reports_missing_receipts_after_every_member_joins() {
    let identity = Identity::new(1);
    let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "loki-phase-status-{}",
        hex::encode(identity.public().signing)
    ));
    let member = MemberDir::create(&root, "member").unwrap();
    let status = serde_json::json!({"phase":"awaiting_backups","policy":"2-of-4","own_slot":1,
        "joined_slots":[1,2,3,4],"missing_slots":[4],"agreed_fingerprint":hex::encode([1;32]),
        "retryable":true,"handoff":"pending"});
    let path = member.path().join("setup-status.json");
    fs::write(&path, serde_json::to_vec(&status).unwrap()).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    assert!(HostedSetup::cached_status(member.path()).unwrap() == status);
    fs::remove_dir_all(root).unwrap();
}
