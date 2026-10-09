use loki_poc::state::MemberDir;
use std::{
    fs,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

#[test]
fn simultaneous_identity_creation_keeps_only_one_identity() {
    let exe = env!("CARGO_BIN_EXE_loki_setup_member");
    let root = std::env::temp_dir().join(format!(
        "loki-identity-race-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let pass = root.join("pass.txt");
    fs::write(&pass, "test passphrase\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&pass, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut children = (0..2)
        .map(|_| {
            Command::new(exe)
                .args([
                    "identity",
                    root.to_str().unwrap(),
                    "1",
                    pass.to_str().unwrap(),
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap()
        })
        .collect::<Vec<_>>();
    let outputs = children
        .drain(..)
        .map(|child| child.wait_with_output().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(outputs.iter().filter(|out| out.status.success()).count(), 1);
    let winner = outputs.iter().find(|out| out.status.success()).unwrap();
    let public: serde_json::Value = serde_json::from_slice(&winner.stdout).unwrap();
    let stored = MemberDir::open(&root, "secrets")
        .read_sealed("identity.sealed", "test passphrase")
        .unwrap();
    let actual = loki_poc::setup_transport::Identity::from_secret_bytes(&stored)
        .unwrap()
        .public();
    assert_eq!(public["signing"], hex::encode(actual.signing));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn three_processes_create_one_vault_without_sharing_secrets() {
    let exe = env!("CARGO_BIN_EXE_loki_setup_member");
    let root = std::env::temp_dir().join(format!(
        "loki-setup-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let exchange = root.join("exchange");
    fs::create_dir(&exchange).unwrap();

    let mut public = Vec::new();
    for id in 1..=3 {
        let member = root.join(format!("member-{id}"));
        fs::create_dir(&member).unwrap();
        let pass = member.join("pass.txt");
        fs::write(&pass, "test passphrase for DKG setup\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&pass, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let out = Command::new(exe)
            .args([
                "identity",
                member.to_str().unwrap(),
                &id.to_string(),
                pass.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "identity: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        public.push(serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap());
    }

    let roster = root.join("roster.json");
    fs::write(
        &roster,
        serde_json::to_vec(&serde_json::json!({
            "vault": hex::encode([7u8; 32]), "members": public
        }))
        .unwrap(),
    )
    .unwrap();
    let out = Command::new(exe)
        .args(["fingerprint", roster.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "fingerprint: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let fingerprint = String::from_utf8(out.stdout).unwrap().trim().to_string();

    let first = root.join("member-1");
    let refused = Command::new(exe)
        .args([
            "run",
            first.to_str().unwrap(),
            first.join("pass.txt").to_str().unwrap(),
            roster.to_str().unwrap(),
            exchange.to_str().unwrap(),
            &hex::encode([0u8; 32]),
        ])
        .output()
        .unwrap();
    assert!(!refused.status.success());
    assert_eq!(fs::read_dir(&exchange).unwrap().count(), 0);

    let mut children = Vec::new();
    for id in 1..=3 {
        let member = root.join(format!("member-{id}"));
        children.push(
            Command::new(exe)
                .args([
                    "run",
                    member.to_str().unwrap(),
                    member.join("pass.txt").to_str().unwrap(),
                    roster.to_str().unwrap(),
                    exchange.to_str().unwrap(),
                    &fingerprint,
                ])
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap(),
        );
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut addresses = Vec::new();
    for mut child in children {
        while child.try_wait().unwrap().is_none() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
        }
        let out = child.wait_with_output().unwrap();
        assert!(
            out.status.success(),
            "setup: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        addresses.push(String::from_utf8(out.stdout).unwrap());
    }
    assert!(addresses.windows(2).all(|pair| pair[0] == pair[1]));
    let mut shares = Vec::new();
    let mut vault_secrets = Vec::new();
    for id in 1..=3 {
        let secrets = root.join(format!("member-{id}/secrets"));
        assert!(secrets.join("vault.sealed").exists());
        assert!(!secrets.join("key_package.hex").exists());
        let store = MemberDir::open(&root.join(format!("member-{id}")), "secrets");
        let state: serde_json::Value = serde_json::from_slice(
            &store
                .read_sealed("vault.sealed", "test passphrase for DKG setup")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(state["version"], 1);
        assert_eq!(state["network"], "regtest");
        assert_eq!(state["address"], addresses[0].trim());
        shares.push(state["key_package"].as_str().unwrap().to_string());
        vault_secrets.push(state["vault_secret"].as_str().unwrap().to_string());
    }
    assert_ne!(shares[0], shares[1]);
    assert_ne!(shares[1], shares[2]);
    assert!(vault_secrets.windows(2).all(|pair| pair[0] == pair[1]));
    let first = root.join("member-1");
    let recovered_address = Command::new(exe)
        .args([
            "address",
            first.to_str().unwrap(),
            first.join("pass.txt").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(recovered_address.status.success());
    assert_eq!(recovered_address.stdout, addresses[0].as_bytes());
    fs::remove_dir_all(root).unwrap();
}
