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
    let mut completed = Vec::new();
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
        completed.push(out.stdout);
    }
    assert!(
        completed.iter().all(Vec::is_empty),
        "setup exposed an address before backup"
    );
    let first = root.join("member-1");
    let early = Command::new(exe)
        .args([
            "address",
            first.to_str().unwrap(),
            first.join("pass.txt").to_str().unwrap(),
            roster.to_str().unwrap(),
            exchange.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !early.status.success(),
        "address appeared before members checked backups"
    );
    let cached_early = Command::new(exe)
        .args([
            "address",
            first.to_str().unwrap(),
            first.join("pass.txt").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !cached_early.status.success(),
        "address appeared before activation"
    );
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
        assert_eq!(state["version"], 2);
        assert_eq!(state["network"], "regtest");
        assert_eq!(state["key_derivation"], "zip2005-use-qsk-2026.8.0");
        let address = state["address"].as_str().unwrap();
        let ak: [u8; 32] = hex::decode(state["group_ak"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let sk: [u8; 32] = hex::decode(state["vault_secret"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let fvk = loki_poc::zip2005::frost_viewing_key(&ak, &sk).unwrap();
        assert_eq!(loki_poc::vault::regtest_unified_address(&fvk), address);
        shares.push(state["key_package"].as_str().unwrap().to_string());
        vault_secrets.push(state["vault_secret"].as_str().unwrap().to_string());
    }
    assert_ne!(shares[0], shares[1]);
    assert_ne!(shares[1], shares[2]);
    assert!(vault_secrets.windows(2).all(|pair| pair[0] == pair[1]));
    let mut addresses = Vec::new();
    for id in 1..=3 {
        let member = root.join(format!("member-{id}"));
        let card = root.join(format!("card-{id}"));
        let pass = member.join("pass.txt");
        let created = Command::new(exe)
            .args([
                "backup-create",
                member.to_str().unwrap(),
                pass.to_str().unwrap(),
                card.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            created.status.success(),
            "backup create: {}",
            String::from_utf8_lossy(&created.stderr)
        );
        let words = String::from_utf8(created.stdout).unwrap();
        assert_eq!(words.split_whitespace().count(), 24);
        let words_file = member.join("words.txt");
        fs::write(&words_file, words).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&words_file, fs::Permissions::from_mode(0o600)).unwrap();
        }
        if id == 1 {
            let wrong = member.join("wrong-words.txt");
            fs::write(
                &wrong,
                format!("{}\n", bip39::Mnemonic::from_entropy(&[0u8; 32]).unwrap()),
            )
            .unwrap();
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&wrong, fs::Permissions::from_mode(0o600)).unwrap();
            }
            let refused = Command::new(exe)
                .args([
                    "backup-verify",
                    member.to_str().unwrap(),
                    pass.to_str().unwrap(),
                    card.to_str().unwrap(),
                    wrong.to_str().unwrap(),
                    roster.to_str().unwrap(),
                    exchange.to_str().unwrap(),
                ])
                .output()
                .unwrap();
            assert!(!refused.status.success(), "wrong words checked a backup");
        }
        let checked = Command::new(exe)
            .args([
                "backup-verify",
                member.to_str().unwrap(),
                pass.to_str().unwrap(),
                card.to_str().unwrap(),
                words_file.to_str().unwrap(),
                roster.to_str().unwrap(),
                exchange.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            checked.status.success(),
            "backup verify: {}",
            String::from_utf8_lossy(&checked.stderr)
        );
        if id < 3 {
            let pending = Command::new(exe)
                .args([
                    "address",
                    first.to_str().unwrap(),
                    first.join("pass.txt").to_str().unwrap(),
                    roster.to_str().unwrap(),
                    exchange.to_str().unwrap(),
                ])
                .output()
                .unwrap();
            assert!(
                !pending.status.success(),
                "address before every member's backup"
            );
        }
        let restore = root.join(format!("restored-{id}"));
        fs::create_dir(&restore).unwrap();
        let new_pass = restore.join("pass.txt");
        fs::write(&new_pass, "new passphrase\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&new_pass, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let recovered = Command::new(exe)
            .args([
                "restore",
                restore.to_str().unwrap(),
                new_pass.to_str().unwrap(),
                card.to_str().unwrap(),
                words_file.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            recovered.status.success(),
            "restore: {}",
            String::from_utf8_lossy(&recovered.stderr)
        );
        let original = MemberDir::open(&member, "secrets")
            .read_sealed("vault.sealed", "test passphrase for DKG setup")
            .unwrap();
        let restored = MemberDir::open(&restore, "secrets")
            .read_sealed("vault.sealed", "new passphrase")
            .unwrap();
        assert_eq!(original, restored);
        addresses.push(String::from_utf8(recovered.stdout).unwrap());
    }
    assert!(addresses.windows(2).all(|pair| pair[0] == pair[1]));
    let recovered_address = Command::new(exe)
        .args([
            "address",
            first.to_str().unwrap(),
            first.join("pass.txt").to_str().unwrap(),
            roster.to_str().unwrap(),
            exchange.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(recovered_address.status.success());
    assert_eq!(recovered_address.stdout, addresses[0].as_bytes());
    let bad_member = root.join("bad-member");
    let mut bad_state: serde_json::Value = serde_json::from_slice(
        &MemberDir::open(&first, "secrets")
            .read_sealed("vault.sealed", "test passphrase for DKG setup")
            .unwrap(),
    )
    .unwrap();
    bad_state["address"] = serde_json::Value::String("wrong".into());
    MemberDir::create(&bad_member, "secrets")
        .unwrap()
        .write_sealed(
            "vault.sealed",
            &serde_json::to_vec(&bad_state).unwrap(),
            "test passphrase for DKG setup",
        )
        .unwrap();
    let bad_address = Command::new(exe)
        .args([
            "address",
            bad_member.to_str().unwrap(),
            first.join("pass.txt").to_str().unwrap(),
            roster.to_str().unwrap(),
            exchange.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!bad_address.status.success());
    assert!(String::from_utf8_lossy(&bad_address.stderr).contains("stored address differs"));
    let backup_receipt = exchange.join(format!("{}-backup-3.bin", hex::encode([7u8; 32])));
    let original_receipt = fs::read(&backup_receipt).unwrap();
    let mut broken = original_receipt.clone();
    *broken.last_mut().unwrap() ^= 1;
    fs::write(&backup_receipt, broken).unwrap();
    let denied = Command::new(exe)
        .args([
            "address",
            first.to_str().unwrap(),
            first.join("pass.txt").to_str().unwrap(),
            roster.to_str().unwrap(),
            exchange.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !denied.status.success(),
        "forged backup receipt exposed the address"
    );
    fs::write(&backup_receipt, original_receipt).unwrap();
    fs::remove_dir_all(&exchange).unwrap();
    let cached_address = Command::new(exe)
        .args([
            "address",
            first.to_str().unwrap(),
            first.join("pass.txt").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        cached_address.status.success(),
        "activated address needs no exchange"
    );
    assert_eq!(cached_address.stdout, addresses[0].as_bytes());
    let offline = root.join("offline-restore");
    fs::create_dir(&offline).unwrap();
    let offline_pass = offline.join("pass.txt");
    fs::write(&offline_pass, "offline passphrase\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&offline_pass, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let offline_restored = Command::new(exe)
        .args([
            "restore",
            offline.to_str().unwrap(),
            offline_pass.to_str().unwrap(),
            root.join("card-1").to_str().unwrap(),
            first.join("words.txt").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        offline_restored.status.success(),
        "offline restore: {}",
        String::from_utf8_lossy(&offline_restored.stderr)
    );
    assert_eq!(offline_restored.stdout, addresses[0].as_bytes());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn address_refuses_legacy_state() {
    let exe = env!("CARGO_BIN_EXE_loki_setup_member");
    let root = std::env::temp_dir().join(format!("loki-bad-address-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    let pass = root.join("pass.txt");
    fs::write(&pass, "test passphrase\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&pass, fs::Permissions::from_mode(0o600)).unwrap();
    }
    MemberDir::create(&root, "secrets")
        .unwrap()
        .write_sealed(
            "vault.sealed",
            br#"{"version":1,"network":"regtest"}"#,
            "test passphrase",
        )
        .unwrap();
    let out = Command::new(exe)
        .args([
            "address",
            root.to_str().unwrap(),
            pass.to_str().unwrap(),
            root.to_str().unwrap(),
            root.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("unsupported vault state version"));
    fs::remove_dir_all(root).unwrap();
}
