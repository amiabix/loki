use loki_poc::state::MemberDir;
use std::{
    collections::BTreeMap,
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
    let mut public_packages = Vec::new();
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
        public_packages.push(state["public_package"].as_str().unwrap().to_string());
        vault_secrets.push(state["vault_secret"].as_str().unwrap().to_string());
    }
    assert_ne!(shares[0], shares[1]);
    assert_ne!(shares[1], shares[2]);
    assert!(public_packages.windows(2).all(|pair| pair[0] == pair[1]));
    assert!(vault_secrets.windows(2).all(|pair| pair[0] == pair[1]));
    {
        use loki_poc::{
            candidate::{
                alpha_from_canonical_bytes, build_candidate, quote_fee, CandidateInputs, Regtest,
            },
            intent::{alpha_for_candidate, alpha_seed, ChangePolicy, Intent},
            verify::{check_candidate, Expectations, Refusal},
            zip2005,
        };
        use orchard::{
            keys::Scope,
            note::{RandomSeed, Rho},
            value::NoteValue,
            Note, NoteVersion,
        };
        use pczt::roles::{
            creator::Creator,
            io_finalizer::IoFinalizer,
            signer::Signer,
            verifier::{OrchardError, Verifier},
        };
        use reddsa_frost::frost::redpallas as frost;
        use zcash_protocol::{memo::MemoBytes, value::Zatoshis};

        let public =
            frost::keys::PublicKeyPackage::deserialize(&hex::decode(&public_packages[0]).unwrap())
                .unwrap();
        let ak: [u8; 32] = public
            .verifying_key()
            .serialize()
            .unwrap()
            .try_into()
            .unwrap();
        let sk: [u8; 32] = hex::decode(&vault_secrets[0]).unwrap().try_into().unwrap();
        let fvk = zip2005::frost_viewing_key(&ak, &sk).unwrap();
        let keys: Vec<_> = shares[..2]
            .iter()
            .map(|s| frost::keys::KeyPackage::deserialize(&hex::decode(s).unwrap()).unwrap())
            .collect();
        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        for key in &keys {
            let (nonce, commitment) =
                frost::round1::commit(key.signing_share(), &mut rand_core::OsRng);
            nonces.insert(*key.identifier(), nonce);
            commitments.insert(*key.identifier(), commitment);
        }

        let rho = Rho::from_bytes(&[1u8; 32]).unwrap();
        let rseed = RandomSeed::from_bytes([2u8; 32], &rho).unwrap();
        let note = Note::from_parts(
            fvk.address_at(0u64, Scope::External),
            NoteValue::from_raw(625_000_000),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .unwrap();
        let recipient = fvk.address_at(7u64, Scope::External);
        let memo = b"separate-member transaction".to_vec();
        let amount_zat = 40_000_000;
        let mut inputs = CandidateInputs {
            vault_fvk: &fvk,
            notes: vec![note],
            recipient,
            amount: Zatoshis::const_from_u64(amount_zat),
            memo: MemoBytes::from_bytes(&memo).unwrap(),
            change: Zatoshis::ZERO,
            target_height: 700,
            expiry_height: 1_152,
        };
        let fee_zat = u64::from(quote_fee(&Regtest, &inputs).unwrap());
        let change_zat = 625_000_000 - amount_zat - fee_zat;
        inputs.change = Zatoshis::const_from_u64(change_zat);
        let intent = Intent {
            proposer: keys[0].identifier().serialize(),
            created_height: 700,
            input_nullifiers: vec![note.nullifier(&fvk).to_bytes()],
            recipient: recipient.to_raw_address_bytes().to_vec(),
            amount_zat,
            memo: memo.clone(),
            change_policy: ChangePolicy::VaultInternal,
            fee_zat,
            change_zat,
            expiry_height: 1_152,
        };
        let seed = alpha_seed(
            &intent.proposal_id(),
            (keys[0].identifier(), keys[1].identifier()),
            0,
        );
        let alpha = alpha_for_candidate(&seed, &commitments).unwrap();
        let alpha_bytes: [u8; 32] = alpha.serialize().try_into().unwrap();
        let built = build_candidate(
            &Regtest,
            &inputs,
            &[alpha_from_canonical_bytes(&alpha_bytes).unwrap()],
            rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng),
        )
        .unwrap();
        let pczt = Creator::build_from_parts(built.pczt_parts).unwrap();
        let pczt = IoFinalizer::new(pczt)
            .finalize_io(rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng))
            .unwrap();
        let candidate_bytes = pczt.serialize().unwrap();
        let pczt = pczt::Pczt::parse(&candidate_bytes).unwrap();
        let want = Expectations {
            input_nullifiers: intent.input_nullifiers,
            recipient: recipient.to_raw_address_bytes(),
            amount_zat,
            memo,
            change_zat,
            fee_zat,
            expiry_height: 1_152,
        };
        let checked = Verifier::new(pczt)
            .with_ironwood::<Refusal, _>(|bundle| {
                check_candidate(bundle, &fvk, &want).map_err(OrchardError::Custom)
            })
            .unwrap()
            .finish();
        let sighash = Signer::new(checked.clone()).unwrap().shielded_sighash();
        let package = frost::SigningPackage::new(commitments, &sighash);
        let mut signature_shares = BTreeMap::new();
        for key in &keys {
            #[allow(deprecated)] // The transaction fixes alpha before its sighash exists.
            let share =
                frost_rerandomized::sign(&package, &nonces[key.identifier()], key, alpha).unwrap();
            signature_shares.insert(*key.identifier(), share);
        }
        let params =
            frost_rerandomized::RandomizedParams::from_randomizer(public.verifying_key(), alpha);
        let signature =
            frost_rerandomized::aggregate(&package, &signature_shares, &public, &params).unwrap();
        params
            .randomized_verifying_key()
            .verify(&sighash, &signature)
            .unwrap();
        let real = checked
            .ironwood()
            .actions()
            .iter()
            .find(|action| *action.spend().nullifier() == note.nullifier(&fvk).to_bytes())
            .unwrap();
        assert_eq!(
            params.randomized_verifying_key().serialize().unwrap(),
            real.spend().rk().to_vec(),
        );
    }
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
