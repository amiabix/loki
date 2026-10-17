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
    assert!(loki_poc::member_state::open(&first, &first.join("pass.txt"), &roster).is_err());
    let unactivated_payment = Command::new(env!("CARGO_BIN_EXE_loki_member_payment"))
        .args([
            "sign",
            first.to_str().unwrap(),
            first.join("pass.txt").to_str().unwrap(),
            roster.to_str().unwrap(),
            root.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!unactivated_payment.status.success());
    assert!(String::from_utf8_lossy(&unactivated_payment.stderr)
        .contains("vault needs all members' backup confirmations"));
    assert!(!first.join("signing").exists());
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
            intent::{ChangePolicy, Intent},
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
        let (params, seed) = frost_rerandomized::RandomizedParams::new_from_commitments(
            public.verifying_key(),
            &commitments,
            rand_core::OsRng,
        )
        .unwrap();
        let restored = frost_rerandomized::RandomizedParams::regenerate_from_seed_and_commitments(
            public.verifying_key(),
            &seed,
            &commitments,
        )
        .unwrap();
        assert_eq!(
            params.randomizer().serialize(),
            restored.randomizer().serialize()
        );
        let alpha_bytes: [u8; 32] = params.randomizer().serialize().try_into().unwrap();
        let built = build_candidate(
            &Regtest,
            &inputs,
            &[alpha_from_canonical_bytes(&alpha_bytes).unwrap()],
            rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng),
        )
        .unwrap();
        let pczt = Creator::build_from_parts(built.pczt_parts).unwrap();
        let pczt = IoFinalizer::new(pczt).finalize_io().unwrap();
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
            let share = frost_rerandomized::sign_with_randomizer_seed(
                &package,
                &nonces[key.identifier()],
                key,
                &seed,
            )
            .unwrap();
            signature_shares.insert(*key.identifier(), share);
        }
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
        let original_card = fs::read(card.join("vault.card")).unwrap();
        let resumed = Command::new(exe)
            .args([
                "backup-create",
                member.to_str().unwrap(),
                pass.to_str().unwrap(),
                card.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            resumed.status.success(),
            "backup resume: {}",
            String::from_utf8_lossy(&resumed.stderr)
        );
        assert_eq!(resumed.stdout, words.as_bytes());
        assert_eq!(fs::read(card.join("vault.card")).unwrap(), original_card);
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
        // The member can reopen the words until the final card has been made.
        assert!(member.join("secrets/backup-words.sealed").exists());
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
    for id in 1..=3 {
        let member = root.join(format!("member-{id}"));
        let activated = Command::new(exe)
            .args([
                "address",
                member.to_str().unwrap(),
                member.join("pass.txt").to_str().unwrap(),
                roster.to_str().unwrap(),
                exchange.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            activated.status.success(),
            "activation: {}",
            String::from_utf8_lossy(&activated.stderr)
        );
        let loaded =
            loki_poc::member_state::open(&member, &member.join("pass.txt"), &roster).unwrap();
        assert_eq!(loaded.identity.public().id, id);
        assert_eq!(loaded.vault, [7u8; 32]);
        assert_eq!(
            loki_poc::vault::regtest_unified_address(&loaded.fvk),
            addresses[0].trim()
        );
        let finalized = Command::new(exe)
            .args([
                "backup-finalize",
                member.to_str().unwrap(),
                member.join("pass.txt").to_str().unwrap(),
                root.join(format!("card-{id}")).to_str().unwrap(),
                root.join(format!("final-card-{id}")).to_str().unwrap(),
                member.join("words.txt").to_str().unwrap(),
                roster.to_str().unwrap(),
                exchange.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            finalized.status.success(),
            "backup finalization: {}",
            String::from_utf8_lossy(&finalized.stderr)
        );
        assert!(!member.join("secrets/backup-words.sealed").exists());
        let repeated = Command::new(exe)
            .args([
                "backup-finalize",
                member.to_str().unwrap(),
                member.join("pass.txt").to_str().unwrap(),
                root.join(format!("card-{id}")).to_str().unwrap(),
                root.join(format!("final-card-{id}")).to_str().unwrap(),
                member.join("words.txt").to_str().unwrap(),
                roster.to_str().unwrap(),
                exchange.to_str().unwrap(),
            ])
            .output()
            .unwrap();
        assert!(
            repeated.status.success(),
            "backup finalization retry: {}",
            String::from_utf8_lossy(&repeated.stderr)
        );
    }
    // The payment CLI must reject bad local context before it can create an
    // attempt record or publish any commitment.
    let pay = env!("CARGO_BIN_EXE_loki_member_payment");
    let work = root.join("payment-cli-faults");
    fs::create_dir(&work).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&work, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let sign = |roster_path: &std::path::Path| {
        Command::new(pay)
            .args([
                "sign",
                first.to_str().unwrap(),
                first.join("pass.txt").to_str().unwrap(),
                roster_path.to_str().unwrap(),
                work.to_str().unwrap(),
            ])
            .output()
            .unwrap()
    };
    let manifest_path = work.join("payment.json");
    fs::write(&manifest_path, b"{broken json").unwrap();
    let malformed = sign(&roster);
    assert!(!malformed.status.success());
    assert!(String::from_utf8_lossy(&malformed.stderr).contains("manifest:"));
    assert!(!first.join("signing").exists());

    let intent = loki_poc::intent::Intent {
        proposer: reddsa_frost::frost::redpallas::Identifier::try_from(1u16)
            .unwrap()
            .serialize(),
        created_height: 1,
        input_nullifiers: vec![[1u8; 32]],
        recipient: vec![2u8; 43],
        amount_zat: 1,
        memo: b"check".to_vec(),
        change_policy: loki_poc::intent::ChangePolicy::VaultInternal,
        fee_zat: 10_000,
        change_zat: 1,
        expiry_height: 1_152,
    };
    let mut manifest = serde_json::json!({
        "version": 1, "network": "regtest", "vault": hex::encode([7u8; 32]),
        "payment": hex::encode(intent.proposal_id()), "attempt": hex::encode([3u8; 32]),
        "proposer": hex::encode(&intent.proposer), "created_height": intent.created_height,
        "input_nullifiers": intent.input_nullifiers.iter().map(hex::encode).collect::<Vec<_>>(),
        "recipient": hex::encode(&intent.recipient), "amount_zat": intent.amount_zat,
        "memo": hex::encode(&intent.memo), "change_policy": "vault_internal",
        "fee_zat": intent.fee_zat, "change_zat": intent.change_zat,
        "expiry_height": intent.expiry_height,
    });
    manifest["payment"] = serde_json::Value::String(hex::encode([9u8; 32]));
    fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let mismatch = sign(&roster);
    assert!(!mismatch.status.success());
    assert!(String::from_utf8_lossy(&mismatch.stderr).contains("payment ID differs from intent"));
    assert!(!first.join("signing").exists());

    manifest["payment"] = serde_json::Value::String(hex::encode(intent.proposal_id()));
    manifest["vault"] = serde_json::Value::String(hex::encode([8u8; 32]));
    fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let wrong_vault = sign(&roster);
    assert!(!wrong_vault.status.success());
    assert!(String::from_utf8_lossy(&wrong_vault.stderr).contains("another vault"));
    assert!(!first.join("signing").exists());

    let wrong_roster = root.join("wrong-roster.json");
    let mut changed_roster: serde_json::Value =
        serde_json::from_slice(&fs::read(&roster).unwrap()).unwrap();
    changed_roster["vault"] = serde_json::Value::String(hex::encode([8u8; 32]));
    fs::write(&wrong_roster, serde_json::to_vec(&changed_roster).unwrap()).unwrap();
    let wrong_certificate = sign(&wrong_roster);
    assert!(!wrong_certificate.status.success());
    assert!(String::from_utf8_lossy(&wrong_certificate.stderr).contains("roster differs"));
    assert!(!first.join("signing").exists());

    // A killed signer cannot reuse the attempt. A fresh attempt ID starts a
    // distinct local record, while resend refuses before a share was saved.
    manifest["vault"] = serde_json::Value::String(hex::encode([7u8; 32]));
    fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let start = || {
        Command::new(pay)
            .args([
                "sign",
                first.to_str().unwrap(),
                first.join("pass.txt").to_str().unwrap(),
                roster.to_str().unwrap(),
                work.to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap()
    };
    let attempt_dir = |id: u8| {
        first
            .join("signing")
            .join(hex::encode(intent.proposal_id()))
            .join(hex::encode([id; 32]))
    };
    let mut interrupted = start();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !attempt_dir(3).join("started").exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    assert!(attempt_dir(3).join("started").exists());
    interrupted.kill().unwrap();
    interrupted.wait().unwrap();
    let replay = sign(&roster);
    assert!(!replay.status.success());
    assert!(String::from_utf8_lossy(&replay.stderr).contains("attempt already exists"));
    let resend = Command::new(pay)
        .args([
            "resend",
            first.to_str().unwrap(),
            first.join("pass.txt").to_str().unwrap(),
            roster.to_str().unwrap(),
            work.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!resend.status.success(), "no share exists to resend");
    manifest["attempt"] = serde_json::Value::String(hex::encode([4u8; 32]));
    fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    let mut retry = start();
    let deadline = Instant::now() + Duration::from_secs(10);
    while !attempt_dir(4).join("started").exists() && Instant::now() < deadline {
        thread::sleep(Duration::from_millis(20));
    }
    assert!(attempt_dir(4).join("started").exists());
    retry.kill().unwrap();
    retry.wait().unwrap();
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
    let recovery = root.join("new-device");
    fs::create_dir(&recovery).unwrap();
    let recovered_card = recovery.join("card");
    fs::create_dir(&recovered_card).unwrap();
    fs::copy(
        root.join("final-card-1/vault.card"),
        recovered_card.join("vault.card"),
    )
    .unwrap();
    assert!(!root.join("final-card-1/recovery.card").exists());
    let recovered_words = recovery.join("words.txt");
    fs::copy(first.join("words.txt"), &recovered_words).unwrap();
    let recovered_pass = recovery.join("pass.txt");
    fs::write(&recovered_pass, "new device passphrase\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&recovered_pass, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&recovered_words, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let offline_card_check = Command::new(exe)
        .args([
            "backup-finalize",
            first.to_str().unwrap(),
            first.join("pass.txt").to_str().unwrap(),
            root.join("card-1").to_str().unwrap(),
            recovered_card.to_str().unwrap(),
            recovered_words.to_str().unwrap(),
            roster.to_str().unwrap(),
            exchange.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        offline_card_check.status.success(),
        "offline saved-card check: {}",
        String::from_utf8_lossy(&offline_card_check.stderr)
    );

    let bad_card = recovery.join("bad-card");
    fs::create_dir(&bad_card).unwrap();
    let words = fs::read_to_string(&recovered_words).unwrap();
    let card = MemberDir::open(&recovery, "card");
    let mut evidence: serde_json::Value =
        serde_json::from_slice(&card.read_sealed("vault.card", words.trim()).unwrap()).unwrap();
    evidence["receipts"].as_object_mut().unwrap().remove("3");
    MemberDir::open(&recovery, "bad-card")
        .write_sealed(
            "vault.card",
            &serde_json::to_vec(&evidence).unwrap(),
            words.trim(),
        )
        .unwrap();
    let refused_root = recovery.join("refused");
    let refused = Command::new(exe)
        .args([
            "restore",
            refused_root.to_str().unwrap(),
            recovered_pass.to_str().unwrap(),
            bad_card.to_str().unwrap(),
            recovered_words.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !refused.status.success(),
        "missing peer receipt restored a spendable share"
    );
    assert!(!refused_root.join("secrets").exists());

    let tampered_card = recovery.join("tampered-card");
    fs::create_dir(&tampered_card).unwrap();
    let mut evidence: serde_json::Value =
        serde_json::from_slice(&card.read_sealed("vault.card", words.trim()).unwrap()).unwrap();
    let mut wire = hex::decode(evidence["receipts"]["3"].as_str().unwrap()).unwrap();
    *wire.last_mut().unwrap() ^= 1;
    evidence["receipts"]["3"] = hex::encode(wire).into();
    MemberDir::open(&recovery, "tampered-card")
        .write_sealed(
            "vault.card",
            &serde_json::to_vec(&evidence).unwrap(),
            words.trim(),
        )
        .unwrap();
    let tampered_root = recovery.join("tampered");
    let refused = Command::new(exe)
        .args([
            "restore",
            tampered_root.to_str().unwrap(),
            recovered_pass.to_str().unwrap(),
            tampered_card.to_str().unwrap(),
            recovered_words.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !refused.status.success(),
        "tampered peer receipt restored a spendable share"
    );
    assert!(!tampered_root.join("secrets").exists());

    let changed_view_card = recovery.join("changed-view-card");
    fs::create_dir(&changed_view_card).unwrap();
    let mut evidence: serde_json::Value =
        serde_json::from_slice(&card.read_sealed("vault.card", words.trim()).unwrap()).unwrap();
    let ak: [u8; 32] = hex::decode(evidence["state"]["group_ak"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let changed_secret = [9u8; 32];
    let changed_fvk = loki_poc::zip2005::frost_viewing_key(&ak, &changed_secret).unwrap();
    evidence["state"]["vault_secret"] = hex::encode(changed_secret).into();
    evidence["state"]["address"] = loki_poc::vault::regtest_unified_address(&changed_fvk).into();
    MemberDir::open(&recovery, "changed-view-card")
        .write_sealed(
            "vault.card",
            &serde_json::to_vec(&evidence).unwrap(),
            words.trim(),
        )
        .unwrap();
    let changed_view_root = recovery.join("changed-view");
    let refused = Command::new(exe)
        .args([
            "restore",
            changed_view_root.to_str().unwrap(),
            recovered_pass.to_str().unwrap(),
            changed_view_card.to_str().unwrap(),
            recovered_words.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !refused.status.success(),
        "changed viewing secret and matching address kept old peer receipts"
    );
    assert!(!changed_view_root.join("secrets").exists());

    let restored_root = recovery.join("restored");
    let restored = Command::new(exe)
        .args([
            "restore",
            restored_root.to_str().unwrap(),
            recovered_pass.to_str().unwrap(),
            recovered_card.to_str().unwrap(),
            recovered_words.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        restored.status.success(),
        "two-artifact restore: {}",
        String::from_utf8_lossy(&restored.stderr)
    );
    assert_eq!(restored.stdout, addresses[0].as_bytes());
    let loaded = loki_poc::member_state::open(
        &restored_root,
        &recovered_pass,
        &restored_root.join("roster.json"),
    )
    .unwrap();
    assert_eq!(loaded.identity.public().id, 1);
    let interrupted_root = recovery.join("interrupted");
    MemberDir::create(&interrupted_root, "secrets")
        .unwrap()
        .write_sealed(
            "identity.sealed",
            &loaded.identity.to_secret_bytes(),
            "new device passphrase",
        )
        .unwrap();
    let resumed = Command::new(exe)
        .args([
            "restore",
            interrupted_root.to_str().unwrap(),
            recovered_pass.to_str().unwrap(),
            recovered_card.to_str().unwrap(),
            recovered_words.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        resumed.status.success(),
        "interrupted restore: {}",
        String::from_utf8_lossy(&resumed.stderr)
    );
    loki_poc::member_state::open(
        &interrupted_root,
        &recovered_pass,
        &interrupted_root.join("roster.json"),
    )
    .unwrap();
    let conflicting_root = recovery.join("conflicting-target");
    MemberDir::create(&conflicting_root, "secrets")
        .unwrap()
        .write_sealed("identity.sealed", &[5u8; 32], "new device passphrase")
        .unwrap();
    let conflicting = Command::new(exe)
        .args([
            "restore",
            conflicting_root.to_str().unwrap(),
            recovered_pass.to_str().unwrap(),
            recovered_card.to_str().unwrap(),
            recovered_words.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!conflicting.status.success());
    assert!(!conflicting_root.join("secrets/vault.sealed").exists());
    assert!(!conflicting_root.join("secrets/activation.sealed").exists());
    let v1_root = recovery.join("existing-v1-member");
    let mut v1_state: serde_json::Value =
        serde_json::from_slice(&card.read_sealed("vault.card", words.trim()).unwrap()).unwrap();
    v1_state = v1_state["state"].take();
    v1_state.as_object_mut().unwrap().remove("backup_version");
    let mut v1_digest = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"Loki_bkup_v1")
        .to_state();
    for field in ["vault", "roster_fingerprint", "group_ak"] {
        v1_digest.update(&hex::decode(v1_state[field].as_str().unwrap()).unwrap());
    }
    v1_digest.update(loki_poc::zip2005::VERSION.as_bytes());
    let v1_dir = MemberDir::create(&v1_root, "secrets").unwrap();
    v1_dir
        .write_sealed(
            "identity.sealed",
            &loaded.identity.to_secret_bytes(),
            "new device passphrase",
        )
        .unwrap();
    v1_dir
        .write_sealed(
            "vault.sealed",
            &serde_json::to_vec(&v1_state).unwrap(),
            "new device passphrase",
        )
        .unwrap();
    let v1_body: [u8; 32] = v1_digest.finalize().as_bytes().try_into().unwrap();
    v1_dir
        .write_sealed("activation.sealed", &v1_body, "new device passphrase")
        .unwrap();
    fs::copy(
        restored_root.join("roster.json"),
        v1_root.join("roster.json"),
    )
    .unwrap();
    loki_poc::member_state::open(&v1_root, &recovered_pass, &v1_root.join("roster.json"))
        .expect("previously activated v1 vault must still open");
    let v1_provisional = recovery.join("v1-provisional");
    MemberDir::create(&recovery, "v1-provisional")
        .unwrap()
        .write_sealed("vault.card", &serde_json::to_vec(&v1_state).unwrap(), words.trim())
        .unwrap();
    let mut v1_receipts = BTreeMap::new();
    for number in 1..=3 {
        let member = root.join(format!("member-{number}"));
        let signer = loki_poc::member_state::open(&member, &member.join("pass.txt"), &roster)
            .unwrap();
        v1_receipts.insert(
            number.to_string(),
            hex::encode(signer.identity.sign_backup(&[7u8; 32], &v1_body).unwrap()),
        );
    }
    let v1_final = recovery.join("v1-disguised-final");
    let v1_envelope = serde_json::json!({
        "recovery_version": 2,
        "state": v1_state,
        "roster": serde_json::from_slice::<serde_json::Value>(&fs::read(&roster).unwrap()).unwrap(),
        "receipts": v1_receipts,
    });
    MemberDir::create(&recovery, "v1-disguised-final")
        .unwrap()
        .write_sealed("vault.card", &serde_json::to_vec(&v1_envelope).unwrap(), words.trim())
        .unwrap();
    let v1_final_check = Command::new(exe)
        .args([
            "backup-finalize",
            v1_root.to_str().unwrap(),
            recovered_pass.to_str().unwrap(),
            v1_provisional.to_str().unwrap(),
            v1_final.to_str().unwrap(),
            recovered_words.to_str().unwrap(),
            roster.to_str().unwrap(),
            exchange.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        !v1_final_check.status.success(),
        "legacy receipts must not verify as a restorable final card"
    );
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
    assert!(String::from_utf8_lossy(&offline_restored.stderr)
        .contains("Legacy card restored keys and address only"));
    assert!(
        loki_poc::member_state::open(&offline, &offline_pass, &roster)
            .err()
            .unwrap()
            .contains("backup confirmations")
    );
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
