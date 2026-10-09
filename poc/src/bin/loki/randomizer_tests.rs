use super::*;
use loki_poc::{
    candidate::{alpha_from_canonical_bytes, build_candidate, quote_fee, CandidateInputs, Regtest},
    intent::{ChangePolicy, Intent},
    randomizer::SeedRecord,
};
use orchard::{
    keys::Scope,
    note::{RandomSeed, Rho},
    value::NoteValue,
    Note, NoteVersion,
};
use rand_core::RngCore;
use std::fs;
use zcash_protocol::{memo::MemoBytes, value::Zatoshis};

struct Fixture {
    root: PathBuf,
    public: frost::keys::PublicKeyPackage,
    ak: [u8; 32],
    fvk: orchard::keys::FullViewingKey,
    notes: [Note; 2],
    intent: Intent,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

impl Fixture {
    fn new() -> Self {
        let mut suffix = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut suffix);
        let root =
            std::env::temp_dir().join(format!("loki-randomizer-tests-{}", hex::encode(suffix)));
        let (shares, public) = frost::keys::generate_with_dealer(
            3,
            2,
            frost::keys::IdentifierList::Default,
            rand_core::OsRng,
        )
        .unwrap();
        for (name, number) in MEMBERS {
            let id: frost::Identifier = number.try_into().unwrap();
            let key = frost::keys::KeyPackage::try_from(shares[&id].clone()).unwrap();
            let dir = MemberDir::create(&root, name).unwrap();
            dir.write_hex("key_package.hex", &key.serialize().unwrap())
                .unwrap();
            dir.write_hex("public_package.hex", &public.serialize().unwrap())
                .unwrap();
            dir.write_hex("identifier.hex", &id.serialize()).unwrap();
        }
        let ak = public
            .verifying_key()
            .serialize()
            .unwrap()
            .try_into()
            .unwrap();
        let fvk = vault::test_only_fvk(&ak).unwrap();
        let notes = [1u8, 2].map(|seed| {
            let rho = Rho::from_bytes(&[seed + 1; 32]).unwrap();
            let rseed = RandomSeed::from_bytes([seed + 2; 32], &rho).unwrap();
            Note::from_parts(
                fvk.address_at(0u64, Scope::External),
                NoteValue::from_raw(30_000_000),
                rho,
                rseed,
                NoteVersion::V3,
            )
            .unwrap()
        });
        let inputs = CandidateInputs {
            vault_fvk: &fvk,
            notes: notes.to_vec(),
            recipient: fvk.address_at(7u64, Scope::External),
            amount: Zatoshis::const_from_u64(50_000_000),
            memo: MemoBytes::from_bytes(b"two-input seed test").unwrap(),
            change: Zatoshis::ZERO,
            target_height: 20,
            expiry_height: 9_216,
        };
        let fee = u64::from(quote_fee(&Regtest, &inputs).unwrap());
        let intent = Intent {
            proposer: frost::Identifier::try_from(1u16).unwrap().serialize(),
            created_height: 20,
            input_nullifiers: notes.iter().map(|n| n.nullifier(&fvk).to_bytes()).collect(),
            recipient: inputs.recipient.to_raw_address_bytes().to_vec(),
            amount_zat: 50_000_000,
            memo: b"two-input seed test".to_vec(),
            change_policy: ChangePolicy::VaultInternal,
            fee_zat: fee,
            change_zat: 10_000_000 - fee,
            expiry_height: 9_216,
        };
        let fixture = Self {
            root,
            public,
            ak,
            fvk,
            notes,
            intent,
        };
        let shared = MemberDir::create(&fixture.root, &shared_name()).unwrap();
        shared.write_hex("group_ak.hex", &ak).unwrap();
        fixture.write_intent();
        for (member, _) in MEMBERS {
            commit(&[fixture.arg(), member.into(), "--spends".into(), "2".into()]).unwrap();
        }
        for (pair, _, _) in PAIRS {
            let mut alphas = Vec::new();
            for spend in 0..2 {
                let commitments = fixture.commitments(pair, spend);
                let (params, seed) = frost_rerandomized::RandomizedParams::new_from_commitments(
                    fixture.public.verifying_key(),
                    &commitments,
                    rand_core::OsRng,
                )
                .unwrap();
                let record = SeedRecord::new(
                    fixture.intent.proposal_id(),
                    pair,
                    spend,
                    fixture.intent.input_nullifiers[spend],
                    &commitments,
                    &seed,
                )
                .unwrap();
                shared
                    .write_text(&seed_file(pair, spend), &record.encode().unwrap())
                    .unwrap();
                let bytes = params.randomizer().serialize().try_into().unwrap();
                alphas.push(alpha_from_canonical_bytes(&bytes).unwrap());
            }
            fixture.write_candidate(pair, &alphas);
        }
        fixture
    }

    fn arg(&self) -> String {
        self.root.to_str().unwrap().to_string()
    }
    fn shared(&self) -> MemberDir {
        MemberDir::open(&self.root, &shared_name())
    }
    fn write_intent(&self) {
        let i = &self.intent;
        self.shared().write_text("intent.txt", &format!(
            "proposal_id={}\nproposer={}\ncreated_height={}\ninput_nullifier={}\nrecipient={}\namount_zat={}\nmemo={}\nchange_policy=vault_internal\nfee_zat={}\nchange_zat={}\nexpiry_height={}\ntarget_height={}\n",
            hex::encode(i.proposal_id()), hex::encode(&i.proposer), i.created_height,
            i.input_nullifiers.iter().map(hex::encode).collect::<Vec<_>>().join(","), hex::encode(&i.recipient),
            i.amount_zat, hex::encode(&i.memo), i.fee_zat, i.change_zat, i.expiry_height, i.created_height,
        )).unwrap();
    }
    fn ids(pair: &str) -> [frost::Identifier; 2] {
        let (_, x, y) = PAIRS.iter().find(|(name, _, _)| *name == pair).unwrap();
        [
            MEMBERS[*x].1.try_into().unwrap(),
            MEMBERS[*y].1.try_into().unwrap(),
        ]
    }
    fn commitments(
        &self,
        pair: &str,
        spend: usize,
    ) -> BTreeMap<frost::Identifier, frost::round1::SigningCommitments> {
        let (_, x, y) = PAIRS.iter().find(|(name, _, _)| *name == pair).unwrap();
        [*x, *y]
            .into_iter()
            .zip(Self::ids(pair))
            .map(|(slot, id)| {
                let raw = self
                    .shared()
                    .read_hex(&commitment_file(pair, MEMBERS[slot].0, spend))
                    .unwrap();
                (
                    id,
                    frost::round1::SigningCommitments::deserialize(&raw).unwrap(),
                )
            })
            .collect()
    }
    fn write_candidate(&self, pair: &str, alphas: &[pasta_curves::pallas::Scalar]) {
        let i = &self.intent;
        let inputs = CandidateInputs {
            vault_fvk: &self.fvk,
            notes: self.notes.to_vec(),
            recipient: self.fvk.address_at(7u64, Scope::External),
            amount: Zatoshis::from_u64(i.amount_zat).unwrap(),
            memo: MemoBytes::from_bytes(&i.memo).unwrap(),
            change: Zatoshis::from_u64(i.change_zat).unwrap(),
            target_height: i.created_height,
            expiry_height: i.expiry_height,
        };
        let built = build_candidate(
            &Regtest,
            &inputs,
            alphas,
            rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng),
        )
        .unwrap();
        let candidate = pczt::roles::creator::Creator::build_from_parts(built.pczt_parts).unwrap();
        let candidate = pczt::roles::io_finalizer::IoFinalizer::new(candidate)
            .finalize_io(rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng))
            .unwrap();
        self.shared()
            .write_hex(
                &format!("candidate_{pair}.pczt.hex"),
                &candidate.serialize().unwrap(),
            )
            .unwrap();
    }
    fn sign_all(&self) {
        for (member, _) in MEMBERS {
            review_sign(&[self.arg(), member.into()]).unwrap();
        }
    }
    fn inputs(&self, pair: &str) -> AggregateInputs {
        let shared = self.shared();
        let (_, x, y) = PAIRS.iter().find(|(name, _, _)| *name == pair).unwrap();
        let members = [MEMBERS[*x].0, MEMBERS[*y].0];
        AggregateInputs {
            pair: pair.into(),
            group_ak: self.ak,
            candidate: shared
                .read_hex(&format!("candidate_{pair}.pczt.hex"))
                .unwrap(),
            public_package: self.public.serialize().unwrap(),
            ids: Self::ids(pair).map(|id| id.serialize()),
            commitments: (0..2)
                .map(|spend| {
                    members.map(|m| shared.read_hex(&commitment_file(pair, m, spend)).unwrap())
                })
                .collect(),
            shares: (0..2)
                .map(|spend| members.map(|m| shared.read_hex(&share_file(pair, m, spend)).unwrap()))
                .collect(),
            seeds: (0..2)
                .map(|spend| {
                    SeedRecord::decode(&shared.read_text(&seed_file(pair, spend)).unwrap()).unwrap()
                })
                .collect(),
            proposal_id: self.intent.proposal_id(),
            want_nfs: self.intent.input_nullifiers.clone(),
        }
    }
    fn nonce_snapshot(&self) -> BTreeMap<PathBuf, Vec<u8>> {
        let me = MemberDir::open(&self.root, "alice");
        ["AB", "AC"]
            .into_iter()
            .flat_map(|pair| (0..2).map(move |spend| nonce_file(pair, spend)))
            .filter_map(|file| {
                let path = me.path().join(file);
                fs::read(&path).ok().map(|bytes| (path, bytes))
            })
            .collect()
    }
    fn assert_alice_refuses(&self, expected: &str) {
        let before = self.nonce_snapshot();
        let error = review_sign(&[self.arg(), "alice".into()]).unwrap_err();
        assert!(
            error.contains(expected),
            "expected {expected:?}, found {error}"
        );
        for pair in ["AB", "AC"] {
            for spend in 0..2 {
                assert!(
                    !self
                        .shared()
                        .path()
                        .join(share_file(pair, "alice", spend))
                        .exists(),
                    "partial approval for {pair} spend {spend}"
                );
            }
        }
        assert_eq!(
            self.nonce_snapshot(),
            before,
            "review refusal consumed nonce secrets"
        );
    }
}

#[test]
fn randomizer_review_refuses_final_spend_seed_corruption_without_any_shares() {
    let f = Fixture::new();
    let file = f.shared().path().join(seed_file("AC", 1));
    let saved = fs::read_to_string(&file).unwrap();
    for (field, value, refusal) in [
        (
            "seed",
            serde_json::json!("zz"),
            "invalid randomizer seed hex",
        ),
        (
            "seed",
            serde_json::json!(hex::encode([7; 31])),
            "randomizer seed must be exactly 32 bytes",
        ),
        (
            "seed",
            serde_json::json!(hex::encode([7; 33])),
            "randomizer seed must be exactly 32 bytes",
        ),
        (
            "version",
            serde_json::json!(99),
            "unsupported randomizer seed record version",
        ),
        (
            "pair",
            serde_json::json!("AB"),
            "randomizer seed pair mismatch",
        ),
        (
            "spend_index",
            serde_json::json!(0),
            "randomizer seed spend index mismatch",
        ),
        (
            "nullifier",
            serde_json::json!(hex::encode([7; 32])),
            "randomizer seed nullifier mismatch",
        ),
        (
            "proposal_id",
            serde_json::json!(hex::encode([7; 32])),
            "randomizer seed proposal mismatch",
        ),
        (
            "seed",
            serde_json::json!(hex::encode([7; 32])),
            "rk does not match recomputed alpha",
        ),
    ] {
        let mut record: serde_json::Value = serde_json::from_str(&saved).unwrap();
        record[field] = value;
        fs::write(&file, record.to_string()).unwrap();
        f.assert_alice_refuses(refusal);
    }
    fs::write(&file, "not JSON").unwrap();
    f.assert_alice_refuses("invalid randomizer seed record JSON");
    fs::remove_file(&file).unwrap();
    f.assert_alice_refuses("missing randomizer seed");
    fs::write(&file, &saved).unwrap();
    let other_pair = fs::read(f.shared().path().join(seed_file("AB", 1))).unwrap();
    fs::write(&file, other_pair).unwrap();
    f.assert_alice_refuses("randomizer seed pair mismatch");
    fs::write(&file, saved).unwrap();
    let zero = f.shared().path().join(seed_file("AC", 0));
    let original_zero = fs::read(&zero).unwrap();
    let original_one = fs::read(&file).unwrap();
    fs::write(&zero, &original_one).unwrap();
    fs::write(&file, &original_zero).unwrap();
    f.assert_alice_refuses("randomizer seed spend index mismatch");
    fs::write(&zero, original_zero).unwrap();
    fs::write(&file, original_one).unwrap();
    let mut record: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&file).unwrap()).unwrap();
    record["commitments"].as_array_mut().unwrap().reverse();
    fs::write(&file, record.to_string()).unwrap();
    f.assert_alice_refuses("randomizer seed commitments mismatch");
}

#[test]
fn randomizer_seedless_legacy_and_later_missing_nonce_emit_no_shares() {
    let legacy = Fixture::new();
    for (pair, _, _) in PAIRS {
        for spend in 0..2 {
            fs::remove_file(legacy.shared().path().join(seed_file(pair, spend))).unwrap();
        }
    }
    legacy.assert_alice_refuses("missing randomizer seed");
    let f = Fixture::new();
    fs::remove_file(
        MemberDir::open(&f.root, "alice")
            .path()
            .join(nonce_file("AC", 1)),
    )
    .unwrap();
    f.assert_alice_refuses("run commit first");
}

#[test]
fn randomizer_fixed_candidate_rejects_changed_commitments_and_canonical_alpha() {
    let f = Fixture::new();
    let file = commitment_file("AC", "carol", 1);
    let saved = f.shared().read_hex(&file).unwrap();
    f.shared()
        .write_hex(
            &file,
            &f.shared()
                .read_hex(&commitment_file("AC", "carol", 0))
                .unwrap(),
        )
        .unwrap();
    f.assert_alice_refuses("randomizer seed commitments mismatch");
    let seed_name = seed_file("AC", 1);
    let saved_record = f.shared().read_text(&seed_name).unwrap();
    let seed = SeedRecord::decode(&saved_record).unwrap().seed;
    let rebound = SeedRecord::new(
        f.intent.proposal_id(),
        "AC",
        1,
        f.intent.input_nullifiers[1],
        &f.commitments("AC", 1),
        &seed,
    )
    .unwrap();
    f.shared()
        .write_text(&seed_name, &rebound.encode().unwrap())
        .unwrap();
    f.assert_alice_refuses("rk does not match recomputed alpha");
    f.shared().write_text(&seed_name, &saved_record).unwrap();
    f.shared().write_hex(&file, &saved).unwrap();
    let mut alphas = (0..2)
        .map(|spend| {
            let record =
                SeedRecord::decode(&f.shared().read_text(&seed_file("AC", spend)).unwrap())
                    .unwrap();
            let c = f.commitments("AC", spend);
            let seed = record
                .validate(
                    &f.intent.proposal_id(),
                    "AC",
                    spend,
                    &f.intent.input_nullifiers[spend],
                    &c,
                )
                .unwrap();
            let params =
                frost_rerandomized::RandomizedParams::regenerate_from_seed_and_commitments(
                    f.public.verifying_key(),
                    &seed,
                    &c,
                )
                .unwrap();
            alpha_from_canonical_bytes(&params.randomizer().serialize().try_into().unwrap())
                .unwrap()
        })
        .collect::<Vec<_>>();
    alphas[1] += pasta_curves::pallas::Scalar::from(1u64);
    f.write_candidate("AC", &alphas);
    f.assert_alice_refuses("rk does not match recomputed alpha");
}

#[test]
fn randomizer_all_pairs_sign_two_inputs_before_anchor_witness_or_proof() {
    let f = Fixture::new();
    let saved: Vec<_> = PAIRS
        .into_iter()
        .flat_map(|(pair, _, _)| (0..2).map(move |spend| seed_file(pair, spend)))
        .map(|file| {
            (
                file.clone(),
                fs::read(f.shared().path().join(file)).unwrap(),
            )
        })
        .collect();
    f.sign_all();
    for (file, bytes) in saved {
        assert_eq!(fs::read(f.shared().path().join(file)).unwrap(), bytes);
    }
    let candidates = PAIRS.map(|(pair, _, _)| (pair, f.inputs(pair)));
    for (member, _) in MEMBERS {
        fs::remove_dir_all(f.root.join(member)).unwrap();
    }
    fs::remove_dir_all(f.shared().path()).unwrap();
    let cmxs = f
        .notes
        .map(|note| orchard::note::ExtractedNoteCommitment::from(note.commitment()).to_bytes());
    let anchor = loki_poc::witness::CommitmentTree::build(&cmxs)
        .unwrap()
        .root()
        .to_bytes();
    for (pair, mut inputs) in candidates {
        let original = pczt::Pczt::parse(&inputs.candidate).unwrap();
        let expected_sighash = pczt::roles::signer::Signer::new(original.clone())
            .unwrap()
            .shielded_sighash();
        let (signed, sighash, indices) = aggregate_and_apply(&inputs).unwrap();
        assert_eq!(sighash, expected_sighash);
        assert_eq!(indices.len(), 2);
        assert_ne!(indices[0], indices[1]);
        assert!(signed.ironwood().anchor().is_none());
        assert!(signed.ironwood().zkproof().is_none());
        for (spend, index) in indices.iter().copied().enumerate() {
            let action = &signed.ironwood().actions()[index];
            assert_eq!(
                action.spend().nullifier(),
                &f.intent.input_nullifiers[spend]
            );
            assert!(action.spend().witness().is_none());
            let signature = action.spend().spend_auth_sig().as_ref().unwrap();
            let rk = orchard::primitives::redpallas::VerificationKey::<
                orchard::primitives::redpallas::SpendAuth,
            >::try_from(*action.spend().rk())
            .unwrap();
            rk.verify(
                &sighash,
                &orchard::primitives::redpallas::Signature::from(*signature),
            )
            .unwrap();
        }
        let positions = indices
            .iter()
            .copied()
            .enumerate()
            .map(|(position, index)| (index, position as u64))
            .collect::<Vec<_>>();
        let (raw, txid) = prove_and_extract(
            signed,
            &sighash,
            &positions,
            &cmxs,
            anchor,
            &format!("independent {pair} two-note"),
        )
        .unwrap();
        let tx = zcash_primitives::transaction::Transaction::read(
            &raw[..],
            zcash_protocol::consensus::BranchId::Nu6_3,
        )
        .unwrap();
        assert_eq!(tx.txid().to_string(), txid);
        assert_eq!(finalized_sighash(&tx).unwrap(), expected_sighash);
        let bundle = tx.ironwood_bundle().unwrap();
        for nf in &f.intent.input_nullifiers {
            assert_eq!(
                bundle
                    .actions()
                    .iter()
                    .filter(|action| action.nullifier().to_bytes() == *nf)
                    .count(),
                1
            );
        }
        assert_eq!(
            u64::try_from(*bundle.value_balance()).unwrap(),
            f.intent.fee_zat
        );
        inputs.seeds.swap(0, 1);
        assert!(aggregate_and_apply(&inputs)
            .unwrap_err()
            .contains("randomizer seed spend index mismatch"));
        inputs.seeds.swap(0, 1);
        inputs.commitments.swap(0, 1);
        assert!(aggregate_and_apply(&inputs)
            .unwrap_err()
            .contains("randomizer seed commitments mismatch"));
        inputs.commitments.swap(0, 1);
        inputs.seeds[1].seed[0] ^= 1;
        assert!(aggregate_and_apply(&inputs)
            .unwrap_err()
            .contains("rk does not match recomputed alpha"));
        inputs.seeds[1].seed[0] ^= 1;
        inputs.shares[1][0] = inputs.shares[0][0].clone();
        assert!(aggregate_and_apply(&inputs)
            .unwrap_err()
            .contains("aggregate"));
    }
}

#[test]
fn randomizer_restart_reloads_identical_candidate_and_seed_and_new_sessions_are_fresh() {
    let f = Fixture::new();
    let mut before = BTreeMap::new();
    for (pair, _, _) in PAIRS {
        for file in [
            format!("candidate_{pair}.pczt.hex"),
            seed_file(pair, 0),
            seed_file(pair, 1),
        ] {
            before.insert(
                file.clone(),
                fs::read(f.shared().path().join(file)).unwrap(),
            );
        }
    }
    review_sign(&[f.arg(), "alice".into()]).unwrap();
    review_sign(&[f.arg(), "carol".into()]).unwrap();
    assert!(aggregate_and_apply(&f.inputs("AC")).is_ok());
    for (file, bytes) in before {
        assert_eq!(fs::read(f.shared().path().join(file)).unwrap(), bytes);
    }
    let fresh = Fixture::new();
    for (pair, x, _) in PAIRS {
        for spend in 0..2 {
            assert_ne!(
                f.shared().read_text(&seed_file(pair, spend)).unwrap(),
                fresh.shared().read_text(&seed_file(pair, spend)).unwrap()
            );
            assert_ne!(
                f.shared()
                    .read_hex(&commitment_file(pair, MEMBERS[x].0, spend))
                    .unwrap(),
                fresh
                    .shared()
                    .read_hex(&commitment_file(pair, MEMBERS[x].0, spend))
                    .unwrap(),
                "fresh commitments for {pair}"
            );
        }
    }
}

#[test]
fn randomizer_incomplete_saved_session_files_refuse_reproposal_unchanged() {
    for file in ["candidate_AC.pczt.hex", "randomizer_seed_BC_1.hex"] {
        let f = Fixture::new();
        for entry in fs::read_dir(f.shared().path()).unwrap() {
            fs::remove_file(entry.unwrap().path()).unwrap();
        }
        f.shared().write_text(file, "saved session marker").unwrap();
        let before = fs::read(f.shared().path().join(file)).unwrap();
        let error = propose(&[f.arg()]).unwrap_err();
        assert!(error.contains("saved signing session exists"), "{error}");
        assert_eq!(fs::read(f.shared().path().join(file)).unwrap(), before);
        assert_eq!(fs::read_dir(f.shared().path()).unwrap().count(), 1);
    }
}

#[test]
fn randomizer_replica_reloads_seeds_without_approver_state_and_fails_locally() {
    let f = Fixture::new();
    f.sign_all();
    let out = f.root.join("replica");
    replicate(&[f.arg(), out.to_str().unwrap().into()]).unwrap();
    let replica = MemberDir::open(&f.root, "replica");
    for (member, _) in MEMBERS {
        fs::remove_dir_all(f.root.join(member)).unwrap();
    }
    fs::remove_dir_all(f.shared().path()).unwrap();
    for forbidden in [
        "alice",
        "bob",
        "carol",
        "key_package.hex",
        "funded_note.txt",
        "funded_notes.txt",
        "cmxs.hex",
        "anchor.txt",
    ] {
        assert!(
            !out.join(forbidden).exists(),
            "replica contains {forbidden}"
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&out).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for spend in 0..2 {
            assert_eq!(
                fs::metadata(out.join(seed_file("AC", spend)))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }
    assert!(aggregate_and_apply(&replica_inputs(&replica).unwrap()).is_ok());
    for posted in [false, true] {
        if posted {
            replica
                .write_hex(
                    "final_tx.hex",
                    b"invalid posted transaction; seed validation must precede parsing",
                )
                .unwrap();
        }
        let missing = out.join(seed_file("AC", 1));
        let saved = fs::read(&missing).unwrap();
        fs::remove_file(&missing).unwrap();
        let work = f.root.join(if posted {
            "work-posted"
        } else {
            "work-reprove"
        });
        let error = finish_second(&[out.to_str().unwrap().into(), work.to_str().unwrap().into()])
            .unwrap_err();
        assert!(error.contains("missing randomizer seed"), "{error}");
        fs::write(&missing, &saved).unwrap();
        let first = out.join(seed_file("AC", 0));
        let first_saved = fs::read(&first).unwrap();
        fs::write(&missing, &first_saved).unwrap();
        let error = finish_second(&[out.to_str().unwrap().into(), work.to_str().unwrap().into()])
            .unwrap_err();
        assert!(
            error.contains("randomizer seed spend index mismatch"),
            "{error}"
        );
        fs::write(&missing, saved).unwrap();
    }
}

#[test]
fn randomizer_public_package_must_match_known_vault_before_signing_or_aggregation() {
    let f = Fixture::new();
    let (_, unrelated) = frost::keys::generate_with_dealer(
        3,
        2,
        frost::keys::IdentifierList::Default,
        rand_core::OsRng,
    )
    .unwrap();
    let alice = MemberDir::open(&f.root, "alice");
    let saved = alice.read_hex("public_package.hex").unwrap();
    alice
        .write_hex("public_package.hex", &unrelated.serialize().unwrap())
        .unwrap();
    f.assert_alice_refuses("public package differs from known vault key");
    alice.write_hex("public_package.hex", &saved).unwrap();
    f.sign_all();
    let mut inputs = f.inputs("AC");
    inputs.public_package = unrelated.serialize().unwrap();
    assert!(aggregate_and_apply(&inputs)
        .unwrap_err()
        .contains("public package differs from known vault key"));
    inputs.public_package = saved;
    inputs.group_ak = unrelated
        .verifying_key()
        .serialize()
        .unwrap()
        .try_into()
        .unwrap();
    assert!(aggregate_and_apply(&inputs)
        .unwrap_err()
        .contains("public package differs from known vault key"));
}

#[test]
fn randomizer_replica_refuses_nonempty_destination_without_changing_any_bytes() {
    let original = Fixture::new();
    original.sign_all();
    let out = original.root.join("replica");
    replicate(&[original.arg(), out.to_str().unwrap().into()]).unwrap();
    let saved: BTreeMap<_, _> = fs::read_dir(&out)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            (
                path.file_name().unwrap().to_owned(),
                fs::read(&path).unwrap(),
            )
        })
        .collect();
    let fresh = Fixture::new();
    fresh.sign_all();
    let error = replicate(&[fresh.arg(), out.to_str().unwrap().into()]).unwrap_err();
    assert!(
        error.contains("replica destination is not empty"),
        "{error}"
    );
    let after: BTreeMap<_, _> = fs::read_dir(&out)
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            (
                path.file_name().unwrap().to_owned(),
                fs::read(&path).unwrap(),
            )
        })
        .collect();
    assert_eq!(after, saved);
}
