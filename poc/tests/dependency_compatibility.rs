use loki_poc::{
    candidate::{build_candidate, quote_fee, CandidateInputs, Regtest},
    vault,
};
use orchard::{
    keys::Scope,
    note::{RandomSeed, Rho},
    value::NoteValue,
    Note, NoteVersion,
};
use rand_core::SeedableRng;
use reddsa_frost::frost::redpallas as frost;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use zcash_protocol::{memo::MemoBytes, value::Zatoshis};

fn synthetic_artifacts() -> Value {
    let mut rng = rand_chacha::ChaCha20Rng::from_seed([42; 32]);
    let (shares, public) =
        frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, &mut rng)
            .unwrap();
    let keys: BTreeMap<_, _> = shares
        .into_iter()
        .map(|(id, share)| (id, frost::keys::KeyPackage::try_from(share).unwrap()))
        .collect();
    let digests: Vec<_> = keys.iter().map(|(id, key)| {
        let bytes = key.serialize().unwrap();
        assert_eq!(frost::keys::KeyPackage::deserialize(&bytes).unwrap().serialize().unwrap(), bytes);
        json!({"identifier": hex::encode(id.serialize()), "blake3": blake3::hash(&bytes).to_hex().to_string()})
    }).collect();
    let ids: Vec<_> = keys.keys().copied().take(2).collect();
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for id in &ids {
        let (n, c) = frost::round1::commit(keys[id].signing_share(), &mut rng);
        nonces.insert(*id, n);
        commitments.insert(*id, c);
    }
    let alpha_bytes = [7u8; 32];
    let alpha = frost_rerandomized::Randomizer::deserialize(&alpha_bytes).unwrap();
    let message = b"loki issue4 old-graph compatibility";
    let package = frost::SigningPackage::new(commitments, message);
    let signature_shares = ids
        .iter()
        .map(|id| {
            #[allow(deprecated)]
            let share = frost_rerandomized::sign(&package, &nonces[id], &keys[id], alpha).unwrap();
            (*id, share)
        })
        .collect();
    let params =
        frost_rerandomized::RandomizedParams::from_randomizer(public.verifying_key(), alpha);
    let signature =
        frost_rerandomized::aggregate(&package, &signature_shares, &public, &params).unwrap();
    params
        .randomized_verifying_key()
        .verify(message, &signature)
        .unwrap();
    let ak: [u8; 32] = public
        .verifying_key()
        .serialize()
        .unwrap()
        .try_into()
        .unwrap();
    let fvk = vault::test_only_fvk(&ak).unwrap();
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
    let mut inputs = CandidateInputs {
        vault_fvk: &fvk,
        notes: vec![note],
        recipient: fvk.address_at(7u64, Scope::External),
        amount: Zatoshis::const_from_u64(40_000_000),
        memo: MemoBytes::from_bytes(b"compatibility").unwrap(),
        change: Zatoshis::ZERO,
        target_height: 700,
        expiry_height: 1_152,
    };
    let fee = quote_fee(&Regtest, &inputs).unwrap();
    inputs.change = Zatoshis::const_from_u64(585_000_000 - u64::from(fee));
    let tx_rng = <rand_zp::rngs::StdRng as rand_core_zp::SeedableRng>::from_seed([43; 32]);
    let built = build_candidate(
        &Regtest,
        &inputs,
        &[loki_poc::candidate::alpha_from_canonical_bytes(&alpha_bytes).unwrap()],
        tx_rng,
    )
    .unwrap();
    let pczt = pczt::roles::creator::Creator::build_from_parts(built.pczt_parts).unwrap();
    let full_hash = blake3::hash(&pczt.clone().serialize().unwrap())
        .to_hex()
        .to_string();
    let redacted = pczt::roles::redactor::Redactor::new(pczt)
        .redact_ironwood_with(|mut b| {
            b.clear_bsk();
            b.redact_actions(|mut a| {
                a.clear_spend_recipient();
                a.clear_spend_value();
                a.clear_spend_rho();
                a.clear_spend_rseed();
                a.clear_spend_fvk();
                a.clear_spend_witness();
                a.clear_spend_alpha();
                a.clear_spend_dummy_sk();
                a.clear_output_recipient();
                a.clear_output_value();
                a.clear_output_rseed();
                a.clear_output_ock();
                a.clear_rcv();
            });
        })
        .finish();
    json!({"key_package_digests": digests, "public_package": hex::encode(public.serialize().unwrap()),
        "group_key": hex::encode(ak), "alpha": hex::encode(alpha_bytes), "message": hex::encode(message),
        "signature": hex::encode(signature.serialize().unwrap()), "unproved_pczt_blake3": full_hash,
        "redacted_pczt": hex::encode(redacted.serialize().unwrap())})
}

fn old_fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/zakura-migration-public.json")).unwrap()
}

fn bytes(fixture: &Value, field: &str) -> Vec<u8> {
    hex::decode(fixture[field].as_str().unwrap()).unwrap()
}

#[test]
fn deterministic_runtime_keys_and_candidates_match_the_old_graph() {
    assert_eq!(synthetic_artifacts(), old_fixture());
}

#[test]
fn old_public_package_and_randomized_signature_round_trip_and_verify() {
    let f = old_fixture();
    let encoded = bytes(&f, "public_package");
    let public = frost::keys::PublicKeyPackage::deserialize(&encoded).unwrap();
    assert_eq!(public.serialize().unwrap(), encoded);
    assert_eq!(
        public.verifying_key().serialize().unwrap(),
        bytes(&f, "group_key")
    );
    for key in f["key_package_digests"].as_array().unwrap() {
        let id = hex::decode(key["identifier"].as_str().unwrap()).unwrap();
        assert_eq!(frost::Identifier::deserialize(&id).unwrap().serialize(), id);
    }
    let encoded_signature = bytes(&f, "signature");
    let signature = frost::Signature::deserialize(&encoded_signature).unwrap();
    assert_eq!(signature.serialize().unwrap(), encoded_signature);
    let alpha = frost_rerandomized::Randomizer::deserialize(&bytes(&f, "alpha")).unwrap();
    let params =
        frost_rerandomized::RandomizedParams::from_randomizer(public.verifying_key(), alpha);
    params
        .randomized_verifying_key()
        .verify(&bytes(&f, "message"), &signature)
        .unwrap();
    assert!(params
        .randomized_verifying_key()
        .verify(b"corrupted message", &signature)
        .is_err());
}

#[test]
fn old_redacted_pczt_round_trips_without_note_secrets() {
    let f = old_fixture();
    let encoded = bytes(&f, "redacted_pczt");
    let parsed = pczt::Pczt::parse(&encoded).unwrap();
    assert_eq!(parsed.clone().serialize().unwrap(), encoded);
    for action in parsed.ironwood().actions() {
        assert!(action.spend().dummy_sk().is_none());
        assert!(action.output().rseed().is_none());
    }
    let mut corrupted = encoded.clone();
    corrupted[0] ^= 1;
    assert!(pczt::Pczt::parse(&corrupted).is_err());
    assert!(pczt::Pczt::parse(&encoded[..encoded.len() / 2]).is_err());
    assert!(frost::keys::PublicKeyPackage::deserialize(&[0xff; 32]).is_err());
    assert!(frost::keys::KeyPackage::deserialize(&[0xff; 32]).is_err());
}

struct Scratch(std::path::PathBuf);

impl Scratch {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "loki-artifact-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir(&root).unwrap();
        Self(root)
    }

    fn cli(&self, stage: &str, member: &str) -> std::process::Output {
        std::process::Command::new(env!("CARGO_BIN_EXE_loki"))
            .arg(stage)
            .arg(&self.0)
            .arg(member)
            .env_remove("LOKI_ROUND")
            .env("LOKI_RPC", "http://127.0.0.1:1")
            .output()
            .unwrap()
    }

    fn snapshot(&self) -> BTreeMap<std::path::PathBuf, Vec<u8>> {
        fn read(root: &std::path::Path, files: &mut BTreeMap<std::path::PathBuf, Vec<u8>>) {
            for entry in std::fs::read_dir(root).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    read(&path, files);
                } else {
                    files.insert(path.clone(), std::fs::read(path).unwrap());
                }
            }
        }
        let mut files = BTreeMap::new();
        read(&self.0, &mut files);
        files
    }

    fn synthetic_signer_state() -> Self {
        let scratch = Self::new();
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([42; 32]);
        let (shares, public) =
            frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, &mut rng)
                .unwrap();
        for ((id, share), member) in shares.into_iter().zip(["alice", "bob", "carol"]) {
            let dir = loki_poc::state::MemberDir::create(&scratch.0, member).unwrap();
            dir.write_hex("identifier.hex", &id.serialize()).unwrap();
            dir.write_hex(
                "key_package.hex",
                &frost::keys::KeyPackage::try_from(share)
                    .unwrap()
                    .serialize()
                    .unwrap(),
            )
            .unwrap();
            dir.write_hex("public_package.hex", &public.serialize().unwrap())
                .unwrap();
            assert!(scratch.cli("commit", member).status.success());
        }
        let dir = loki_poc::state::MemberDir::open(&scratch.0, "public");
        dir.write_hex("group_ak.hex", &public.verifying_key().serialize().unwrap())
            .unwrap();
        let f = old_fixture();
        dir.write_text("intent.txt", &format!("input_nullifier={}\nrecipient={}\namount_zat=40000000\nchange_zat=584990000\nmemo={}\nexpiry_height=1152\nfee_zat=10000\nproposal_id={}\n",
            hex::encode([1; 32]), hex::encode([1; 43]), f["message"].as_str().unwrap(), hex::encode([9; 32]))).unwrap();
        for pair in ["AB", "AC", "BC"] {
            dir.write_hex(
                &format!("candidate_{pair}.pczt.hex"),
                &bytes(&f, "redacted_pczt"),
            )
            .unwrap();
        }
        scratch
    }

    fn refuses_without_mutating(&self, stage: &str, reason: &str) {
        let before = self.snapshot();
        assert!(!before.keys().any(|p| p
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("share_")));
        assert!(before.keys().any(|p| p
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .starts_with("nonces_")));
        let output = self.cli(stage, "alice");
        assert!(!output.status.success());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(error.contains(reason), "wrong refusal: {error}");
        assert!(
            self.snapshot() == before,
            "refusal must not write shares, replace keys, or consume/reset nonces"
        );
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn malformed_saved_keys_are_refused_by_cli_without_changing_state() {
    let state = Scratch::synthetic_signer_state();
    let path = state.0.join("alice/key_package.hex");
    let original = hex::decode(std::fs::read_to_string(&path).unwrap().trim()).unwrap();
    for corrupt in [vec![0xff; 32], original[..original.len() / 2].to_vec()] {
        std::fs::write(&path, hex::encode(corrupt)).unwrap();
        state.refuses_without_mutating("commit", "key package:");
        state.refuses_without_mutating("review-sign", "key package:");
    }
}

#[test]
fn malformed_saved_pczts_are_refused_by_cli_without_changing_state() {
    let state = Scratch::synthetic_signer_state();
    let original = bytes(&old_fixture(), "redacted_pczt");
    let mut bad_magic = original.clone();
    bad_magic[0] ^= 1;
    let mut unknown_version = original.clone();
    unknown_version[4..8].copy_from_slice(&3u32.to_le_bytes());
    for corrupt in [
        bad_magic,
        unknown_version,
        original[..original.len() / 2].to_vec(),
    ] {
        std::fs::write(
            state.0.join("public/candidate_AB.pczt.hex"),
            hex::encode(corrupt),
        )
        .unwrap();
        state.refuses_without_mutating("review-sign", "AB: parse:");
    }
}

#[test]
fn old_sealed_public_payload_is_read_without_changing_the_saved_file() {
    let state = Scratch::new();
    let member = loki_poc::state::MemberDir::create(&state.0, "member").unwrap();
    let encoded = hex::decode(include_str!("fixtures/legacy-public-seal.hex").trim()).unwrap();
    std::fs::write(member.path().join("legacy.sealed"), &encoded).unwrap();
    let before = state.snapshot();
    assert_eq!(
        member
            .read_sealed("legacy.sealed", "public migration fixture passphrase")
            .unwrap(),
        b"public legacy seal compatibility payload"
    );
    assert!(member
        .read_sealed("legacy.sealed", "wrong passphrase")
        .is_err());
    assert!(state.snapshot() == before);
}

#[test]
fn cli_handoff_copies_only_the_selected_pairs_public_inputs() {
    let state = Scratch::synthetic_signer_state();
    let public = state.0.join("public");
    for (pair, members) in [
        ("AB", ["alice", "bob"]),
        ("AC", ["alice", "carol"]),
        ("BC", ["bob", "carol"]),
    ] {
        for member in members {
            std::fs::write(public.join(format!("share_{pair}_{member}.hex")), "0102").unwrap();
        }
    }
    for (pair, members) in [
        ("AB", ["alice", "bob"]),
        ("AC", ["alice", "carol"]),
        ("BC", ["bob", "carol"]),
    ] {
        let replica = state.0.join(format!("replica-{pair}"));
        let before = state.snapshot();
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_loki"))
            .arg("replicate")
            .arg(&state.0)
            .arg(&replica)
            .args(["--pair", pair])
            .env_remove("LOKI_ROUND")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            std::fs::read_to_string(replica.join("pair.txt")).unwrap(),
            pair
        );
        assert!(replica.join(format!("candidate_{pair}.pczt.hex")).is_file());
        for member in members {
            assert!(replica.join(format!("identifier_{member}.hex")).is_file());
            assert!(replica.join(format!("share_{pair}_{member}.hex")).is_file());
        }
        for other in ["AB", "AC", "BC"]
            .into_iter()
            .filter(|other| *other != pair)
        {
            assert!(!replica.join(format!("candidate_{other}.pczt.hex")).exists());
        }
        assert!(!std::fs::read_dir(&replica).unwrap().any(|entry| {
            let name = entry.unwrap().file_name().to_string_lossy().into_owned();
            name.contains("key_package")
                || name.contains("nonces")
                || ["alice", "bob", "carol"].contains(&name.as_str())
        }));
        std::fs::remove_dir_all(replica).unwrap();
        assert!(
            state.snapshot() == before,
            "handoff must preserve the original member and proposal state"
        );
    }
}
