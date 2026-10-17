use loki_poc::{
    candidate::{alpha_from_canonical_bytes, build_candidate, quote_fee, CandidateInputs, Regtest},
    intent::{ChangePolicy, Intent},
    setup_transport::Identity,
    signing_session::{
        aggregate_and_apply, AttemptId, Mailbox, MessageKind, NonceWitness, PackagePayload,
        SessionContext, SigningSession,
    },
    state::MemberDir,
    vault,
};
use orchard::{
    keys::Scope,
    note::{RandomSeed, Rho},
    value::NoteValue,
    Note, NoteVersion,
};
use pczt::roles::{creator::Creator, io_finalizer::IoFinalizer};
use reddsa_frost::frost::redpallas as frost;
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
};

#[derive(Default)]
struct FirstWriter(BTreeSet<[u8; 32]>);
impl NonceWitness for FirstWriter {
    fn pins(&self) -> loki_poc::signing_session::WitnessPins {
        [([7; 32], [8; 32], [15; 32]), ([9; 32], [10; 32], [16; 32])]
    }
    fn claim(&mut self, cid: [u8; 32], _: &[u8]) -> Result<(), String> {
        if !self.0.insert(cid) {
            return Err("already claimed".into());
        }
        Ok(())
    }
}

struct WrongRelays;
impl NonceWitness for WrongRelays {
    fn pins(&self) -> loki_poc::signing_session::WitnessPins {
        [
            ([11; 32], [12; 32], [15; 32]),
            ([13; 32], [14; 32], [16; 32]),
        ]
    }
    fn claim(&mut self, _: [u8; 32], _: &[u8]) -> Result<(), String> {
        panic!("mismatched relays must be refused before a claim")
    }
}
struct ReprovisionedMailbox;
impl NonceWitness for ReprovisionedMailbox {
    fn pins(&self) -> loki_poc::signing_session::WitnessPins {
        // Same relay keys and runs, but fresh mailboxes have empty consumed-CID ledgers.
        [([7; 32], [8; 32], [17; 32]), ([9; 32], [10; 32], [18; 32])]
    }
    fn claim(&mut self, _: [u8; 32], _: &[u8]) -> Result<(), String> {
        panic!("changed mailbox must be refused before a nonce claim")
    }
}
use zcash_protocol::{memo::MemoBytes, value::Zatoshis};

#[test]
fn two_spend_review_refuses_swaps_before_share_and_recovery_resends_exact_wire() {
    run_review_and_rollback(3, [1, 2]);
}

#[test]
fn every_four_member_pair_refuses_nonce_rollback_and_replays_exact_fanout() {
    for pair in [[1, 2], [1, 3], [1, 4], [2, 3], [2, 4], [3, 4]] {
        run_review_and_rollback(4, pair);
    }
}

fn run_review_and_rollback(member_count: u16, pair: [u16; 2]) {
    let [first, second] = pair;
    let root = std::env::temp_dir().join(format!(
        "loki-signing-flow-{}",
        hex::encode(AttemptId::random().0)
    ));
    fs::create_dir(&root).unwrap();
    let alice_root = root.join("alice");
    let bob_root = root.join("bob");
    let mailbox = Mailbox::new(&root.join("relay")).unwrap();
    let (shares, public) = frost::keys::generate_with_dealer(
        member_count,
        2,
        frost::keys::IdentifierList::Default,
        rand_core::OsRng,
    )
    .unwrap();
    let alice_id = frost::Identifier::try_from(first).unwrap();
    let bob_id = frost::Identifier::try_from(second).unwrap();
    let alice_key = frost::keys::KeyPackage::try_from(shares[&alice_id].clone()).unwrap();
    let bob_key = frost::keys::KeyPackage::try_from(shares[&bob_id].clone()).unwrap();
    let ak: [u8; 32] = public
        .verifying_key()
        .serialize()
        .unwrap()
        .try_into()
        .unwrap();
    let fvk = vault::test_only_fvk(&ak).unwrap();
    let notes = [10u8, 20]
        .into_iter()
        .zip([625_000_000, 100_000_000])
        .map(|(seed, value)| {
            let rho = Rho::from_bytes(&[seed + 1; 32]).unwrap();
            let rseed = RandomSeed::from_bytes([seed + 2; 32], &rho).unwrap();
            Note::from_parts(
                fvk.address_at(0u64, Scope::External),
                NoteValue::from_raw(value),
                rho,
                rseed,
                NoteVersion::V3,
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let recipient = fvk.address_at(7u64, Scope::External);
    let memo = b"two spend approved payment".to_vec();
    let amount = 700_000_000u64;
    let mut inputs = CandidateInputs {
        vault_fvk: &fvk,
        notes: notes.clone(),
        recipient,
        amount: Zatoshis::const_from_u64(amount),
        memo: MemoBytes::from_bytes(&memo).unwrap(),
        change: Zatoshis::ZERO,
        target_height: 700,
        expiry_height: 1_152,
    };
    let fee = u64::from(quote_fee(&Regtest, &inputs).unwrap());
    let change = 725_000_000 - amount - fee;
    inputs.change = Zatoshis::const_from_u64(change);
    let intent = Intent {
        proposer: alice_id.serialize(),
        created_height: 700,
        input_nullifiers: notes
            .iter()
            .map(|note| note.nullifier(&fvk).to_bytes())
            .collect(),
        recipient: recipient.to_raw_address_bytes().to_vec(),
        amount_zat: amount,
        memo: memo.clone(),
        change_policy: ChangePolicy::VaultInternal,
        fee_zat: fee,
        change_zat: change,
        expiry_height: 1_152,
    };
    let ctx = SessionContext {
        vault: ak,
        payment: intent.proposal_id(),
        attempt: AttemptId::random(),
        signers: pair.to_vec(),
    };
    let alice_identity = Identity::new(first);
    let bob_identity = Identity::new(second);
    let observers = (1..=member_count).filter(|id| !pair.contains(id)).collect::<Vec<_>>();
    let carol = Identity::new(observers[0]);
    let other_observer = observers.get(1).map(|id| Identity::new(*id));
    let carol_public = carol.public();
    MemberDir::create(&alice_root, "secrets")
        .unwrap()
        .write_sealed("identity.sealed", &alice_identity.to_secret_bytes(), "pass")
        .unwrap();
    let alice_sender = Identity::from_secret_bytes(&alice_identity.to_secret_bytes()).unwrap();
    let bob_sender = Identity::from_secret_bytes(&bob_identity.to_secret_bytes()).unwrap();
    let alice_public = alice_identity.public();
    let bob_public = bob_identity.public();
    let mut alice = SigningSession::begin(
        &alice_root,
        ctx.clone(),
        &ak,
        intent.clone(),
        alice_identity,
        alice_key.clone(),
        public.clone(),
        fvk.clone(),
        2,
    )
    .unwrap();
    let duplicate_relay_key = SigningSession::begin_sealed(
        &root.join("duplicate-relay-key"),
        ctx.clone(),
        &ak,
        intent.clone(),
        Identity::from_secret_bytes(&bob_identity.to_secret_bytes()).unwrap(),
        bob_key.clone(),
        public.clone(),
        fvk.clone(),
        2,
        "pass",
        [([7; 32], [8; 32], [15; 32]), ([7; 32], [10; 32], [16; 32])],
    );
    assert!(
        duplicate_relay_key.is_err(),
        "one relay signing key must not count as two nonce witnesses"
    );
    let mut bob = SigningSession::begin_sealed(
        &bob_root,
        ctx.clone(),
        &ak,
        intent.clone(),
        bob_identity,
        bob_key.clone(),
        public.clone(),
        fvk.clone(),
        2,
        "pass",
        [([7; 32], [8; 32], [15; 32]), ([9; 32], [10; 32], [16; 32])],
    )
    .unwrap();
    let mut sets = Vec::new();
    let mut seeds = Vec::new();
    let mut alphas = Vec::new();
    for spend in 0..2 {
        let set = BTreeMap::from([
            (alice_id, alice.commitments()[spend].clone()),
            (bob_id, bob.commitments()[spend].clone()),
        ]);
        let (randomized, seed) = frost_rerandomized::RandomizedParams::new_from_commitments(
            public.verifying_key(),
            &set,
            rand_core::OsRng,
        )
        .unwrap();
        let alpha_bytes: [u8; 32] = randomized.randomizer().serialize().try_into().unwrap();
        alphas.push(alpha_from_canonical_bytes(&alpha_bytes).unwrap());
        sets.push(set);
        seeds.push(seed.try_into().unwrap());
    }
    let candidate_for = |payment_amount, change_amount| {
        let candidate_inputs = CandidateInputs {
            vault_fvk: &fvk,
            notes: notes.clone(),
            recipient,
            amount: Zatoshis::const_from_u64(payment_amount),
            memo: MemoBytes::from_bytes(&memo).unwrap(),
            change: Zatoshis::const_from_u64(change_amount),
            target_height: 700,
            expiry_height: 1_152,
        };
        let built = build_candidate(
            &Regtest,
            &candidate_inputs,
            &alphas,
            rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng),
        )
        .unwrap();
        let pczt = Creator::build_from_parts(built.pczt_parts).unwrap();
        IoFinalizer::new(pczt)
            .finalize_io()
            .unwrap()
            .serialize()
            .unwrap()
    };
    let candidate = candidate_for(amount, change);
    let send_to_bob = |payload: PackagePayload| {
        let body = payload.encode(&ctx).unwrap();
        let wire = alice_sender
            .seal_session(&bob_public, &ctx, MessageKind::Package, &body)
            .unwrap();
        bob_sender.open_session(&alice_public, &ctx, &wire).unwrap()
    };
    let honest = PackagePayload {
        candidate: candidate.clone(),
        commitments: sets.clone(),
        seeds: seeds.clone(),
    };
    let wrong_effects = send_to_bob(PackagePayload {
        candidate: candidate_for(amount + 1, change - 1),
        commitments: sets.clone(),
        seeds: seeds.clone(),
    });
    assert!(bob.review_package(&wrong_effects, &alice_public).is_err());
    let mut wrong_seeds = seeds.clone();
    wrong_seeds[1][0] ^= 1;
    let wrong_seed = send_to_bob(PackagePayload {
        candidate: candidate.clone(),
        commitments: sets.clone(),
        seeds: wrong_seeds,
    });
    assert!(bob.review_package(&wrong_seed, &alice_public).is_err());
    let mut wrong_sets = sets.clone();
    let (_, other_commitment) =
        frost::round1::commit(bob_key.signing_share(), &mut rand_core::OsRng);
    wrong_sets[1].insert(bob_id, other_commitment);
    let wrong_commitment = send_to_bob(PackagePayload {
        candidate: candidate.clone(),
        commitments: wrong_sets,
        seeds: seeds.clone(),
    });
    assert!(bob
        .review_package(&wrong_commitment, &alice_public)
        .is_err());
    let mut roster = BTreeMap::from([
        (first, alice_public.clone()),
        (second, bob_public.clone()),
        (carol_public.id, carol_public.clone()),
    ]);
    if let Some(other) = &other_observer {
        roster.insert(other.public().id, other.public());
    }
    let package_hashes = alice
        .publish_package_to_roster(&roster, &honest, &mailbox, "pass")
        .unwrap();
    let good = mailbox
        .read_for(&bob_sender, &roster, &ctx)
        .unwrap()
        .into_iter()
        .find(|message| message.wire_hash() == package_hashes[0])
        .unwrap();
    let bob_attempt = bob_root
        .join(hex::encode(ctx.payment))
        .join(hex::encode(ctx.attempt.0));
    let reviewed = bob.review_package(&good, &alice_public).unwrap();
    assert!(bob
        .publish_approved_secured_to_roster(
            reviewed,
            &alice_public,
            &roster,
            &mailbox,
            "pass",
            &mut WrongRelays
        )
        .is_err());
    assert!(!bob_attempt.join("decision").exists());
    let reviewed = bob.review_package(&good, &alice_public).unwrap();
    assert!(bob
        .publish_approved_secured(
            reviewed,
            &alice_public,
            &carol_public,
            &mailbox,
            "pass",
            &mut ReprovisionedMailbox,
        )
        .is_err());
    assert!(!bob_attempt.join("decision").exists());
    assert!(!bob_attempt.join("share.sealed").exists());
    let reviewed = bob.review_package(&good, &alice_public).unwrap();
    assert_eq!(reviewed.summary().vault, ak);
    assert_eq!(reviewed.summary().payment, intent.proposal_id());
    assert_eq!(reviewed.summary().attempt, ctx.attempt);
    assert_eq!(reviewed.summary().signers, pair);
    assert_eq!(
        reviewed.summary().recipient,
        recipient.to_raw_address_bytes()
    );
    assert_eq!(reviewed.summary().amount_zat, amount);
    assert_eq!(reviewed.summary().memo, memo);
    assert_eq!(reviewed.summary().fee_zat, fee);
    assert_eq!(reviewed.summary().change_zat, change);
    assert_eq!(reviewed.summary().expiry_height, 1_152);
    assert_eq!(reviewed.summary().input_nullifiers, intent.input_nullifiers);
    assert!(bob_attempt.join("nonces.sealed").exists());
    let old_root = root.join("bob-old");
    let old_attempt = old_root
        .join(hex::encode(ctx.payment))
        .join(hex::encode(ctx.attempt.0));
    fs::create_dir_all(&old_attempt).unwrap();
    for name in ["started", "nonces.sealed"] {
        fs::copy(bob_attempt.join(name), old_attempt.join(name)).unwrap();
    }
    let bad_root = root.join("bob-duplicate-relay-key-restore");
    let bad_attempt = bad_root
        .join(hex::encode(ctx.payment))
        .join(hex::encode(ctx.attempt.0));
    let bad_dir = MemberDir::create(
        &bad_root.join(hex::encode(ctx.payment)),
        &hex::encode(ctx.attempt.0),
    )
    .unwrap();
    fs::copy(bob_attempt.join("started"), bad_attempt.join("started")).unwrap();
    let mut bad_nonces = MemberDir::open(
        &bob_root.join(hex::encode(ctx.payment)),
        &hex::encode(ctx.attempt.0),
    )
    .read_sealed("nonces.sealed", "pass")
    .unwrap();
    bad_nonces[97..129].copy_from_slice(&[7; 32]);
    bad_dir
        .write_sealed("nonces.sealed", &bad_nonces, "pass")
        .unwrap();
    let legacy_root = root.join("bob-v1-nonce-restore");
    let legacy_attempt = legacy_root
        .join(hex::encode(ctx.payment))
        .join(hex::encode(ctx.attempt.0));
    let legacy_dir = MemberDir::create(
        &legacy_root.join(hex::encode(ctx.payment)),
        &hex::encode(ctx.attempt.0),
    )
    .unwrap();
    fs::copy(bob_attempt.join("started"), legacy_attempt.join("started")).unwrap();
    // v1 records contain relay key and run, but no mailbox binding. They must fail closed.
    let current_nonces = MemberDir::open(
        &bob_root.join(hex::encode(ctx.payment)),
        &hex::encode(ctx.attempt.0),
    )
    .read_sealed("nonces.sealed", "pass")
    .unwrap();
    let mut legacy_nonces = Vec::from([1u8]);
    legacy_nonces.extend_from_slice(&current_nonces[1..65]);
    legacy_nonces.extend_from_slice(&current_nonces[97..161]);
    legacy_nonces.extend_from_slice(&current_nonces[193..]);
    legacy_dir
        .write_sealed("nonces.sealed", &legacy_nonces, "pass")
        .unwrap();
    assert_eq!(
        SigningSession::reopen_sealed(
            &legacy_root,
            ctx.clone(),
            &ak,
            intent.clone(),
            Identity::from_secret_bytes(&bob_sender.to_secret_bytes()).unwrap(),
            bob_key.clone(),
            public.clone(),
            fvk.clone(),
            "pass"
        )
        .err()
        .as_deref(),
        Some("invalid sealed nonce record")
    );
    assert!(SigningSession::reopen_sealed(
        &bad_root,
        ctx.clone(),
        &ak,
        intent.clone(),
        Identity::from_secret_bytes(&bob_sender.to_secret_bytes()).unwrap(),
        bob_key.clone(),
        public.clone(),
        fvk.clone(),
        "pass"
    )
    .is_err());
    assert!(SigningSession::reopen_sealed(
        &bob_root,
        ctx.clone(),
        &ak,
        intent.clone(),
        Identity::from_secret_bytes(&bob_sender.to_secret_bytes()).unwrap(),
        bob_key.clone(),
        public.clone(),
        fvk.clone(),
        "pass"
    )
    .is_err()); // A second tab cannot open the same nonce set while Bob is active.
    drop(bob);
    let mut bob = SigningSession::reopen_sealed(
        &bob_root,
        ctx.clone(),
        &ak,
        intent.clone(),
        Identity::from_secret_bytes(&bob_sender.to_secret_bytes()).unwrap(),
        bob_key.clone(),
        public.clone(),
        fvk.clone(),
        "pass",
    )
    .unwrap();
    let reviewed = bob.review_package(&good, &alice_public).unwrap();
    let token = reviewed.review_token();
    let mut swapped = token;
    swapped[0] ^= 1;
    let nonce_bytes = std::fs::read(bob_attempt.join("nonces.sealed")).unwrap();
    assert!(reviewed.require_review_token(swapped).is_err());
    assert_eq!(
        std::fs::read(bob_attempt.join("nonces.sealed")).unwrap(),
        nonce_bytes
    );
    assert!(!bob_attempt.join("decision").exists());
    assert!(!bob_attempt.join("share.sealed").exists());
    reviewed.require_review_token(token).unwrap();
    assert!(!bob_attempt.join("share.sealed").exists());
    assert!(mailbox
        .read_for(
            &alice_sender,
            &BTreeMap::from([(first, alice_public.clone()), (second, bob_public.clone())]),
            &ctx
        )
        .unwrap()
        .is_empty());
    assert!(mailbox
        .read_for(
            &carol,
            &roster,
            &ctx
        )
        .unwrap()
        .iter()
        .all(|message| message.kind() != MessageKind::Share));

    let mut witness = FirstWriter::default();
    let bob_share_hash = bob
        .publish_approved_secured_to_roster(
            reviewed,
            &alice_public,
            &roster,
            &mailbox,
            "pass",
            &mut witness,
        )
        .unwrap();
    assert_eq!(witness.0.len(), 2);
    assert!(!bob_attempt.join("nonces.sealed").exists());
    assert!(SigningSession::reopen_sealed(
        &bob_root,
        ctx.clone(),
        &ak,
        intent.clone(),
        Identity::from_secret_bytes(&bob_sender.to_secret_bytes()).unwrap(),
        bob_key.clone(),
        public.clone(),
        fvk.clone(),
        "pass"
    )
    .is_err());
    let mut restored = SigningSession::reopen_sealed(
        &old_root,
        ctx.clone(),
        &ak,
        intent.clone(),
        Identity::from_secret_bytes(&bob_sender.to_secret_bytes()).unwrap(),
        bob_key.clone(),
        public.clone(),
        fvk.clone(),
        "pass",
    )
    .unwrap();
    let restored_review = restored.review_package(&good, &alice_public).unwrap();
    assert!(restored
        .publish_approved_secured_to_roster(
            restored_review,
            &alice_public,
            &roster,
            &mailbox,
            "pass",
            &mut witness
        )
        .is_err());
    assert!(!old_attempt.join("share.sealed").exists());
    let bob_saved = SigningSession::saved_share_wires(&bob_root, &ctx, second, "pass").unwrap();
    let forged_bob_wire = {
        let opened = carol
            .open_session(&bob_public, &ctx, &bob_saved[1])
            .unwrap();
        let mut body = opened.body().to_vec();
        let first_len = u16::from_be_bytes(body[99..101].try_into().unwrap()) as usize;
        let second_len_at = 101 + first_len;
        let second_len =
            u16::from_be_bytes(body[second_len_at..second_len_at + 2].try_into().unwrap()) as usize;
        let second_start = second_len_at + 2;
        body[second_start] ^= 1;
        assert!(frost::round2::SignatureShare::deserialize(
            &body[second_start..second_start + second_len]
        )
        .is_ok());
        bob_sender
            .seal_session(&carol_public, &ctx, MessageKind::Share, &body)
            .unwrap()
    };
    let bob_wire = fs::read(root.join("relay").join(hex::encode(bob_share_hash))).unwrap();
    drop(bob);
    assert_eq!(
        SigningSession::recover_share(&bob_root, &ctx, second, "pass", &mailbox).unwrap(),
        bob_share_hash
    );
    assert_eq!(
        fs::read(root.join("relay").join(hex::encode(bob_share_hash))).unwrap(),
        bob_wire
    );
    assert_eq!(
        SigningSession::saved_share_wires(&bob_root, &ctx, second, "pass").unwrap(),
        bob_saved
    );
    assert_eq!(bob_saved[0], bob_wire);
    assert_eq!(
        fs::read(
            root.join("relay")
                .join(hex::encode(blake3::hash(&bob_saved[1]).as_bytes()))
        )
        .unwrap(),
        bob_saved[1]
    );
    let package_for_alice = {
        let body = PackagePayload {
            candidate: candidate.clone(),
            commitments: sets.clone(),
            seeds: seeds.clone(),
        }
        .encode(&ctx)
        .unwrap();
        let wire = bob_sender
            .seal_session(&alice_public, &ctx, MessageKind::Package, &body)
            .unwrap();
        mailbox.append(&wire).unwrap();
        alice_sender.open_session(&bob_public, &ctx, &wire).unwrap()
    };
    let alice_review = alice
        .review_package(&package_for_alice, &bob_public)
        .unwrap();
    assert_eq!(
        alice_review.summary().candidate_hash,
        *blake3::hash(&candidate).as_bytes()
    );
    let sighash = alice_review.summary().sighash;
    let finishers = roster.values().filter(|identity| !pair.contains(&identity.id))
        .cloned().collect::<Vec<_>>();
    alice
        .publish_approved(
            alice_review,
            &bob_public,
            &finishers,
            &mailbox,
            "pass",
        )
        .unwrap();
    drop(alice);
    drop(good);
    drop(honest);
    drop(wrong_effects);
    drop(wrong_seed);
    drop(wrong_commitment);
    drop(package_for_alice);
    drop(alice_sender);
    drop(bob_sender);
    drop(alice_key);
    drop(bob_key);
    drop(shares);
    drop(candidate);
    drop(sets);
    drop(seeds);
    drop(alphas);
    drop(inputs);
    drop(notes);
    let inbox = mailbox.read_for(&carol, &roster, &ctx).unwrap();
    let package = inbox
        .iter()
        .find(|m| m.kind() == MessageKind::Package)
        .unwrap();
    let package = PackagePayload::decode(&ctx, package.body()).unwrap();
    let shares = inbox
        .iter()
        .filter(|m| m.kind() == MessageKind::Share)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(shares.len(), 2);
    let (signed, checked_sighash, indices) = aggregate_and_apply(
        &ctx,
        &intent,
        &ak,
        &public,
        &fvk,
        &package,
        &[shares[0].clone(), shares[1].clone()],
    )
    .unwrap();
    assert_eq!(checked_sighash, sighash);
    assert_eq!(indices.len(), 2);
    assert!(indices
        .iter()
        .all(|i| signed.ironwood().actions()[*i].spend().witness().is_none()));
    if let Some(other) = &other_observer {
        let inbox = mailbox.read_for(other, &roster, &ctx).unwrap();
        let payload = PackagePayload::decode(&ctx,
            inbox.iter().find(|message| message.kind() == MessageKind::Package).unwrap().body(),
        ).unwrap();
        let shares: [loki_poc::signing_session::OpenedMessage; 2] = inbox.into_iter()
            .filter(|message| message.kind() == MessageKind::Share)
            .collect::<Vec<_>>().try_into().unwrap();
        let (_, other_sighash, indices) = aggregate_and_apply(
            &ctx, &intent, &ak, &public, &fvk, &payload, &shares,
        ).unwrap();
        assert_eq!(other_sighash, sighash);
        assert_eq!(indices.len(), 2);
    }
    let forged = carol
        .open_session(&roster[&second], &ctx, &forged_bob_wire)
        .unwrap();
    let alice_share = shares.iter().find(|m| m.sender() == first).unwrap().clone();
    let error = aggregate_and_apply(
        &ctx,
        &intent,
        &ak,
        &public,
        &fvk,
        &package,
        &[alice_share, forged],
    )
    .err()
    .expect("authenticated invalid Bob share must refuse the whole batch");
    assert!(error.contains(&format!("member {second}")), "{error}");
    let restarted = Identity::from_secret_bytes(
        &MemberDir::open(&alice_root, "secrets")
            .read_sealed("identity.sealed", "pass")
            .unwrap(),
    )
    .unwrap();
    let saved = SigningSession::saved_share_wires(&alice_root, &ctx, first, "pass").unwrap();
    let own_share = restarted
        .open_sent_session(&roster[&second], &ctx, &saved[0])
        .unwrap();
    let alice_inbox = mailbox.read_for(&restarted, &roster, &ctx).unwrap();
    let peer_share = alice_inbox
        .iter()
        .find(|m| m.kind() == MessageKind::Share)
        .unwrap()
        .clone();
    let package = alice_inbox
        .iter()
        .find(|m| m.kind() == MessageKind::Package)
        .unwrap();
    let package = PackagePayload::decode(&ctx, package.body()).unwrap();
    let (_, restarted_sighash, restarted_indices) = aggregate_and_apply(
        &ctx,
        &intent,
        &ak,
        &public,
        &fvk,
        &package,
        &[own_share.clone(), peer_share.clone()],
    )
    .unwrap();
    assert_eq!(restarted_sighash, sighash);
    assert_eq!(restarted_indices.len(), 2);
    let sent_wires = SigningSession::saved_package_wires(&alice_root, &ctx, first, "pass").unwrap();
    let sent_package = restarted
        .open_sent_session(&roster[&second], &ctx, &sent_wires[0])
        .unwrap();
    let sent_package = PackagePayload::decode(&ctx, sent_package.body()).unwrap();
    let (_, publisher_sighash, publisher_indices) = aggregate_and_apply(
        &ctx,
        &intent,
        &ak,
        &public,
        &fvk,
        &sent_package,
        &[own_share, peer_share],
    )
    .unwrap();
    assert_eq!(publisher_sighash, sighash);
    assert_eq!(publisher_indices.len(), 2);
    fs::remove_dir_all(root).unwrap();
}
