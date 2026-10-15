use loki_poc::{
    candidate::{alpha_from_canonical_bytes, build_candidate, quote_fee, CandidateInputs, Regtest},
    intent::{ChangePolicy, Intent},
    setup_transport::Identity,
    signing_session::{
        aggregate_and_apply, commitments_from_message, AttemptId, Mailbox, MessageKind,
        PackagePayload, SessionContext, SigningSession,
    },
    vault,
};
use orchard::{
    keys::Scope,
    note::{RandomSeed, Rho},
    value::NoteValue,
    Note, NoteVersion,
};
use reddsa_frost::frost::redpallas as frost;
use std::{collections::BTreeMap, fs};
use zcash_protocol::{memo::MemoBytes, value::Zatoshis};

fn scratch() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "loki-signing-test-{}",
        hex::encode(AttemptId::random().0)
    ));
    fs::create_dir(&dir).unwrap();
    dir
}

fn note(fvk: &orchard::keys::FullViewingKey, seed: u8) -> Note {
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
}

#[test]
fn signing_attempt_end_to_end() {
    run_signing_attempt(3, [1, 2], false);
}

#[test]
fn four_member_vault_delivers_a_valid_payment_to_both_finishers() {
    run_signing_attempt(4, [1, 4], false);
}

#[test]
fn secured_four_member_approvals_reach_both_finishers_for_every_pair() {
    for pair in [[1, 2], [1, 3], [1, 4], [2, 3], [2, 4], [3, 4]] {
        run_signing_attempt(4, pair, true);
    }
}

#[test]
fn secured_three_member_approvals_keep_the_existing_finisher_and_retry() {
    run_signing_attempt(3, [1, 2], true);
}

#[derive(Default)]
struct FreshClaims(std::collections::BTreeSet<[u8; 32]>);
impl loki_poc::signing_session::NonceWitness for FreshClaims {
    fn pins(&self) -> loki_poc::signing_session::WitnessPins {
        [([7; 32], [8; 32], [15; 32]), ([9; 32], [10; 32], [16; 32])]
    }
    fn claim(&mut self, cid: [u8; 32], _: &[u8]) -> Result<(), String> {
        if self.0.insert(cid) { Ok(()) } else { Err("already claimed".into()) }
    }
}

fn run_signing_attempt(member_count: u16, pair: [u16; 2], secured: bool) {
    let [first_signer, second_signer] = pair;
    let root = scratch();
    let relay = Mailbox::new(&root.join("relay")).unwrap();
    let (shares, public) = frost::keys::generate_with_dealer(
        member_count,
        2,
        frost::keys::IdentifierList::Default,
        rand_core::OsRng,
    )
    .unwrap();
    let id1 = frost::Identifier::try_from(first_signer).unwrap();
    let id2 = frost::Identifier::try_from(second_signer).unwrap();
    let key1 = frost::keys::KeyPackage::try_from(shares[&id1].clone()).unwrap();
    let key2 = frost::keys::KeyPackage::try_from(shares[&id2].clone()).unwrap();
    let ak: [u8; 32] = public
        .verifying_key()
        .serialize()
        .unwrap()
        .try_into()
        .unwrap();
    let fvk = vault::test_only_fvk(&ak).unwrap();
    let notes = vec![note(&fvk, 1), note(&fvk, 7)];
    let recipient = fvk.address_at(7u64, Scope::External);
    let mut inputs = CandidateInputs {
        vault_fvk: &fvk,
        notes: notes.clone(),
        recipient,
        amount: Zatoshis::const_from_u64(50_000_000),
        memo: MemoBytes::from_bytes(b"member approved payment").unwrap(),
        change: Zatoshis::ZERO,
        target_height: 20,
        expiry_height: 1_152,
    };
    let fee = u64::from(quote_fee(&Regtest, &inputs).unwrap());
    inputs.change = Zatoshis::const_from_u64(10_000_000 - fee);
    let intent = Intent {
        proposer: id1.serialize(),
        created_height: 20,
        input_nullifiers: notes.iter().map(|n| n.nullifier(&fvk).to_bytes()).collect(),
        recipient: recipient.to_raw_address_bytes().to_vec(),
        amount_zat: 50_000_000,
        memo: b"member approved payment".to_vec(),
        change_policy: ChangePolicy::VaultInternal,
        fee_zat: fee,
        change_zat: 10_000_000 - fee,
        expiry_height: 1_152,
    };
    let context = SessionContext {
        vault: [3; 32],
        payment: intent.proposal_id(),
        attempt: AttemptId::random(),
        pair,
    };
    let alice = Identity::new(first_signer);
    let bob = Identity::new(second_signer);
    let observers = (1..=member_count).filter(|id| !pair.contains(id)).collect::<Vec<_>>();
    let carol = Identity::new(observers[0]);
    let other_finisher = observers.get(1).map(|id| Identity::new(*id));
    let alice_copy = Identity::from_secret_bytes(&alice.to_secret_bytes()).unwrap();
    let bob_copy = Identity::from_secret_bytes(&bob.to_secret_bytes()).unwrap();
    let alice_pub = alice.public();
    let bob_pub = bob.public();
    let carol_pub = carol.public();
    let mut roster = BTreeMap::from([
        (first_signer, alice_pub.clone()),
        (second_signer, bob_pub.clone()),
        (carol.public().id, carol_pub.clone()),
    ]);
    if let Some(other) = &other_finisher {
        roster.insert(other.public().id, other.public());
    }
    let begin = |path: &std::path::Path, identity, key, pass| {
        if secured {
            SigningSession::begin_sealed(
                path, context.clone(), &context.vault, intent.clone(), identity, key,
                public.clone(), fvk.clone(), 2, pass,
                [([7; 32], [8; 32], [15; 32]), ([9; 32], [10; 32], [16; 32])],
            )
        } else {
            SigningSession::begin(
                path, context.clone(), &context.vault, intent.clone(), identity, key,
                public.clone(), fvk.clone(), 2,
            )
        }.unwrap()
    };
    let mut a = begin(&root.join("alice"), alice, key1, "alice pass");
    let mut b = begin(&root.join("bob"), bob, key2, "bob pass");

    a.publish_commitments(&bob_pub, &relay).unwrap();
    b.publish_commitments(&alice_pub, &relay).unwrap();
    let a_inbox = relay.read_for(&alice_copy, &roster, &context).unwrap();
    let b_inbox = relay.read_for(&bob_copy, &roster, &context).unwrap();
    let a_peer = commitments_from_message(
        &context,
        a_inbox
            .iter()
            .find(|m| m.kind() == MessageKind::Commitment)
            .unwrap(),
        2,
    )
    .unwrap();
    let b_peer = commitments_from_message(
        &context,
        b_inbox
            .iter()
            .find(|m| m.kind() == MessageKind::Commitment)
            .unwrap(),
        2,
    )
    .unwrap();
    assert_eq!(a_peer, b.commitments());
    assert_eq!(b_peer, a.commitments());

    let mut sets = Vec::new();
    let mut seeds = Vec::new();
    let mut alphas = Vec::new();
    for i in 0..2 {
        let set = BTreeMap::from([
            (id1, a.commitments()[i].clone()),
            (id2, b.commitments()[i].clone()),
        ]);
        let (params, seed) = frost_rerandomized::RandomizedParams::new_from_commitments(
            public.verifying_key(),
            &set,
            rand_core::OsRng,
        )
        .unwrap();
        let bytes: [u8; 32] = params.randomizer().serialize().try_into().unwrap();
        alphas.push(alpha_from_canonical_bytes(&bytes).unwrap());
        sets.push(set);
        seeds.push(seed.try_into().unwrap());
    }
    let built = build_candidate(
        &Regtest,
        &inputs,
        &alphas,
        rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng),
    )
    .unwrap();
    let candidate = pczt::roles::creator::Creator::build_from_parts(built.pczt_parts).unwrap();
    let candidate = pczt::roles::io_finalizer::IoFinalizer::new(candidate)
        .finalize_io()
        .unwrap();
    let payload = PackagePayload {
        candidate: candidate.serialize().unwrap(),
        commitments: sets,
        seeds,
    };

    let mut bad = PackagePayload {
        candidate: payload.candidate.clone(),
        commitments: payload.commitments.clone(),
        seeds: payload.seeds.clone(),
    };
    bad.seeds[1][0] ^= 1;
    let bad_wire = bob_copy
        .seal_session(
            &alice_pub,
            &context,
            MessageKind::Package,
            &bad.encode(&context).unwrap(),
        )
        .unwrap();
    relay.append(&bad_wire).unwrap();
    let bad_inbox = relay.read_for(&alice_copy, &roster, &context).unwrap();
    let bad_message = bad_inbox
        .iter()
        .find(|m| m.wire_hash() == *blake3::hash(&bad_wire).as_bytes())
        .unwrap();
    assert!(a.review_package(bad_message, &bob_pub).is_err());
    assert!(bad_inbox.iter().all(|m| m.kind() != MessageKind::Share));

    let from_alice = a
        .publish_package_to_roster(&roster, &payload, &relay, "alice pass")
        .unwrap();
    let saved_package =
        SigningSession::saved_package_wires(&root.join("alice"), &context, first_signer, "alice pass")
            .unwrap();
    let a_message = alice_copy
        .open_sent_session(&bob_pub, &context, &saved_package[0])
        .unwrap();
    let a_inbox = relay.read_for(&alice_copy, &roster, &context).unwrap();
    let b_inbox = relay.read_for(&bob_copy, &roster, &context).unwrap();
    let b_message = b_inbox
        .iter()
        .find(|m| m.wire_hash() == from_alice[0])
        .unwrap();
    let a_review = a.review_package(&a_message, &bob_pub).unwrap();
    let b_review = b.review_package(b_message, &alice_pub).unwrap();
    assert!(a_review
        .require_review_token(a_review.review_token())
        .is_ok());
    assert!(a_review
        .require_review_token(b_review.review_token())
        .is_err());
    assert_eq!(a_review.summary().amount_zat, 50_000_000);
    assert_eq!(b_review.summary().input_nullifiers.len(), 2);
    assert_eq!(
        a_review.summary().candidate_hash,
        b_review.summary().candidate_hash
    );
    assert!(a_inbox.iter().all(|m| m.kind() != MessageKind::Share));
    assert!(b_inbox.iter().all(|m| m.kind() != MessageKind::Share));

    let finishers = roster
        .values()
        .filter(|identity| !context.pair.contains(&identity.id))
        .cloned()
        .collect::<Vec<_>>();
    let a_share_hash = if secured {
        let mut incomplete = roster.clone();
        incomplete.remove(&observers[0]);
        let mut claims = FreshClaims::default();
        let refused = a.review_package(&a_message, &bob_pub).unwrap();
        assert!(a.publish_approved_secured_to_roster(
            refused,
            &bob_pub, &incomplete, &relay, "alice pass", &mut claims,
        ).is_err());
        assert!(claims.0.is_empty());
        let mut substituted = roster.clone();
        substituted.get_mut(&observers[0]).unwrap().signing = alice_pub.signing;
        let refused = a.review_package(&a_message, &bob_pub).unwrap();
        assert!(a.publish_approved_secured_to_roster(
            refused,
            &bob_pub, &substituted, &relay, "alice pass", &mut claims,
        ).is_err());
        assert!(claims.0.is_empty());
        let attempt = root.join("alice")
            .join(hex::encode(context.payment)).join(hex::encode(context.attempt.0));
        assert!(!attempt.join("decision").exists());
        assert!(!attempt.join("share.sealed").exists());
        assert!(attempt.join("nonces.sealed").exists());
        let mut claims = FreshClaims::default();
        let hash = if member_count == 3 {
            a.publish_approved_secured(
                a_review, &bob_pub, &finishers[0], &relay, "alice pass", &mut claims,
            )
        } else {
            a.publish_approved_secured_to_roster(
                a_review, &bob_pub, &roster, &relay, "alice pass", &mut claims,
            )
        }.unwrap();
        assert_eq!(claims.0.len(), 2);
        let mut claims = FreshClaims::default();
        if member_count == 3 {
            b.publish_approved_secured(
                b_review, &alice_pub, &finishers[0], &relay, "bob pass", &mut claims,
            )
        } else {
            b.publish_approved_secured_to_roster(
                b_review, &alice_pub, &roster, &relay, "bob pass", &mut claims,
            )
        }.unwrap();
        assert_eq!(claims.0.len(), 2);
        hash
    } else {
        let hash = a.publish_approved(a_review, &bob_pub, &finishers, &relay, "alice pass").unwrap();
        b.publish_approved(b_review, &alice_pub, &finishers, &relay, "bob pass").unwrap();
        hash
    };
    let saved_before = SigningSession::saved_share_wires(
        &root.join("alice"), &context, first_signer, "alice pass",
    ).unwrap();
    assert_eq!(saved_before.len(), usize::from(member_count - 1));
    drop(a);
    drop(b);

    // Carol loads everything from her own encrypted mailbox after both signers close.
    let carol_inbox = relay.read_for(&carol, &roster, &context).unwrap();
    let carol_package = carol_inbox
        .iter()
        .find(|m| m.wire_hash() == from_alice[1])
        .unwrap();
    let carol_payload = PackagePayload::decode(&context, carol_package.body()).unwrap();
    let carol_shares: [loki_poc::signing_session::OpenedMessage; 2] = carol_inbox
        .into_iter()
        .filter(|m| m.kind() == MessageKind::Share)
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let (signed, sighash, indices) = aggregate_and_apply(
        &context,
        &intent,
        &context.vault,
        &public,
        &fvk,
        &carol_payload,
        &carol_shares,
    )
    .unwrap();
    assert_eq!(indices.len(), 2);
    if let Some(other) = &other_finisher {
        let inbox = relay.read_for(other, &roster, &context).unwrap();
        let package = inbox
            .iter()
            .find(|m| m.kind() == MessageKind::Package)
            .unwrap();
        let payload = PackagePayload::decode(&context, package.body()).unwrap();
        let shares: [loki_poc::signing_session::OpenedMessage; 2] = inbox
            .into_iter()
            .filter(|m| m.kind() == MessageKind::Share)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let (_, other_sighash, _) = aggregate_and_apply(
            &context,
            &intent,
            &context.vault,
            &public,
            &fvk,
            &payload,
            &shares,
        )
        .unwrap();
        assert_eq!(other_sighash, sighash);
    }
    assert_eq!(
        pczt::roles::signer::Signer::new(signed)
            .unwrap()
            .shielded_sighash(),
        sighash
    );

    // Alice can also finish after restart using only her sealed outbound wire and inbox.
    let saved =
        SigningSession::saved_share_wires(&root.join("alice"), &context, first_signer, "alice pass").unwrap();
    let own_share = alice_copy
        .open_sent_session(&bob_pub, &context, &saved[0])
        .unwrap();
    let alice_inbox = relay.read_for(&alice_copy, &roster, &context).unwrap();
    let peer_share = alice_inbox
        .iter()
        .find(|m| m.kind() == MessageKind::Share)
        .unwrap()
        .clone();
    let own_package = alice_copy
        .open_sent_session(&bob_pub, &context, &saved_package[0])
        .unwrap();
    let own_payload = PackagePayload::decode(&context, own_package.body()).unwrap();
    let (_, alice_sighash, alice_indices) = aggregate_and_apply(
        &context,
        &intent,
        &context.vault,
        &public,
        &fvk,
        &own_payload,
        &[own_share, peer_share],
    )
    .unwrap();
    assert_eq!(alice_sighash, sighash);
    assert_eq!(alice_indices.len(), 2);

    assert_eq!(
        SigningSession::recover_share(&root.join("alice"), &context, first_signer, "alice pass", &relay,)
            .unwrap(),
        a_share_hash
    );
    assert_eq!(SigningSession::saved_share_wires(
        &root.join("alice"), &context, first_signer, "alice pass",
    ).unwrap(), saved_before);
    let attempt_dir = root
        .join("alice")
        .join(hex::encode(context.payment))
        .join(hex::encode(context.attempt.0));
    assert!(!fs::read_dir(attempt_dir).unwrap().any(|e| e
        .unwrap()
        .file_name()
        .to_string_lossy()
        .contains("nonce")));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn envelope_hides_context_and_rejects_wrong_attempt() {
    let alice = Identity::new(1);
    let bob = Identity::new(2);
    let context = SessionContext {
        vault: [3; 32],
        payment: [4; 32],
        attempt: AttemptId::random(),
        pair: [1, 2],
    };
    let body = b"private payment and seed";
    let wire = alice
        .seal_session(&bob.public(), &context, MessageKind::Package, body)
        .unwrap();
    assert!(!wire.windows(body.len()).any(|w| w == body));
    assert!(!wire.windows(32).any(|w| w == context.vault));
    assert!(!wire.windows(32).any(|w| w == context.payment));
    assert!(!wire.windows(32).any(|w| w == context.attempt.0));
    assert_eq!(
        bob.open_session(&alice.public(), &context, &wire)
            .unwrap()
            .body(),
        body
    );
    let mut wrong = context.clone();
    wrong.payment[0] ^= 1;
    assert!(bob.open_session(&alice.public(), &wrong, &wire).is_err());
    let mut corrupt = wire;
    corrupt[50] ^= 1;
    assert!(bob
        .open_session(&alice.public(), &context, &corrupt)
        .is_err());
}
