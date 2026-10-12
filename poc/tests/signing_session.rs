use loki_poc::{
    candidate::{alpha_from_canonical_bytes, build_candidate, quote_fee, CandidateInputs, Regtest},
    intent::{ChangePolicy, Intent},
    setup_transport::Identity,
    signing_session::{
        aggregate_and_apply, commitments_from_message, AttemptId, EnvelopeRoute, FileCourier,
        Mailbox, MessageKind, OpenedMessage, PackagePayload, SessionContext, SessionCourier,
        SigningSession,
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

struct RecordingCourier<'a> {
    mailbox: &'a Mailbox,
    published: Vec<(u16, u16, MessageKind, SessionContext, Vec<u8>)>,
}

impl SessionCourier for RecordingCourier<'_> {
    fn publish(&mut self, route: &EnvelopeRoute<'_>, wire: &[u8]) -> Result<[u8; 32], String> {
        self.published.push((
            route.author,
            route.recipient,
            route.kind,
            route.context.clone(),
            wire.to_vec(),
        ));
        FileCourier(self.mailbox).publish(route, wire)
    }

    fn receive(
        &mut self,
        own: &Identity,
        roster: &std::collections::BTreeMap<u16, loki_poc::setup_transport::PublicIdentity>,
        context: &SessionContext,
        kind: MessageKind,
        sender: u16,
    ) -> Result<Option<OpenedMessage>, String> {
        FileCourier(self.mailbox).receive(own, roster, context, kind, sender)
    }

    fn drive_once(&mut self) -> Result<(), String> {
        Ok(())
    }
}

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
    run_signing_attempt(3, 1, 2);
}

#[test]
fn four_member_vault_delivers_a_valid_payment_to_both_finishers() {
    run_signing_attempt(4, 1, 4);
}

#[test]
fn non_alice_signer_pairs_preserve_saved_delivery_routes() {
    run_signing_attempt(3, 2, 3);
    run_signing_attempt(4, 3, 4);
}

fn run_signing_attempt(member_count: u16, first_signer: u16, second_signer: u16) {
    let root = scratch();
    let relay = Mailbox::new(&root.join("relay")).unwrap();
    let mut courier = RecordingCourier {
        mailbox: &relay,
        published: Vec::new(),
    };
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
        pair: [first_signer, second_signer],
    };
    let alice = Identity::new(first_signer);
    let bob = Identity::new(second_signer);
    let remaining = (1..=member_count)
        .filter(|id| !context.pair.contains(id))
        .collect::<Vec<_>>();
    let carol = Identity::new(remaining[0]);
    let other_finisher = remaining.get(1).map(|id| Identity::new(*id));
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
    let mut a = SigningSession::begin(
        &root.join("alice"),
        context.clone(),
        &context.vault,
        intent.clone(),
        alice,
        key1,
        public.clone(),
        fvk.clone(),
        2,
    )
    .unwrap();
    let mut b = SigningSession::begin(
        &root.join("bob"),
        context.clone(),
        &context.vault,
        intent.clone(),
        bob,
        key2,
        public.clone(),
        fvk.clone(),
        2,
    )
    .unwrap();

    a.publish_commitments_with_courier(&bob_pub, &mut courier, "alice pass")
        .unwrap();
    b.publish_commitments_with_courier(&alice_pub, &mut courier, "bob pass")
        .unwrap();
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
        .publish_package_to_roster_with_courier(&roster, &payload, &mut courier, "alice pass")
        .unwrap();
    let package_wires: Vec<_> = courier
        .published
        .iter()
        .filter(|item| item.2 == MessageKind::Package)
        .collect();
    assert_eq!(package_wires.len(), (member_count - 1) as usize);
    assert_ne!(package_wires[0].4, package_wires[1].4);
    assert!(package_wires.iter().all(|item| {
        item.0 == first_signer
            && item.2 == MessageKind::Package
            && item.3 == context
            && roster.contains_key(&item.1)
            && item.1 != first_signer
    }));
    assert_eq!(
        package_wires.iter().map(|item| item.1).collect::<Vec<_>>(),
        std::iter::once(second_signer)
            .chain(
                roster
                    .keys()
                    .copied()
                    .filter(|id| !context.pair.contains(id))
            )
            .collect::<Vec<_>>()
    );
    assert!(courier
        .published
        .iter()
        .all(|item| item.2 != MessageKind::Share));
    let saved_package = SigningSession::saved_package_wires(
        &root.join("alice"),
        &context,
        first_signer,
        "alice pass",
    )
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
    let a_share_hash = a
        .publish_approved_with_courier(a_review, &bob_pub, &finishers, &mut courier, "alice pass")
        .unwrap();
    b.publish_approved_with_courier(b_review, &alice_pub, &finishers, &mut courier, "bob pass")
        .unwrap();
    let alice_shares: Vec<_> = courier
        .published
        .iter()
        .filter(|item| item.0 == first_signer && item.2 == MessageKind::Share)
        .collect();
    assert_eq!(alice_shares.len(), (member_count - 1) as usize);
    assert_ne!(alice_shares[0].4, alice_shares[1].4);
    assert!(alice_shares.iter().all(|item| item.3 == context));
    assert_eq!(
        alice_shares.iter().map(|item| item.1).collect::<Vec<_>>(),
        std::iter::once(second_signer)
            .chain(
                roster
                    .keys()
                    .copied()
                    .filter(|id| !context.pair.contains(id))
            )
            .collect::<Vec<_>>()
    );
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
    let saved = SigningSession::saved_share_wires(
        &root.join("alice"),
        &context,
        first_signer,
        "alice pass",
    )
    .unwrap();
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
        SigningSession::recover_share_with_courier(
            &root.join("alice"),
            &context,
            first_signer,
            "alice pass",
            &mut courier
        )
        .unwrap(),
        a_share_hash
    );
    let recovered = &courier.published[courier.published.len() - saved.len()..];
    let recipients = std::iter::once(second_signer)
        .chain(
            roster
                .keys()
                .copied()
                .filter(|id| !context.pair.contains(id)),
        )
        .collect::<Vec<_>>();
    for ((published, wire), recipient) in recovered.iter().zip(&saved).zip(&recipients) {
        assert_eq!(published.0, first_signer);
        assert_eq!(published.1, *recipient);
        assert_eq!(published.2, MessageKind::Share);
        assert_eq!(&published.4, wire);
    }
    assert_eq!(
        SigningSession::republish_saved_package(
            &root.join("alice"),
            &context,
            &roster,
            first_signer,
            "alice pass",
            &mut courier,
        )
        .unwrap(),
        from_alice
    );
    let recovered = &courier.published[courier.published.len() - saved_package.len()..];
    for ((published, wire), recipient) in recovered.iter().zip(&saved_package).zip(&recipients) {
        assert_eq!(published.1, *recipient);
        assert_eq!(published.2, MessageKind::Package);
        assert_eq!(&published.4, wire);
    }
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
