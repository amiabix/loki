use loki_poc::{
    intent::{ChangePolicy, Intent},
    setup_transport::Identity,
    signing_session::{AttemptId, Mailbox, MessageKind, SessionContext, SigningSession},
    vault,
};
use reddsa_frost::frost::redpallas as frost;
use std::{collections::BTreeMap, fs, sync::Arc, thread};

fn context() -> SessionContext {
    SessionContext {
        vault: [11; 32],
        payment: [22; 32],
        attempt: AttemptId::random(),
        signers: vec![1, 2],
    }
}

fn scratch() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "loki-signing-faults-{}",
        hex::encode(AttemptId::random().0)
    ));
    fs::create_dir(&path).unwrap();
    path
}

#[test]
fn relay_retry_and_reordering_preserve_two_authenticated_messages() {
    let path = scratch();
    let alice = Identity::new(1);
    let bob = Identity::new(2);
    let ctx = context();
    let mailbox = Mailbox::new(&path).unwrap();
    let roster = BTreeMap::from([(1, alice.public()), (2, bob.public())]);
    let invite = alice
        .seal_session(&bob.public(), &ctx, MessageKind::Invite, b"invite")
        .unwrap();
    let package = alice
        .seal_session(
            &bob.public(),
            &ctx,
            MessageKind::Package,
            b"different package",
        )
        .unwrap();

    mailbox.append(&package).unwrap();
    let original_hash = mailbox.append(&invite).unwrap();
    assert_eq!(mailbox.append(&invite).unwrap(), original_hash);
    let messages = mailbox.read_for(&bob, &roster, &ctx).unwrap();
    assert_eq!(messages.len(), 2);
    assert!(messages
        .iter()
        .any(|m| m.kind() == MessageKind::Invite && m.body() == b"invite"));
    assert!(messages
        .iter()
        .any(|m| m.kind() == MessageKind::Package && m.body() == b"different package"));
    fs::write(path.join("junk"), b"malformed relay entry").unwrap();
    assert_eq!(mailbox.read_for(&bob, &roster, &ctx).unwrap().len(), 2);

    for wrong in [
        SessionContext {
            vault: [99; 32],
            ..ctx.clone()
        },
        SessionContext {
            payment: [99; 32],
            ..ctx.clone()
        },
        SessionContext {
            attempt: AttemptId::random(),
            ..ctx.clone()
        },
        SessionContext {
            signers: vec![1, 3],
            ..ctx.clone()
        },
    ] {
        assert!(bob.open_session(&alice.public(), &wrong, &package).is_err());
    }
    let carol = Identity::new(3);
    let finisher_copy = alice
        .seal_session(&carol.public(), &ctx, MessageKind::Package, b"x")
        .unwrap();
    assert_eq!(
        carol
            .open_session(&alice.public(), &ctx, &finisher_copy)
            .unwrap()
            .body(),
        b"x"
    );
    assert!(Identity::new(3)
        .seal_session(&bob.public(), &ctx, MessageKind::Package, b"x")
        .is_err());
    let fourth = Identity::new(4);
    let fourth_copy = alice
        .seal_session(&fourth.public(), &ctx, MessageKind::Package, b"x")
        .unwrap();
    assert_eq!(
        fourth
            .open_session(&alice.public(), &ctx, &fourth_copy)
            .unwrap()
            .body(),
        b"x"
    );
    // Any vault member up to 16 can receive the package; member 17 cannot exist.
    let sixteenth = Identity::new(16);
    let sixteenth_copy = alice
        .seal_session(&sixteenth.public(), &ctx, MessageKind::Package, b"x")
        .unwrap();
    assert_eq!(
        sixteenth
            .open_session(&alice.public(), &ctx, &sixteenth_copy)
            .unwrap()
            .body(),
        b"x"
    );
    let mut seventeenth = Identity::new(16).public();
    seventeenth.id = 17;
    assert!(alice
        .seal_session(&seventeenth, &ctx, MessageKind::Package, b"x")
        .is_err());
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn largest_package_survives_encryption_and_mailbox_delivery() {
    let path = scratch();
    let alice = Identity::new(1);
    let bob = Identity::new(2);
    let ctx = context();
    let mailbox = Mailbox::new(&path).unwrap();
    let body = vec![0x5a; MessageKind::Package.max_body()];
    let mut oversized = body.clone();
    oversized.push(0);
    assert!(alice
        .seal_session(&bob.public(), &ctx, MessageKind::Package, &oversized)
        .is_err());
    let wire = alice
        .seal_session(&bob.public(), &ctx, MessageKind::Package, &body)
        .unwrap();
    mailbox.append(&wire).unwrap();
    let messages = mailbox
        .read_for(
            &bob,
            &BTreeMap::from([(1, alice.public()), (2, bob.public())]),
            &ctx,
        )
        .unwrap();
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].body(), body);
    fs::remove_dir_all(path).unwrap();
}

#[test]
fn concurrent_start_has_one_winner_and_crash_before_share_requires_new_attempt() {
    let path = scratch();
    let (shares, public) = frost::keys::generate_with_dealer(
        3,
        2,
        frost::keys::IdentifierList::Default,
        rand_core::OsRng,
    )
    .unwrap();
    let key = frost::keys::KeyPackage::try_from(
        shares[&frost::Identifier::try_from(1u16).unwrap()].clone(),
    )
    .unwrap();
    let ak: [u8; 32] = public
        .verifying_key()
        .serialize()
        .unwrap()
        .try_into()
        .unwrap();
    let fvk = vault::test_only_fvk(&ak).unwrap();
    let intent = Intent {
        proposer: key.identifier().serialize(),
        created_height: 700,
        input_nullifiers: vec![[7; 32]],
        recipient: vec![8; 43],
        amount_zat: 1,
        memo: b"approved payment".to_vec(),
        change_policy: ChangePolicy::VaultInternal,
        fee_zat: 1,
        change_zat: 1,
        expiry_height: 1_152,
    };
    let mut ctx = context();
    ctx.vault = ak;
    ctx.payment = intent.proposal_id();
    let path = Arc::new(path);
    let ctx = Arc::new(ctx);
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let path = Arc::clone(&path);
            let ctx = Arc::clone(&ctx);
            let key = key.clone();
            let public = public.clone();
            let fvk = fvk.clone();
            let intent = intent.clone();
            thread::spawn(move || {
                SigningSession::begin(
                    &path,
                    (*ctx).clone(),
                    &ak,
                    intent,
                    Identity::new(1),
                    key,
                    public,
                    fvk,
                    1,
                )
                .is_ok()
            })
        })
        .collect();
    assert_eq!(
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|ok| *ok)
            .count(),
        1
    );

    let stored = path
        .join(hex::encode(ctx.payment))
        .join(hex::encode(ctx.attempt.0));
    let names: Vec<_> = fs::read_dir(&stored)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names, ["started"]);
    let mailbox = Mailbox::new(&path.join("mailbox")).unwrap();
    assert!(SigningSession::recover_share(&path, &ctx, 1, "pass", &mailbox).is_err());
    let mut fresh = (*ctx).clone();
    fresh.attempt = AttemptId::random();
    assert!(SigningSession::begin(
        &path,
        fresh,
        &ak,
        intent,
        Identity::new(1),
        key,
        public,
        fvk,
        1,
    )
    .is_ok());
    fs::remove_dir_all(path.as_path()).unwrap();
}
