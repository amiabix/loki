use loki_poc::setup_transport::Identity;

#[test]
fn round_two_is_private_and_bound_to_sender_recipient_and_vault() {
    let alice = Identity::new(1);
    let bob = Identity::new(2);
    let carol = Identity::new(3);
    let vault = [7u8; 32];
    let sealed = alice
        .seal_round2(&bob.public(), &vault, b"bob's DKG share")
        .unwrap();
    assert!(!sealed.windows(15).any(|w| w == b"bob's DKG share"));
    assert_eq!(
        bob.open_round2(&alice.public(), &vault, &sealed).unwrap(),
        b"bob's DKG share"
    );
    assert!(carol.open_round2(&alice.public(), &vault, &sealed).is_err());
    assert!(bob
        .open_round2(&alice.public(), &[8u8; 32], &sealed)
        .is_err());
    assert!(bob.open_round2(&carol.public(), &vault, &sealed).is_err());
    let mut tampered = sealed.clone();
    tampered[80] ^= 1;
    assert!(bob.open_round2(&alice.public(), &vault, &tampered).is_err());
}

#[test]
fn public_round_one_is_signed_and_vault_bound() {
    let alice = Identity::new(1);
    let bob = Identity::new(2);
    let vault = [9u8; 32];
    let message = alice.sign_round1(&vault, b"round-one package").unwrap();
    assert_eq!(
        bob.verify_round1(&alice.public(), &vault, &message)
            .unwrap(),
        b"round-one package"
    );
    assert!(bob
        .verify_round1(&alice.public(), &[8u8; 32], &message)
        .is_err());
    let mut tampered = message;
    tampered[50] ^= 1;
    assert!(bob
        .verify_round1(&alice.public(), &vault, &tampered)
        .is_err());
}

#[test]
fn identity_round_trips_for_a_member_only_sealed_store() {
    let alice = Identity::new(1);
    let restored = Identity::from_secret_bytes(&alice.to_secret_bytes()).unwrap();
    assert_eq!(restored.public(), alice.public());
    assert!(Identity::from_secret_bytes(&[0u8; 65]).is_err());
}
