#![cfg(feature = "relay-communication")]
use loki_poc::{
    setup_relay::install_payment_configuration, setup_transport::Identity, state::MemberDir,
};
use std::fs;

#[test]
fn public_ready_cache_and_bootstrap_identity_cannot_activate_uncertified_payments() {
    for count in [3u16, 4] {
        let identity = Identity::new(count);
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "loki-handoff-uncertified-{}",
            hex::encode(identity.public().signing)
        ));
        let member = MemberDir::create(&root, "member").unwrap();
        let secrets = MemberDir::create(member.path(), "secrets").unwrap();
        secrets
            .write_sealed("identity.sealed", &identity.to_secret_bytes(), "pass")
            .unwrap();
        let before = fs::read(member.path().join("secrets/identity.sealed")).unwrap();
        fs::write(
            member.path().join("setup-status.json"),
            br#"{"phase":"active","handoff":"ready","missing_slots":[]}"#,
        )
        .unwrap();
        assert!(install_payment_configuration(member.path(), "pass").is_err());
        assert_eq!(
            fs::read(member.path().join("secrets/identity.sealed")).unwrap(),
            before
        );
        assert!(!member.path().join("secrets/vault.sealed").exists());
        assert!(!member.path().join("secrets/activation.sealed").exists());
        assert!(!member.path().join("transport").exists());
        drop(secrets);
        drop(member);
        fs::remove_dir_all(root).unwrap();
    }
}
