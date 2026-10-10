#![cfg(feature = "relay-communication")]
//! Relay payment commands stay off the file mailbox unless file transport is selected.

use std::{
    fs,
    path::PathBuf,
    process::Command,
};

#[test]
fn relay_flag_is_explicit_and_does_not_create_a_mailbox() {
    let pay = env!("CARGO_BIN_EXE_loki_member_payment");
    let root = std::env::temp_dir().join(format!("loki-relay-pay-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    let work = root.join("work");
    fs::create_dir(&work).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&work, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let missing = Command::new(pay)
        .args([
            "sign",
            root.join("missing").to_str().unwrap(),
            root.join("pass").to_str().unwrap(),
            root.join("roster.json").to_str().unwrap(),
            work.to_str().unwrap(),
            "--transport",
            "relay",
        ])
        .output()
        .unwrap();
    assert!(!missing.status.success());
    let error = String::from_utf8(missing.stderr).unwrap();
    assert!(error.starts_with("error:"), "{error}");
    assert!(!error.contains("mailbox"), "{error}");
    assert!(!work.join("mailbox").exists());

    let bad = Command::new(pay)
        .args(["sign", "--transport", "postal"])
        .output()
        .unwrap();
    assert!(!bad.status.success());
    let error = String::from_utf8(bad.stderr).unwrap();
    assert!(error.contains("transport must be file or relay"), "{error}");

    let positional = Command::new(pay).args(["sign"]).output().unwrap();
    let error = String::from_utf8(positional.stderr).unwrap();
    assert!(error.contains("sign <member-dir>"), "{error}");
    let _ = fs::remove_dir_all(&root);
    let _ = PathBuf::from(pay);
}
