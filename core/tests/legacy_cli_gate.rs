use std::process::Command;

#[test]
fn fixed_key_cli_refuses_default_invocation_before_creating_state() {
    let state = std::env::temp_dir().join(format!(
        "loki-legacy-gate-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let output = Command::new(env!("CARGO_BIN_EXE_loki"))
        .args(["setup", state.to_str().unwrap()])
        .env_remove("LOKI_ALLOW_FIXED_VIEWING_KEY")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("LOKI_ALLOW_FIXED_VIEWING_KEY=1"));
    let created = state.exists();
    if created {
        std::fs::remove_dir_all(&state).unwrap();
    }
    assert!(!created);
}

#[test]
fn fixed_key_cli_requires_exact_opt_in() {
    let output = Command::new(env!("CARGO_BIN_EXE_loki"))
        .args(["address", "/no-such-loki-legacy-state"])
        .env("LOKI_ALLOW_FIXED_VIEWING_KEY", "true")
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("LOKI_ALLOW_FIXED_VIEWING_KEY=1"));

    let allowed = Command::new(env!("CARGO_BIN_EXE_loki"))
        .args(["address", "/no-such-loki-legacy-state"])
        .env("LOKI_ALLOW_FIXED_VIEWING_KEY", "1")
        .output()
        .unwrap();
    assert!(!allowed.status.success());
    assert!(String::from_utf8_lossy(&allowed.stderr).contains("run setup first"));
}
