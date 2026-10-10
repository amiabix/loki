use std::process::Command;

fn unit_case(name: &str) {
    let output = Command::new(env!("CARGO"))
        .args([
            "test",
            "--manifest-path",
            concat!(env!("CARGO_MANIFEST_DIR"), "/../Cargo.toml"),
            "-p",
            "loki-relay-server",
            "--locked",
            "--offline",
            "--lib",
            name,
            "--",
            "--exact",
            "--nocapture",
        ])
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    print!("{stdout}{stderr}");
    assert!(output.status.success(), "library fault case failed: {name}");
    assert!(
        stdout.contains("1 passed; 0 failed"),
        "case did not execute: {name}"
    );
}

#[test]
fn relay_commit_fault_preinsert() {
    unit_case("store::fault_tests::relay_commit_fault_preinsert");
}

#[test]
fn relay_commit_fault_afterinsert() {
    unit_case("store::fault_tests::relay_commit_fault_afterinsert");
}

#[test]
fn relay_commit_fault_commit_error() {
    unit_case("store::fault_tests::relay_commit_fault_commit_error");
}

#[test]
fn relay_commit_fault_lostreply() {
    unit_case("store::fault_tests::relay_commit_fault_lostreply");
}

#[test]
fn relay_commit_fault_sqlite_full() {
    unit_case("store::fault_tests::relay_commit_fault_sqlite_full");
}

#[test]
fn relay_commit_fault_process_precommit() {
    unit_case("store::fault_tests::relay_commit_fault_process_precommit");
}

#[test]
fn relay_commit_fault_process_postcommit() {
    unit_case("store::fault_tests::relay_commit_fault_process_postcommit");
}
