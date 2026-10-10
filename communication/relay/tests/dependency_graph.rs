use std::{path::Path, process::Command};

#[test]
fn server_excludes_wallet_and_client_dependencies() {
    let repository_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("relay package is inside communication at the repository root");
    let output = Command::new(env!("CARGO"))
        .current_dir(repository_root)
        .args([
            "tree",
            "--manifest-path",
            "communication/Cargo.toml",
            "-p",
            "loki-relay-server",
            "--locked",
            "--edges",
            "normal,build",
            "--prefix",
            "none",
        ])
        .output()
        .expect("cargo tree must run");
    assert!(
        output.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let graph = String::from_utf8(output.stdout).expect("cargo tree emits UTF-8");
    let forbidden: Vec<_> = graph
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| {
            matches!(
                *name,
                "loki-poc"
                    | "loki-relay-client"
                    | "hpke"
                    | "x25519-dalek"
                    | "orchard"
                    | "pczt"
                    | "reddsa"
            ) || name.starts_with("zakura-")
                || name.starts_with("frost-")
        })
        .collect();
    assert!(forbidden.is_empty(), "forbidden packages: {forbidden:?}");
}
