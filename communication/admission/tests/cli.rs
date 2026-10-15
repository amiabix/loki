mod support;
use std::{
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
};
#[test]
fn admission_cli_rejects_secret_values_unknown_flags_and_missing_config() {
    for args in [
        vec!["serve"],
        vec!["serve", "--secret", "must-not-be-logged"],
        vec!["serve", "--root", "/", "--listen", "0.0.0.0:9000"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_loki-setup-admission"))
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.starts_with("admission_error_"));
        assert!(!stderr.contains("must-not-be-logged"));
        assert!(output.stdout.is_empty());
    }
}
#[test]
fn inspect_denies_permissive_secret_file_without_logging_contents() {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let root: PathBuf = std::env::temp_dir().canonicalize().unwrap().join(format!(
        "loki-admission-cli-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir(&root).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    let seed = root.join("signing.seed");
    std::fs::write(&seed, [8; 32]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&seed, std::fs::Permissions::from_mode(0o644)).unwrap();
    }
    let signing = ed25519_dalek::SigningKey::from_bytes(&[90; 32]);
    let bundle = root.join("operator.cbor");
    std::fs::write(&bundle, support::bundle(&signing, |_| {})).unwrap();
    let key = root.join("config.key");
    std::fs::write(&key, signing.verifying_key().to_bytes()).unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_loki-setup-admission"))
        .arg("serve")
        .arg("--root")
        .arg(&root)
        .arg("--bundle-file")
        .arg(&bundle)
        .arg("--config-key-file")
        .arg(&key)
        .arg("--signing-key-file")
        .arg(&seed)
        .arg("--relay-1-provision-file")
        .arg(&seed)
        .arg("--relay-2-provision-file")
        .arg(&seed)
        .arg("--relay-3-provision-file")
        .arg(&seed)
        .arg("--listen")
        .arg("127.0.0.1:9000")
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert_eq!(
        String::from_utf8_lossy(&result.stderr),
        "admission_error_storage\n"
    );
    assert!(result.stdout.is_empty());
    assert!(!String::from_utf8(result.stderr)
        .unwrap()
        .contains("signing.seed"));
    std::fs::remove_dir_all(root).unwrap();
}

struct OwnedChild(Option<std::process::Child>);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}
#[tokio::test]
async fn owned_admission_process_kill_replays_committed_operation_after_restart() {
    use ed25519_dalek::SigningKey;
    use loki_relay_client::AdmissionHttp;
    use support::*;
    let db = OwnedDb::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let origin = format!("http://{address}");
    let cfg = config_with_admission(&origin);
    let signer = SigningKey::from_bytes(&[90; 32]);
    let raw = bundle(&signer, |f| {
        let loki_relay_protocol::canonical::Value::Array(a) = &mut f[2] else {
            panic!()
        };
        a[0] = loki_relay_protocol::canonical::Value::Bytes(origin.as_bytes().to_vec());
    });
    for (name, bytes) in [
        ("operator.cbor", raw),
        ("config.key", signer.verifying_key().to_bytes().to_vec()),
        (
            "issuer.key",
            SigningKey::from_bytes(&[9; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
        ),
        ("signing.seed", vec![8; 32]),
        ("relay.secret", vec![20; 32]),
    ] {
        let path = db.root.join(name);
        std::fs::write(&path, bytes).unwrap();
        if name.ends_with("seed") || name.ends_with("secret") {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
    }
    let spawn = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_loki-setup-admission"));
        command
            .arg("serve")
            .arg("--root")
            .arg(&db.root)
            .arg("--listen")
            .arg(address.to_string())
            .arg("--development");
        for (flag, name) in [
            ("--bundle-file", "operator.cbor"),
            ("--config-key-file", "config.key"),
            ("--issuer-key-file", "issuer.key"),
            ("--signing-key-file", "signing.seed"),
            ("--relay-1-provision-file", "relay.secret"),
            ("--relay-2-provision-file", "relay.secret"),
            ("--relay-3-provision-file", "relay.secret"),
        ] {
            command.arg(flag).arg(db.root.join(name));
        }
        OwnedChild(Some(
            command
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .unwrap(),
        ))
    };
    let mut child = spawn();
    wait_owned_listener(&mut child, address).await;
    let client = AdmissionHttp::development(&cfg).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let g = grant_for(&cfg, 2, 48, now + 3600);
    let req = create_for(1, [70; 32], 4, &g, &cfg);
    let committed = client
        .execute_authenticated(&identity(1, 1), &req, Some(&g))
        .await
        .unwrap()
        .package()
        .to_vec();
    child.0.as_mut().unwrap().kill().unwrap();
    child.0.as_mut().unwrap().wait().unwrap();
    child.0 = None;
    let mut resumed = spawn();
    wait_owned_listener(&mut resumed, address).await;
    assert_eq!(
        client.execute(&req, None).await.unwrap().package(),
        committed
    );
}
async fn wait_owned_listener(child: &mut OwnedChild, address: std::net::SocketAddr) {
    for _ in 0..100 {
        assert!(
            child.0.as_mut().unwrap().try_wait().unwrap().is_none(),
            "owned admission process exited before listening"
        );
        if tokio::net::TcpStream::connect(address).await.is_ok() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("owned admission process did not listen within test deadline");
}
