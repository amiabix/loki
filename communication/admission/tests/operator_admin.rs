use ed25519_dalek::SigningKey;
use loki_relay_client::OperatorSet;
use loki_setup_admission::EnrollmentVerifier;
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

fn scratch() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let path = std::env::temp_dir().join(format!(
        "loki-operator-admin-{}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&path).unwrap();
    path
}

fn seed(path: &Path, byte: u8) {
    fs::write(path, [byte; 32]).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_loki_operator_admin"))
        .args(args)
        .output()
        .unwrap()
}

fn as_str(path: &Path) -> &str {
    path.to_str().unwrap()
}

#[test]
fn signed_https_bundle_and_scoped_grant_verify_with_service_code() {
    let root = scratch();
    let config = root.join("config.seed");
    let admission = root.join("admission.seed");
    let issuer = root.join("issuer.seed");
    seed(&config, 41);
    seed(&admission, 42);
    seed(&issuer, 43);
    let admission_public = root.join("admission-key");
    assert!(
        run(&["pubkey", as_str(&admission), as_str(&admission_public)])
            .status
            .success()
    );
    let manifests: Vec<_> = (1u8..=3)
        .map(|n| {
            let path = root.join(format!("relay-{n}.manifest"));
            fs::write(
                &path,
                format!(
                    "https://relay{n}.example.org\n{}\n{}\n",
                    hex::encode([n; 32]),
                    hex::encode(
                        SigningKey::from_bytes(&[n + 10; 32])
                            .verifying_key()
                            .to_bytes()
                    ),
                ),
            )
            .unwrap();
            path
        })
        .collect();
    let bundle = root.join("bundle");
    let public = root.join("config-key");
    let order = root.join("relay-order");
    assert!(run(&[
        "bundle",
        as_str(&config),
        as_str(&admission_public),
        "https://admission.example.org",
        as_str(&manifests[0]),
        as_str(&manifests[1]),
        as_str(&manifests[2]),
        as_str(&bundle),
        as_str(&public),
        as_str(&order),
    ])
    .status
    .success());
    let public_bytes: [u8; 32] = fs::read(&public).unwrap().try_into().unwrap();
    let signed = fs::read(&bundle).unwrap();
    let set = OperatorSet::verify(&signed, &public_bytes).unwrap();
    assert_eq!(set.admission_origin(), "https://admission.example.org");
    assert_eq!(set.relay_routes().len(), 3);
    let slots: Vec<usize> = fs::read_to_string(&order)
        .unwrap()
        .lines()
        .map(|line| line.parse().unwrap())
        .collect();
    for (route, slot) in set.relay_routes().iter().zip(slots) {
        assert_eq!(route.endpoint, format!("https://relay{slot}.example.org"));
    }
    assert!(!run(&[
        "bundle",
        as_str(&config),
        as_str(&admission_public),
        "https://admission.example.org",
        as_str(&manifests[0]),
        as_str(&manifests[1]),
        as_str(&manifests[2]),
        as_str(&bundle),
        as_str(&public),
        as_str(&order),
    ])
    .status
    .success());

    let issuer_public = root.join("issuer-key");
    assert!(run(&["pubkey", as_str(&issuer), as_str(&issuer_public)])
        .status
        .success());
    let issuer_key: [u8; 32] = fs::read(&issuer_public).unwrap().try_into().unwrap();
    let device = SigningKey::from_bytes(&[60; 32]).verifying_key().to_bytes();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expires = (now + 3600).to_string();
    let grant = root.join("grant");
    assert!(run(&[
        "grant",
        as_str(&issuer),
        as_str(&bundle),
        as_str(&public),
        &hex::encode(device),
        &expires,
        "1",
        "50",
        as_str(&grant),
    ])
    .status
    .success());
    let bytes = fs::read(grant).unwrap();
    let verifier = EnrollmentVerifier::new(Some(issuer_key));
    let budget = verifier.verify(&bytes, &device, now).unwrap();
    assert_eq!(budget.config_digest(), set.digest());
    assert!(verifier.verify(&bytes, &[99; 32], now).is_err());
    let streamed = run(&[
        "grant",
        as_str(&issuer),
        as_str(&bundle),
        as_str(&public),
        &hex::encode(device),
        &expires,
        "1",
        "50",
        "-",
    ]);
    assert!(streamed.status.success());
    assert!(verifier.verify(&streamed.stdout, &device, now).is_ok());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn bundle_rejects_http_and_repeated_relay_run() {
    let root = scratch();
    let config = root.join("config.seed");
    let admission = root.join("admission.seed");
    seed(&config, 41);
    seed(&admission, 42);
    let admission_public = root.join("admission-key");
    assert!(
        run(&["pubkey", as_str(&admission), as_str(&admission_public)])
            .status
            .success()
    );
    let mut manifests = Vec::new();
    for n in 1u8..=3 {
        let path = root.join(format!("relay-{n}.manifest"));
        fs::write(
            &path,
            format!(
                "https://relay{n}.example.org\n{}\n{}\n",
                hex::encode(if n == 3 { [1; 32] } else { [n; 32] }),
                hex::encode(
                    SigningKey::from_bytes(&[n + 10; 32])
                        .verifying_key()
                        .to_bytes()
                ),
            ),
        )
        .unwrap();
        manifests.push(path);
    }
    let out = root.join("bundle");
    let key = root.join("key");
    let order = root.join("relay-order");
    let args = [
        "bundle",
        as_str(&config),
        as_str(&admission_public),
        "https://admission.example.org",
        as_str(&manifests[0]),
        as_str(&manifests[1]),
        as_str(&manifests[2]),
        as_str(&out),
        as_str(&key),
        as_str(&order),
    ];
    assert!(!run(&args).status.success());
    assert!(!out.exists());
    fs::write(
        &manifests[2],
        format!(
            "http://relay3.example.org\n{}\n{}\n",
            hex::encode([3; 32]),
            hex::encode(SigningKey::from_bytes(&[13; 32]).verifying_key().to_bytes()),
        ),
    )
    .unwrap();
    assert!(!run(&args).status.success());
    assert!(!out.exists());
    fs::remove_dir_all(root).unwrap();
}
