use ed25519_dalek::{Signer, SigningKey};
use loki_relay_protocol::canonical::{self, Value};
use std::{
    fs,
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::OnceLock,
    time::{Duration, Instant},
};

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn private_write(path: &Path, bytes: &[u8]) {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}
fn address() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}
fn start(command: &mut Command, address: SocketAddr) -> OwnedChild {
    let mut child = OwnedChild(
        command
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "owned service exited before readiness"
        );
        if TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok() {
            return child;
        }
        assert!(
            Instant::now() < deadline,
            "owned service readiness deadline"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}
fn binaries() -> (PathBuf, PathBuf) {
    static READY: OnceLock<(PathBuf, PathBuf)> = OnceLock::new();
    READY
        .get_or_init(|| {
            let repository = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
            let output = Command::new("cargo")
                .args(["+1.89.0", "build", "--manifest-path"])
                .arg(repository.join("communication/Cargo.toml"))
                .args(["--bins", "--locked", "--offline"])
                .env("CARGO_INCREMENTAL", "0")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "owned communication service build failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            (
                repository.join("communication/target/debug/loki-relay-server"),
                repository.join("communication/target/debug/loki-setup-admission"),
            )
        })
        .clone()
}
pub struct HostedServices {
    pub root: PathBuf,
    pub bundle: Vec<u8>,
    pub config_key: [u8; 32],
    admission_address: SocketAddr,
    admission_command: Command,
    children: Vec<OwnedChild>,
    retain: bool,
}
impl HostedServices {
    pub fn stop_relay(&mut self, index: usize) {
        assert!(index < 3);
        self.children[index].0.kill().unwrap();
        self.children[index].0.wait().unwrap();
    }
    pub fn stop_admission(&mut self) {
        assert_eq!(self.children.len(), 4);
        self.children.pop();
    }
    pub fn restart_admission(&mut self) {
        assert_eq!(self.children.len(), 3);
        self.children
            .push(start(&mut self.admission_command, self.admission_address));
    }
    pub fn start() -> Self {
        if let Some(root) = std::env::var_os("LOKI_HOSTED_RESUME_ROOT") {
            return Self::resume(PathBuf::from(root));
        }
        Self::start_with_limits(86400, 2592000)
    }
    fn resume(root: PathBuf) -> Self {
        assert!(root.is_absolute() && root.canonicalize().unwrap() == root);
        let bundle = fs::read(root.join("operator.cbor")).unwrap();
        let config_key: [u8; 32] = fs::read(root.join("config.key"))
            .unwrap()
            .try_into()
            .unwrap();
        let operators =
            loki_relay_client::OperatorSet::verify_development(&bundle, &config_key).unwrap();
        let (relay_binary, admission_binary) = binaries();
        let mut children = Vec::new();
        let mut provisions = Vec::new();
        for route in operators.relay_routes() {
            let index = (1..=3)
                .find(|index| {
                    let manifest =
                        fs::read_to_string(root.join(format!("relay-{index}/manifest"))).unwrap();
                    manifest.lines().next() == Some(route.endpoint.as_str())
                })
                .expect("saved route must match an owned relay manifest");
            let listen: SocketAddr = route
                .endpoint
                .strip_prefix("http://")
                .unwrap()
                .parse()
                .unwrap();
            let mut command = Command::new(&relay_binary);
            command
                .arg("serve")
                .arg("--root")
                .arg(root.join(format!("relay-{index}")))
                .arg("--listen")
                .arg(listen.to_string());
            children.push((index, start(&mut command, listen)));
            provisions.push(root.join(format!("relay-{index}.secret")));
        }
        children.sort_by_key(|(index, _)| *index);
        let mut children: Vec<_> = children.into_iter().map(|(_, child)| child).collect();
        let admission_address: SocketAddr = operators
            .admission_origin()
            .strip_prefix("http://")
            .unwrap()
            .parse()
            .unwrap();
        let mut command = Command::new(admission_binary);
        command
            .arg("serve")
            .arg("--root")
            .arg(root.join("admission"))
            .arg("--listen")
            .arg(admission_address.to_string())
            .arg("--development");
        for (flag, name) in [
            ("--bundle-file", "operator.cbor"),
            ("--config-key-file", "config.key"),
            ("--issuer-key-file", "issuer.key"),
            ("--signing-key-file", "signing.seed"),
        ] {
            command.arg(flag).arg(root.join(name));
        }
        for (index, provision) in provisions.iter().enumerate() {
            command
                .arg(format!("--relay-{}-provision-file", index + 1))
                .arg(provision);
        }
        children.push(start(&mut command, admission_address));
        Self {
            root,
            bundle,
            config_key,
            admission_address,
            admission_command: command,
            children,
            retain: true,
        }
    }
    pub fn start_with_limits(first_claim_seconds: u64, ceremony_seconds: u64) -> Self {
        let (relay_binary, admission_binary) = binaries();
        let mut random = [0; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut random);
        let selected = std::env::var_os("LOKI_HOSTED_RUN_ROOT");
        let retain = selected.is_some();
        let root = selected.map(PathBuf::from).unwrap_or_else(|| {
            std::env::temp_dir().canonicalize().unwrap().join(format!(
                "loki-owned-hosted-services-{}",
                hex::encode(random)
            ))
        });
        assert!(
            root.is_absolute() && !root.exists(),
            "owned service root must be new"
        );
        assert!(
            root.parent().unwrap().canonicalize().unwrap() == root.parent().unwrap(),
            "owned service root must have a canonical parent"
        );
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut routes = Vec::new();
        let mut children = Vec::new();
        for slot in 1u8..=3 {
            let address = address();
            let relay_root = root.join(format!("relay-{slot}"));
            let provision = root.join(format!("relay-{slot}.secret"));
            let mut secret = [0; 32];
            rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut secret);
            private_write(&provision, &secret);
            let result = Command::new(&relay_binary)
                .arg("init")
                .arg("--root")
                .arg(&relay_root)
                .arg("--listen")
                .arg(address.to_string())
                .arg("--provision-capability-file")
                .arg(&provision)
                .args([
                    "--total-bytes",
                    "268435456",
                    "--mailbox-bytes",
                    "67108864",
                    "--mailbox-count",
                    "1024",
                ])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
            assert!(result.success(), "owned relay init failed");
            let manifest = fs::read_to_string(relay_root.join("manifest")).unwrap();
            let fields: Vec<_> = manifest.lines().collect();
            assert_eq!(fields.len(), 3);
            let route = Value::Array(vec![
                Value::Bytes(hex::decode(fields[2]).unwrap()),
                Value::Bytes(hex::decode(fields[1]).unwrap()),
                Value::Bytes(fields[0].as_bytes().to_vec()),
            ]);
            routes.push((route, provision));
            let mut command = Command::new(&relay_binary);
            command
                .arg("serve")
                .arg("--root")
                .arg(&relay_root)
                .arg("--listen")
                .arg(address.to_string());
            children.push(start(&mut command, address));
        }
        routes.sort_by_key(|(route, _)| canonical::encode(route).unwrap());
        let admission_address = address();
        let admission_origin = format!("http://{admission_address}");
        let signer = SigningKey::from_bytes(&[91; 32]);
        let config_key = signer.verifying_key().to_bytes();
        let body = canonical::encode(&Value::Array(vec![
            Value::Integer(1.into()),
            Value::Array(routes.iter().map(|(route, _)| route.clone()).collect()),
            Value::Array(vec![
                Value::Bytes(admission_origin.as_bytes().to_vec()),
                Value::Bytes(
                    SigningKey::from_bytes(&[8; 32])
                        .verifying_key()
                        .to_bytes()
                        .to_vec(),
                ),
            ]),
            Value::Array(vec![Value::Integer(1.into())]),
            Value::Array(
                [
                    first_claim_seconds,
                    ceremony_seconds,
                    1048576,
                    67108864,
                    5,
                    1,
                    60,
                ]
                .into_iter()
                .map(|n| Value::Integer(n.into()))
                .collect(),
            ),
        ]))
        .unwrap();
        let mut input = b"Loki_Operator_Config_v1\0".to_vec();
        input.extend_from_slice(&(body.len() as u32).to_be_bytes());
        input.extend_from_slice(&body);
        let bundle = canonical::encode(&Value::Array(vec![
            Value::Bytes(body),
            Value::Bytes(signer.sign(&input).to_bytes().to_vec()),
        ]))
        .unwrap();
        for (name, bytes) in [
            ("operator.cbor", bundle.clone()),
            ("config.key", config_key.to_vec()),
            (
                "issuer.key",
                SigningKey::from_bytes(&[9; 32])
                    .verifying_key()
                    .to_bytes()
                    .to_vec(),
            ),
            ("signing.seed", vec![8; 32]),
        ] {
            private_write(&root.join(name), &bytes);
        }
        let admission_root = root.join("admission");
        fs::create_dir(&admission_root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&admission_root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut command = Command::new(admission_binary);
        command
            .arg("serve")
            .arg("--root")
            .arg(&admission_root)
            .arg("--listen")
            .arg(admission_address.to_string())
            .arg("--development");
        for (flag, name) in [
            ("--bundle-file", "operator.cbor"),
            ("--config-key-file", "config.key"),
            ("--issuer-key-file", "issuer.key"),
            ("--signing-key-file", "signing.seed"),
        ] {
            command.arg(flag).arg(root.join(name));
        }
        for (index, (_, provision)) in routes.iter().enumerate() {
            command
                .arg(format!("--relay-{}-provision-file", index + 1))
                .arg(provision);
        }
        children.push(start(&mut command, admission_address));
        Self {
            root,
            bundle,
            config_key,
            admission_address,
            admission_command: command,
            children,
            retain,
        }
    }
}
impl Drop for HostedServices {
    fn drop(&mut self) {
        self.children.clear();
        if !self.retain {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
}
