use ed25519_dalek::{Signer, SigningKey};
use loki_relay_client::OperatorSet;
use loki_relay_protocol::{admission, canonical::{self, Value}};
use std::{fs, path::Path, process::Command};

fn write(path: &Path, bytes: &[u8]) {
    use std::os::unix::fs::OpenOptionsExt;
    use std::io::Write;
    let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).unwrap();
    f.write_all(bytes).unwrap();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args[1].as_str() {
        "init" => {
            let root = Path::new(&args[2]);
            fs::create_dir(root).unwrap();
            let relay = &args[3];
            let mut routes = Vec::new();
            for slot in 1..=3 {
                let port = &args[3 + slot];
                let relay_root = root.join(format!("relay-{slot}"));
                let provision = root.join(format!("relay-{slot}.secret"));
                let mut secret = [0u8; 32];
                rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut secret);
                write(&provision, &secret);
                let ok = Command::new(relay).arg("init").arg("--root").arg(&relay_root)
                    .arg("--listen").arg(format!("127.0.0.1:{port}"))
                    .arg("--provision-capability-file").arg(&provision)
                    .args(["--total-bytes", "268435456", "--mailbox-bytes", "67108864", "--mailbox-count", "1024"])
                    .status().unwrap();
                assert!(ok.success());
                let manifest = fs::read_to_string(relay_root.join("manifest")).unwrap();
                let f: Vec<_> = manifest.lines().collect();
                routes.push((Value::Array(vec![
                    Value::Bytes(hex::decode(f[2]).unwrap()),
                    Value::Bytes(hex::decode(f[1]).unwrap()),
                    Value::Bytes(f[0].as_bytes().to_vec()),
                ]), slot));
            }
            routes.sort_by_key(|(r, _)| canonical::encode(r).unwrap());
            let origin = format!("http://127.0.0.1:{}", args[7]);
            let signer = SigningKey::from_bytes(&[91; 32]);
            let body = canonical::encode(&Value::Array(vec![
                Value::Integer(1.into()),
                Value::Array(routes.iter().map(|(r, _)| r.clone()).collect()),
                Value::Array(vec![Value::Bytes(origin.into_bytes()),
                    Value::Bytes(SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes().to_vec())]),
                Value::Array(vec![Value::Integer(2.into())]),
                Value::Array([86400u64, 2592000, 1048576, 67108864, 5, 1, 60].into_iter()
                    .map(|n| Value::Integer(n.into())).collect()),
            ])).unwrap();
            let mut input = b"Loki_Operator_Config_v1\0".to_vec();
            input.extend_from_slice(&(body.len() as u32).to_be_bytes());
            input.extend_from_slice(&body);
            let bundle = canonical::encode(&Value::Array(vec![
                Value::Bytes(body), Value::Bytes(signer.sign(&input).to_bytes().to_vec())])).unwrap();
            write(&root.join("operator.cbor"), &bundle);
            write(&root.join("config.key"), &signer.verifying_key().to_bytes());
            write(&root.join("issuer.key"), &SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes());
            write(&root.join("signing.seed"), &[8; 32]);
            let order: Vec<String> = routes.iter().map(|(_, s)| s.to_string()).collect();
            fs::write(root.join("provision-order"), order.join(" ")).unwrap();
            println!("{}", hex::encode(signer.verifying_key().to_bytes()));
        }
        "grant" => {
            let get = |k: &str| args.iter().position(|a| a == k).map(|i| args[i + 1].clone()).unwrap();
            let device = hex::decode(get("--device-key")).unwrap();
            let bundle = fs::read(get("--operator-bundle")).unwrap();
            let key = SigningKey::from_bytes(&[91; 32]).verifying_key().to_bytes();
            let operators = OperatorSet::verify_development(&bundle, &key).unwrap();
            let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
            let mut id = [0u8; 32];
            rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut id);
            let body = canonical::encode(&Value::Array(vec![
                Value::Integer(1.into()), Value::Bytes(id.to_vec()), Value::Bytes(device),
                Value::Integer((now + 3600).into()), Value::Integer(1.into()), Value::Integer(24.into()),
                Value::Bytes(operators.digest().to_vec()),
            ])).unwrap();
            let sig = SigningKey::from_bytes(&[9; 32])
                .sign(&admission::signature_input(b"Loki_Setup_Enrollment_v1\0", &body).unwrap());
            let grant = canonical::encode(&Value::Array(vec![Value::Bytes(body), Value::Bytes(sig.to_bytes().to_vec())])).unwrap();
            use std::io::Write;
            std::io::stdout().write_all(&grant).unwrap();
        }
        _ => panic!("init|grant"),
    }
}
