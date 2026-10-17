use ed25519_dalek::{Signer, SigningKey};
use loki_relay_client::OperatorSet;
use loki_relay_protocol::canonical::{self, Value};
use loki_setup_admission::EnrollmentVerifier;
use sha2::Digest;
use std::{
    env, fs,
    io::{self, Write},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

fn main() {
    if let Err(error) = run() {
        eprintln!("owned_testnet_config_error: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args().skip(1).collect();
    match args.as_slice() {
        [command, root, origin] if command == "init" => init(Path::new(root), origin),
        [command, root, device, policy, digest] if command == "grant" => {
            grant(Path::new(root), device, policy, digest)
        }
        [command, root] if command == "check" => check(Path::new(root)),
        _ => Err("usage: loki-owned-testnet-config init ROOT ADMISSION_HTTPS_ORIGIN | grant ROOT DEVICE_KEY_HEX POLICY BUNDLE_SHA256_HEX | check ROOT".into()),
    }
}

fn private_write(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn seed(path: &Path) -> Result<SigningKey, Box<dyn std::error::Error>> {
    let bytes: [u8; 32] = fs::read(path)?.try_into().map_err(|_| "invalid seed")?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn new_signer(path: &Path) -> Result<SigningKey, Box<dyn std::error::Error>> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes)?;
    private_write(path, &bytes)?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn signed(
    domain: &[u8],
    body: Vec<u8>,
    signer: &SigningKey,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut input = domain.to_vec();
    input.extend_from_slice(&(body.len() as u32).to_be_bytes());
    input.extend_from_slice(&body);
    Ok(canonical::encode(&Value::Array(vec![
        Value::Bytes(body),
        Value::Bytes(signer.sign(&input).to_bytes().to_vec()),
    ]))?)
}

fn init(root: &Path, admission_origin: &str) -> Result<(), Box<dyn std::error::Error>> {
    if !admission_origin.starts_with("https://") {
        return Err("admission origin must use HTTPS".into());
    }
    let mut routes = Vec::new();
    for slot in 1..=3 {
        let manifest = fs::read_to_string(root.join(format!("relay-{slot}/manifest")))?;
        let lines: Vec<_> = manifest.lines().collect();
        if lines.len() != 3 || !lines[0].starts_with("https://") {
            return Err("invalid relay manifest".into());
        }
        let key = hex::decode(lines[2])?;
        let run = hex::decode(lines[1])?;
        if key.len() != 32
            || run.len() != 32
            || fs::read(root.join(format!("relay-{slot}.secret")))?.len() != 32
        {
            return Err("invalid relay identity or provision secret".into());
        }
        routes.push((
            Value::Array(vec![
                Value::Bytes(key),
                Value::Bytes(run),
                Value::Bytes(lines[0].as_bytes().to_vec()),
            ]),
            slot,
        ));
    }
    routes.sort_by_key(|(route, _)| canonical::encode(route).unwrap());
    let config = new_signer(&root.join("config.seed"))?;
    let admission = new_signer(&root.join("signing.seed"))?;
    let issuer = new_signer(&root.join("issuer.seed"))?;
    let body = canonical::encode(&Value::Array(vec![
        Value::Integer(1.into()),
        Value::Array(routes.iter().map(|(route, _)| route.clone()).collect()),
        Value::Array(vec![
            Value::Bytes(admission_origin.as_bytes().to_vec()),
            Value::Bytes(admission.verifying_key().to_bytes().to_vec()),
        ]),
        Value::Array(vec![Value::Integer(1.into())]),
        Value::Array(
            [86400, 2592000, 1048576, 67108864, 30, 1, 60]
                .into_iter()
                .map(|n| Value::Integer(n.into()))
                .collect(),
        ),
    ]))?;
    let bundle = signed(b"Loki_Operator_Config_v1\0", body, &config)?;
    OperatorSet::verify(&bundle, &config.verifying_key().to_bytes())?;
    private_write(&root.join("operator.cbor"), &bundle)?;
    private_write(&root.join("config.key"), &config.verifying_key().to_bytes())?;
    private_write(&root.join("issuer.key"), &issuer.verifying_key().to_bytes())?;
    for (position, (_, slot)) in routes.iter().enumerate() {
        private_write(
            &root.join(format!("ordered-relay-{}.secret", position + 1)),
            &fs::read(root.join(format!("relay-{slot}.secret")))?,
        )?;
    }
    Ok(())
}

fn grant(
    root: &Path,
    device: &str,
    policy: &str,
    digest: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // shortcut: grants cannot bind a policy in v1; add that field when the protocol supports it.
    if !matches!(policy, "2-of-3" | "2-of-4" | "3-of-4") {
        return Err("unsupported policy".into());
    }
    let device: [u8; 32] = hex::decode(device)?
        .try_into()
        .map_err(|_| "invalid device key")?;
    let bundle = fs::read(root.join("operator.cbor"))?;
    let expected = sha2::Sha256::digest(&bundle);
    if digest != hex::encode(expected) {
        return Err("operator bundle digest mismatch".into());
    }
    let issuer = seed(&root.join("issuer.seed"))?;
    let config_key: [u8; 32] = fs::read(root.join("config.key"))?
        .try_into()
        .map_err(|_| "invalid config key")?;
    let config = OperatorSet::verify(&bundle, &config_key)?;
    let mut grant_id = [0; 32];
    getrandom::fill(&mut grant_id)?;
    let expires = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() + 3600;
    let body = canonical::encode(&Value::Array(vec![
        Value::Integer(1.into()),
        Value::Bytes(grant_id.to_vec()),
        Value::Bytes(device.to_vec()),
        Value::Integer(expires.into()),
        Value::Integer(1.into()),
        Value::Integer(48.into()),
        Value::Bytes(config.digest().to_vec()),
    ]))?;
    let raw = signed(b"Loki_Setup_Enrollment_v1\0", body, &issuer)?;
    EnrollmentVerifier::new(Some(issuer.verifying_key().to_bytes())).verify(
        &raw,
        &device,
        expires - 1,
    )?;
    io::stdout().write_all(&raw)?;
    Ok(())
}

fn check(root: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let bundle = fs::read(root.join("operator.cbor"))?;
    let key: [u8; 32] = fs::read(root.join("config.key"))?
        .try_into()
        .map_err(|_| "invalid config key")?;
    let config = OperatorSet::verify(&bundle, &key)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let client = loki_relay_client::RelayHttp::hosted()?;
        for route in config.relay_routes() {
            client
                .authenticate_endpoint(&route.pin, &route.endpoint)
                .await?;
        }
        Ok::<_, loki_relay_client::ClientError>(())
    })?;
    Ok(())
}
