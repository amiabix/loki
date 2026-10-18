//! Disposable single-host TEST operator inputs. Never use these keys for custody.
use ed25519_dalek::{Signer, SigningKey};
use loki_relay_client::OperatorSet;
use loki_relay_protocol::canonical::{self, Value};
use loki_setup_admission::EnrollmentVerifier;
use std::{
    env, fs,
    io::{self, Write},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

fn private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn random() -> io::Result<[u8; 32]> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes).map_err(io::Error::other)?;
    Ok(bytes)
}

fn signed(
    signer: &SigningKey,
    domain: &[u8],
    body: Vec<u8>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut input = domain.to_vec();
    input.extend_from_slice(&(body.len() as u32).to_be_bytes());
    input.extend_from_slice(&body);
    Ok(canonical::encode(&Value::Array(vec![
        Value::Bytes(body),
        Value::Bytes(signer.sign(&input).to_bytes().to_vec()),
    ]))?)
}

fn init(root: &Path, relay_bin: &Path) -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir(root)?;
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    let inputs = root.join("inputs");
    fs::create_dir(&inputs)?;
    fs::set_permissions(&inputs, fs::Permissions::from_mode(0o700))?;
    let admission_root = root.join("admission");
    fs::create_dir(&admission_root)?;
    fs::set_permissions(&admission_root, fs::Permissions::from_mode(0o700))?;

    let mut routes = Vec::new();
    for slot in 1..=3 {
        let secret = random()?;
        let provision = inputs.join(format!("relay-{slot}-provision-unsorted"));
        private(&provision, &secret)?;
        let status = Command::new(relay_bin)
            .args(["init", "--root"])
            .arg(root.join(format!("relay-{slot}")))
            .args(["--provision-capability-file"])
            .arg(&provision)
            .args([
                "--listen",
                &format!("127.0.0.1:{}", 39100 + slot),
                "--total-bytes",
                "268435456",
                "--mailbox-bytes",
                "67108864",
                "--mailbox-count",
                "1024",
            ])
            .status()?;
        if !status.success() {
            return Err(io::Error::other("relay init failed").into());
        }
        let manifest = fs::read_to_string(root.join(format!("relay-{slot}/manifest")))?;
        let lines: Vec<_> = manifest.lines().collect();
        if lines.len() != 3 {
            return Err(io::Error::other("invalid relay manifest").into());
        }
        let key: [u8; 32] = hex::decode(lines[2])?
            .try_into()
            .map_err(|_| io::Error::other("invalid relay key"))?;
        let run = hex::decode(lines[1])?;
        routes.push((
            key,
            Value::Array(vec![
                Value::Bytes(key.to_vec()),
                Value::Bytes(run),
                Value::Bytes(lines[0].as_bytes().to_vec()),
            ]),
            provision,
        ));
    }
    routes.sort_by_key(|(key, _, _)| *key);
    for (index, (_, _, provision)) in routes.iter().enumerate() {
        fs::rename(
            provision,
            inputs.join(format!("relay-{}-provision", index + 1)),
        )?;
    }
    let config = SigningKey::from_bytes(&random()?);
    let admission = SigningKey::from_bytes(&random()?);
    let issuer = SigningKey::from_bytes(&random()?);
    private(&admission_root.join("signing-key"), &admission.to_bytes())?;
    private(&inputs.join("config-signing-key"), &config.to_bytes())?;
    private(
        &inputs.join("config-key"),
        &config.verifying_key().to_bytes(),
    )?;
    private(&inputs.join("issuer-signing-key"), &issuer.to_bytes())?;
    private(
        &inputs.join("issuer-public-key"),
        &issuer.verifying_key().to_bytes(),
    )?;
    let body = canonical::encode(&Value::Array(vec![
        Value::Integer(1.into()),
        Value::Array(routes.into_iter().map(|(_, route, _)| route).collect()),
        Value::Array(vec![
            Value::Bytes(b"http://127.0.0.1:39104".to_vec()),
            Value::Bytes(admission.verifying_key().to_bytes().to_vec()),
        ]),
        Value::Array(vec![Value::Integer(1.into())]),
        Value::Array(
            [86400u64, 2592000, 1048576, 67108864, 5, 1, 60]
                .into_iter()
                .map(|n| Value::Integer(n.into()))
                .collect(),
        ),
    ]))?;
    let bundle = signed(&config, b"Loki_Operator_Config_v1\0", body)?;
    OperatorSet::verify_development(&bundle, &config.verifying_key().to_bytes())?;
    private(&inputs.join("bundle"), &bundle)?;
    println!("owned TEST inputs: {}", inputs.display());
    Ok(())
}

fn grant(root: &Path, args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    if args.len() != 6
        || args[0] != "--device-key"
        || args[2] != "--operator-bundle"
        || args[4] != "--policy"
        || !matches!(args[5].as_str(), "2-of-3" | "2-of-4" | "3-of-4")
    {
        return Err(io::Error::other(
            "expected --device-key HEX --operator-bundle PATH --policy 2-of-N",
        )
        .into());
    }
    let device: [u8; 32] = hex::decode(&args[1])?
        .try_into()
        .map_err(|_| io::Error::other("invalid device key"))?;
    let inputs = root.join("inputs");
    let trusted: [u8; 32] = fs::read(inputs.join("config-key"))?
        .try_into()
        .map_err(|_| io::Error::other("invalid config key"))?;
    let bundle = fs::read(&args[3])?;
    let operators = OperatorSet::verify_development(&bundle, &trusted)?;
    let seed: [u8; 32] = fs::read(inputs.join("issuer-signing-key"))?
        .try_into()
        .map_err(|_| io::Error::other("invalid issuer seed"))?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let body = canonical::encode(&Value::Array(vec![
        Value::Integer(1.into()),
        Value::Bytes(random()?.to_vec()),
        Value::Bytes(device.to_vec()),
        Value::Integer((now + 3600).into()),
        Value::Integer(1.into()),
        Value::Integer(24.into()),
        Value::Bytes(operators.digest().to_vec()),
    ]))?;
    let bytes = signed(
        &SigningKey::from_bytes(&seed),
        b"Loki_Setup_Enrollment_v1\0",
        body,
    )?;
    let budget = EnrollmentVerifier::new(Some(
        SigningKey::from_bytes(&seed).verifying_key().to_bytes(),
    ))
    .verify(&bytes, &device, now)?;
    if budget.config_digest() != operators.digest() {
        return Err(io::Error::other("grant configuration mismatch").into());
    }
    io::stdout().write_all(&bytes)?;
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().skip(1).collect();
    match args.as_slice() {
        [command, root, relay] if command == "init" => init(Path::new(root), Path::new(relay)),
        [command, root, rest @ ..] if command == "grant" => grant(Path::new(root), rest),
        _ => Err(io::Error::other("usage: loki-owned-test-inputs init ROOT RELAY_BIN | grant ROOT --device-key HEX --operator-bundle PATH --policy 2-of-N").into()),
    }
}
