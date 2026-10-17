use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use loki_relay_client::{validate_endpoint, OperatorSet};
use loki_relay_protocol::canonical::{self, Value};
use std::{
    env, fs,
    io::Write,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

fn main() {
    if let Err(error) = run(env::args().skip(1).collect()) {
        eprintln!("operator admin: {error}");
        std::process::exit(1);
    }
}

fn run(args: Vec<String>) -> Result<(), String> {
    match args.as_slice() {
        [command, seed, output_path] if command == "pubkey" => {
            let seed = secret(Path::new(seed))?;
            output(Path::new(output_path), &SigningKey::from_bytes(&seed).verifying_key().to_bytes(), false)
        }
        [command, config_seed, admission_key, admission_origin, relay1, relay2, relay3, bundle, config_key, order]
            if command == "bundle" => bundle_command(
                Path::new(config_seed), Path::new(admission_key), admission_origin,
                [Path::new(relay1), Path::new(relay2), Path::new(relay3)],
                Path::new(bundle), Path::new(config_key), Path::new(order),
            ),
        [command, issuer_seed, bundle, config_key, device_key, expires, creations, mailboxes, grant]
            if command == "grant" => grant_command(
                Path::new(issuer_seed), Path::new(bundle), Path::new(config_key), device_key,
                expires, creations, mailboxes, Path::new(grant),
            ),
        _ => Err("usage: loki_operator_admin pubkey SEED PUBLIC_KEY_OUT | bundle CONFIG_SEED ADMISSION_PUBLIC_KEY ADMISSION_HTTPS_ORIGIN RELAY1_MANIFEST RELAY2_MANIFEST RELAY3_MANIFEST BUNDLE_OUT CONFIG_KEY_OUT RELAY_ORDER_OUT | grant ISSUER_SEED BUNDLE CONFIG_KEY DEVICE_KEY_HEX EXPIRES_UNIX MAX_CREATIONS MAILBOX_BUDGET GRANT_OUT".into()),
    }
}

fn secret(path: &Path) -> Result<Zeroizing<[u8; 32]>, String> {
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !metadata.is_file() {
        return Err("seed must be a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o777 != 0o600 {
            return Err("seed file must have mode 0600".into());
        }
    }
    let bytes = Zeroizing::new(fs::read(path).map_err(|e| e.to_string())?);
    let seed: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| "seed must be 32 bytes")?;
    Ok(Zeroizing::new(seed))
}

fn public_key(path: &Path) -> Result<[u8; 32], String> {
    fs::read(path)
        .map_err(|e| e.to_string())?
        .as_slice()
        .try_into()
        .map_err(|_| "configuration public key must be 32 bytes".into())
}

fn decode_id(raw: &str) -> Result<[u8; 32], String> {
    hex::decode(raw)
        .map_err(|e| e.to_string())?
        .as_slice()
        .try_into()
        .map_err(|_| "expected a 32-byte hex key".into())
}

fn output(path: &Path, bytes: &[u8], private: bool) -> Result<(), String> {
    if path == Path::new("-") {
        if !private {
            return Err("only a scoped grant may be written to stdout".into());
        }
        return std::io::stdout()
            .write_all(bytes)
            .map_err(|e| e.to_string());
    }
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    let mut file = options.open(path).map_err(|e| e.to_string())?;
    file.write_all(bytes).map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())
}

fn signed(body: Vec<u8>, key: &SigningKey, domain: &[u8]) -> Result<Vec<u8>, String> {
    let mut input = domain.to_vec();
    input.extend_from_slice(&(body.len() as u32).to_be_bytes());
    input.extend_from_slice(&body);
    canonical::encode(&Value::Array(vec![
        Value::Bytes(body),
        Value::Bytes(key.sign(&input).to_bytes().to_vec()),
    ]))
    .map_err(|e| e.to_string())
}

struct RelayInput {
    key: [u8; 32],
    run: [u8; 32],
    endpoint: String,
    slot: usize,
}

fn relay(manifest: &Path, slot: usize) -> Result<RelayInput, String> {
    let raw = fs::read_to_string(manifest).map_err(|e| e.to_string())?;
    let lines: Vec<_> = raw.lines().collect();
    if lines.len() != 3 || !raw.ends_with('\n') {
        return Err("relay manifest must contain exactly three lines".into());
    }
    validate_endpoint(lines[0], false).map_err(|_| "relay must have a public HTTPS origin")?;
    let run = decode_id(lines[1])?;
    let key = decode_id(lines[2])?;
    Ok(RelayInput {
        key,
        run,
        endpoint: lines[0].to_owned(),
        slot,
    })
}

fn bundle_command(
    config_seed: &Path,
    admission_key: &Path,
    admission_origin: &str,
    manifests: [&Path; 3],
    bundle_path: &Path,
    key_path: &Path,
    order_path: &Path,
) -> Result<(), String> {
    validate_endpoint(admission_origin, false)
        .map_err(|_| "admission needs a public HTTPS origin")?;
    if bundle_path.exists() || key_path.exists() || order_path.exists() {
        return Err("output already exists; refusing to replace the trusted bundle".into());
    }
    let config_seed = secret(config_seed)?;
    let config = SigningKey::from_bytes(&config_seed);
    let admission = public_key(admission_key)?;
    VerifyingKey::from_bytes(&admission).map_err(|_| "invalid admission public key")?;
    let mut routes = manifests
        .into_iter()
        .enumerate()
        .map(|(index, manifest)| relay(manifest, index + 1))
        .collect::<Result<Vec<_>, _>>()?;
    routes.sort_by_key(|route| route.key);
    if routes
        .iter()
        .any(|route| route.key == [0; 32] || route.run == [0; 32])
        || routes
            .windows(2)
            .any(|pair| pair[0].key == pair[1].key || pair[0].run == pair[1].run)
        || routes[0].run == routes[2].run
    {
        return Err("relay keys and run IDs must be distinct".into());
    }
    let order = routes
        .iter()
        .map(|route| format!("{}\n", route.slot))
        .collect::<String>();
    let body = canonical::encode(&Value::Array(vec![
        Value::Integer(1.into()),
        Value::Array(
            routes
                .into_iter()
                .map(|route| {
                    Value::Array(vec![
                        Value::Bytes(route.key.to_vec()),
                        Value::Bytes(route.run.to_vec()),
                        Value::Bytes(route.endpoint.into_bytes()),
                    ])
                })
                .collect(),
        ),
        Value::Array(vec![
            Value::Bytes(admission_origin.as_bytes().to_vec()),
            Value::Bytes(admission.to_vec()),
        ]),
        Value::Array(vec![Value::Integer(1.into())]),
        Value::Array(
            [86400, 2592000, 1048576, 67108864, 30, 1, 60]
                .into_iter()
                .map(|value: u64| Value::Integer(value.into()))
                .collect(),
        ),
    ]))
    .map_err(|e| e.to_string())?;
    let bundle = signed(body, &config, b"Loki_Operator_Config_v1\0")?;
    let key = config.verifying_key().to_bytes();
    OperatorSet::verify(&bundle, &key).map_err(|e| format!("bundle verification: {e}"))?;
    output(bundle_path, &bundle, false)?;
    output(key_path, &key, false)?;
    output(order_path, order.as_bytes(), false)
}

#[allow(clippy::too_many_arguments)]
fn grant_command(
    issuer_seed: &Path,
    bundle_path: &Path,
    key_path: &Path,
    device_key: &str,
    expires: &str,
    creations: &str,
    mailboxes: &str,
    grant_path: &Path,
) -> Result<(), String> {
    let issuer_seed = secret(issuer_seed)?;
    let issuer = SigningKey::from_bytes(&issuer_seed);
    let bundle = fs::read(bundle_path).map_err(|e| e.to_string())?;
    let operators = OperatorSet::verify(&bundle, &public_key(key_path)?)
        .map_err(|e| format!("bundle verification: {e}"))?;
    let device = decode_id(device_key)?;
    let expires: u64 = expires.parse().map_err(|_| "invalid expiry")?;
    let creations: u64 = creations.parse().map_err(|_| "invalid creation count")?;
    let mailboxes: u64 = mailboxes.parse().map_err(|_| "invalid mailbox budget")?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    if expires <= now
        || expires > now + 86400
        || !(1..=100).contains(&creations)
        || !(1..=2400).contains(&mailboxes)
    {
        return Err("grant must expire within 24 hours and stay within admission quotas".into());
    }
    let mut grant_id = [0u8; 32];
    getrandom::fill(&mut grant_id).map_err(|e| e.to_string())?;
    let body = canonical::encode(&Value::Array(vec![
        Value::Integer(1.into()),
        Value::Bytes(grant_id.to_vec()),
        Value::Bytes(device.to_vec()),
        Value::Integer(expires.into()),
        Value::Integer(creations.into()),
        Value::Integer(mailboxes.into()),
        Value::Bytes(operators.digest().to_vec()),
    ]))
    .map_err(|e| e.to_string())?;
    let grant = signed(body, &issuer, b"Loki_Setup_Enrollment_v1\0")?;
    loki_setup_admission::EnrollmentVerifier::new(Some(issuer.verifying_key().to_bytes()))
        .verify(&grant, &device, now)
        .map_err(|e| format!("grant verification: {e}"))?;
    output(grant_path, &grant, true)
}
