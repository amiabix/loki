//! Separate-member DKG ceremony on regtest. The exchange directory is an untrusted courier.
//! This ZIP 2005 implementation has not been independently reviewed; regtest only.

use std::{
    collections::BTreeMap,
    env, fs,
    io::Write,
    path::{Path, PathBuf},
    process, thread,
    time::{Duration, Instant},
};

use blake2b_simd::Params;
use loki_poc::{
    distributed_setup::Member,
    setup_transport::{Identity, PublicIdentity},
    state::MemberDir,
    vault, zip2005,
};
use rand_core::{OsRng, RngCore};

struct Roster {
    vault: [u8; 32],
    members: BTreeMap<u16, PublicIdentity>,
}

impl Roster {
    fn load(path: &Path) -> Result<Self, String> {
        let data: serde_json::Value =
            serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
        let vault = hex32(
            data.get("vault")
                .and_then(|v| v.as_str())
                .ok_or("missing vault id")?,
        )?;
        let entries = data
            .get("members")
            .and_then(|v| v.as_array())
            .ok_or("missing members")?;
        let mut members = BTreeMap::new();
        for entry in entries {
            let id: u16 = entry
                .get("id")
                .and_then(|v| v.as_u64())
                .ok_or("missing member id")?
                .try_into()
                .map_err(|_| "invalid member id")?;
            let signing = hex32(
                entry
                    .get("signing")
                    .and_then(|v| v.as_str())
                    .ok_or("missing signing key")?,
            )?;
            let encryption = hex32(
                entry
                    .get("encryption")
                    .and_then(|v| v.as_str())
                    .ok_or("missing encryption key")?,
            )?;
            ed25519_dalek::VerifyingKey::from_bytes(&signing)
                .map_err(|_| "invalid signing public key")?;
            if members
                .insert(
                    id,
                    PublicIdentity {
                        id,
                        signing,
                        encryption,
                    },
                )
                .is_some()
            {
                return Err("duplicate member in roster".into());
            }
        }
        if members.keys().copied().collect::<Vec<_>>() != [1, 2, 3] {
            return Err("roster must have exactly members 1, 2 and 3".into());
        }
        Ok(Self { vault, members })
    }

    fn fingerprint(&self) -> [u8; 32] {
        let mut hash = Params::new()
            .hash_length(32)
            .personal(b"Loki_roster_v1")
            .to_state();
        hash.update(&self.vault);
        for member in self.members.values() {
            hash.update(&member.id.to_be_bytes());
            hash.update(&member.signing);
            hash.update(&member.encryption);
        }
        hash.finalize().as_bytes().try_into().unwrap()
    }
}

fn hex32(text: &str) -> Result<[u8; 32], String> {
    hex::decode(text)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "expected 32 bytes".into())
}

fn passphrase(path: &Path) -> Result<String, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(path)
            .map_err(|e| e.to_string())?
            .permissions()
            .mode()
            & 0o077
            != 0
        {
            return Err("passphrase file must be owner-only (mode 0600)".into());
        }
    }
    let pass = fs::read_to_string(path).map_err(|e| e.to_string())?;
    let pass = pass.trim_end_matches(['\r', '\n']);
    if pass.is_empty() {
        return Err("empty passphrase".into());
    }
    Ok(pass.to_string())
}

fn name(vault: &[u8; 32], phase: &str, from: u16, to: Option<u16>) -> String {
    match to {
        Some(to) => format!("{}-{phase}-{from}-{to}.bin", hex::encode(vault)),
        None => format!("{}-{phase}-{from}.bin", hex::encode(vault)),
    }
}

fn publish(dir: &Path, file: &str, bytes: &[u8]) -> Result<(), String> {
    let target = dir.join(file);
    if target.exists() {
        return Err(format!(
            "{} already exists; start a fresh vault session",
            target.display()
        ));
    }
    let mut suffix = [0u8; 8];
    OsRng.fill_bytes(&mut suffix);
    let temp = dir.join(format!(".{file}.{}.tmp", hex::encode(suffix)));
    let mut out = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)
        .map_err(|e| e.to_string())?;
    let result = (|| -> Result<(), String> {
        out.write_all(bytes).map_err(|e| e.to_string())?;
        out.sync_all().map_err(|e| e.to_string())?;
        fs::hard_link(&temp, &target).map_err(|e| e.to_string())?;
        fs::remove_file(&temp).map_err(|e| e.to_string())?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

fn setup_lock(dir: &MemberDir) -> Result<fs::File, String> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(dir.path().join(".setup.lock"))
        .map_err(|e| e.to_string())?;
    file.lock().map_err(|e| e.to_string())?;
    Ok(file)
}

fn wait_file(dir: &Path, file: &str) -> Result<Vec<u8>, String> {
    let target = dir.join(file);
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        match fs::read(&target) {
            Ok(bytes) => return Ok(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(100))
            }
            Err(e) => return Err(format!("waiting for {}: {e}", target.display())),
        }
    }
}

fn digest(personal: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut state = Params::new().hash_length(32).personal(personal).to_state();
    for part in parts {
        state.update(part);
    }
    state.finalize().as_bytes().try_into().unwrap()
}

fn identity(args: &[String]) -> Result<(), String> {
    if args.len() != 3 {
        return Err("identity <member-dir> <id> <passphrase-file>".into());
    }
    let dir = MemberDir::create(Path::new(&args[0]), "secrets").map_err(|e| e.to_string())?;
    let _lock = setup_lock(&dir)?;
    if dir.exists("identity.sealed") {
        return Err("identity already exists".into());
    }
    let id: u16 = args[1].parse().map_err(|_| "invalid member id")?;
    if !(1..=3).contains(&id) {
        return Err("member id must be 1, 2 or 3".into());
    }
    let secret = Identity::new(id);
    dir.write_sealed(
        "identity.sealed",
        &secret.to_secret_bytes(),
        &passphrase(Path::new(&args[2]))?,
    )
    .map_err(|e| e.to_string())?;
    let public = secret.public();
    println!(
        "{}",
        serde_json::json!({
            "id": public.id,
            "signing": hex::encode(public.signing),
            "encryption": hex::encode(public.encryption),
        })
    );
    Ok(())
}

fn address(args: &[String]) -> Result<(), String> {
    if args.len() != 2 {
        return Err("address <member-dir> <passphrase-file>".into());
    }
    let dir = MemberDir::open(Path::new(&args[0]), "secrets");
    let state: serde_json::Value = serde_json::from_slice(
        &dir.read_sealed("vault.sealed", &passphrase(Path::new(&args[1]))?)
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if state.get("version").and_then(|v| v.as_u64()) != Some(1)
        || state.get("network").and_then(|v| v.as_str()) != Some("regtest")
    {
        return Err("unsupported vault state version or network".into());
    }
    if state.get("key_derivation").and_then(|v| v.as_str()) != Some(zip2005::VERSION) {
        return Err("unsupported key derivation; recreate this regtest vault".into());
    }
    let ak = hex32(state["group_ak"].as_str().ok_or("missing group key")?)?;
    let sk = hex32(
        state["vault_secret"]
            .as_str()
            .ok_or("missing vault secret")?,
    )?;
    let fvk = zip2005::frost_viewing_key(&ak, &sk)
        .map_err(|e| format!("ZIP 2005 key derivation: {e:?}"))?;
    let expected = vault::regtest_unified_address(&fvk);
    if state["address"].as_str() != Some(&expected) {
        return Err("stored address differs from the derived vault address".into());
    }
    println!("{expected}");
    Ok(())
}

fn run(args: &[String]) -> Result<(), String> {
    if args.len() != 5 {
        return Err("run <member-dir> <passphrase-file> <roster.json> <exchange-dir> <expected-fingerprint>".into());
    }
    let root = PathBuf::from(&args[0]);
    let dir = MemberDir::open(&root, "secrets");
    let _lock = setup_lock(&dir)?;
    if dir.exists("vault.sealed") {
        return Err("this member already completed setup".into());
    }
    let secret = Identity::from_secret_bytes(
        &dir.read_sealed("identity.sealed", &passphrase(Path::new(&args[1]))?)
            .map_err(|e| e.to_string())?,
    )?;
    let roster = Roster::load(Path::new(&args[2]))?;
    if hex::encode(roster.fingerprint()) != args[4] {
        return Err("roster fingerprint differs from the one compared by members".into());
    }
    let own = secret.public();
    if roster.members.get(&own.id) != Some(&own) {
        return Err("your identity is not in the agreed roster".into());
    }
    let exchange = Path::new(&args[3]);
    if !exchange.is_dir() {
        return Err("exchange directory does not exist".into());
    }

    let mut contribution = [0u8; 32];
    OsRng.fill_bytes(&mut contribution);
    let commitment = digest(
        b"Loki_vs_commit1",
        &[&roster.vault, &own.id.to_be_bytes(), &contribution],
    );
    let (member, own_r1) = Member::start(own.id)?;
    let mut r1_body = commitment.to_vec();
    r1_body.extend_from_slice(&own_r1);
    publish(
        exchange,
        &name(&roster.vault, "r1", own.id, None),
        &secret.sign_round1(&roster.vault, &r1_body)?,
    )?;

    let mut round1 = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    round1.insert(own.id, own_r1);
    commitments.insert(own.id, commitment);
    for peer in roster.members.values().filter(|peer| peer.id != own.id) {
        let wire = wait_file(exchange, &name(&roster.vault, "r1", peer.id, None))?;
        let body = secret.verify_round1(peer, &roster.vault, &wire)?;
        if body.len() <= 32 {
            return Err("short round-one package".into());
        }
        commitments.insert(peer.id, body[..32].try_into().unwrap());
        round1.insert(peer.id, body[32..].to_vec());
    }
    let (member, outgoing) = member.advance(&round1)?;
    for (&peer_id, bytes) in &outgoing {
        let mut body = contribution.to_vec();
        body.extend_from_slice(bytes);
        let sealed = secret.seal_round2(&roster.members[&peer_id], &roster.vault, &body)?;
        publish(
            exchange,
            &name(&roster.vault, "r2", own.id, Some(peer_id)),
            &sealed,
        )?;
    }

    let mut incoming = BTreeMap::new();
    let mut contributions = BTreeMap::new();
    contributions.insert(own.id, contribution);
    for peer in roster.members.values().filter(|peer| peer.id != own.id) {
        let wire = wait_file(exchange, &name(&roster.vault, "r2", peer.id, Some(own.id)))?;
        let body = secret.open_round2(peer, &roster.vault, &wire)?;
        if body.len() <= 32 {
            return Err("short round-two package".into());
        }
        let theirs: [u8; 32] = body[..32].try_into().unwrap();
        let expected = digest(
            b"Loki_vs_commit1",
            &[&roster.vault, &peer.id.to_be_bytes(), &theirs],
        );
        if expected != commitments[&peer.id] {
            return Err("vault secret contribution changed".into());
        }
        contributions.insert(peer.id, theirs);
        incoming.insert(peer.id, body[32..].to_vec());
    }
    let completed = member.finish(&incoming)?;
    let mut vs_state = Params::new()
        .hash_length(32)
        .personal(b"Loki_vs_v1")
        .to_state();
    vs_state.update(&completed.certificate_digest());
    for c in contributions.values() {
        vs_state.update(c);
    }
    let vs: [u8; 32] = vs_state.finalize().as_bytes().try_into().unwrap();
    let mut cert_body = completed.certificate_digest().to_vec();
    cert_body.extend_from_slice(&digest(b"Loki_vs_cert_v1", &[&vs]));
    cert_body.extend_from_slice(&roster.fingerprint());
    cert_body.extend_from_slice(zip2005::VERSION.as_bytes());
    publish(
        exchange,
        &name(&roster.vault, "cert", own.id, None),
        &secret.sign_certificate(&roster.vault, &cert_body)?,
    )?;

    let mut certificates = BTreeMap::new();
    certificates.insert(own.id, completed.certificate_digest());
    for peer in roster.members.values().filter(|peer| peer.id != own.id) {
        let wire = wait_file(exchange, &name(&roster.vault, "cert", peer.id, None))?;
        let body = secret.verify_certificate(peer, &roster.vault, &wire)?;
        if body != cert_body {
            return Err("members disagree on the vault certificate".into());
        }
        certificates.insert(peer.id, body[..32].try_into().unwrap());
    }
    let certified = completed.certify(&certificates)?;
    let fvk = zip2005::frost_viewing_key(&certified.group_ak, &vs)
        .map_err(|e| format!("ZIP 2005 key derivation: {e:?}"))?;
    let pass = passphrase(Path::new(&args[1]))?;
    let address = vault::regtest_unified_address(&fvk);
    let state = serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "network": "regtest",
        "key_derivation": zip2005::VERSION,
        "vault": hex::encode(roster.vault),
        "roster_fingerprint": hex::encode(roster.fingerprint()),
        "key_package": hex::encode(&certified.key_package),
        "vault_secret": hex::encode(vs),
        "public_package": hex::encode(&certified.public_package),
        "group_ak": hex::encode(certified.group_ak),
        "address": address,
    }))
    .map_err(|e| e.to_string())?;
    dir.write_sealed("vault.sealed", &state, &pass)
        .map_err(|e| e.to_string())?;
    println!("{address}");
    eprintln!(
        "REGTEST ONLY: ZIP 2005 key derivation is locally implemented and awaits independent review"
    );
    Ok(())
}

fn main() {
    let args: Vec<_> = env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("identity") => identity(&args[1..]),
        Some("address") => address(&args[1..]),
        Some("fingerprint") if args.len() == 2 => {
            Roster::load(Path::new(&args[1])).map(|r| println!("{}", hex::encode(r.fingerprint())))
        }
        Some("run") => run(&args[1..]),
        _ => Err("usage: loki_setup_member identity|fingerprint|run|address ...".into()),
    };
    if let Err(error) = result {
        eprintln!("error: {error}");
        process::exit(1);
    }
}
