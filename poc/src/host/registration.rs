//! Member-owned startup and public self-registration. No local credential leaves this process.
use std::path::PathBuf;

use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::state::{Config, Session, Shared};
use crate::signer::device_auth::{verify_device_signature, DeviceRegistry};
use crate::state::MemberDir;

pub struct RegistrationConfig {
    pub coordinator: String,
    pub slot: Option<u32>,
    pub passphrase_file: Option<PathBuf>,
    pub name: String,
    pub pairing_challenge: Option<String>,
}

impl RegistrationConfig {
    pub fn pairing(link: &str, development_http: bool) -> Result<Self, String> {
        let url = reqwest::Url::parse(link).map_err(|_| "invalid pairing link")?;
        if url.scheme() != "loki" || url.host_str() != Some("pair") || !url.path().is_empty()
            || !url.username().is_empty() || url.password().is_some() || url.port().is_some() || url.fragment().is_some() {
            return Err("expected a loki://pair link".into());
        }
        let pairs: Vec<_> = url.query_pairs().collect();
        let get = |name: &str| -> Result<String, String> {
            let values: Vec<_> = pairs.iter().filter(|(k, _)| k == name).collect();
            if values.len() != 1 { return Err(format!("pairing link requires one {name}")); }
            Ok(values[0].1.to_string())
        };
        if pairs.len() != 3 { return Err("unexpected pairing fields".into()); }
        let coordinator = plain_origin(&get("origin")?, development_http)?;
        let raw_slot = get("slot")?;
        let slot = raw_slot.parse::<u32>().ok().filter(|s| *s > 0 && s.to_string() == raw_slot).ok_or("invalid pairing slot")?;
        let challenge = get("challenge")?;
        if challenge.len() != 64 || !challenge.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err("invalid pairing challenge".into());
        }
        Ok(Self { coordinator, slot: Some(slot), passphrase_file: None, name: "Member".into(), pairing_challenge: Some(challenge) })
    }

    pub fn resume(data: &std::path::Path, development_http: bool) -> Result<Self, String> {
        let saved: PairedCoordinator = serde_json::from_slice(&std::fs::read(data.join("paired-coordinator.json")).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        if saved.slot == 0 { return Err("invalid saved slot".into()); }
        Ok(Self { coordinator: plain_origin(&saved.origin, development_http)?, slot: Some(saved.slot),
            passphrase_file: None, name: "Member".into(), pairing_challenge: None })
    }

    pub(super) fn from_args(args: &[String], development_http: bool) -> Result<Option<Self>, String> {
        let value = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
        if args.iter().any(|a| a == "--pairing-url") {
            if args.iter().any(|a| matches!(a.as_str(), "--coordinator-url" | "--registration-slot")) {
                return Err("pairing link already specifies coordinator and slot".into());
            }
            let mut launch = Self::pairing(&value("--pairing-url").ok_or("--pairing-url needs a link")?, development_http)?;
            launch.passphrase_file = Some(value("--local-passphrase-file").ok_or("--local-passphrase-file is required for local unlock")?.into());
            launch.name = value("--profile-name").unwrap_or_else(|| "Member".into());
            return Ok(Some(launch));
        }
        let Some(coordinator) = value("--coordinator-url") else {
            if args.iter().any(|a| matches!(a.as_str(), "--coordinator-url" | "--local-passphrase-file" | "--registration-slot" | "--profile-name")) {
                return Err("self-registration requires --coordinator-url and --local-passphrase-file".into());
            }
            return Ok(None);
        };
        let coordinator = plain_origin(&coordinator, development_http)?;
        let slot = value("--registration-slot").map(|v| v.parse::<u32>().ok().filter(|s| *s > 0)
            .ok_or("--registration-slot requires a positive integer")).transpose()?;
        let passphrase_file = value("--local-passphrase-file").ok_or("--local-passphrase-file is required for local unlock")?.into();
        Ok(Some(Self { coordinator, slot, passphrase_file: Some(passphrase_file), name: value("--profile-name").unwrap_or_else(|| "Member".into()), pairing_challenge: None }))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PairedCoordinator { origin: String, slot: u32 }

fn plain_origin(value: &str, development_http: bool) -> Result<String, String> {
    let url = reqwest::Url::parse(value).map_err(|_| "invalid origin")?;
    let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if url.origin().ascii_serialization() != value || !url.username().is_empty() || url.password().is_some()
        || !(url.scheme() == "https" || (development_http && local && url.scheme() == "http")) {
        return Err("registration needs a plain HTTPS origin; loopback HTTP requires --development-http".into());
    }
    Ok(value.into())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PublicMember {
    pub slot: u32,
    pub signing_pubkey: String,
    pub relay_pubkey: String,
    pub advertise_url: String,
}

#[derive(Serialize)]
struct Enrollment {
    #[serde(skip_serializing_if = "Option::is_none")]
    slot: Option<u32>,
    signing_pubkey: String,
    relay_pubkey: String,
    advertise_url: String,
    device_pubkey: String,
    authorization: String,
}

impl Enrollment {
    fn message(&self, origin: &str, challenge: &str) -> Vec<u8> {
        format!("loki-member-registration-v1\n{origin}\n{}\n{}\n{}\n{}\n{}\n{challenge}",
            self.slot.unwrap_or(0), self.signing_pubkey, self.relay_pubkey, self.advertise_url, self.device_pubkey).into_bytes()
    }
}

enum DeviceKey {
    Software(SigningKey),
    #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
    Apple(crate::signer::secure_element_apple::AppleSecureElement),
}
impl DeviceKey {
    fn open(config: &Config, pass: &str) -> Result<Self, String> {
        #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
        if config.secure_element == "apple" {
            if let super::state::HostedSecureElement::Apple(key) = config.open_secure_element(&config.data.join("device-auth"), pass)? {
                return Ok(Self::Apple(key));
            }
            return Err("expected an Enclave device key".into());
        }
        if config.secure_element != "software" { return Err("device key backend unavailable".into()); }
        // Development stand-in only, selected by the existing software backend flag.
        let dir = MemberDir::create(&config.data, "device-auth").map_err(|e| e.to_string())?;
        let key = match dir.read_sealed("login.sealed", pass) {
            Ok(raw) => SigningKey::from_slice(&Zeroizing::new(raw)).map_err(|e| e.to_string())?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key = SigningKey::random(&mut rand_core::OsRng);
                let bytes = Zeroizing::new(key.to_bytes());
                dir.write_sealed("login.sealed", &bytes, pass).map_err(|e| e.to_string())?;
                key
            }
            Err(e) => return Err(e.to_string()),
        };
        Ok(Self::Software(key))
    }
    fn public(&self) -> Result<Vec<u8>, String> {
        match self {
            Self::Software(key) => Ok(key.verifying_key().to_encoded_point(false).as_bytes().to_vec()),
            #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
            Self::Apple(key) => key.public_key_sec1(),
        }
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, String> {
        match self {
            Self::Software(key) => { let sig: Signature = key.sign(message); Ok(sig.to_der().as_bytes().to_vec()) }
            #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
            Self::Apple(key) => key.sign(message),
        }
    }
}

async fn register(config: &Config, pass: &str) -> Result<PublicMember, String> {
    let launch = config.registration.as_ref().ok_or("self-registration not configured")?;
    // Loopback is the device-local browser endpoint, even with an HTTPS coordinator.
    let advertise_url = plain_origin(&config.base_url(), true)?;
    let identity = super::ceremony::identity(&config.data, pass, 1)?;
    let device = DeviceKey::open(config, pass)?;
    let device_pub = device.public()?;
    let authorization = identity.authorize_device(&device_pub);
    // Reuse the device enrollment verifier; this profile's identity authorizes the device.
    DeviceRegistry::new(identity.public().signing).enroll(&device_pub, &authorization)?;
    let enrollment = Enrollment {
        slot: launch.slot, signing_pubkey: hex::encode(identity.public().signing),
        relay_pubkey: hex::encode(identity.public().encryption), advertise_url,
        device_pubkey: hex::encode(&device_pub), authorization: hex::encode(authorization),
    };
    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(15)).build().map_err(|e| e.to_string())?;
    let mut claim = serde_json::to_value(&enrollment).map_err(|e| e.to_string())?;
    if let Some(challenge) = &launch.pairing_challenge { claim["pairing_challenge"] = challenge.clone().into(); }
    let challenge: serde_json::Value = client.post(format!("{}/api/members/challenge", launch.coordinator))
        .json(&claim).send().await.and_then(|r| r.error_for_status()).map_err(|e| format!("registration challenge: {e}"))?
        .json().await.map_err(|e| e.to_string())?;
    let challenge = challenge["challenge"].as_str().filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        .ok_or("invalid coordinator challenge")?;
    let message = enrollment.message(&launch.coordinator, challenge);
    let signature = device.sign(&message)?;
    verify_device_signature(&device_pub, &message, &signature)?;
    let mut body = serde_json::to_value(&enrollment).map_err(|e| e.to_string())?;
    body["challenge"] = challenge.into();
    body["signature"] = hex::encode(signature).into();
    let reply: serde_json::Value = client.post(format!("{}/api/members", launch.coordinator))
        .json(&body).send().await.and_then(|r| r.error_for_status()).map_err(|e| format!("self-registration: {e}"))?
        .json().await.map_err(|e| e.to_string())?;
    let member: PublicMember = serde_json::from_value(reply["member"].clone()).map_err(|e| e.to_string())?;
    if member.slot == 0 || launch.slot.is_some_and(|s| s != member.slot) || member.signing_pubkey != enrollment.signing_pubkey
        || member.relay_pubkey != enrollment.relay_pubkey || member.advertise_url != enrollment.advertise_url {
        return Err("coordinator returned a different identity".into());
    }
    Ok(member)
}

pub(super) async fn start(st: &Shared, pass: Option<Zeroizing<String>>, notice: Option<&super::LocalNotice>) -> Result<(), String> {
    let Some(launch) = &st.config.registration else { return Ok(()); };
    let pass = match pass {
        Some(pass) => pass,
        None => {
            let file = launch.passphrase_file.as_ref().ok_or("local unlock is required")?;
            #[cfg(unix)] {
                use std::os::unix::fs::PermissionsExt;
                if std::fs::metadata(file).map_err(|e| e.to_string())?.permissions().mode() & 0o077 != 0 {
                    return Err("local unlock file must have mode 0600".into());
                }
            }
            let raw = Zeroizing::new(std::fs::read_to_string(file).map_err(|e| e.to_string())?);
            Zeroizing::new(raw.trim_end_matches(['\r', '\n']).to_owned())
        }
    };
    if pass.is_empty() { return Err("empty local unlock".into()); }
    let data = st.config.data.clone();
    let name = launch.name.clone();
    let secret = pass.clone();
    let session = tokio::task::spawn_blocking(move || {
        if !crate::profile::exists(&data) { crate::profile::create(&data, &secret, &name)?; }
        Session::unlock(data, secret).map(|(session, _)| session)
    }).await.map_err(|e| e.to_string())??;
    if let Some(words) = super::recovery::establish_recovery(&st.config.data).await? {
        if let Some(notice) = notice { notice("recovery", words.as_str()); }
        else { println!("Member {} ({}) — save these recovery words privately (shown once): {}", launch.name, st.config.data.display(), words.as_str()); }
    }
    // Keep the public resume destination before consuming a claim; a lost reply is retryable.
    if let Some(slot) = launch.slot { save_coordinator(&st.config.data, &launch.coordinator, slot)?; }
    let owned = st.clone();
    let member = tokio::task::spawn_blocking(move || {
        tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?
            .block_on(register(&owned.config, &pass))
    }).await.map_err(|e| e.to_string())??;
    save_coordinator(&st.config.data, &launch.coordinator, member.slot)?;
    *st.registration.write().await = Some(member.clone());
    *st.session.write().await = Some(session);
    println!("Public roster slot: {}", member.slot);
    Ok(())
}

fn save_coordinator(data: &std::path::Path, origin: &str, slot: u32) -> Result<(), String> {
    if data.join("paired-coordinator.json").try_exists().map_err(|e| e.to_string())? {
        let existing = RegistrationConfig::resume(data, true)?;
        if existing.coordinator != origin || existing.slot != Some(slot) {
            return Err("this profile is already paired with a different coordinator or slot".into());
        }
    }
    let saved = PairedCoordinator { origin: origin.into(), slot };
    let dir = MemberDir::create(data, "").map_err(|e| e.to_string())?;
    dir.write_text("paired-coordinator.json.tmp", &serde_json::to_string(&saved).map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
    std::fs::rename(dir.path().join("paired-coordinator.json.tmp"), dir.path().join("paired-coordinator.json")).map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairing_links_are_strict_and_bind_origin_slot_and_challenge() {
        let link = format!("loki://pair?origin=https%3A%2F%2Fcoordinator.example&slot=7&challenge={}", "ab".repeat(32));
        let launch = RegistrationConfig::pairing(&link, false).unwrap();
        assert_eq!(launch.coordinator, "https://coordinator.example");
        assert_eq!(launch.slot, Some(7));
        assert_eq!(launch.pairing_challenge.as_deref(), Some("ab".repeat(32).as_str()));
        for bad in [link.replace("loki://", "https://"), format!("{link}&slot=8"),
            format!("{link}&token=secret"), format!("{link}#fragment"),
            link.replace("slot=7", "slot=0"), link.replace("slot=7", "slot=07"),
            link.replace("pair?", "pair/path?"), link.replace("pair?", "user@pair?"),
            link.replace("https%3A%2F%2Fcoordinator.example", "http%3A%2F%2Fevil.example"),
            link.replace(&"ab".repeat(32), "bad")] {
            assert!(RegistrationConfig::pairing(&bad, true).is_err(), "{bad}");
        }
        let local = link.replace("https%3A%2F%2Fcoordinator.example", "http%3A%2F%2F127.0.0.1%3A3001");
        assert!(RegistrationConfig::pairing(&local, false).is_err());
        assert!(RegistrationConfig::pairing(&local, true).is_ok());
    }

    #[tokio::test]
    async fn native_unlock_keeps_resume_destination_when_registration_has_no_reply() {
        let data = std::env::temp_dir().join(format!("loki-pair-resume-{}", uuid::Uuid::new_v4()));
        let mut config = super::super::config_from_args(&[
            "--data".into(), data.to_str().unwrap().into(), "--port".into(), "3601".into(),
        ]).unwrap();
        // No local unlock file or plaintext-coordinator opt-in. The local endpoint is still valid.
        config.registration = Some(RegistrationConfig::pairing(&format!(
            "loki://pair?origin=https%3A%2F%2F127.0.0.1%3A1&slot=7&challenge={}", "ab".repeat(32)), false).unwrap());
        let state = std::sync::Arc::new(super::super::state::AppState::new(config));
        let notice: super::super::LocalNotice = std::sync::Arc::new(|kind, words| {
            assert_eq!(kind, "recovery");
            assert_eq!(words.split_whitespace().count(), 24);
        });
        let error = start(&state, Some(Zeroizing::new("native local unlock".into())), Some(&notice)).await.unwrap_err();
        assert!(error.starts_with("registration challenge:"), "{error}");
        let resumed = RegistrationConfig::resume(&data, false).unwrap();
        assert_eq!(resumed.coordinator, "https://127.0.0.1:1");
        assert_eq!(resumed.slot, Some(7));
        assert!(resumed.pairing_challenge.is_none());
        assert!(resumed.passphrase_file.is_none());
        assert!(state.session.read().await.is_none());
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&std::fs::read(data.join("paired-coordinator.json")).unwrap()).unwrap(),
            serde_json::json!({ "origin": "https://127.0.0.1:1", "slot": 7 }));
        std::fs::remove_dir_all(data).unwrap();
    }

    #[test]
    fn a_new_link_cannot_replace_an_existing_resume_destination() {
        let data = std::env::temp_dir().join(format!("loki-pair-pin-{}", uuid::Uuid::new_v4()));
        save_coordinator(&data, "https://coordinator.example", 1).unwrap();
        assert!(save_coordinator(&data, "https://coordinator.example", 2).is_err());
        assert!(save_coordinator(&data, "https://other.example", 1).is_err());
        let saved = RegistrationConfig::resume(&data, false).unwrap();
        assert_eq!(saved.coordinator, "https://coordinator.example");
        assert_eq!(saved.slot, Some(1));
        save_coordinator(&data, "https://coordinator.example", 1).unwrap();
        std::fs::remove_dir_all(data).unwrap();
    }

    #[test]
    fn registration_origins_reject_credentials_paths_and_remote_plaintext() {
        for origin in ["http://example.com", "https://example.com/path", "https://user@example.com", "https://example.com#x", "http://127.0.0.1:3001/"] {
            assert!(plain_origin(origin, true).is_err(), "{origin}");
        }
        assert!(plain_origin("https://example.com", false).is_ok());
        assert!(plain_origin("http://localhost:3001", false).is_err());
        assert!(plain_origin("http://localhost:3001", true).is_ok());
    }

    #[test]
    fn software_device_key_is_local_persistent_and_requires_its_unlock() {
        let data = std::env::temp_dir().join(format!("loki-registration-{}", uuid::Uuid::new_v4()));
        let config = super::super::config_from_args(&[
            "--data".into(), data.to_str().unwrap().into(), "--port".into(), "3601".into(),
        ]).unwrap();
        let key = DeviceKey::open(&config, "member one").unwrap().public().unwrap();
        assert_eq!(key, DeviceKey::open(&config, "member one").unwrap().public().unwrap());
        assert!(DeviceKey::open(&config, "member two").is_err());
        assert_eq!(key, DeviceKey::open(&config, "member one").unwrap().public().unwrap());
        std::fs::remove_dir_all(data).unwrap();
    }

    #[test]
    fn registration_transcript_binds_every_public_field_and_coordinator() {
        let identity = crate::setup_transport::Identity::new(1);
        let sk = SigningKey::random(&mut rand_core::OsRng);
        let public = sk.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        let mut registry = DeviceRegistry::new(identity.public().signing);
        registry.enroll(&public, &identity.authorize_device(&public)).unwrap();
        let mut e = Enrollment { slot: Some(1), signing_pubkey: hex::encode(identity.public().signing), relay_pubkey: hex::encode(identity.public().encryption), advertise_url: "http://127.0.0.1:3601".into(), device_pubkey: hex::encode(&public), authorization: hex::encode(identity.authorize_device(&public)) };
        let origin = "http://localhost:3001";
        let challenge = hex::encode(registry.issue_challenge());
        let message = e.message(origin, &challenge);
        let sig: Signature = sk.sign(&message);
        let sig = sig.to_der();
        assert!(verify_device_signature(&public, &message, sig.as_bytes()).is_ok());
        assert!(verify_device_signature(&public, &e.message("http://localhost:3002", &challenge), sig.as_bytes()).is_err());
        e.slot = Some(2);
        assert!(verify_device_signature(&public, &e.message(origin, &challenge), sig.as_bytes()).is_err());
        e.slot = Some(1);
        e.advertise_url = "http://127.0.0.1:3602".into();
        assert!(verify_device_signature(&public, &e.message(origin, &challenge), sig.as_bytes()).is_err());
    }
}
