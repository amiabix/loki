//! Member-owned startup and public self-registration. No local credential leaves this process.
use std::path::PathBuf;

use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::state::{write_native_key_scope, Config, Session, Shared};
use crate::signer::device_auth::{verify_device_signature, DeviceRegistry};
use crate::state::MemberDir;
#[cfg(all(target_os = "macos", feature = "apple-enclave"))]
use crate::signer::secure_element_apple::KeyFailure;

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

pub(super) fn plain_origin(value: &str, development_http: bool) -> Result<String, String> {
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lokisigner_url: Option<String>,
}

const COORDINATOR_UNREACHABLE: &str = "LokiSigner couldn’t reach the coordinator. Check your connection, then try again.";

#[cfg(any(test, all(target_os = "macos", feature = "apple-enclave")))]
pub(super) async fn fetch_roster(client: &reqwest::Client, origin: &str) -> Result<Vec<PublicMember>, &'static str> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Roster { slots: Vec<PublicMember> }

    let mut response = client.get(format!("{origin}/api/members")).send().await.map_err(|_| COORDINATOR_UNREACHABLE)?;
    if !response.status().is_success() { return Err(COORDINATOR_UNREACHABLE); }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| COORDINATOR_UNREACHABLE)? {
        if body.len() + chunk.len() > 1024 * 1024 { return Err(COORDINATOR_UNREACHABLE); }
        body.extend_from_slice(&chunk);
    }
    serde_json::from_slice::<Roster>(&body).map(|r| r.slots).map_err(|_| COORDINATOR_UNREACHABLE)
}

#[derive(Serialize)]
struct Enrollment {
    #[serde(skip_serializing_if = "Option::is_none")]
    slot: Option<u32>,
    signing_pubkey: String,
    relay_pubkey: String,
    advertise_url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    lokisigner_url: Option<String>,
    device_pubkey: String,
    authorization: String,
}

enum RegistrationFailure {
    Other(String),
    Connection(String),
    Device(DeviceKeyError),
    Refused(String),
    WrongSlot,
}

impl From<String> for RegistrationFailure {
    fn from(error: String) -> Self { Self::Other(error) }
}

impl From<&str> for RegistrationFailure {
    fn from(error: &str) -> Self { Self::Other(error.into()) }
}

impl RegistrationFailure {
    fn native_code(&self) -> &'static str {
        match self {
            #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
            Self::Device(DeviceKeyError::Enclave(error)) => error.message(),
            #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
            Self::Device(DeviceKeyError::CoordinatorUnavailable(_)) => "coordinator-roster-unreachable",
            Self::Device(_) => "device-key",
            Self::WrongSlot | Self::Refused(_) => "registration-refused",
            Self::Connection(_) => "registration-failed",
            Self::Other(_) => "native registration stopped",
        }
    }
}

impl std::fmt::Display for RegistrationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Other(e) | Self::Connection(e) | Self::Refused(e) => f.write_str(e),
            Self::Device(e) => std::fmt::Display::fmt(e, f),
            Self::WrongSlot => f.write_str("registered identity cannot change slot"),
        }
    }
}

// Only the coordinator's exact, bounded 400 refusal is a hint to reread its public roster.
// No arbitrary response text is passed to the UI or treated as a slot number.
async fn registration_response(mut response: reqwest::Response, step: &str, native: bool) -> Result<reqwest::Response, RegistrationFailure> {
    if let Err(error) = response.error_for_status_ref() {
        let error = format!("{step}: {error}");
        if native && response.status() == reqwest::StatusCode::BAD_REQUEST {
            let mut body = Vec::new();
            while let Some(chunk) = response.chunk().await.map_err(|_| RegistrationFailure::Refused(error.clone()))? {
                if body.len() + chunk.len() > 1024 { return Err(RegistrationFailure::Refused(error)); }
                body.extend_from_slice(&chunk);
            }
            if serde_json::from_slice::<serde_json::Value>(&body).ok().as_ref().is_some_and(|json|
                matches!(json["error"].as_str(), Some("registered identity cannot change slot" | "registered identity cannot change slot or relay key"))) {
                return Err(RegistrationFailure::WrongSlot);
            }
        }
        if native && response.status().is_client_error()
            && !matches!(response.status(), reqwest::StatusCode::REQUEST_TIMEOUT | reqwest::StatusCode::TOO_MANY_REQUESTS) {
            return Err(RegistrationFailure::Refused(error));
        }
        return Err(RegistrationFailure::Connection(error));
    }
    Ok(response)
}

impl Enrollment {
    fn message(&self, origin: &str, challenge: &str) -> Vec<u8> {
        let (version, local) = self.lokisigner_url.as_ref()
            .map_or(("v1", String::new()), |url| ("v2", format!("{url}\n")));
        format!("loki-member-registration-{version}\n{origin}\n{}\n{}\n{}\n{}\n{local}{}\n{challenge}",
            self.slot.unwrap_or(0), self.signing_pubkey, self.relay_pubkey, self.advertise_url, self.device_pubkey).into_bytes()
    }
}

#[derive(Debug)]
pub(super) enum DeviceKeyError {
    #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
    Enclave(KeyFailure),
    #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
    CoordinatorUnavailable(&'static str),
    Other(String),
}

impl std::fmt::Display for DeviceKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
            Self::Enclave(error) => std::fmt::Display::fmt(error, f),
            #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
            Self::CoordinatorUnavailable(message) => f.write_str(message),
            Self::Other(error) => f.write_str(error),
        }
    }
}

pub(super) enum DeviceKey {
    Software(SigningKey),
    #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
    Apple(crate::signer::secure_element_apple::AppleSecureElement),
}
impl DeviceKey {
    pub(super) fn open(config: &Config, pass: &str) -> Result<Self, DeviceKeyError> {
        Self::open_with_intent(config, pass, false)
    }

    #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
    pub(super) fn create(config: &Config, pass: &str) -> Result<Self, DeviceKeyError> {
        Self::open_with_intent(config, pass, true)
    }

    #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
    pub(super) fn create_staged(config: &Config, stage: &std::path::Path, dest: &std::path::Path) -> Result<(), DeviceKeyError> {
        Self::apple(config, stage, true, Some(&dest.join("device-auth"))).map(drop)
    }

    #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
    fn apple(config: &Config, root: &std::path::Path, create: bool, published: Option<&std::path::Path>) -> Result<Self, DeviceKeyError> {
        use super::state::{key_scope, open_apple_element, HostedSecureElement};
        let scope = key_scope(config, root).map_err(|_| DeviceKeyError::Enclave(KeyFailure::Other))?;
        let element = open_apple_element(&root.join("device-auth"), create, published, scope, "device-auth", None)
            .map_err(DeviceKeyError::Enclave)?;
        match element {
            HostedSecureElement::Apple(key, _) => Ok(Self::Apple(key)),
            #[cfg(test)]
            HostedSecureElement::Software(_) => Ok(Self::Software(SigningKey::from_slice(&[42; 32]).unwrap())),
            #[cfg(not(test))]
            HostedSecureElement::Software(_) => Err(DeviceKeyError::Enclave(KeyFailure::Other)),
        }
    }

    fn open_with_intent(config: &Config, pass: &str, _create: bool) -> Result<Self, DeviceKeyError> {
        #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
        if config.secure_element == "apple" {
            return Self::apple(config, &config.data, _create, None);
        }
        if config.secure_element != "software" { return Err(DeviceKeyError::Other("device key backend unavailable".into())); }
        // Development stand-in only, selected by the existing software backend flag.
        let dir = MemberDir::create(&config.data, "device-auth").map_err(|e| DeviceKeyError::Other(e.to_string()))?;
        let key = match dir.read_sealed("login.sealed", pass) {
            Ok(raw) => SigningKey::from_slice(&Zeroizing::new(raw)).map_err(|e| DeviceKeyError::Other(e.to_string()))?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let key = SigningKey::random(&mut rand_core::OsRng);
                let bytes = Zeroizing::new(key.to_bytes());
                dir.write_sealed("login.sealed", &bytes, pass).map_err(|e| DeviceKeyError::Other(e.to_string()))?;
                key
            }
            Err(e) => return Err(DeviceKeyError::Other(e.to_string())),
        };
        Ok(Self::Software(key))
    }
    fn public(&self) -> Result<Vec<u8>, DeviceKeyError> {
        match self {
            Self::Software(key) => Ok(key.verifying_key().to_encoded_point(false).as_bytes().to_vec()),
            #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
            Self::Apple(key) => key.public_key_sec1().map_err(DeviceKeyError::Enclave),
        }
    }
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, DeviceKeyError> {
        match self {
            Self::Software(key) => { let sig: Signature = key.sign(message); Ok(sig.to_der().as_bytes().to_vec()) }
            #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
            Self::Apple(key) => key.sign(message).map_err(DeviceKeyError::Enclave),
        }
    }
}

#[cfg(all(target_os = "macos", feature = "apple-enclave"))]
const DEVICE_REGISTERED: &str = "device-registration-confirmed";

async fn registration_device(config: &Config, pass: &str, _client: &reqwest::Client, _origin: &str, _signing_key: &str) -> Result<DeviceKey, DeviceKeyError> {
    let opened = DeviceKey::open(config, pass);
    #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
    if matches!(&opened, Err(DeviceKeyError::Enclave(KeyFailure::Missing))) {
        let saved = config.data.join(DEVICE_REGISTERED).try_exists().map_err(|_| DeviceKeyError::Enclave(KeyFailure::Other))?;
        if saved { return opened; }
        let unreachable = DeviceKeyError::CoordinatorUnavailable(COORDINATOR_UNREACHABLE);
        if config.data.join("paired-coordinator.json").try_exists().map_err(|_| DeviceKeyError::Enclave(KeyFailure::Other))? {
            let pinned = RegistrationConfig::resume(&config.data, config.development_http)
                .map_err(|_| DeviceKeyError::CoordinatorUnavailable(COORDINATOR_UNREACHABLE))?;
            if pinned.coordinator != _origin { return Err(unreachable); }
        }
        let roster = fetch_roster(_client, _origin).await.map_err(DeviceKeyError::CoordinatorUnavailable)?;
        if roster.iter().any(|member| member.slot == 0 || [&member.signing_pubkey, &member.relay_pubkey]
            .iter().any(|key| key.len() != 64 || !key.bytes().all(|b| b.is_ascii_hexdigit()))) {
            return Err(unreachable);
        }
        if roster.iter().any(|member| member.signing_pubkey.eq_ignore_ascii_case(_signing_key)) { return opened; }
        // A coordinator hiding this identity can only cause creation where no key exists.
        return DeviceKey::create(config, pass);
    }
    opened
}

/// `pairing_claim`: the one-use claim from a pairing link, sent on the first attempt only.
async fn register(config: &Config, pass: &str, pairing_claim: Option<&str>, slot: Option<u32>) -> Result<PublicMember, RegistrationFailure> {
    let launch = config.registration.as_ref().ok_or("self-registration not configured")?;
    // Loopback is the device-local browser endpoint, even with an HTTPS coordinator.
    let advertise_url = plain_origin(&config.base_url(), true)?;
    let identity = super::ceremony::identity(&config.data, pass, 1)?;
    let signing_pubkey = hex::encode(identity.public().signing);
    let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(15)).build().map_err(|e| e.to_string())?;
    let device = registration_device(config, pass, &client, &launch.coordinator, &signing_pubkey).await.map_err(RegistrationFailure::Device)?;
    let device_pub = device.public().map_err(RegistrationFailure::Device)?;
    let authorization = identity.authorize_device(&device_pub);
    // Reuse the device enrollment verifier; this profile's identity authorizes the device.
    DeviceRegistry::new(identity.public().signing).enroll(&device_pub, &authorization)?;
    let enrollment = Enrollment {
        slot, signing_pubkey,
        relay_pubkey: hex::encode(identity.public().encryption), advertise_url,
        lokisigner_url: config.lokisigner_url(),
        device_pubkey: hex::encode(&device_pub), authorization: hex::encode(authorization),
    };
    let mut claim = serde_json::to_value(&enrollment).map_err(|e| e.to_string())?;
    if let Some(challenge) = pairing_claim { claim["pairing_challenge"] = challenge.into(); }
    let response = client.post(format!("{}/api/members/challenge", launch.coordinator))
        .json(&claim).send().await.map_err(|e| RegistrationFailure::Connection(format!("registration challenge: {e}")))?;
    let challenge: serde_json::Value = registration_response(response, "registration challenge", config.native).await?
        .json().await.map_err(|e| e.to_string())?;
    let challenge = challenge["challenge"].as_str().filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)))
        .ok_or("invalid coordinator challenge")?;
    let message = enrollment.message(&launch.coordinator, challenge);
    let signature = device.sign(&message).map_err(RegistrationFailure::Device)?;
    verify_device_signature(&device_pub, &message, &signature)?;
    let mut body = serde_json::to_value(&enrollment).map_err(|e| e.to_string())?;
    body["challenge"] = challenge.into();
    body["signature"] = hex::encode(signature).into();
    let response = client.post(format!("{}/api/members", launch.coordinator))
        .json(&body).send().await.map_err(|e| RegistrationFailure::Connection(format!("self-registration: {e}")))?;
    let reply: serde_json::Value = registration_response(response, "self-registration", config.native).await?
        .json().await.map_err(|e| e.to_string())?;
    let member: PublicMember = serde_json::from_value(reply["member"].clone()).map_err(|e| e.to_string())?;
    if member.slot == 0 || slot.is_some_and(|s| s != member.slot) || member.signing_pubkey != enrollment.signing_pubkey
        || member.relay_pubkey != enrollment.relay_pubkey || member.advertise_url != enrollment.advertise_url
        || member.lokisigner_url != enrollment.lokisigner_url {
        return Err("coordinator returned a different identity".into());
    }
    Ok(member)
}

/// Unlock the profile. A native launch with a pairing claim waits for registration and reports
/// failure before going ready. A pending restore tries once and runs even on failure. Regular
/// unlocks and headless launches serve immediately and retry registration in the background.
pub(super) async fn start(st: &Shared, pass: Option<Zeroizing<String>>, notice: Option<&super::LocalNotice>) -> Result<&'static str, String> {
    use std::io::IsTerminal;
    start_with(st, pass, notice, std::io::stdout().is_terminal()).await
}

/// `interactive`: standard output is a terminal, so recovery words printed there reach the
/// member and not a log file.
async fn start_with(st: &Shared, pass: Option<Zeroizing<String>>, notice: Option<&super::LocalNotice>, interactive: bool) -> Result<&'static str, String> {
    let Some(launch) = &st.config.registration else { return Ok("ready"); };
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
    let restored = st.config.data.join(RESTORE_PENDING).is_file();
    let native = st.config.native;
    let apple = st.config.secure_element == "apple";
    let session = tokio::task::spawn_blocking(move || -> Result<Session, String> {
        if !crate::profile::exists(&data) {
            if apple {
                for file in ["profile/profile.sealed", "paired-coordinator.json"] {
                    if data.join(file).try_exists().map_err(|_| "LokiSigner could not access its profile.")? {
                        return Err("LokiSigner could not open its existing profile.".into());
                    }
                }
            }
            if native { write_native_key_scope(&data)?; }
            crate::profile::create(&data, &secret, &name)?;
        }
        Session::unlock(data, secret).map(|(session, _)| session).map_err(|e| {
            if native && e == "sealed file failed authentication: wrong passphrase or tampered file" { "unlock".into() }
            else { e }
        })
    }).await.map_err(|e| e.to_string())??;
    if restored {
        // A published restore already adopted its words. Never mint different words for it,
        // even if someone deleted one of its files after publication.
        if !super::recovery::exists(&st.config.data) { return Err("The restored recovery identity is missing.".into()); }
    } else if notice.is_some() || interactive {
        if let Some(words) = super::recovery::establish_recovery(&st.config.data).await? {
            if let Some(notice) = notice { notice("recovery", words.as_str()); }
            else { println!("Member {} ({}) — save these recovery words privately (shown once): {}", launch.name, st.config.data.display(), words.as_str()); }
        }
    } else if !super::recovery::exists(&st.config.data) {
        // Standard output is redirected (to a log file, typically beside the sealed share), so
        // the words are never minted here. POST /api/recovery-setup returns them to the caller.
        println!("{} ({}) — recovery words not set up: output is not a terminal, so they are not printed; set them up with POST /api/recovery-setup", launch.name, st.config.data.display());
    }
    let data = st.config.data.clone();
    let secret = pass.clone();
    tokio::task::spawn_blocking(move || super::recovery::seal_missing_backups_logged(&data, &secret))
        .await.map_err(|e| e.to_string())?;
    // Keep the public resume destination before consuming a claim; a lost reply is retryable.
    if let Some(slot) = launch.slot { save_coordinator(&st.config.data, &launch.coordinator, slot)?; }
    // Only an unlocked profile saves (or refreshes) the configuration it was paired with.
    if !restored {
        if let Some(fetched) = &st.fetched_config { fetched.save_unlocked(&st.config.data)?; }
    }
    *st.session.write().await = Some(session);
    if restored {
        // The profile is already committed; registration can fail without losing the restore.
        if register_once(st, pass.clone(), None).await.is_ok() { return Ok("restore-ready"); }
        *st.registration_error.write().await = Some(RESTORE_RETRY.into());
    } else if let Some(claim) = launch.pairing_challenge.as_ref().filter(|_| native) {
        // Only a first pairing waits for a refusal or a local key failure before going ready.
        register_once(st, pass, Some(claim.clone())).await.map_err(|e| {
            eprintln!("native coordinator registration failed: {e}");
            e.native_code()
        })?;
        return Ok("ready");
    }
    tokio::spawn(keep_registering(st.clone(), pass, restored, notice.filter(|_| native).cloned()));
    Ok(if restored { "restore-pending" } else { "ready" })
}

pub(super) const RESTORE_PENDING: &str = "restore-registration-pending";
const RESTORE_RETRY: &str = "Vault restored. LokiSigner could not reconnect to the coordinator yet; it will retry without your recovery words.";

/// One registration attempt; on success the public roster entry is saved and served.
async fn register_once(st: &Shared, pass: Zeroizing<String>, pairing_claim: Option<String>) -> Result<PublicMember, RegistrationFailure> {
    let launch = st.config.registration.as_ref().ok_or("self-registration not configured")?;
    let owned = st.clone();
    let member = tokio::task::spawn_blocking(move || -> Result<_, RegistrationFailure> {
        let config = &owned.config;
        let launch = config.registration.as_ref().unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?;
        #[cfg(any(test, all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication")))]
        if config.native && config.data.join(RESTORE_PENDING).is_file() {
            let pinned = RegistrationConfig::resume(&config.data, config.development_http)?;
            if pinned.coordinator != launch.coordinator || !config.data.join("identity.sealed").is_file() {
                return Err("restored registration identity or coordinator missing".into());
            }
            let attempt = |slot| runtime.block_on(register(config, &pass, None, slot));
            return match attempt(pinned.slot) {
                Err(RegistrationFailure::WrongSlot) => {
                    let identity = super::ceremony::identity(&config.data, &pass, 1)?.public();
                    let roster = super::native_recovery::read_roster(&pinned.coordinator)?;
                    let slot = super::native_recovery::restored_slot(&identity, &roster)?;
                    if Some(slot) == pinned.slot || !config.data.join(RESTORE_PENDING).is_file() {
                        return Err(RegistrationFailure::WrongSlot);
                    }
                    write_coordinator(&config.data, &pinned.coordinator, slot)?;
                    attempt(Some(slot))
                }
                result => result,
            };
        }
        runtime.block_on(register(config, &pass, pairing_claim.as_deref(), launch.slot))
    }).await.map_err(|e| e.to_string())?;
    #[cfg(all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication"))]
    if st.config.native && matches!(&member, Err(RegistrationFailure::Device(DeviceKeyError::Enclave(error))) if error.is_gone()) {
        super::native_member::authorize_key_recovery(&st.config.data);
    }
    let member = member?;
    save_coordinator(&st.config.data, &launch.coordinator, member.slot)?;
    if st.config.native && st.config.data.join(RESTORE_PENDING).is_file() {
        std::fs::remove_file(st.config.data.join(RESTORE_PENDING)).map_err(|e| e.to_string())?;
    } else {
        let _ = std::fs::remove_file(st.config.data.join(RESTORE_PENDING));
    }
    #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
    if st.config.secure_element == "apple" {
        match std::fs::OpenOptions::new().write(true).create_new(true).open(st.config.data.join(DEVICE_REGISTERED)) {
            Ok(_) => {},
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {},
            Err(e) => eprintln!("could not record confirmed device registration: {e}"),
        }
    }
    *st.registration.write().await = Some(member.clone());
    Ok(member)
}

/// Retry registration with backoff (5 s doubling to 5 min) until the coordinator accepts it.
async fn keep_registering(st: Shared, pass: Zeroizing<String>, restored: bool, notice: Option<super::LocalNotice>) {
    let mut wait = std::time::Duration::from_secs(5);
    let mut warning = notice.clone();
    #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
    let mut shown_key_errors = std::collections::HashSet::new();
    // The coordinator consumes a pairing claim even when its reply is lost, so only the first
    // attempt carries it. Later attempts resume against the saved coordinator and slot, which
    // the coordinator accepts once the claim's reservation expires (or as the same identity).
    let mut pairing_claim = st.config.registration.as_ref().and_then(|launch| launch.pairing_challenge.clone());
    if restored { tokio::time::sleep(wait).await; }
    loop {
        match register_once(&st, pass.clone(), pairing_claim.take()).await {
            Ok(member) => {
                println!("Public roster slot: {}", member.slot);
                return;
            }
            Err(e) => {
                #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
                let (key_message, roster_unreachable) = match &e {
                    RegistrationFailure::Device(DeviceKeyError::Enclave(key)) => {
                        if shown_key_errors.insert(*key) {
                            if let Some(notice) = &notice {
                                notice(if key.is_gone() { "registration-key-gone" } else { "registration-key" }, key.message());
                            }
                        }
                        (Some(key.message()), false)
                    }
                    RegistrationFailure::Device(DeviceKeyError::CoordinatorUnavailable(_)) => (None, true),
                    _ => (None, false),
                };
                #[cfg(not(all(target_os = "macos", feature = "apple-enclave")))]
                let (key_message, roster_unreachable): (Option<&str>, bool) = (None, false);
                let logged = if restored { RESTORE_RETRY.to_owned() } else { e.to_string() };
                let reported = if let Some(message) = key_message {
                    message.to_owned()
                } else if roster_unreachable {
                    COORDINATOR_UNREACHABLE.to_owned()
                } else if restored {
                    RESTORE_RETRY.to_owned()
                } else if st.config.native {
                    let reason = match e.native_code() {
                        "registration-refused" => "The coordinator refused to register this device.",
                        "registration-failed" => "LokiSigner couldn’t reach the coordinator.",
                        "device-key" => "LokiSigner couldn’t use the device key it needs to connect.",
                        _ => "LokiSigner couldn’t finish connecting to the coordinator.",
                    };
                    format!("{reason} Your profile is unlocked and LokiSigner will keep trying in the background.")
                } else {
                    logged.clone()
                };
                eprintln!("coordinator registration failed, retrying in {}s (the local signer keeps running): {}", wait.as_secs(), key_message.unwrap_or(&logged));
                *st.registration_error.write().await = Some(reported.clone());
                if key_message.is_none() && (!restored || roster_unreachable) {
                    if let Some(notice) = warning.take() { notice("registration-warning", &reported); }
                }
            }
        }
        tokio::time::sleep(wait).await;
        wait = (wait * 2).min(std::time::Duration::from_secs(300));
    }
}

pub(super) fn save_coordinator(data: &std::path::Path, origin: &str, slot: u32) -> Result<(), String> {
    if data.join("paired-coordinator.json").try_exists().map_err(|e| e.to_string())? {
        let existing = RegistrationConfig::resume(data, true)?;
        if existing.coordinator != origin || existing.slot != Some(slot) {
            return Err("this profile is already paired with a different coordinator or slot".into());
        }
        return Ok(());
    }
    write_coordinator(data, origin, slot)
}

fn write_coordinator(data: &std::path::Path, origin: &str, slot: u32) -> Result<(), String> {
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

    /// Wait for the first background registration attempt to fail and return its error.
    async fn failed_attempt(state: &Shared) -> String {
        for _ in 0..200 {
            if let Some(error) = state.registration_error.read().await.clone() { return error; }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!("registration never reported a failed attempt");
    }

    fn pairing_state(data: &std::path::Path) -> Shared {
        let mut config = super::super::config_from_args(&[
            "--data".into(), data.to_str().unwrap().into(), "--port".into(), "3601".into(),
        ]).unwrap();
        // No local unlock file or plaintext-coordinator opt-in. The local endpoint is still valid.
        config.registration = Some(RegistrationConfig::pairing(&format!(
            "loki://pair?origin=https%3A%2F%2F127.0.0.1%3A1&slot=7&challenge={}", "ab".repeat(32)), false).unwrap());
        std::sync::Arc::new(super::super::state::AppState::new(config))
    }

    #[tokio::test]
    async fn transient_client_statuses_are_connection_failures_not_pairing_refusals() {
        use axum::{http::StatusCode, routing::get, Router};
        let app = Router::new()
            .route("/timeout", get(|| async { StatusCode::REQUEST_TIMEOUT }))
            .route("/rate-limit", get(|| async { StatusCode::TOO_MANY_REQUESTS }))
            .route("/refusal", get(|| async { StatusCode::FORBIDDEN }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        for (path, code) in [("timeout", "registration-failed"), ("rate-limit", "registration-failed"), ("refusal", "registration-refused")] {
            let response = reqwest::get(format!("{origin}/{path}")).await.unwrap();
            let error = registration_response(response, "registration challenge", true).await.unwrap_err();
            assert_eq!(error.native_code(), code);
        }
    }

    #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
    #[tokio::test]
    async fn first_pairing_writes_scope_before_opening_or_creating_the_key() {
        use axum::{routing::get, Json, Router};
        let data = std::env::temp_dir().join(format!("loki-fresh-apple-pair-{}", uuid::Uuid::new_v4()));
        let mut state = pairing_state(&data);
        let config = &mut std::sync::Arc::get_mut(&mut state).unwrap().config;
        config.native = true;
        config.secure_element = "apple".into();
        config.development_http = true;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        config.registration.as_mut().unwrap().coordinator = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move {
            let app = Router::new().route("/api/members", get(|| async { Json(serde_json::json!({"slots": []})) }));
            axum::serve(listener, app).await.unwrap();
        });
        let calls = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let observed = calls.clone();
        let profile = data.clone();
        let _fixture = super::super::state::apple_test::install(&data, move |_, tag, create| {
            let scope = super::super::state::read_native_key_scope(&profile).unwrap().unwrap();
            assert_eq!(tag, format!("cash.loki.member.kek.v2:{scope}:device-auth").as_bytes());
            observed.lock().unwrap().push(create);
            Err(if create { KeyFailure::BiometryNotEnrolled } else { KeyFailure::Missing })
        });
        let result = start_with(&state, Some(Zeroizing::new("local unlock".into())), None, false).await;
        assert_eq!(result, Err(KeyFailure::BiometryNotEnrolled.message().into()));
        assert_eq!(*calls.lock().unwrap(), [false, true]);
        assert!(!data.join(DEVICE_REGISTERED).exists());
        std::fs::remove_dir_all(data).unwrap();
    }

    #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
    #[tokio::test]
    async fn background_registration_notifies_once_per_key_failure_class() {
        use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
        use std::time::Duration;
        let data = std::env::temp_dir().join(format!("loki-apple-key-notice-{}", uuid::Uuid::new_v4()));
        let mut state = pairing_state(&data);
        let config = &mut Arc::get_mut(&mut state).unwrap().config;
        config.native = true;
        config.secure_element = "apple".into();
        config.registration.as_mut().unwrap().pairing_challenge = None;
        crate::profile::create(&data, "local unlock", "Member").unwrap();
        let attempts = AtomicUsize::new(0);
        let _fixture = super::super::state::apple_test::install(&data, move |_, _, create| {
            assert!(!create);
            Err(if attempts.fetch_add(1, Ordering::Relaxed) < 2 { KeyFailure::Cancelled } else { KeyFailure::Invalidated })
        });
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let notice: super::super::LocalNotice = Arc::new(move |kind, text| {
            if kind != "recovery" { let _ = tx.send((kind.to_owned(), text.to_owned())); }
        });
        assert_eq!(start_with(&state, Some(Zeroizing::new("local unlock".into())), Some(&notice), false).await.unwrap(), "ready");
        assert_eq!(tokio::time::timeout(Duration::from_secs(5), rx.recv()).await.unwrap().unwrap(),
            ("registration-key".into(), KeyFailure::Cancelled.message().into()));
        assert_eq!(tokio::time::timeout(Duration::from_secs(20), rx.recv()).await.unwrap().unwrap(),
            ("registration-key-gone".into(), KeyFailure::Invalidated.message().into()));
        std::fs::remove_dir_all(data).unwrap();
    }

    #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
    #[tokio::test]
    async fn apple_serve_starts_with_a_missing_registered_device_key() {
        apple_serve_case(true, Some(false), KeyFailure::Missing, 0, Some(KeyFailure::Missing.message())).await;
    }

    #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
    #[tokio::test]
    async fn apple_serve_starts_without_replacing_a_missing_key_for_an_identity_on_the_roster() {
        apple_serve_case(false, Some(true), KeyFailure::Missing, 1, Some(KeyFailure::Missing.message())).await;
    }

    #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
    #[tokio::test]
    async fn apple_serve_can_create_a_missing_key_for_an_identity_not_on_the_roster() {
        apple_serve_case(false, Some(false), KeyFailure::Missing, 1, None).await;
    }

    #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
    #[tokio::test]
    async fn apple_serve_starts_without_creating_a_key_when_the_roster_is_unreadable() {
        apple_serve_case(false, None, KeyFailure::Missing, 1, Some(COORDINATOR_UNREACHABLE)).await;
    }

    #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
    #[tokio::test]
    async fn apple_serve_does_not_check_the_roster_on_an_invalidated_or_cancelled_lookup() {
        for error in [KeyFailure::Invalidated, KeyFailure::Cancelled] {
            apple_serve_case(false, Some(false), error, 0, Some(error.message())).await;
        }
    }

    #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
    async fn apple_serve_case(recorded: bool, on_roster: Option<bool>, lookup: KeyFailure, expected_reads: usize, expected_error: Option<&str>) {
        use axum::{routing::{get, post}, Json, Router};
        use serde_json::{json, Value};
        use std::{sync::{Arc, Mutex, atomic::{AtomicUsize, Ordering}}, os::unix::fs::PermissionsExt};

        let pass = "existing unlock";
        let data = std::env::temp_dir().join(format!("loki-apple-device-{}", uuid::Uuid::new_v4()));
        crate::profile::create(&data, pass, "Member").unwrap();
        let unlock = data.join("passphrase");
        std::fs::write(&unlock, pass).unwrap();
        std::fs::set_permissions(&unlock, std::fs::Permissions::from_mode(0o600)).unwrap();
        if recorded { std::fs::write(data.join(DEVICE_REGISTERED), []).unwrap(); }
        let identity = super::super::ceremony::identity(&data, pass, 1).unwrap().public();
        let reads = Arc::new(AtomicUsize::new(0));
        let count = reads.clone();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let calls = seen.clone();
        let device = data.join("device-auth");
        let expected_tag = [b"cash.loki.member.kek.v1:", data.canonicalize().unwrap().join("device-auth").as_os_str().as_encoded_bytes()].concat();
        let _keychain = super::super::state::apple_test::install(&data, move |path, tag, create| {
            assert_eq!(path, device);
            assert_eq!(tag, expected_tag);
            calls.lock().unwrap().push(create);
            if create { Ok(()) } else { Err(lookup) }
        });
        let pending = data.join(DEVICE_REGISTERED);
        let app = Router::new()
            .route("/api/members", get(move || {
                count.fetch_add(1, Ordering::SeqCst);
                let slots = if on_roster == Some(true) { vec![json!({"slot": 7, "signing_pubkey": hex::encode(identity.signing),
                    "relay_pubkey": hex::encode(identity.encryption), "advertise_url": "http://127.0.0.1:3601"})] } else { vec![] };
                async move { if on_roster.is_none() { Err(axum::http::StatusCode::BAD_GATEWAY) } else { Ok(Json(json!({"slots": slots}))) } }
            }).post(move |Json(body): Json<Value>| {
                assert!(!pending.exists(), "the success record must wait for a validated reply");
                async move { Json(json!({"member": {"slot": body["slot"], "signing_pubkey": body["signing_pubkey"],
                    "relay_pubkey": body["relay_pubkey"], "advertise_url": body["advertise_url"]}})) }
            }))
            .route("/api/members/challenge", post(|| async { Json(json!({"challenge": "ab".repeat(32)})) }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let mut config = super::super::config_from_args(&[
            "--data".into(), data.to_str().unwrap().into(), "--port".into(), "3601".into(),
            "--coordinator-url".into(), origin, "--registration-slot".into(), "7".into(),
            "--local-passphrase-file".into(), unlock.to_str().unwrap().into(), "--development-http".into(),
        ]).unwrap();
        config.secure_element = "apple".into(); // same path as LokiSigner serve
        let state = Arc::new(super::super::state::AppState::new(config));
        assert_eq!(start_with(&state, None, None, false).await.unwrap(), "ready");
        assert!(state.session.read().await.is_some());
        if let Some(message) = expected_error {
            assert_eq!(failed_attempt(&state).await, message);
            assert!(!data.join("device-auth").exists());
            assert_eq!(&*seen.lock().unwrap(), &[false]);
            assert_eq!(data.join(DEVICE_REGISTERED).exists(), recorded);
        } else {
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                while state.registration.read().await.is_none() { tokio::time::sleep(std::time::Duration::from_millis(20)).await; }
            }).await.unwrap();
            assert_eq!(&*seen.lock().unwrap(), &[false, true]);
            assert!(data.join(DEVICE_REGISTERED).is_file());
        }
        assert_eq!(reads.load(Ordering::SeqCst), expected_reads);
        std::fs::remove_dir_all(data).unwrap();
    }

    #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
    #[tokio::test]
    async fn existing_pairing_without_profile_does_not_create_a_new_profile_or_key() {
        let data = std::env::temp_dir().join(format!("loki-incomplete-profile-{}", uuid::Uuid::new_v4()));
        let mut state = pairing_state(&data);
        std::sync::Arc::get_mut(&mut state).unwrap().config.secure_element = "apple".into();
        save_coordinator(&data, "https://127.0.0.1:1", 7).unwrap();
        let _keychain = super::super::state::apple_test::install(&data, |_, _, _| panic!("must not reach Keychain"));
        let result = start_with(&state, Some(Zeroizing::new("existing unlock".into())), None, false).await;
        assert_eq!(result.unwrap_err(), "LokiSigner could not open its existing profile.");
        assert!(!crate::profile::exists(&data));
        std::fs::remove_dir_all(data).unwrap();
    }

    #[tokio::test]
    async fn headless_pairing_keeps_resume_destination_and_retries_when_registration_has_no_reply() {
        let data = std::env::temp_dir().join(format!("loki-pair-resume-{}", uuid::Uuid::new_v4()));
        let state = pairing_state(&data);
        let notice: super::super::LocalNotice = std::sync::Arc::new(|kind, words| {
            assert_eq!(kind, "recovery");
            assert_eq!(words.split_whitespace().count(), 24);
        });
        // The coordinator is unreachable, yet the profile unlocks and startup succeeds.
        start(&state, Some(Zeroizing::new("native local unlock".into())), Some(&notice)).await.unwrap();
        assert!(state.session.read().await.is_some());
        let error = failed_attempt(&state).await;
        assert!(error.starts_with("registration challenge:"), "{error}");
        assert!(state.registration.read().await.is_none());
        let resumed = RegistrationConfig::resume(&data, false).unwrap();
        assert_eq!(resumed.coordinator, "https://127.0.0.1:1");
        assert_eq!(resumed.slot, Some(7));
        assert!(resumed.pairing_challenge.is_none());
        assert!(resumed.passphrase_file.is_none());
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&std::fs::read(data.join("paired-coordinator.json")).unwrap()).unwrap(),
            serde_json::json!({ "origin": "https://127.0.0.1:1", "slot": 7 }));
        std::fs::remove_dir_all(data).unwrap();
    }

    #[tokio::test]
    async fn first_native_pairing_reports_connection_failure_before_going_ready() {
        let data = std::env::temp_dir().join(format!("loki-native-pair-failure-{}", uuid::Uuid::new_v4()));
        let mut state = pairing_state(&data);
        std::sync::Arc::get_mut(&mut state).unwrap().config.native = true;
        let result = start_with(&state, Some(Zeroizing::new("native local unlock".into())), None, false).await;
        assert_eq!(result, Err("registration-failed".into()));
        assert!(crate::profile::exists(&data));
        let scope = std::fs::read_to_string(data.join(super::super::state::NATIVE_KEY_SCOPE)).unwrap();
        assert_eq!(uuid::Uuid::parse_str(&scope).unwrap().get_version_num(), 4);
        std::fs::remove_dir_all(data).unwrap();
    }

    /// A pairing claim is consumed by the coordinator even when the reply is lost, so a retry
    /// that resent it could never register. Only the first attempt carries the claim.
    #[tokio::test]
    async fn registration_retries_resume_without_the_consumed_pairing_claim() {
        use axum::{routing::post, Json, Router};
        use serde_json::{json, Value};
        let claims = std::sync::Arc::new(std::sync::Mutex::new(Vec::<bool>::new()));
        let posts = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let (c, p) = (claims.clone(), posts.clone());
        let app = Router::new()
            .route("/api/members/challenge", post(move |Json(body): Json<Value>| {
                c.lock().unwrap().push(body.get("pairing_challenge").is_some());
                async { Json(json!({ "challenge": "cd".repeat(32) })) }
            }))
            .route("/api/members", post(move |Json(body): Json<Value>| {
                // The first registration reply is lost; the next one succeeds.
                let first = p.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0;
                async move {
                    if first { return Err(axum::http::StatusCode::BAD_GATEWAY); }
                    Ok(Json(json!({ "member": { "slot": body["slot"], "signing_pubkey": body["signing_pubkey"],
                        "relay_pubkey": body["relay_pubkey"], "advertise_url": body["advertise_url"] } })))
                }
            }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move { axum::serve(listener, app).await });
        let data = std::env::temp_dir().join(format!("loki-pair-claim-{}", uuid::Uuid::new_v4()));
        let mut config = super::super::config_from_args(&[
            "--data".into(), data.to_str().unwrap().into(), "--port".into(), "3601".into(),
        ]).unwrap();
        config.registration = Some(RegistrationConfig::pairing(&format!(
            "loki://pair?origin=http%3A%2F%2F127.0.0.1%3A{port}&slot=7&challenge={}", "ab".repeat(32)), true).unwrap());
        let state: Shared = std::sync::Arc::new(super::super::state::AppState::new(config));
        start_with(&state, Some(Zeroizing::new("claim unlock".into())), None, false).await.unwrap();
        let mut member = None;
        for _ in 0..300 {
            if let Some(m) = state.registration.read().await.clone() { member = Some(m); break; }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let member = member.expect("registration recovers after the lost reply");
        assert_eq!(member.slot, 7);
        assert_eq!(*claims.lock().unwrap(), vec![true, false], "only the first attempt carries the claim");
        std::fs::remove_dir_all(data).unwrap();
    }

    /// Words printed to a redirected standard output land in a log file beside the sealed share,
    /// so without a notice hook they are minted at startup only for an interactive terminal.
    #[tokio::test]
    async fn recovery_words_are_not_minted_at_startup_when_output_is_not_a_terminal() {
        for interactive in [false, true] {
            let data = std::env::temp_dir().join(format!("loki-pair-words-{}", uuid::Uuid::new_v4()));
            let state = pairing_state(&data);
            start_with(&state, Some(Zeroizing::new("unlock".into())), None, interactive).await.unwrap();
            assert_eq!(data.join("recovery.pub").exists(), interactive, "interactive: {interactive}");
            assert!(state.session.read().await.is_some());
            failed_attempt(&state).await;
            std::fs::remove_dir_all(data).unwrap();
        }
    }

    /// An unreachable coordinator does not stop the member app: the local API serves an
    /// unlocked profile and reports the failed registration, which keeps retrying.
    #[tokio::test]
    async fn the_local_api_serves_while_coordinator_registration_fails() {
        let data = std::env::temp_dir().join(format!("loki-pair-serve-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&data).unwrap();
        let pass_file = data.join("local.pass");
        std::fs::write(&pass_file, "serve unlock\n").unwrap();
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&pass_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        let config = super::super::config_from_args(&[
            "--data".into(), data.join("state").to_str().unwrap().into(), "--port".into(), "0".into(),
            "--coordinator-url".into(), "http://127.0.0.1:1".into(), "--development-http".into(),
            "--local-passphrase-file".into(), pass_file.to_str().unwrap().into(),
        ]).unwrap();
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        let notice: super::super::LocalNotice = std::sync::Arc::new(move |kind, value| {
            if kind == "ready" { tx.send(value.to_owned()).unwrap(); }
        });
        let app = std::thread::spawn(move || super::super::run_local(config, None, Some(notice), None, None));
        let ready = tokio::task::spawn_blocking(move || rx.recv_timeout(std::time::Duration::from_secs(60))).await.unwrap()
            .unwrap_or_else(|_| panic!("the app did not come up: {:?}", app.join()));
        let (base, token) = ready.split_once("/#").unwrap();
        let client = reqwest::Client::new();
        let get = |path: &str| client.get(format!("{base}{path}")).header("x-loki-token", token).send();
        let status: serde_json::Value = get("/api/status").await.unwrap().json().await.unwrap();
        assert_eq!(status["phase"], "home", "{status}");
        let mut reported = None;
        for _ in 0..200 {
            let reply = get("/api/registration").await.unwrap();
            assert_eq!(reply.status(), reqwest::StatusCode::CONFLICT);
            let body: serde_json::Value = reply.json().await.unwrap();
            let error = body["error"].as_str().unwrap().to_owned();
            if error.contains("retrying after") { reported = Some(error); break; }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        let reported = reported.expect("the failed registration is reported locally");
        assert!(reported.contains("registration challenge:"), "{reported}");
        // The app still serves after the failed attempt; its retry loop keeps it registering.
        assert_eq!(get("/api/status").await.unwrap().status(), reqwest::StatusCode::OK);
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

    #[tokio::test]
    async fn only_a_pending_native_restore_consults_the_roster_and_needs_one_match_for_both_keys() {
        use axum::{http::StatusCode, routing::{get, post}, Json, Router};
        use serde_json::json;
        use std::sync::{Arc, Mutex, atomic::{AtomicUsize, Ordering}};

        let data = std::env::temp_dir().join(format!("loki-registration-repair-{}", uuid::Uuid::new_v4()));
        let pass = "registration repair fixture";
        std::fs::create_dir(&data).unwrap();
        let identity = super::super::ceremony::identity(&data, pass, 1).unwrap().public();
        let matched = json!({ "slot": 19, "signing_pubkey": hex::encode(identity.signing),
            "relay_pubkey": hex::encode(identity.encryption), "advertise_url": "http://127.0.0.1:3601" });
        let mut wrong_relay = matched.clone();
        wrong_relay["relay_pubkey"] = json!("different relay key");
        let roster = Arc::new(Mutex::new(vec![matched.clone()]));
        let reads = Arc::new(AtomicUsize::new(0));
        let (r, count) = (roster.clone(), reads.clone());
        let app = Router::new().route("/api/members", get(move || {
            count.fetch_add(1, Ordering::SeqCst);
            let members = json!({ "slots": *r.lock().unwrap() });
            async { Json(members) }
        })).route("/api/members/challenge", post(|| async {
            (StatusCode::BAD_REQUEST, Json(json!({ "error": "registered identity cannot change slot or relay key" })))
        }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await });
        save_coordinator(&data, &origin, 7).unwrap();

        for (native, pending, entries, expected_reads) in [
            (true, false, vec![matched.clone()], 0),
            (false, true, vec![matched.clone()], 0), // Headless refuses as before, without repinning.
            (true, true, vec![wrong_relay], 1),
            (true, true, vec![matched.clone(), matched], 2),
        ] {
            if pending { std::fs::write(data.join(RESTORE_PENDING), []).unwrap(); }
            *roster.lock().unwrap() = entries;
            let mut config = super::super::config_from_args(&["--data".into(), data.to_str().unwrap().into(),
                "--port".into(), "3601".into(), "--development-http".into()]).unwrap();
            config.registration = Some(RegistrationConfig::resume(&data, true).unwrap());
            config.native = native;
            let state = Arc::new(super::super::state::AppState::new(config));
            let error = register_once(&state, Zeroizing::new(pass.into()), None).await.err().expect("refused enrollment");
            if !native { assert!(error.to_string().starts_with("registration challenge:")); }
            assert_eq!(reads.load(Ordering::SeqCst), expected_reads);
            assert_eq!(RegistrationConfig::resume(&data, true).unwrap().slot, Some(7));
            assert_eq!(data.join(RESTORE_PENDING).exists(), pending);
        }
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

    #[tokio::test]
    async fn native_registration_sends_its_loopback_address_and_requires_the_same_address_back() {
        use axum::{routing::post, Json, Router};
        use serde_json::{json, Value};
        use std::sync::{atomic::{AtomicUsize, Ordering}, Arc};

        const LOCAL: &str = "http://127.0.0.1:3601";
        let replies = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route("/api/members/challenge", post(|Json(body): Json<Value>| async move {
                assert_eq!(body["lokisigner_url"], LOCAL);
                Json(json!({"challenge": "cd".repeat(32)}))
            }))
            .route("/api/members", post(move |Json(body): Json<Value>| {
                let reply = replies.fetch_add(1, Ordering::SeqCst);
                async move {
                    assert_eq!(body["lokisigner_url"], LOCAL);
                    let mut member = json!({"slot": body["slot"], "signing_pubkey": body["signing_pubkey"],
                        "relay_pubkey": body["relay_pubkey"], "advertise_url": body["advertise_url"]});
                    match reply {
                        0 => member["lokisigner_url"] = body["lokisigner_url"].clone(),
                        1 => member["lokisigner_url"] = "http://127.0.0.1:3602".into(),
                        _ => {} // An absent field must not be silently accepted either.
                    }
                    Json(json!({"member": member}))
                }
            }));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let coordinator = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap(); });
        let data = std::env::temp_dir().join(format!("loki-native-register-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir(&data).unwrap();
        let mut config = super::super::native_config_from_args(&[
            "--data".into(), data.to_str().unwrap().into(), "--port".into(), "3601".into(),
            "--registration-slot".into(), "7".into(), "--coordinator-url".into(), coordinator,
            "--local-passphrase-file".into(), "unused".into(), "--development-http".into(),
        ]).unwrap();
        config.secure_element = "software".into();
        let member = register(&config, "native unlock", None, Some(7)).await.map_err(|e| e.to_string()).unwrap();
        assert_eq!(member.lokisigner_url.as_deref(), Some(LOCAL));
        for _ in 0..2 {
            assert_eq!(register(&config, "native unlock", None, Some(7)).await.unwrap_err().to_string(), "coordinator returned a different identity");
        }
        server.abort();
        std::fs::remove_dir_all(data).unwrap();
    }

    #[test]
    fn registration_v2_transcript_matches_the_shared_wire_fixture() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!("../../tests/fixtures/lokisigner-registration-v2.json")).unwrap();
        let field = |name: &str| fixture["enrollment"][name].as_str().unwrap().to_owned();
        let enrollment = Enrollment {
            slot: Some(fixture["enrollment"]["slot"].as_u64().unwrap() as u32),
            signing_pubkey: field("signing_pubkey"), relay_pubkey: field("relay_pubkey"),
            advertise_url: field("advertise_url"), lokisigner_url: Some(field("lokisigner_url")),
            device_pubkey: field("device_pubkey"), authorization: field("authorization"),
        };
        assert_eq!(enrollment.message(fixture["origin"].as_str().unwrap(), fixture["challenge"].as_str().unwrap()),
            fixture["expected"].as_str().unwrap().as_bytes());
    }

    #[test]
    fn registration_transcript_binds_every_public_field_and_coordinator() {
        let identity = crate::setup_transport::Identity::new(1);
        let sk = SigningKey::random(&mut rand_core::OsRng);
        let public = sk.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        let mut registry = DeviceRegistry::new(identity.public().signing);
        registry.enroll(&public, &identity.authorize_device(&public)).unwrap();
        let mut e = Enrollment { slot: Some(1), signing_pubkey: hex::encode(identity.public().signing), relay_pubkey: hex::encode(identity.public().encryption), advertise_url: "http://127.0.0.1:3601".into(), lokisigner_url: None, device_pubkey: hex::encode(&public), authorization: hex::encode(identity.authorize_device(&public)) };
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
