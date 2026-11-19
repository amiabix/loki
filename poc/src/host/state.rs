use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use tokio::sync::RwLock;
use zeroize::Zeroizing;

use crate::signer::secure_element::{OpenError, SecureElement, SoftwareSecureElement, WrappedDek};

/// Launch configuration for one member coordinator (one process per member).
pub struct Config {
    pub registration: Option<super::RegistrationConfig>,
    /// The GUI entry points own local recovery and may use a profile-scoped Apple key tag.
    pub(super) native: bool,
    pub data: PathBuf,
    pub port: u16,
    pub bind: std::net::IpAddr,
    pub advertise_url: Option<String>,
    pub network: String,
    pub lightwalletd: Option<String>,
    pub transport: String,
    pub secure_element: String,
    pub operator_bundle: Option<PathBuf>,
    /// Two pinned external nonce-witness mailboxes; required for hosted signing.
    pub nonce_witnesses: Option<PathBuf>,
    pub operator_key: Option<String>,
    pub enrollment_issuer: Option<PathBuf>,
    pub development_http: bool,
    /// Printed in the signer link and required on every `/api/*` request.
    pub token: String,
    pub frostd_url: String,
    /// Operator URL allowlist for remote peers; vault slots never resolve through this map.
    pub peers: BTreeMap<u16, String>,
    /// Operator opt-in: admit new loopback peer origins outside regtest, for a co-located
    /// demo where every signer runs on this host. Off by default so real deployments stay locked.
    pub loopback_peers: bool,
}

impl Config {
    pub(super) fn base_url(&self) -> String {
        self.advertise_url.clone().unwrap_or_else(|| format!("http://127.0.0.1:{}", self.port))
            .trim_end_matches('/').to_owned()
    }

    pub(super) fn validate_peer_url(&self, base: &str) -> Result<(), String> {
        let url = reqwest::Url::parse(base).map_err(|_| "invalid member base URL")?;
        let origin = url.origin().ascii_serialization();
        let explicit_default = if url.port().is_none() {
            format!("{origin}:{}", if url.scheme() == "https" { 443 } else { 80 })
        } else {
            origin.clone()
        };
        if !matches!(url.scheme(), "http" | "https") || !url.username().is_empty()
            || url.password().is_some() || url.query().is_some() || url.fragment().is_some()
            || url.path() != "/" || (origin != base && explicit_default != base) {
            return Err("member URL must be a plain HTTP(S) origin".into());
        }
        // The co-located regtest demo, or an explicit operator opt-in, admits new loopback origins.
        let local = (self.network == "regtest" || self.loopback_peers)
            && matches!(url.host_str(), Some("127.0.0.1" | "[::1]"))
            && url.port().is_some_and(|p| p >= 1024);
        if local || self.peers.values().any(|allowed| allowed == &origin || allowed == &explicit_default) {
            Ok(())
        } else {
            Err("member URL is not an allowed peer".into())
        }
    }

    pub fn validate_secure_element(&self) -> Result<(), String> {
        match self.secure_element.as_str() {
            "software" => Ok(()),
            "apple" if cfg!(all(target_os = "macos", feature = "apple-enclave")) => Ok(()),
            "apple" => Err("--secure-element apple requires macOS and the apple-enclave feature".into()),
            _ => Err("--secure-element must be software or apple".into()),
        }
    }

    pub(super) fn open_secure_element(&self, dir: &Path, pass: &str) -> Result<HostedSecureElement, String> {
        let result = self.open_element(dir, pass, None);
        eprintln!("secure-element open: {}", if result.is_ok() { "ok" } else { "error" });
        result
    }

    // A staged vault must use the same Enclave key after its directory is published.
    pub(super) fn open_element(&self, dir: &Path, pass: &str, _published: Option<&Path>) -> Result<HostedSecureElement, String> {
        self.validate_secure_element()?;
        #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
        if self.secure_element == "apple" {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(|e| format!("signer directory: {e}"))?;
            // Only device login keys opt into the scope here. A staged restore uses the
            // published path for legacy tags; scoped callers read the actual profile root.
            let scope = if self.native && dir.file_name().is_some_and(|n| n == "device-auth") {
                read_native_key_scope(&self.data)?
            } else { None };
            let dir = match _published {
                Some(path) => path.to_owned(),
                None => dir.canonicalize().map_err(|e| format!("signer directory: {e}"))?,
            };
            let tag = apple_key_tag(&dir, scope, "device-auth");
            return crate::signer::secure_element_apple::AppleSecureElement::persistent(&tag)
                .map(HostedSecureElement::Apple);
        }
        SoftwareSecureElement::persistent(dir, pass).map(HostedSecureElement::Software)
    }
}

pub(super) const NATIVE_KEY_SCOPE: &str = "native-key-scope";

pub(super) fn write_native_key_scope(data: &Path) -> Result<(), String> {
    let dir = crate::state::MemberDir::create(data, "").map_err(|e| e.to_string())?;
    dir.write_text(NATIVE_KEY_SCOPE, &uuid::Uuid::new_v4().to_string()).map_err(|e| e.to_string())
}

#[cfg(any(test, all(target_os = "macos", feature = "apple-enclave")))]
pub(super) fn read_native_key_scope(data: &Path) -> Result<Option<uuid::Uuid>, String> {
    match std::fs::read_to_string(data.join(NATIVE_KEY_SCOPE)) {
        Ok(scope) => uuid::Uuid::parse_str(&scope).map(Some).map_err(|_| "invalid native key scope".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

/// The scoped form survives a folder move. For a staged restore, pass the scope read from
/// the staged profile and use the published directory only as the legacy fallback.
#[cfg(any(test, all(target_os = "macos", feature = "apple-enclave")))]
pub(super) fn apple_key_tag(dir: &Path, scope: Option<uuid::Uuid>, role: &str) -> Vec<u8> {
    if let Some(scope) = scope {
        return format!("cash.loki.member.kek.v2:{scope}:{role}").into_bytes();
    }
    let mut tag = b"cash.loki.member.kek.v1:".to_vec();
    tag.extend_from_slice(dir.as_os_str().as_encoded_bytes());
    tag
}

pub(super) enum HostedSecureElement {
    Software(SoftwareSecureElement),
    #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
    Apple(crate::signer::secure_element_apple::AppleSecureElement),
}

impl SecureElement for HostedSecureElement {
    fn wrap_dek(&self, dek: &[u8; 32]) -> Result<WrappedDek, String> {
        match self {
            Self::Software(se) => se.wrap_dek(dek),
            #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
            Self::Apple(se) => se.wrap_dek(dek),
        }
    }

    fn unwrap_dek(&self, wrapped: &WrappedDek) -> Result<Zeroizing<[u8; 32]>, OpenError> {
        let result = match self {
            Self::Software(se) => se.unwrap_dek(wrapped),
            #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
            Self::Apple(se) => se.unwrap_dek(wrapped),
        };
        let outcome = match &result {
            Ok(_) => "ok",
            Err(OpenError::WrongBinding(_)) => "error (wrong binding)",
            Err(OpenError::Element(_)) => "error (secure element)",
        };
        eprintln!("secure-element unwrap: {outcome}");
        result
    }
}

/// The unlocked profile. Holds only the passphrase + data root (no live connections);
/// the hosted relay runtime is a process-wide singleton in `setup_relay`. Mirrors
/// `member_service::Service` but shaped for the HTTP + `spawn_blocking` model.
pub struct Session {
    pub passphrase: Zeroizing<String>,
    pub data: PathBuf,
}

impl Session {
    /// Validate the sealed profile with this passphrase and prime the KDF cache.
    pub fn unlock(
        data: PathBuf,
        passphrase: Zeroizing<String>,
    ) -> Result<(Self, serde_json::Value), String> {
        let profile = crate::profile::open(&data, &passphrase)?;
        crate::seal_kdf::enable_session_cache(&passphrase);
        Ok((Self { passphrase, data }, profile))
    }
}

pub struct AppState {
    pub config: Config,
    pub(super) registration: RwLock<Option<super::registration::PublicMember>>,
    /// The last failed registration attempt, reported locally while registration retries.
    pub(super) registration_error: RwLock<Option<String>>,
    pub session: RwLock<Option<Session>>,
    pub ceremony: std::sync::Mutex<()>,
    pub payment: std::sync::Mutex<()>,
    pub active_payments: std::sync::Mutex<BTreeSet<String>>,
    pub active_dkgs: std::sync::Mutex<BTreeSet<String>>,
    /// Device login registry, built lazily from `data/recovery.pub` + `data/devices.json` once
    /// a recovery identity exists. Holds outstanding challenges in-process across requests.
    pub device_auth: std::sync::Mutex<Option<crate::signer::device_auth::DeviceRegistry>>,
    /// The member's native payment decision; `None` (headless) refuses every payment.
    pub approval: Option<super::LocalApproval>,
    /// The member's native roster-code comparison; `None` (headless) trusts the caller of
    /// `/api/agree`.
    pub roster_confirmation: Option<super::LocalRosterConfirmation>,
    /// The vault whose roster code the native app is asking about; it asks about one at a time.
    pub(super) roster_asking: std::sync::Mutex<Option<String>>,
    /// Vaults whose codes the member said differ, refused until the app restarts.
    pub(super) roster_refused: std::sync::Mutex<BTreeSet<String>>,
    /// Each vault's group viewing key, read from its device-bound signer once per process.
    pub(super) viewing_keys: std::sync::Mutex<BTreeMap<String, orchard::keys::FullViewingKey>>,
    /// The signer configuration LokiSigner fetched for this launch, saved once the profile unlocks.
    pub(super) fetched_config: Option<super::FetchedConfig>,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            registration: RwLock::new(None),
            registration_error: RwLock::new(None),
            session: RwLock::new(None),
            ceremony: std::sync::Mutex::new(()),
            payment: std::sync::Mutex::new(()),
            active_payments: std::sync::Mutex::new(BTreeSet::new()),
            active_dkgs: std::sync::Mutex::new(BTreeSet::new()),
            device_auth: std::sync::Mutex::new(None),
            approval: None,
            roster_confirmation: None,
            roster_asking: std::sync::Mutex::new(None),
            roster_refused: std::sync::Mutex::new(BTreeSet::new()),
            viewing_keys: std::sync::Mutex::new(BTreeMap::new()),
            fetched_config: None,
        }
    }
}

pub type Shared = std::sync::Arc<AppState>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::secure_element::SealedShare;

    #[test]
    fn apple_tags_keep_legacy_identity_and_scope_new_keys_to_the_profile_and_role() {
        let data = std::env::temp_dir().join(format!("loki-device-tag-{}", uuid::Uuid::new_v4()));
        let device = data.join("device-auth");
        let legacy = |path: &Path| format!("cash.loki.member.kek.v1:{}", path.display()).into_bytes();
        assert_eq!(apple_key_tag(&device, read_native_key_scope(&data).unwrap(), "device-auth"), legacy(&device));
        write_native_key_scope(&data).unwrap();
        let scope = read_native_key_scope(&data).unwrap();
        let tag = apple_key_tag(&device, scope, "device-auth");
        assert_ne!(tag, legacy(&device));
        assert_eq!(tag, apple_key_tag(Path::new("moved/profile/device-auth"), scope, "device-auth"));
        assert_ne!(tag, apple_key_tag(&device, scope, "vault:example"));
        write_native_key_scope(&data).unwrap();
        assert_ne!(tag, apple_key_tag(&device, read_native_key_scope(&data).unwrap(), "device-auth"));
        let vault = data.join("vaults/vault/signer");
        assert_eq!(apple_key_tag(&vault, None, "vault:example"), legacy(&vault));
        std::fs::remove_dir_all(data).unwrap();
    }

    fn config(secure_element: &str) -> Config {
        Config {
            registration: None, native: false,
            bind: "127.0.0.1".parse().unwrap(), advertise_url: None,
            data: PathBuf::new(), port: 3001, network: "regtest".into(),
            lightwalletd: None, transport: "local".into(), secure_element: secure_element.into(),
            operator_bundle: None, nonce_witnesses: None, operator_key: None, enrollment_issuer: None,
            development_http: false, token: "test".into(),
            frostd_url: "http://127.0.0.1:2744".into(), peers: BTreeMap::new(),
            loopback_peers: false,
        }
    }

    #[test]
    fn cli_network_is_testnet_or_regtest_only() {
        let args = |network: Option<&str>| {
            let mut args: Vec<String> = ["--data", "unused", "--port", "0"].map(Into::into).to_vec();
            args.extend(network.map(|n| ["--network".into(), n.into()]).into_iter().flatten());
            super::super::config_from_args(&args).map(|c| c.network)
        };
        assert_eq!(args(None).unwrap(), "regtest");
        assert_eq!(args(Some("testnet")).unwrap(), "testnet");
        for refused in ["mainnet", "main", "Mainnet", "", "test"] {
            assert!(args(Some(refused)).is_err(), "{refused}");
        }
    }

    #[test]
    fn peer_urls_allow_regtest_loopback_and_operator_origins_only() {
        let mut c = config("software");
        for url in ["http://127.0.0.1:42783", "http://[::1]:42784"] {
            assert!(c.validate_peer_url(url).is_ok(), "{url}");
        }
        for url in ["http://169.254.169.254", "http://10.0.0.1:4000", "http://example.com",
            "http://localhost:4000", "http://127.0.0.1:80", "http://127.0.0.1:4000/path",
            "http://127.0.0.1:4000?url=evil", "http://127.0.0.1:4000#evil",
            "http://user@127.0.0.1:4000", "file:///etc/passwd", "http://127.1:4000"] {
            assert!(c.validate_peer_url(url).is_err(), "{url}");
        }
        c.network = "testnet".into();
        assert!(c.validate_peer_url("http://127.0.0.1:42783").is_err());
        c.loopback_peers = true;
        assert!(c.validate_peer_url("http://127.0.0.1:42783").is_ok());
        assert!(c.validate_peer_url("http://127.0.0.1:80").is_err());
        c.loopback_peers = false;
        c.peers.insert(9, "https://signer.example".into());
        assert!(c.validate_peer_url("https://signer.example").is_ok());
        assert!(c.validate_peer_url("https://signer.example:443").is_ok());
        c.peers.insert(9, "https://signer.example:443".into());
        assert!(c.validate_peer_url("https://signer.example").is_ok());
        assert!(c.validate_peer_url("https://signer.example:444").is_err());
    }

    #[test]
    fn secure_element_selection_rejects_invalid_or_unavailable_backends() {
        assert!(config("software").validate_secure_element().is_ok());
        assert_eq!(
            config("apple").validate_secure_element().is_ok(),
            cfg!(all(target_os = "macos", feature = "apple-enclave")),
        );
        let dir = std::env::temp_dir().join(format!("loki-invalid-se-{}", uuid::Uuid::new_v4()));
        for name in ["", "unknown", "Software"] {
            assert!(config(name).validate_secure_element().is_err());
            assert!(config(name).open_secure_element(&dir, "pass").is_err());
        }
        #[cfg(not(all(target_os = "macos", feature = "apple-enclave")))]
        assert!(config("apple").open_secure_element(&dir, "pass").is_err());
        assert!(!dir.exists());
    }

    #[test]
    fn software_secure_element_preserves_existing_seals_and_kek() {
        let dir = std::env::temp_dir().join(format!("loki-software-se-{}", uuid::Uuid::new_v4()));
        let old = SoftwareSecureElement::persistent(&dir, "pass").unwrap();
        let kek = std::fs::read(dir.join("kek.sealed")).unwrap();
        let sealed = SealedShare::seal(&old, 0, b"share").unwrap();
        let configured = config("software").open_secure_element(&dir, "pass").unwrap();
        assert_eq!(&**sealed.open(&configured).unwrap(), b"share");
        let sealed = SealedShare::seal(&configured, 0, b"share").unwrap();
        assert_eq!(&**sealed.open(&old).unwrap(), b"share");
        let reopened = config("software").open_secure_element(&dir, "pass").unwrap();
        assert_eq!(&**sealed.open(&reopened).unwrap(), b"share");
        assert!(config("software").open_secure_element(&dir, "wrong pass").is_err());
        assert_eq!(std::fs::read(dir.join("kek.sealed")).unwrap(), kek);
        std::fs::remove_dir_all(dir).unwrap();
    }
}
