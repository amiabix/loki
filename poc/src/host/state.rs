use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use tokio::sync::RwLock;
use zeroize::Zeroizing;

use crate::signer::secure_element::{SecureElement, SoftwareSecureElement, WrappedDek};

/// Launch configuration for one member coordinator (one process per member).
pub struct Config {
    pub registration: Option<super::RegistrationConfig>,
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
        self.validate_secure_element()?;
        #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
        if self.secure_element == "apple" {
            use std::os::unix::fs::DirBuilderExt;
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(|e| format!("signer directory: {e}"))?;
            // Scope the persistent key to this signer directory, resolving path aliases.
            let dir = dir.canonicalize().map_err(|e| format!("signer directory: {e}"))?;
            let mut tag = b"cash.loki.member.kek.v1:".to_vec();
            tag.extend_from_slice(dir.as_os_str().as_encoded_bytes());
            return crate::signer::secure_element_apple::AppleSecureElement::persistent(&tag)
                .map(HostedSecureElement::Apple);
        }
        SoftwareSecureElement::persistent(dir, pass).map(HostedSecureElement::Software)
    }
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

    fn unwrap_dek(&self, wrapped: &WrappedDek) -> Result<Zeroizing<[u8; 32]>, String> {
        match self {
            Self::Software(se) => se.unwrap_dek(wrapped),
            #[cfg(all(target_os = "macos", feature = "apple-enclave"))]
            Self::Apple(se) => se.unwrap_dek(wrapped),
        }
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
    pub session: RwLock<Option<Session>>,
    pub ceremony: std::sync::Mutex<()>,
    pub active_dkgs: std::sync::Mutex<BTreeSet<String>>,
    /// Device login registry, built lazily from `data/recovery.pub` + `data/devices.json` once
    /// a recovery identity exists. Holds outstanding challenges in-process across requests.
    pub device_auth: std::sync::Mutex<Option<crate::signer::device_auth::DeviceRegistry>>,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            registration: RwLock::new(None),
            session: RwLock::new(None),
            ceremony: std::sync::Mutex::new(()),
            active_dkgs: std::sync::Mutex::new(BTreeSet::new()),
            device_auth: std::sync::Mutex::new(None),
        }
    }
}

pub type Shared = std::sync::Arc<AppState>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::secure_element::SealedShare;

    fn config(secure_element: &str) -> Config {
        Config {
            registration: None,
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
