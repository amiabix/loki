use std::collections::BTreeMap;
use std::path::PathBuf;

use tokio::sync::RwLock;
use zeroize::Zeroizing;

/// Launch configuration for one member coordinator (one process per member).
pub struct Config {
    pub data: PathBuf,
    pub port: u16,
    pub network: String,
    pub lightwalletd: Option<String>,
    pub transport: String,
    pub operator_bundle: Option<PathBuf>,
    pub operator_key: Option<String>,
    pub enrollment_issuer: Option<PathBuf>,
    pub development_http: bool,
    /// Printed in the signer link and required on every `/api/*` request.
    pub token: String,
    pub frostd_url: String,
    pub peers: BTreeMap<u16, String>,
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
    pub session: RwLock<Option<Session>>,
    pub ceremony: std::sync::Mutex<()>,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            session: RwLock::new(None),
            ceremony: std::sync::Mutex::new(()),
        }
    }
}

pub type Shared = std::sync::Arc<AppState>;
