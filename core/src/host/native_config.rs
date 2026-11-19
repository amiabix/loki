//! The configuration LokiSigner, the native member app, runs with on a normal launch: network,
//! frostd, lightwalletd and the two nonce witnesses. The coordinator whose origin the member
//! confirmed chooses them. It serves the browser signer's own values at `/api/signer-config`.
//! LokiSigner asks only after the member confirmed that origin, shows the values before it
//! pairs or unlocks, and saves them owner-only in the data directory, pinned to that
//! coordinator, once the profile has unlocked. An explicit launch flag overrides its field for
//! that launch only, and then nothing is saved. Only the native path (`loki_member_app_pair`)
//! uses this; the headless `loki_member_app` and `LokiSigner serve` keep their flags and defaults.
//!
//! Nothing the coordinator sends is echoed in an error: the member reads these errors in
//! LokiSigner's own dialogs.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::nonce_witness::{self, WitnessConfig};
use super::{Config, RegistrationConfig};

/// Network, frostd and lightwalletd, with the origin of the coordinator that chose them.
const SAVED: &str = "signer-config.json";
/// The saved witnesses, in the `--nonce-witnesses` file format.
const WITNESSES: &str = "nonce-witnesses.json";
const FETCH_LIMIT: usize = 65_536;
/// The flags that override a coordinator's value for one field.
const OVERRIDES: [&str; 4] = ["--network", "--frostd-url", "--lightwalletd-url", "--nonce-witnesses"];

/// The deployment's signer configuration, as `GET <coordinator>/api/signer-config` serves it.
/// Untrusted until [`Deployment::check`] passes.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Deployment {
    pub network: String,
    pub frostd_url: String,
    pub lightwalletd_url: Option<String>,
    pub nonce_witnesses: [WitnessConfig; 2],
}

impl Deployment {
    fn check(&self, development_http: bool) -> Result<(), String> {
        crate::network::VaultNetwork::parse(&self.network)?;
        endpoint(&self.frostd_url, development_http, "frostd URL")?;
        if let Some(url) = &self.lightwalletd_url { endpoint(url, development_http, "lightwalletd URL")?; }
        nonce_witness::check(&self.nonce_witnesses, development_http)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Saved {
    origin: String,
    network: String,
    frostd_url: String,
    lightwalletd_url: Option<String>,
}

/// What LokiSigner shows the member before it pairs or unlocks, and then runs with unchanged.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeConfig {
    pub coordinator: String,
    pub slot: u32,
    pub network: String,
    pub frostd_url: String,
    pub lightwalletd_url: Option<String>,
    /// The two witness endpoints, for the member to read.
    pub nonce_witnesses: [String; 2],
    /// Fetched from `coordinator` for this launch.
    pub fetched: Option<Deployment>,
    /// Whether the fetched configuration is saved once the profile unlocks: not when a launch
    /// flag overrides any field, because the member was then shown something else.
    pub save: bool,
}

/// A configuration fetched for this launch: its witnesses are used from memory, and it is saved
/// for later launches only after the profile unlocks (see `registration::start`).
pub struct FetchedConfig {
    origin: String,
    deployment: Deployment,
    save: bool,
}

impl FetchedConfig {
    pub(super) fn witnesses(&self) -> [WitnessConfig; 2] { self.deployment.nonce_witnesses.clone() }

    /// Called once the profile has unlocked, after the paired coordinator is saved.
    pub(super) fn save_unlocked(&self, data: &Path) -> Result<(), String> {
        if self.save { save(data, &self.origin, &self.deployment) } else { Ok(()) }
    }
}

impl NativeConfig {
    /// The configuration a native launch with these arguments and pairing link would use.
    /// Fetches from the coordinator for a pairing link, or for an unlock with nothing saved.
    pub fn preview(args: &[String], pairing_url: Option<&str>) -> Result<Self, String> {
        Self::resolve(args, pairing_url, fetch)
    }

    #[cfg(all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication"))]
    pub(crate) fn recovery_origin(args: &[String], origin: &str) -> Result<String, String> {
        let config = super::native_config_from_args(args)?;
        super::registration::plain_origin(origin, config.development_http)
    }

    #[cfg(all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication"))]
    pub(crate) fn preview_restore(args: &[String], origin: &str) -> Result<Self, String> {
        let origin = Self::recovery_origin(args, origin)?;
        let deployment = fetch(&origin)?;
        Self::resolve_restore(args, origin, deployment)
    }

    #[cfg(all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication"))]
    fn resolve_restore(args: &[String], origin: String, deployment: Deployment) -> Result<Self, String> {
        // The coordinator slot is unknown until we open the backup and find its identity.
        Self::merge(args, Some((origin, 0)), Some(deployment.clone()), Some(deployment), super::native_config_from_args(args)?.development_http)
    }

    #[cfg(all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication"))]
    pub(crate) fn apply_restore(self, config: &mut Config, args: &[String], origin: &str) -> Result<Option<FetchedConfig>, String> {
        let origin = Self::recovery_origin(args, origin)?;
        let deployment = self.fetched.clone().ok_or("missing restored profile configuration")?;
        let resolved = Self::resolve_restore(args, origin, deployment)?;
        self.apply_resolved(config, args, resolved)
    }

    /// The coordinator and slot a pairing link names, checked without any network request, for
    /// the member to confirm before LokiSigner asks that coordinator for anything.
    pub fn pairing_target(args: &[String], pairing_url: &str) -> Result<(String, u32), String> {
        let config = super::native_config_from_args(args)?;
        Self::target(&config, Some(pairing_url))?.ok_or_else(|| "invalid pairing link".into())
    }

    /// Run with the configuration the member saw: resolve it again from the same launch, using
    /// the shown fetch instead of a second one, and set it on `config`. Returns what was fetched,
    /// which is saved only after the profile unlocks.
    pub fn apply(self, config: &mut Config, args: &[String], pairing_url: Option<&str>) -> Result<Option<FetchedConfig>, String> {
        let shown = self.fetched.clone();
        let resolved = Self::resolve(args, pairing_url, |_| shown.ok_or_else(|| "the confirmed configuration is missing".to_string()))?;
        self.apply_resolved(config, args, resolved)
    }

    fn apply_resolved(self, config: &mut Config, args: &[String], resolved: Self) -> Result<Option<FetchedConfig>, String> {
        if resolved != self {
            return Err("the configuration changed after it was shown; open LokiSigner again".into());
        }
        // A witness flag names its file; fetched witnesses stay in memory; otherwise the saved file.
        config.nonce_witnesses = match (value(args, "--nonce-witnesses"), &self.fetched) {
            (Some(path), _) => Some(PathBuf::from(path)),
            (None, Some(_)) => None,
            (None, None) => Some(config.data.join(WITNESSES)),
        };
        config.network = self.network;
        config.frostd_url = self.frostd_url;
        config.lightwalletd = self.lightwalletd_url;
        Ok(self.fetched.map(|deployment| FetchedConfig { origin: self.coordinator, deployment, save: self.save }))
    }

    /// The pairing link's coordinator and slot, or the paired ones for an unlock. A link for a
    /// coordinator or slot other than the paired one is refused.
    fn target(config: &Config, pairing_url: Option<&str>) -> Result<Option<(String, u32)>, String> {
        let paired = paired_coordinator(&config.data, config.development_http)?;
        let Some(link) = pairing_url else { return Ok(paired) };
        let link = RegistrationConfig::pairing(link, config.development_http)?;
        let target = (link.coordinator, link.slot.ok_or("invalid pairing slot")?);
        if let Some((origin, slot)) = paired.filter(|paired| *paired != target) {
            return Err(format!("this profile is already paired with {origin} slot {slot}; a link for another coordinator or slot is refused"));
        }
        Ok(Some(target))
    }

    fn resolve(args: &[String], pairing_url: Option<&str>, fetch: impl FnOnce(&str) -> Result<Deployment, String>) -> Result<Self, String> {
        let config = super::native_config_from_args(args)?;
        let (data, development_http) = (&config.data, config.development_http);
        let target = Self::target(&config, pairing_url)?;
        let saved = load(data, development_http)?;
        if let (Some((origin, _)), Some((coordinator, _))) = (&saved, &target) {
            if origin != coordinator { return Err(format!("the saved configuration belongs to {origin}, not {coordinator}")); }
        }
        let flag = |name: &str| value(args, name);
        let flags_complete = ["--network", "--frostd-url", "--nonce-witnesses"].iter().all(|name| flag(name).is_some())
            && (flag("--network").as_deref() == Some("regtest") || flag("--lightwalletd-url").is_some());
        // A pairing link always fetches, so a new link refreshes the saved configuration. An
        // unlock uses the saved one, and fetches only when none is saved and the flags lack a field.
        let fetched = match (&target, saved) {
            (Some((coordinator, _)), _) if pairing_url.is_some() => Some(fetch(coordinator)?),
            (_, Some((_, saved))) => return Self::merge(args, target, Some(saved), None, development_http),
            (Some((coordinator, _)), None) if !flags_complete => Some(fetch(coordinator)?),
            _ => None,
        };
        Self::merge(args, target, fetched.clone(), fetched, development_http)
    }

    fn merge(args: &[String], target: Option<(String, u32)>, deployment: Option<Deployment>, fetched: Option<Deployment>, development_http: bool) -> Result<Self, String> {
        if let (Some(deployment), Some((coordinator, _))) = (&deployment, &target) {
            deployment.check(development_http).map_err(|e| format!("signer configuration from {coordinator}: {e}"))?;
        }
        let flag = |name: &str| value(args, name);
        let network = flag("--network").or_else(|| deployment.as_ref().map(|d| d.network.clone()));
        let frostd_url = flag("--frostd-url").or_else(|| deployment.as_ref().map(|d| d.frostd_url.clone()));
        let lightwalletd_url = flag("--lightwalletd-url").or_else(|| deployment.as_ref().and_then(|d| d.lightwalletd_url.clone()));
        let nonce_witnesses = match flag("--nonce-witnesses") {
            Some(path) => {
                let witnesses = nonce_witness::read(Path::new(&path))?;
                nonce_witness::check(&witnesses, development_http)?;
                Some(witnesses.each_ref().map(|w| w.endpoint.clone()))
            }
            None => deployment.as_ref().map(|d| d.nonce_witnesses.each_ref().map(|w| w.endpoint.clone())),
        };
        let mut missing = Vec::new();
        if network.is_none() { missing.push("network"); }
        if frostd_url.is_none() { missing.push("frostd URL"); }
        if lightwalletd_url.is_none() && network.as_deref() != Some("regtest") { missing.push("lightwalletd URL"); }
        if nonce_witnesses.is_none() { missing.push("nonce witnesses"); }
        if !missing.is_empty() {
            let source = match (&deployment, &target) {
                (Some(_), Some((coordinator, _))) => format!("the coordinator {coordinator} did not provide it and no launch flag sets it"),
                _ => "nothing is saved and no launch flag sets it. Open a pairing link from the wallet, or launch with \
                    --network, --frostd-url, --lightwalletd-url and --nonce-witnesses".into(),
            };
            return Err(format!("LokiSigner is missing its {}: {source}", missing.join(", ")));
        }
        let (coordinator, slot) = target.ok_or("this signer is not paired yet: open a pairing link from the wallet")?;
        Ok(Self {
            coordinator, slot,
            network: network.unwrap_or_default(),
            frostd_url: frostd_url.unwrap_or_default(),
            lightwalletd_url,
            nonce_witnesses: nonce_witnesses.unwrap_or_default(),
            save: fetched.is_some() && OVERRIDES.iter().all(|name| flag(name).is_none()),
            fetched,
        })
    }
}

/// A flag's value, read the way `config_from_args` reads it.
fn value(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

/// Remote endpoints need TLS; loopback plaintext only in an explicit development launch. The
/// URL is shown to the member, so whitespace, control characters and non-ASCII are refused
/// (`Url::parse` would silently drop tabs and newlines), and the error never repeats it.
fn endpoint(url: &str, development_http: bool, what: &str) -> Result<(), String> {
    let refused = || format!("the {what} is not a plain HTTPS URL; loopback HTTP requires --development-http");
    if !url.is_ascii() || url.bytes().any(|b| b.is_ascii_whitespace() || b.is_ascii_control()) { return Err(refused()); }
    let parsed = reqwest::Url::parse(url).map_err(|_| refused())?;
    let loopback = matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    // Check the spelling shown to the member: URL parsing can normalize a path to `/`.
    let authority_and_path = url[parsed.scheme().len()..].strip_prefix("://").ok_or_else(&refused)?;
    let root_only = authority_and_path.find(['/', '\\']).is_none_or(|i| &authority_and_path[i..] == "/");
    if !parsed.username().is_empty() || parsed.password().is_some() || parsed.query().is_some() || parsed.fragment().is_some()
        || !root_only
        || !(parsed.scheme() == "https" || (development_http && loopback && parsed.scheme() == "http")) {
        return Err(refused());
    }
    Ok(())
}

fn paired_coordinator(data: &Path, development_http: bool) -> Result<Option<(String, u32)>, String> {
    if !data.join("paired-coordinator.json").try_exists().map_err(|e| e.to_string())? { return Ok(None); }
    let paired = RegistrationConfig::resume(data, development_http)?;
    Ok(Some((paired.coordinator, paired.slot.ok_or("invalid saved slot")?)))
}

fn read_saved(data: &Path) -> Result<Option<Saved>, String> {
    let path = data.join(SAVED);
    if !path.try_exists().map_err(|e| e.to_string())? { return Ok(None); }
    let raw = std::fs::read(&path).map_err(|e| format!("saved signer configuration: {e}"))?;
    serde_json::from_slice(&raw).map(Some).map_err(|e| format!("saved signer configuration: {e}"))
}

fn load(data: &Path, development_http: bool) -> Result<Option<(String, Deployment)>, String> {
    let Some(saved) = read_saved(data)? else { return Ok(None) };
    let deployment = Deployment {
        network: saved.network, frostd_url: saved.frostd_url, lightwalletd_url: saved.lightwalletd_url,
        nonce_witnesses: nonce_witness::read(&data.join(WITNESSES))?,
    };
    deployment.check(development_http).map_err(|e| format!("saved signer configuration: {e}"))?;
    Ok(Some((saved.origin, deployment)))
}

/// Save a configuration for `origin`. It must be the coordinator this profile is paired with,
/// or, before pairing completes, the one whose configuration is already saved.
fn save(data: &Path, origin: &str, deployment: &Deployment) -> Result<(), String> {
    let pinned = match paired_coordinator(data, true)? {
        Some((paired, _)) => Some(paired),
        None => read_saved(data)?.map(|saved| saved.origin),
    };
    if pinned.as_deref().is_some_and(|pinned| pinned != origin) {
        return Err("this profile's configuration belongs to another coordinator".into());
    }
    let dir = crate::state::MemberDir::create(data, "").map_err(|e| e.to_string())?;
    let saved = Saved {
        origin: origin.into(), network: deployment.network.clone(),
        frostd_url: deployment.frostd_url.clone(), lightwalletd_url: deployment.lightwalletd_url.clone(),
    };
    let witnesses = Zeroizing::new(serde_json::to_vec(&deployment.nonce_witnesses).map_err(|e| e.to_string())?);
    write_private(dir.path(), WITNESSES, &witnesses)?;
    write_private(dir.path(), SAVED, &serde_json::to_vec(&saved).map_err(|e| e.to_string())?)
}

/// Owner-only, and atomic: written beside the target, then renamed over it.
fn write_private(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    let tmp = dir.join(format!("{name}.tmp"));
    match std::fs::remove_file(&tmp) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(e.to_string()),
        _ => {}
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)] { use std::os::unix::fs::OpenOptionsExt; options.mode(0o600); }
    let mut file = options.open(&tmp).map_err(|e| format!("{name}: {e}"))?;
    file.write_all(bytes).and_then(|_| file.sync_all()).map_err(|e| format!("{name}: {e}"))?;
    std::fs::rename(&tmp, dir.join(name)).map_err(|e| format!("{name}: {e}"))
}

/// `GET <origin>/api/signer-config`, following no redirect, with a timeout and a size limit.
/// The caller checks what it returns. Errors name only the origin and the HTTP status: the
/// reply's own text never reaches the member.
fn fetch(origin: &str) -> Result<Deployment, String> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?;
    runtime.block_on(async {
        let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(15)).build().map_err(|e| e.to_string())?;
        let failed = |e: reqwest::Error| if e.is_timeout() { format!("{origin} did not answer in time") } else { format!("could not reach {origin}") };
        let mut reply = client.get(format!("{origin}/api/signer-config")).send().await.map_err(failed)?;
        let status = reply.status();
        let mut body = Vec::new();
        while let Some(chunk) = reply.chunk().await.map_err(failed)? {
            body.extend_from_slice(&chunk);
            if body.len() > FETCH_LIMIT { return Err(format!("signer configuration from {origin} is too large")); }
        }
        if !status.is_success() {
            return Err(format!("{origin} did not serve a signer configuration (HTTP {})", status.as_u16()));
        }
        serde_json::from_slice(&body).map_err(|_| format!("invalid signer configuration from {origin}"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};
    use std::sync::{Arc, Mutex};

    fn temp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("loki-native-config-{name}-{}", uuid::Uuid::new_v4()))
    }

    fn args(data: &Path, extra: &[&str]) -> Vec<String> {
        let mut args = vec!["--data".into(), data.to_str().unwrap().into(), "--port".into(), "0".into()];
        args.extend(extra.iter().map(|a| a.to_string()));
        args
    }

    fn link(origin: &str, slot: u32) -> String {
        reqwest::Url::parse_with_params("loki://pair", &[("origin", origin), ("slot", &slot.to_string()), ("challenge", &"ab".repeat(32))])
            .unwrap().to_string()
    }

    fn served() -> Value {
        let witness = |n: u8, host: &str| json!({ "endpoint": format!("https://{host}"), "key": vec![n; 32],
            "run": vec![n + 1; 32], "mailbox": vec![n + 2; 32], "read": vec![n + 3; 32] });
        json!({ "network": "testnet", "frostdUrl": "https://frostd.example", "lightwalletdUrl": "https://lwd.example:443",
            "nonceWitnesses": [witness(1, "w1.example"), witness(5, "w2.example")] })
    }

    fn deployment(value: Value) -> Deployment { serde_json::from_value(value).unwrap() }

    fn pair(data: &Path, origin: &str, slot: u32) {
        std::fs::create_dir_all(data).unwrap();
        std::fs::write(data.join("paired-coordinator.json"), json!({ "origin": origin, "slot": slot }).to_string()).unwrap();
    }

    /// Confirm a pairing link as the native dialog does: preview with `served`, apply, then save
    /// as `registration::start` does once the profile has unlocked.
    fn confirm(data: &Path, origin: &str, served: Value) -> Config {
        let (args, link) = (args(data, &[]), link(origin, 7));
        let shown = NativeConfig::resolve(&args, Some(&link), |_| Ok(deployment(served))).unwrap();
        let mut config = super::super::config_from_args(&args).unwrap();
        let fetched = shown.apply(&mut config, &args, Some(&link)).unwrap().expect("a pairing link fetches");
        fetched.save_unlocked(data).unwrap();
        config
    }

    fn files(data: &Path) -> (Vec<u8>, Vec<u8>) {
        (std::fs::read(data.join(SAVED)).unwrap(), std::fs::read(data.join(WITNESSES)).unwrap())
    }

    type Reply = Arc<Mutex<Option<(u16, String)>>>;

    fn ok(body: Value) -> Option<(u16, String)> { Some((200, body.to_string())) }

    /// A local coordinator serving `/api/signer-config`: the status and body in `reply`, or, when
    /// it is `None`, a redirect to a path that serves a valid configuration.
    fn mock_coordinator() -> (String, Reply) {
        use axum::{http::StatusCode, response::{IntoResponse, Redirect}, routing::get, Json, Router};
        let reply: Reply = Arc::new(Mutex::new(None));
        let state = reply.clone();
        let app = Router::new()
            .route("/api/signer-config", get(move || {
                let reply = state.lock().unwrap().clone();
                async move { match reply {
                    Some((status, body)) => (StatusCode::from_u16(status).unwrap(), body).into_response(),
                    None => Redirect::temporary("/elsewhere").into_response(),
                } }
            }))
            .route("/elsewhere", get(|| async { Json(served()) }));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let origin = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        listener.set_nonblocking(true).unwrap();
        std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async move {
                axum::serve(tokio::net::TcpListener::from_std(listener).unwrap(), app).await.unwrap();
            })
        });
        (origin, reply)
    }

    #[test]
    fn the_coordinators_configuration_is_fetched_strictly() {
        let (origin, reply) = mock_coordinator();
        let data = temp("fetch");
        let (args, link) = (args(&data, &["--development-http"]), link(&origin, 7));
        let preview = || NativeConfig::preview(&args, Some(&link));

        *reply.lock().unwrap() = ok(served());
        let shown = preview().unwrap();
        assert_eq!((shown.coordinator.as_str(), shown.slot), (origin.as_str(), 7));
        assert_eq!((shown.network.as_str(), shown.frostd_url.as_str()), ("testnet", "https://frostd.example"));
        assert_eq!(shown.lightwalletd_url.as_deref(), Some("https://lwd.example:443"));
        assert_eq!(shown.nonce_witnesses, ["https://w1.example".to_string(), "https://w2.example".to_string()]);
        assert!(shown.fetched == Some(deployment(served())));
        assert!(!data.exists(), "nothing is saved before the member confirms");

        let mut bad = Vec::new();
        let mut unknown = served();
        unknown["walletOrigin"] = json!("https://wallet.example");
        bad.push((unknown, "invalid signer configuration from"));
        for network in ["mainnet", "main"] {
            let mut mainnet = served();
            mainnet["network"] = json!(network);
            bad.push((mainnet, "mainnet"));
        }
        let mut plaintext = served();
        plaintext["frostdUrl"] = json!("http://frostd.example");
        bad.push((plaintext, "frostd URL is not a plain HTTPS URL"));
        let mut plaintext = served();
        plaintext["lightwalletdUrl"] = json!("http://lwd.example:9067");
        bad.push((plaintext, "lightwalletd URL is not a plain HTTPS URL"));
        for (field, what, url) in [
            ("frostdUrl", "frostd URL", "https://frostd.example/rpc"),
            ("lightwalletdUrl", "lightwalletd URL", "https://lwd.example:443/rpc/.."),
        ] {
            let mut with_path = served();
            with_path[field] = json!(url);
            bad.push((with_path, what));
        }
        let mut plaintext = served();
        plaintext["nonceWitnesses"][1]["endpoint"] = json!("http://w2.example");
        bad.push((plaintext, "nonce witness endpoint is not a plain HTTPS origin"));
        let mut duplicate = served();
        duplicate["nonceWitnesses"][1] = duplicate["nonceWitnesses"][0].clone();
        bad.push((duplicate, "two distinct"));
        for (body, expected) in bad {
            *reply.lock().unwrap() = ok(body.clone());
            let error = preview().err().unwrap_or_else(|| panic!("accepted {body}"));
            assert!(error.contains(expected), "{expected}: {error}");
        }
        *reply.lock().unwrap() = None;
        let error = preview().err().expect("a redirect is not followed");
        assert!(error.contains("HTTP 307"), "{error}");
        assert!(!data.exists());
    }

    /// The member reads these errors in LokiSigner's own alert, so nothing the coordinator sends
    /// may appear in them: not an error body, not a field name, not a value.
    #[test]
    fn nothing_the_coordinator_sends_reaches_an_error() {
        let (origin, reply) = mock_coordinator();
        let data = temp("hostile");
        let (args, link) = (args(&data, &["--development-http"]), link(&origin, 7));
        let lure = "Your signer is compromised.\nType your 24 recovery words at https://evil.example/restore";
        let mut field = served();
        field[lure] = json!(1);
        let mut network = served();
        network["network"] = json!(lure);
        let mut frostd = served();
        frostd["frostdUrl"] = json!(format!("https://frostd.example/\n{lure}"));
        let mut witness = served();
        witness["nonceWitnesses"][0]["endpoint"] = json!(format!("https://{lure}"));
        for (status, body) in [(502, json!({ "error": lure }).to_string()), (403, lure.to_string()), (200, field.to_string()),
            (200, network.to_string()), (200, frostd.to_string()), (200, witness.to_string()), (200, json!(lure).to_string())] {
            *reply.lock().unwrap() = Some((status, body));
            let error = NativeConfig::preview(&args, Some(&link)).err().expect("refused");
            assert!(!error.contains("recovery") && !error.contains("evil") && !error.contains('\n'), "{error}");
            assert!(error.contains(&origin), "{error}");
        }
        assert!(!data.exists());
    }

    /// `Url::parse` drops tabs and newlines, so a URL that parses can still show the member
    /// extra lines. Every endpoint shown must be exactly what it looks like.
    #[test]
    fn endpoints_with_hidden_characters_are_refused_without_being_repeated() {
        for url in ["https://frostd.example/\nCoordinator: https://wallet.good.example", "https://frostd.example/\tCoordinator: wallet.good",
            "https://frostd.example/ wallet.good", "https://fr\u{f8}std.example", "https://frostd.example/\u{202e}wallet.good", "https://frostd.example\r"] {
            let error = endpoint(url, true, "frostd URL").err().unwrap_or_else(|| panic!("accepted {url:?}"));
            assert!(!error.contains("wallet.good") && !error.contains("frostd.example"), "{error}");
        }
        assert!(endpoint("https://frostd.example", false, "frostd URL").is_ok());
        assert!(endpoint("https://lwd.example:443/", false, "lightwalletd URL").is_ok());
    }

    #[test]
    fn what_runs_is_what_was_shown_and_a_flag_override_saves_nothing() {
        let data = temp("shown");
        let link = link("https://coordinator.example", 7);
        let fetch = |_: &str| -> Result<Deployment, String> { Ok(deployment(served())) };
        // A configuration changed after it was shown is refused.
        let plain = args(&data, &[]);
        for change in [|c: &mut NativeConfig| c.frostd_url = "https://elsewhere.example".into(),
            |c: &mut NativeConfig| c.network = "regtest".into(), |c: &mut NativeConfig| c.save = !c.save] {
            let mut shown = NativeConfig::resolve(&plain, Some(&link), fetch).unwrap();
            change(&mut shown);
            let mut config = super::super::config_from_args(&plain).unwrap();
            let error = shown.apply(&mut config, &plain, Some(&link)).err().expect("a changed configuration is refused");
            assert!(error.contains("changed after it was shown"), "{error}");
        }
        // A flag overrides its field for this launch only: the member saw the flag's value, so
        // the coordinator's configuration is not saved.
        let flagged = args(&data, &["--frostd-url", "https://mine.example"]);
        let shown = NativeConfig::resolve(&flagged, Some(&link), fetch).unwrap();
        assert_eq!(shown.frostd_url, "https://mine.example");
        assert!(!shown.save);
        let mut config = super::super::config_from_args(&flagged).unwrap();
        let fetched = shown.apply(&mut config, &flagged, Some(&link)).unwrap().unwrap();
        assert_eq!((config.frostd_url.as_str(), config.network.as_str()), ("https://mine.example", "testnet"));
        fetched.save_unlocked(&data).unwrap();
        assert!(!data.join(SAVED).exists() && !data.join(WITNESSES).exists());
        let _ = std::fs::remove_dir_all(data);
    }

    /// A wrong passphrase, or a first pairing that never unlocks, leaves nothing saved: the
    /// configuration is written where the paired coordinator is, after the profile unlocks.
    #[tokio::test]
    async fn the_configuration_is_saved_only_once_the_profile_unlocks() {
        let data = temp("unlock");
        let link = link("https://127.0.0.1:1", 7);
        let args = args(&data, &[]);
        crate::profile::create(&data, "right passphrase", "Member").unwrap();
        let state = || {
            let shown = NativeConfig::resolve(&args, Some(&link), |_| Ok(deployment(served()))).unwrap();
            let mut config = super::super::config_from_args(&args).unwrap();
            let fetched = shown.apply(&mut config, &args, Some(&link)).unwrap();
            config.registration = Some(RegistrationConfig::pairing(&link, false).unwrap());
            std::sync::Arc::new(super::super::state::AppState { fetched_config: fetched, ..super::super::state::AppState::new(config) })
        };
        let notice: super::super::LocalNotice = Arc::new(|_, _| {});
        let wrong = state();
        // This launch signs with the fetched witnesses from memory, before anything is saved.
        let opened = wrong.clone();
        assert!(tokio::task::spawn_blocking(move || super::super::nonce_witness::RelayWitness::for_member(&opened, "test").is_ok()).await.unwrap());
        assert!(super::super::registration::start(&wrong, Some(Zeroizing::new("wrong passphrase".into())), Some(&notice)).await.is_err());
        for file in [SAVED, WITNESSES, "paired-coordinator.json"] { assert!(!data.join(file).exists(), "{file}"); }
        let right = state();
        super::super::registration::start(&right, Some(Zeroizing::new("right passphrase".into())), Some(&notice)).await.unwrap();
        let saved = NativeConfig::resolve(&args, None, |_| panic!("the saved configuration is used")).unwrap();
        assert_eq!((saved.coordinator.as_str(), saved.frostd_url.as_str()), ("https://127.0.0.1:1", "https://frostd.example"));
        std::fs::remove_dir_all(data).unwrap();
    }

    #[test]
    fn a_saved_configuration_is_private_reused_and_overridden_field_by_field() {
        let data = temp("saved");
        pair(&data, "https://coordinator.example", 7);
        let config = confirm(&data, "https://coordinator.example", served());
        assert_eq!((config.network.as_str(), config.frostd_url.as_str()), ("testnet", "https://frostd.example"));
        assert!(config.nonce_witnesses.is_none(), "the pairing launch uses the fetched witnesses from memory");
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            for file in [SAVED, WITNESSES] {
                assert_eq!(std::fs::metadata(data.join(file)).unwrap().permissions().mode() & 0o777, 0o600, "{file}");
            }
        }

        // A plain unlock takes the saved values without fetching, and the saved witnesses are a
        // `--nonce-witnesses` file that hosted signing opens.
        let no_fetch = |_: &str| -> Result<Deployment, String> { panic!("an unlock with a saved configuration fetched") };
        let plain = args(&data, &[]);
        let shown = NativeConfig::resolve(&plain, None, no_fetch).unwrap();
        let mut config = super::super::config_from_args(&plain).unwrap();
        assert!(shown.apply(&mut config, &plain, None).unwrap().is_none());
        assert_eq!(config.nonce_witnesses.as_deref(), Some(data.join(WITNESSES).as_path()));
        let witness = super::super::nonce_witness::RelayWitness::open(config.nonce_witnesses.as_deref(), false, "test").unwrap();
        use crate::signing_session::NonceWitness;
        assert_eq!(witness.pins(), [([1; 32], [2; 32], [3; 32]), ([5; 32], [6; 32], [7; 32])]);

        // A flag overrides its field only.
        let unlock = args(&data, &["--frostd-url", "https://mine.example"]);
        let shown = NativeConfig::resolve(&unlock, None, no_fetch).unwrap();
        assert_eq!(shown.frostd_url, "https://mine.example");
        assert_eq!((shown.network.as_str(), shown.lightwalletd_url.as_deref()), ("testnet", Some("https://lwd.example:443")));
        let mut config = super::super::config_from_args(&unlock).unwrap();
        shown.apply(&mut config, &unlock, None).unwrap();
        assert_eq!((config.network.as_str(), config.frostd_url.as_str()), ("testnet", "https://mine.example"));
        assert_eq!(config.lightwalletd.as_deref(), Some("https://lwd.example:443"));
        let regtest = args(&data, &["--network", "regtest"]);
        assert_eq!(NativeConfig::resolve(&regtest, None, no_fetch).unwrap().network, "regtest");

        // A new link for the same coordinator and slot refreshes it once the member confirms.
        let mut refreshed = served();
        refreshed["frostdUrl"] = json!("https://frostd2.example");
        confirm(&data, "https://coordinator.example", refreshed);
        assert_eq!(NativeConfig::resolve(&plain, None, no_fetch).unwrap().frostd_url, "https://frostd2.example");
        std::fs::remove_dir_all(data).unwrap();
    }

    #[test]
    fn another_coordinators_configuration_never_replaces_the_saved_one() {
        let data = temp("pinned");
        pair(&data, "https://coordinator.example", 7);
        confirm(&data, "https://coordinator.example", served());
        let before = files(&data);
        let mut other = served();
        other["frostdUrl"] = json!("https://attacker.example");
        let fetch = |_: &str| -> Result<Deployment, String> { Ok(deployment(other.clone())) };
        for link in [link("https://other.example", 7), link("https://coordinator.example", 8)] {
            let error = NativeConfig::resolve(&args(&data, &[]), Some(&link), fetch).err().unwrap();
            assert!(error.contains("already paired"), "{error}");
        }
        // A configuration claiming to be from another coordinator is refused when applied.
        let mut forged = NativeConfig::resolve(&args(&data, &[]), None, fetch).unwrap();
        forged.coordinator = "https://other.example".into();
        forged.fetched = Some(deployment(other.clone()));
        let mut config = super::super::config_from_args(&args(&data, &[])).unwrap();
        assert!(forged.apply(&mut config, &args(&data, &[]), None).is_err());
        assert!(save(&data, "https://other.example", &deployment(other.clone())).is_err());
        // Before pairing completes, the saved configuration's origin pins it.
        std::fs::remove_file(data.join("paired-coordinator.json")).unwrap();
        let error = NativeConfig::resolve(&args(&data, &[]), Some(&link("https://other.example", 7)), fetch).err().unwrap();
        assert!(error.contains("belongs to https://coordinator.example"), "{error}");
        assert!(save(&data, "https://other.example", &deployment(other.clone())).is_err());
        assert!(files(&data) == before, "the saved configuration is byte-identical");
        std::fs::remove_dir_all(data).unwrap();
    }

    #[test]
    fn a_launch_without_a_configuration_names_what_is_missing() {
        let data = temp("missing");
        let error = NativeConfig::preview(&args(&data, &[]), None).err().unwrap();
        for field in ["network", "frostd URL", "lightwalletd URL", "nonce witnesses"] {
            assert!(error.contains(field), "{field}: {error}");
        }
        // A testnet coordinator without a lightwalletd: only that is missing.
        let mut served = served();
        served["lightwalletdUrl"] = Value::Null;
        let error = NativeConfig::resolve(&args(&data, &[]), Some(&link("https://coordinator.example", 7)), |_| Ok(deployment(served.clone())))
            .err().unwrap();
        assert!(error.contains("missing its lightwalletd URL: the coordinator https://coordinator.example"), "{error}");
        // Every field from flags, but no pairing: the signer says it is not paired.
        let witnesses = data.join("w.json");
        std::fs::create_dir_all(&data).unwrap();
        std::fs::write(&witnesses, serde_json::to_vec(&served["nonceWitnesses"]).unwrap()).unwrap();
        let flags = args(&data, &["--network", "regtest", "--frostd-url", "https://f.example", "--nonce-witnesses", witnesses.to_str().unwrap()]);
        let error = NativeConfig::preview(&flags, None).err().unwrap();
        assert!(error.contains("not paired"), "{error}");
        std::fs::remove_dir_all(data).unwrap();
    }
}
