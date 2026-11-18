//! The configuration LokiSigner, the native member app, runs with on a normal launch: network,
//! frostd, lightwalletd and the two nonce witnesses. The coordinator whose origin the member
//! confirmed chooses them. It serves the browser signer's own values at `/api/signer-config`.
//! LokiSigner shows them to the member before it pairs or unlocks, then saves them owner-only
//! in the data directory, pinned to that coordinator. An explicit launch flag overrides the
//! saved value for its field. Only the native path (`loki_member_app_pair`) uses this; the
//! headless `loki_member_app` and `LokiSigner serve` keep their flags and defaults.

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
    /// Fetched from `coordinator` for this launch; saved once the member continues.
    pub fetched: Option<Deployment>,
}

impl NativeConfig {
    /// The configuration a native launch with these arguments and pairing link would use.
    /// Fetches from the coordinator for a pairing link, or for an unlock with nothing saved.
    pub fn preview(args: &[String], pairing_url: Option<&str>) -> Result<Self, String> {
        Self::resolve(args, pairing_url, fetch)
    }

    /// Run with the configuration the member saw: resolve it again from the same launch, using
    /// the shown fetch instead of a second one, save what was fetched, and set it on `config`.
    pub fn apply(self, config: &mut Config, args: &[String], pairing_url: Option<&str>) -> Result<(), String> {
        let shown = self.fetched.clone();
        let resolved = Self::resolve(args, pairing_url, |_| shown.ok_or_else(|| "the confirmed configuration is missing".to_string()))?;
        if resolved != self {
            return Err("the configuration changed after it was shown; open LokiSigner again".into());
        }
        if let Some(deployment) = &self.fetched { save(&config.data, &self.coordinator, deployment)?; }
        config.network = self.network;
        config.frostd_url = self.frostd_url;
        config.lightwalletd = self.lightwalletd_url;
        config.nonce_witnesses = Some(value(args, "--nonce-witnesses").map(PathBuf::from).unwrap_or_else(|| config.data.join(WITNESSES)));
        Ok(())
    }

    fn resolve(args: &[String], pairing_url: Option<&str>, fetch: impl FnOnce(&str) -> Result<Deployment, String>) -> Result<Self, String> {
        let config = super::config_from_args(args)?;
        let (data, development_http) = (&config.data, config.development_http);
        let paired = paired_coordinator(data, development_http)?;
        let target = match pairing_url {
            Some(link) => {
                let link = RegistrationConfig::pairing(link, development_http)?;
                let target = (link.coordinator, link.slot.ok_or("invalid pairing slot")?);
                if let Some((origin, slot)) = paired.filter(|paired| *paired != target) {
                    return Err(format!("this profile is already paired with {origin} slot {slot}; a link for another coordinator or slot is refused"));
                }
                Some(target)
            }
            None => paired,
        };
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
            fetched,
        })
    }
}

/// A flag's value, read the way `config_from_args` reads it.
fn value(args: &[String], name: &str) -> Option<String> {
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

/// Remote endpoints need TLS; loopback plaintext only in an explicit development launch.
fn endpoint(url: &str, development_http: bool, what: &str) -> Result<(), String> {
    let parsed = reqwest::Url::parse(url).map_err(|_| format!("invalid {what}: {url}"))?;
    let loopback = matches!(parsed.host_str(), Some("localhost" | "127.0.0.1" | "[::1]"));
    if !parsed.username().is_empty() || parsed.password().is_some() || parsed.query().is_some() || parsed.fragment().is_some()
        || !(parsed.scheme() == "https" || (development_http && loopback && parsed.scheme() == "http")) {
        return Err(format!("{what} {url} must use HTTPS; loopback HTTP requires --development-http"));
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
/// The caller checks what it returns.
fn fetch(origin: &str) -> Result<Deployment, String> {
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|e| e.to_string())?;
    runtime.block_on(async {
        let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(15)).build().map_err(|e| e.to_string())?;
        let failed = |e: reqwest::Error| format!("signer configuration from {origin}: {e}");
        let mut reply = client.get(format!("{origin}/api/signer-config")).send().await.map_err(failed)?;
        let status = reply.status();
        let mut body = Vec::new();
        while let Some(chunk) = reply.chunk().await.map_err(failed)? {
            body.extend_from_slice(&chunk);
            if body.len() > FETCH_LIMIT { return Err(format!("signer configuration from {origin} is too large")); }
        }
        if !status.is_success() {
            let reason = serde_json::from_slice::<serde_json::Value>(&body).ok()
                .and_then(|v| v["error"].as_str().map(|e| format!(": {e}"))).unwrap_or_default();
            return Err(format!("{origin} did not serve a signer configuration ({status}){reason}"));
        }
        serde_json::from_slice(&body).map_err(|e| format!("invalid signer configuration from {origin}: {e}"))
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

    /// Confirm a pairing link as the native dialog does: preview with `served`, then apply.
    fn confirm(data: &Path, origin: &str, served: Value) -> Config {
        let (args, link) = (args(data, &[]), link(origin, 7));
        let shown = NativeConfig::resolve(&args, Some(&link), |_| Ok(deployment(served))).unwrap();
        let mut config = super::super::config_from_args(&args).unwrap();
        shown.apply(&mut config, &args, Some(&link)).unwrap();
        config
    }

    fn files(data: &Path) -> (Vec<u8>, Vec<u8>) {
        (std::fs::read(data.join(SAVED)).unwrap(), std::fs::read(data.join(WITNESSES)).unwrap())
    }

    /// A local coordinator serving `/api/signer-config`: the body in `reply`, or, when it is
    /// `None`, a redirect to a path that serves a valid configuration.
    fn mock_coordinator() -> (String, Arc<Mutex<Option<Value>>>) {
        use axum::{response::{IntoResponse, Redirect}, routing::get, Json, Router};
        let reply = Arc::new(Mutex::new(None::<Value>));
        let state = reply.clone();
        let app = Router::new()
            .route("/api/signer-config", get(move || {
                let body = state.lock().unwrap().clone();
                async move { match body { Some(body) => Json(body).into_response(), None => Redirect::temporary("/elsewhere").into_response() } }
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

        *reply.lock().unwrap() = Some(served());
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
        bad.push((unknown, "unknown field"));
        for network in ["mainnet", "main"] {
            let mut mainnet = served();
            mainnet["network"] = json!(network);
            bad.push((mainnet, "mainnet"));
        }
        let mut plaintext = served();
        plaintext["frostdUrl"] = json!("http://frostd.example");
        bad.push((plaintext, "must use HTTPS"));
        let mut plaintext = served();
        plaintext["lightwalletdUrl"] = json!("http://lwd.example:9067");
        bad.push((plaintext, "must use HTTPS"));
        let mut plaintext = served();
        plaintext["nonceWitnesses"][1]["endpoint"] = json!("http://w2.example");
        bad.push((plaintext, "signer configuration from"));
        let mut duplicate = served();
        duplicate["nonceWitnesses"][1] = duplicate["nonceWitnesses"][0].clone();
        bad.push((duplicate, "two distinct"));
        for (body, expected) in bad {
            *reply.lock().unwrap() = Some(body.clone());
            let error = preview().err().unwrap_or_else(|| panic!("accepted {body}"));
            assert!(error.contains(expected), "{expected}: {error}");
        }
        *reply.lock().unwrap() = None;
        let error = preview().err().expect("a redirect is not followed");
        assert!(error.contains("307"), "{error}");
        assert!(!data.exists());
    }

    #[test]
    fn a_saved_configuration_is_private_reused_and_overridden_field_by_field() {
        let data = temp("saved");
        pair(&data, "https://coordinator.example", 7);
        let config = confirm(&data, "https://coordinator.example", served());
        assert_eq!((config.network.as_str(), config.frostd_url.as_str()), ("testnet", "https://frostd.example"));
        assert_eq!(config.nonce_witnesses.as_deref(), Some(data.join(WITNESSES).as_path()));
        #[cfg(unix)] {
            use std::os::unix::fs::PermissionsExt;
            for file in [SAVED, WITNESSES] {
                assert_eq!(std::fs::metadata(data.join(file)).unwrap().permissions().mode() & 0o777, 0o600, "{file}");
            }
        }
        // The saved witnesses are a `--nonce-witnesses` file hosted signing opens.
        let witness = super::super::nonce_witness::RelayWitness::open(config.nonce_witnesses.as_deref(), false, "test").unwrap();
        use crate::signing_session::NonceWitness;
        assert_eq!(witness.pins(), [([1; 32], [2; 32], [3; 32]), ([5; 32], [6; 32], [7; 32])]);

        // A plain unlock takes the saved values without fetching; a flag overrides its field only.
        let no_fetch = |_: &str| -> Result<Deployment, String> { panic!("an unlock with a saved configuration fetched") };
        let unlock = args(&data, &["--frostd-url", "https://mine.example"]);
        let shown = NativeConfig::resolve(&unlock, None, no_fetch).unwrap();
        assert_eq!(shown.frostd_url, "https://mine.example");
        assert_eq!((shown.network.as_str(), shown.lightwalletd_url.as_deref()), ("testnet", Some("https://lwd.example:443")));
        assert!(shown.fetched.is_none());
        let mut config = super::super::config_from_args(&unlock).unwrap();
        shown.apply(&mut config, &unlock, None).unwrap();
        assert_eq!((config.network.as_str(), config.frostd_url.as_str()), ("testnet", "https://mine.example"));
        assert_eq!(config.lightwalletd.as_deref(), Some("https://lwd.example:443"));
        assert_eq!(config.nonce_witnesses.as_deref(), Some(data.join(WITNESSES).as_path()));
        let regtest = args(&data, &["--network", "regtest"]);
        assert_eq!(NativeConfig::resolve(&regtest, None, no_fetch).unwrap().network, "regtest");

        // A new link for the same coordinator and slot refreshes it once the member confirms.
        let mut refreshed = served();
        refreshed["frostdUrl"] = json!("https://frostd2.example");
        confirm(&data, "https://coordinator.example", refreshed);
        assert_eq!(NativeConfig::resolve(&args(&data, &[]), None, no_fetch).unwrap().frostd_url, "https://frostd2.example");
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
