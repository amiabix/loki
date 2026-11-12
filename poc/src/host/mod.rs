//! The member-owned HTTP device (axum). One process per member, started locally by
//! that member. Profile unlock, custody, ceremony and payment signing stay here; the web
//! coordinator only publishes public artifacts. This process drives the audited library. All library calls run on `spawn_blocking` because the hosted relay
//! stack blocks on its own runtime (see `setup_relay::shared_runtime`).

mod ceremony;
mod device;
mod payment;
mod nonce_witness;
mod recovery;
mod registration;
#[cfg(test)]
mod repair;
mod routes;
mod state;

pub use state::Config;
pub use registration::RegistrationConfig;
pub use nonce_witness::WitnessConfig;

/// Device-local UI notifications; never forwarded to the coordinator or a log.
pub type LocalNotice = std::sync::Arc<dyn Fn(&str, &str) + Send + Sync>;

/// Parse member-app CLI args into a `Config`. Shared by the `loki_member_app` bin and the native
/// signer app's FFI `serve` entry point, so both build the member identically.
pub fn config_from_args(args: &[String]) -> Result<Config, String> {
    use base64::Engine;
    use rand_core::{OsRng, RngCore};
    use std::{collections::BTreeMap, path::PathBuf};
    let value = |name: &str| -> Option<String> {
        args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
    };
    let flag = |name: &str| args.iter().any(|a| a == name);
    let data = value("--data").map(PathBuf::from).ok_or("--data <dir> is required")?;
    let port = value("--port").and_then(|p| p.parse::<u16>().ok()).ok_or("--port <n> is required")?;
    let bind = if flag("--bind") {
        value("--bind").and_then(|a| a.parse::<std::net::IpAddr>().ok()).ok_or("--bind requires an IP address")?
    } else {
        std::net::Ipv4Addr::LOCALHOST.into()
    };
    if flag("--secure-element") && value("--secure-element").is_none() {
        return Err("--secure-element requires <software|apple>".into());
    }
    let mut token = [0u8; 32];
    OsRng.fill_bytes(&mut token);
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token);
    let mut peers = BTreeMap::new();
    for (index, arg) in args.iter().enumerate() {
        if arg == "--peer" {
            let (slot, url) = args.get(index + 1).and_then(|s| s.split_once('=')).ok_or("--peer requires <slot=baseurl>")?;
            let slot = slot.parse::<u16>().map_err(|_| format!("invalid peer slot: {slot}"))?;
            if slot == 0 || !(url.starts_with("http://") || url.starts_with("https://")) {
                return Err(format!("invalid peer: {slot}={url}"));
            }
            peers.insert(slot, url.trim_end_matches('/').to_owned());
        }
    }
    Ok(Config {
        data, port, bind,
        registration: RegistrationConfig::from_args(args, flag("--development-http"))?,
        advertise_url: value("--advertise-url"),
        network: value("--network").unwrap_or_else(|| "regtest".into()),
        lightwalletd: value("--lightwalletd-url"),
        transport: value("--transport").unwrap_or_else(|| "local".into()),
        secure_element: value("--secure-element").unwrap_or_else(|| "software".into()),
        operator_bundle: value("--operator-bundle").map(PathBuf::from),
        nonce_witnesses: value("--nonce-witnesses").map(PathBuf::from),
        operator_key: value("--operator-key"),
        enrollment_issuer: value("--enrollment-issuer").map(PathBuf::from),
        development_http: flag("--development-http"),
        token,
        frostd_url: value("--frostd-url").unwrap_or_else(|| "http://127.0.0.1:2744".into()),
        peers,
        loopback_peers: flag("--allow-loopback-peers"),
    })
}

/// Build the axum app and serve on the configured bind IP and port. Blocks.
pub fn run(config: Config) -> Result<(), String> {
    run_local(config, None, None)
}

pub fn run_local(mut config: Config, pass: Option<zeroize::Zeroizing<String>>, notice: Option<LocalNotice>) -> Result<(), String> {
    // rustls has no default provider; install one before any relay/lightwalletd TLS.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))?;

    runtime.block_on(async move {
        let addr = std::net::SocketAddr::new(config.bind, config.port);
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| format!("bind {addr}: {e}"))?;
        let addr = listener.local_addr().map_err(|e| e.to_string())?;
        config.port = addr.port();
        let state: state::Shared = std::sync::Arc::new(state::AppState::new(config));
        registration::start(&state, pass, notice.as_ref()).await?;
        // Member-local output only. Paste into a local browser tab; never send to the coordinator.
        if let Some(notice) = notice {
            notice("ready", &format!("http://{addr}/#{}", state.config.token));
        } else if let Some(launch) = &state.config.registration {
            println!("{} ({}) — Local pairing: http://{addr}/#{}", launch.name, state.config.data.display(), state.config.token);
        } else {
            println!("Signer: http://{addr}/#{}", state.config.token);
        }
        ceremony::spawn_auto_resume(state.clone());
        payment::spawn_auto_resume(state.clone());
        axum::serve(listener, routes::router(state))
            .await
            .map_err(|e| format!("serve: {e}"))
    })
}
