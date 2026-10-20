//! The per-member HTTP coordinator. Account + hosted-vault ceremony + multi-party payment
//! for the web UI, driving the audited library in-process (see `loki_poc::host`).
//!
//!   loki_member_app --data <dir> --port <n> [--network testnet] [--lightwalletd-url <url>]
//!       [--frostd-url <url>] [--peer <slot=baseurl>]...
//!       [--transport hosted --operator-bundle <cbor> --operator-key <hex>
//!        --enrollment-issuer <path> --development-http]

use std::{collections::BTreeMap, path::PathBuf};

use base64::Engine;
use loki_poc::host::{self, Config};
use rand_core::{OsRng, RngCore};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let value = |name: &str| -> Option<String> {
        args.iter()
            .position(|a| a == name)
            .and_then(|i| args.get(i + 1))
            .cloned()
    };
    let flag = |name: &str| args.iter().any(|a| a == name);

    let Some(data) = value("--data").map(PathBuf::from) else {
        eprintln!("--data <dir> is required");
        std::process::exit(2);
    };
    let Some(port) = value("--port").and_then(|p| p.parse::<u16>().ok()) else {
        eprintln!("--port <n> is required");
        std::process::exit(2);
    };

    let mut token = [0u8; 32];
    OsRng.fill_bytes(&mut token);
    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token);
    let mut peers = BTreeMap::new();
    for (index, arg) in args.iter().enumerate() {
        if arg == "--peer" {
            let Some((slot, url)) = args.get(index + 1).and_then(|s| s.split_once('=')) else {
                eprintln!("--peer requires <slot=baseurl>");
                std::process::exit(2);
            };
            let Ok(slot) = slot.parse::<u16>() else {
                eprintln!("invalid peer slot: {slot}");
                std::process::exit(2);
            };
            if slot == 0 || !(url.starts_with("http://") || url.starts_with("https://")) {
                eprintln!("invalid peer: {slot}={url}");
                std::process::exit(2);
            }
            peers.insert(slot, url.trim_end_matches('/').to_owned());
        }
    }

    let config = Config {
        data,
        port,
        network: value("--network").unwrap_or_else(|| "regtest".into()),
        lightwalletd: value("--lightwalletd-url"),
        transport: value("--transport").unwrap_or_else(|| "local".into()),
        operator_bundle: value("--operator-bundle").map(PathBuf::from),
        operator_key: value("--operator-key"),
        enrollment_issuer: value("--enrollment-issuer").map(PathBuf::from),
        development_http: flag("--development-http"),
        token,
        frostd_url: value("--frostd-url").unwrap_or_else(|| "http://127.0.0.1:2744".into()),
        peers,
    };

    if let Err(error) = host::run(config) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
