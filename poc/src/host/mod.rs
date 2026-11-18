//! The member-owned HTTP device (axum). One process per member, started locally by
//! that member. Profile unlock, custody, ceremony and payment signing stay here; the web
//! coordinator only publishes public artifacts. This process drives the audited library. All library calls run on `spawn_blocking` because the hosted relay
//! stack blocks on its own runtime (see `setup_relay::shared_runtime`).

mod ceremony;
mod custody;
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

/// The member's own decision on one payment, asked on this device (the native app's dialog).
/// Receives the signer-derived summary as JSON ([`approval_summary`]); `true` approves.
/// Without one, every payment is refused: HTTP or relay requests never approve on their own.
pub type LocalApproval = std::sync::Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// The signer's [`ApprovalPolicy`](crate::signer::local::ApprovalPolicy): route each request
/// to the member's local decision, and refuse when no approval channel is attached.
pub fn approval_policy(
    approval: Option<LocalApproval>,
    network: crate::signer::Network,
    slot: u16,
) -> crate::signer::local::ApprovalPolicy {
    Box::new(move |request| {
        let approved = approval.as_ref().is_some_and(|approve| approve(&approval_summary(request, network, slot)));
        let attempt = hex::encode(request.candidate.attempt_id);
        eprintln!("payment {attempt}: member {slot} approval {}", if approved { "approved" } else { "refused" });
        approved
    })
}

/// What the member reviews: the payee, amounts and network the signer derived itself from the
/// PCZT bytes, and the candidate and sighash its consent binds to.
pub fn approval_summary(request: &crate::signer::local::ApprovalRequest<'_>, network: crate::signer::Network, slot: u16) -> String {
    use zcash_protocol::consensus::NetworkType;
    let (label, kind) = match network {
        crate::signer::Network::Regtest => ("regtest", NetworkType::Regtest),
        crate::signer::Network::Testnet => ("testnet", NetworkType::Test),
    };
    let view = request.view;
    serde_json::json!({
        "recipient": crate::vault::unified_receiver(view.to, kind),
        "amount_zat": view.amount_zat,
        "fee_zat": view.fee_zat,
        "fee_verified": view.fee_verified,
        "change_zat": view.change_zat,
        "memo": String::from_utf8_lossy(&view.memo).trim_end_matches('\0'),
        "network": label,
        "branch_id": format!("{:08x}", view.network_branch_id),
        "vault": hex::encode(request.candidate.vault_id),
        "member": slot,
        "payment": hex::encode(request.candidate.payment_id),
        "attempt": hex::encode(request.candidate.attempt_id),
        "sighash": hex::encode(request.sighash),
    })
    .to_string()
}

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
    run_local(config, None, None, None)
}

pub fn run_local(
    mut config: Config,
    pass: Option<zeroize::Zeroizing<String>>,
    notice: Option<LocalNotice>,
    approval: Option<LocalApproval>,
) -> Result<(), String> {
    // rustls has no default provider; install one before any relay/lightwalletd TLS.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    // Peer origins must use TLS off loopback (preserved from main's hardening).
    for url in config.peers.values() {
        crate::transport::require_tls_off_loopback(url)?;
    }

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
        let state: state::Shared = std::sync::Arc::new(state::AppState { approval, ..state::AppState::new(config) });
        registration::start(&state, pass, notice.as_ref()).await?;
        // Member-local output only. Paste into a local browser tab; never send to the coordinator.
        if let Some(notice) = notice {
            notice("ready", &format!("http://{addr}/#{}", state.config.token));
        } else if let Some(launch) = &state.config.registration {
            println!("{} ({}) — Local pairing: http://{addr}/#{}", launch.name, state.config.data.display(), state.config.token);
        } else {
            println!("Signer: http://{addr}/#{}", state.config.token);
        }
        axum::serve(listener, routes::router(state))
            .await
            .map_err(|e| format!("serve: {e}"))
    })
}

#[cfg(test)]
mod tests {
    use crate::signer::{local::ApprovalRequest, wysiwys::PaymentView, CandidateRef, Network};
    use std::sync::{Arc, Mutex};

    #[test]
    fn payment_approval_fails_closed_and_asks_with_signer_derived_details() {
        let sk = orchard::keys::SpendingKey::from_bytes([7; 32]).unwrap();
        let to = orchard::keys::FullViewingKey::from(&sk).address_at(0u64, orchard::keys::Scope::External);
        let view = PaymentView {
            to: to.to_raw_address_bytes(), amount_zat: 40_000_000, fee_zat: 15_000, change_zat: 5,
            memo: b"rent".to_vec(), expiry_height: 1_152, network_branch_id: 0x77190ad8, fee_verified: true,
        };
        let candidate = CandidateRef { vault_id: [1; 32], payment_id: [2; 32], attempt_id: [3; 32] };
        let request = ApprovalRequest { candidate: &candidate, sighash: [9; 32], view: &view };
        // No approval channel (headless serve): refused.
        assert!(!(super::approval_policy(None, Network::Testnet, 2))(&request));

        let asked = Arc::new(Mutex::new(Vec::new()));
        let decision = Arc::new(Mutex::new(false));
        let (log, answer) = (asked.clone(), decision.clone());
        let approve: super::LocalApproval = Arc::new(move |summary| {
            log.lock().unwrap().push(summary.to_owned());
            *answer.lock().unwrap()
        });
        let mut policy = super::approval_policy(Some(approve), Network::Testnet, 2);
        assert!(!policy(&request), "the member's refusal refuses");
        *decision.lock().unwrap() = true;
        assert!(policy(&request), "the member's approval approves");

        let shown: serde_json::Value = serde_json::from_str(&asked.lock().unwrap()[0]).unwrap();
        let recipient = shown["recipient"].as_str().unwrap();
        assert!(recipient.starts_with("utest1"), "{recipient}");
        let decoded = crate::vault::orchard_receiver_from_ua(recipient, zcash_protocol::consensus::NetworkType::Test).unwrap();
        assert_eq!(decoded.to_raw_address_bytes(), view.to);
        assert_eq!(shown["amount_zat"], 40_000_000);
        assert_eq!(shown["fee_zat"], 15_000);
        assert_eq!(shown["network"], "testnet");
        assert_eq!(shown["member"], 2);
        assert_eq!(shown["memo"], "rent");
        assert_eq!(shown["attempt"], hex::encode([3; 32]));
        assert_eq!(shown["sighash"], hex::encode([9; 32]));
    }
}
