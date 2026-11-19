//! The member-owned HTTP device (axum). One process per member, started locally by
//! that member. Profile unlock, custody, ceremony and payment signing stay here; the web
//! coordinator only publishes public artifacts. This process drives the audited library. All library calls run on `spawn_blocking` because the hosted relay
//! stack blocks on its own runtime (see `setup_relay::shared_runtime`).

mod ceremony;
mod connect;
mod custody;
mod device;
mod payment;
mod native_config;
#[cfg(any(test, all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication")))]
mod native_member;
#[cfg(any(test, all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication")))]
mod native_recovery;
mod nonce_witness;
mod recovery;
mod registration;
#[cfg(test)]
mod repair;
mod routes;
mod state;

pub use state::Config;
#[cfg(all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication"))]
pub(crate) use connect::{ConnectAttempt, LocalConnect};
pub use registration::RegistrationConfig;
pub use native_config::{Deployment, FetchedConfig, NativeConfig};
#[cfg(all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication"))]
pub(crate) use native_member::{disconnect_wallet_tabs, run_native, request_stop as native_request_stop, set_aside as native_set_aside, vault_addresses as native_vault_addresses};
#[cfg(all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication"))]
pub(crate) use native_member::restore_running as native_restore_running;
#[cfg(all(target_os = "macos", feature = "apple-enclave", feature = "relay-communication"))]
pub(crate) use native_recovery::{clean_staging as native_clean_staging, profile_state as native_profile_state, restore_new as native_restore_new, REFUSED as NATIVE_RESTORE_REFUSED};
#[cfg(feature = "relay-communication")]
pub use nonce_witness::WitnessConfig;

/// Device-local UI notifications; never forwarded to the coordinator or a log.
pub type LocalNotice = std::sync::Arc<dyn Fn(&str, &str) + Send + Sync>;

/// The member's own decision on one payment, asked on this device (the native app's dialog).
/// Receives the signer-derived summary as JSON ([`approval_summary`]); `true` approves.
/// Without one, every payment is refused: HTTP or relay requests never approve on their own.
pub type LocalApproval = std::sync::Arc<dyn Fn(&str) -> bool + Send + Sync>;

/// The member's answer when LokiSigner asks them to compare a vault's roster code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RosterAnswer {
    /// "Codes match": every member sees the same code.
    Match,
    /// "Codes differ": this vault is refused until the app restarts.
    Differ,
    /// The dialog closed or timed out, or the request could not be shown. A retry may ask again.
    NoAnswer,
}

/// The member's own comparison of a vault's roster code before key generation, asked on this
/// device (the native app's dialog). Receives the summary `/api/agree` derives from the setup
/// document as JSON. Only [`RosterAnswer::Match`] records agreement. Without one (headless),
/// `/api/agree` trusts its caller to have compared the code.
pub type LocalRosterConfirmation = std::sync::Arc<dyn Fn(&str) -> RosterAnswer + Send + Sync>;

/// What a native window shows in place of a vault name it will not show.
pub(crate) const HIDDEN_VAULT_NAME: &str = "Name hidden (unsupported characters)";

/// The creator's vault name as LokiSigner shows it, in the roster dialog and in
/// "Vault addresses…". A name is shown as written or hidden whole, never cleaned: hidden when
/// it is longer than 80 characters or holds a control character, whitespace other than a
/// space, a format character (Cf, such as bidi overrides and zero-width joiners), a default
/// ignorable character (such as variation selectors and U+034F), or a run of more than three
/// combining marks, which draw outside a one-line box.
pub(crate) fn vault_label(name: &str) -> &str {
    use icu_properties::{props::{DefaultIgnorableCodePoint, GeneralCategory}, CodePointMapData, CodePointSetData};
    let category = CodePointMapData::<GeneralCategory>::new();
    let ignorable = CodePointSetData::new::<DefaultIgnorableCodePoint>();
    let mut marks = 0;
    let unsupported = name.chars().count() > 80 || name.chars().any(|c| {
        let general = category.get(c);
        marks = if matches!(general, GeneralCategory::NonspacingMark | GeneralCategory::EnclosingMark) { marks + 1 } else { 0 };
        c.is_control() || (c.is_whitespace() && c != ' ') || general == GeneralCategory::Format
            || ignorable.contains(c) || marks > 3
    });
    if unsupported { HIDDEN_VAULT_NAME } else { name }
}

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

/// A scripted reviewer in place of the native dialog (`loki_member_app --approve-from <file>`),
/// for test harnesses. Each request's summary is printed as an `approval-request <json>` line
/// on stderr; the member approves only when `approve <sighash>` for that request appears in
/// `file` within `timeout`. `refuse <sighash>`, no answer, or an unreadable summary refuse.
pub fn file_approval(file: std::path::PathBuf, timeout: std::time::Duration) -> LocalApproval {
    std::sync::Arc::new(move |summary| {
        let Some(sighash) = serde_json::from_str::<serde_json::Value>(summary)
            .ok()
            .and_then(|v| v["sighash"].as_str().map(str::to_owned))
        else {
            return false;
        };
        eprintln!("approval-request {summary}");
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            for line in std::fs::read_to_string(&file).unwrap_or_default().lines() {
                match line.split_once(' ') {
                    Some(("approve", h)) if h == sighash => return true,
                    Some(("refuse", h)) if h == sighash => return false,
                    _ => {}
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(250));
        }
        false
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
    parse_config(args, false)
}

pub(crate) fn native_config_from_args(args: &[String]) -> Result<Config, String> {
    let mut config = parse_config(args, true)?;
    config.secure_element = "apple".into();
    Ok(config)
}

fn new_token() -> String {
    use base64::Engine;
    use rand_core::{OsRng, RngCore};
    let mut token = [0u8; 32];
    OsRng.fill_bytes(&mut token);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token)
}

fn parse_config(args: &[String], native: bool) -> Result<Config, String> {
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
    let network = value("--network").unwrap_or_else(|| "regtest".into());
    crate::network::VaultNetwork::parse(&network)?;
    Ok(Config {
        data, port, bind, native,
        registration: RegistrationConfig::from_args(args, flag("--development-http"))?,
        advertise_url: value("--advertise-url"),
        network,
        lightwalletd: value("--lightwalletd-url"),
        transport: value("--transport").unwrap_or_else(|| "local".into()),
        secure_element: value("--secure-element").unwrap_or_else(|| "software".into()),
        operator_bundle: value("--operator-bundle").map(PathBuf::from),
        nonce_witnesses: value("--nonce-witnesses").map(PathBuf::from),
        operator_key: value("--operator-key"),
        enrollment_issuer: value("--enrollment-issuer").map(PathBuf::from),
        development_http: flag("--development-http"),
        token: if native { String::new() } else { new_token() },
        frostd_url: value("--frostd-url").unwrap_or_else(|| "http://127.0.0.1:2744".into()),
        peers,
        loopback_peers: flag("--allow-loopback-peers"),
    })
}

/// Build the axum app and serve on the configured bind IP and port. Blocks.
pub fn run(config: Config) -> Result<(), String> {
    run_local(config, None, None, None, None)
}

/// `fetched`: the configuration the native app fetched and the member confirmed; it is saved
/// only once the profile unlocks. A member started here has no roster dialog: `/api/agree`
/// trusts its caller to have compared the code. LokiSigner starts through `run_native`.
pub fn run_local(
    config: Config,
    pass: Option<zeroize::Zeroizing<String>>,
    notice: Option<LocalNotice>,
    approval: Option<LocalApproval>,
    fetched: Option<FetchedConfig>,
) -> Result<(), String> {
    run_local_with(config, pass, notice, approval, None, fetched, None, None, |_| Ok(()))
}

fn run_local_with<G>(
    mut config: Config,
    pass: Option<zeroize::Zeroizing<String>>,
    notice: Option<LocalNotice>,
    approval: Option<LocalApproval>,
    roster_confirmation: Option<LocalRosterConfirmation>,
    fetched: Option<FetchedConfig>,
    stop: Option<&tokio::sync::Notify>,
    connect: Option<connect::LocalConnect>,
    on_start: impl FnOnce(&state::Shared) -> Result<G, String>,
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
        let wallet_tabs = connect.zip(config.registration.as_ref()).map(|(ask, registration)| {
            let endpoint = config.lokisigner_url().ok_or("LokiSigner needs a loopback listener")?;
            Ok::<_, &str>(connect::WalletTabs::new(endpoint, registration.coordinator.clone(), ask))
        }).transpose()?;
        let state: state::Shared = std::sync::Arc::new(state::AppState { approval, roster_confirmation, fetched_config: fetched, wallet_tabs, ..state::AppState::new(config) });
        let _scope = on_start(&state)?;
        let ready = registration::start(&state, pass, notice.as_ref()).await?;
        if state.config.native {
            if let Some(notice) = notice { notice(ready, ""); }
        } else if let Some(notice) = notice {
            notice(ready, &format!("http://{addr}/#{}", state.config.token));
        } else if let Some(launch) = &state.config.registration {
            println!("{} ({}) — Local pairing: http://{addr}/#{}", launch.name, state.config.data.display(), state.config.token);
        } else {
            println!("Signer: http://{addr}/#{}", state.config.token);
        }
        let server = axum::serve(listener, routes::router(state).into_make_service_with_connect_info::<std::net::SocketAddr>());
        if let Some(stop) = stop {
            // Drop the native runtime before the UI can set aside the profile. No HTTP
            // request or signer worker may keep writing to the old profile after that.
            tokio::select! {
                result = async { server.await } => result.map_err(|e| format!("serve: {e}")),
                _ = stop.notified() => Ok(()),
            }
        } else {
            server.await.map_err(|e| format!("serve: {e}"))
        }
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

    #[test]
    fn a_vault_name_is_shown_as_written_or_hidden_whole() {
        for shown in ["Household", "Friends’ vault", "Tiền nhà", "Tie\u{0323}\u{0302}n", "家族 🏠", &"é".repeat(80)] {
            assert_eq!(super::vault_label(shown), shown, "{shown:?}");
        }
        let marks = |n: usize| format!("Rent{}", "\u{0301}".repeat(n));
        assert_eq!(super::vault_label(&marks(3)), marks(3));
        for hidden in [
            "Rent\nChoose Codes match".to_owned(), "a\u{0085}b".into(), "a\u{2028}b".into(), "a\u{202e}b".into(),
            "a\u{001b}[2Jb".into(), "a\u{200b}b".into(), "a\u{feff}b".into(), "a\tb".into(),
            // Format and default ignorable characters the review found shown as written.
            "a\u{0600}b".into(), "a\u{13430}b".into(), "a\u{1bca0}b".into(), "a\u{1d173}b".into(),
            "a\u{e0100}b".into(), "a\u{034f}b".into(), "a\u{fe0f}b".into(), "a\u{3164}b".into(),
            // A base letter with 39 combining marks draws far outside its line.
            format!("a{}", "\u{0301}".repeat(39)), marks(4), "é".repeat(81),
        ] {
            assert_eq!(super::vault_label(&hidden), super::HIDDEN_VAULT_NAME, "{hidden:?}");
        }
    }

    #[test]
    fn file_approval_approves_only_its_own_sighash() {
        let file = std::env::temp_dir().join(format!("loki-approvals-{}", uuid::Uuid::new_v4()));
        let wait = std::time::Duration::from_millis(600);
        let approve = super::file_approval(file.clone(), wait);
        let summary = |sighash: &str| serde_json::json!({ "sighash": sighash }).to_string();
        assert!(!approve(&summary("aa")), "no answer refuses");
        assert!(!approve("not json"), "an unreadable summary refuses");
        std::fs::write(&file, "approve bb\nrefuse cc\napprove aaa\n").unwrap();
        assert!(approve(&summary("bb")));
        assert!(!approve(&summary("cc")), "an explicit refusal refuses");
        assert!(!approve(&summary("aa")), "another sighash's approval does not approve this one");
        std::fs::remove_file(file).unwrap();
    }
}
