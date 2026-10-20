//! `loki_serve` — a localhost HTTP server that fronts ONE member's view-only wallet for
//! the web UI. The browser logs in with the wallet passphrase; the server unlocks the
//! sealed member state, scans to the lightwalletd tip, and serves the real vault summary
//! (balance, address, height, policy) as JSON. No key material and no passphrase ever
//! leave this process, and nothing here can sign — signing stays on the native signer.
//!
//!   loki_serve <member-dir> <roster.json> <lightwalletd-url> [listen-addr]
//!
//! Routes (all JSON, permissive CORS for the local dev UI):
//!   POST /api/unlock  {"passphrase": "..."}  -> unlock + scan, returns the vault summary
//!   GET  /api/vault                           -> the cached summary (401 until unlocked)
//!   POST /api/sync                            -> re-scan to the tip, returns a fresh summary

use std::{env, fs, path::Path};

use loki_poc::{
    member_state::{self, MemberState},
    network::VaultNetwork,
    payment_manifest::MAX_INPUTS,
    vault,
    wallet_store::{sync_member_wallet, Lightwalletd, VaultWallet},
};
use serde_json::{json, Value};
use tiny_http::{Header, Method, Response, Server};
use zcash_client_backend::proto::service::Empty;
use zcash_protocol::consensus::NetworkType;
use zeroize::Zeroizing;

/// The unlocked, scanned wallet plus the static roster facts needed to render a summary.
struct Session {
    member: MemberState,
    wallet: VaultWallet,
    client: Lightwalletd,
    summary: Value,
}

fn network_type(network: VaultNetwork) -> NetworkType {
    match network {
        VaultNetwork::Regtest => NetworkType::Regtest,
        VaultNetwork::Testnet => NetworkType::Test,
    }
}

/// Everything the UI shows, read straight from the scanned wallet — nothing invented.
fn build_summary(member: &MemberState, wallet: &mut VaultWallet, chain_tip: u64) -> Result<Value, String> {
    let height = wallet
        .scanned_height()?
        .ok_or("wallet did not scan any blocks")?;
    let balance = wallet.ironwood_balance_zat()?;
    let address = vault::unified_address(&wallet.viewing_key()?, network_type(member.network));
    let max_spendable = wallet.max_spendable(MAX_INPUTS);
    Ok(json!({
        "vault": hex::encode(member.vault),
        "network": member.network.label(),
        "threshold": member.roster.threshold,
        "members": member.roster.members.len(),
        "policy": format!("{}-of-{}", member.roster.threshold, member.roster.members.len()),
        "address": address,
        "balance_zat": balance,
        "max_spendable_zat": max_spendable,
        "height": height,
        "chain_tip": chain_tip,
        "synced": u64::from(height) >= chain_tip,
    }))
}

/// Write the posted passphrase to an owner-only file so `member_state::open` can read it
/// (its API takes a 0600 file path, matching the CLI). Removed again right after unlock.
fn stage_passphrase(path: &Path, passphrase: &str) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::{io::Write, os::unix::fs::OpenOptionsExt};
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| format!("stage passphrase: {e}"))?;
        file.write_all(passphrase.as_bytes())
            .map_err(|e| format!("stage passphrase: {e}"))
    }
    #[cfg(not(unix))]
    {
        fs::write(path, passphrase).map_err(|e| format!("stage passphrase: {e}"))
    }
}

async fn load_session(
    member_dir: &Path,
    roster: &Path,
    url: &str,
    passphrase: &str,
) -> Result<Session, String> {
    let pass_path = member_dir.join(".loki-serve-pass");
    stage_passphrase(&pass_path, passphrase)?;
    let opened = member_state::open(member_dir, &pass_path, roster);
    let _ = fs::remove_file(&pass_path);
    let member = opened?;

    let (mut wallet, mut client) = sync_member_wallet(&member, member_dir, passphrase, url).await?;
    let chain_tip = client
        .get_lightd_info(Empty {})
        .await
        .map_err(|e| format!("lightwalletd info: {e}"))?
        .into_inner()
        .block_height;
    let summary = build_summary(&member, &mut wallet, chain_tip)?;
    Ok(Session { member, wallet, client, summary })
}

async fn resync(session: &mut Session) -> Result<(), String> {
    session.wallet.sync(&mut session.client).await?;
    let chain_tip = session
        .client
        .get_lightd_info(Empty {})
        .await
        .map_err(|e| format!("lightwalletd info: {e}"))?
        .into_inner()
        .block_height;
    session.summary = build_summary(&session.member, &mut session.wallet, chain_tip)?;
    Ok(())
}

fn header(key: &str, value: &str) -> Header {
    Header::from_bytes(key.as_bytes(), value.as_bytes()).expect("static header")
}

fn err_json(message: &str) -> String {
    json!({ "error": message }).to_string()
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() < 3 || args.len() > 4 {
        eprintln!("usage: loki_serve <member-dir> <roster.json> <lightwalletd-url> [listen-addr]");
        std::process::exit(2);
    }
    let member_dir = std::path::PathBuf::from(&args[0]);
    let roster = std::path::PathBuf::from(&args[1]);
    let url = args[2].clone();
    let listen = args.get(3).cloned().unwrap_or_else(|| "127.0.0.1:8099".into());

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("start tokio runtime");

    let server = match Server::http(&listen) {
        Ok(server) => server,
        Err(e) => {
            eprintln!("error: bind {listen}: {e}");
            std::process::exit(1);
        }
    };
    eprintln!("loki_serve listening on http://{listen}  (vault: {})", roster.display());

    let mut session: Option<Session> = None;
    for mut req in server.incoming_requests() {
        let method = req.method().clone();
        let path = req.url().to_string();
        let (status, body) = match (&method, path.as_str()) {
            (Method::Options, _) => (204, String::new()),

            (Method::Post, "/api/unlock") => {
                let mut raw = String::new();
                let _ = req.as_reader().read_to_string(&mut raw);
                let passphrase = serde_json::from_str::<Value>(&raw)
                    .ok()
                    .and_then(|v| v["passphrase"].as_str().map(|s| Zeroizing::new(s.to_string())));
                match passphrase {
                    None => (400, err_json("missing passphrase")),
                    Some(p) => match rt.block_on(load_session(&member_dir, &roster, &url, &p)) {
                        Ok(s) => {
                            let out = s.summary.to_string();
                            session = Some(s);
                            (200, out)
                        }
                        Err(e) => (401, err_json(&e)),
                    },
                }
            }

            (Method::Get, "/api/vault") => match &session {
                Some(s) => (200, s.summary.to_string()),
                None => (401, err_json("locked: unlock the wallet first")),
            },

            (Method::Post, "/api/sync") => match &mut session {
                Some(s) => match rt.block_on(resync(s)) {
                    Ok(()) => (200, s.summary.to_string()),
                    Err(e) => (500, err_json(&e)),
                },
                None => (401, err_json("locked: unlock the wallet first")),
            },

            _ => (404, err_json("not found")),
        };

        let mut resp = Response::from_string(body).with_status_code(status);
        for (k, v) in [
            ("Content-Type", "application/json"),
            ("Access-Control-Allow-Origin", "*"),
            ("Access-Control-Allow-Methods", "GET, POST, OPTIONS"),
            ("Access-Control-Allow-Headers", "Content-Type"),
        ] {
            resp = resp.with_header(header(k, v));
        }
        let _ = req.respond(resp);
    }
}
