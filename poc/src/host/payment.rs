//! Member-device payments. Share loading and signing execute in this member-owned process,
//! never the web coordinator. All wallet, frostd, proving, and broadcast work is blocking.

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use orchard::keys::FullViewingKey;
use rand_core::{OsRng, RngCore};
use reddsa_frost::frost::redpallas as frost;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;
use zcash_client_backend::proto::service::{BlockId, ChainSpec, Empty, RawTransaction};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, NetworkUpgrade, Parameters},
    memo::MemoBytes,
    value::Zatoshis,
};
use zeroize::Zeroizing;

use super::{
    routes::{blocking, err},
    state::Shared,
};
use crate::{
    candidate::{quote_fee, CandidateInputs},
    network::{VaultNetwork, TESTNET_NU7_BIRTH},
    payment_transport::{coordinate_resumable, signer_loop_resumable, Progress, SigningRun, DRIVE_YIELDED, SIGNING_WINDOW},
    setup_transport::{Identity, PublicIdentity},
    signer::{
        local::LocalSigner, CandidateRef, Network,
        PublicPaymentParams, Signer,
    },
    state::MemberDir,
    transport::{FrostdChannel, FrostdLoginKey, FrostdTransport, Incoming, Outbound, PaymentEncryption, Peer, Transport},
    tx_finalize::prove,
    vault,
    verify::{check_candidate, Expectations, Refusal},
    wallet_store::{lightwalletd_endpoint, Lightwalletd, VaultWallet},
    zip2005,
};

type Reply = (StatusCode, Json<Value>);

#[derive(Clone, Serialize, Deserialize)]
struct Payment {
    attempt: String,
    vault: String,
    proposer: u16,
    recipient: String,
    amount_zat: u64,
    memo: String,
    fee_zat: u64,
    change_zat: u64,
    note_selection: Vec<String>,
    target_height: u32,
    expiry_height: u32,
    signers: Vec<u16>,
    #[serde(default)]
    open_approval: bool,
    phase: String,
    session_id: Option<Uuid>,
    #[serde(skip_serializing_if = "Option::is_none")]
    coordinator_secret: Option<String>,
    #[serde(default)]
    coordinator: Option<PublicIdentity>,
    #[serde(skip_serializing_if = "Option::is_none")]
    review_token: Option<String>,
    #[serde(default)]
    approval_requested: bool,
    #[serde(default)]
    approval_started: bool,
    #[serde(default)]
    approval_complete: bool,
    #[serde(default)]
    finish_requested: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    txid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signed_pczt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_tx: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

struct Vault {
    network: VaultNetwork,
    fvk: FullViewingKey,
    key: frost::keys::KeyPackage,
    share_epoch: u64,
    public: frost::keys::PublicKeyPackage,
    identity: Identity,
    threshold: u16,
    slot: u16,
    peers: BTreeMap<u16, Peer>,
    roster: BTreeMap<u16, PublicIdentity>,
    base_urls: BTreeMap<u16, String>,
    birth_height: u32,
}

fn hex32(s: &str) -> Result<[u8; 32], String> {
    hex::decode(s)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "expected 32 bytes of hex".into())
}
fn required<'a>(v: &'a Value, field: &str) -> Result<&'a str, String> {
    v[field]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| format!("missing {field}"))
}
fn pair(body: &Value) -> Result<(String, String), String> {
    let vault = required(body, "vault")?.to_owned();
    hex32(&vault)?;
    let attempt = required(body, "attempt")?.to_owned();
    hex32(&attempt)?;
    Ok((vault, attempt))
}
fn member_dir(data: &Path, vault: &str) -> Result<MemberDir, String> {
    hex32(vault)?;
    Ok(MemberDir::open(&data.join("vaults"), vault))
}
fn payment_dir(data: &Path, vault: &str) -> Result<MemberDir, String> {
    hex32(vault)?;
    MemberDir::create(&data.join("vaults").join(vault), "payments").map_err(|e| e.to_string())
}
fn read_payment(data: &Path, pass: &str, vault: &str, attempt: &str) -> Result<Payment, String> {
    hex32(attempt)?;
    let raw = payment_dir(data, vault)?
        .read_sealed(&format!("{attempt}.json"), pass)
        .map_err(|e| e.to_string())?;
    let p: Payment = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    if p.vault != vault || p.attempt != attempt {
        return Err("payment identity mismatch".into());
    }
    Ok(p)
}
fn save_record(dir: &MemberDir, file: &str, pass: &str, value: &impl Serialize) -> Result<(), String> {
    let temp = format!("{file}.{}.tmp", Uuid::new_v4());
    let bytes = Zeroizing::new(serde_json::to_vec(value).map_err(|e| e.to_string())?);
    dir.write_sealed(&temp, &bytes, pass).map_err(|e| e.to_string())?;
    std::fs::rename(dir.path().join(temp), dir.path().join(file)).map_err(|e| e.to_string())?;
    std::fs::File::open(dir.path()).and_then(|dir| dir.sync_all()).map_err(|e| e.to_string())
}
fn save_payment(data: &Path, pass: &str, p: &Payment) -> Result<(), String> {
    save_record(&payment_dir(data, &p.vault)?, &format!("{}.json", p.attempt), pass, p)
}

#[derive(Default)]
pub(super) struct ExpiryTip {
    checked: Option<Instant>,
    height: Option<u64>,
}

impl ExpiryTip {
    fn check(&mut self, expiry: u32, fetch: impl FnOnce() -> Result<u64, String>) -> Result<(), String> {
        if self.height.is_some_and(|height| height >= u64::from(expiry)) { return Err("payment expired".into()); }
        if self.checked.is_none_or(|checked| checked.elapsed() >= Duration::from_secs(60)) {
            // Throttle failed probes too, so the next drive can exchange signatures during an outage.
            self.checked = Some(Instant::now());
            self.height = Some(fetch().map_err(|_| DRIVE_YIELDED.to_owned())?);
        }
        if self.height.is_some_and(|height| height >= u64::from(expiry)) { return Err("payment expired".into()); }
        Ok(())
    }
}

// A separate sealed transcript for each role, bound to this exact relay session and intent.
fn signing_run<'a>(st: &'a Shared, data: &'a Path, pass: &'a str, p: &'a Payment, role: &'a str)
    -> Result<SigningRun<'a>, String>
{
    let dir = payment_dir(data, &p.vault)?;
    let file = format!("{}.{role}.sealed", p.attempt);
    let binding = (p.vault.clone(), p.attempt.clone(), p.session_id, role.to_owned());
    let progress = if dir.exists(&file) {
        let raw = Zeroizing::new(dir.read_sealed(&file, pass).map_err(|e| e.to_string())?);
        let (saved, progress): ((String, String, Option<Uuid>, String), Progress) =
            serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        if saved != binding { return Err("payment checkpoint identity mismatch".into()); }
        progress
    } else { Progress::default() };
    let deadline = Instant::now() + Duration::from_secs(30);
    let rt = runtime()?;
    let endpoint = lightwalletd_endpoint(url(st)?)?
        .connect_timeout(Duration::from_secs(10)).timeout(Duration::from_secs(10));
    SigningRun::new(progress, SIGNING_WINDOW,
        move |progress| save_record(&dir, &file, pass, &(&binding, progress)),
        move || {
            if st.session.blocking_read().as_ref().is_none_or(|session| session.data != data) {
                return Err("payment signing paused while profile is locked".into());
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() { return Err(DRIVE_YIELDED.into()); }
            let mut tip = match st.payment_tip.try_lock() {
                Ok(tip) => tip,
                Err(std::sync::TryLockError::WouldBlock) => return Err(DRIVE_YIELDED.into()),
                Err(error) => return Err(error.to_string()),
            };
            tip.check(p.expiry_height, || rt.block_on(async {
                tokio::time::timeout(remaining.min(Duration::from_secs(10)), async {
                    let channel = endpoint.connect().await.map_err(|e| e.to_string())?;
                    Lightwalletd::new(channel).get_latest_block(ChainSpec {}).await
                        .map(|reply| reply.into_inner().height).map_err(|e| e.to_string())
                }).await.map_err(|e| e.to_string())?
            }))
        }).map(|run| run.with_drive_limit(deadline.saturating_duration_since(Instant::now())))
}

struct PaymentRunner { st: Shared, key: String }
impl Drop for PaymentRunner {
    fn drop(&mut self) {
        if let Ok(mut active) = self.st.active_payments.lock() { active.remove(&self.key); }
    }
}
fn claim_payment(st: &Shared, vault: &str, attempt: &str, role: &str) -> Result<Option<PaymentRunner>, String> {
    let key = format!("{vault}:{attempt}:{role}");
    if !st.active_payments.lock().map_err(|e| e.to_string())?.insert(key.clone()) { return Ok(None); }
    Ok(Some(PaymentRunner { st: st.clone(), key }))
}

fn apply_signing_result(local: &mut Payment, slot: u16, received: bool, result: Result<(), String>) -> bool {
    // Finalization may have advanced while this runner was waiting on the network.
    if local.signed_pczt.is_some() || !matches!(local.phase.as_str(), "signing" | "approved") { return false; }
    match result {
        Ok(()) => {
            local.approval_complete = received;
            if !local.finish_requested { local.error = None; }
            if local.proposer != slot { local.phase = "approved".into(); }
        }
        Err(error) if error == DRIVE_YIELDED => {}
        Err(error) => {
            if error == "payment expired" || error == "signing window expired" { local.phase = "expired".into(); }
            local.error = Some(error);
            // Retain authorization and the exact committed nonces for a transient-error resume.
        }
    }
    true
}

fn spawn_signing(st: Shared, data: PathBuf, pass: Zeroizing<String>, vault: String, attempt: String) {
    tokio::task::spawn_blocking(move || {
        let outcome = (|| -> Result<(), String> {
            let Some(_runner) = claim_payment(&st, &vault, &attempt, "signer")? else { return Ok(()) };
            let mut p = read_payment(&data, &pass, &vault, &attempt)?;
            if !matches!(p.phase.as_str(), "signing" | "approved") || !p.approval_requested || p.approval_complete { return Ok(()); }
            let v = load_vault(&data, &pass, &vault, &st.config)?;
            check_intent(&p, &v)?;
            if p.open_approval && p.proposer != v.slot {
                let response = peer_request(&st.config, &vault, Some(&attempt), &v, p.proposer, Some(&p))?;
                let remote: Payment = serde_json::from_value(response["intent"].clone()).map_err(|e| e.to_string())?;
                check_intent(&remote, &v)?;
                if approval_intent(&remote) != approval_intent(&p) { return Err("proposer changed approved payment".into()); }
                p.signers = remote.signers;
                let _guard = st.payment.lock().map_err(|e| e.to_string())?;
                let mut local = read_payment(&data, &pass, &vault, &attempt)?;
                if local.approval_started && local.signers != p.signers { return Err("signing quorum changed".into()); }
                local.signers = p.signers.clone();
                if !p.signers.contains(&v.slot) {
                    local.phase = "not_selected".into();
                    local.error = Some("payment quorum already filled".into());
                }
                save_payment(&data, &pass, &local)?;
                if !p.signers.contains(&v.slot) { return Ok(()); }
            }
            if p.signers.len() != usize::from(v.threshold) { return Ok(()); }
            let received = if p.proposer == v.slot { p.signed_pczt.is_some() } else {
                peer_read(&st.config, &vault, Some(&attempt), &v, p.proposer)?["signatures_received"] == true
            };
            let result = if received { Ok(()) } else { sign(&st, &data, &pass, &p, &v) };
            let _guard = st.payment.lock().map_err(|e| e.to_string())?;
            let mut local = read_payment(&data, &pass, &vault, &attempt)?;
            if !apply_signing_result(&mut local, v.slot, received, result) { return Ok(()); }
            save_payment(&data, &pass, &local)
        })();
        if let Err(error) = outcome { eprintln!("payment signing: {error}"); }
    });
}

fn finalization_pending(data: &Path, p: &Payment) -> bool {
    matches!(p.phase.as_str(), "signing" | "approved") && (p.finish_requested || (p.coordinator_secret.is_some()
        && payment_dir(data, &p.vault).is_ok_and(|dir| dir.exists(&format!("{}.coordinator.sealed", p.attempt)))))
}

/// As with DKG, persisted authorization survives a restart; only the runner claim is in memory.
pub(super) fn spawn_auto_resume(st: Shared) {
    tokio::spawn(async move {
        loop {
            if let Ok((data, pass)) = unlocked(&st).await {
                let (scan_data, scan_pass) = (data.clone(), pass.clone());
                let pending = tokio::task::spawn_blocking(move || -> Vec<(String, String, bool, bool)> {
                    let mut pending = Vec::new();
                    let Ok(vaults) = std::fs::read_dir(scan_data.join("vaults")) else { return pending };
                    for vault in vaults.flatten() {
                        let vault = vault.file_name().to_string_lossy().into_owned();
                        if hex32(&vault).is_err() { continue; }
                        let Ok(files) = std::fs::read_dir(scan_data.join("vaults").join(&vault).join("payments")) else { continue };
                        for file in files.flatten() {
                            let name = file.file_name().to_string_lossy().into_owned();
                            let Some(attempt) = name.strip_suffix(".json") else { continue };
                            if let Ok(p) = read_payment(&scan_data, &scan_pass, &vault, attempt) {
                                let signer = matches!(p.phase.as_str(), "signing" | "approved") && p.approval_requested && !p.approval_complete;
                                let coordinator = finalization_pending(&scan_data, &p);
                                if signer || coordinator { pending.push((vault.clone(), attempt.to_owned(), signer, coordinator)); }
                            }
                        }
                    }
                    pending
                }).await;
                if let Ok(pending) = pending {
                    for (vault, attempt, signer, coordinator) in pending {
                        if signer { spawn_signing(st.clone(), data.clone(), pass.clone(), vault.clone(), attempt.clone()); }
                        if coordinator { spawn_finalization(st.clone(), data.clone(), pass.clone(), vault, attempt); }
                    }
                }
            }
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
}
fn load_vault(data: &Path, pass: &str, vault: &str, config: &super::Config) -> Result<Vault, String> {
    let dir = member_dir(data, vault)?;
    let sealed = Zeroizing::new(
        dir.read_sealed("vault.sealed", pass)
            .map_err(|e| e.to_string())?,
    );
    let v: Value = serde_json::from_slice(&sealed).map_err(|e| e.to_string())?;
    if required(&v, "vault")? != vault || v["key_derivation"] != zip2005::VERSION {
        return Err("sealed vault identity or derivation mismatch".into());
    }
    let network = VaultNetwork::parse(required(&v, "network")?)?;
    if network.label() != config.network {
        return Err("vault and coordinator networks differ".into());
    }
    let slot: u16 = v["my_frost_id"]
        .as_u64()
        .ok_or("missing member slot")?
        .try_into()
        .map_err(|_| "invalid member slot")?;
    let threshold: u16 = v["threshold"]
        .as_u64()
        .ok_or("missing threshold")?
        .try_into()
        .map_err(|_| "invalid threshold")?;
    if !MemberDir::open(data, ".").exists("identity.sealed") {
        return Err("missing member identity; restore from recovery backup".into());
    }
    let identity = super::ceremony::identity(data, pass, slot)?;
    let ak = hex32(required(&v, "group_ak")?)?;
    if v.get("key_package").is_some() || v.get("vault_secret").is_some() {
        return Err("legacy vault contains password-only spend material; migrate or restore into a fresh device profile".into());
    }
    let sdir = super::ceremony::signer_dir(data, vault)?;
    let store = crate::signer::store::SignerStore::open(&sdir)?;
    let expected_network = match network { VaultNetwork::Regtest => Network::Regtest, VaultNetwork::Testnet => Network::Testnet };
    if store.vault() != hex32(vault)? || store.member() != slot || store.network() != expected_network {
        return Err("secure-element share belongs to another vault or member".into());
    }
    let se = config.open_secure_element(&sdir, pass)?;
    let (share_epoch, raw) = store.read(&se, crate::signer::store::FileKind::Share)?
        .ok_or("missing secure-element share; restore from recovery backup")?;
    let (key_bytes, public_bytes, secret) = crate::signer::local::decode_share(&raw)?;
    let secret = Zeroizing::new(secret);
    let fvk = zip2005::frost_viewing_key(&ak, &secret)
        .map_err(|e| format!("group viewing key: {e:?}"))?;
    if v["group_address"].as_str() != Some(&vault::unified_address(&fvk, network.network_type())) {
        return Err("sealed vault address mismatch".into());
    }
    if hex::encode(public_bytes) != required(&v, "public_package")? {
        return Err("secure-element share and public vault metadata differ".into());
    }
    let key = frost::keys::KeyPackage::deserialize(&key_bytes).map_err(|e| e.to_string())?;
    let public = frost::keys::PublicKeyPackage::deserialize(
        &hex::decode(required(&v, "public_package")?).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    let id = frost::Identifier::try_from(slot).map_err(|e| e.to_string())?;
    if key.identifier() != &id
        || key.verifying_key() != public.verifying_key()
        || public.min_signers() != Some(threshold)
        || public.verifying_shares().get(&id) != Some(key.verifying_share())
        || public
            .verifying_key()
            .serialize()
            .map_err(|e| e.to_string())?
            != ak
    {
        return Err("member key differs from sealed vault".into());
    }
    let c: Value = serde_json::from_slice(
        &member_dir(data, vault)?
            .read_sealed("ceremony.sealed", pass)
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if c["vault"] != vault || c["my_slot"] != slot || c["threshold"] != threshold {
        return Err("ceremony and vault differ".into());
    }
    let mut peers = BTreeMap::new();
    let mut roster = BTreeMap::new();
    let mut base_urls = BTreeMap::new();
    for n in 1..=v["members"].as_u64().ok_or("missing members")? {
        let slot: u16 = n.try_into().map_err(|_| "invalid member id")?;
        let encryption = required(&c["slots"][slot.to_string()]["identity"], "encryption")?;
        let signing = required(&c["slots"][slot.to_string()]["identity"], "signing")?;
        roster.insert(slot, PublicIdentity { id: slot, signing: hex32(signing)?, encryption: hex32(encryption)? });
        peers.insert(slot, Peer(hex32(encryption)?));
        if let Some(base) = c["slots"][slot.to_string()]["base_url"].as_str() {
            base_urls.insert(slot, base.to_owned());
        }
    }
    if roster.get(&slot) != Some(&identity.public()) {
        return Err("member relay identity mismatch".into());
    }
    // shortcut: older Testnet seals scan from NU7; upgrade when migrating those vaults to stored birth checkpoints.
    let birth_height = v["birth_height"]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .unwrap_or(match network {
            VaultNetwork::Regtest => 2,
            VaultNetwork::Testnet => TESTNET_NU7_BIRTH,
        });
    Ok(Vault {
        network,
        fvk,
        key,
        share_epoch,
        public,
        identity,
        threshold,
        slot,
        peers,
        roster,
        base_urls,
        birth_height,
    })
}
fn runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Runtime::new().map_err(|e| e.to_string())
}
fn wallet(
    data: &Path,
    pass: &str,
    vault: &str,
    v: &Vault,
    url: &str,
) -> Result<(VaultWallet, Lightwalletd, tokio::runtime::Runtime), String> {
    let rt = runtime()?;
    let channel = rt
        .block_on(
            lightwalletd_endpoint(url)?
                .connect_timeout(Duration::from_secs(10))
                .timeout(Duration::from_secs(30))
                .connect(),
        )
        .map_err(|e| format!("connect to lightwalletd: {e}"))?;
    let mut client = Lightwalletd::new(channel);
    let info = rt
        .block_on(client.get_lightd_info(Empty {}))
        .map_err(|e| format!("lightwalletd info: {e}"))?
        .into_inner();
    if info.chain_name != "test"
        || Some(info.sapling_activation_height)
            != v.network
                .activation_height(NetworkUpgrade::Sapling)
                .map(u64::from)
    {
        return Err("lightwalletd serves another chain".into());
    }
    if info.block_height < u64::from(v.birth_height) {
        return Err("lightwalletd is below vault birth".into());
    }
    let prior = rt
        .block_on(client.get_tree_state(BlockId {
            height: u64::from(v.birth_height - 1),
            hash: vec![],
        }))
        .map_err(|e| format!("birth tree state: {e}"))?
        .into_inner();
    if prior.height != u64::from(v.birth_height - 1) || prior.network != info.chain_name {
        return Err("lightwalletd returned a different birth checkpoint".into());
    }
    let birthday = zcash_client_backend::data_api::AccountBirthday::from_treestate(prior, None)
        .map_err(|e| format!("parse birth tree state: {e}"))?;
    let mut w = VaultWallet::open(
        &member_dir(data, vault)?.path().join("wallet.sqlite"),
        v.network,
        &v.fvk,
        &birthday,
        pass,
    )?;
    rt.block_on(w.sync(&mut client))?;
    Ok((w, client, rt))
}
fn relay(identity: &Identity, url: &str) -> Result<FrostdTransport, String> {
    let raw = Zeroizing::new(identity.to_secret_bytes());
    let secret: [u8; 32] = raw[34..].try_into().map_err(|_| "identity secret length")?;
    // Log in to the relay with the member's own X25519 key, so its relay address matches the
    // encryption pubkey the roster already maps it to. (A dedicated login key is a later
    // hardening; here reuse keeps the roster addressing unchanged.)
    FrostdTransport::new(url, FrostdLoginKey::from_secret_bytes(secret)).map_err(|e| e.to_string())
}

struct ReviewedTransport<'a> {
    inner: &'a FrostdTransport,
    payment: &'a Payment,
    vault: &'a Vault,
    data: &'a Path,
    pass: &'a str,
}

impl Transport for ReviewedTransport<'_> {
    type Error = String;
    type Channel = FrostdChannel;
    fn set_deadline(&self, deadline: Option<Instant>) -> bool { self.inner.set_deadline(deadline) }
    fn open(&mut self, _peers: &[Peer], _message_count: u8) -> Result<FrostdChannel, String> {
        Err("signer cannot open session".into())
    }
    fn join(&mut self, _session: Uuid) -> Result<FrostdChannel, String> {
        Err("signer session already joined".into())
    }
    fn send(&self, channel: &FrostdChannel, to: &[Peer], message: &Outbound) -> Result<(), String> {
        if let Outbound::Candidate(candidate) = message {
            bind_approved_candidate(self.data, self.pass, candidate.as_bytes(), self.payment, self.vault)?;
        }
        self.inner
            .send(channel, to, message)
            .map_err(|e| e.to_string())
    }
    fn recv(&self, channel: &FrostdChannel, as_coordinator: bool) -> Result<Vec<Incoming>, String> {
        let messages = self
            .inner
            .recv(channel, as_coordinator)
            .map_err(|e| e.to_string())?;
        for incoming in &messages {
            if pczt::Pczt::parse(&incoming.message).is_ok() {
                if incoming.from != self.vault.peers[&self.payment.proposer] { return Err("candidate from a non-proposer".into()); }
                bind_approved_candidate(self.data, self.pass, &incoming.message, self.payment, self.vault)?;
            } else if Some(incoming.from.0) != self.payment.coordinator.as_ref().map(|c| c.encryption) {
                return Err("signing message from a non-coordinator".into());
            }
        }
        Ok(messages)
    }
    fn close(&self, channel: FrostdChannel) -> Result<(), String> {
        self.inner.close(channel).map_err(|e| e.to_string())
    }
}

fn review_candidate(bytes: &[u8], payment: &Payment, vault: &Vault) -> Result<(), String> {
    let parsed = pczt::Pczt::parse(bytes).map_err(|e| format!("candidate: {e:?}"))?;
    crate::verify::check_pools_and_version(&parsed).map_err(|e| e.to_string())?;
    if *parsed.global().consensus_branch_id()
        != u32::from(BranchId::for_height(
            &vault.network,
            BlockHeight::from_u32(payment.target_height),
        ))
        || *parsed.global().expiry_height() != payment.expiry_height
    {
        return Err("candidate network or expiry differs from reviewed intent".into());
    }
    let recipient =
        vault::orchard_receiver_from_ua(&payment.recipient, vault.network.network_type())?;
    let expected = Expectations {
        input_nullifiers: payment
            .note_selection
            .iter()
            .map(|s| hex32(s))
            .collect::<Result<_, _>>()?,
        recipient: recipient.to_raw_address_bytes(),
        amount_zat: payment.amount_zat,
        memo: payment.memo.as_bytes().to_vec(),
        change_zat: payment.change_zat,
        fee_zat: payment.fee_zat,
        expiry_height: payment.expiry_height,
    };
    pczt::roles::verifier::Verifier::new(parsed)
        .with_ironwood::<Refusal, _>(|bundle| {
            check_candidate(bundle, &vault.fvk, &expected)
                .map_err(pczt::roles::verifier::OrchardError::Custom)
        })
        .map_err(|e| format!("candidate differs from reviewed intent: {e:?}"))?;
    crate::signer::wysiwys::sighash_of_pczt(bytes, &vault.fvk)?;
    Ok(())
}
fn check_intent(p: &Payment, v: &Vault) -> Result<(), String> {
    if p.signers.len() > usize::from(v.threshold)
        || (!p.open_approval && p.signers.len() != usize::from(v.threshold))
        || p.signers.first() != Some(&p.proposer)
        || (!p.open_approval && !p.signers.contains(&v.slot))
        || p.signers.iter().any(|s| !v.peers.contains_key(s))
        || p.signers
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != p.signers.len()
        || p.note_selection.is_empty()
        || p.amount_zat == 0
        || p.expiry_height <= p.target_height
    {
        return Err("invalid payment intent".into());
    }
    vault::orchard_receiver_from_ua(&p.recipient, v.network.network_type())?;
    MemoBytes::from_bytes(p.memo.as_bytes()).map_err(|e| format!("memo: {e:?}"))?;
    Zatoshis::from_u64(p.amount_zat).map_err(|e| format!("amount: {e:?}"))?;
    Zatoshis::from_u64(p.change_zat).map_err(|e| format!("change: {e:?}"))?;
    for nullifier in &p.note_selection {
        hex32(nullifier)?;
    }
    Ok(())
}
// Bind authorization to the reviewed effects and relay session, excluding only the growing quorum.
fn approval_intent(p: &Payment) -> Value {
    let mut intent = public_intent(p);
    intent.as_object_mut().unwrap().remove("signers");
    intent.as_object_mut().unwrap().remove("phase");
    intent
}

fn accept_approval(p: &mut Payment, slot: u16, threshold: u16) -> Result<(), String> {
    if !p.open_approval { return Err("payment has a fixed signing quorum".into()); }
    if p.signers.contains(&slot) { return Ok(()); }
    if p.phase != "signing" || p.session_id.is_none() { return Err("payment is not signing".into()); }
    // The caller holds the payment lock; retries are idempotent and a full quorum never changes.
    if p.signers.len() < usize::from(threshold) { p.signers.push(slot); }
    Ok(())
}

fn public_intent(p: &Payment) -> Value {
    json!({"attempt":p.attempt,"vault":p.vault,"proposer":p.proposer,"recipient":p.recipient,"amount_zat":p.amount_zat,"memo":p.memo,"fee_zat":p.fee_zat,"change_zat":p.change_zat,"note_selection":p.note_selection,"target_height":p.target_height,"expiry_height":p.expiry_height,"signers":p.signers,"open_approval":p.open_approval,"phase":p.phase,"session_id":p.session_id,"coordinator":p.coordinator})
}
// Process tokens stay local. Peers prove roster membership with the same signed
// recipient box as the relay, and receive only encrypted, request-bound responses.
fn peer_context(vault: &str) -> Result<[u8; 32], String> {
    let mut hash = blake3::Hasher::new_derive_key("Loki payment peer HTTP v1");
    hash.update(&hex32(vault)?);
    Ok(hash.finalize().into())
}
fn peer_read(config: &super::Config, vault: &str, attempt: Option<&str>, v: &Vault, slot: u16) -> Result<Value, String> {
    peer_request(config, vault, attempt, v, slot, None)
}
fn peer_request(config: &super::Config, vault: &str, attempt: Option<&str>, v: &Vault, slot: u16, approval: Option<&Payment>) -> Result<Value, String> {
    let peer = v.roster.get(&slot).ok_or("peer outside vault roster")?;
    let url = v.base_urls.get(&slot).ok_or("missing member URL in vault roster; legacy vault needs URL migration")?;
    config.validate_peer_url(url)?;
    let context = peer_context(vault)?;
    let request = Uuid::new_v4().to_string();
    let body = serde_json::to_vec(&json!({"request":request,"attempt":attempt,"approve":approval.map(approval_intent)})).map_err(|e| e.to_string())?;
    let wire = v.identity.seal_payment(peer, &context, &body)?;
    let rt = runtime()?;
    let response: Value = rt.block_on(async {
        let response = reqwest::Client::builder()
            .timeout(Duration::from_secs(10)).redirect(reqwest::redirect::Policy::none()).build().map_err(|e| e.to_string())?
            .post(format!("{url}/api/payment-peer"))
            .json(&json!({"vault":vault,"sender":v.slot,"body":hex::encode(wire)}))
            .send().await.map_err(|e| e.to_string())?;
        if !response.status().is_success() { return Err("payment peer unavailable".into()); }
        response.json().await.map_err(|e| e.to_string())
    })?;
    let wire = hex::decode(required(&response, "body")?).map_err(|e| e.to_string())?;
    let body = Zeroizing::new(v.identity.open_payment(peer, &context, &wire)?);
    let response: Value = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
    if response["request"].as_str() != Some(request.as_str()) { return Err("payment peer response mismatch".into()); }
    Ok(response["response"].clone())
}

fn session_view(p: &Payment) -> Result<Value, String> {
    let id = p.session_id.ok_or("payment session pending")?;
    let mut view = finalization_view(p);
    view["session_id"] = json!(id);
    view["intent"] = public_intent(p);
    view["approval_started"] = json!(p.approval_started);
    view["signatures_received"] = json!(p.signed_pczt.is_some() || p.approval_complete || matches!(p.phase.as_str(), "broadcast" | "confirmed"));
    Ok(view)
}

/// Peer reads and approval admission verify a signed recipient envelope against the sealed
/// vault roster. The response is encrypted to that member.
pub(super) async fn peer_session(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    with_body(st, body, |st, data, pass, body| {
        let vault = required(&body, "vault")?;
        let v = load_vault(&data, &pass, vault, &st.config)?;
        let slot: u16 = body["sender"].as_u64().ok_or("missing sender")?
            .try_into().map_err(|_| "invalid sender")?;
        let peer = v.roster.get(&slot).ok_or("sender outside vault roster")?;
        let context = peer_context(vault)?;
        let wire = hex::decode(required(&body, "body")?).map_err(|e| e.to_string())?;
        let plain = Zeroizing::new(v.identity.open_payment(peer, &context, &wire)?);
        let request: Value = serde_json::from_slice(&plain).map_err(|e| e.to_string())?;
        let nonce = required(&request, "request")?;
        Uuid::parse_str(nonce).map_err(|e| e.to_string())?;
        let response = if let Some(attempt) = request["attempt"].as_str() {
            let _guard = if request["approve"].is_null() { None } else {
                Some(st.payment.lock().map_err(|e| e.to_string())?)
            };
            let mut p = read_payment(&data, &pass, vault, attempt)?;
            if !request["approve"].is_null() {
                if p.proposer != v.slot || request["approve"] != approval_intent(&p) {
                    return Err("approval differs from proposer intent".into());
                }
                accept_approval(&mut p, slot, v.threshold)?;
                save_payment(&data, &pass, &p)?;
            }
            if !p.open_approval && !p.signers.contains(&slot) { return Err("sender outside payment quorum".into()); }
            session_view(&p)?
        } else {
            proposed_view(&data, &pass, vault, Some(slot))?
        };
        let plain = Zeroizing::new(serde_json::to_vec(&json!({"request":nonce,"response":response})).map_err(|e| e.to_string())?);
        let wire = v.identity.seal_payment(peer, &context, &plain)?;
        Ok(json!({"body":hex::encode(wire)}))
    }).await
}

fn payment_encryption(identity: &Identity, p: &Payment, v: &Vault) -> Result<PaymentEncryption, String> {
    let coordinator = p.coordinator.clone().ok_or("missing authenticated payment coordinator")?;
    if coordinator.id != 0 { return Err("invalid payment coordinator".into()); }
    let mut members = p.signers.iter().map(|id| {
        v.roster.get(id).cloned().map(|member| (*id, member)).ok_or("signer outside roster")
    }).collect::<Result<BTreeMap<_, _>, _>>()?;
    members.insert(0, coordinator);
    PaymentEncryption::new(identity, members, &hex32(&p.vault)?, &hex32(&p.attempt)?,
        p.session_id.ok_or("missing payment session")?).map_err(|e| e.to_string())
}

fn ready_to_send(st: &Shared, p: &Payment, v: &Vault) -> bool {
    matches!(p.phase.as_str(), "signing" | "approved")
        && p.proposer == v.slot
        && p.signers.len() == usize::from(v.threshold)
        && p.approval_requested
        && p.signers.iter().all(|slot| {
            if *slot == v.slot {
                p.approval_started
            } else {
                peer_read(&st.config, &p.vault, Some(&p.attempt), v, *slot).ok()
                    .and_then(|r| r["approval_started"].as_bool())
                    .unwrap_or(false)
            }
        })
}
fn discover(
    st: &Shared,
    data: &Path,
    pass: &str,
    vault: &str,
    attempt: &str,
    v: &Vault,
) -> Result<Payment, String> {
    if let Ok(p) = read_payment(data, pass, vault, attempt) {
        return Ok(p);
    }
    for &slot in v.roster.keys() {
        if slot == v.slot {
            continue;
        }
        let Ok(response) = peer_read(&st.config, vault, Some(attempt), v, slot) else {
            continue;
        };
        let mut p: Payment =
            serde_json::from_value(response["intent"].clone()).map_err(|e| e.to_string())?;
        if p.vault != vault
            || p.attempt != attempt
            || p.proposer != slot
            || p.session_id
                != response["session_id"]
                    .as_str()
                    .and_then(|s| Uuid::parse_str(s).ok())
        {
            continue;
        }
        check_intent(&p, v)?;
        p.coordinator_secret = None;
        p.review_token = None;
        p.approval_requested = false;
        p.approval_started = false;
        p.approval_complete = false;
        p.txid = None;
        p.signed_pczt = None;
        p.raw_tx = None;
        p.error = None;
        save_payment(data, pass, &p)?;
        return Ok(p);
    }
    Err("payment session unavailable".into())
}
async fn unlocked(st: &Shared) -> Result<(PathBuf, Zeroizing<String>), Reply> {
    let guard = st.session.read().await;
    let s = guard
        .as_ref()
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "profile is locked"))?;
    Ok((s.data.clone(), s.passphrase.clone()))
}
async fn with_body(
    st: Shared,
    body: Value,
    f: impl FnOnce(Shared, PathBuf, Zeroizing<String>, Value) -> Result<Value, String> + Send + 'static,
) -> Reply {
    let (data, pass) = match unlocked(&st).await {
        Ok(x) => x,
        Err(e) => return e,
    };
    blocking(move || f(st, data, pass, body)).await
}
fn url(st: &Shared) -> Result<&str, String> {
    st.config
        .lightwalletd
        .as_deref()
        .ok_or("lightwalletd URL is required".into())
}

pub(super) async fn balance(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    with_body(st, body, |st, data, pass, body| {
        let vault = required(&body, "vault")?;
        let v = load_vault(&data, &pass, vault, &st.config)?;
        let (w, _, _) = wallet(&data, &pass, vault, &v, url(&st)?)?;
        Ok(json!({"balance_zat": w.ironwood_balance_zat()?}))
    })
    .await
}

pub(super) async fn draft(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    with_body(st, body, |st, data, pass, body| {
        let vault = required(&body, "vault")?;
        let v = load_vault(&data, &pass, vault, &st.config)?;
        let recipient = required(&body, "recipient")?;
        let address = vault::orchard_receiver_from_ua(recipient, v.network.network_type())?;
        let amount_zat: u64 = required(&body, "amount_zat")?.parse().map_err(|_| "invalid amount_zat")?;
        if amount_zat == 0 { return Err("amount must exceed zero".into()); }
        let amount = Zatoshis::from_u64(amount_zat).map_err(|e| format!("amount: {e:?}"))?;
        let memo = body["memo"].as_str().unwrap_or("");
        let memo_bytes = MemoBytes::from_bytes(memo.as_bytes()).map_err(|e| format!("memo: {e:?}"))?;
        let (mut w, _, _) = wallet(&data, &pass, vault, &v, url(&st)?)?;
        let tip = w.scanned_height()?.ok_or("wallet has no scanned blocks")?;
        let expiry = tip.checked_add(match v.network { VaultNetwork::Regtest => 8_064, VaultNetwork::Testnet => 24_192 }).ok_or("expiry overflow")?.div_ceil(1_152).checked_mul(1_152).ok_or("expiry overflow")?;
        // The wallet's own coin selection picks exactly the notes that cover amount + fee (one
        // or several). Spend that whole set — one signing lane per note downstream.
        let funding = match w.propose(address, Some(amount), memo_bytes.clone()) {
            Ok(f) => f,
            // Distinguish "not synced/confirmed yet" from "genuinely no funds": the overview may
            // already show a balance that this draft can't spend until its block is synced.
            Err(e) if e.contains("Insufficient balance") => {
                let total = w.ironwood_balance_zat().unwrap_or(0);
                let taz = total as f64 / 100_000_000.0;
                return Err(if total >= amount_zat {
                    format!("funds are still syncing — {taz} TAZ detected but not spendable yet; try again in a moment")
                } else {
                    format!("not enough funds — this vault holds {taz} TAZ; fund its address and let it sync")
                });
            }
            Err(e) => return Err(e),
        };
        let notes = funding.notes.clone();
        if notes.is_empty() { return Err("wallet proposed no Ironwood notes".into()); }
        let inputs = CandidateInputs { vault_fvk: &v.fvk, notes: notes.clone(), recipient: address, amount, memo: memo_bytes, change: Zatoshis::ZERO, target_height: tip, expiry_height: expiry };
        let fee_zat: u64 = quote_fee(&v.network, &inputs)?.into();
        let spend: u64 = notes.iter().map(|note| note.value().inner()).sum();
        let change_zat = spend.checked_sub(amount_zat).and_then(|n| n.checked_sub(fee_zat)).ok_or("selected notes cannot cover amount and fee")?;
        // Cross-check against the wallet's own fee/change so the reviewed intent matches the candidate.
        if funding.fee_zat != fee_zat || funding.change_zat != change_zat { return Err("wallet funding differs from candidate fee or change".into()); }
        let mut random = [0u8; 32]; OsRng.fill_bytes(&mut random);
        let attempt = hex::encode(random);
        let signers = vec![v.slot];
        if v.base_urls.len() < usize::from(v.threshold) { return Err("not enough signer URLs in vault roster; legacy vault needs URL migration".into()); }
        let note_selection: Vec<String> = notes.iter().map(|n| hex::encode(n.nullifier(&v.fvk).to_bytes())).collect();
        let p = Payment { attempt: attempt.clone(), vault: vault.to_owned(), proposer: v.slot, recipient: recipient.to_owned(), amount_zat, memo: memo.to_owned(), fee_zat, change_zat, note_selection, target_height: tip, expiry_height: expiry, signers, open_approval: true, phase: "draft".into(), session_id: None, coordinator_secret: None, coordinator: None, review_token: None, approval_requested: false, approval_started: false, approval_complete: false, finish_requested: false, txid: None, signed_pczt: None, raw_tx: None, error: None };
        check_intent(&p, &v)?;
        let nullifiers: Vec<[u8; 32]> = p.note_selection.iter().map(|s| hex32(s)).collect::<Result<_, _>>()?;
        w.reserve_inputs(zcash_client_backend::wallet::LockOwner::new(random), &nullifiers, expiry)?;
        if let Err(e) = save_payment(&data, &pass, &p) { let _ = w.release_inputs(zcash_client_backend::wallet::LockOwner::new(random), &nullifiers); return Err(e); }
        Ok(json!({"attempt":attempt,"fee_zat":fee_zat.to_string(),"change_zat":change_zat.to_string()}))
    }).await
}

pub(super) async fn publish(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    with_body(st, body, |st, data, pass, body| {
        let _guard = st.payment.lock().map_err(|e| e.to_string())?;
        let (vault, attempt) = pair(&body)?;
        let v = load_vault(&data, &pass, &vault, &st.config)?;
        let mut p = read_payment(&data, &pass, &vault, &attempt)?;
        if p.proposer != v.slot || p.phase != "draft" {
            return Err("only the proposer can publish a draft".into());
        }
        // An unpublished legacy draft has no nonce transcript to preserve.
        p.signers = vec![v.slot];
        p.open_approval = true;
        check_intent(&p, &v)?;
        let coord = Identity::new(0);
        let mut tx = relay(&coord, &st.config.frostd_url)?;
        let peers = v.peers.values().cloned().collect::<Vec<_>>();
        let ch = tx.open(&peers, 4).map_err(|e| e.to_string())?;
        p.session_id = Some(ch.session_id());
        p.coordinator_secret = Some(hex::encode(&*Zeroizing::new(coord.to_secret_bytes())));
        p.coordinator = Some(coord.public());
        p.phase = "signing".into();
        save_payment(&data, &pass, &p)?;
        Ok(json!({"phase":p.phase,"session_id":p.session_id}))
    })
    .await
}

pub(super) async fn session(
    State(st): State<Shared>,
    Query(query): Query<BTreeMap<String, String>>,
) -> Reply {
    let (Some(vault), Some(attempt)) = (query.get("vault"), query.get("attempt")) else {
        return err(StatusCode::BAD_REQUEST, "missing vault or attempt");
    };
    let (vault, attempt) = (vault.clone(), attempt.clone());
    let (data, pass) = match unlocked(&st).await {
        Ok(x) => x,
        Err(e) => return e,
    };
    blocking(move || {
        let p = read_payment(&data, &pass, &vault, &attempt)?;
        session_view(&p)
    }).await
}

pub(super) async fn review(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    with_body(st, body, |st, data, pass, body| {
        let _guard = st.payment.lock().map_err(|e| e.to_string())?;
        let (vault, attempt) = pair(&body)?;
        let v = load_vault(&data, &pass, &vault, &st.config)?;
        let mut p = discover(&st, &data, &pass, &vault, &attempt, &v)?;
        if p.phase != "signing" || p.session_id.is_none() { return Err("payment is not signing".into()); }
        check_intent(&p, &v)?;
        if p.approval_requested { return Err("payment approval already requested".into()); }
        if p.review_token.is_none() {
            let mut token = [0u8; 32]; OsRng.fill_bytes(&mut token);
            p.review_token = Some(hex::encode(token));
            save_payment(&data, &pass, &p)?;
        }
        Ok(json!({"review_token":p.review_token,"recipient":p.recipient,"amount_zat":p.amount_zat.to_string(),"fee_zat":p.fee_zat.to_string(),"change_zat":p.change_zat.to_string(),"memo":p.memo}))
    }).await
}

pub(super) async fn approve(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    let (data, pass) = match unlocked(&st).await {
        Ok(x) => x,
        Err(e) => return e,
    };
    let work_st = st.clone();
    let reply = blocking(move || {
        let _guard = work_st.payment.lock().map_err(|e| e.to_string())?;
        let (vault, attempt) = pair(&body)?;
        let mut p = read_payment(&data, &pass, &vault, &attempt)?;
        if p.phase != "signing"
            || p.approval_requested
            || p.review_token.is_none()
            || p.review_token.as_deref() != body["review_token"].as_str()
        {
            return Err("invalid or repeated payment approval".into());
        }
        let v = load_vault(&data, &pass, &vault, &work_st.config)?;
        check_intent(&p, &v)?;
        record_approval(&data, &pass, &p)?;
        p.approval_requested = true;
        save_payment(&data, &pass, &p)?;
        drop(_guard);
        spawn_signing(work_st.clone(), data, pass, vault, attempt);
        Ok(json!({"phase":"signing"}))
    })
    .await;
    reply
}
fn record_approval(data: &Path, pass: &str, p: &Payment) -> Result<(), String> {
    let dir = payment_dir(data, &p.vault)?;
    let file = format!("{}.consent", p.attempt);
    let intent = serde_json::to_vec(&approval_intent(p)).map_err(|e| e.to_string())?;
    if !dir.exists(&file) {
        dir.write_sealed(&file, &intent, pass).map_err(|e| e.to_string())?;
    }
    require_approval(data, pass, p)
}

fn require_approval(data: &Path, pass: &str, p: &Payment) -> Result<(), String> {
    let raw = payment_dir(data, &p.vault)?.read_sealed(&format!("{}.consent", p.attempt), pass)
        .map_err(|_| "no recorded member consent for this attempt")?;
    let intent: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    if intent != approval_intent(p) { return Err("payment differs from recorded member consent".into()); }
    Ok(())
}

fn bind_approved_candidate(data: &Path, pass: &str, bytes: &[u8], p: &Payment, v: &Vault) -> Result<(), String> {
    require_approval(data, pass, p)?;
    review_candidate(bytes, p, v)?;
    let sighash = crate::signer::wysiwys::sighash_of_pczt(bytes, &v.fvk)?;
    let dir = payment_dir(data, &p.vault)?;
    let file = format!("{}.consent-sighash", p.attempt);
    if !dir.exists(&file) {
        dir.write_sealed(&file, &sighash, pass).map_err(|e| e.to_string())?;
    }
    if dir.read_sealed(&file, pass).map_err(|e| e.to_string())? != sighash {
        return Err("candidate differs from the approved sighash; start a new attempt".into());
    }
    Ok(())
}

fn payment_approval(data: PathBuf, pass: Zeroizing<String>, payment: Payment) -> crate::signer::local::ApprovalPolicy {
    Box::new(move |request| {
        let approved = || -> Result<bool, String> {
            require_approval(&data, &pass, &payment)?;
            let attempt = hex32(&payment.attempt)?;
            let candidate = CandidateRef { vault_id: hex32(&payment.vault)?, payment_id: attempt, attempt_id: attempt };
            // Each input lane has its own nonce id, but signs the same approved candidate.
            if !(0..payment.note_selection.len()).any(|lane| crate::payment_transport::lane_cand(&candidate, lane) == *request.candidate) {
                return Ok(false);
            }
            let hash = payment_dir(&data, &payment.vault)?.read_sealed(&format!("{}.consent-sighash", payment.attempt), &pass)
                .map_err(|e| e.to_string())?;
            Ok(hash == request.sighash)
        };
        approved().unwrap_or(false)
    })
}

fn open_payment_nonces(
    config: &super::Config, data: &Path, pass: &str, vault: &str, epoch: u64,
) -> Result<(super::state::HostedSecureElement, crate::signer::nonce::NonceStore), String> {
    let sdir = super::ceremony::signer_dir(data, vault)?;
    let store = crate::signer::store::SignerStore::open(&sdir)?;
    let se = config.open_secure_element(&sdir, pass)?;
    let (share_epoch, _) = store.read(&se, crate::signer::store::FileKind::Share)?
        .ok_or("missing secure-element share; restore from recovery backup")?;
    if store.vault() != hex32(vault)? || share_epoch != epoch {
        return Err("nonce store and secure-element share differ; reload the vault".into());
    }
    // Nonces belong beside the device share/KEK, never in the host's payment state or backups.
    let nonces = crate::signer::nonce::NonceStore::open_at_epoch(&store.nonce_dir(), share_epoch).map_err(|e| e.to_string())?;
    Ok((se, nonces))
}

fn sign(st: &Shared, data: &Path, pass: &str, p: &Payment, v: &Vault) -> Result<(), String> {
    if p.signers.len() != usize::from(v.threshold) || !p.signers.contains(&v.slot) {
        return Err("signing quorum is not ready".into());
    }
    let witness = super::nonce_witness::RelayWitness::open(
        st.config.nonce_witnesses.as_deref(), st.config.development_http,
    )?;
    let mut tx = relay(&v.identity, &st.config.frostd_url)?;
    tx.encrypt_payments(payment_encryption(&v.identity, p, v)?).map_err(|e| e.to_string())?;
    let ch = tx
        .join(p.session_id.ok_or("missing signing session")?)
        .map_err(|e| e.to_string())?;
    let mut owned = None;
    if p.proposer == v.slot {
        let (w, mut client, rt) = wallet(data, pass, &p.vault, v, url(st)?)?;
        // Select the candidate's input notes at its fixed draft height (target_height), so the
        // proposer rebuilds the same candidate the quorum reviewed; the witness here is unused.
        let height = p.target_height;
        let (frontier, _) = frontier(&w, &mut client, &rt, height)?;
        let selected: Vec<[u8; 32]> =
            p.note_selection.iter().map(|s| hex32(s)).collect::<Result<_, _>>()?;
        let notes = w
            .ironwood_inputs_at(BlockHeight::from_u32(height), frontier, &selected)?
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        let recipient = vault::orchard_receiver_from_ua(&p.recipient, v.network.network_type())?;
        owned = Some(CandidateInputs {
            vault_fvk: &v.fvk,
            notes,
            recipient,
            amount: Zatoshis::from_u64(p.amount_zat).map_err(|e| format!("amount: {e:?}"))?,
            memo: MemoBytes::from_bytes(p.memo.as_bytes()).map_err(|e| format!("memo: {e:?}"))?,
            change: Zatoshis::from_u64(p.change_zat).map_err(|e| format!("change: {e:?}"))?,
            target_height: p.target_height,
            expiry_height: p.expiry_height,
        });
        if u64::from(quote_fee(&v.network, owned.as_ref().unwrap())?) != p.fee_zat {
            return Err("candidate fee differs from reviewed intent".into());
        }
    }
    let mut run = signing_run(st, data, pass, p, "signer")?;
    {
        let _guard = st.payment.lock().map_err(|e| e.to_string())?;
        let mut local = read_payment(data, pass, &p.vault, &p.attempt)?;
        local.approval_started = true;
        save_payment(data, pass, &local)?;
    }
    let reviewed = ReviewedTransport {
        inner: &tx,
        payment: p,
        vault: v,
        data,
        pass,
    };
    let signer_network = match v.network {
        VaultNetwork::Regtest => Network::Regtest,
        VaultNetwork::Testnet => Network::Testnet,
    };
    let (se, nonces) = open_payment_nonces(&st.config, data, pass, &p.vault, v.share_epoch)?;
    let mut signer = LocalSigner::from_restored(
        v.slot, v.threshold, v.peers.len() as u16, hex32(&p.vault)?,
        p.vault.clone(), signer_network, se,
        &Zeroizing::new(v.key.serialize().map_err(|e| e.to_string())?),
        v.public.serialize().map_err(|e| e.to_string())?, v.fvk.clone(),
        v.share_epoch, nonces, payment_approval(data.to_path_buf(), Zeroizing::new(pass.to_owned()), p.clone()), None,
    ).and_then(|s| s.with_nonce_witness(Box::new(witness))).map_err(|e| e.to_string())?;
    if let Some(inputs) = &owned {
        signer.set_candidate_notes(inputs.notes.clone());
    }
    let session = signer.connect("hosted payment", signer_network, p.attempt.as_bytes())
        .map_err(|e| e.to_string())?.session;
    let candidate = CandidateRef {
        vault_id: hex32(&p.vault)?, payment_id: hex32(&p.attempt)?, attempt_id: hex32(&p.attempt)?,
    };
    let params = owned.as_ref().map(|inputs| PublicPaymentParams {
        recipient: inputs.recipient, amount: inputs.amount, memo: inputs.memo.clone(),
        target_height: inputs.target_height, expiry_height: inputs.expiry_height,
    });
    let other_signers = p.signers.iter().filter(|id| **id != v.slot)
        .map(|id| v.peers[id].clone()).collect::<Vec<_>>();
    signer_loop_resumable(
        &reviewed,
        &ch,
        &mut signer, &session, &candidate, &v.public,
        frost::Identifier::try_from(v.slot).map_err(|e| e.to_string())?,
        params.as_ref(), &v.peers[&p.proposer], &other_signers,
        p.note_selection.len(), &mut run,
    )
}

fn frontier(
    w: &VaultWallet,
    client: &mut Lightwalletd,
    rt: &tokio::runtime::Runtime,
    height: u32,
) -> Result<
    (
        incrementalmerkletree::frontier::NonEmptyFrontier<orchard::tree::MerkleHashOrchard>,
        [u8; 32],
    ),
    String,
> {
    let info = rt
        .block_on(client.get_lightd_info(Empty {}))
        .map_err(|e| format!("lightwalletd info: {e}"))?
        .into_inner();
    // `height` is the candidate anchor (may be below the tip once the chain advances); only
    // fail if the node has not reached it yet. get_tree_state fetches the tree at that height.
    if info.block_height < u64::from(height) {
        return Err("lightwalletd is behind the payment anchor height".into());
    }
    let state = rt
        .block_on(client.get_tree_state(BlockId {
            height: u64::from(height),
            hash: vec![],
        }))
        .map_err(|e| format!("lightwalletd tree state: {e}"))?
        .into_inner();
    if state.network != info.chain_name
        || state.height != u64::from(height)
        || state.hash != w.scanned_hash(BlockHeight::from_u32(height))?
    {
        return Err("wallet scan is on a different chain".into());
    }
    let tree = state
        .ironwood_tree()
        .map_err(|e| format!("Ironwood tree state: {e}"))?;
    // Witnesses from `ironwood_inputs_at` root to the depth-padded commitment-tree root
    // (`tree.root()`), NOT the natural-level `frontier.root(None)`; use it as the prove anchor.
    let anchor = tree.root().to_bytes();
    let frontier = tree
        .to_frontier()
        .value()
        .cloned()
        .ok_or("scanned Ironwood tree is empty")?;
    Ok((frontier, anchor))
}

fn save_finalization(st: &Shared, data: &Path, pass: &str, p: &Payment) -> Result<(), String> {
    let _guard = st.payment.lock().map_err(|e| e.to_string())?;
    let mut local = read_payment(data, pass, &p.vault, &p.attempt)?;
    local.phase = p.phase.clone();
    local.signed_pczt = p.signed_pczt.clone();
    local.raw_tx = p.raw_tx.clone();
    local.txid = p.txid.clone();
    local.error = None;
    save_payment(data, pass, &local)
}

fn finalization_view(p: &Payment) -> Value {
    json!({"phase":p.phase,"txid":if matches!(p.phase.as_str(), "broadcast" | "confirmed") { p.txid.as_ref() } else { None },
        "finish_requested":p.finish_requested,"error":p.error})
}

pub(super) async fn finish(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    with_body(st, body, |st, data, pass, body| {
        let (vault, attempt) = pair(&body)?;
        let v = load_vault(&data, &pass, &vault, &st.config)?;
        let guard = st.payment.lock().map_err(|e| e.to_string())?;
        let mut p = read_payment(&data, &pass, &vault, &attempt)?;
        if p.proposer != v.slot {
            return Err("only the proposer can finish a signing payment".into());
        }
        check_intent(&p, &v)?;
        if matches!(p.phase.as_str(), "broadcast" | "confirmed") { return Ok(finalization_view(&p)); }
        if !matches!(p.phase.as_str(), "signing" | "approved") { return Err("payment is not signing".into()); }
        if !p.finish_requested && p.signed_pczt.is_none()
            && (p.signers.len() != usize::from(v.threshold) || !p.approval_requested || !p.approval_started)
        {
            return Err("signer approvals are not ready".into());
        }
        p.finish_requested = true;
        save_payment(&data, &pass, &p)?;
        drop(guard);
        spawn_finalization(st, data, pass, vault, attempt);
        Ok(finalization_view(&p))
    }).await
}

fn spawn_finalization(st: Shared, data: PathBuf, pass: Zeroizing<String>, vault: String, attempt: String) {
    tokio::task::spawn_blocking(move || {
        if let Err(error) = run_finalization(st, data, pass, vault, attempt) {
            eprintln!("payment finalization: {error}");
        }
    });
}

fn run_finalization(st: Shared, data: PathBuf, pass: Zeroizing<String>, vault: String, attempt: String) -> Result<(), String> {
    let Some(_runner) = claim_payment(&st, &vault, &attempt, "coordinator")? else { return Ok(()) };
    let outcome = (|| -> Result<Value, String> {
        let mut p = {
            let _guard = st.payment.lock().map_err(|e| e.to_string())?;
            let mut p = read_payment(&data, &pass, &vault, &attempt)?;
            // An old coordinator checkpoint proves finish was requested before this field existed.
            if !p.finish_requested && finalization_pending(&data, &p) {
                p.finish_requested = true;
                save_payment(&data, &pass, &p)?;
            }
            p
        };
        if !matches!(p.phase.as_str(), "signing" | "approved") || !p.finish_requested { return Ok(finalization_view(&p)); }
        let v = load_vault(&data, &pass, &vault, &st.config)?;
        if p.proposer != v.slot { return Err("only the proposer can finish a signing payment".into()); }
        check_intent(&p, &v)?;
        if p.signed_pczt.is_none()
            && !payment_dir(&data, &vault)?.exists(&format!("{attempt}.coordinator.sealed"))
            && !ready_to_send(&st, &p, &v)
        { return Ok(finalization_view(&p)); }
        if p.signed_pczt.is_none() {
            let coord = Identity::from_secret_bytes(
                &hex::decode(
                    p.coordinator_secret
                        .as_deref()
                        .ok_or("missing coordinator identity")?,
                )
                .map_err(|e| e.to_string())?,
            )?;
            let mut tx = relay(&coord, &st.config.frostd_url)?;
            tx.encrypt_payments(payment_encryption(&coord, &p, &v)?).map_err(|e| e.to_string())?;
            let ch = tx
                .join(p.session_id.ok_or("missing signing session")?)
                .map_err(|e| e.to_string())?;
            let ids = p
                .signers
                .iter()
                .map(|id| frost::Identifier::try_from(*id).map_err(|e| e.to_string()))
                .collect::<Result<Vec<_>, _>>()?;
            let peer_of = p
                .signers
                .iter()
                .zip(&ids)
                .map(|(slot, id)| (*id, v.peers[slot].clone()))
                .collect();
            let signed = {
                let mut run = signing_run(&st, &data, &pass, &p, "coordinator")?;
                coordinate_resumable(&tx, &ch, &v.public, &ids, &peer_of, v.threshold, p.note_selection.len(), OsRng, &mut run)?
            };
            p.signed_pczt = Some(hex::encode(signed));
            save_finalization(&st, &data, &pass, &p)?;
            let _ = tx.close(ch);
        }
        let (mut w, mut client, rt) = wallet(&data, &pass, &vault, &v, url(&st)?)?;
        if p.raw_tx.is_none() {
            let signed = hex::decode(p.signed_pczt.as_deref().ok_or("missing signed PCZT")?)
                .map_err(|e| e.to_string())?;
            let pczt = pczt::Pczt::parse(&signed).map_err(|e| format!("signed PCZT: {e:?}"))?;
            let sighash = pczt::roles::signer::Signer::new(pczt.clone())
                .map_err(|e| format!("sighash: {e:?}"))?
                .shielded_sighash();
            // Anchor and witness are installed here (deferred at candidate build). Both come
            // from the tree at target_height so the witness roots to the anchor; the signed
            // sighash is anchor-independent, so the height need only hold the unspent note.
            let height = p.target_height;
            let (tree, anchor) = frontier(&w, &mut client, &rt, height)?;
            let selected: Vec<[u8; 32]> =
                p.note_selection.iter().map(|s| hex32(s)).collect::<Result<_, _>>()?;
            let inputs = w.ironwood_inputs_at(BlockHeight::from_u32(height), tree, &selected)?;
            if inputs.len() != selected.len() {
                return Err("missing one or more payment notes".into());
            }
            // Pair each note's witness with its spend's position in the signed candidate.
            let mut index_witness = Vec::with_capacity(inputs.len());
            for (note, witness) in inputs {
                let nf = note.nullifier(&v.fvk).to_bytes();
                let index = pczt
                    .ironwood()
                    .actions()
                    .iter()
                    .position(|a| a.spend().nullifier() == &nf)
                    .ok_or("signed candidate spends a different note")?;
                index_witness.push((index, witness));
            }
            let (raw, txid) = prove(pczt, sighash, index_witness, anchor)?;
            let owner = zcash_client_backend::wallet::LockOwner::new(hex32(&p.attempt)?);
            w.release_inputs(owner, &selected)?;
            w.reserve_inputs(txid.into(), &selected, p.expiry_height)?;
            p.raw_tx = Some(hex::encode(raw));
            p.txid = Some(txid.to_string());
            save_finalization(&st, &data, &pass, &p)?;
        }
        let raw = hex::decode(p.raw_tx.as_deref().ok_or("missing raw transaction")?)
            .map_err(|e| e.to_string())?;
        // shortcut: an ambiguous send error keeps the raw transaction for retry; add mempool reconciliation before reporting duplicate broadcasts as failures.
        let tip = rt.block_on(client.get_latest_block(ChainSpec {}))
            .map_err(|e| format!("broadcast expiry height: {e}"))?.into_inner().height;
        if tip >= u64::from(p.expiry_height) { return Err("payment expired".into()); }
        let sent = rt
            .block_on(client.send_transaction(RawTransaction {
                data: raw,
                height: 0,
            }))
            .map_err(|e| format!("lightwalletd send transaction: {e}"))?
            .into_inner();
        if sent.error_code != 0 {
            return Err(format!(
                "lightwalletd rejected transaction ({}): {}",
                sent.error_code, sent.error_message
            ));
        }
        p.phase = "broadcast".into();
        p.signed_pczt = None;
        p.raw_tx = None;
        save_finalization(&st, &data, &pass, &p)?;
        Ok(json!({"phase":"broadcast","txid":p.txid}))
    })();
    if let Err(error) = outcome {
        if error == DRIVE_YIELDED { return Ok(()); }
        let _guard = st.payment.lock().map_err(|e| e.to_string())?;
        let mut p = read_payment(&data, &pass, &vault, &attempt)?;
        if matches!(p.phase.as_str(), "signing" | "approved") {
            if error == "payment expired" || error == "signing window expired" { p.phase = "expired".into(); }
            p.error = Some(error.clone());
            save_payment(&data, &pass, &p)?;
        }
        return Err(error);
    }
    Ok(())
}

pub(super) async fn verify(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    with_body(st, body, |st, data, pass, body| {
        let (vault, attempt) = pair(&body)?;
        let v = load_vault(&data, &pass, &vault, &st.config)?;
        let mut p = read_payment(&data, &pass, &vault, &attempt)?;
        let txid = required(&body, "txid")?;
        if p.txid.as_deref() != Some(txid) {
            return Err("txid differs from broadcast payment".into());
        }
        let id = zcash_primitives::transaction::TxId::from_hex(txid).ok_or("invalid txid")?;
        let (w, _, _) = wallet(&data, &pass, &vault, &v, url(&st)?)?;
        p.phase = if w.mined_height(id)?.is_some() {
            "confirmed"
        } else {
            "broadcast"
        }
        .into();
        save_payment(&data, &pass, &p)?;
        Ok(json!({"phase":p.phase}))
    })
    .await
}

fn history_view(history: &[crate::wallet_store::WalletTransaction], local: Vec<(Payment, bool)>) -> Value {
    // Match each sent chain tx back to the local payment that produced it (same txid, or a shared
    // input nullifier), so history can show the amount the user actually sent + recipient + fee
    // instead of the net balance change — which, for a self-send, is only the fee.
    let origin = |tx: &crate::wallet_store::WalletTransaction| local.iter().find(|(p, _)| {
        p.txid.as_ref() == Some(&tx.txid) || p.note_selection.iter().any(|nf| tx.spent_nullifiers.contains(nf))
    }).map(|(p, _)| p);
    let mut out: Vec<Value> = history.iter().map(|tx| {
        let sent = if tx.received { None } else { origin(tx) };
        json!({
            "attempt":tx.txid,"phase":if tx.mined_height.is_some() { "confirmed" } else { "broadcast" },
            "recipient":sent.map(|p| p.recipient.clone()).unwrap_or_else(|| tx.recipient.clone()),
            "amount_zat":sent.map(|p| p.amount_zat).unwrap_or(tx.amount_zat).to_string(),"ready_to_send":false,
            "txid":tx.txid,"signers":[],"direction":if tx.received { "received" } else { "sent" },
            "amount_is_net":if sent.is_some() { false } else { tx.amount_is_net },
            "fee_zat":sent.map(|p| p.fee_zat.to_string()),"mined_height":tx.mined_height
        })
    }).collect();
    for (p, ready) in local {
        if history.iter().any(|tx| p.txid.as_ref() == Some(&tx.txid)
            || p.note_selection.iter().any(|nf| tx.spent_nullifiers.contains(nf))) {
            continue;
        }
        if matches!(p.phase.as_str(), "broadcast" | "confirmed") { continue; }
        out.push(json!({"attempt":p.attempt,"phase":p.phase,"recipient":p.recipient,"amount_zat":p.amount_zat.to_string(),"ready_to_send":ready,"txid":Value::Null,"signers":p.signers,"finish_requested":p.finish_requested,"error":p.error}));
    }
    json!({"payments":out})
}

pub(super) async fn payments(
    State(st): State<Shared>,
    Query(query): Query<BTreeMap<String, String>>,
) -> Reply {
    let Some(vault) = query.get("vault") else {
        return err(StatusCode::BAD_REQUEST, "missing vault");
    };
    let vault = vault.clone();
    let (data, pass) = match unlocked(&st).await {
        Ok(x) => x,
        Err(e) => return e,
    };
    blocking(move || {
        let v = load_vault(&data, &pass, &vault, &st.config)?;
        let (mut w, mut client, rt) = wallet(&data, &pass, &vault, &v, url(&st)?)?;
        let mempool = rt.block_on(w.scan_mempool(&mut client))?;
        let history: Vec<_> = w.transaction_history()?.into_iter()
            .filter(|tx| tx.mined_height.is_some() || mempool.contains(&tx.txid)).collect();
        let dir = payment_dir(&data, &vault)?;
        let mut local = Vec::new();
        for entry in std::fs::read_dir(dir.path()).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(attempt) = name.strip_suffix(".json") else { continue };
            if hex32(attempt).is_err() { continue; }
            let p = read_payment(&data, &pass, &vault, attempt)?;
            let ready = ready_to_send(&st, &p, &v);
            local.push((p, ready));
        }
        Ok(history_view(&history, local))
    }).await
}

fn proposed_view(data: &Path, pass: &str, vault: &str, member: Option<u16>) -> Result<Value, String> {
    let dir = payment_dir(data, vault)?;
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir.path()).map_err(|e| e.to_string())? {
        let name = entry.map_err(|e| e.to_string())?.file_name().to_string_lossy().into_owned();
        let Some(attempt) = name.strip_suffix(".json") else { continue };
        if hex32(attempt).is_err() { continue; }
        let p = read_payment(data, pass, vault, attempt)?;
        if p.phase == "signing" && member.is_none_or(|id| p.open_approval || p.signers.contains(&id)) {
            out.push(json!({"attempt":p.attempt,"proposer":p.proposer,"amount_zat":p.amount_zat.to_string(),"recipient":p.recipient,"signers":p.signers,"open_approval":p.open_approval}));
        }
    }
    Ok(json!({"proposed":out}))
}

/// Local payment discovery requires the process token; peers use encrypted reads.
pub(super) async fn proposed(
    State(st): State<Shared>, Query(query): Query<BTreeMap<String, String>>,
) -> Reply {
    let Some(vault) = query.get("vault") else { return err(StatusCode::BAD_REQUEST, "missing vault"); };
    let vault = vault.clone();
    let (data, pass) = match unlocked(&st).await { Ok(x) => x, Err(e) => return e };
    blocking(move || proposed_view(&data, &pass, &vault, None)).await
}

/// GET /api/pending?vault=X — payments awaiting THIS member's approval, discovered from peers.
/// Fans out to each vault peer's encrypted payment endpoint, keeps the signing-phase payments where
/// this member can still approve, and returns their public
/// intent so the UI can show an Approve button. Outbound only to validated URLs in this vault's roster.
pub(super) async fn pending(
    State(st): State<Shared>,
    Query(query): Query<BTreeMap<String, String>>,
) -> Reply {
    let Some(vault) = query.get("vault") else {
        return err(StatusCode::BAD_REQUEST, "missing vault");
    };
    let vault = vault.clone();
    let (data, pass) = match unlocked(&st).await {
        Ok(x) => x,
        Err(e) => return e,
    };
    blocking(move || {
        let v = load_vault(&data, &pass, &vault, &st.config)?;
        let mut out = Vec::new();
        let mut seen = std::collections::BTreeSet::new();
        for &slot in v.base_urls.keys() {
            if slot == v.slot {
                continue;
            }
            let Ok(resp) = peer_read(&st.config, &vault, None, &v, slot) else { continue };
            let Some(list) = resp["proposed"].as_array() else { continue };
            for item in list {
                let Some(attempt) = item["attempt"].as_str() else { continue };
                let signers: Vec<u16> = item["signers"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_u64().and_then(|n| u16::try_from(n).ok()))
                            .collect()
                    })
                    .unwrap_or_default();
                if item["proposer"].as_u64() != Some(u64::from(slot))
                    || (item["open_approval"] != true && !signers.contains(&v.slot))
                    || (signers.len() >= usize::from(v.threshold) && !signers.contains(&v.slot))
                    || !seen.insert(attempt.to_owned()) {
                    continue;
                }
                // Skip anything this member has already approved locally.
                if let Ok(local) = read_payment(&data, &pass, &vault, attempt) {
                    if local.approval_requested {
                        continue;
                    }
                }
                out.push(json!({"attempt":attempt,"amount_zat":item["amount_zat"],"recipient":item["recipient"],"proposer":item["proposer"]}));
            }
        }
        Ok(json!({ "pending": out }))
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use orchard::{
        keys::Scope,
        note::{RandomSeed, Rho},
        value::NoteValue,
        NoteVersion,
    };
    use pasta_curves::pallas;

    fn payment_fixture() -> Payment {
        serde_json::from_value(json!({"attempt":hex::encode([1;32]),"vault":hex::encode([2;32]),
            "proposer":1,"recipient":"test","amount_zat":1,"memo":"","fee_zat":1,
            "change_zat":0,"note_selection":[hex::encode([3;32])],"target_height":1,"expiry_height":2,
            "signers":[1],"open_approval":true,"phase":"signing","session_id":Uuid::new_v4()})).unwrap()
    }

    fn hosted_payment_fixture() -> (PathBuf, [Identity; 3], Payment) {
        let data = std::env::temp_dir().join(format!("loki-payment-approvals-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&data).unwrap();
        let root = MemberDir::create(&data, ".").unwrap();
        let identities = [Identity::new(1), Identity::new(2), Identity::new(3)];
        let mut secret = Zeroizing::new(identities[0].to_secret_bytes());
        secret[..2].copy_from_slice(&3u16.to_be_bytes());
        root.write_sealed("identity.sealed", &*secret, "pass").unwrap();
        let (shares, public) = frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, &mut OsRng).unwrap();
        let key = frost::keys::KeyPackage::try_from(shares[&frost::Identifier::try_from(1u16).unwrap()].clone()).unwrap();
        let p = payment_fixture();
        let dir = MemberDir::create(&data.join("vaults"), &p.vault).unwrap();
        let sealed = super::super::ceremony::vault_sealed_bytes(
            &p.vault, 1, 2, 3, "", &public,
            &zip2005::frost_viewing_key(&public.verifying_key().serialize().unwrap().try_into().unwrap(), &[42;32]).unwrap(),
            2, VaultNetwork::Regtest,
        ).unwrap();
        dir.write_sealed("vault.sealed", &sealed, "pass").unwrap();
        let sdir = super::super::ceremony::signer_dir(&data, &p.vault).unwrap();
        let se = test_state().config.open_secure_element(&sdir, "pass").unwrap();
        let store = crate::signer::store::SignerStore::create(&sdir, Network::Regtest, hex32(&p.vault).unwrap(), 1).unwrap();
        store.write(&se, crate::signer::store::FileKind::Share, 0,
            &crate::signer::local::encode_share(&key.serialize().unwrap(), &public.serialize().unwrap(), &[42;32])).unwrap();
        let slots: BTreeMap<_, _> = identities.iter().map(|id| {
            let id = id.public();
            (id.id, json!({"identity":{"id":id.id,"signing":hex::encode(id.signing),"encryption":hex::encode(id.encryption)}}))
        }).collect();
        dir.write_sealed("ceremony.sealed", &serde_json::to_vec(&json!({
            "vault":p.vault,"my_slot":1,"threshold":2,"slots":slots
        })).unwrap(), "pass").unwrap();
        save_payment(&data, "pass", &p).unwrap();
        (data, identities, p)
    }

    #[test]
    fn custody_nonces_live_with_the_share_and_use_its_element() {
        use crate::signer::secure_element::{SealedShare, SoftwareSecureElement};
        let (data, _, p) = hosted_payment_fixture();
        let st = test_state();
        let v = load_vault(&data, "pass", &p.vault, &st.config).unwrap();
        let sdir = super::super::ceremony::signer_dir(&data, &p.vault).unwrap();
        let (se, nonces) = open_payment_nonces(&st.config, &data, "pass", &p.vault, v.share_epoch).unwrap();
        let commitment = nonces.commit("locality", &se, v.key.signing_share()).unwrap();
        let path = data.join("vaults").join(&p.vault).join("signer/nonces/locality.nonce");
        assert!(path.is_file(), "nonce was not persisted in the device signer store");
        assert!(!member_dir(&data, &p.vault).unwrap().path().join("signer-nonces").exists());
        let sealed = SealedShare::from_bytes(&std::fs::read(&path).unwrap()).unwrap();
        let share_se = st.config.open_secure_element(&sdir, "pass").unwrap();
        assert!(sealed.open(&share_se).is_ok(), "nonce used a different SE from the share");
        assert!(sealed.open(&SoftwareSecureElement::generate()).is_err());
        drop((se, nonces));
        let (se, nonces) = open_payment_nonces(&st.config, &data, "pass", &p.vault, v.share_epoch).unwrap();
        assert_eq!(nonces.commit("locality", &se, v.key.signing_share()).unwrap(), commitment);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            for dir in [&sdir, path.parent().unwrap()] {
                assert_eq!(std::fs::metadata(dir).unwrap().permissions().mode() & 0o777, 0o700);
            }
            assert_eq!(std::fs::metadata(path).unwrap().permissions().mode() & 0o777, 0o600);
        }
        std::fs::remove_dir_all(data).unwrap();
    }

    #[test]
    fn custody_nonces_require_the_current_share_element_and_epoch() {
        let (data, _, p) = hosted_payment_fixture();
        let st = test_state();
        let sdir = super::super::ceremony::signer_dir(&data, &p.vault).unwrap();
        assert!(open_payment_nonces(&st.config, &data, "pass", &p.vault, 1).is_err(),
            "host-selected epoch overrode the share's epoch");
        std::fs::rename(sdir.join("share.sealed"), sdir.join("offline-share")).unwrap();
        assert!(open_payment_nonces(&st.config, &data, "pass", &p.vault, 0).is_err(),
            "opened nonces without the device share");
        std::fs::rename(sdir.join("offline-share"), sdir.join("share.sealed")).unwrap();
        std::fs::rename(sdir.join("kek.sealed"), sdir.join("offline-kek")).unwrap();
        assert!(open_payment_nonces(&st.config, &data, "pass", &p.vault, 0).is_err(),
            "replacement element opened the device nonce store");
        assert!(!sdir.join("nonces").exists());
        std::fs::remove_dir_all(data).unwrap();
    }

    #[test]
    fn custody_nonces_sign_and_refuse_reuse_snapshot_and_stale_epoch() {
        use crate::signer::{local::tests::{candidate_and_package, DurableWitness, UnavailableWitness}, store::{FileKind, SignerStore}};
        let data = std::env::temp_dir().join(format!("loki-device-nonces-{}", Uuid::new_v4()));
        let witnesses = std::env::temp_dir().join(format!("loki-device-witnesses-{}", Uuid::new_v4()));
        let st = test_state();
        let vault = hex::encode([2; 32]);
        let sdir = super::super::ceremony::signer_dir(&data, &vault).unwrap();
        let se = st.config.open_secure_element(&sdir, "pass").unwrap();
        let store = SignerStore::create(&sdir, Network::Regtest, [2; 32], 1).unwrap();
        let (shares, public) = frost::keys::generate_with_dealer(2, 2, frost::keys::IdentifierList::Default, &mut OsRng).unwrap();
        let key = frost::keys::KeyPackage::try_from(shares[&frost::Identifier::try_from(1u16).unwrap()].clone()).unwrap();
        let peer = frost::keys::KeyPackage::try_from(shares[&frost::Identifier::try_from(2u16).unwrap()].clone()).unwrap();
        let fvk = zip2005::frost_viewing_key(&public.verifying_key().serialize().unwrap().try_into().unwrap(), &[42; 32]).unwrap();
        let material = crate::signer::local::encode_share(&key.serialize().unwrap(), &public.serialize().unwrap(), &[42; 32]);
        store.write(&se, FileKind::Share, 0, &material).unwrap();
        let reopen = |epoch| {
            let (se, nonces) = open_payment_nonces(&st.config, &data, "pass", &vault, epoch).unwrap();
            LocalSigner::from_restored(1, 2, 2, [2; 32], "device".into(), Network::Regtest,
                se, &key.serialize().unwrap(), public.serialize().unwrap(), fvk.clone(), epoch,
                nonces, Box::new(|_| true), None).unwrap()
                .with_nonce_witness(Box::new(DurableWitness(witnesses.clone()))).unwrap()
        };
        let mut signer = reopen(0);
        let session = signer.connect("test", Network::Regtest, b"nonce locality").unwrap().session;
        let cand = CandidateRef { vault_id: [2; 32], payment_id: [7; 32], attempt_id: [9; 32] };
        let commitment = signer.sign_commit(&session, &cand).unwrap();
        let nonce_path = std::fs::read_dir(sdir.join("nonces")).unwrap().next().unwrap().unwrap().path();
        assert_eq!(nonce_path.extension().unwrap(), "nonce");
        let snapshot = std::fs::read(&nonce_path).unwrap();
        let (peer_nonces, peer_commitment) = frost::round1::commit(peer.signing_share(), &mut OsRng);
        let (pczt, package, seed) = candidate_and_package(&fvk, &key, &public, *peer.identifier(), peer_commitment, commitment, true);
        signer = signer.with_nonce_witness(Box::new(UnavailableWitness)).unwrap();
        let error = signer.sign_approve(&session, &cand, &pczt, &package, &seed).unwrap_err();
        assert!(error.to_string().contains("external witness unavailable"), "{error}");
        assert!(!nonce_path.with_extension("burn").exists());
        signer = signer.with_nonce_witness(Box::new(DurableWitness(witnesses.clone()))).unwrap();
        let first = signer.sign_approve(&session, &cand, &pczt, &package, &seed).unwrap();
        let second = frost_rerandomized::sign_with_randomizer_seed(&package, &peer_nonces, &peer, &seed).unwrap();
        let params = frost_rerandomized::RandomizedParams::regenerate_from_seed_and_commitments(
            public.verifying_key(), &seed, package.signing_commitments()).unwrap();
        let signature = frost_rerandomized::aggregate(&package,
            &BTreeMap::from([(*key.identifier(), first), (*peer.identifier(), second)]), &public, &params).unwrap();
        params.randomized_verifying_key().verify(package.message(), &signature).unwrap();
        assert_eq!(signer.sign_approve(&session, &cand, &pczt, &package, &seed).unwrap(), first);
        let (other_pczt, other_package, other_seed) = candidate_and_package(&fvk, &key, &public,
            *peer.identifier(), peer_commitment, commitment, true);
        assert_ne!(package.message(), other_package.message());
        let error = signer.sign_approve(&session, &cand, &other_pczt, &other_package, &other_seed).unwrap_err();
        assert!(error.to_string().contains("nonce reuse"), "{error}");
        drop(signer);

        // Restoring every local nonce byte cannot restore an external witness claim.
        std::fs::remove_file(nonce_path.with_extension("burn")).unwrap();
        std::fs::write(&nonce_path, &snapshot).unwrap();
        let mut signer = reopen(0);
        let session = signer.connect("test", Network::Regtest, b"restored snapshot").unwrap().session;
        assert_eq!(signer.sign_commit(&session, &cand).unwrap(), commitment);
        let error = signer.sign_approve(&session, &cand, &other_pczt, &other_package, &other_seed).unwrap_err();
        assert!(error.to_string().contains("nonce already claimed"), "{error}");
        assert!(!nonce_path.with_extension("burn").exists());
        drop(signer);

        store.write(&se, FileKind::Share, 1, &material).unwrap();
        assert!(open_payment_nonces(&st.config, &data, "pass", &vault, 0).is_err());
        let mut signer = reopen(1);
        let session = signer.connect("test", Network::Regtest, b"new epoch").unwrap().session;
        let error = signer.sign_commit(&session, &cand).unwrap_err();
        assert!(error.to_string().contains("pre-restore epoch"), "{error}");
        let error = signer.sign_approve(&session, &cand, &pczt, &package, &seed).unwrap_err();
        assert!(error.to_string().contains("pre-restore epoch"), "{error}");
        assert_eq!(std::fs::read(&nonce_path).unwrap(), snapshot);
        std::fs::remove_dir_all(data).unwrap();
        std::fs::remove_dir_all(witnesses).unwrap();
    }

    #[test]
    fn custody_metadata_does_not_contain_spend_material() {
        let (data, _, p) = hosted_payment_fixture();
        let raw = member_dir(&data, &p.vault).unwrap().read_sealed("vault.sealed", "pass").unwrap();
        let metadata: Value = serde_json::from_slice(&raw).unwrap();
        assert!(metadata.get("key_package").is_none(), "passphrase alone recovered the FROST share");
        assert!(metadata.get("vault_secret").is_none(), "vault secret escaped the secure element");
        load_vault(&data, "pass", &p.vault, &test_state().config).unwrap();
        let sdir = super::super::ceremony::signer_dir(&data, &p.vault).unwrap();
        std::fs::rename(&sdir, sdir.with_file_name("offline-signer")).unwrap();
        assert!(load_vault(&data, "pass", &p.vault, &test_state().config).is_err(),
            "metadata and passphrase loaded a share without its secure-element store");
        std::fs::remove_dir_all(data).unwrap();
    }

    #[test]
    fn custody_legacy_password_share_requires_explicit_migration() {
        let (data, _, p) = hosted_payment_fixture();
        let st = test_state();
        let v = load_vault(&data, "pass", &p.vault, &st.config).unwrap();
        let dir = member_dir(&data, &p.vault).unwrap();
        let mut metadata: Value = serde_json::from_slice(&dir.read_sealed("vault.sealed", "pass").unwrap()).unwrap();
        metadata["key_package"] = json!(hex::encode(v.key.serialize().unwrap()));
        metadata["vault_secret"] = json!(hex::encode([42; 32]));
        save_record(&dir, "vault.sealed", "pass", &metadata).unwrap();
        let error = load_vault(&data, "pass", &p.vault, &st.config).err().expect("legacy share was accepted");
        assert!(error.contains("legacy vault"), "{error}");
        assert_eq!(serde_json::from_slice::<Value>(&dir.read_sealed("vault.sealed", "pass").unwrap()).unwrap(), metadata);
        std::fs::remove_dir_all(data).unwrap();
    }

    #[test]
    fn custody_recovery_reseals_for_the_hosted_loader() {
        let (data, _, p) = hosted_payment_fixture();
        let st = test_state();
        let original = load_vault(&data, "pass", &p.vault, &st.config).unwrap();
        let (se, nonces) = open_payment_nonces(&st.config, &data, "pass", &p.vault, original.share_epoch).unwrap();
        nonces.commit("before-recovery", &se, original.key.signing_share()).unwrap();
        let nonce_path = super::super::ceremony::signer_dir(&data, &p.vault).unwrap().join("nonces/before-recovery.nonce");
        let nonce_snapshot = std::fs::read(&nonce_path).unwrap();
        let roster = serde_json::to_vec(&json!({
            "vault": p.vault, "threshold": 2, "setup_version": 2,
            "members": original.roster.values().map(|member| json!({
                "id": member.id, "signing": hex::encode(member.signing), "encryption": hex::encode(member.encryption),
            })).collect::<Vec<_>>(),
        })).unwrap();
        let fingerprint = crate::member_state::Roster::from_bytes(&roster).unwrap().fingerprint();
        let material = crate::signer::backup::BackupMaterial {
            member_id: 1, threshold: 2, members: 3, network: Network::Regtest,
            vault_id: hex32(&p.vault).unwrap(), label: "restored".into(), group_sk: [42; 32],
            key_package: Zeroizing::new(original.key.serialize().unwrap()),
            public_package: original.public.serialize().unwrap(), backup_epoch: original.share_epoch,
            identity: Zeroizing::new(original.identity.to_secret_bytes().to_vec()), roster,
            roster_fingerprint: fingerprint, birth_height: None,
        };
        let (words, recovery) = crate::signer::recovery::RecoveryKey::generate().unwrap();
        let artifact = crate::signer::backup::create_to_recovery(&material, &recovery.public_bytes()).unwrap();
        let sdir = super::super::ceremony::signer_dir(&data, &p.vault).unwrap();
        std::fs::write(super::super::recovery::backup_file(&sdir), &artifact.0).unwrap();
        std::fs::remove_file(member_dir(&data, &p.vault).unwrap().path().join("vault.sealed")).unwrap();
        std::fs::remove_file(sdir.join("share.sealed")).unwrap();
        std::fs::remove_file(sdir.join("kek.sealed")).unwrap();
        super::super::ceremony::restore_vault_from_backup(&data, &p.vault, &words, "pass", &st.config).unwrap();
        let restored = load_vault(&data, "pass", &p.vault, &st.config).unwrap();
        assert_eq!(restored.key.serialize().unwrap(), *material.key_package);
        assert_eq!(restored.fvk.to_bytes(), original.fvk.to_bytes());
        assert_eq!(restored.share_epoch, 1);
        let (se, nonces) = open_payment_nonces(&st.config, &data, "pass", &p.vault, restored.share_epoch).unwrap();
        assert_eq!(nonces.commit("before-recovery", &se, restored.key.signing_share()).unwrap_err(),
            crate::signer::nonce::NonceError::StaleEpoch);
        assert_eq!(std::fs::read(&nonce_path).unwrap(), nonce_snapshot, "profile recovery rewrote device nonce state");
        std::fs::remove_file(member_dir(&data, &p.vault).unwrap().path().join("vault.sealed")).unwrap();
        super::super::ceremony::restore_vault_from_backup(&data, &p.vault, &words, "pass", &st.config).unwrap();
        assert_eq!(load_vault(&data, "pass", &p.vault, &st.config).unwrap().share_epoch, 2,
            "restoring the same backup rolled back the device epoch");
        std::fs::remove_dir_all(data).unwrap();
    }

    #[test]
    fn custody_host_flag_without_recorded_consent_cannot_sign() {
        use crate::signer::secure_element::SoftwareSecureElement;
        let (_, mut p, v) = reviewed_candidate_fixture();
        p.approval_requested = true;
        p.memo = "loki bind".into();
        let data = std::env::temp_dir().join(format!("loki-consent-{}", Uuid::new_v4()));
        let mut signer = LocalSigner::with_sealed_share(
            1, 2, 3, hex32(&p.vault).unwrap(), "consent".into(), Network::Regtest,
            SoftwareSecureElement::generate(), &v.key.serialize().unwrap(),
            v.public.serialize().unwrap(), v.fvk.clone(), data.join("nonces"),
            payment_approval(data.clone(), Zeroizing::new("pass".into()), p.clone()),
        ).unwrap();
        let session = signer.connect("test", Network::Regtest, b"consent").unwrap().session;
        let cand = CandidateRef { vault_id: hex32(&p.vault).unwrap(), payment_id: hex32(&p.attempt).unwrap(), attempt_id: hex32(&p.attempt).unwrap() };
        let own = signer.sign_commit(&session, &cand).unwrap();
        let (_, peer) = frost::round1::commit(v.key.signing_share(), &mut OsRng);
        let (pczt, package, seed) = crate::signer::local::tests::candidate_and_package(
            &v.fvk, &v.key, &v.public, frost::Identifier::try_from(2u16).unwrap(), peer, own, true,
        );
        let result = signer.sign_approve(&session, &cand, &pczt, &package, &seed);
        assert!(matches!(result, Err(crate::signer::local::SignerError::MemberRefused)),
            "host approval_requested flag released a signature share: {result:?}");
        assert!(bind_approved_candidate(&data, "pass", &pczt, &p, &v).is_err());
        record_approval(&data, "pass", &p).unwrap();
        assert!(matches!(signer.sign_approve(&session, &cand, &pczt, &package, &seed),
            Err(crate::signer::local::SignerError::MemberRefused)), "unbound intent approval released a share");
        let mut changed_intent = p.clone();
        changed_intent.amount_zat += 1;
        assert!(bind_approved_candidate(&data, "pass", &pczt, &changed_intent, &v).is_err());
        bind_approved_candidate(&data, "pass", &pczt, &p, &v).unwrap();
        // A fresh policy reads the durable approval, as after a process restart.
        let mut policy = payment_approval(data.clone(), Zeroizing::new("pass".into()), p.clone());
        let view = crate::signer::wysiwys::describe_pczt(&pczt, &v.fvk).unwrap();
        let mut other_attempt = cand;
        other_attempt.attempt_id[1] ^= 1;
        assert!(!policy(&crate::signer::local::ApprovalRequest {
            candidate: &other_attempt, sighash: package.message().as_slice().try_into().unwrap(), view: &view,
        }));
        let (other_pczt, other_package, other_seed) = crate::signer::local::tests::candidate_and_package(
            &v.fvk, &v.key, &v.public, frost::Identifier::try_from(2u16).unwrap(), peer, own, true,
        );
        assert_ne!(package.message(), other_package.message());
        assert!(bind_approved_candidate(&data, "pass", &other_pczt, &p, &v).is_err());
        assert!(matches!(signer.sign_approve(&session, &cand, &other_pczt, &other_package, &other_seed),
            Err(crate::signer::local::SignerError::MemberRefused)), "another candidate used the approval");
        let share = signer.sign_approve(&session, &cand, &pczt, &package, &seed).unwrap();
        assert_eq!(share.serialize().len(), 32);
        std::fs::remove_dir_all(data).unwrap();
    }

    #[tokio::test]
    async fn finish_observes_an_existing_coordinator_without_waiting() {
        let (data, _, mut p) = hosted_payment_fixture();
        p.recipient = vault::unified_address(
            &load_vault(&data, "pass", &p.vault, &test_state().config).unwrap().fvk,
            VaultNetwork::Regtest.network_type(),
        );
        p.signers = vec![1, 2];
        p.approval_requested = true;
        p.approval_started = true;
        save_payment(&data, "pass", &p).unwrap();
        let st = test_state();
        *st.session.write().await = Some(super::super::state::Session {
            data: data.clone(), passphrase: Zeroizing::new("pass".into()),
        });
        let runner = claim_payment(&st, &p.vault, &p.attempt, "coordinator").unwrap().unwrap();
        for _ in 0..2 {
            let reply = tokio::time::timeout(Duration::from_secs(2),
                finish(State(st.clone()), Json(json!({"vault":p.vault,"attempt":p.attempt}))))
                .await.expect("finish blocked on the coordinator");
            assert_eq!(reply.0, StatusCode::OK, "{}", reply.1.0);
            assert_eq!(reply.1.0["phase"], "signing");
            assert!(reply.1.0["txid"].is_null());
        }
        let saved = serde_json::to_value(read_payment(&data, "pass", &p.vault, &p.attempt).unwrap()).unwrap();
        assert_eq!(saved["finish_requested"], true);
        drop(runner);
        std::fs::remove_dir_all(data).unwrap();
    }

    #[test]
    fn finalization_resumes_after_failure_and_restart_without_losing_signed_checkpoint() {
        let (data, _, mut p) = hosted_payment_fixture();
        p.recipient = vault::unified_address(
            &load_vault(&data, "pass", &p.vault, &test_state().config).unwrap().fvk,
            VaultNetwork::Regtest.network_type(),
        );
        assert!(!finalization_pending(&data, &p), "publishing alone must not request broadcast");
        p.approval_complete = true;
        p.signed_pczt = Some("durable signed checkpoint".into());
        p.raw_tx = Some("durable transaction".into());
        p.txid = Some(hex::encode([9; 32]));
        p.finish_requested = true;
        save_payment(&data, "pass", &p).unwrap();
        for _ in 0..2 {
            let st = test_state();
            let saved = read_payment(&data, "pass", &p.vault, &p.attempt).unwrap();
            assert!(finalization_pending(&data, &saved), "completed signer must not suppress coordinator resume");
            assert!(finalization_view(&saved)["txid"].is_null(), "unbroadcast txid reported as sent");
            assert_eq!(run_finalization(st.clone(), data.clone(), Zeroizing::new("pass".into()), p.vault.clone(), p.attempt.clone()).unwrap_err(),
                "lightwalletd URL is required");
            assert!(st.active_payments.lock().unwrap().is_empty());
            let saved = read_payment(&data, "pass", &p.vault, &p.attempt).unwrap();
            assert_eq!(saved.signed_pczt, p.signed_pczt);
            assert_eq!(saved.raw_tx, p.raw_tx);
            assert_eq!(session_view(&saved).unwrap()["error"], "lightwalletd URL is required");
        }
        p.finish_requested = false;
        p.coordinator_secret = Some("legacy coordinator".into());
        let dir = payment_dir(&data, &p.vault).unwrap();
        dir.write_sealed(&format!("{}.coordinator.sealed", p.attempt), b"checkpoint", "pass").unwrap();
        assert!(finalization_pending(&data, &p), "legacy in-flight finalization must resume");
        p.phase = "approved".into();
        assert!(finalization_pending(&data, &p));
        p.phase = "broadcast".into();
        assert!(!finalization_pending(&data, &p));
        p.phase = "expired".into();
        assert!(!finalization_pending(&data, &p));
        std::fs::remove_dir_all(data).unwrap();
    }

    #[test]
    fn coordinator_resume_does_not_require_signers_to_stay_online() {
        let (data, _, mut p) = hosted_payment_fixture();
        let v = load_vault(&data, "pass", &p.vault, &test_state().config).unwrap();
        p.recipient = vault::unified_address(&v.fvk, VaultNetwork::Regtest.network_type());
        p.signers = vec![1, 2];
        p.approval_requested = true;
        p.approval_started = true;
        p.finish_requested = true;
        // No peer URL is available; before a transcript exists this must remain unready.
        let mut st = test_state();
        std::sync::Arc::get_mut(&mut st).unwrap().config.frostd_url = "invalid relay URL".into();
        assert!(!ready_to_send(&st, &p, &v));
        let coordinator = Identity::new(0);
        p.coordinator_secret = Some(hex::encode(coordinator.to_secret_bytes()));
        p.coordinator = Some(coordinator.public());
        save_payment(&data, "pass", &p).unwrap();
        let binding = (&p.vault, &p.attempt, p.session_id, "coordinator");
        save_record(&payment_dir(&data, &p.vault).unwrap(), &format!("{}.coordinator.sealed", p.attempt),
            "pass", &(binding, Progress::default())).unwrap();
        // Reaching relay setup proves the offline peer did not suppress this resumed drive.
        let error = run_finalization(st.clone(), data.clone(), Zeroizing::new("pass".into()), p.vault.clone(), p.attempt.clone()).unwrap_err();
        assert!(error.contains("frostd http error"), "{error}");
        assert!(st.active_payments.lock().unwrap().is_empty());
        std::fs::remove_dir_all(data).unwrap();
    }

    #[tokio::test]
    async fn peer_approvals_are_authenticated_serialized_and_bound_to_review() {
        let (data, identities, p) = hosted_payment_fixture();
        let root = MemberDir::open(&data, ".");
        let st = test_state();
        *st.session.write().await = Some(super::super::state::Session {
            data: data.clone(), passphrase: Zeroizing::new("pass".into()),
        });
        let context = peer_context(&p.vault).unwrap();
        let request = |id: &Identity, intent: Value| {
            let body = serde_json::to_vec(&json!({"request":Uuid::new_v4().to_string(),"attempt":p.attempt,"approve":intent})).unwrap();
            json!({"vault":p.vault,"sender":id.public().id,
                "body":hex::encode(id.seal_payment(&identities[0].public(), &context, &body).unwrap())})
        };
        let mut changed = approval_intent(&p);
        changed["amount_zat"] = json!(99);
        assert_eq!(peer_session(State(st.clone()), Json(request(&identities[1], changed))).await.0, StatusCode::BAD_REQUEST);
        let mut forged = request(&identities[1], approval_intent(&p));
        forged["sender"] = json!(3);
        assert_eq!(peer_session(State(st.clone()), Json(forged)).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(read_payment(&data, "pass", &p.vault, &p.attempt).unwrap().signers, vec![1]);
        let second = request(&identities[1], approval_intent(&p));
        let third = request(&identities[2], approval_intent(&p));
        let (a, b) = tokio::join!(peer_session(State(st.clone()), Json(second.clone())), peer_session(State(st.clone()), Json(third)));
        assert_eq!((a.0, b.0), (StatusCode::OK, StatusCode::OK));
        let selected = read_payment(&data, "pass", &p.vault, &p.attempt).unwrap().signers;
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0], 1);
        assert!([2, 3].contains(&selected[1]));
        assert_eq!(peer_session(State(st.clone()), Json(second)).await.0, StatusCode::OK);
        assert_eq!(read_payment(&data, "pass", &p.vault, &p.attempt).unwrap().signers, selected);
        std::fs::remove_file(root.path().join("identity.sealed")).unwrap();
        assert!(load_vault(&data, "pass", &p.vault, &test_state().config).is_err());
        assert!(!root.exists("identity.sealed"));
        std::fs::remove_dir_all(data).unwrap();
    }

    #[test]
    fn first_approvers_fill_an_immutable_quorum() {
        let mut p = payment_fixture();
        let reviewed = approval_intent(&p);
        accept_approval(&mut p, 3, 3).unwrap();
        assert_eq!(p.signers, vec![1, 3]);
        accept_approval(&mut p, 3, 3).unwrap();
        assert_eq!(p.signers, vec![1, 3]);
        accept_approval(&mut p, 4, 3).unwrap();
        accept_approval(&mut p, 2, 3).unwrap();
        assert_eq!(p.signers, vec![1, 3, 4]);
        assert_eq!(approval_intent(&p), reviewed);
        p.amount_zat += 1;
        assert_ne!(approval_intent(&p), reviewed);
        p.open_approval = false;
        assert!(accept_approval(&mut p, 2, 3).is_err());
    }

    #[test]
    fn chain_history_shares_ledger_facts_and_shows_the_sender_their_amount() {
        let mut p = payment_fixture(); // amount 1, fee 1, recipient "test", spends note [3;32]
        let txid = hex::encode([9; 32]);
        let mut history = vec![crate::wallet_store::WalletTransaction {
            txid: txid.clone(), mined_height: Some(7), recipient: String::new(),
            amount_zat: 2, received: false, amount_is_net: true,
            spent_nullifiers: p.note_selection.clone(),
        }];
        // A member without the local record sees the chain's net view (what left the wallet).
        let canonical = history_view(&history, vec![]);
        assert_eq!(canonical["payments"][0]["phase"], "confirmed");
        assert_eq!(canonical["payments"][0]["amount_zat"], "2");
        assert_eq!(canonical["payments"][0]["amount_is_net"], true);
        // The sender (holding the payment record) sees the SAME tx — same id, phase, block —
        // enriched with the amount + recipient + fee they actually authorized.
        let mine = history_view(&history, vec![(p.clone(), true)]);
        for k in ["txid", "phase", "mined_height", "direction"] {
            assert_eq!(mine["payments"][0][k], canonical["payments"][0][k], "{k} must agree across members");
        }
        assert_eq!(mine["payments"][0]["amount_zat"], "1");
        assert_eq!(mine["payments"][0]["recipient"], "test");
        assert_eq!(mine["payments"][0]["amount_is_net"], false);
        assert_eq!(mine["payments"][0]["fee_zat"], "1");
        // A broadcast (not yet mined) tx reconciles against the local record — one row, no duplicate.
        p.phase = "broadcast".into();
        p.txid = Some(txid);
        history[0].mined_height = None;
        let bc = history_view(&history, vec![(p, false)]);
        assert_eq!(bc["payments"].as_array().unwrap().len(), 1);
        assert_eq!(bc["payments"][0]["phase"], "broadcast");
        // A draft spending different notes stays its own pending row.
        let mut draft = payment_fixture();
        draft.note_selection = vec![hex::encode([8;32])];
        draft.phase = "draft".into();
        assert_eq!(history_view(&history, vec![(draft, false)])["payments"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn proposed_payment_is_visible_to_every_vault_member() {
        let data = std::env::temp_dir().join(format!("loki-payment-discovery-{}", Uuid::new_v4()));
        let p = payment_fixture();
        save_payment(&data, "pass", &p).unwrap();
        let proposed = proposed_view(&data, "pass", &p.vault, Some(3)).unwrap();
        assert_eq!(proposed["proposed"][0]["attempt"], p.attempt);
        std::fs::remove_dir_all(data).unwrap();
    }

    #[test]
    fn stale_signing_expiry_cannot_overwrite_finalization() {
        let base = json!({"attempt":hex::encode([1;32]),"vault":hex::encode([2;32]),
            "proposer":1,"recipient":"test","amount_zat":1,"memo":"","fee_zat":1,
            "change_zat":0,"note_selection":[],"target_height":1,"expiry_height":2,
            "signers":[1,2],"phase":"signing","approval_requested":true});
        for phase in ["signing", "broadcast", "confirmed"] {
            let mut payment: Payment = serde_json::from_value(base.clone()).unwrap();
            payment.phase = phase.into();
            if phase == "signing" { payment.signed_pczt = Some("durable signed transaction".into()); }
            let before = serde_json::to_value(&payment).unwrap();
            assert!(!apply_signing_result(&mut payment, 1, false, Err("payment expired".into())));
            assert_eq!(serde_json::to_value(&payment).unwrap(), before);
        }
        let mut payment: Payment = serde_json::from_value(base).unwrap();
        assert!(apply_signing_result(&mut payment, 1, false, Err("payment expired".into())));
        assert_eq!(payment.phase, "expired");
        assert!(payment.approval_requested);
    }

    fn test_state() -> Shared {
        std::sync::Arc::new(super::super::state::AppState::new(super::super::state::Config {
            registration: None,
            bind: "127.0.0.1".parse().unwrap(), advertise_url: None,
            data: PathBuf::new(), port: 3701, network: "regtest".into(), lightwalletd: None,
            transport: "local".into(), secure_element: "software".into(), operator_bundle: None, nonce_witnesses: None,
            operator_key: None, enrollment_issuer: None, development_http: false,
            token: "test".into(), frostd_url: "http://127.0.0.1:2744".into(), peers: BTreeMap::new(),
            loopback_peers: false,
        }))
    }

    #[test]
    fn timed_out_payment_expiry_probe_yields_and_resumes() {
        // Accept TCP connections without answering the HTTP/2 handshake.
        let stalled = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let data = std::env::temp_dir().join(format!("loki-payment-expiry-{}", Uuid::new_v4()));
        let mut st = test_state();
        std::sync::Arc::get_mut(&mut st).unwrap().config.lightwalletd =
            Some(format!("http://{}", stalled.local_addr().unwrap()));
        *st.session.blocking_write() = Some(super::super::state::Session {
            data: data.clone(), passphrase: Zeroizing::new("pass".into()),
        });
        let mut p = payment_fixture();
        p.approval_requested = true;
        p.approval_started = true;
        let before = serde_json::to_value(&p).unwrap();
        let result = signing_run(&st, &data, "pass", &p, "signer").map(|_| ());
        assert_eq!(result, Err(DRIVE_YIELDED.into()));
        assert!(apply_signing_result(&mut p, 1, false, result));
        assert_eq!(serde_json::to_value(&p).unwrap(), before);
        let dir = payment_dir(&data, &p.vault).unwrap();
        let file = format!("{}.signer.sealed", p.attempt);
        let saved = dir.read_sealed(&file, "pass").unwrap();
        for role in ["signer", "coordinator"] {
            assert!(signing_run(&st, &data, "pass", &p, role).is_ok(), "retry probed again");
        }
        assert_eq!(dir.read_sealed(&file, "pass").unwrap(), saved);
        std::fs::remove_dir_all(data).unwrap();
    }

    #[test]
    fn payment_expiry_tip_is_cached_and_refreshes_at_the_expiry_boundary() {
        let mut tip = ExpiryTip::default();
        assert!(tip.check(100, || Ok(99)).is_ok());
        assert!(tip.check(100, || panic!("fresh tip fetched again")).is_ok());
        assert_eq!(tip.check(99, || panic!("cached expiry ignored")), Err("payment expired".into()));
        tip.checked = Some(Instant::now() - Duration::from_secs(60));
        assert_eq!(tip.check(100, || Err(tonic::Status::deadline_exceeded("Timeout expired").to_string())),
            Err(DRIVE_YIELDED.into()));
        assert!(tip.check(100, || panic!("failed probe retried without cooldown")).is_ok());
        assert_eq!(tip.check(99, || panic!("last good tip lost")), Err("payment expired".into()));
        tip.checked = Some(Instant::now() - Duration::from_secs(60));
        assert_eq!(tip.check(100, || Ok(100)), Err("payment expired".into()));
    }

    #[test]
    fn payment_runner_claim_is_exclusive_and_released_on_drop() {
        let st = test_state();
        let claims = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8).map(|_| scope.spawn(|| claim_payment(&st, "vault", "attempt", "signer").unwrap())).collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect::<Vec<_>>()
        });
        assert_eq!(claims.iter().filter(|c| c.is_some()).count(), 1);
        assert!(claim_payment(&st, "vault", "attempt", "signer").unwrap().is_none());
        assert!(claim_payment(&st, "vault", "attempt", "coordinator").unwrap().is_some());
        drop(claims);
        assert!(claim_payment(&st, "vault", "attempt", "signer").unwrap().is_some());
    }

    fn reviewed_candidate_fixture() -> (Vec<u8>, Payment, Vault) {
        let (shares, public) = frost::keys::generate_with_dealer(
            3,
            2,
            frost::keys::IdentifierList::Default,
            &mut OsRng,
        )
        .unwrap();
        let key = frost::keys::KeyPackage::try_from(
            shares[&frost::Identifier::try_from(1u16).unwrap()].clone(),
        )
        .unwrap();
        let ak: [u8; 32] = public
            .verifying_key()
            .serialize()
            .unwrap()
            .try_into()
            .unwrap();
        let fvk = zip2005::frost_viewing_key(&ak, &[42u8; 32]).unwrap();
        let rho = Rho::from_bytes(&[1u8; 32]).unwrap();
        let rseed = RandomSeed::from_bytes([2u8; 32], &rho).unwrap();
        let note = orchard::Note::from_parts(
            fvk.address_at(0u64, Scope::External),
            NoteValue::from_raw(625_000_000),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .unwrap();
        let to = fvk.address_at(7u64, Scope::External);
        let recipient = vault::unified_receiver(
            to.to_raw_address_bytes(),
            VaultNetwork::Regtest.network_type(),
        );
        let mut inputs = CandidateInputs {
            vault_fvk: &fvk,
            notes: vec![note],
            recipient: to,
            amount: Zatoshis::const_from_u64(40_000_000),
            memo: MemoBytes::from_bytes(b"reviewed memo").unwrap(),
            change: Zatoshis::ZERO,
            target_height: 700,
            expiry_height: 1_152,
        };
        let fee_zat: u64 = quote_fee(&VaultNetwork::Regtest, &inputs).unwrap().into();
        let change_zat = 625_000_000 - 40_000_000 - fee_zat;
        inputs.change = Zatoshis::from_u64(change_zat).unwrap();
        let built = crate::candidate::build_candidate(
            &VaultNetwork::Regtest,
            &inputs,
            &[pallas::Scalar::from(3)],
            rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng),
        )
        .unwrap();
        let pczt = pczt::roles::creator::Creator::build_from_parts(built.pczt_parts)
            .unwrap()
            .serialize()
            .unwrap();
        assert_candidate_wire_is_private(&pczt, &fvk);
        let identity = Identity::new(1);
        let v = Vault {
            network: VaultNetwork::Regtest,
            fvk,
            key,
            share_epoch: 0,
            public,
            identity,
            threshold: 2,
            slot: 1,
            peers: BTreeMap::new(),
            roster: BTreeMap::new(),
            base_urls: BTreeMap::new(),
            birth_height: 2,
        };
        let p = Payment {
            attempt: hex::encode([1u8; 32]),
            vault: hex::encode([2u8; 32]),
            proposer: 1,
            recipient,
            amount_zat: 40_000_000,
            memo: "reviewed memo".into(),
            fee_zat,
            change_zat,
            note_selection: vec![hex::encode(note.nullifier(&v.fvk).to_bytes())],
            target_height: 700,
            expiry_height: 1_152,
            signers: vec![1, 2],
            open_approval: false,
            phase: "signing".into(),
            session_id: None,
            coordinator_secret: None,
            coordinator: None,
            review_token: None,
            approval_requested: false,
            approval_started: false,
            approval_complete: false,
            finish_requested: false,
            txid: None,
            signed_pczt: None,
            raw_tx: None,
            error: None,
        };
        (pczt, p, v)
    }

    fn mutate_candidate(bytes: &[u8], mutate: impl FnOnce(&mut Value)) -> Vec<u8> {
        let wire = pczt::v2::Pczt::try_from(pczt::Pczt::parse(bytes).unwrap()).unwrap();
        let mut value = serde_json::to_value(wire).unwrap();
        mutate(&mut value);
        serde_json::from_value::<pczt::v2::Pczt>(value).unwrap().serialize()
    }

    #[test]
    fn hosted_signing_refuses_without_nonce_witnesses() {
        let (_, p, mut v) = reviewed_candidate_fixture();
        v.peers = (1..=3).map(|id| (id, Peer([id as u8; 32]))).collect();
        let error = sign(&test_state(), Path::new("/unused"), "pass", &p, &v).unwrap_err();
        assert!(error.contains("--nonce-witnesses"), "{error}");
    }

    #[test]
    fn hosted_review_rejects_substituted_epk_for_payee_and_change() {
        let (pczt, p, v) = reviewed_candidate_fixture();
        review_candidate(&pczt, &p, &v).unwrap();
        for index in 0..2 {
            let bad = mutate_candidate(&pczt, |value| {
                value["ironwood"]["actions"][index]["output"]["ephemeral_key"] =
                    value["ironwood"]["actions"][1 - index]["output"]["ephemeral_key"].clone();
            });
            assert!(review_candidate(&bad, &p, &v).is_err(), "accepted substituted epk at output {index}");
        }
    }

    #[test]
    fn hosted_review_rejects_other_pools_and_versions() {
        let (pczt, p, v) = reviewed_candidate_fixture();
        review_candidate(&pczt, &p, &v).unwrap();
        let bad = mutate_candidate(&pczt, |value| {
            value["transparent"] = json!({"inputs": [], "outputs": [{
                "value": 0, "script_pubkey": [106], "redeem_script": null,
                "bip32_derivation": {}, "user_address": null, "proprietary": {}
            }]});
        });
        assert!(review_candidate(&bad, &p, &v).is_err(), "accepted a transparent output");
        let bad = mutate_candidate(&pczt, |value| { value["global"]["tx_version"] = json!(5); });
        assert!(review_candidate(&bad, &p, &v).is_err(), "accepted tx version 5");
    }

    #[test]
    fn signer_reviews_candidate_effects_before_signing() {
        let (pczt, mut p, mut v) = reviewed_candidate_fixture();
        review_candidate(&pczt, &p, &v).unwrap();
        v.peers = (1..=3).map(|id| (id, Peer([id as u8; 32]))).collect();
        p.open_approval = true;
        p.signers = vec![1];
        v.slot = 3;
        check_intent(&p, &v).unwrap();
        assert!(sign(&test_state(), Path::new(""), "", &p, &v).is_err());
        v.slot = 1;
        assert!(!ready_to_send(&test_state(), &p, &v));
        p.signers = vec![1, 1];
        assert!(check_intent(&p, &v).is_err());
        p.signers = vec![1, 3];
        p.amount_zat += 1;
        assert!(review_candidate(&pczt, &p, &v).is_err());
    }

    fn assert_candidate_wire_is_private(pczt: &[u8], fvk: &FullViewingKey) {
        let identities = [Identity::new(0), Identity::new(1), Identity::new(2)];
        let roster: BTreeMap<_, _> = identities.iter().map(|i| (i.public().id, i.public())).collect();
        let session = Uuid::new_v4();
        let encryption = |id: usize, attempt, session| PaymentEncryption::new(
            &identities[id], roster.clone(), &[4; 32], &attempt, session,
        ).unwrap();
        let proposer = encryption(1, [5; 32], session);
        let fvk_bytes = fvk.to_bytes();
        assert!(pczt.windows(fvk_bytes.len()).any(|w| w == fvk_bytes), "fixture must contain the real FVK");
        let message = Outbound::Candidate(crate::signer::CandidatePczt(pczt.to_vec()));
        assert!(message.to_bytes().is_err());
        let sender = Peer(identities[1].public().encryption);
        let mut wires = Vec::new();
        for id in [0, 2] {
            let wire = proposer.seal(&Peer(identities[id].public().encryption), &message).unwrap();
            assert!(!wire.windows(pczt.len()).any(|w| w == pczt));
            assert!(!wire.windows(fvk_bytes.len()).any(|w| w == fvk_bytes));
            let recipient = encryption(id, [5; 32], session);
            assert_eq!(recipient.open(&sender, &wire).unwrap(), pczt);
            assert!(recipient.open(&sender, pczt).is_err(), "plaintext downgrade");
            assert!(encryption(id, [6; 32], session).open(&sender, &wire).is_err());
            assert!(encryption(id, [5; 32], Uuid::new_v4()).open(&sender, &wire).is_err());
            assert!(recipient.open(&Peer(Identity::new(3).public().encryption), &wire).is_err());
            let mut tampered = wire.clone();
            tampered[80] ^= 1;
            assert!(recipient.open(&sender, &tampered).is_err());
            wires.push(wire);
        }
        assert_ne!(wires[0], wires[1]);
        assert!(encryption(2, [5; 32], session).open(&sender, &wires[0]).is_err());
    }
}
