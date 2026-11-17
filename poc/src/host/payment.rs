//! Hosted one-note payments. All wallet, frostd, proving, and broadcast work is blocking.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    time::Duration,
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
use zcash_client_backend::proto::service::{BlockId, Empty, RawTransaction};
use zcash_protocol::{
    consensus::{BlockHeight, BranchId, NetworkUpgrade, Parameters},
    memo::MemoBytes,
    value::Zatoshis,
};
use zeroize::Zeroizing;

use super::{
    ceremony::WireIdentity,
    routes::{blocking, err},
    state::Shared,
};
use crate::{
    candidate::{quote_fee, CandidateInputs},
    network::{VaultNetwork, TESTNET_NU7_BIRTH},
    payment_transport::{coordinate, signer_loop},
    setup_transport::{Identity, PublicIdentity},
    signer::{
        local::LocalSigner, secure_element::SoftwareSecureElement, CandidateRef, Network,
        PublicPaymentParams, Signer,
    },
    signing_session::{AttemptId, MessageKind, SessionContext},
    state::MemberDir,
    transport::{FrostdLoginKey, FrostdTransport, Outbound, Peer, SealedPeer, Transport},
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
    /// The signing group: empty while the request is open to every member, then fixed by
    /// the proposer to itself plus the first `threshold - 1` other members who approved.
    #[serde(default)]
    signers: Vec<u16>,
    phase: String,
    session_id: Option<Uuid>,
    #[serde(default)]
    control_session_id: Option<Uuid>,
    /// Members who approved, in the order their approvals arrived.
    #[serde(default)]
    approvals: Vec<u16>,
    #[serde(default)]
    start_requested: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    coordinator_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    review_token: Option<String>,
    #[serde(default)]
    approval_requested: bool,
    #[serde(default)]
    approval_started: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    txid: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signed_pczt: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    raw_tx: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

pub(super) struct Vault {
    network: VaultNetwork,
    fvk: FullViewingKey,
    key: frost::keys::KeyPackage,
    public: frost::keys::PublicKeyPackage,
    identity: Identity,
    threshold: u16,
    slot: u16,
    peers: BTreeMap<u16, PublicIdentity>,
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
fn save_payment(data: &Path, pass: &str, p: &Payment) -> Result<(), String> {
    hex32(&p.vault)?;
    hex32(&p.attempt)?;
    let dir = payment_dir(data, &p.vault)?;
    let file = format!("{}.json", p.attempt);
    let temp = format!("{}.{}.tmp", p.attempt, Uuid::new_v4());
    dir.write_sealed(
        &temp,
        &serde_json::to_vec(p).map_err(|e| e.to_string())?,
        pass,
    )
    .map_err(|e| e.to_string())?;
    std::fs::rename(dir.path().join(temp), dir.path().join(file)).map_err(|e| e.to_string())?;
    std::fs::File::open(dir.path())
        .and_then(|f| f.sync_all())
        .map_err(|e| e.to_string())
}
pub(super) fn load_vault(data: &Path, pass: &str, vault: &str, configured: &str) -> Result<Vault, String> {
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
    if network.label() != configured {
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
    // Re-stamp the profile identity to this vault's FROST slot (registration seals it at slot 1).
    let identity = super::ceremony::identity(data, pass, slot)?;
    let ak = hex32(required(&v, "group_ak")?)?;
    let secret = Zeroizing::new(hex32(required(&v, "vault_secret")?)?);
    let fvk = zip2005::frost_viewing_key(&ak, &secret)
        .map_err(|e| format!("group viewing key: {e:?}"))?;
    if v["group_address"].as_str() != Some(&vault::unified_address(&fvk, network.network_type())) {
        return Err("sealed vault address mismatch".into());
    }
    let key = frost::keys::KeyPackage::deserialize(
        &hex::decode(required(&v, "key_package")?).map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
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
    for n in 1..=v["members"].as_u64().ok_or("missing members")? {
        let slot: u16 = n.try_into().map_err(|_| "invalid member id")?;
        let wire: WireIdentity =
            serde_json::from_value(c["slots"][slot.to_string()]["identity"].clone())
                .map_err(|e| e.to_string())?;
        peers.insert(slot, wire.public(slot)?);
    }
    if peers.get(&slot) != Some(&identity.public()) {
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
        public,
        identity,
        threshold,
        slot,
        peers,
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

fn review_candidate(bytes: &[u8], payment: &Payment, vault: &Vault) -> Result<(), String> {
    let parsed = pczt::Pczt::parse(bytes).map_err(|e| format!("candidate: {e:?}"))?;
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
/// The payment terms every member reviews. The signing group is not part of them: any member
/// may approve, and the group is fixed later (`signing_group`, `check_signers`).
fn check_intent(p: &Payment, v: &Vault) -> Result<(), String> {
    hex32(&p.vault)?;
    hex32(&p.attempt)?;
    if !v.peers.contains_key(&p.proposer)
        || p.note_selection.len() != 1
        || p.amount_zat == 0
        || p.expiry_height <= p.target_height
    {
        return Err("invalid payment intent".into());
    }
    vault::orchard_receiver_from_ua(&p.recipient, v.network.network_type())?;
    MemoBytes::from_bytes(p.memo.as_bytes()).map_err(|e| format!("memo: {e:?}"))?;
    Zatoshis::from_u64(p.amount_zat).map_err(|e| format!("amount: {e:?}"))?;
    Zatoshis::from_u64(p.change_zat).map_err(|e| format!("change: {e:?}"))?;
    hex32(&p.note_selection[0])?;
    Ok(())
}
/// A fixed signing group: exactly `threshold` distinct vault members, led by the proposer
/// (the coordinator sends the randomizer to the first signer, who builds the candidate).
fn check_signers(p: &Payment, v: &Vault) -> Result<(), String> {
    let distinct: BTreeSet<_> = p.signers.iter().collect();
    if p.signers.len() != usize::from(v.threshold)
        || distinct.len() != p.signers.len()
        || p.signers.first() != Some(&p.proposer)
        || p.signers.iter().any(|s| !v.peers.contains_key(s))
    {
        return Err("invalid signing group".into());
    }
    Ok(())
}
/// The proposer plus the first `threshold - 1` other members whose approvals arrived, once
/// the proposer has approved too; `None` while fewer than `threshold` members approved.
fn signing_group(p: &Payment, v: &Vault) -> Option<Vec<u16>> {
    if !p.approvals.contains(&p.proposer) {
        return None;
    }
    let mut group = vec![p.proposer];
    group.extend(
        p.approvals
            .iter()
            .copied()
            .filter(|id| *id != p.proposer && v.peers.contains_key(id))
            .take(usize::from(v.threshold) - 1),
    );
    (group.len() == usize::from(v.threshold)).then_some(group)
}
fn record_approval(p: &mut Payment, id: u16) {
    if !p.approvals.contains(&id) {
        p.approvals.push(id);
    }
}
fn members(v: &Vault) -> Vec<u16> {
    v.peers.keys().copied().collect()
}
fn public_intent(p: &Payment) -> Value {
    json!({"attempt":p.attempt,"vault":p.vault,"proposer":p.proposer,"recipient":p.recipient,"amount_zat":p.amount_zat,"memo":p.memo,"fee_zat":p.fee_zat,"change_zat":p.change_zat,"note_selection":p.note_selection,"target_height":p.target_height,"expiry_height":p.expiry_height,"signers":p.signers,"phase":p.phase,"session_id":p.session_id,"control_session_id":p.control_session_id})
}
const UNAVAILABLE: &str = "payment session unavailable";
const ENOUGH_APPROVED: &str = "enough members already approved this payment";

fn ready_to_send(p: &Payment) -> bool {
    p.phase == "ready" && p.error.is_none() && p.signed_pczt.is_some()
}

fn control_context(vault: &str, session: Uuid, a: u16, b: u16) -> Result<SessionContext, String> {
    Ok(SessionContext::control(hex32(vault)?, session, a, b))
}

/// Binds approvals to the payment terms, not to the signing group fixed after them.
fn intent_hash(p: &Payment) -> String {
    let mut intent = public_intent(p);
    intent.as_object_mut().unwrap().remove("phase");
    intent.as_object_mut().unwrap().remove("signers");
    blake3::hash(&serde_json::to_vec(&intent).unwrap())
        .to_hex()
        .to_string()
}

fn send_control(
    url: &str,
    v: &Vault,
    p: &Payment,
    kind: &str,
    slots: &[u16],
) -> Result<(), String> {
    let session = p
        .control_session_id
        .ok_or("missing payment control session; create a fresh payment")?;
    let mut tx = relay(&v.identity, url)?;
    let ch = tx.join(session).map_err(|e| e.to_string())?;
    for slot in slots.iter().copied().filter(|s| *s != v.slot) {
        let peer = v.peers.get(&slot).ok_or("unknown control recipient")?;
        let context = control_context(&p.vault, session, v.slot, slot)?;
        let body = serde_json::to_vec(
            &json!({"kind":kind,"hash":intent_hash(p),"intent":public_intent(p),"txid":p.txid}),
        )
        .map_err(|e| e.to_string())?;
        let sealed = SealedPeer::seal(&v.identity, peer, &context, MessageKind::PeerReply, &body)?;
        tx.send(&ch, &[Peer(peer.encryption)], &Outbound::Peer(sealed))
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

// Only roster-owned control sessions are drained. Signing sessions have ephemeral owners.
fn sync_control(url: &str, data: &Path, pass: &str, vault: &str, v: &Vault) -> Result<(), String> {
    let mut tx = relay(&v.identity, url)?;
    for session in tx.list_sessions().map_err(|e| e.to_string())? {
        let Ok((participants, Some(owner))) = tx.session_details(session) else {
            continue;
        };
        let Some(proposer) = v.peers.values().find(|p| p.encryption == owner) else {
            continue;
        };
        if participants.len() != v.peers.len()
            || !participants.contains(&v.identity.public().encryption)
            || !participants.contains(&owner)
            || !participants
                .iter()
                .all(|k| v.peers.values().any(|p| &p.encryption == k))
        {
            continue;
        }
        let ch = tx.join(session).map_err(|e| e.to_string())?;
        for msg in tx.recv(&ch, false).map_err(|e| e.to_string())? {
            let Some(peer) = v
                .peers
                .values()
                .find(|p| p.encryption == msg.from.0 && p.id != v.slot)
            else {
                continue;
            };
            let context = control_context(vault, session, v.slot, peer.id)?;
            let Ok(opened) = v.identity.open_session(peer, &context, &msg.message) else {
                continue;
            };
            if opened.kind() != MessageKind::PeerReply {
                continue;
            }
            let Ok(body) = serde_json::from_slice::<Value>(opened.body()) else {
                continue;
            };
            let Ok(mut incoming) = serde_json::from_value::<Payment>(body["intent"].clone()) else {
                continue;
            };
            if incoming.vault != vault
                || incoming.proposer != proposer.id
                || incoming.control_session_id != Some(session)
                || incoming.session_id.is_none()
                || incoming.session_id == Some(session)
                || body["hash"].as_str() != Some(intent_hash(&incoming).as_str())
                || check_intent(&incoming, v).is_err()
                || !incoming.signers.is_empty() && check_signers(&incoming, v).is_err()
            {
                continue;
            }
            match read_payment(data, pass, vault, &incoming.attempt) {
                Ok(mut p) => {
                    if intent_hash(&p) != intent_hash(&incoming) || p.error.is_some() {
                        continue;
                    }
                    if peer.id == p.proposer
                        && body["kind"] == "failed"
                        && matches!(p.phase.as_str(), "signing" | "approved" | "not_selected")
                    {
                        p.phase = "failed".into();
                        p.error = Some("The proposer could not complete this signing attempt. Create a fresh payment after recovery.".into());
                        save_payment(data, pass, &p)?;
                        continue;
                    }
                    // The proposer cancels only before signing starts; a copy that already
                    // committed a nonce is kept as it is.
                    if peer.id == p.proposer
                        && body["kind"] == "cancelled"
                        && matches!(p.phase.as_str(), "signing" | "not_selected")
                        && !p.approval_started
                    {
                        p.phase = "cancelled".into();
                        save_payment(data, pass, &p)?;
                        continue;
                    }
                    if peer.id == p.proposer
                        && matches!(p.phase.as_str(), "approved" | "not_selected" | "broadcast")
                        && matches!(body["kind"].as_str(), Some("broadcast" | "confirmed"))
                    {
                        let Some(txid) = body["txid"].as_str().filter(|s| hex32(s).is_ok()) else {
                            continue;
                        };
                        if p.txid.as_deref().is_some_and(|id| id != txid) {
                            continue;
                        }
                        p.txid = Some(txid.to_owned());
                        p.phase = "broadcast".into();
                        save_payment(data, pass, &p)?;
                        continue;
                    }
                    if p.phase != "signing" {
                        continue;
                    }
                    match body["kind"].as_str() {
                        Some("approval") if v.slot == p.proposer => {
                            record_approval(&mut p, peer.id);
                        }
                        // The proposer fixed the group from the first approvals; it never changes.
                        Some("start")
                            if peer.id == p.proposer
                                && !incoming.signers.is_empty()
                                && (p.signers.is_empty() || p.signers == incoming.signers) =>
                        {
                            p.signers = incoming.signers;
                            if !p.signers.contains(&v.slot) {
                                p.phase = "not_selected".into();
                            } else if p.approval_requested {
                                p.start_requested = true;
                            }
                        }
                        _ => continue,
                    }
                    save_payment(data, pass, &p)?;
                }
                Err(_)
                    if body["kind"] == "intent"
                        && peer.id == proposer.id
                        && !payment_dir(data, vault)?
                            .path()
                            .join(format!("{}.json", incoming.attempt))
                            .try_exists()
                            .map_err(|e| e.to_string())? =>
                {
                    incoming.phase = "signing".into();
                    // Only a `start` from the proposer fixes the group.
                    incoming.signers.clear();
                    incoming.coordinator_secret = None;
                    incoming.review_token = None;
                    incoming.approval_requested = false;
                    incoming.approval_started = false;
                    incoming.approvals.clear();
                    incoming.start_requested = false;
                    incoming.txid = None;
                    incoming.signed_pczt = None;
                    incoming.raw_tx = None;
                    incoming.error = None;
                    save_payment(data, pass, &incoming)?;
                }
                _ => {}
            }
        }
    }
    Ok(())
}

fn discover(
    url: &str,
    data: &Path,
    pass: &str,
    vault: &str,
    attempt: &str,
    v: &Vault,
) -> Result<Payment, String> {
    if let Ok(p) = read_payment(data, pass, vault, attempt) {
        return Ok(p);
    }
    sync_control(url, data, pass, vault, v)?;
    read_payment(data, pass, vault, attempt).map_err(|_| UNAVAILABLE.into())
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
    blocking(move || {
        let locked_st = st.clone();
        let _guard = locked_st.payment.lock().map_err(|e| e.to_string())?;
        f(st, data, pass, body)
    })
    .await
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
        let v = load_vault(&data, &pass, vault, &st.config.network)?;
        let (w, _, _) = wallet(&data, &pass, vault, &v, url(&st)?)?;
        Ok(json!({"balance_zat": w.ironwood_balance_zat()?}))
    })
    .await
}

pub(super) async fn draft(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    with_body(st, body, |st, data, pass, body| {
        let vault = required(&body, "vault")?;
        let v = load_vault(&data, &pass, vault, &st.config.network)?;
        let recipient = required(&body, "recipient")?;
        let address = vault::orchard_receiver_from_ua(recipient, v.network.network_type())?;
        let amount_zat: u64 = required(&body, "amount_zat")?.parse().map_err(|_| "invalid amount_zat")?;
        if amount_zat == 0 { return Err("amount must exceed zero".into()); }
        let amount = Zatoshis::from_u64(amount_zat).map_err(|e| format!("amount: {e:?}"))?;
        let memo = body["memo"].as_str().unwrap_or("");
        let memo_bytes = MemoBytes::from_bytes(memo.as_bytes()).map_err(|e| format!("memo: {e:?}"))?;
        let (mut w, _, _) = wallet(&data, &pass, vault, &v, url(&st)?)?;
        let tip = w.scanned_height()?.ok_or("wallet has no scanned blocks")?;
        // The candidate's target and anchor height, which signing and finish reread from
        // lightwalletd. Not the scanned tip: public endpoints such as zec.rocks balance each
        // request across backends whose tips differ by a block, so a later request can land on
        // one that has not reached it. The wallet funds only from notes with at least 3
        // confirmations (`ConfirmationsPolicy::default`), so the selected note is in the tree here.
        let anchor = tip.checked_sub(2).ok_or("wallet has too few scanned blocks")?;
        let expiry = tip.checked_add(match v.network { VaultNetwork::Regtest => 8_064, VaultNetwork::Testnet => 24_192 }).ok_or("expiry overflow")?.div_ceil(1_152).checked_mul(1_152).ok_or("expiry overflow")?;
        let funding = w.propose(address, Some(amount), memo_bytes.clone())?;
        let first = *funding.notes.first().ok_or("wallet proposed no Ironwood notes")?;
        let inputs = CandidateInputs { vault_fvk: &v.fvk, notes: vec![first], recipient: address, amount, memo: memo_bytes, change: Zatoshis::ZERO, target_height: anchor, expiry_height: expiry };
        let fee_zat: u64 = quote_fee(&v.network, &inputs)?.into();
        let note = funding.notes.iter().find(|note| note.value().inner() >= amount_zat.saturating_add(fee_zat))
            .ok_or("payment needs one Ironwood note large enough for amount and fee")?;
        let change_zat = note.value().inner().checked_sub(amount_zat).and_then(|n| n.checked_sub(fee_zat)).ok_or("note cannot cover amount and fee")?;
        if funding.notes.len() == 1 && (funding.fee_zat != fee_zat || funding.change_zat != change_zat) { return Err("wallet funding differs from candidate fee or change".into()); }
        let mut random = [0u8; 32]; OsRng.fill_bytes(&mut random);
        let attempt = hex::encode(random);
        let note_selection = vec![hex::encode(note.nullifier(&v.fvk).to_bytes())];
        // No signing group yet: the request is open to every member (`signing_group`).
        let p = Payment { attempt: attempt.clone(), vault: vault.to_owned(), proposer: v.slot, recipient: recipient.to_owned(), amount_zat, memo: memo.to_owned(), fee_zat, change_zat, note_selection, target_height: anchor, expiry_height: expiry, signers: Vec::new(), phase: "draft".into(), session_id: None, control_session_id: None, approvals: Vec::new(), start_requested: false, coordinator_secret: None, review_token: None, approval_requested: false, approval_started: false, txid: None, signed_pczt: None, raw_tx: None, error: None };
        check_intent(&p, &v)?;
        let nullifier = [hex32(&p.note_selection[0])?];
        w.reserve_inputs(zcash_client_backend::wallet::LockOwner::new(random), &nullifier, expiry)?;
        if let Err(e) = save_payment(&data, &pass, &p) { let _ = w.release_inputs(zcash_client_backend::wallet::LockOwner::new(random), &nullifier); return Err(e); }
        Ok(json!({"attempt":attempt,"fee_zat":fee_zat.to_string(),"change_zat":change_zat.to_string()}))
    }).await
}

pub(super) async fn publish(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    with_body(st, body, |st, data, pass, body| {
        let (vault, attempt) = pair(&body)?;
        let v = load_vault(&data, &pass, &vault, &st.config.network)?;
        let mut p = read_payment(&data, &pass, &vault, &attempt)?;
        if p.proposer != v.slot || p.phase != "draft" {
            return Err("only the proposer can publish a draft".into());
        }
        check_intent(&p, &v)?;
        let coord = Identity::new(0);
        let mut tx = relay(&coord, &st.config.frostd_url)?;
        // Every member joins both sessions: whoever approves first may end up signing.
        let peers = v
            .peers
            .values()
            .map(|peer| Peer(peer.encryption))
            .collect::<Vec<_>>();
        let ch = tx.open(&peers, 4).map_err(|e| e.to_string())?;
        p.session_id = Some(ch.session_id());
        p.coordinator_secret = Some(hex::encode(&*Zeroizing::new(coord.to_secret_bytes())));
        p.phase = "signing".into();
        let mut control = relay(&v.identity, &st.config.frostd_url)?;
        let control_ch = control.open(&peers, 4).map_err(|e| e.to_string())?;
        p.control_session_id = Some(control_ch.session_id());
        save_payment(&data, &pass, &p)?;
        send_control(&st.config.frostd_url, &v, &p, "intent", &members(&v))?;
        Ok(json!({"phase":p.phase,"session_id":p.session_id,"control_session_id":p.control_session_id}))
    })
    .await
}

pub(super) async fn review(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    with_body(st, body, |st, data, pass, body| {
        let (vault, attempt) = pair(&body)?;
        let v = load_vault(&data, &pass, &vault, &st.config.network)?;
        let mut p = discover(&st.config.frostd_url, &data, &pass, &vault, &attempt, &v)?;
        if p.phase != "signing" || p.session_id.is_none() || p.control_session_id.is_none() || p.error.is_some() { return Err("payment is not signing".into()); }
        check_intent(&p, &v)?;
        if p.approval_requested { return Err("payment approval already requested".into()); }
        if !p.signers.is_empty() && !p.signers.contains(&v.slot) { return Err(ENOUGH_APPROVED.into()); }
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
    blocking(move || {
        let guard = st.payment.lock().map_err(|e| e.to_string())?;
        let (vault, attempt) = pair(&body)?;
        let mut p = read_payment(&data, &pass, &vault, &attempt)?;
        if p.phase != "signing"
            || p.error.is_some()
            || p.control_session_id.is_none()
            || p.approval_requested
            || p.review_token.is_none()
            || p.review_token.as_deref() != body["review_token"].as_str()
        {
            return Err(
                "invalid or repeated payment approval; failed attempts need a new payment".into(),
            );
        }
        let v = load_vault(&data, &pass, &vault, &st.config.network)?;
        check_intent(&p, &v)?;
        if !p.signers.is_empty() && !p.signers.contains(&v.slot) {
            return Err(ENOUGH_APPROVED.into());
        }
        p.approval_requested = true;
        record_approval(&mut p, v.slot);
        p.review_token = None;
        save_payment(&data, &pass, &p)?;
        drop(guard);
        ensure_worker(&st, &data, &pass, &vault, &attempt)?;
        Ok(json!({"phase":"signing"}))
    })
    .await
}

fn ensure_worker(
    st: &Shared,
    data: &Path,
    pass: &str,
    vault: &str,
    attempt: &str,
) -> Result<(), String> {
    let guard = st.payment.lock().map_err(|e| e.to_string())?;
    let mut p = read_payment(data, pass, vault, attempt)?;
    if p.phase == "signing" && p.error.is_some() {
        p.phase = "failed".into();
        save_payment(data, pass, &p)?;
    }
    if p.phase != "signing" || !p.approval_requested {
        return Ok(());
    }
    let key = format!("{vault}/{attempt}");
    let mut active = st.active_payments.lock().map_err(|e| e.to_string())?;
    if active.contains(&key) {
        return Ok(());
    }
    if p.approval_started {
        p.phase = "failed".into();
        p.error = Some("Signing was interrupted. Keep this attempt for recovery; create a fresh payment after discarding it safely.".into());
        save_payment(data, pass, &p)?;
        if let Ok(v) = load_vault(data, pass, vault, &st.config.network) {
            if p.proposer == v.slot {
                let _ = send_control(&st.config.frostd_url, &v, &p, "failed", &members(&v));
            }
        }
        return Ok(());
    }
    active.insert(key.clone());
    drop(active);
    drop(guard);
    let st = st.clone();
    let data = data.to_owned();
    let pass = Zeroizing::new(pass.to_owned());
    let (vault, attempt) = (vault.to_owned(), attempt.to_owned());
    tokio::task::spawn_blocking(move || {
        let result = payment_worker(&st, &data, &pass, &vault, &attempt);
        let _guard = st.payment.lock().unwrap();
        if let Err(error) = result {
            if let Ok(mut p) = read_payment(&data, &pass, &vault, &attempt) {
                if p.phase == "signing" {
                    p.phase = "failed".into();
                    p.error = Some(error);
                    let _ = save_payment(&data, &pass, &p);
                    if let Ok(v) = load_vault(&data, &pass, &vault, &st.config.network) {
                        if p.proposer == v.slot {
                            let _ =
                                send_control(&st.config.frostd_url, &v, &p, "failed", &members(&v));
                        }
                    }
                }
            }
        }
        st.active_payments.lock().unwrap().remove(&key);
    });
    Ok(())
}

fn payment_worker(
    st: &Shared,
    data: &Path,
    pass: &str,
    vault: &str,
    attempt: &str,
) -> Result<(), String> {
    let v = load_vault(data, pass, vault, &st.config.network)?;
    let mut last_notice = std::time::Instant::now() - Duration::from_secs(5);
    let p = loop {
        if st.session.blocking_read().is_none() {
            return Ok(());
        }
        let guard = st.payment.lock().map_err(|e| e.to_string())?;
        // A relay outage while waiting for people is retried before any nonce exists.
        let _ = sync_control(&st.config.frostd_url, data, pass, vault, &v);
        let mut p = read_payment(data, pass, vault, attempt)?;
        if p.phase != "signing" || p.error.is_some() {
            return Ok(());
        }
        if p.proposer == v.slot && p.signers.is_empty() {
            if let Some(group) = signing_group(&p, &v) {
                // Saved before any nonce exists, so a restart signs with the same group.
                p.signers = group;
                save_payment(data, pass, &p)?;
            }
        }
        if p.proposer == v.slot && !p.signers.is_empty() || p.proposer != v.slot && p.start_requested {
            break p;
        }
        drop(guard);
        if last_notice.elapsed() >= Duration::from_secs(3) {
            if v.slot == p.proposer {
                let _ = send_control(&st.config.frostd_url, &v, &p, "intent", &members(&v));
            } else {
                let _ = send_control(&st.config.frostd_url, &v, &p, "approval", &[p.proposer]);
            }
            last_notice = std::time::Instant::now();
        }
        std::thread::sleep(Duration::from_millis(300));
    };
    // Wallet synchronization and candidate inputs precede the bounded protocol round.
    let owned = prepare_sign(st, data, pass, &p, &v)?;
    {
        let _guard = st.payment.lock().map_err(|e| e.to_string())?;
        let mut local = read_payment(data, pass, vault, attempt)?;
        if local.phase != "signing" || local.approval_started {
            return Err("payment cannot start again".into());
        }
        local.approval_started = true;
        save_payment(data, pass, &local)?;
    }
    if p.proposer == v.slot {
        // Every member hears the group: those outside it stop waiting to sign.
        send_control(&st.config.frostd_url, &v, &p, "start", &members(&v))?;
        let signed = std::thread::scope(|scope| {
            let coordinator = scope.spawn(|| aggregate(st, data, pass, &p, &v));
            let signer_result = sign(st, data, pass, &p, &v, owned);
            let signed = coordinator
                .join()
                .map_err(|_| "payment coordinator panicked".to_owned())??;
            signer_result?;
            Ok::<_, String>(signed)
        })?;
        let _guard = st.payment.lock().map_err(|e| e.to_string())?;
        let mut local = read_payment(data, pass, vault, attempt)?;
        local.signed_pczt = Some(hex::encode(signed));
        if local.phase == "signing" && local.error.is_none() {
            local.phase = "ready".into();
        }
        save_payment(data, pass, &local)?;
    } else {
        sign(st, data, pass, &p, &v, owned)?;
        let _guard = st.payment.lock().map_err(|e| e.to_string())?;
        let mut local = read_payment(data, pass, vault, attempt)?;
        if local.phase == "signing" && local.error.is_none() {
            local.phase = "approved".into();
        }
        save_payment(data, pass, &local)?;
    }
    Ok(())
}

fn prepare_sign<'a>(
    st: &Shared,
    data: &Path,
    pass: &str,
    p: &Payment,
    v: &'a Vault,
) -> Result<Option<CandidateInputs<'a>>, String> {
    let mut owned = None;
    if p.proposer == v.slot {
        let (w, mut client, rt) = wallet(data, pass, &p.vault, v, url(st)?)?;
        // Select the candidate's input notes at its fixed draft height (target_height), so the
        // proposer rebuilds the same candidate the quorum reviewed; the witness here is unused.
        let height = p.target_height;
        let (frontier, _) = frontier(&w, &mut client, &rt, height)?;
        let selected = [hex32(&p.note_selection[0])?];
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
    Ok(owned)
}

fn sign(
    st: &Shared,
    data: &Path,
    pass: &str,
    p: &Payment,
    v: &Vault,
    owned: Option<CandidateInputs<'_>>,
) -> Result<(), String> {
    let mut tx = relay(&v.identity, &st.config.frostd_url)?;
    let ch = tx
        .join(p.session_id.ok_or("missing signing session")?)
        .map_err(|e| e.to_string())?;
    let signer_network = match v.network {
        VaultNetwork::Regtest => Network::Regtest,
        VaultNetwork::Testnet => Network::Testnet,
    };
    let mut signer = LocalSigner::with_sealed_share(
        v.slot,
        v.threshold,
        v.peers.len() as u16,
        hex32(&p.vault)?,
        p.vault.clone(),
        signer_network,
        SoftwareSecureElement::generate(),
        &v.key.serialize().map_err(|e| e.to_string())?,
        v.public.serialize().map_err(|e| e.to_string())?,
        v.fvk.clone(),
        member_dir(data, &p.vault)?.path().join("signer-nonces"),
        Box::new(|_| true),
    )
    .map_err(|e| e.to_string())?;
    if let Some(inputs) = &owned {
        signer.set_candidate_notes(inputs.notes.clone());
    }
    let session = signer
        .connect("hosted payment", signer_network, p.attempt.as_bytes())
        .map_err(|e| e.to_string())?
        .session;
    let candidate = CandidateRef {
        vault_id: hex32(&p.vault)?,
        payment_id: hex32(&p.attempt)?,
        attempt_id: hex32(&p.attempt)?,
    };
    let params = owned.as_ref().map(|inputs| PublicPaymentParams {
        recipient: inputs.recipient,
        amount: inputs.amount,
        memo: inputs.memo.clone(),
        target_height: inputs.target_height,
        expiry_height: inputs.expiry_height,
    });
    let other_signers = p
        .signers
        .iter()
        .filter(|id| **id != v.slot)
        .map(|id| v.peers[id].clone())
        .collect::<Vec<_>>();
    let context = signing_context(p)?;
    let dir = member_dir(data, &p.vault)?;
    let proposer = p.proposer == v.slot;
    if proposer {
        // A retry builds a new candidate under a new randomizer; never hand over a stale one.
        match std::fs::remove_file(dir.path().join(candidate_file(&p.attempt))) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => {
                return Err(format!("clear stale candidate: {e}"))
            }
            _ => {}
        }
    }
    signer_loop(
        &tx,
        &ch,
        &mut signer,
        &session,
        &candidate,
        &v.public,
        frost::Identifier::try_from(v.slot).map_err(|e| e.to_string())?,
        params.as_ref(),
        &v.identity,
        &context,
        &v.peers[&p.proposer],
        &other_signers,
        &mut |bytes| {
            review_candidate(bytes, p, v)?;
            // The background coordinator runs in this process; hand it the candidate through
            // the encrypted member store instead of the relay.
            if proposer {
                dir.write_sealed(&candidate_file(&p.attempt), bytes, pass)
                    .map_err(|e| format!("save candidate: {e}"))?;
            }
            Ok(())
        },
    )
}

/// The proposer's encrypted local hand-off of its candidate to its own coordinator.
fn candidate_file(attempt: &str) -> String {
    format!("candidate-{attempt}.sealed")
}

/// The sealed-envelope context of one hosted signing attempt.
fn signing_context(p: &Payment) -> Result<SessionContext, String> {
    let mut signers = p.signers.clone();
    signers.sort_unstable();
    Ok(SessionContext {
        vault: hex32(&p.vault)?,
        payment: hex32(&p.attempt)?,
        attempt: AttemptId(hex32(&p.attempt)?),
        signers,
    })
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

fn aggregate(
    st: &Shared,
    data: &Path,
    pass: &str,
    p: &Payment,
    v: &Vault,
) -> Result<Vec<u8>, String> {
    let coord = Identity::from_secret_bytes(
        &hex::decode(
            p.coordinator_secret
                .as_deref()
                .ok_or("missing coordinator identity")?,
        )
        .map_err(|e| e.to_string())?,
    )?;
    let mut tx = relay(&coord, &st.config.frostd_url)?;
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
        .map(|(slot, id)| (*id, Peer(v.peers[slot].encryption)))
        .collect();
    let dir = member_dir(data, &p.vault)?;
    let file = candidate_file(&p.attempt);
    let signed = coordinate(
        &tx,
        &ch,
        &v.public,
        &ids,
        &peer_of,
        v.threshold,
        OsRng,
        || match dir.read_sealed(&file, pass) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(format!("read candidate: {e}")),
        },
    )?;
    let _ = tx.close(ch);
    Ok(signed)
}

struct ActivePayment<'a> {
    st: &'a Shared,
    key: String,
}
impl Drop for ActivePayment<'_> {
    fn drop(&mut self) {
        self.st.active_payments.lock().unwrap().remove(&self.key);
    }
}

pub(super) async fn finish(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    let (data, pass) = match unlocked(&st).await {
        Ok(x) => x,
        Err(e) => return e,
    };
    blocking(move || {
        let (vault, attempt) = pair(&body)?;
        let v = load_vault(&data, &pass, &vault, &st.config.network)?;
        let key = format!("{vault}/{attempt}");
        if !st
            .active_payments
            .lock()
            .map_err(|e| e.to_string())?
            .insert(key.clone())
        {
            return Err("payment work is already running".into());
        }
        let _active = ActivePayment { st: &st, key };
        let mut p = read_payment(&data, &pass, &vault, &attempt)?;
        if p.proposer != v.slot || p.phase != "ready" {
            return Err("only the proposer can send a ready payment".into());
        }
        check_intent(&p, &v)?;
        if !ready_to_send(&p) {
            return Err("signer approvals are not ready".into());
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
            let selected = [hex32(&p.note_selection[0])?];
            let witness = w
                .ironwood_inputs_at(BlockHeight::from_u32(height), tree, &selected)?
                .into_iter()
                .next()
                .ok_or("missing payment note")?
                .1;
            let index = pczt
                .ironwood()
                .actions()
                .iter()
                .position(|a| a.spend().nullifier() == &selected[0])
                .ok_or("signed candidate spends a different note")?;
            let (raw, txid) = prove(pczt, sighash, vec![(index, witness)], anchor)?;
            p.raw_tx = Some(hex::encode(raw));
            p.txid = Some(txid.to_string());
            let _guard = st.payment.lock().map_err(|e| e.to_string())?;
            save_payment(&data, &pass, &p)?;
        }
        {
            let _guard = st.payment.lock().map_err(|e| e.to_string())?;
            let txid = zcash_primitives::transaction::TxId::from_hex(
                p.txid.as_deref().ok_or("missing transaction id")?,
            )
            .ok_or("invalid transaction id")?;
            w.transfer_inputs(
                zcash_client_backend::wallet::LockOwner::new(hex32(&attempt)?),
                txid.into(),
                &[hex32(&p.note_selection[0])?],
                p.expiry_height,
            )?;
        }
        let raw = hex::decode(p.raw_tx.as_deref().ok_or("missing raw transaction")?)
            .map_err(|e| e.to_string())?;
        // shortcut: an ambiguous send error keeps the raw transaction for retry; add mempool reconciliation before reporting duplicate broadcasts as failures.
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
        {
            let _guard = st.payment.lock().map_err(|e| e.to_string())?;
            save_payment(&data, &pass, &p)?;
        }
        let _ = send_control(&st.config.frostd_url, &v, &p, "broadcast", &members(&v));
        let _ = std::fs::remove_file(
            member_dir(&data, &vault)?
                .path()
                .join(candidate_file(&attempt)),
        );
        Ok(json!({"phase":"broadcast","txid":p.txid}))
    })
    .await
}

pub(super) async fn verify(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    with_body(st, body, |st, data, pass, body| {
        let (vault, attempt) = pair(&body)?;
        let v = load_vault(&data, &pass, &vault, &st.config.network)?;
        let mut p = read_payment(&data, &pass, &vault, &attempt)?;
        let txid = required(&body, "txid")?;
        if !matches!(p.phase.as_str(), "broadcast" | "confirmed") || p.txid.as_deref() != Some(txid)
        {
            return Err("txid differs from broadcast payment".into());
        }
        let id = zcash_primitives::transaction::TxId::from_hex(txid).ok_or("invalid txid")?;
        let (w, _, _) = wallet(&data, &pass, &vault, &v, url(&st)?)?;
        let mined_height = w.mined_height(id)?;
        p.phase = if mined_height.is_some() {
            "confirmed"
        } else {
            "broadcast"
        }
        .into();
        save_payment(&data, &pass, &p)?;
        let _ = send_control(&st.config.frostd_url, &v, &p, &p.phase, &members(&v));
        Ok(json!({"phase":p.phase,"mined_height":mined_height.map(u32::from)}))
    })
    .await
}

fn local_attempts(data: &Path, vault: &str) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(payment_dir(data, vault)?.path()).map_err(|e| e.to_string())? {
        let name = entry
            .map_err(|e| e.to_string())?
            .file_name()
            .to_string_lossy()
            .into_owned();
        if let Some(attempt) = name.strip_suffix(".json").filter(|s| hex32(s).is_ok()) {
            out.push(attempt.to_owned());
        }
    }
    Ok(out)
}

fn restore_workers(st: &Shared, data: &Path, pass: &str, vault: &str) -> Result<(), String> {
    for attempt in local_attempts(data, vault)? {
        ensure_worker(st, data, pass, vault, &attempt)?;
    }
    Ok(())
}

fn discardable(data: &Path, p: &Payment) -> Result<(), String> {
    // No nonce exists before the proposer's worker marks `approval_started`; after it, one may
    // be in use, so a request can be cancelled only while it is still collecting approvals.
    if p.phase == "signing" && p.approval_started {
        return Err("signing already started; this payment can no longer be cancelled".into());
    }
    let open = p.phase == "signing" && p.error.is_none();
    if !open && !matches!(p.phase.as_str(), "failed" | "discarding" | "draft")
        || p.signed_pczt.is_some()
        || p.raw_tx.is_some()
        || p.txid.is_some()
    {
        return Err("only an open request, a failed unsigned payment or a draft can be discarded".into());
    }
    let burn = member_dir(data, &p.vault)?
        .path()
        .join("signer-nonces")
        .join(format!("{}{}.burn", p.attempt, p.attempt));
    if burn.try_exists().map_err(|e| e.to_string())? {
        return Err("a signature share was released; keep the input reserved for recovery".into());
    }
    Ok(())
}

fn close_if_present(tx: &mut FrostdTransport, session: Uuid) -> Result<(), String> {
    if tx
        .list_sessions()
        .map_err(|e| e.to_string())?
        .contains(&session)
    {
        let ch = tx.join(session).map_err(|e| e.to_string())?;
        tx.close(ch).map_err(|e| e.to_string())?;
    }
    Ok(())
}

/// Everything a discard does before releasing the note. Runs under `st.payment`. An open
/// request is cancelled even while the proposer's worker waits for approvals: the worker takes
/// the same lock to mark `approval_started` and stops once the phase is no longer `signing`.
fn stop_payment(
    st: &Shared,
    data: &Path,
    pass: &str,
    v: &Vault,
    p: &mut Payment,
) -> Result<(), String> {
    if p.proposer != v.slot {
        return Err("only the proposer can discard a payment".into());
    }
    if p.phase == "signing" && p.error.is_some() {
        p.phase = "failed".into();
    }
    discardable(data, p)?;
    // Published and not failed: an open request, or a cancel interrupted after `discarding`.
    let cancel = p.error.is_none() && p.control_session_id.is_some();
    if !cancel
        && st
            .active_payments
            .lock()
            .map_err(|e| e.to_string())?
            .contains(&format!("{}/{}", p.vault, p.attempt))
    {
        return Err("payment worker is still running".into());
    }
    p.phase = "discarding".into();
    save_payment(data, pass, p)?;
    if cancel {
        // Sent before the session ids change: members match it against their copy.
        send_control(&st.config.frostd_url, v, p, "cancelled", &members(v))?;
    }
    if let Some(session) = p.session_id {
        let coord = Identity::from_secret_bytes(
            &hex::decode(
                p.coordinator_secret
                    .as_deref()
                    .ok_or("missing coordinator identity")?,
            )
            .map_err(|e| e.to_string())?,
        )?;
        let mut tx = relay(&coord, &st.config.frostd_url)?;
        close_if_present(&mut tx, session)?;
        p.session_id = None;
        save_payment(data, pass, p)?;
    }
    // A cancelled request keeps its control session: closing it would drop the notice for
    // members who have not read it yet. frostd expires the session once it is idle.
    if let Some(session) = p.control_session_id.filter(|_| !cancel) {
        let mut tx = relay(&v.identity, &st.config.frostd_url)?;
        close_if_present(&mut tx, session)?;
        p.control_session_id = None;
        save_payment(data, pass, p)?;
    }
    Ok(())
}

/// Discards a draft or a failed unsigned payment, or cancels a request still collecting
/// approvals, and releases its reserved note.
pub(super) async fn discard(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    with_body(st, body, |st, data, pass, body| {
        let (vault, attempt) = pair(&body)?;
        let v = load_vault(&data, &pass, &vault, &st.config.network)?;
        let mut p = read_payment(&data, &pass, &vault, &attempt)?;
        stop_payment(&st, &data, &pass, &v, &mut p)?;
        let (mut w, _, _) = wallet(&data, &pass, &vault, &v, url(&st)?)?;
        w.release_inputs(
            zcash_client_backend::wallet::LockOwner::new(hex32(&attempt)?),
            &[hex32(&p.note_selection[0])?],
        )?;
        p.phase = "cancelled".into();
        save_payment(&data, &pass, &p)?;
        Ok(json!({"phase":"cancelled"}))
    })
    .await
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
        let v = load_vault(&data, &pass, &vault, &st.config.network)?;
        restore_workers(&st, &data, &pass, &vault)?;
        let _guard = st.payment.lock().map_err(|e| e.to_string())?;
        let _ = sync_control(&st.config.frostd_url, &data, &pass, &vault, &v);
        let dir = payment_dir(&data, &vault)?;
        let mut out = Vec::new();
        for entry in std::fs::read_dir(dir.path()).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(attempt) = name.strip_suffix(".json") else { continue };
            if hex32(attempt).is_err() { continue; }
            let p = read_payment(&data, &pass, &vault, attempt)?;
            let ready = ready_to_send(&p);
            out.push(json!({"attempt":p.attempt,"phase":p.phase,"recipient":p.recipient,"amount_zat":p.amount_zat.to_string(),"ready_to_send":ready && p.proposer == v.slot,"txid":if matches!(p.phase.as_str(), "broadcast" | "confirmed") {p.txid.clone()} else {None},"signers":p.signers,"approvals":p.approvals,"approval_requested":p.approval_requested,"finish_requested":st.active_payments.lock().map_err(|e| e.to_string())?.contains(&format!("{}/{}",p.vault,p.attempt)) && p.phase=="ready","can_discard":p.proposer==v.slot && discardable(&data,&p).is_ok(),"fee_zat":p.fee_zat.to_string(),"error":p.error}));
        }
        Ok(json!({"payments":out}))
    }).await
}

/// A co-signer's approval inbox: payments in this member's local store that another member
/// proposed, that are still open to this member, and that it has not yet approved.
fn pending_for(data: &Path, pass: &str, vault: &str, slot: u16) -> Result<Vec<Value>, String> {
    let dir = payment_dir(data, vault)?;
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir.path()).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(attempt) = name.strip_suffix(".json") else {
            continue;
        };
        if hex32(attempt).is_err() {
            continue;
        }
        let p = read_payment(data, pass, vault, attempt)?;
        if p.phase == "signing"
            && p.proposer != slot
            && (p.signers.is_empty() || p.signers.contains(&slot))
            && !p.approval_requested
            && p.error.is_none()
        {
            out.push(json!({"attempt":p.attempt,"amount_zat":p.amount_zat.to_string(),"recipient":p.recipient,"proposer":p.proposer}));
        }
    }
    Ok(out)
}

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
        // load_vault authorizes the caller as a member of this vault before listing anything.
        let v = load_vault(&data, &pass, &vault, &st.config.network)?;
        restore_workers(&st, &data, &pass, &vault)?;
        let _guard = st.payment.lock().map_err(|e| e.to_string())?;
        sync_control(&st.config.frostd_url, &data, &pass, &vault, &v)?;
        Ok(json!({"pending": pending_for(&data, &pass, &vault, v.slot)?}))
    })
    .await
}

/// A payment's current status for the UI (replaces the removed UI-facing payment-session GET):
/// the sealed intent this member already holds locally, plus live signer readiness.
pub(super) async fn status(
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
        let v = load_vault(&data, &pass, &vault, &st.config.network)?;
        ensure_worker(&st, &data, &pass, &vault, &attempt)?;
        let _guard = st.payment.lock().map_err(|e| e.to_string())?;
        let _ = sync_control(&st.config.frostd_url, &data, &pass, &vault, &v);
        let p = read_payment(&data, &pass, &vault, &attempt)?;
        let ready = ready_to_send(&p);
        Ok(json!({
            "phase": p.phase,
            "finish_requested": p.phase == "ready" && st.active_payments.lock().map_err(|e| e.to_string())?.contains(&format!("{vault}/{attempt}")),
            "approvals":p.approvals,"error":p.error,"approval_requested":p.approval_requested,
            "signatures_received": ready,
            "intent": {
                "proposer": p.proposer,
                "signers": p.signers,
                "recipient": p.recipient,
                "amount_zat": p.amount_zat,
                "fee_zat": p.fee_zat,
                "open_approval": p.signers.is_empty(),
            },
        }))
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

    #[test]
    fn signer_reviews_candidate_effects_before_signing() {
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
            VaultNetwork::Testnet.network_type(),
        );
        let mut inputs = CandidateInputs {
            vault_fvk: &fvk,
            notes: vec![note],
            recipient: to,
            amount: Zatoshis::const_from_u64(40_000_000),
            memo: MemoBytes::from_bytes(b"reviewed memo").unwrap(),
            change: Zatoshis::ZERO,
            target_height: TESTNET_NU7_BIRTH + 1,
            expiry_height: TESTNET_NU7_BIRTH + 1_152,
        };
        let fee_zat: u64 = quote_fee(&VaultNetwork::Testnet, &inputs).unwrap().into();
        let change_zat = 625_000_000 - 40_000_000 - fee_zat;
        inputs.change = Zatoshis::from_u64(change_zat).unwrap();
        let built = crate::candidate::build_candidate(
            &VaultNetwork::Testnet,
            &inputs,
            &[pallas::Scalar::from(3)],
            rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng),
        )
        .unwrap();
        let pczt = pczt::roles::creator::Creator::build_from_parts(built.pczt_parts)
            .unwrap()
            .serialize()
            .unwrap();
        let identity = Identity::new(1);
        let v = Vault {
            network: VaultNetwork::Testnet,
            fvk,
            key,
            public,
            identity,
            threshold: 2,
            slot: 1,
            peers: BTreeMap::new(),
            birth_height: TESTNET_NU7_BIRTH,
        };
        let mut p = Payment {
            attempt: hex::encode([1u8; 32]),
            vault: hex::encode([2u8; 32]),
            proposer: 1,
            recipient,
            amount_zat: 40_000_000,
            memo: "reviewed memo".into(),
            fee_zat,
            change_zat,
            note_selection: vec![hex::encode(note.nullifier(&v.fvk).to_bytes())],
            target_height: TESTNET_NU7_BIRTH + 1,
            expiry_height: TESTNET_NU7_BIRTH + 1_152,
            signers: vec![1, 2],
            phase: "signing".into(),
            session_id: None,
            control_session_id: None,
            approvals: Vec::new(),
            start_requested: false,
            coordinator_secret: None,
            review_token: None,
            approval_requested: false,
            approval_started: false,
            txid: None,
            signed_pczt: None,
            raw_tx: None,
            error: None,
        };
        review_candidate(&pczt, &p, &v).unwrap();
        p.amount_zat += 1;
        assert!(review_candidate(&pczt, &p, &v).is_err());
    }

    /// A vault member's view: a share of a throwaway 2-of-3 key plus the roster.
    fn member(identity: &Identity, peers: &BTreeMap<u16, PublicIdentity>) -> Vault {
        let (shares, public) = frost::keys::generate_with_dealer(
            3,
            2,
            frost::keys::IdentifierList::Default,
            &mut OsRng,
        )
        .unwrap();
        let key = frost::keys::KeyPackage::try_from(shares.into_values().next().unwrap()).unwrap();
        let ak: [u8; 32] = public
            .verifying_key()
            .serialize()
            .unwrap()
            .try_into()
            .unwrap();
        Vault {
            network: VaultNetwork::Testnet,
            fvk: zip2005::frost_viewing_key(&ak, &[42u8; 32]).unwrap(),
            key,
            public,
            identity: Identity::from_secret_bytes(&identity.to_secret_bytes()).unwrap(),
            threshold: 2,
            slot: identity.public().id,
            peers: peers.clone(),
            birth_height: TESTNET_NU7_BIRTH,
        }
    }

    /// A request no member has acted on yet: proposed by `proposer`, open to every member.
    fn open_payment(vault: &str, proposer: u16) -> Payment {
        Payment {
            attempt: hex::encode([1; 32]),
            vault: vault.to_owned(),
            proposer,
            recipient: "uregtest1recipient".into(),
            amount_zat: 100_000,
            memo: "private control notice".into(),
            fee_zat: 10_000,
            change_zat: 1,
            note_selection: vec![hex::encode([5; 32])],
            target_height: TESTNET_NU7_BIRTH + 1,
            expiry_height: TESTNET_NU7_BIRTH + 1152,
            signers: Vec::new(),
            phase: "signing".into(),
            session_id: None,
            control_session_id: None,
            approvals: Vec::new(),
            start_requested: false,
            coordinator_secret: None,
            review_token: None,
            approval_requested: false,
            approval_started: false,
            txid: None,
            signed_pczt: None,
            raw_tx: None,
            error: None,
        }
    }

    fn state(data: &Path, frostd_url: &str) -> Shared {
        use crate::host::state::{AppState, Config};
        std::sync::Arc::new(AppState::new(Config {
            registration: None,
            data: data.to_owned(),
            port: 0,
            bind: "127.0.0.1".parse().unwrap(),
            advertise_url: None,
            network: "testnet".into(),
            lightwalletd: None,
            transport: "frostd".into(),
            secure_element: "software".into(),
            operator_bundle: None,
            nonce_witnesses: None,
            operator_key: None,
            enrollment_issuer: None,
            development_http: true,
            token: "disposable".into(),
            frostd_url: frostd_url.into(),
            peers: BTreeMap::new(),
            loopback_peers: true,
        }))
    }

    #[test]
    fn cancel_is_refused_once_signing_started_or_a_share_was_released() {
        let data = std::env::temp_dir().join(format!("loki-cancel-refused-{}", Uuid::new_v4()));
        let identities: Vec<_> = (1..=3).map(Identity::new).collect();
        let peers: BTreeMap<_, _> = identities
            .iter()
            .map(|i| (i.public().id, i.public()))
            .collect();
        let a = member(&identities[0], &peers);
        let b = member(&identities[1], &peers);
        // Every refusal comes before frostd is contacted, so no relay is needed.
        let st = state(&data, "http://127.0.0.1:9");
        let vault = hex::encode([2; 32]);
        let mut p = open_payment(&vault, 1);
        p.session_id = Some(Uuid::new_v4());
        p.control_session_id = Some(Uuid::new_v4());
        p.approval_requested = true;
        p.approvals = vec![1, 2];
        // The group is fixed and the worker prepares outside the lock: still cancellable.
        p.signers = vec![1, 2];
        st.active_payments
            .lock()
            .unwrap()
            .insert(format!("{vault}/{}", p.attempt));
        assert!(discardable(&data, &p).is_ok());
        let refused = |p: &Payment, v: &Vault, reason: &str| {
            save_payment(&data, "pass", p).unwrap();
            let error = stop_payment(&st, &data, "pass", v, &mut p.clone()).unwrap_err();
            assert!(error.contains(reason), "{error}");
            let saved = read_payment(&data, "pass", &vault, &p.attempt).unwrap();
            assert_eq!(saved.phase, "signing");
            assert_eq!(saved.session_id, p.session_id);
        };
        refused(&p, &b, "only the proposer");
        // Once the worker marked `approval_started` under the lock, nonces may be in use.
        p.approval_started = true;
        assert!(discardable(&data, &p).is_err());
        refused(&p, &a, "signing already started");
        p.approval_started = false;
        let nonce_dir = member_dir(&data, &vault)
            .unwrap()
            .path()
            .join("signer-nonces");
        std::fs::create_dir_all(&nonce_dir).unwrap();
        std::fs::write(
            nonce_dir.join(format!("{}{}.burn", p.attempt, p.attempt)),
            b"burned",
        )
        .unwrap();
        assert!(discardable(&data, &p).is_err());
        refused(&p, &a, "signature share was released");
        std::fs::remove_dir_all(data).unwrap();
    }

    #[test]
    fn testnet_proposer_cancels_an_open_request_and_every_member_drops_it() {
        let Ok(url) = std::env::var("FROSTD_URL") else {
            return;
        };
        let identities: Vec<_> = (1..=4).map(Identity::new).collect();
        let peers: BTreeMap<_, _> = identities
            .iter()
            .map(|i| (i.public().id, i.public()))
            .collect();
        let m: Vec<_> = identities.iter().map(|i| member(i, &peers)).collect();
        let dirs: Vec<_> = (0..4)
            .map(|_| std::env::temp_dir().join(format!("loki-cancel-{}", Uuid::new_v4())))
            .collect();
        let vault = hex::encode([2; 32]);
        let mut p = open_payment(&vault, 1);
        p.recipient = vault::unified_address(&m[0].fvk, m[0].network.network_type());
        let everyone: Vec<_> = peers.values().map(|m| Peer(m.encryption)).collect();
        let coord = Identity::new(0);
        let mut signing = relay(&coord, &url).unwrap();
        let signing_ch = signing.open(&everyone, 4).unwrap();
        p.session_id = Some(signing_ch.session_id());
        p.coordinator_secret = Some(hex::encode(coord.to_secret_bytes()));
        let mut control = relay(&m[0].identity, &url).unwrap();
        let control_ch = control.open(&everyone, 4).unwrap();
        p.control_session_id = Some(control_ch.session_id());
        // The proposer approved and its worker waits for one more approval.
        p.approval_requested = true;
        record_approval(&mut p, 1);
        save_payment(&dirs[0], "pass", &p).unwrap();
        let st = state(&dirs[0], &url);
        st.active_payments
            .lock()
            .unwrap()
            .insert(format!("{vault}/{}", p.attempt));
        send_control(&url, &m[0], &p, "intent", &members(&m[0])).unwrap();
        for i in 1..4 {
            sync_control(&url, &dirs[i], "pass", &vault, &m[i]).unwrap();
            assert_eq!(pending_for(&dirs[i], "pass", &vault, m[i].slot).unwrap().len(), 1);
        }
        // Member 2 approved and waits for the group. Member 4's copy stands in for a member
        // left outside a group.
        let mut local = read_payment(&dirs[1], "pass", &vault, &p.attempt).unwrap();
        local.approval_requested = true;
        record_approval(&mut local, 2);
        save_payment(&dirs[1], "pass", &local).unwrap();
        local = read_payment(&dirs[3], "pass", &vault, &p.attempt).unwrap();
        local.phase = "not_selected".into();
        save_payment(&dirs[3], "pass", &local).unwrap();

        // Only the proposer can cancel its request.
        send_control(&url, &m[1], &p, "cancelled", &members(&m[1])).unwrap();
        for i in 2..4 {
            sync_control(&url, &dirs[i], "pass", &vault, &m[i]).unwrap();
        }
        assert_eq!(pending_for(&dirs[2], "pass", &vault, 3).unwrap().len(), 1);
        assert_eq!(
            read_payment(&dirs[3], "pass", &vault, &p.attempt)
                .unwrap()
                .phase,
            "not_selected"
        );

        stop_payment(&st, &dirs[0], "pass", &m[0], &mut p).unwrap();
        // The waiting worker rereads this under the lock before it marks `approval_started`.
        let proposer = read_payment(&dirs[0], "pass", &vault, &p.attempt).unwrap();
        assert_eq!(proposer.phase, "discarding");
        assert!(proposer.session_id.is_none());
        assert!(!signing
            .list_sessions()
            .unwrap()
            .contains(&signing_ch.session_id()));
        for i in 1..4 {
            sync_control(&url, &dirs[i], "pass", &vault, &m[i]).unwrap();
            let copy = read_payment(&dirs[i], "pass", &vault, &p.attempt).unwrap();
            assert_eq!(copy.phase, "cancelled", "member {}", m[i].slot);
            assert!(pending_for(&dirs[i], "pass", &vault, m[i].slot)
                .unwrap()
                .is_empty());
        }
        close_if_present(&mut control, control_ch.session_id()).unwrap();
        for data in dirs {
            let _ = std::fs::remove_dir_all(data);
        }
    }

    #[test]
    fn signing_group_is_the_proposer_and_the_first_other_approvers() {
        let identities: Vec<_> = (1..=5).map(Identity::new).collect();
        let peers: BTreeMap<_, _> = identities
            .iter()
            .map(|i| (i.public().id, i.public()))
            .collect();
        let mut v = member(&identities[1], &peers);
        let mut p = open_payment(&hex::encode([2; 32]), 2);
        // Arrival order decides, not slot numbers; the proposer must approve too.
        for (threshold, approvals, group) in [
            (2, vec![], None),
            (2, vec![3, 1], None),
            (2, vec![3, 2, 1], Some(vec![2, 3])),
            (2, vec![9, 2, 4], Some(vec![2, 4])),
            (3, vec![5, 2], None),
            (3, vec![5, 2, 1, 3], Some(vec![2, 5, 1])),
        ] {
            v.threshold = threshold;
            p.approvals = approvals;
            assert_eq!(signing_group(&p, &v), group, "{:?}", p.approvals);
            if let Some(group) = group {
                p.signers = group;
                check_signers(&p, &v).unwrap();
            }
        }
        for invalid in [vec![5, 2, 1], vec![2, 5, 5], vec![2, 5], vec![2, 5, 9]] {
            p.signers = invalid;
            assert!(check_signers(&p, &v).is_err(), "{:?}", p.signers);
        }
    }

    #[test]
    fn testnet_control_opens_requests_to_every_member_and_signs_with_the_first_approvers() {
        let Ok(url) = std::env::var("FROSTD_URL") else {
            return;
        };
        let identities: Vec<_> = (1..=3).map(Identity::new).collect();
        let peers: BTreeMap<_, _> = identities
            .iter()
            .map(|i| (i.public().id, i.public()))
            .collect();
        let a = member(&identities[0], &peers);
        let b = member(&identities[1], &peers);
        let c = member(&identities[2], &peers);
        let stranger = member(&Identity::new(4), &peers);
        let dirs: Vec<_> = (0..4)
            .map(|_| std::env::temp_dir().join(format!("loki-control-{}", Uuid::new_v4())))
            .collect();
        let (data_a, data_b, data_c) = (&dirs[0], &dirs[1], &dirs[2]);
        let vault = hex::encode([2; 32]);
        let mut p = open_payment(&vault, 1);
        p.recipient = vault::unified_address(&a.fvk, a.network.network_type());
        let everyone: Vec<_> = peers.values().map(|m| Peer(m.encryption)).collect();
        let coord = Identity::new(0);
        let mut signing = relay(&coord, &url).unwrap();
        let signing_ch = signing.open(&everyone, 4).unwrap();
        p.session_id = Some(signing_ch.session_id());
        let mut control = relay(&a.identity, &url).unwrap();
        let control_ch = control.open(&everyone, 4).unwrap();
        p.control_session_id = Some(control_ch.session_id());
        save_payment(data_a, "pass", &p).unwrap();
        send_control(&url, &a, &p, "intent", &members(&a)).unwrap();
        let mut second = p.clone();
        second.attempt = hex::encode([8; 32]);
        let control_ch2 = control.open(&everyone, 4).unwrap();
        second.control_session_id = Some(control_ch2.session_id());
        send_control(&url, &a, &second, "intent", &members(&a)).unwrap();
        signing
            .send(
                &signing_ch,
                &[Peer(peers[&2].encryption)],
                &Outbound::RandomizerSeed([7; 32]),
            )
            .unwrap();
        // Every member, not a preselected pair, can approve the request.
        for (data, m) in [(data_b, &b), (data_c, &c)] {
            sync_control(&url, data, "pass", &vault, m).unwrap();
            assert_eq!(pending_for(data, "pass", &vault, m.slot).unwrap().len(), 2);
        }
        let mut receiver = relay(&b.identity, &url).unwrap();
        let ch = receiver.join(p.session_id.unwrap()).unwrap();
        assert_eq!(receiver.recv(&ch, false).unwrap()[0].message, vec![7; 32]);
        let mut invalid = p.clone();
        invalid.attempt = "../outside".into();
        assert!(save_payment(data_a, "pass", &invalid).is_err());
        send_control(&url, &a, &invalid, "intent", &members(&a)).unwrap();
        let corrupt_path = payment_dir(data_b, &vault)
            .unwrap()
            .path()
            .join(format!("{}.json", second.attempt));
        std::fs::write(&corrupt_path, b"unreadable sealed record").unwrap();
        send_control(&url, &a, &second, "intent", &members(&a)).unwrap();
        sync_control(&url, data_b, "pass", &vault, &b).unwrap();
        assert_eq!(
            std::fs::read(&corrupt_path).unwrap(),
            b"unreadable sealed record"
        );

        // Member 3 approves before member 2, so member 3 signs: arrival order, not slot order.
        let approve = |data: &Path, m: &Vault| {
            let mut local = read_payment(data, "pass", &vault, &p.attempt).unwrap();
            assert!(!local.approval_requested);
            local.approval_requested = true;
            record_approval(&mut local, m.slot);
            save_payment(data, "pass", &local).unwrap();
            send_control(&url, m, &local, "approval", &[1]).unwrap();
        };
        approve(data_c, &c);
        sync_control(&url, data_a, "pass", &vault, &a).unwrap();
        approve(data_b, &b);
        sync_control(&url, data_a, "pass", &vault, &a).unwrap();
        let mut proposer = read_payment(data_a, "pass", &vault, &p.attempt).unwrap();
        assert_eq!(proposer.approvals, vec![3, 2]);
        assert!(signing_group(&proposer, &a).is_none(), "the proposer approves too");
        // A repeated notice preserves consent; conflicting terms cannot replace it.
        send_control(&url, &a, &p, "intent", &members(&a)).unwrap();
        let mut changed = p.clone();
        changed.amount_zat += 1;
        send_control(&url, &a, &changed, "intent", &members(&a)).unwrap();
        sync_control(&url, data_b, "pass", &vault, &b).unwrap();
        let local = read_payment(data_b, "pass", &vault, &p.attempt).unwrap();
        assert!(local.approval_requested);
        assert_eq!(local.amount_zat, p.amount_zat);
        // Only the proposer fixes the group.
        let mut forged = p.clone();
        forged.signers = vec![1, 2];
        send_control(&url, &b, &forged, "start", &[3]).unwrap();
        sync_control(&url, data_c, "pass", &vault, &c).unwrap();
        let local = read_payment(data_c, "pass", &vault, &p.attempt).unwrap();
        assert!(local.signers.is_empty() && !local.start_requested);
        record_approval(&mut proposer, 1);
        proposer.signers = signing_group(&proposer, &a).unwrap();
        assert_eq!(proposer.signers, vec![1, 3]);
        save_payment(data_a, "pass", &proposer).unwrap();
        // Human delay exceeds the old timeout without starting a nonce or signing round.
        std::thread::sleep(Duration::from_secs(12));
        sync_control(&url, data_c, "pass", &vault, &c).unwrap();
        assert!(
            !read_payment(data_c, "pass", &vault, &p.attempt)
                .unwrap()
                .approval_started
        );
        send_control(&url, &a, &proposer, "start", &members(&a)).unwrap();
        // A later, different group from the proposer cannot replace the first.
        let mut regroup = proposer.clone();
        regroup.signers = vec![1, 2];
        send_control(&url, &a, &regroup, "start", &members(&a)).unwrap();
        sync_control(&url, data_b, "pass", &vault, &b).unwrap();
        sync_control(&url, data_c, "pass", &vault, &c).unwrap();
        let signer = read_payment(data_c, "pass", &vault, &p.attempt).unwrap();
        assert_eq!(signer.signers, vec![1, 3]);
        assert!(signer.start_requested);
        assert_eq!(signer.phase, "signing");
        let outside = read_payment(data_b, "pass", &vault, &p.attempt).unwrap();
        assert_eq!(outside.signers, vec![1, 3]);
        assert!(!outside.start_requested);
        assert_eq!(outside.phase, "not_selected");

        let mut reported = signer;
        reported.phase = "approved".into();
        save_payment(data_c, "pass", &reported).unwrap();
        proposer.txid = Some(hex::encode([6; 32]));
        send_control(&url, &a, &proposer, "confirmed", &members(&a)).unwrap();
        for (data, m) in [(data_b, &b), (data_c, &c)] {
            sync_control(&url, data, "pass", &vault, m).unwrap();
            assert_eq!(
                read_payment(data, "pass", &vault, &p.attempt)
                    .unwrap()
                    .phase,
                "broadcast"
            );
        }
        reported.phase = "signing".into();
        reported.txid = None;
        save_payment(data_c, "pass", &reported).unwrap();
        send_control(&url, &a, &proposer, "failed", &members(&a)).unwrap();
        send_control(&url, &a, &proposer, "start", &members(&a)).unwrap();
        sync_control(&url, data_c, "pass", &vault, &c).unwrap();
        assert_eq!(
            read_payment(data_c, "pass", &vault, &p.attempt)
                .unwrap()
                .phase,
            "failed"
        );
        let data_stranger = &dirs[3];
        sync_control(&url, data_stranger, "pass", &vault, &stranger).unwrap();
        assert!(local_attempts(data_stranger, &vault).unwrap().is_empty());
        signing.close(signing_ch).unwrap();
        close_if_present(&mut control, control_ch.session_id()).unwrap();
        close_if_present(&mut control, control_ch.session_id()).unwrap();
        control.close(control_ch2).unwrap();
        for data in dirs {
            let _ = std::fs::remove_dir_all(data);
        }
    }

    #[test]
    fn testnet_signed_artifact_survives_a_delayed_final_send() {
        let Ok(url) = std::env::var("FROSTD_URL") else {
            return;
        };
        let data = std::env::temp_dir().join(format!("loki-testnet-round-{}", Uuid::new_v4()));
        let identities: Vec<_> = (1..=3).map(Identity::new).collect();
        let peers: BTreeMap<_, _> = identities
            .iter()
            .map(|i| (i.public().id, i.public()))
            .collect();
        let (shares, public) = frost::keys::generate_with_dealer(
            3,
            2,
            frost::keys::IdentifierList::Default,
            &mut OsRng,
        )
        .unwrap();
        let ak = public
            .verifying_key()
            .serialize()
            .unwrap()
            .try_into()
            .unwrap();
        let fvk = zip2005::frost_viewing_key(&ak, &[42; 32]).unwrap();
        let make = |slot: u16| Vault {
            network: VaultNetwork::Testnet,
            fvk: fvk.clone(),
            key: frost::keys::KeyPackage::try_from(
                shares[&frost::Identifier::try_from(slot).unwrap()].clone(),
            )
            .unwrap(),
            public: public.clone(),
            identity: Identity::from_secret_bytes(
                &identities[usize::from(slot - 1)].to_secret_bytes(),
            )
            .unwrap(),
            threshold: 2,
            slot,
            peers: peers.clone(),
            birth_height: TESTNET_NU7_BIRTH,
        };
        // Members 1 and 3 sign; member 2 is in the session but never joins it.
        let a = make(1);
        let b = make(3);
        let rho = Rho::from_bytes(&[1; 32]).unwrap();
        let note = orchard::Note::from_parts(
            fvk.address_at(0u64, Scope::External),
            NoteValue::from_raw(5_000_000),
            rho,
            RandomSeed::from_bytes([2; 32], &rho).unwrap(),
            NoteVersion::V3,
        )
        .unwrap();
        let vault = hex::encode([2; 32]);
        member_dir(&data, &vault).unwrap();
        std::fs::create_dir_all(data.join("vaults").join(&vault)).unwrap();
        let mut inputs = CandidateInputs {
            vault_fvk: &fvk,
            notes: vec![note],
            recipient: fvk.address_at(0u64, Scope::External),
            amount: Zatoshis::const_from_u64(100_000),
            memo: MemoBytes::from_bytes(b"").unwrap(),
            change: Zatoshis::ZERO,
            target_height: TESTNET_NU7_BIRTH + 1,
            expiry_height: TESTNET_NU7_BIRTH + 1152,
        };
        let fee: u64 = quote_fee(&VaultNetwork::Testnet, &inputs).unwrap().into();
        inputs.change = Zatoshis::from_u64(4_900_000 - fee).unwrap();
        let coord = Identity::new(0);
        let mut tx = relay(&coord, &url).unwrap();
        let ch = tx
            .open(&peers.values().map(|m| Peer(m.encryption)).collect::<Vec<_>>(), 4)
            .unwrap();
        let mut p = Payment {
            attempt: hex::encode([3; 32]),
            vault: vault.clone(),
            proposer: 1,
            recipient: vault::unified_address(&fvk, VaultNetwork::Testnet.network_type()),
            amount_zat: 100_000,
            memo: String::new(),
            fee_zat: fee,
            change_zat: 4_900_000 - fee,
            note_selection: vec![hex::encode(note.nullifier(&fvk).to_bytes())],
            target_height: inputs.target_height,
            expiry_height: inputs.expiry_height,
            signers: vec![1, 3],
            phase: "signing".into(),
            session_id: Some(ch.session_id()),
            control_session_id: None,
            approvals: vec![1, 3],
            start_requested: true,
            coordinator_secret: Some(hex::encode(coord.to_secret_bytes())),
            review_token: None,
            approval_requested: true,
            approval_started: true,
            txid: None,
            signed_pczt: None,
            raw_tx: None,
            error: None,
        };
        let st = state(&data, &url);
        let b_data = data.join("b");
        std::fs::create_dir_all(b_data.join("vaults").join(&vault)).unwrap();
        let signed = std::thread::scope(|scope| {
            let aggregate = scope.spawn(|| aggregate(&st, &data, "pass", &p, &a));
            let other = scope.spawn(|| sign(&st, &b_data, "pass", &p, &b, None));
            let result = sign(&st, &data, "pass", &p, &a, Some(inputs));
            result.unwrap();
            other.join().unwrap().unwrap();
            aggregate.join().unwrap().unwrap()
        });
        p.phase = "ready".into();
        p.signed_pczt = Some(hex::encode(signed));
        save_payment(&data, "pass", &p).unwrap();
        std::thread::sleep(Duration::from_secs(12));
        let reloaded = read_payment(&data, "pass", &vault, &p.attempt).unwrap();
        assert!(ready_to_send(&reloaded));
        assert_eq!(reloaded.signed_pczt, p.signed_pczt);
        assert!(reloaded.txid.is_none());
        assert!(discardable(&data, &reloaded).is_err());
        let mut interrupted = reloaded.clone();
        interrupted.attempt = hex::encode([4; 32]);
        interrupted.phase = "signing".into();
        interrupted.signed_pczt = None;
        save_payment(&data, "pass", &interrupted).unwrap();
        ensure_worker(&st, &data, "pass", &vault, &interrupted.attempt).unwrap();
        let interrupted = read_payment(&data, "pass", &vault, &interrupted.attempt).unwrap();
        assert_eq!(interrupted.phase, "failed");
        assert!(!ready_to_send(&interrupted));
        assert!(st.active_payments.lock().unwrap().is_empty());
        std::fs::remove_dir_all(data).unwrap();
    }

    #[test]
    fn pending_lists_only_this_members_unapproved_signing_payments() {
        let data = std::env::temp_dir().join(format!("loki-pending-{}", Uuid::new_v4()));
        let vault = hex::encode([2u8; 32]);
        let mk =
            |attempt: [u8; 32], signers: Vec<u16>, proposer: u16, phase: &str, started: bool| {
                Payment {
                    attempt: hex::encode(attempt),
                    vault: vault.clone(),
                    proposer,
                    recipient: "uregtest1recipient".into(),
                    amount_zat: 40_000_000,
                    memo: "rent".into(),
                    fee_zat: 10_000,
                    change_zat: 1,
                    note_selection: vec![hex::encode([5u8; 32])],
                    target_height: TESTNET_NU7_BIRTH + 1,
                    expiry_height: TESTNET_NU7_BIRTH + 1_152,
                    signers,
                    phase: phase.into(),
                    session_id: Some(Uuid::new_v4()),
                    control_session_id: None,
                    approvals: Vec::new(),
                    start_requested: false,
                    coordinator_secret: None,
                    review_token: None,
                    approval_requested: started,
                    approval_started: started,
                    txid: None,
                    signed_pczt: None,
                    raw_tx: None,
                    error: None,
                }
            };
        let mut readiness = mk([9u8; 32], vec![1, 2], 1, "signing", false);
        assert!(
            !ready_to_send(&readiness),
            "publishing is not signature readiness"
        );
        readiness.phase = "ready".into();
        readiness.signed_pczt = Some("signed artifact".into());
        assert!(ready_to_send(&readiness));
        readiness.error = Some("round failed".into());
        assert!(!ready_to_send(&readiness), "errors must never report ready");
        let mut failed = mk([9; 32], vec![1, 2], 1, "failed", true);
        assert!(discardable(&data, &failed).is_ok());
        let nonce_dir = member_dir(&data, &vault)
            .unwrap()
            .path()
            .join("signer-nonces");
        std::fs::create_dir_all(&nonce_dir).unwrap();
        std::fs::write(
            nonce_dir.join(format!("{}{}.burn", failed.attempt, failed.attempt)),
            b"burned",
        )
        .unwrap();
        assert!(discardable(&data, &failed).is_err());
        failed.attempt = hex::encode([10; 32]);
        failed.raw_tx = Some("raw".into());
        assert!(discardable(&data, &failed).is_err());
        failed.raw_tx = None;
        failed.signed_pczt = Some("signed".into());
        assert!(discardable(&data, &failed).is_err());
        // Member 2's inbox should surface only the first payment.
        save_payment(
            &data,
            "pass",
            &mk([1u8; 32], vec![1, 2], 1, "signing", false),
        )
        .unwrap(); // must approve → shown
        save_payment(
            &data,
            "pass",
            &mk([2u8; 32], vec![1, 3], 1, "signing", false),
        )
        .unwrap(); // not a signer → hidden
        save_payment(
            &data,
            "pass",
            &mk([3u8; 32], vec![1, 2], 1, "signing", true),
        )
        .unwrap(); // already approved → hidden
        save_payment(
            &data,
            "pass",
            &mk([4u8; 32], vec![2, 1], 2, "signing", false),
        )
        .unwrap(); // own proposal → hidden
        save_payment(
            &data,
            "pass",
            &mk([5u8; 32], vec![1, 2], 1, "broadcast", false),
        )
        .unwrap(); // not signing → hidden
        save_payment(&data, "pass", &mk([6u8; 32], vec![], 3, "signing", false))
            .unwrap(); // open to every member → shown

        let mut seen: Vec<String> = pending_for(&data, "pass", &vault, 2)
            .unwrap()
            .iter()
            .map(|p| p["attempt"].as_str().unwrap().to_owned())
            .collect();
        seen.sort();
        assert_eq!(seen, vec![hex::encode([1u8; 32]), hex::encode([6u8; 32])]);
        std::fs::remove_dir_all(data).unwrap();
    }
}
