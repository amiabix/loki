//! Hosted one-note payments. All wallet, frostd, proving, and broadcast work is blocking.

use std::{
    collections::BTreeMap,
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
    signing_session::{AttemptId, MessageKind, SessionContext},
    setup_transport::{Identity, PublicIdentity},
    signer::{
        local::LocalSigner, secure_element::SoftwareSecureElement, CandidateRef, Network,
        PublicPaymentParams, Signer,
    },
    state::MemberDir,
    transport::{FrostdLoginKey, FrostdTransport, Peer, Transport},
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
    phase: String,
    session_id: Option<Uuid>,
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

struct Vault {
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
    let dir = payment_dir(data, &p.vault)?;
    let file = format!("{}.json", p.attempt);
    let temp = format!("{}.{}.tmp", p.attempt, Uuid::new_v4());
    dir.write_sealed(
        &temp,
        &serde_json::to_vec(p).map_err(|e| e.to_string())?,
        pass,
    )
    .map_err(|e| e.to_string())?;
    std::fs::rename(dir.path().join(temp), dir.path().join(file)).map_err(|e| e.to_string())
}
fn load_vault(data: &Path, pass: &str, vault: &str, configured: &str) -> Result<Vault, String> {
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
fn check_intent(p: &Payment, v: &Vault) -> Result<(), String> {
    if p.signers.len() != usize::from(v.threshold)
        || p.signers.first() != Some(&p.proposer)
        || !p.signers.contains(&v.slot)
        || p.signers.iter().any(|s| !v.peers.contains_key(s))
        || p.signers
            .iter()
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != p.signers.len()
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
fn public_intent(p: &Payment) -> Value {
    json!({"attempt":p.attempt,"vault":p.vault,"proposer":p.proposer,"recipient":p.recipient,"amount_zat":p.amount_zat,"memo":p.memo,"fee_zat":p.fee_zat,"change_zat":p.change_zat,"note_selection":p.note_selection,"target_height":p.target_height,"expiry_height":p.expiry_height,"signers":p.signers,"phase":p.phase,"session_id":p.session_id})
}
const UNAVAILABLE: &str = "payment session unavailable";
const PEER_REQUEST: &[u8] = b"loki payment-session v1";

/// The sealed-envelope context between two members about one payment attempt.
fn peer_context(vault: &str, attempt: &str, a: u16, b: u16) -> Result<SessionContext, String> {
    Ok(SessionContext {
        vault: hex32(vault)?,
        payment: hex32(attempt)?,
        attempt: AttemptId(hex32(attempt)?),
        signers: vec![a.min(b), a.max(b)],
    })
}

/// Ask member `slot`'s host for its view of a payment. The request is signed and sealed
/// with this member's roster identity, and the reply must open under `slot`'s.
fn peer_get(url: &str, v: &Vault, vault: &str, attempt: &str, slot: u16) -> Result<Value, String> {
    let peer = v.peers.get(&slot).ok_or("unknown peer")?;
    let context = peer_context(vault, attempt, v.slot, slot)?;
    let request = v.identity.seal_session(peer, &context, MessageKind::PeerRequest, PEER_REQUEST)?;
    let rt = runtime()?;
    let response: Value = rt.block_on(async {
        let response = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| e.to_string())?
            .post(format!("{url}/api/payment-session"))
            .json(&json!({"vault":vault,"attempt":attempt,"from":v.slot,"request":hex::encode(request)}))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        if !response.status().is_success() {
            return Err(UNAVAILABLE.to_string());
        }
        response.json().await.map_err(|e| e.to_string())
    })?;
    let reply = hex::decode(response["reply"].as_str().ok_or(UNAVAILABLE)?).map_err(|e| e.to_string())?;
    let opened = v.identity.open_session(peer, &context, &reply)?;
    if opened.kind != MessageKind::PeerReply {
        return Err(UNAVAILABLE.into());
    }
    serde_json::from_slice(&opened.body).map_err(|e| e.to_string())
}

/// Answer a selected signer's sealed `/api/payment-session` request with this member's view
/// of the payment, sealed back to it. Anyone else gets the same refusal whether or not the
/// payment exists.
fn answer_peer(data: &Path, pass: &str, v: &Vault, body: &Value) -> Result<Value, String> {
    let (vault, attempt) = pair(body).map_err(|_| UNAVAILABLE)?;
    let (vault, attempt) = (vault.as_str(), attempt.as_str());
    let from = body["from"].as_u64().and_then(|n| u16::try_from(n).ok()).ok_or(UNAVAILABLE)?;
    let request = hex::decode(body["request"].as_str().ok_or(UNAVAILABLE)?).map_err(|_| UNAVAILABLE)?;
    let peer = v.peers.get(&from).filter(|_| from != v.slot).ok_or(UNAVAILABLE)?;
    let p = read_payment(data, pass, vault, attempt).map_err(|_| UNAVAILABLE)?;
    let id = p.session_id.filter(|_| p.signers.contains(&from)).ok_or(UNAVAILABLE)?;
    let context = peer_context(vault, attempt, v.slot, from)?;
    let opened = v.identity.open_session(peer, &context, &request).map_err(|_| UNAVAILABLE)?;
    if opened.kind != MessageKind::PeerRequest || opened.body != PEER_REQUEST {
        return Err(UNAVAILABLE.into());
    }
    let reply = json!({"session_id":id,"intent":public_intent(&p),"approval_started":p.approval_started});
    let reply = v.identity.seal_session(
        peer,
        &context,
        MessageKind::PeerReply,
        &serde_json::to_vec(&reply).map_err(|e| e.to_string())?,
    )?;
    Ok(json!({"reply":hex::encode(reply)}))
}
fn ready_to_send(st: &Shared, p: &Payment, v: &Vault) -> bool {
    p.phase == "signing"
        && p.signers.iter().all(|slot| {
            if *slot == v.slot {
                p.approval_started
            } else {
                st.config
                    .peers
                    .get(slot)
                    .and_then(|url| peer_get(url, v, &p.vault, &p.attempt, *slot).ok())
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
    for (&slot, url) in &st.config.peers {
        if slot == v.slot {
            continue;
        }
        let Ok(response) = peer_get(url, v, vault, attempt, slot) else {
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
        let expiry = tip.checked_add(match v.network { VaultNetwork::Regtest => 8_064, VaultNetwork::Testnet => 24_192 }).ok_or("expiry overflow")?.div_ceil(1_152).checked_mul(1_152).ok_or("expiry overflow")?;
        let funding = w.propose(address, Some(amount), memo_bytes.clone())?;
        let first = *funding.notes.first().ok_or("wallet proposed no Ironwood notes")?;
        let inputs = CandidateInputs { vault_fvk: &v.fvk, notes: vec![first], recipient: address, amount, memo: memo_bytes, change: Zatoshis::ZERO, target_height: tip, expiry_height: expiry };
        let fee_zat: u64 = quote_fee(&v.network, &inputs)?.into();
        let note = funding.notes.iter().find(|note| note.value().inner() >= amount_zat.saturating_add(fee_zat))
            .ok_or("payment needs one Ironwood note large enough for amount and fee")?;
        let change_zat = note.value().inner().checked_sub(amount_zat).and_then(|n| n.checked_sub(fee_zat)).ok_or("note cannot cover amount and fee")?;
        if funding.notes.len() == 1 && (funding.fee_zat != fee_zat || funding.change_zat != change_zat) { return Err("wallet funding differs from candidate fee or change".into()); }
        let mut random = [0u8; 32]; OsRng.fill_bytes(&mut random);
        let attempt = hex::encode(random);
        let mut signers = vec![v.slot];
        signers.extend(v.peers.keys().copied().filter(|id| *id != v.slot && st.config.peers.contains_key(id)).take(usize::from(v.threshold - 1)));
        if signers.len() != usize::from(v.threshold) { return Err("not enough configured signer coordinators".into()); }
        let note_selection = vec![hex::encode(note.nullifier(&v.fvk).to_bytes())];
        let p = Payment { attempt: attempt.clone(), vault: vault.to_owned(), proposer: v.slot, recipient: recipient.to_owned(), amount_zat, memo: memo.to_owned(), fee_zat, change_zat, note_selection, target_height: tip, expiry_height: expiry, signers, phase: "draft".into(), session_id: None, coordinator_secret: None, review_token: None, approval_requested: false, approval_started: false, txid: None, signed_pczt: None, raw_tx: None, error: None };
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
        let peers = p
            .signers
            .iter()
            .map(|id| Peer(v.peers[id].encryption))
            .collect::<Vec<_>>();
        let ch = tx.open(&peers, 4).map_err(|e| e.to_string())?;
        p.session_id = Some(ch.session_id());
        p.coordinator_secret = Some(hex::encode(&*Zeroizing::new(coord.to_secret_bytes())));
        p.phase = "signing".into();
        save_payment(&data, &pass, &p)?;
        Ok(json!({"phase":p.phase,"session_id":p.session_id}))
    })
    .await
}

pub(super) async fn session(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    let (data, pass) = match unlocked(&st).await {
        Ok(x) => x,
        Err(e) => return e,
    };
    let reply = blocking(move || {
        let vault = required(&body, "vault").map_err(|_| UNAVAILABLE)?;
        let v = load_vault(&data, &pass, vault, &st.config.network).map_err(|_| UNAVAILABLE)?;
        answer_peer(&data, &pass, &v, &body)
    })
    .await;
    if reply.0 == StatusCode::OK {
        reply
    } else {
        err(StatusCode::NOT_FOUND, UNAVAILABLE)
    }
}

pub(super) async fn review(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    with_body(st, body, |st, data, pass, body| {
        let (vault, attempt) = pair(&body)?;
        let v = load_vault(&data, &pass, &vault, &st.config.network)?;
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
        let (vault, attempt) = pair(&body)?;
        let mut p = read_payment(&data, &pass, &vault, &attempt)?;
        if p.phase != "signing"
            || p.approval_requested
            || p.review_token.as_deref() != body["review_token"].as_str()
        {
            return Err("invalid or repeated payment approval".into());
        }
        let v = load_vault(&data, &pass, &vault, &work_st.config.network)?;
        check_intent(&p, &v)?;
        p.approval_requested = true;
        save_payment(&data, &pass, &p)?;
        let bg_st = work_st.clone();
        tokio::task::spawn_blocking(move || {
            let result = sign(&bg_st, &data, &pass, &p, &v);
            if let Ok(mut local) = read_payment(&data, &pass, &vault, &attempt) {
                let changed = match result {
                    Ok(()) if local.phase == "signing" && local.proposer != v.slot => {
                        local.phase = "approved".into();
                        true
                    }
                    Ok(()) => false,
                    Err(e) => {
                        local.approval_started = false;
                        local.error = Some(e);
                        true
                    }
                };
                if changed {
                    let _ = save_payment(&data, &pass, &local);
                }
            }
        });
        Ok(json!({"phase":"signing"}))
    })
    .await;
    reply
}
fn sign(st: &Shared, data: &Path, pass: &str, p: &Payment, v: &Vault) -> Result<(), String> {
    let mut tx = relay(&v.identity, &st.config.frostd_url)?;
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
    let mut local = read_payment(data, pass, &p.vault, &p.attempt)?;
    local.approval_started = true;
    save_payment(data, pass, &local)?;
    let signer_network = match v.network {
        VaultNetwork::Regtest => Network::Regtest,
        VaultNetwork::Testnet => Network::Testnet,
    };
    let mut signer = LocalSigner::with_sealed_share(
        v.slot, v.threshold, v.peers.len() as u16, hex32(&p.vault)?,
        p.vault.clone(), signer_network, SoftwareSecureElement::generate(),
        &v.key.serialize().map_err(|e| e.to_string())?,
        v.public.serialize().map_err(|e| e.to_string())?, v.fvk.clone(),
        member_dir(data, &p.vault)?.path().join("signer-nonces"), Box::new(|_| true),
    ).map_err(|e| e.to_string())?;
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
        &mut signer, &session, &candidate, &v.public,
        frost::Identifier::try_from(v.slot).map_err(|e| e.to_string())?,
        params.as_ref(), &v.identity, &context, &v.peers[&p.proposer], &other_signers,
        &mut |bytes| {
            review_candidate(bytes, p, v)?;
            // The coordinator runs in this process (`finish`); hand it the candidate through
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

pub(super) async fn finish(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    with_body(st, body, |st, data, pass, body| {
        let (vault, attempt) = pair(&body)?;
        let v = load_vault(&data, &pass, &vault, &st.config.network)?;
        let mut p = read_payment(&data, &pass, &vault, &attempt)?;
        if p.proposer != v.slot || p.phase != "signing" {
            return Err("only the proposer can finish a signing payment".into());
        }
        check_intent(&p, &v)?;
        if p.signed_pczt.is_none() && !ready_to_send(&st, &p, &v) {
            return Err("signer approvals are not ready".into());
        }
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
            let dir = member_dir(&data, &vault)?;
            let file = candidate_file(&attempt);
            let signed = coordinate(&tx, &ch, &v.public, &ids, &peer_of, v.threshold, OsRng, || {
                match dir.read_sealed(&file, &pass) {
                    Ok(bytes) => Ok(Some(bytes)),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
                    Err(e) => Err(format!("read candidate: {e}")),
                }
            })?;
            p.signed_pczt = Some(hex::encode(signed));
            save_payment(&data, &pass, &p)?;
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
            let owner = zcash_client_backend::wallet::LockOwner::new(hex32(&p.attempt)?);
            w.release_inputs(owner, &selected)?;
            w.reserve_inputs(txid.into(), &selected, p.expiry_height)?;
            p.raw_tx = Some(hex::encode(raw));
            p.txid = Some(txid.to_string());
            save_payment(&data, &pass, &p)?;
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
        save_payment(&data, &pass, &p)?;
        let _ = std::fs::remove_file(member_dir(&data, &vault)?.path().join(candidate_file(&attempt)));
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
        let dir = payment_dir(&data, &vault)?;
        let mut out = Vec::new();
        for entry in std::fs::read_dir(dir.path()).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(attempt) = name.strip_suffix(".json") else { continue };
            if hex32(attempt).is_err() { continue; }
            let p = read_payment(&data, &pass, &vault, attempt)?;
            let ready = ready_to_send(&st, &p, &v);
            out.push(json!({"attempt":p.attempt,"phase":p.phase,"recipient":p.recipient,"amount_zat":p.amount_zat.to_string(),"ready_to_send":ready,"txid":p.txid,"signers":p.signers}));
        }
        Ok(json!({"payments":out}))
    }).await
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
        let identity = Identity::new(1);
        let v = Vault {
            network: VaultNetwork::Regtest,
            fvk,
            key,
            public,
            identity,
            threshold: 2,
            slot: 1,
            peers: BTreeMap::new(),
            birth_height: 2,
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
            target_height: 700,
            expiry_height: 1_152,
            signers: vec![1, 2],
            phase: "signing".into(),
            session_id: None,
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
        let (shares, public) =
            frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, &mut OsRng)
                .unwrap();
        let key = frost::keys::KeyPackage::try_from(shares.into_values().next().unwrap()).unwrap();
        let ak: [u8; 32] = public.verifying_key().serialize().unwrap().try_into().unwrap();
        Vault {
            network: VaultNetwork::Regtest,
            fvk: zip2005::frost_viewing_key(&ak, &[42u8; 32]).unwrap(),
            key,
            public,
            identity: Identity::from_secret_bytes(&identity.to_secret_bytes()).unwrap(),
            threshold: 2,
            slot: identity.public().id,
            peers: peers.clone(),
            birth_height: 2,
        }
    }

    #[test]
    fn payment_session_answers_only_selected_signers_over_sealed_http() {
        let identities: Vec<Identity> = (1..=3).map(Identity::new).collect();
        let peers: BTreeMap<_, _> = identities.iter().map(|i| (i.public().id, i.public())).collect();
        let data = std::env::temp_dir().join(format!("loki-peer-session-{}", Uuid::new_v4()));
        let (vault, attempt) = (hex::encode([2u8; 32]), hex::encode([1u8; 32]));
        let session_id = Uuid::new_v4();
        let p = Payment {
            attempt: attempt.clone(), vault: vault.clone(), proposer: 1,
            recipient: "uregtest1recipient".into(), amount_zat: 40_000_000, memo: "rent".into(),
            fee_zat: 10_000, change_zat: 1, note_selection: vec![hex::encode([5u8; 32])],
            target_height: 700, expiry_height: 1_152, signers: vec![1, 2], phase: "signing".into(),
            session_id: Some(session_id), coordinator_secret: Some("secret".into()),
            review_token: Some("token".into()), approval_requested: false, approval_started: true,
            txid: None, signed_pczt: None, raw_tx: None, error: None,
        };
        save_payment(&data, "pass", &p).unwrap();

        // The proposer's host serves `answer_peer`, exactly as the real handler does after
        // loading its vault.
        let proposer = std::sync::Arc::new(member(&identities[0], &peers));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let served = data.clone();
        std::thread::spawn(move || {
            runtime().unwrap().block_on(async move {
                let app = axum::Router::new().route(
                    "/api/payment-session",
                    axum::routing::post(move |Json(body): Json<Value>| async move {
                        match answer_peer(&served, "pass", &proposer, &body) {
                            Ok(reply) => (StatusCode::OK, Json(reply)),
                            Err(e) => (StatusCode::NOT_FOUND, Json(json!({"error": e}))),
                        }
                    }),
                );
                let listener = tokio::net::TcpListener::from_std(listener).unwrap();
                axum::serve(listener, app).await.unwrap();
            })
        });

        // The selected signer gets the proposer's signed intent.
        let reply = peer_get(&url, &member(&identities[1], &peers), &vault, &attempt, 1).unwrap();
        assert_eq!(reply["intent"]["recipient"], "uregtest1recipient");
        assert_eq!(reply["session_id"], session_id.to_string());
        assert_eq!(reply["approval_started"], true);
        assert!(reply["intent"].get("coordinator_secret").is_none());
        // A vault member outside the signer set is refused.
        assert!(peer_get(&url, &member(&identities[2], &peers), &vault, &attempt, 1).is_err());
        // So is someone claiming slot 2 without slot 2's roster key.
        let impostor = Identity::new(2);
        assert!(peer_get(&url, &member(&impostor, &peers), &vault, &attempt, 1).is_err());
        // The wire carries neither the intent nor the IDs it is about.
        let request = member(&identities[1], &peers)
            .identity
            .seal_session(&peers[&1], &peer_context(&vault, &attempt, 2, 1).unwrap(), MessageKind::PeerRequest, PEER_REQUEST)
            .unwrap();
        let reply = answer_peer(&data, "pass", &member(&identities[0], &peers), &json!({
            "vault": vault, "attempt": attempt, "from": 2, "request": hex::encode(request),
        }))
        .unwrap();
        let wire = hex::decode(reply["reply"].as_str().unwrap()).unwrap();
        assert!(!wire.windows(4).any(|w| w == b"rent"));
        assert!(!wire.windows(18).any(|w| w == b"uregtest1recipient"));
        std::fs::remove_dir_all(data).unwrap();
    }
}
