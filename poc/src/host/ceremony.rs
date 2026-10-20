//! HTTP enrollment and frostd DKG for one sealed member vault.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::Duration,
};

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use base64::Engine;
use rand_core::{OsRng, RngCore};
use reddsa_frost::frost::redpallas as frost;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;
use zcash_protocol::consensus::Parameters;
use zeroize::Zeroizing;

use super::{
    routes::{blocking, err},
    state::Shared,
};
use crate::{
    dkg_transport::run_dkg,
    frost_roster::FrostRoster,
    network::VaultNetwork,
    setup_transport::{Identity, PublicIdentity},
    state::MemberDir,
    transport::{FrostdTransport, Peer, Transport},
    vault, zip2005,
};

type Reply = (StatusCode, Json<Value>);

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
struct WireIdentity {
    id: u16,
    signing: String,
    encryption: String,
}

impl WireIdentity {
    fn from_public(p: PublicIdentity) -> Self {
        Self {
            id: p.id,
            signing: hex::encode(p.signing),
            encryption: hex::encode(p.encryption),
        }
    }

    fn public(&self, slot: u16) -> Result<PublicIdentity, String> {
        if self.id != slot {
            return Err("identity slot mismatch".into());
        }
        let signing: [u8; 32] = hex::decode(&self.signing)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "signing key must be 32 bytes")?;
        let encryption: [u8; 32] = hex::decode(&self.encryption)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "encryption key must be 32 bytes")?;
        ed25519_dalek::VerifyingKey::from_bytes(&signing).map_err(|e| e.to_string())?;
        if encryption == [0; 32] {
            return Err("invalid encryption key".into());
        }
        Ok(PublicIdentity {
            id: slot,
            signing,
            encryption,
        })
    }
}

#[derive(Default, Serialize, Deserialize)]
struct Slot {
    identity: Option<WireIdentity>,
    pending_token: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Ceremony {
    vault: String,
    name: String,
    members: u16,
    threshold: u16,
    my_slot: u16,
    creator_base_url: String,
    frostd_url: String,
    slots: BTreeMap<u16, Slot>,
    fingerprint: Option<String>,
    agreed: BTreeSet<u16>,
    session_id: Option<Uuid>,
    #[serde(default)]
    vs_session_id: Option<Uuid>,
    dkg_started: bool,
    error: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Invite {
    vault: String,
    slot: u16,
    creator_base_url: String,
    token: String,
    members: u16,
    threshold: u16,
    name: String,
}

fn vault_bytes(vault: &str) -> Result<[u8; 32], String> {
    hex::decode(vault)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "vault must be 32 bytes of hex".into())
}

fn dir(data: &Path, vault: &str) -> Result<MemberDir, String> {
    vault_bytes(vault)?;
    Ok(MemberDir::open(&data.join("vaults"), vault))
}

fn load(data: &Path, pass: &str, vault: &str) -> Result<Ceremony, String> {
    let raw = dir(data, vault)?
        .read_sealed("ceremony.sealed", pass)
        .map_err(|e| e.to_string())?;
    let c: Ceremony = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    if c.vault != vault {
        return Err("ceremony vault mismatch".into());
    }
    Ok(c)
}

fn save(data: &Path, pass: &str, c: &Ceremony) -> Result<(), String> {
    let root = data.join("vaults");
    let d = MemberDir::create(&root, &c.vault).map_err(|e| e.to_string())?;
    let temp = format!("ceremony.{}.sealed", Uuid::new_v4());
    d.write_sealed(
        &temp,
        &serde_json::to_vec(c).map_err(|e| e.to_string())?,
        pass,
    )
    .map_err(|e| e.to_string())?;
    std::fs::rename(d.path().join(&temp), d.path().join("ceremony.sealed"))
        .map_err(|e| e.to_string())
}

/// Summaries of every vault this member belongs to, for the home screen. Best-effort: a vault
/// whose ceremony file won't open (or isn't a 32-byte id) is skipped, not fatal to the list.
pub(super) fn vault_summaries(data: &Path, pass: &str) -> Result<Vec<Value>, String> {
    let root = data.join("vaults");
    let entries = match std::fs::read_dir(&root) {
        Ok(e) => e,
        Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
        Err(e) => return Err(e.to_string()),
    };
    let mut out = Vec::new();
    for entry in entries.flatten() {
        let Some(vault) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        if vault_bytes(&vault).is_err() {
            continue;
        }
        if let Ok(c) = load(data, pass, &vault) {
            out.push(json!({
                "vault": c.vault,
                "name": c.name,
                "members": c.members,
                "threshold": c.threshold,
                "policy": format!("{}-of-{}", c.threshold, c.members),
            }));
        }
    }
    Ok(out)
}

fn identity(data: &Path, pass: &str, slot: u16) -> Result<Identity, String> {
    let d = MemberDir::create(data, ".").map_err(|e| e.to_string())?;
    match d.read_sealed("identity.sealed", pass) {
        Ok(raw) => {
            let raw = Zeroizing::new(raw);
            let id = Identity::from_secret_bytes(&raw)?;
            if id.public().id != slot {
                return Err("this coordinator already has a different member slot".into());
            }
            Ok(id)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let id = Identity::new(slot);
            let secret = Zeroizing::new(id.to_secret_bytes());
            d.write_sealed("identity.sealed", &secret[..], pass)
                .map_err(|e| e.to_string())?;
            Ok(id)
        }
        Err(e) => Err(e.to_string()),
    }
}

fn roster_of(c: &Ceremony) -> Result<FrostRoster, String> {
    if c.slots.len() != usize::from(c.members) {
        return Err("roster pending".into());
    }
    let mut members = Vec::new();
    let mut addresses = BTreeSet::new();
    for slot in 1..=c.members {
        let wire = c
            .slots
            .get(&slot)
            .and_then(|s| s.identity.as_ref())
            .ok_or("roster pending")?;
        let public = wire.public(slot)?;
        if !addresses.insert(public.encryption) {
            return Err("duplicate relay address".into());
        }
        members.push((
            frost::Identifier::try_from(slot).map_err(|e| e.to_string())?,
            public,
        ));
    }
    Ok(FrostRoster::from_identities(
        vault_bytes(&c.vault)?,
        c.threshold,
        members,
    ))
}

fn invitations(c: &Ceremony) -> Result<Vec<Value>, String> {
    (2..=c.members)
        .map(|slot| {
            let s = c.slots.get(&slot).ok_or("missing invite slot")?;
            let token = s.pending_token.as_ref().ok_or("missing invite token")?;
            let code = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&Invite {
                    vault: c.vault.clone(),
                    slot,
                    creator_base_url: c.creator_base_url.clone(),
                    token: token.clone(),
                    members: c.members,
                    threshold: c.threshold,
                    name: c.name.clone(),
                })
                .map_err(|e| e.to_string())?,
            );
            Ok(json!({"slot":slot,"code":code,"joined":s.identity.is_some()}))
        })
        .collect()
}

fn peer_request(method: &str, url: &str, body: Option<Value>) -> Result<Value, String> {
    let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    runtime.block_on(async {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| e.to_string())?;
        let req = if method == "POST" {
            client.post(url).json(&body.unwrap_or(json!({})))
        } else {
            client.get(url)
        };
        let response = req.send().await.map_err(|e| e.to_string())?;
        let status = response.status();
        let value: Value = response.json().await.map_err(|e| e.to_string())?;
        if !status.is_success() {
            return Err(value["error"]
                .as_str()
                .unwrap_or("peer request failed")
                .into());
        }
        Ok(value)
    })
}

async fn unlocked(st: &Shared) -> Result<(std::path::PathBuf, Zeroizing<String>), Reply> {
    let session = st.session.read().await;
    let s = session
        .as_ref()
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "profile is locked"))?;
    Ok((s.data.clone(), s.passphrase.clone()))
}

pub(super) async fn create(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    let name = body["name"].as_str().unwrap_or("").trim().to_owned();
    let members = body["members"]
        .as_u64()
        .and_then(|n| u16::try_from(n).ok())
        .unwrap_or(0);
    let threshold = body["threshold"]
        .as_u64()
        .and_then(|n| u16::try_from(n).ok())
        .unwrap_or(0);
    if name.is_empty()
        || name.len() > 80
        || !(2..=4).contains(&members)
        || threshold < 2
        || threshold > members
    {
        return err(
            StatusCode::BAD_REQUEST,
            "name must be 1 to 80 bytes; use 2 to 4 members and a valid threshold",
        );
    }
    let (data, pass) = match unlocked(&st).await {
        Ok(x) => x,
        Err(e) => return e,
    };
    blocking(move || {
        let _guard = st.ceremony.lock().map_err(|e| e.to_string())?;
        let me = identity(&data, &pass, 1)?;
        let mut vault = [0u8; 32];
        OsRng.fill_bytes(&mut vault);
        let mut slots = BTreeMap::new();
        slots.insert(
            1,
            Slot {
                identity: Some(WireIdentity::from_public(me.public())),
                pending_token: None,
            },
        );
        for slot in 2..=members {
            let mut token = [0u8; 32];
            OsRng.fill_bytes(&mut token);
            slots.insert(
                slot,
                Slot {
                    identity: None,
                    pending_token: Some(
                        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(token),
                    ),
                },
            );
        }
        let c = Ceremony {
            vault: hex::encode(vault),
            name,
            members,
            threshold,
            my_slot: 1,
            creator_base_url: st
                .config
                .peers
                .get(&1)
                .cloned()
                .unwrap_or_else(|| format!("http://127.0.0.1:{}", st.config.port)),
            frostd_url: st.config.frostd_url.clone(),
            slots,
            fingerprint: None,
            agreed: BTreeSet::new(),
            session_id: None,
            vs_session_id: None,
            dkg_started: false,
            error: None,
        };
        save(&data, &pass, &c)?;
        Ok(json!({"vault":c.vault,"invites":invitations(&c)?}))
    })
    .await
}

pub(super) async fn join(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    let Some(code) = body["invite"].as_str() else {
        return err(StatusCode::BAD_REQUEST, "missing invite");
    };
    let invite: Invite = match base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(code)
        .map_err(|e| e.to_string())
        .and_then(|raw| serde_json::from_slice(&raw).map_err(|e| e.to_string()))
    {
        Ok(i) => i,
        Err(e) => return err(StatusCode::BAD_REQUEST, e),
    };
    if vault_bytes(&invite.vault).is_err()
        || !(2..=4).contains(&invite.members)
        || !(2..=invite.members).contains(&invite.slot)
        || invite.threshold < 2
        || invite.threshold > invite.members
        || invite.name.trim().is_empty()
        || invite.name.len() > 80
        || !(invite.creator_base_url.starts_with("http://")
            || invite.creator_base_url.starts_with("https://"))
        || !base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(&invite.token)
            .is_ok_and(|bytes| bytes.len() == 32)
    {
        return err(StatusCode::BAD_REQUEST, "invalid invite");
    }
    let (data, pass) = match unlocked(&st).await {
        Ok(x) => x,
        Err(e) => return e,
    };
    blocking(move || {
        let _guard = st.ceremony.lock().map_err(|e| e.to_string())?;
        let me = identity(&data, &pass, invite.slot)?;
        let wire = WireIdentity::from_public(me.public());
        peer_request(
            "POST",
            &format!("{}/api/enroll", invite.creator_base_url),
            Some(json!({
                "vault":invite.vault,"slot":invite.slot,"token":invite.token,"identity":wire
            })),
        )?;
        let mut slots = BTreeMap::new();
        slots.insert(
            invite.slot,
            Slot {
                identity: Some(wire),
                pending_token: Some(invite.token.clone()),
            },
        );
        let c = Ceremony {
            vault: invite.vault.clone(),
            name: invite.name,
            members: invite.members,
            threshold: invite.threshold,
            my_slot: invite.slot,
            creator_base_url: invite.creator_base_url,
            frostd_url: st.config.frostd_url.clone(),
            slots,
            fingerprint: None,
            agreed: BTreeSet::new(),
            session_id: None,
            vs_session_id: None,
            dkg_started: false,
            error: None,
        };
        if dir(&data, &c.vault)?.exists("ceremony.sealed") {
            let old = load(&data, &pass, &c.vault)?;
            if old.my_slot != c.my_slot
                || old.creator_base_url != c.creator_base_url
                || old
                    .slots
                    .get(&c.my_slot)
                    .and_then(|s| s.pending_token.as_ref())
                    != c.slots
                        .get(&c.my_slot)
                        .and_then(|s| s.pending_token.as_ref())
                || old.slots.get(&c.my_slot).and_then(|s| s.identity.as_ref())
                    != c.slots.get(&c.my_slot).and_then(|s| s.identity.as_ref())
            {
                return Err("existing ceremony does not match invite".into());
            }
        } else {
            save(&data, &pass, &c)?;
        }
        Ok(json!({"vault":invite.vault}))
    })
    .await
}

pub(super) async fn enroll(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    let (vault, slot, token, wire): (String, u16, String, WireIdentity) = match (
        body["vault"].as_str(),
        body["slot"].as_u64().and_then(|n| u16::try_from(n).ok()),
        body["token"].as_str(),
        serde_json::from_value(body["identity"].clone()),
    ) {
        (Some(v), Some(s), Some(t), Ok(w)) => (v.into(), s, t.into(), w),
        _ => return err(StatusCode::BAD_REQUEST, "invalid enrollment"),
    };
    if let Err(e) = wire.public(slot) {
        return err(StatusCode::BAD_REQUEST, e);
    }
    let (data, pass) = match unlocked(&st).await {
        Ok(x) => x,
        Err(e) => return e,
    };
    blocking(move || {
        let _guard = st.ceremony.lock().map_err(|e| e.to_string())?;
        let mut c = load(&data, &pass, &vault)?;
        if c.my_slot != 1 {
            return Err("only creator can enroll".into());
        }
        let target = c.slots.get_mut(&slot).ok_or("unknown slot")?;
        let expected = target.pending_token.as_ref().ok_or("missing slot token")?;
        if !token_eq(expected, &token) {
            return Err("invalid invite token".into());
        }
        if let Some(existing) = &target.identity {
            if existing != &wire {
                return Err("slot already enrolled".into());
            }
        } else {
            target.identity = Some(wire);
        }
        if c.slots.values().all(|s| s.identity.is_some()) {
            c.fingerprint = Some(hex::encode(roster_of(&c)?.fingerprint()));
        }
        save(&data, &pass, &c)?;
        Ok(json!({"ok":true}))
    })
    .await
}

fn token_eq(expected: &str, given: &str) -> bool {
    if expected.len() != given.len() {
        return false;
    }
    expected
        .bytes()
        .zip(given.bytes())
        .fold(0u8, |diff, (a, b)| diff | (a ^ b))
        == 0
}

fn query_vault(query: &BTreeMap<String, String>) -> Result<String, Reply> {
    let vault = query
        .get("vault")
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "missing vault"))?;
    vault_bytes(vault).map_err(|e| err(StatusCode::BAD_REQUEST, e))?;
    Ok(vault.clone())
}

pub(super) async fn roster(
    State(st): State<Shared>,
    Query(query): Query<BTreeMap<String, String>>,
) -> Reply {
    let vault = match query_vault(&query) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let (data, pass) = match unlocked(&st).await {
        Ok(x) => x,
        Err(e) => return e,
    };
    let reply = blocking(move || {
        let c = load(&data, &pass, &vault)?;
        if c.my_slot != 1 {
            return Err("not creator".into());
        }
        let fingerprint = c.fingerprint.ok_or("roster pending")?;
        let roster: BTreeMap<_, _> = c
            .slots
            .into_iter()
            .map(|(slot, s)| (slot, s.identity))
            .collect();
        Ok(json!({"fingerprint":fingerprint,"roster":roster}))
    })
    .await;
    if reply.1 .0["error"] == "roster pending" {
        err(StatusCode::NOT_FOUND, "roster pending")
    } else {
        reply
    }
}

fn refresh_roster(c: &mut Ceremony) -> Result<(), String> {
    if c.my_slot == 1 {
        return Ok(());
    }
    let remote = peer_request(
        "GET",
        &format!("{}/api/roster?vault={}", c.creator_base_url, c.vault),
        None,
    )?;
    let fingerprint = remote["fingerprint"]
        .as_str()
        .ok_or("missing roster fingerprint")?;
    let roster: BTreeMap<u16, WireIdentity> =
        serde_json::from_value(remote["roster"].clone()).map_err(|e| e.to_string())?;
    let own = c
        .slots
        .get(&c.my_slot)
        .and_then(|s| s.identity.as_ref())
        .ok_or("missing own identity")?;
    if roster.get(&c.my_slot) != Some(own) {
        return Err("creator roster changed this member's identity".into());
    }
    c.slots = roster
        .into_iter()
        .map(|(slot, wire)| {
            (
                slot,
                Slot {
                    identity: Some(wire),
                    pending_token: if slot == c.my_slot {
                        c.slots.get(&slot).and_then(|s| s.pending_token.clone())
                    } else {
                        None
                    },
                },
            )
        })
        .collect();
    let actual = hex::encode(roster_of(c)?.fingerprint());
    if actual != fingerprint {
        return Err("roster fingerprint mismatch".into());
    }
    c.fingerprint = Some(actual);
    Ok(())
}

pub(super) async fn status(st: Shared, vault: String) -> Reply {
    if let Err(e) = vault_bytes(&vault) {
        return err(StatusCode::BAD_REQUEST, e);
    }
    let (data, pass) = match unlocked(&st).await {
        Ok(x) => x,
        Err(e) => return e,
    };
    blocking(move || {
        let _guard = st.ceremony.lock().map_err(|e| e.to_string())?;
        let mut c = load(&data, &pass, &vault)?;
        if c.my_slot != 1 && c.fingerprint.is_none() {
            if refresh_roster(&mut c).is_ok() {
                save(&data, &pass, &c)?;
            }
        }
        let active = dir(&data, &vault)?.exists("vault.sealed");
        let phase = if active {
            "active"
        } else if c.dkg_started || (c.my_slot == 1 && c.agreed.len() == usize::from(c.members)) {
            "creating_keys"
        } else if c.fingerprint.is_some() {
            "compare_roster"
        } else {
            "waiting_for_members"
        };
        let mut value = json!({"phase":phase,"members":c.members,"threshold":c.threshold,
            "confirmations":c.agreed.len(),"fingerprint":c.fingerprint});
        if c.my_slot == 1 {
            value["invites"] = json!(invitations(&c)?);
        }
        if let Some(error) = c.error {
            value["error"] = json!(error);
        }
        Ok(value)
    })
    .await
}

fn spawn_dkg(st: Shared, vault: String, data: std::path::PathBuf, pass: Zeroizing<String>) {
    tokio::spawn(async move {
        let result = blocking(move || run_background(st, &data, &pass, &vault)).await;
        if result.0 != StatusCode::OK {
            eprintln!("ceremony DKG: {}", result.1 .0);
        }
    });
}

pub(super) async fn agree(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    let (Some(vault), Some(fingerprint)) = (body["vault"].as_str(), body["fingerprint"].as_str())
    else {
        return err(StatusCode::BAD_REQUEST, "missing vault or fingerprint");
    };
    let (vault, fingerprint) = (vault.to_owned(), fingerprint.to_owned());
    let (data, pass) = match unlocked(&st).await {
        Ok(x) => x,
        Err(e) => return e,
    };
    let work_data = data.clone();
    let work_pass = pass.clone();
    let work_vault = vault.clone();
    let work_st = st.clone();
    let reply = blocking(move || {
        let _guard = work_st.ceremony.lock().map_err(|e| e.to_string())?;
        let mut c = load(&work_data, &work_pass, &work_vault)?;
        refresh_roster(&mut c)?;
        if c.fingerprint.as_deref() != Some(&fingerprint) {
            return Err("roster fingerprint mismatch".into());
        }
        if c.my_slot != 1 {
            let token = c
                .slots
                .get(&c.my_slot)
                .and_then(|s| s.pending_token.as_ref())
                .ok_or("missing invite token")?;
            peer_request(
                "POST",
                &format!("{}/api/agreed", c.creator_base_url),
                Some(json!({
                    "vault":c.vault,"slot":c.my_slot,"token":token
                })),
            )?;
        }
        c.agreed.insert(c.my_slot);
        save(&work_data, &work_pass, &c)?;
        Ok(json!({"ok":true}))
    })
    .await;
    if reply.0 == StatusCode::OK {
        spawn_dkg(st, vault, data, pass);
    }
    reply
}

pub(super) async fn agreed(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    let (Some(vault), Some(slot), Some(token)) = (
        body["vault"].as_str(),
        body["slot"].as_u64().and_then(|n| u16::try_from(n).ok()),
        body["token"].as_str(),
    ) else {
        return err(StatusCode::BAD_REQUEST, "invalid agreement");
    };
    let (vault, token) = (vault.to_owned(), token.to_owned());
    let (data, pass) = match unlocked(&st).await {
        Ok(x) => x,
        Err(e) => return e,
    };
    let work_data = data.clone();
    let work_pass = pass.clone();
    let work_vault = vault.clone();
    let work_st = st.clone();
    let reply = blocking(move || {
        let _guard = work_st.ceremony.lock().map_err(|e| e.to_string())?;
        let mut c = load(&work_data, &work_pass, &work_vault)?;
        if c.my_slot != 1 || c.fingerprint.is_none() {
            return Err("roster pending".into());
        }
        let expected = c
            .slots
            .get(&slot)
            .and_then(|s| s.pending_token.as_deref())
            .ok_or("unknown slot")?;
        if !token_eq(expected, &token)
            || c.slots
                .get(&slot)
                .and_then(|s| s.identity.as_ref())
                .is_none()
        {
            return Err("invalid agreement token".into());
        }
        c.agreed.insert(slot);
        save(&work_data, &work_pass, &c)?;
        Ok(json!({"ok":true}))
    })
    .await;
    if reply.0 == StatusCode::OK {
        spawn_dkg(st, vault, data, pass);
    }
    reply
}

pub(super) async fn session(
    State(st): State<Shared>,
    Query(query): Query<BTreeMap<String, String>>,
) -> Reply {
    let vault = match query_vault(&query) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let (data, pass) = match unlocked(&st).await {
        Ok(x) => x,
        Err(e) => return e,
    };
    let reply = blocking(move || {
        let c = load(&data, &pass, &vault)?;
        if c.my_slot != 1 {
            return Err("not creator".into());
        }
        Ok(json!({
            "session_id": c.session_id.ok_or("session pending")?,
            "vs_session_id": c.vs_session_id,
        }))
    })
    .await;
    if reply.1 .0["error"] == "session pending" {
        err(StatusCode::NOT_FOUND, "session pending")
    } else {
        reply
    }
}

pub(super) async fn address(
    State(st): State<Shared>,
    Query(query): Query<BTreeMap<String, String>>,
) -> Reply {
    let vault = match query_vault(&query) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let (data, pass) = match unlocked(&st).await {
        Ok(x) => x,
        Err(e) => return e,
    };
    blocking(move || {
        let raw = dir(&data, &vault)?
            .read_sealed("vault.sealed", &pass)
            .map_err(|e| e.to_string())?;
        let value: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
        let address = value["group_address"]
            .as_str()
            .ok_or("sealed vault has no address")?;
        Ok(json!({"address":address}))
    })
    .await
}

fn run_background(st: Shared, data: &Path, pass: &str, vault_id: &str) -> Result<Value, String> {
    let mut c = {
        let _guard = st.ceremony.lock().map_err(|e| e.to_string())?;
        let mut c = load(data, pass, vault_id)?;
        if c.dkg_started || dir(data, vault_id)?.exists("vault.sealed") {
            return Ok(json!({"ok":true}));
        }
        if (c.my_slot == 1 && c.agreed.len() != usize::from(c.members))
            || (c.my_slot != 1 && !c.agreed.contains(&c.my_slot))
        {
            return Ok(json!({"ok":true}));
        }
        c.dkg_started = true;
        save(data, pass, &c)?;
        c
    };
    let outcome: Result<Value, String> = (|| {
        let me = identity(data, pass, c.my_slot)?;
        let roster = roster_of(&c)?;
        let peers: BTreeMap<_, _> = roster
            .members
            .keys()
            .map(|id| (*id, roster.peer_of(id).unwrap()))
            .collect();
        let identity_secret = Zeroizing::new(me.to_secret_bytes());
        let secret: [u8; 32] = identity_secret[34..]
            .try_into()
            .map_err(|_| "identity secret length")?;
        let mut transport =
            FrostdTransport::new(&c.frostd_url, Peer(me.public().encryption), secret)
                .map_err(|e| e.to_string())?;
        let (session_id, coordinator) = if c.my_slot == 1 {
            // frostd needs the session opener (coordinator) to be DISTINCT from the
            // participants — a member cannot both open and join the same session. Open with
            // a fresh ephemeral identity and hold it alive until the DKG completes.
            let coord = crate::setup_transport::Identity::new(0);
            let coord_secret: [u8; 32] = coord.to_secret_bytes()[34..]
                .try_into()
                .map_err(|_| "coordinator secret length")?;
            let mut coord_tx =
                FrostdTransport::new(&c.frostd_url, Peer(coord.public().encryption), coord_secret)
                    .map_err(|e| e.to_string())?;
            let coord_ch = coord_tx
                .open(&roster.peer_list(), 16)
                .map_err(|e| e.to_string())?;
            let id = coord_ch.session_id();
            c.session_id = Some(id);
            {
                let _guard = st.ceremony.lock().map_err(|e| e.to_string())?;
                save(data, pass, &c)?;
            }
            (id, Some((coord_tx, coord_ch)))
        } else {
            let mut found = None;
            for _ in 0..200 {
                if let Ok(response) = peer_request(
                    "GET",
                    &format!("{}/api/session?vault={}", c.creator_base_url, c.vault),
                    None,
                ) {
                    found = response["session_id"]
                        .as_str()
                        .and_then(|s| Uuid::parse_str(s).ok());
                    if found.is_some() {
                        break;
                    }
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            (found.ok_or("creator session not available")?, None)
        };
        let channel = transport.join(session_id).map_err(|e| e.to_string())?;
        let my_id = frost::Identifier::try_from(c.my_slot).map_err(|e| e.to_string())?;
        let (key, public) = run_dkg(
            &transport,
            &channel,
            &me,
            my_id,
            &roster.members,
            &peers,
            &roster.vault_id,
            c.threshold,
        )?;
        // Do NOT close the session here. Member 1 can finish before the slower peers, and
        // close_session would delete it out from under them (frostd 500 SessionNotFound). The
        // relay reaps the session by TTL (24h), refreshed by participant activity; dropping the
        // coordinator's connection does not remove it.
        let ak: [u8; 32] = public
            .verifying_key()
            .serialize()
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "group key length")?;
        // The vault-secret contribution is a separate commit-reveal protocol. Its sealed
        // reveals share the DKG round-2 envelope magic, so running it on the DKG session would
        // corrupt both when they interleave. Open a SECOND session for it (same pattern).
        let (vs_session_id, vs_coordinator) = if c.my_slot == 1 {
            let coord = crate::setup_transport::Identity::new(0);
            let coord_secret: [u8; 32] = coord.to_secret_bytes()[34..]
                .try_into()
                .map_err(|_| "coordinator secret length")?;
            let mut coord_tx =
                FrostdTransport::new(&c.frostd_url, Peer(coord.public().encryption), coord_secret)
                    .map_err(|e| e.to_string())?;
            let coord_ch = coord_tx
                .open(&roster.peer_list(), 16)
                .map_err(|e| e.to_string())?;
            let id = coord_ch.session_id();
            c.vs_session_id = Some(id);
            {
                let _guard = st.ceremony.lock().map_err(|e| e.to_string())?;
                save(data, pass, &c)?;
            }
            (id, Some((coord_tx, coord_ch)))
        } else {
            let mut found = None;
            for _ in 0..200 {
                if let Ok(response) = peer_request(
                    "GET",
                    &format!("{}/api/session?vault={}", c.creator_base_url, c.vault),
                    None,
                ) {
                    found = response["vs_session_id"]
                        .as_str()
                        .and_then(|s| Uuid::parse_str(s).ok());
                    if found.is_some() {
                        break;
                    }
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            (found.ok_or("creator vault-secret session not available")?, None)
        };
        let vs_channel = transport.join(vs_session_id).map_err(|e| e.to_string())?;
        let vault_secret = Zeroizing::new(crate::vault_secret::contribute(
            &transport,
            &vs_channel,
            &me,
            my_id,
            &roster.members,
            &peers,
            &roster.vault_id,
            &ak,
        )?);
        drop(coordinator);
        drop(vs_coordinator);
        let fvk = zip2005::frost_viewing_key(&ak, &vault_secret)
            .map_err(|e| format!("group viewing key: {e:?}"))?;
        let network = VaultNetwork::parse(&st.config.network)?;
        let group_address = vault::unified_address(&fvk, network.network_type());
        let birth_height = match network {
            VaultNetwork::Regtest => 2,
            VaultNetwork::Testnet => {
                let url = st.config.lightwalletd.as_deref().ok_or("Testnet vault requires a lightwalletd URL")?;
                let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
                let channel = runtime.block_on(crate::wallet_store::lightwalletd_endpoint(url)?.connect())
                    .map_err(|e| format!("connect to lightwalletd: {e}"))?;
                let mut client = crate::wallet_store::Lightwalletd::new(channel);
                let info = runtime.block_on(client.get_lightd_info(zcash_client_backend::proto::service::Empty {}))
                    .map_err(|e| format!("lightwalletd info: {e}"))?.into_inner();
                if info.chain_name != "test"
                    || Some(info.sapling_activation_height) != network.activation_height(zcash_protocol::consensus::NetworkUpgrade::Sapling).map(u64::from) {
                    return Err("lightwalletd serves another chain".into());
                }
                u32::try_from(info.block_height).map_err(|_| "chain height overflow")?
            }
        };
        let sealed = json!({
            "vault":c.vault,"threshold":c.threshold,"members":c.members,
            "roster_fingerprint":c.fingerprint,"key_package":hex::encode(key.serialize().map_err(|e| e.to_string())?),
            "public_package":hex::encode(public.serialize().map_err(|e| e.to_string())?),
            "my_frost_id":c.my_slot,"group_address":group_address,
            "group_ak":hex::encode(ak),"vault_secret":hex::encode(&*vault_secret),"birth_height":birth_height,
            "key_derivation":zip2005::VERSION,"network":network.label()
        });
        dir(data, vault_id)?
            .write_sealed(
                "vault.sealed",
                &serde_json::to_vec(&sealed).map_err(|e| e.to_string())?,
                pass,
            )
            .map_err(|e| e.to_string())?;
        Ok(json!({"ok":true}))
    })();
    if let Err(ref error) = outcome {
        let _guard = st.ceremony.lock().map_err(|e| e.to_string())?;
        c.error = Some(error.clone());
        c.dkg_started = false;
        save(data, pass, &c)?;
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::state::{AppState, Config, Session};

    #[test]
    fn roster_requires_every_valid_distinct_member() {
        let mut slots = BTreeMap::new();
        for slot in 1..=3 {
            slots.insert(
                slot,
                Slot {
                    identity: Some(WireIdentity::from_public(Identity::new(slot).public())),
                    pending_token: None,
                },
            );
        }
        let mut c = Ceremony {
            vault: hex::encode([7u8; 32]),
            name: "test".into(),
            members: 3,
            threshold: 2,
            my_slot: 1,
            creator_base_url: String::new(),
            frostd_url: String::new(),
            slots,
            fingerprint: None,
            agreed: BTreeSet::new(),
            session_id: None,
            vs_session_id: None,
            dkg_started: false,
            error: None,
        };
        let fingerprint = roster_of(&c).unwrap().fingerprint();
        assert_eq!(fingerprint, roster_of(&c).unwrap().fingerprint());
        c.slots.get_mut(&2).unwrap().identity = None;
        assert!(roster_of(&c).is_err());
        assert!(token_eq("secret", "secret"));
        assert!(!token_eq("secret", "secreu"));
    }

    #[tokio::test]
    async fn creator_enrolls_three_members_and_publishes_roster() {
        let data = std::env::temp_dir().join(format!("loki-ceremony-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&data).unwrap();
        let st = std::sync::Arc::new(AppState::new(Config {
            data: data.clone(),
            port: 3001,
            network: "regtest".into(),
            lightwalletd: None,
            transport: "local".into(),
            operator_bundle: None,
            operator_key: None,
            enrollment_issuer: None,
            development_http: false,
            token: "test".into(),
            frostd_url: "http://127.0.0.1:2744".into(),
            peers: BTreeMap::new(),
        }));
        *st.session.write().await = Some(Session {
            passphrase: Zeroizing::new("test passphrase".into()),
            data: data.clone(),
        });
        let created = create(
            State(st.clone()),
            Json(json!({"name":"test","members":3,"threshold":2})),
        )
        .await;
        assert_eq!(created.0, StatusCode::OK, "{}", created.1 .0);
        let vault = created.1 .0["vault"].as_str().unwrap().to_owned();
        for slot in 2..=3 {
            let code = created.1 .0["invites"]
                .as_array()
                .unwrap()
                .iter()
                .find(|item| item["slot"] == slot)
                .unwrap()["code"]
                .as_str()
                .unwrap();
            let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(code)
                .unwrap();
            let fields: Value = serde_json::from_slice(&decoded).unwrap();
            assert!(fields.get("vault_secret").is_none());
            eprintln!(
                "invite {slot} fields: {:?}",
                fields.as_object().unwrap().keys().collect::<Vec<_>>()
            );
            let invite: Invite = serde_json::from_slice(&decoded).unwrap();
            let wire = WireIdentity::from_public(Identity::new(slot).public());
            let refused = enroll(
                State(st.clone()),
                Json(json!({"vault":vault,"slot":slot,"token":"wrong","identity":wire})),
            )
            .await;
            assert_eq!(refused.0, StatusCode::BAD_REQUEST);
            let reply = enroll(
                State(st.clone()),
                Json(json!({
                    "vault":vault,"slot":slot,"token":invite.token,
                    "identity":wire
                })),
            )
            .await;
            assert_eq!(reply.0, StatusCode::OK);
        }
        let status = status(st.clone(), vault.clone()).await;
        assert_eq!(status.1 .0["phase"], "compare_roster");
        let response = roster(State(st), Query(BTreeMap::from([("vault".into(), vault)]))).await;
        assert_eq!(response.0, StatusCode::OK);
        assert_eq!(response.1 .0["fingerprint"], status.1 .0["fingerprint"]);
        eprintln!("PASS: emitted invite codes contain no vault_secret");
        std::fs::remove_dir_all(data).unwrap();
    }
}
