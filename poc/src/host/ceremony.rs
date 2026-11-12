//! HTTP enrollment and frostd DKG for one sealed member vault.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::{Path, PathBuf},
    time::{Duration, Instant},
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
    frost_roster::FrostRoster,
    network::VaultNetwork,
    setup_transport::{Identity, PublicIdentity},
    signer::{
        backup::BackupArtifact,
        local::{BackupDevice, DevicePrompts, LocalSigner, RosterDecision},
        Network, Signer,
    },
    state::MemberDir,
    transport::{FrostdLoginKey, FrostdTransport, Peer, RelayLog, Transport},
    vault, zip2005,
};

type Reply = (StatusCode, Json<Value>);

struct HostedBackup {
    dir: PathBuf,
    /// The member data root (`data`), where the recovery identity's PUBLIC key lives.
    member_data: PathBuf,
    pass: Zeroizing<String>,
    se: super::state::HostedSecureElement,
    binding: Vec<u8>,
}

impl BackupDevice for HostedBackup {
    fn passphrase(&mut self) -> Option<Zeroizing<String>> {
        Some(self.pass.clone())
    }
    fn save(&mut self, artifact: &BackupArtifact) -> Result<(), String> {
        if self.dir.join("backup.sealed").exists() {
            self.load()?;
            return Ok(());
        }
        // The inner backup uses the login passphrase; its local copy also needs the element.
        let sealed = crate::signer::secure_element::SealedShare::seal_bound(&self.se, 0, &artifact.0, &self.binding)?;
        crate::signer::durable::write_durable(&self.dir, "backup.sealed", &sealed.to_bytes())
            .map_err(|e| e.to_string())
    }
    fn load(&mut self) -> Result<BackupArtifact, String> {
        let raw = std::fs::read(self.dir.join("backup.sealed")).map_err(|e| e.to_string())?;
        let sealed = crate::signer::secure_element::SealedShare::from_bytes(&raw)
            .map_err(|_| "legacy hosted backup requires migration to secure-element custody")?;
        Ok(BackupArtifact(sealed.open_bound(&self.se, &self.binding)?.to_vec()))
    }
    fn recovery_public(&mut self) -> Option<[u8; 32]> {
        super::recovery::read_encryption_pubkey(&self.member_data)
    }
    fn save_recovery(&mut self, blob: &[u8]) -> Result<(), String> {
        // Opaque HPKE ciphertext, stored as-is beside the sealed share. Account login cannot
        // open it (only the member's recovery words can) — no login/backup conflation.
        std::fs::write(super::recovery::backup_file(&self.dir), blob).map_err(|e| e.to_string())
    }
}

/// The per-vault signer directory (`data/vaults/<vault>/signer`), shared by the DKG driver and
/// the recovery-backup fetch handler so both resolve the same path.
pub(super) fn signer_dir(data: &Path, vault: &str) -> Result<PathBuf, String> {
    Ok(dir(data, vault)?.path().join("signer"))
}

/// Build the passphrase-sealed `vault.sealed` payload that `payment::load_vault` reads. Shared
/// by DKG completion and recovery restore so both emit the identical schema.
#[allow(clippy::too_many_arguments)]
pub(super) fn vault_sealed_bytes(
    vault: &str,
    slot: u16,
    threshold: u16,
    members: u16,
    roster_fingerprint: &str,
    public: &frost::keys::PublicKeyPackage,
    fvk: &orchard::keys::FullViewingKey,
    birth_height: u32,
    network: VaultNetwork,
) -> Result<Vec<u8>, String> {
    let ak: [u8; 32] = public
        .verifying_key()
        .serialize()
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "group key length")?;
    let group_address = vault::unified_address(&fvk, network.network_type());
    let sealed = json!({
        "vault": vault, "threshold": threshold, "members": members,
        "roster_fingerprint": roster_fingerprint,
        "public_package": hex::encode(public.serialize().map_err(|e| e.to_string())?),
        "my_frost_id": slot, "group_address": group_address,
        "group_ak": hex::encode(ak),
        "birth_height": birth_height, "key_derivation": zip2005::VERSION,
        "network": network.label(),
    });
    serde_json::to_vec(&sealed).map_err(|e| e.to_string())
}

/// Recovery restore: rebuild this member's `vault.sealed` (and `identity.sealed` if missing)
/// from the stored recovery backup, opened with the member's 24 words. After this the hosted
/// payment path can re-open the vault and sign, exactly as after the original ceremony.
pub(super) fn restore_vault_from_backup(
    data: &Path,
    vault: &str,
    words: &str,
    pass: &str,
    config: &super::Config,
) -> Result<(), String> {
    let key = crate::signer::recovery::RecoveryKey::from_words(words)?;
    let blob = std::fs::read(super::recovery::backup_file(&signer_dir(data, vault)?))
        .map_err(|_| "no recovery backup for this vault".to_string())?;
    let vault_id = vault_bytes(vault)?;
    let material = crate::signer::backup::verify_recovery(&BackupArtifact(blob), &key, &vault_id)?;

    let pp = frost::keys::PublicKeyPackage::deserialize(&material.public_package)
        .map_err(|e| e.to_string())?;
    let kp = frost::keys::KeyPackage::deserialize(&material.key_package).map_err(|e| e.to_string())?;
    let id = frost::Identifier::try_from(material.member_id).map_err(|e| e.to_string())?;
    if kp.identifier() != &id || kp.verifying_key() != pp.verifying_key()
        || pp.min_signers() != Some(material.threshold)
        || pp.verifying_shares().len() != usize::from(material.members)
        || pp.verifying_shares().get(&id) != Some(kp.verifying_share()) {
        return Err("recovery share differs from its public vault metadata".into());
    }
    let network = match material.network {
        Network::Regtest => VaultNetwork::Regtest,
        Network::Testnet => VaultNetwork::Testnet,
    };
    let fvk = zip2005::frost_viewing_key(&pp.verifying_key().serialize().map_err(|e| e.to_string())?.try_into().map_err(|_| "group key length")?, &material.group_sk)
        .map_err(|e| format!("group viewing key: {e:?}"))?;
    let bytes = vault_sealed_bytes(
        vault,
        material.member_id,
        material.threshold,
        material.members,
        &hex::encode(material.roster_fingerprint),
        &pp,
        &fvk,
        material.birth_height.unwrap_or(0),
        network,
    )?;
    let sdir = signer_dir(data, vault)?;
    let se = config.open_secure_element(&sdir, pass)?;
    let store = if sdir.join("signer.meta").exists() {
        crate::signer::store::SignerStore::open(&sdir)?
    } else {
        crate::signer::store::SignerStore::create(&sdir, material.network, vault_id, material.member_id)?
    };
    if store.vault() != vault_id || store.member() != material.member_id || store.network() != material.network {
        return Err("recovery backup belongs to another signer".into());
    }
    if dir(data, vault)?.exists("vault.sealed") {
        return Err("vault already exists; restore into a fresh device profile".into());
    }
    let previous_epoch = store.read(&se, crate::signer::store::FileKind::Share)?
        .map(|(epoch, _)| epoch).unwrap_or(0);
    let epoch = material.backup_epoch.max(previous_epoch).checked_add(1).ok_or("backup epoch overflow")?;
    store.write(&se, crate::signer::store::FileKind::Share, epoch,
        &crate::signer::local::encode_share(&material.key_package, &material.public_package, &material.group_sk))?;
    dir(data, vault)?
        .write_sealed("vault.sealed", &bytes, pass)
        .map_err(|e| e.to_string())?;

    // A brand-new device also needs the member identity the vault is enrolled under.
    let root = MemberDir::open(data, ".");
    if !root.exists("identity.sealed") && !material.identity.is_empty() {
        root.write_sealed("identity.sealed", &material.identity, pass)
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

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

#[derive(Clone, Default, Serialize, Deserialize)]
struct Slot {
    identity: Option<WireIdentity>,
    #[serde(default)]
    base_url: Option<String>,
    pending_token: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
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
    coordinator_peer: Option<String>,
    #[serde(default)]
    vs_session_id: Option<Uuid>,
    #[serde(default)]
    birth_height: Option<u32>,
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

/// Shared roster policy, including the member cap.
use crate::member_state::valid_policy;

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
            // Active = the DKG produced a sealed key; otherwise the vault is still in setup and
            // has no address yet, so the UI routes it back to its ceremony instead of "send".
            let active = dir(data, &vault).map(|d| d.exists("vault.sealed")).unwrap_or(false);
            out.push(json!({
                "vault": c.vault,
                "name": c.name,
                "members": c.members,
                "threshold": c.threshold,
                "policy": format!("{}-of-{}", c.threshold, c.members),
                "active": active,
            }));
        }
    }
    Ok(out)
}

pub(super) fn identity(data: &Path, pass: &str, slot: u16) -> Result<Identity, String> {
    if !(1..=crate::member_state::MAX_MEMBERS).contains(&slot) {
        return Err("invalid member slot".into());
    }
    let d = MemberDir::create(data, ".").map_err(|e| e.to_string())?;
    match d.read_sealed("identity.sealed", pass) {
        Ok(raw) => {
            let mut raw = Zeroizing::new(raw);
            if raw.len() != 66 { return Err("invalid DKG identity length".into()); }
            // Keys belong to the profile; the FROST slot belongs to each vault.
            raw[..2].copy_from_slice(&slot.to_be_bytes());
            Identity::from_secret_bytes(&raw)
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

/// The authenticated original roster used to authorize a hosted repair.
#[cfg(test)]
pub(super) fn repair_roster(data: &Path, pass: &str, vault: &str) -> Result<FrostRoster, String> {
    let c = load(data, pass, vault)?;
    let roster = roster_of(&c)?;
    if c.fingerprint.as_deref() != Some(hex::encode(roster.fingerprint()).as_str()) {
        return Err("stored roster fingerprint mismatch".into());
    }
    Ok(roster)
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

fn peer_request(config: &super::Config, method: &str, url: &str, body: Option<Value>) -> Result<Value, String> {
    let parsed = reqwest::Url::parse(url).map_err(|e| e.to_string())?;
    config.validate_peer_url(&parsed.origin().ascii_serialization())?;
    let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    runtime.block_on(async {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
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
        || !valid_policy(threshold, usize::from(members))
    {
        return err(
            StatusCode::BAD_REQUEST,
            "name must be 1 to 80 bytes; use 2 <= t < n <= 16",
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
                base_url: Some(st.config.base_url()),
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
                    base_url: None,
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
            creator_base_url: st.config.base_url(),
            frostd_url: st.config.frostd_url.clone(),
            slots,
            fingerprint: None,
            agreed: BTreeSet::new(),
            session_id: None,
            coordinator_peer: None,
            vs_session_id: None,
            birth_height: None,
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
        || !valid_policy(invite.threshold, usize::from(invite.members))
        || !(2..=invite.members).contains(&invite.slot)
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
    if let Err(e) = st.config.validate_peer_url(&invite.creator_base_url) {
        return err(StatusCode::BAD_REQUEST, e);
    }
    let (data, pass) = match unlocked(&st).await {
        Ok(x) => x,
        Err(e) => return e,
    };
    blocking(move || {
        let _guard = st.ceremony.lock().map_err(|e| e.to_string())?;
        let me = identity(&data, &pass, invite.slot)?;
        let wire = WireIdentity::from_public(me.public());
        let mut slots = BTreeMap::new();
        slots.insert(
            invite.slot,
            Slot {
                identity: Some(wire),
                base_url: Some(st.config.base_url()),
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
            coordinator_peer: None,
            vs_session_id: None,
            birth_height: None,
            dkg_started: false,
            error: None,
        };
        let exists = dir(&data, &c.vault)?.exists("ceremony.sealed");
        if exists {
            let old = load(&data, &pass, &c.vault)?;
            if old.my_slot != c.my_slot
                || old.creator_base_url != c.creator_base_url
                || old.members != c.members
                || old.threshold != c.threshold
                || old.name != c.name
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
        }
        peer_request(
            &st.config, "POST",
            &format!("{}/api/enroll", c.creator_base_url),
            Some(json!({
                "vault":c.vault,"slot":c.my_slot,"token":invite.token,
                "identity":c.slots[&c.my_slot].identity,"base_url":st.config.base_url()
            })),
        )?;
        if !exists {
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
    let base_url = body["base_url"].as_str().unwrap_or("").to_owned();
    if let Err(e) = st.config.validate_peer_url(&base_url) {
        return err(StatusCode::BAD_REQUEST, e);
    }
    let public = match wire.public(slot) {
        Ok(p) => p,
        Err(e) => return err(StatusCode::BAD_REQUEST, e),
    };
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
        for (&other, occupied) in &c.slots {
            if other != slot {
                if let Some(identity) = &occupied.identity {
                    if identity.public(other)?.encryption == public.encryption {
                        return Err("duplicate relay address".into());
                    }
                }
            }
        }
        let target = c.slots.get_mut(&slot).ok_or("unknown slot")?;
        let expected = target.pending_token.as_ref().ok_or("missing slot token")?;
        if !token_eq(expected, &token) {
            return Err("invalid invite token".into());
        }
        if let Some(existing) = &target.identity {
            if existing != &wire || target.base_url.as_deref() != Some(&base_url) {
                return Err("slot already enrolled".into());
            }
        } else {
            target.identity = Some(wire);
            target.base_url = Some(base_url);
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
        // The creator is the only node that aggregates every member's agreement, so it also
        // reports the agreed set — joiners merge it to show the full Compare-roster state.
        let agreed: Vec<u16> = c.agreed.iter().copied().collect();
        let base_urls: BTreeMap<_, _> = c.slots.iter()
            .map(|(&slot, s)| (slot, s.base_url.clone())).collect();
        let roster: BTreeMap<_, _> = c
            .slots
            .into_iter()
            .map(|(slot, s)| (slot, s.identity))
            .collect();
        Ok(json!({"fingerprint":fingerprint,"roster":roster,"base_urls":base_urls,"agreed":agreed}))
    })
    .await;
    if reply.1 .0["error"] == "roster pending" {
        err(StatusCode::NOT_FOUND, "roster pending")
    } else {
        reply
    }
}

fn refresh_roster(config: &super::Config, c: &mut Ceremony) -> Result<(), String> {
    if c.my_slot == 1 {
        return Ok(());
    }
    let remote = peer_request(
        config, "GET",
        &format!("{}/api/roster?vault={}", c.creator_base_url, c.vault),
        None,
    )?;
    apply_roster(config, c, &remote)
}

fn apply_roster(config: &super::Config, c: &mut Ceremony, remote: &Value) -> Result<(), String> {
    let fingerprint = remote["fingerprint"]
        .as_str()
        .ok_or("missing roster fingerprint")?;
    if c.fingerprint.as_deref().is_some_and(|old| old != fingerprint) {
        return Err("creator roster changed its fingerprint".into());
    }
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
    let base_urls: BTreeMap<u16, String> = serde_json::from_value(remote["base_urls"].clone())
        .map_err(|_| "missing roster member URLs")?;
    if base_urls.keys().ne(roster.keys()) || base_urls.get(&1) != Some(&c.creator_base_url) {
        return Err("roster member URLs differ from invite".into());
    }
    for (&slot, base) in &base_urls {
        if slot != c.my_slot { config.validate_peer_url(base)?; }
        if c.slots.get(&slot).and_then(|s| s.base_url.as_ref()).is_some_and(|old| old != base) {
            return Err("creator roster changed a member URL".into());
        }
    }
    let mut updated = c.clone();
    updated.slots = roster
        .into_iter()
        .map(|(slot, wire)| {
            (
                slot,
                Slot {
                    identity: Some(wire),
                    base_url: base_urls.get(&slot).cloned(),
                    pending_token: if slot == c.my_slot {
                        c.slots.get(&slot).and_then(|s| s.pending_token.clone())
                    } else {
                        None
                    },
                },
            )
        })
        .collect();
    let actual = hex::encode(roster_of(&updated)?.fingerprint());
    if actual != fingerprint {
        return Err("roster fingerprint mismatch".into());
    }
    updated.fingerprint = Some(actual);
    // Merge the creator's aggregated agreement so a joiner's Compare-roster shows everyone, not
    // just itself. Grow-only: we never drop this member's own agreement on a stale fetch.
    if let Some(agreed) = remote["agreed"].as_array() {
        for slot in agreed.iter().filter_map(|v| v.as_u64()).filter_map(|n| u16::try_from(n).ok()) {
            updated.agreed.insert(slot);
        }
    }
    *c = updated;
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
        // Keep a joiner's view fresh through the agreement phase: re-fetch the creator's roster
        // and agreed set on every poll until the vault seals or the DKG starts, so Compare-roster
        // shows every member's confirmation as they arrive — not just this one. (Fails gracefully
        // until the creator's roster is ready; stops once agreement is over.)
        let active = dir(&data, &vault)?.exists("vault.sealed");
        if c.my_slot != 1 && !active && !c.dkg_started {
            if refresh_roster(&st.config, &mut c).is_ok() {
                save(&data, &pass, &c)?;
            }
        }
        let running_here = st.active_dkgs.lock().map_err(|e| e.to_string())?.contains(&vault);
        let phase = if active {
            "active"
        } else if c.dkg_started && !running_here {
            "setup_interrupted"
        } else if c.dkg_started || (c.my_slot == 1 && c.agreed.len() == usize::from(c.members)) {
            "creating_keys"
        } else if c.fingerprint.is_some() {
            "compare_roster"
        } else {
            "waiting_for_members"
        };
        // Per-member roster-agreement status (the UI's Compare-roster screen expects an array,
        // one entry per member). `agreed` holds the slots that confirmed the matching fingerprint.
        let confirmations: Vec<Value> = (1..=c.members)
            .map(|slot| json!({"slot": slot, "confirmed": c.agreed.contains(&slot), "matches": c.agreed.contains(&slot)}))
            .collect();
        let mut value = json!({"phase":phase,"members":c.members,"threshold":c.threshold,
            "confirmations":confirmations,"fingerprint":c.fingerprint});
        if c.my_slot == 1 {
            value["invites"] = json!(invitations(&c)?);
        }
        if let Some(error) = c.error {
            value["error"] = json!(error);
        } else if phase == "setup_interrupted" {
            value["error"] = json!("DKG interrupted; create a fresh vault");
        }
        Ok(value)
    })
    .await
}

async fn interrupted_dkgs(st: Shared) -> Result<Vec<String>, String> {
    let (data, pass) = match unlocked(&st).await {
        Ok(x) => x,
        Err(_) => return Ok(Vec::new()),
    };
    tokio::task::spawn_blocking(move || {
        let _guard = st.ceremony.lock().map_err(|e| e.to_string())?;
        let active = st.active_dkgs.lock().map_err(|e| e.to_string())?;
        let mut vaults = Vec::new();
        for summary in vault_summaries(&data, &pass)? {
            let Some(vault) = summary["vault"].as_str() else { continue };
            if summary["active"] == true || active.contains(vault) {
                continue;
            }
            if load(&data, &pass, vault).is_ok_and(|c| c.dkg_started) {
                vaults.push(vault.to_owned());
            }
        }
        Ok(vaults)
    })
    .await
    .map_err(|e| format!("task join: {e}"))?
}

pub(super) fn spawn_auto_resume(st: Shared) {
    tokio::spawn(async move {
        loop {
            if let Ok(vaults) = interrupted_dkgs(st.clone()).await {
                for vault in vaults {
                    let _ = resume(State(st.clone()), Json(json!({"vault":vault}))).await;
                }
            }
            // Reopen saved DKG state after a transient error or the bounded wait expires.
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
    });
}

/// Re-drive an INTERRUPTED DKG (a transient frostd/network blip killed the background task,
/// leaving `dkg_started` but no runner). This RESUMES — `run_background` re-opens the persisted
/// signer and `redeliver_dkg` replays the saved relay-log wires, continuing from where it
/// stopped; it never regenerates shares, so it is NOT the re-agree restart the ceremony safety
/// forbids. `run_background` claims the slot under the ceremony lock so concurrent resumes
/// can't double-drive. Without this, one network blip mid-DKG means recreate-and-re-invite.
pub(super) async fn resume(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    let Some(vault) = body["vault"].as_str() else {
        return err(StatusCode::BAD_REQUEST, "missing vault");
    };
    let vault = vault.to_owned();
    let (data, pass) = match unlocked(&st).await {
        Ok(x) => x,
        Err(e) => return e,
    };
    let reply = blocking({
        let (d, p, v, st2) = (data.clone(), pass.clone(), vault.clone(), st.clone());
        move || {
            let _guard = st2.ceremony.lock().map_err(|e| e.to_string())?;
            let c = load(&d, &p, &v)?;
            if !c.dkg_started {
                return Err("no interrupted DKG to resume".into());
            }
            let active = st2.active_dkgs.lock().map_err(|e| e.to_string())?;
            if active.contains(&v) {
                return Ok(json!({ "resumed": false, "reason": "already running" }));
            }
            Ok(json!({ "resumed": true }))
        }
    })
    .await;
    if reply.0 == StatusCode::OK
        && reply.1 .0.get("resumed").and_then(|r| r.as_bool()) == Some(true)
    {
        spawn_dkg(st, vault, data, pass);
    }
    reply
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
        if c.dkg_started {
            return Err("DKG interrupted or already running; create a fresh vault if interrupted".into());
        }
        refresh_roster(&work_st.config, &mut c)?;
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
                &work_st.config, "POST",
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
        let mut birth_height = c.birth_height;
        let store = dir(&data, &vault)?;
        if birth_height.is_none() && store.exists("vault.sealed") {
            // Completed ceremonies from older hosts kept the height only in the vault.
            #[derive(Deserialize)]
            struct VaultHeight { birth_height: u32 }
            let raw = Zeroizing::new(store.read_sealed("vault.sealed", &pass).map_err(|e| e.to_string())?);
            birth_height = Some(serde_json::from_slice::<VaultHeight>(&raw).map_err(|e| e.to_string())?.birth_height);
        }
        Ok(json!({
            "session_id": c.session_id.ok_or("session pending")?,
            "coordinator_peer": c.coordinator_peer,
            "vs_session_id": c.vs_session_id,
            "birth_height": birth_height,
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

// Only the task that claimed the runner may release it, including on errors or unwind.
struct DkgRunner {
    st: Shared,
    vault: String,
}

impl Drop for DkgRunner {
    fn drop(&mut self) {
        if let Ok(mut active) = self.st.active_dkgs.lock() {
            active.remove(&self.vault);
        }
    }
}

fn claim_dkg(st: &Shared, data: &Path, pass: &str, vault_id: &str)
    -> Result<Option<(Ceremony, DkgRunner)>, String>
{
    let _guard = st.ceremony.lock().map_err(|e| e.to_string())?;
    let mut c = load(data, pass, vault_id)?;
    let mut active = st.active_dkgs.lock().map_err(|e| e.to_string())?;
    // dkg_started is persisted across restarts; only active_dkgs tracks a live runner.
    if dir(data, vault_id)?.exists("vault.sealed") || active.contains(vault_id) {
        return Ok(None);
    }
    if (c.my_slot == 1 && c.agreed.len() != usize::from(c.members))
        || (c.my_slot != 1 && !c.agreed.contains(&c.my_slot))
    {
        return Ok(None);
    }
    let resuming = c.dkg_started;
    c.dkg_started = true;
    c.error = None;
    save(data, pass, &c)?;
    active.insert(vault_id.to_owned());
    if resuming {
        eprintln!("ceremony DKG: resuming {vault_id}");
    }
    Ok(Some((c, DkgRunner { st: st.clone(), vault: vault_id.to_owned() })))
}

fn dkg_coordinator(data: &Path, pass: &str, vault_id: &str) -> Result<Identity, String> {
    let store = dir(data, vault_id)?;
    if !store.exists("dkg-coordinator.sealed") {
        let identity = Identity::new(0);
        let raw = Zeroizing::new(identity.to_secret_bytes());
        store.write_sealed("dkg-coordinator.sealed", &*raw, pass).map_err(|e| e.to_string())?;
    }
    let raw = Zeroizing::new(store.read_sealed("dkg-coordinator.sealed", pass).map_err(|e| e.to_string())?);
    Identity::from_secret_bytes(&raw)
}

fn run_background(st: Shared, data: &Path, pass: &str, vault_id: &str) -> Result<Value, String> {
    let Some((mut c, _runner)) = claim_dkg(&st, data, pass, vault_id)? else {
        return Ok(json!({"ok":true}));
    };
    let outcome: Result<Value, String> = (|| {
        let me = identity(data, pass, c.my_slot)?;
        let roster = roster_of(&c)?;
        let network = VaultNetwork::parse(&st.config.network)?;
        let identity_secret = Zeroizing::new(me.to_secret_bytes());
        let signer_dir = signer_dir(data, vault_id)?;
        let se = st.config.open_secure_element(&signer_dir, pass)?;
        let signer_network = match network {
            VaultNetwork::Regtest => Network::Regtest,
            VaultNetwork::Testnet => Network::Testnet,
        };
        let prompts = DevicePrompts {
            connect: Box::new(|_, _| true),
            // The hosted flow already required this member's roster agreement.
            roster: Box::new(|_| RosterDecision::Match),
            roster_deadline: Duration::from_secs(60),
            backup: Box::new(HostedBackup {
                dir: signer_dir.clone(),
                member_data: data.to_path_buf(),
                pass: Zeroizing::new(pass.to_owned()),
                se: st.config.open_secure_element(&signer_dir, pass)?,
                binding: crate::signer::secure_element::file_binding("backup", &roster.vault_id, c.my_slot),
            }),
            approval: Box::new(|_| false),
        };
        let mut signer = if signer_dir.join("signer.meta").exists() {
            LocalSigner::open(&signer_dir, se, c.name.clone(), prompts)
        } else {
            LocalSigner::create_with_identity(
                &signer_dir, se, signer_network, roster.vault_id, c.my_slot,
                c.name.clone(), prompts, Identity::from_secret_bytes(&identity_secret[..])?,
            )
        }.map_err(|e| e.to_string())?;
        let connection = signer.connect(&c.creator_base_url, signer_network, b"hosted DKG")
            .map_err(|e| e.to_string())?;
        if connection.member.encryption != me.public().encryption {
            return Err("signer identity differs from enrolled member".into());
        }
        let session = connection.session;
        // One hour per runner, including waiting for the creator; expiry only pauses setup.
        let deadline = Instant::now() + Duration::from_secs(60 * 60);
        let saved_height = signer.setup_birth_height();
        let observed_height = match network {
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
        let mut birth_height = c.birth_height.or(saved_height);
        if c.my_slot == 1 && birth_height.is_none() {
            birth_height = Some(observed_height);
        }
        let peers: BTreeMap<u16, Peer> = roster.members.values()
            .map(|identity| (identity.id, Peer(identity.encryption))).collect();
        let secret: [u8; 32] = identity_secret[34..]
            .try_into().map_err(|_| "identity secret length")?;
        let mut transport = FrostdTransport::new(
            &c.frostd_url, FrostdLoginKey::from_secret_bytes(secret),
        ).map_err(|e| e.to_string())?;
        let (session_id, coordinator, coordinator_peer) = if c.my_slot == 1 {
            // frostd requires a distinct session opener; id 0 is not a DKG member.
            let coord = dkg_coordinator(data, pass, vault_id)?;
            let raw = Zeroizing::new(coord.to_secret_bytes());
            let coord_secret: [u8; 32] = raw[34..].try_into()
                .map_err(|_| "coordinator secret length")?;
            let mut coord_tx = FrostdTransport::new(
                &c.frostd_url, FrostdLoginKey::from_secret_bytes(coord_secret),
            ).map_err(|e| e.to_string())?;
            let peer = Peer(coord.public().encryption);
            let coord_ch = match c.session_id.filter(|_| c.coordinator_peer.as_deref() == Some(&hex::encode(peer.0))) {
                Some(id) => coord_tx.join(id),
                None => coord_tx.open(&roster.peer_list(), 255),
            }.map_err(|e| e.to_string())?;
            let id = coord_ch.session_id();
            c.birth_height = birth_height;
            c.session_id = Some(id);
            c.coordinator_peer = Some(hex::encode(peer.0));
            {
                let _guard = st.ceremony.lock().map_err(|e| e.to_string())?;
                save(data, pass, &c)?;
            }
            (id, Some((coord_tx, coord_ch)), peer)
        } else {
            let mut found = None;
            while Instant::now() < deadline {
                if let Ok(response) = peer_request(
                    &st.config, "GET", &format!("{}/api/session?vault={}", c.creator_base_url, c.vault), None,
                ) {
                    if let (Some(id), Some(peer)) = (
                        response["session_id"].as_str().and_then(|s| Uuid::parse_str(s).ok()),
                        response["coordinator_peer"].as_str().and_then(|s| hex::decode(s).ok())
                            .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok()),
                    ) {
                        birth_height = match network {
                            VaultNetwork::Regtest => Some(2),
                            VaultNetwork::Testnet => response["birth_height"].as_u64()
                                .and_then(|height| u32::try_from(height).ok()),
                        };
                        if birth_height.is_some() {
                            found = Some((id, Peer(peer)));
                            break;
                        }
                    }
                }
                std::thread::sleep(Duration::from_secs(1));
            }
            let (id, peer) = found.ok_or("creator session not available")?;
            (id, None, peer)
        };
        let birth_height = birth_height.ok_or("creator birth height not available")?;
        if c.birth_height.is_some_and(|height| height != birth_height)
            || saved_height.is_some_and(|height| height != birth_height) {
            return Err("creator birth height differs from the saved setup roster".into());
        }
        c.birth_height = Some(birth_height);
        {
            let _guard = st.ceremony.lock().map_err(|e| e.to_string())?;
            save(data, pass, &c)?;
        }
        let channel = transport.join(session_id).map_err(|e| e.to_string())?;
        let document = json!({
            "vault": c.vault, "threshold": c.threshold, "setup_version": 2,
            "network": network.label(),
            "members": roster.members.values().map(|p| json!({
                "id": p.id, "signing": hex::encode(p.signing),
                "encryption": hex::encode(p.encryption),
            })).collect::<Vec<_>>(),
        });
        let mut document = document;
        if network == VaultNetwork::Testnet {
            document["birth_height"] = json!(birth_height);
        }
        let vault_ref = if signer.list_vaults(&session).map_err(|e| e.to_string())?.is_empty() {
            signer.dkg_begin(&session, &serde_json::to_vec(&document).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?
        } else {
            signer.list_vaults(&session).map_err(|e| e.to_string())?.remove(0)
        };
        let mut log = if c.my_slot == 1 {
            Some(RelayLog::open(&dir(data, vault_id)?.path().join("dkg-relay"), c.members)
                .map_err(|e| e.to_string())?)
        } else { None };
        crate::signer::coordination::drive_dkg(
            &mut signer, &session, &vault_ref, &transport, &channel, &coordinator_peer,
            coordinator.as_ref().map(|(tx, ch)| (tx, ch)), log.as_mut(), &peers,
            deadline,
        )?;
        if let Some(log) = log {
            if log.active() { log.delete().map_err(|e| e.to_string())?; }
        }
        // Keep the frostd session open until the relay's TTL; peers may still be finishing.
        let (public, fvk) = signer.hosted_metadata().map_err(|e| e.to_string())?;
        let sealed = vault_sealed_bytes(
            &c.vault,
            c.my_slot,
            c.threshold,
            c.members,
            c.fingerprint.as_deref().unwrap_or(""),
            &public,
            &fvk,
            birth_height,
            network,
        )?;
        dir(data, vault_id)?
            .write_sealed("vault.sealed", &sealed, pass)
            .map_err(|e| e.to_string())?;
        Ok(json!({"ok":true}))
    })();
    if let Err(ref error) = outcome {
        let _guard = st.ceremony.lock().map_err(|e| e.to_string())?;
        c.error = Some(error.clone());
        save(data, pass, &c)?;
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::host::state::{AppState, Config, Session};

    fn dkg_fixture(dkg_started: bool) -> (Shared, Ceremony) {
        let data = std::env::temp_dir().join(format!("loki-dkg-runner-{}", Uuid::new_v4()));
        let c = Ceremony {
            vault: hex::encode([8u8; 32]), name: "test".into(), members: 3, threshold: 2,
            my_slot: 1, creator_base_url: String::new(), frostd_url: String::new(),
            slots: BTreeMap::new(), fingerprint: None, agreed: (1..=3).collect(),
            session_id: None, coordinator_peer: None, vs_session_id: None,
            birth_height: None, dkg_started, error: None,
        };
        save(&data, "pass", &c).unwrap();
        let st = std::sync::Arc::new(AppState::new(Config {
            registration: None,
            bind: "127.0.0.1".parse().unwrap(), advertise_url: None,
            data, port: 3001, network: "regtest".into(),
            lightwalletd: None, transport: "local".into(), secure_element: "software".into(),
            operator_bundle: None, nonce_witnesses: None, operator_key: None, enrollment_issuer: None,
            development_http: false, token: "test".into(), frostd_url: String::new(),
            peers: BTreeMap::new(), loopback_peers: false,
        }));
        (st, c)
    }

    #[test]
    fn member_identity_uses_vault_local_slots_without_replacing_keys() {
        let (st, _) = dkg_fixture(false);
        let first = identity(&st.config.data, "pass", 1).unwrap().public();
        let third = identity(&st.config.data, "pass", 3).unwrap().public();
        assert_eq!((first.id, third.id), (1, 3));
        assert_eq!(first.signing, third.signing);
        assert_eq!(first.encryption, third.encryption);
        assert_eq!(identity(&st.config.data, "pass", 1).unwrap().public(), first);
        let raw = MemberDir::open(&st.config.data, ".").read_sealed("identity.sealed", "pass").unwrap();
        assert_eq!(Identity::from_secret_bytes(&raw).unwrap().public(), first);
        assert!(identity(&st.config.data, "pass", 0).is_err());
        assert!(identity(&st.config.data, "pass", crate::member_state::MAX_MEMBERS + 1).is_err());
        std::fs::remove_dir_all(&st.config.data).unwrap();
    }

    #[test]
    fn roster_refresh_rejects_changed_keys_and_preserves_state_on_error() {
        let (st, mut c) = dkg_fixture(false);
        c.my_slot = 2;
        c.creator_base_url = "http://127.0.0.1:3001".into();
        c.agreed.clear();
        for slot in 1..=3 {
            c.slots.insert(slot, Slot {
                identity: Some(WireIdentity::from_public(Identity::new(slot).public())),
                base_url: Some(format!("http://127.0.0.1:{}", 3000 + slot)),
                pending_token: None,
            });
        }
        let mut remote = json!({
            "fingerprint": hex::encode(roster_of(&c).unwrap().fingerprint()),
            "roster": c.slots.iter().map(|(&slot, s)| (slot, &s.identity)).collect::<BTreeMap<_, _>>(),
            "base_urls": c.slots.iter().map(|(&slot, s)| (slot, &s.base_url)).collect::<BTreeMap<_, _>>(),
            "agreed": [1, 2],
        });
        c.slots.retain(|slot, _| *slot == 2);
        let before = serde_json::to_value(&c).unwrap();
        let mut bad = remote.clone();
        bad["fingerprint"] = json!(hex::encode([0; 32]));
        assert!(apply_roster(&st.config, &mut c, &bad).is_err());
        assert_eq!(serde_json::to_value(&c).unwrap(), before, "rejected roster must not change state");
        apply_roster(&st.config, &mut c, &remote).unwrap();
        let before = serde_json::to_value(&c).unwrap();
        c.slots.get_mut(&3).unwrap().identity = Some(WireIdentity::from_public(Identity::new(3).public()));
        remote["roster"]["3"] = json!(c.slots[&3].identity);
        remote["fingerprint"] = json!(hex::encode(roster_of(&c).unwrap().fingerprint()));
        c = serde_json::from_value(before.clone()).unwrap();
        assert!(apply_roster(&st.config, &mut c, &remote).is_err(), "accepted roster keys must stay pinned");
        assert_eq!(serde_json::to_value(&c).unwrap(), before);
        std::fs::remove_dir_all(&st.config.data).unwrap();
    }

    #[tokio::test]
    async fn conflicting_join_is_rejected_before_remote_enrollment() {
        let (st, mut c) = dkg_fixture(false);
        c.my_slot = 2;
        c.creator_base_url = "http://127.0.0.1:65534".into();
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([1; 32]);
        let wire = WireIdentity::from_public(identity(&st.config.data, "pass", 2).unwrap().public());
        c.slots.insert(2, Slot { identity: Some(wire), base_url: Some(st.config.base_url()), pending_token: Some(token.clone()) });
        save(&st.config.data, "pass", &c).unwrap();
        *st.session.write().await = Some(Session { passphrase: Zeroizing::new("pass".into()), data: st.config.data.clone() });
        let invite = Invite {
            vault: c.vault.clone(), slot: 2, creator_base_url: c.creator_base_url.clone(), token,
            members: 4, threshold: 2, name: c.name.clone(),
        };
        let code = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(serde_json::to_vec(&invite).unwrap());
        let reply = join(State(st.clone()), Json(json!({"invite":code}))).await;
        assert_eq!(reply.1 .0["error"], "existing ceremony does not match invite");
        assert_eq!(serde_json::to_value(load(&st.config.data, "pass", &c.vault).unwrap()).unwrap(), serde_json::to_value(c).unwrap());
        std::fs::remove_dir_all(&st.config.data).unwrap();
    }

    #[tokio::test]
    async fn creator_invites_use_own_advertised_url_or_loopback_default() {
        for advertised in [None, Some("http://100.109.83.103:7003")] {
            let (mut st, _) = dkg_fixture(false);
            let config = &mut std::sync::Arc::get_mut(&mut st).unwrap().config;
            config.port = 7003;
            config.advertise_url = advertised.map(str::to_owned);
            config.peers.insert(1, "http://100.83.113.38:7001".into());
            *st.session.write().await = Some(Session {
                passphrase: Zeroizing::new("pass".into()), data: st.config.data.clone(),
            });
            let created = create(
                State(st.clone()), Json(json!({"name":"test","members":3,"threshold":2})),
            ).await;
            assert_eq!(created.0, StatusCode::OK, "{}", created.1 .0);
            let expected = advertised.unwrap_or("http://127.0.0.1:7003");
            for item in created.1 .0["invites"].as_array().unwrap() {
                let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .decode(item["code"].as_str().unwrap()).unwrap();
                let invite: Invite = serde_json::from_slice(&raw).unwrap();
                assert_eq!(invite.creator_base_url, expected);
                let saved = load(&st.config.data, "pass", &invite.vault).unwrap();
                assert_eq!(saved.creator_base_url, expected);
            }
            std::fs::remove_dir_all(&st.config.data).unwrap();
        }
    }

    #[tokio::test]
    async fn creator_session_publishes_saved_birth_height_to_late_members() {
        let (st, mut c) = dkg_fixture(true);
        c.session_id = Some(Uuid::new_v4());
        c.coordinator_peer = Some(hex::encode([4; 32]));
        let mut saved = serde_json::to_value(&c).unwrap();
        saved["birth_height"] = json!(3_000_000);
        let c: Ceremony = serde_json::from_value(saved.clone()).unwrap();
        save(&st.config.data, "pass", &c).unwrap();
        *st.session.write().await = Some(Session {
            passphrase: Zeroizing::new("pass".into()), data: st.config.data.clone(),
        });
        let reply = session(State(st.clone()), Query(BTreeMap::from([("vault".into(), c.vault)]))).await;
        assert_eq!(reply.0, StatusCode::OK);
        assert_eq!(reply.1 .0["birth_height"], 3_000_000);

        // A creator that finished under the old host has the height only in vault.sealed.
        saved.as_object_mut().unwrap().remove("birth_height");
        let c: Ceremony = serde_json::from_value(saved).unwrap();
        save(&st.config.data, "pass", &c).unwrap();
        dir(&st.config.data, &c.vault).unwrap().write_sealed(
            "vault.sealed", br#"{"birth_height":3000000}"#, "pass",
        ).unwrap();
        let reply = session(State(st.clone()), Query(BTreeMap::from([("vault".into(), c.vault)]))).await;
        assert_eq!(reply.0, StatusCode::OK);
        assert_eq!(reply.1 .0["birth_height"], 3_000_000);
        std::fs::remove_dir_all(&st.config.data).unwrap();
    }

    #[test]
    fn dkg_coordinator_identity_survives_resume_and_rejects_wrong_passphrase() {
        let (st, c) = dkg_fixture(true);
        let first = dkg_coordinator(&st.config.data, "pass", &c.vault).unwrap().public();
        let again = dkg_coordinator(&st.config.data, "pass", &c.vault).unwrap().public();
        assert_eq!(first, again);
        assert_eq!(first.id, 0);
        assert!(dkg_coordinator(&st.config.data, "wrong", &c.vault).is_err());
        assert_eq!(dkg_coordinator(&st.config.data, "pass", &c.vault).unwrap().public(), first);
        std::fs::remove_dir_all(&st.config.data).unwrap();
    }

    #[tokio::test]
    async fn auto_resume_scan_selects_only_interrupted_dkgs_when_unlocked() {
        let (st, mut c) = dkg_fixture(true);
        let data = &st.config.data;
        let interrupted = c.vault.clone();
        c.vault = hex::encode([9u8; 32]);
        save(data, "pass", &c).unwrap();
        dir(data, &c.vault).unwrap().write_sealed("vault.sealed", b"sealed", "pass").unwrap();
        c.vault = hex::encode([10u8; 32]);
        save(data, "pass", &c).unwrap();
        let (_, running) = claim_dkg(&st, data, "pass", &c.vault).unwrap().unwrap();
        c.vault = hex::encode([11u8; 32]);
        c.dkg_started = false;
        save(data, "pass", &c).unwrap();

        assert!(interrupted_dkgs(st.clone()).await.unwrap().is_empty());
        *st.session.write().await = Some(Session {
            passphrase: Zeroizing::new("pass".into()), data: data.clone(),
        });
        assert_eq!(interrupted_dkgs(st.clone()).await.unwrap(), vec![interrupted.clone()]);
        assert_eq!(st.active_dkgs.lock().unwrap().len(), 1);
        assert!(!load(data, "pass", &c.vault).unwrap().dkg_started);

        // A browser resume winning the claim makes the next scan skip this vault too.
        let (_, resumed) = claim_dkg(&st, data, "pass", &interrupted).unwrap().unwrap();
        assert!(interrupted_dkgs(st.clone()).await.unwrap().is_empty());
        drop(resumed);
        assert_eq!(interrupted_dkgs(st.clone()).await.unwrap(), vec![interrupted]);
        *st.session.write().await = None;
        assert!(interrupted_dkgs(st.clone()).await.unwrap().is_empty());
        drop(running);
        std::fs::remove_dir_all(data).unwrap();
    }

    #[tokio::test]
    async fn dkg_runner_resumes_interrupted_ceremony_without_double_driving() {
        let (st, c) = dkg_fixture(true);
        let data = &st.config.data;
        assert!(!dir(data, &c.vault).unwrap().exists("vault.sealed"));
        assert!(st.active_dkgs.lock().unwrap().is_empty());
        let (claimed, runner) = claim_dkg(&st, data, "pass", &c.vault).unwrap()
            .expect("an interrupted DKG must acquire a runner");
        assert!(claimed.dkg_started);
        assert!(load(data, "pass", &c.vault).unwrap().dkg_started);
        assert!(st.active_dkgs.lock().unwrap().contains(&c.vault));
        assert!(claim_dkg(&st, data, "pass", &c.vault).unwrap().is_none());
        *st.session.write().await = Some(Session {
            passphrase: Zeroizing::new("pass".into()), data: data.clone(),
        });
        let reply = resume(State(st.clone()), Json(json!({"vault":c.vault}))).await;
        assert_eq!(reply.0, StatusCode::OK);
        assert_eq!(reply.1 .0, json!({"resumed":false,"reason":"already running"}));
        assert!(st.active_dkgs.lock().unwrap().contains(&c.vault));
        drop(runner);
        assert!(st.active_dkgs.lock().unwrap().is_empty());
        assert!(claim_dkg(&st, data, "pass", &c.vault).unwrap().is_some());
        std::fs::remove_dir_all(data).unwrap();
    }

    #[test]
    fn dkg_runner_claim_is_exclusive_for_concurrent_fresh_starts() {
        let (st, c) = dkg_fixture(false);
        let data = &st.config.data;
        let barrier = std::sync::Barrier::new(2);
        let claims = std::thread::scope(|scope| {
            let start = || {
                barrier.wait();
                claim_dkg(&st, data, "pass", &c.vault).unwrap()
            };
            let first = scope.spawn(start);
            let second = scope.spawn(start);
            [first.join().unwrap(), second.join().unwrap()]
        });
        assert_eq!(claims.iter().filter(|claim| claim.is_some()).count(), 1);
        assert!(load(data, "pass", &c.vault).unwrap().dkg_started);
        assert!(st.active_dkgs.lock().unwrap().contains(&c.vault));
        // A skipped background task must not release the live runner's claim.
        assert!(run_background(st.clone(), data, "pass", &c.vault).is_ok());
        assert!(st.active_dkgs.lock().unwrap().contains(&c.vault));
        drop(claims);
        assert!(st.active_dkgs.lock().unwrap().is_empty());
        std::fs::remove_dir_all(data).unwrap();
    }

    #[test]
    fn dkg_runner_requires_agreement_and_an_unsealed_vault() {
        let (st, mut c) = dkg_fixture(false);
        let data = &st.config.data;
        c.agreed.clear();
        for slot in [1, 2] {
            c.my_slot = slot;
            save(data, "pass", &c).unwrap();
            assert!(claim_dkg(&st, data, "pass", &c.vault).unwrap().is_none());
            assert!(!load(data, "pass", &c.vault).unwrap().dkg_started);
            assert!(st.active_dkgs.lock().unwrap().is_empty());
        }
        c.agreed = (1..=3).collect();
        save(data, "pass", &c).unwrap();
        dir(data, &c.vault).unwrap().write_sealed("vault.sealed", b"sealed", "pass").unwrap();
        assert!(claim_dkg(&st, data, "pass", &c.vault).unwrap().is_none());
        assert!(!load(data, "pass", &c.vault).unwrap().dkg_started);
        assert!(st.active_dkgs.lock().unwrap().is_empty());
        std::fs::remove_dir_all(data).unwrap();
    }

    #[test]
    fn dkg_runner_releases_claim_on_failure() {
        let (st, c) = dkg_fixture(false);
        let data = &st.config.data;
        // The empty roster fails before any relay connection is attempted.
        assert!(run_background(st.clone(), data, "pass", &c.vault).is_err());
        assert!(st.active_dkgs.lock().unwrap().is_empty());
        let saved = load(data, "pass", &c.vault).unwrap();
        assert!(saved.dkg_started);
        assert!(saved.error.is_some());
        std::fs::remove_dir_all(data).unwrap();
    }

    #[test]
    fn custody_real_dkg_exports_only_public_vault_metadata() {
        let vault_id = [71; 32];
        let vault = hex::encode(vault_id);
        let members = crate::signer::local::setup_tests::completed_signers(vault_id);
        for (index, (signer, path)) in members.iter().enumerate() {
            let (public, fvk) = signer.hosted_metadata().unwrap();
            let bytes = vault_sealed_bytes(&vault, index as u16 + 1, 2, 3, "", &public, &fvk, 2, VaultNetwork::Regtest).unwrap();
            let store = MemberDir::open(path, "");
            store.write_sealed("vault.sealed", &bytes, "password only").unwrap();
            let raw = store.read_sealed("vault.sealed", "password only").unwrap();
            let metadata: Value = serde_json::from_slice(&raw).unwrap();
            assert!(metadata.get("key_package").is_none());
            assert!(metadata.get("vault_secret").is_none());
            assert!(store.read_sealed("share.sealed", "password only").is_err());
            let sealed = crate::signer::secure_element::SealedShare::from_bytes(&std::fs::read(path.join("share.sealed")).unwrap()).unwrap();
            let binding = crate::signer::secure_element::file_binding("share", &vault_id, index as u16 + 1);
            assert!(sealed.open_bound(&crate::signer::secure_element::SoftwareSecureElement::generate(), &binding).is_err());
        }
        for (_, path) in members { std::fs::remove_dir_all(path).unwrap(); }
    }

    #[test]
    fn recovery_restore_rebuilds_the_sealed_vault_from_the_words() {
        use crate::signer::backup::{create_to_recovery, BackupMaterial};
        use crate::signer::recovery::RecoveryKey;
        let (st, _) = dkg_fixture(false);

        let data = std::env::temp_dir().join(format!("loki-restore-{}", Uuid::new_v4()));
        let vault_id = [7u8; 32];
        let vault = hex::encode(vault_id);
        let sdir = signer_dir(&data, &vault).unwrap();
        std::fs::create_dir_all(&sdir).unwrap();

        // A dealt 2-of-3 vault's member-1 material, as the ceremony would have produced.
        let (shares, public) = frost::keys::generate_with_dealer(
            3,
            2,
            frost::keys::IdentifierList::Default,
            &mut OsRng,
        )
        .unwrap();
        let id1 = frost::Identifier::try_from(1u16).unwrap();
        let kp1 = frost::keys::KeyPackage::try_from(shares.get(&id1).unwrap().clone()).unwrap();
        let material = BackupMaterial {
            member_id: 1,
            threshold: 2,
            members: 3,
            network: Network::Regtest,
            vault_id,
            label: "restore vault".into(),
            group_sk: [42u8; 32],
            key_package: Zeroizing::new(kp1.serialize().unwrap()),
            public_package: public.serialize().unwrap(),
            backup_epoch: 0,
            identity: Zeroizing::new(Vec::new()),
            roster: Vec::new(),
            roster_fingerprint: [0; 32],
            birth_height: Some(100),
        };

        let mut hosted_backup = HostedBackup {
            dir: sdir.clone(), member_data: data.clone(), pass: Zeroizing::new("pass".into()),
            se: st.config.open_secure_element(&sdir, "pass").unwrap(),
            binding: crate::signer::secure_element::file_binding("backup", &vault_id, 1),
        };
        let password_backup = crate::signer::backup::create(&material, "pass").unwrap();
        hosted_backup.save(&password_backup).unwrap();
        assert!(MemberDir::open(&sdir, "").read_sealed("backup.sealed", "pass").is_err(),
            "hosted backup is another password-only copy of the FROST share");
        assert_eq!(hosted_backup.load().unwrap().0, password_backup.0);

        // First launch: a recovery identity backs the share up to its words.
        let (words, key) = RecoveryKey::generate().unwrap();
        let artifact = create_to_recovery(&material, &key.public_bytes()).unwrap();
        std::fs::write(super::super::recovery::backup_file(&sdir), &artifact.0).unwrap();

        // The share is gone; restore rebuilds vault.sealed from the words.
        assert!(!dir(&data, &vault).unwrap().exists("vault.sealed"));
        restore_vault_from_backup(&data, &vault, &words, "pass", &st.config).unwrap();

        // The restored sealed vault carries exactly the backed-up share, and payment reads it.
        let raw = dir(&data, &vault).unwrap().read_sealed("vault.sealed", "pass").unwrap();
        let v: Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(v["my_frost_id"].as_u64(), Some(1));
        assert_eq!(v["network"].as_str(), Some("regtest"));
        assert!(v.get("key_package").is_none());
        assert!(v.get("vault_secret").is_none());
        let se = crate::signer::secure_element::SoftwareSecureElement::persistent(&sdir, "pass").unwrap();
        let store = crate::signer::store::SignerStore::open(&sdir).unwrap();
        let (epoch, raw) = store.read(&se, crate::signer::store::FileKind::Share).unwrap().unwrap();
        assert_eq!(epoch, 1);
        let (key, restored_public, secret) = crate::signer::local::decode_share(&raw).unwrap();
        assert_eq!(*key, *material.key_package);
        assert_eq!(restored_public, material.public_package);
        assert_eq!(secret, material.group_sk);

        // The recovered share produces a real, verifiable rerandomized FROST signature.
        let candidate = crate::signer::CandidateRef { vault_id, payment_id: [8; 32], attempt_id: [9; 32] };
        let approved = std::sync::Arc::new(std::sync::Mutex::new(None));
        let decision = approved.clone();
        let fvk = zip2005::frost_viewing_key(&public.verifying_key().serialize().unwrap().try_into().unwrap(), &secret).unwrap();
        let nonces = crate::signer::nonce::NonceStore::open_at_epoch(&sdir.join("restored-nonces"), epoch).unwrap();
        let mut signer = LocalSigner::from_restored(1, 2, 3, vault_id, "restored".into(), Network::Regtest,
            se, &key, restored_public, fvk.clone(), epoch, nonces,
            Box::new(move |request| *decision.lock().unwrap() == Some((*request.candidate, request.sighash))), None).unwrap();
        let session = signer.connect("restore test", Network::Regtest, b"restore").unwrap().session;
        let own = signer.sign_commit(&session, &candidate).unwrap();
        let peer = frost::keys::KeyPackage::try_from(shares[&frost::Identifier::try_from(2u16).unwrap()].clone()).unwrap();
        let (peer_nonces, peer_commit) = frost::round1::commit(peer.signing_share(), &mut OsRng);
        let (pczt, package, seed) = crate::signer::local::tests::candidate_and_package(
            &fvk, &kp1, &public, *peer.identifier(), peer_commit, own, true);
        *approved.lock().unwrap() = Some((candidate, package.message().as_slice().try_into().unwrap()));
        let own_share = signer.sign_approve(&session, &candidate, &pczt, &package, &seed).unwrap();
        let peer_share = frost_rerandomized::sign_with_randomizer_seed(&package, &peer_nonces, &peer, &seed).unwrap();
        let params = frost_rerandomized::RandomizedParams::regenerate_from_seed_and_commitments(
            public.verifying_key(), &seed, package.signing_commitments()).unwrap();
        let signature = frost_rerandomized::aggregate(&package,
            &BTreeMap::from([(id1, own_share), (*peer.identifier(), peer_share)]), &public, &params).unwrap();
        params.randomized_verifying_key().verify(package.message(), &signature).unwrap();

        // Wrong words cannot restore.
        let _ = std::fs::remove_file(dir(&data, &vault).unwrap().path().join("vault.sealed"));
        let (other_words, _) = RecoveryKey::generate().unwrap();
        assert!(restore_vault_from_backup(&data, &vault, &other_words, "pass", &st.config).is_err());

        let _ = std::fs::remove_dir_all(&data);
        std::fs::remove_dir_all(&st.config.data).unwrap();
    }

    #[test]
    fn roster_requires_every_valid_distinct_member() {
        let mut slots = BTreeMap::new();
        for slot in 1..=3 {
            slots.insert(
                slot,
                Slot {
                    identity: Some(WireIdentity::from_public(Identity::new(slot).public())),
                    base_url: None,
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
            coordinator_peer: None,
            vs_session_id: None,
            birth_height: None,
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
    async fn interrupted_dkg_cannot_be_restarted_by_agreeing_again() {
        let data = std::env::temp_dir().join(format!("loki-interrupted-dkg-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&data).unwrap();
        let vault = hex::encode([8u8; 32]);
        let slots = (1..=3)
            .map(|slot| (slot, Slot { identity: None, base_url: None, pending_token: Some("token".into()) }))
            .collect();
        let ceremony = Ceremony {
            vault: vault.clone(), name: "test".into(), members: 3, threshold: 2,
            my_slot: 1, creator_base_url: String::new(), frostd_url: String::new(),
            slots, fingerprint: Some("fingerprint".into()), agreed: BTreeSet::new(),
            session_id: None, coordinator_peer: None, vs_session_id: None,
            birth_height: None, dkg_started: true, error: None,
        };
        save(&data, "pass", &ceremony).unwrap();
        let st = std::sync::Arc::new(AppState::new(Config {
            registration: None,
            bind: "127.0.0.1".parse().unwrap(), advertise_url: None,
            data: data.clone(), port: 3001, network: "regtest".into(),
            lightwalletd: None, transport: "local".into(), secure_element: "software".into(), operator_bundle: None, nonce_witnesses: None,
            operator_key: None, enrollment_issuer: None, development_http: false,
            token: "test".into(), frostd_url: "http://127.0.0.1:2744".into(),
            peers: BTreeMap::new(), loopback_peers: false,
        }));
        *st.session.write().await = Some(Session {
            passphrase: Zeroizing::new("pass".into()), data: data.clone(),
        });

        let reply = status(st.clone(), vault.clone()).await;
        assert_eq!(reply.1 .0["phase"], "setup_interrupted");
        let reply = agree(State(st), Json(json!({"vault":vault,"fingerprint":"fingerprint"}))).await;
        assert_eq!(reply.0, StatusCode::BAD_REQUEST);
        assert!(reply.1 .0["error"].as_str().unwrap().contains("interrupted"));
        assert!(load(&data, "pass", &vault).unwrap().dkg_started);
        std::fs::remove_dir_all(data).unwrap();
    }

    #[tokio::test]
    async fn join_rejects_invite_pointing_at_a_non_peer_host() {
        // SSRF guard: a crafted invite whose creator_base_url is not one of this member's
        // configured peers (here, the cloud-metadata address) must be refused before the
        // server issues any outbound request to it.
        let data = std::env::temp_dir().join(format!("loki-ssrf-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&data).unwrap();
        let mut peers = BTreeMap::new();
        peers.insert(1u16, "http://127.0.0.1:3601".to_string());
        let st = std::sync::Arc::new(AppState::new(Config {
            registration: None,
            bind: "127.0.0.1".parse().unwrap(), advertise_url: None,
            data: data.clone(),
            port: 3602,
            network: "regtest".into(),
            lightwalletd: None,
            transport: "local".into(),
            secure_element: "software".into(),
            operator_bundle: None, nonce_witnesses: None,
            operator_key: None,
            enrollment_issuer: None,
            development_http: false,
            token: "test".into(),
            frostd_url: "http://127.0.0.1:2744".into(),
            peers, loopback_peers: false,
        }));
        *st.session.write().await = Some(Session {
            passphrase: Zeroizing::new("pass".into()),
            data: data.clone(),
        });
        let code = |base: &str| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(
                serde_json::to_vec(&Invite {
                    vault: hex::encode([1u8; 32]),
                    slot: 2,
                    creator_base_url: base.into(),
                    token: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode([0u8; 32]),
                    members: 3,
                    threshold: 2,
                    name: "test".into(),
                })
                .unwrap(),
            )
        };
        let evil = join(
            State(st.clone()),
            Json(json!({"invite": code("http://169.254.169.254")})),
        )
        .await;
        assert_eq!(evil.0, StatusCode::BAD_REQUEST);
        assert_eq!(evil.1 .0["error"], "member URL is not an allowed peer");
        // A configured peer gets past the SSRF guard (then fails later for other reasons).
        let ok = join(
            State(st),
            Json(json!({"invite": code("http://127.0.0.1:3601")})),
        )
        .await;
        assert_ne!(ok.1 .0["error"], "member URL is not an allowed peer");
        std::fs::remove_dir_all(data).unwrap();
    }

    #[tokio::test]
    async fn creator_enrolls_three_members_and_publishes_roster() {
        let data = std::env::temp_dir().join(format!("loki-ceremony-{}", Uuid::new_v4()));
        std::fs::create_dir_all(&data).unwrap();
        let st = std::sync::Arc::new(AppState::new(Config {
            registration: None,
            bind: "127.0.0.1".parse().unwrap(), advertise_url: None,
            data: data.clone(),
            port: 3001,
            network: "regtest".into(),
            lightwalletd: None,
            transport: "local".into(),
            secure_element: "software".into(),
            operator_bundle: None, nonce_witnesses: None,
            operator_key: None,
            enrollment_issuer: None,
            development_http: false,
            token: "test".into(),
            frostd_url: "http://127.0.0.1:2744".into(),
            peers: BTreeMap::new(), loopback_peers: false,
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
            if slot == 2 {
                let mut duplicate = load(&data, "test passphrase", &vault).unwrap().slots[&1].identity.clone().unwrap();
                duplicate.id = slot;
                let refused = enroll(State(st.clone()), Json(json!({
                    "vault":vault,"slot":slot,"token":invite.token,"identity":duplicate,
                    "base_url":format!("http://127.0.0.1:{}", 42000 + slot * 7)
                }))).await;
                assert_eq!(refused.0, StatusCode::BAD_REQUEST, "duplicate member must not occupy an invite slot");
                assert!(load(&data, "test passphrase", &vault).unwrap().slots[&slot].identity.is_none());
            }
            let refused = enroll(
                State(st.clone()),
                Json(json!({"vault":vault,"slot":slot,"token":"wrong","identity":wire,
                    "base_url":format!("http://127.0.0.1:{}", 42000 + slot * 7)})),
            )
            .await;
            assert_eq!(refused.0, StatusCode::BAD_REQUEST);
            let reply = enroll(
                State(st.clone()),
                Json(json!({
                    "vault":vault,"slot":slot,"token":invite.token,
                    "identity":wire,"base_url":format!("http://127.0.0.1:{}", 42000 + slot * 7)
                })),
            )
            .await;
            assert_eq!(reply.0, StatusCode::OK);
            let replay = enroll(State(st.clone()), Json(json!({
                "vault":vault,"slot":slot,"token":invite.token,"identity":wire,
                "base_url":format!("http://127.0.0.1:{}", 42000 + slot * 7)
            }))).await;
            assert_eq!(replay.0, StatusCode::OK, "an identical retry is idempotent");
            for replacement in [WireIdentity::from_public(Identity::new(slot).public()),
                WireIdentity { id: slot + 1, ..wire.clone() }] {
                let refused = enroll(State(st.clone()), Json(json!({
                    "vault":vault,"slot":slot,"token":invite.token,"identity":replacement,
                    "base_url":format!("http://127.0.0.1:{}", 42000 + slot * 7)
                }))).await;
                assert_eq!(refused.0, StatusCode::BAD_REQUEST);
            }
            let other = if slot == 2 { 3 } else { 2 };
            let refused = enroll(State(st.clone()), Json(json!({
                "vault":vault,"slot":other,"token":invite.token,
                "identity":WireIdentity::from_public(Identity::new(other).public()),
                "base_url":format!("http://127.0.0.1:{}", 42000 + other * 7)
            }))).await;
            assert_eq!(refused.0, StatusCode::BAD_REQUEST, "an invite token is bound to its slot");
            // Even a valid invite cannot replace a recorded URL or enroll an internal service.
            for base in ["http://127.0.0.1:43000", "http://169.254.169.254"] {
                let refused = enroll(State(st.clone()), Json(json!({
                    "vault":vault,"slot":slot,"token":invite.token,"identity":wire,"base_url":base
                }))).await;
                assert_eq!(refused.0, StatusCode::BAD_REQUEST);
            }
        }
        let status = status(st.clone(), vault.clone()).await;
        assert_eq!(status.1 .0["phase"], "compare_roster");
        let response = roster(State(st.clone()), Query(BTreeMap::from([("vault".into(), vault.clone())]))).await;
        assert_eq!(response.0, StatusCode::OK);
        assert_eq!(response.1 .0["fingerprint"], status.1 .0["fingerprint"]);
        assert_eq!(response.1 .0["base_urls"], json!({
            "1":"http://127.0.0.1:3001", "2":"http://127.0.0.1:42014", "3":"http://127.0.0.1:42021"
        }));
        let mut joiner = load(&data, "test passphrase", &vault).unwrap();
        joiner.my_slot = 2;
        joiner.slots.retain(|&slot, _| slot == 2);
        for (slot, base) in [("1", "http://127.0.0.1:43000"), ("2", "http://127.0.0.1:43000"),
            ("3", "http://169.254.169.254")] {
            let mut bad = response.1 .0.clone();
            bad["base_urls"][slot] = json!(base);
            assert!(apply_roster(&st.config, &mut joiner, &bad).is_err());
        }
        apply_roster(&st.config, &mut joiner, &response.1 .0).unwrap();
        let remote_only = crate::host::config_from_args(&[
            "--data", "unused", "--port", "42014", "--network", "testnet",
            "--peer", "1=http://127.0.0.1:3001", "--peer", "3=http://127.0.0.1:42021",
        ].map(str::to_owned)).unwrap();
        apply_roster(&remote_only, &mut joiner, &response.1 .0).unwrap();
        save(&data, "test passphrase", &joiner).unwrap();
        let restored = load(&data, "test passphrase", &vault).unwrap();
        assert_eq!(restored.slots[&1].base_url.as_deref(), Some("http://127.0.0.1:3001"));
        assert_eq!(restored.slots[&3].base_url.as_deref(), Some("http://127.0.0.1:42021"));
        let mut changed = response.1 .0.clone();
        changed["base_urls"]["3"] = json!("http://127.0.0.1:43000");
        assert!(apply_roster(&st.config, &mut joiner, &changed).is_err());
        eprintln!("PASS: emitted invite codes contain no vault_secret");
        std::fs::remove_dir_all(data).unwrap();
    }
}
