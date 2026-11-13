//! Relay-coordinated, member-local RTS share repair for hosted vaults.
//!
//! POST /api/repair-begin on the replacement: {vault, threshold, roster: [{id,
//! signing, encryption}], roster_fingerprint, helpers: [id, ...], lost}. Pin the
//! original roster fingerprint out of band, as in DKG. Returns {invite, fingerprint}.
//! POST /api/repair-contribute on EACH helper: {invite, approve: fingerprint}.
//! The member must compare that fingerprint with the replacement before approving:
//! it authorizes that replacement identity, lost slot, helper set and fresh session.
//! Both endpoints require the process token and an unlocked local profile. Poll either
//! with {vault, session_id} for status; no peer HTTP endpoint or invite URL is fetched.
//!
//! All participants sign fresh-key announcements bound to the complete invitation.
//! Helpers compare original sealed metadata digests before generating Deltas. Deltas
//! and Sigmas (including original vault metadata) use DKG's signed, fresh-key E2E boxes;
//! the frostd relay and its ephemeral session opener only handle ciphertext.
//! Duplicate, replayed, wrong-session and wrong-identifier messages fail closed.
//! Attempts expire after ten minutes. Transient receive errors are retried, but an
//! ambiguous send or process restart requires a NEW begin and fresh helper consent.
//! Consumed invitation records survive restart; ephemeral repair secrets never do.
//!
//! This restores vault.sealed only, never overwriting it. Device enrollment/revocation,
//! identity restoration, native SecureElement signer state and backup refresh remain
//! separate operations. RTS restores the SAME share/address, does not revoke a
//! compromised share, and the underlying RTS implementation remains unaudited.

use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use axum::{extract::State, http::StatusCode, Json};
use frost::keys::repairable::{Delta, Sigma};
use reddsa_frost::frost::redpallas as frost;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use super::{
    routes::{blocking, err, Reply},
    state::Shared,
};
use crate::{
    frost_roster::FrostRoster,
    network::VaultNetwork,
    setup_transport::{DkgWire, FreshKey, Identity, PublicIdentity},
    signer::repair::{helper_part1, helper_part2, repaired_part3},
    state::MemberDir,
    transport::{FrostdLoginKey, FrostdTransport, Incoming, Outbound, Peer, Transport},
};

const LIFETIME: u64 = 600;

fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| e.to_string())
}
fn hex32(s: &str) -> Result<[u8; 32], String> {
    hex::decode(s)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "expected 32-byte hex".into())
}
fn encode<T: Serialize>(v: &T) -> Result<Vec<u8>, String> {
    serde_json::to_vec(v).map_err(|e| e.to_string())
}
fn digest(bytes: &[u8]) -> [u8; 32] {
    blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"Loki_RTS_v1")
        .hash(bytes)
        .as_bytes()
        .try_into()
        .expect("32-byte digest")
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Member {
    id: u16,
    signing: String,
    encryption: String,
}
impl Member {
    fn from_public(p: PublicIdentity) -> Self {
        Self {
            id: p.id,
            signing: hex::encode(p.signing),
            encryption: hex::encode(p.encryption),
        }
    }
    fn public(&self) -> Result<PublicIdentity, String> {
        let signing = hex32(&self.signing)?;
        let encryption = hex32(&self.encryption)?;
        ed25519_dalek::VerifyingKey::from_bytes(&signing).map_err(|e| e.to_string())?;
        if encryption == [0; 32] {
            return Err("invalid encryption key".into());
        }
        Ok(PublicIdentity {
            id: self.id,
            signing,
            encryption,
        })
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Invitation {
    version: u8,
    vault: String,
    threshold: u16,
    roster: Vec<Member>,
    helpers: Vec<u16>,
    recipient: Member,
    session_id: Uuid,
    expires: u64,
    frostd_url: String,
    network: String,
}
impl Invitation {
    fn roster(&self) -> Result<FrostRoster, String> {
        let vault_id = hex32(&self.vault)?;
        if hex::encode(vault_id) != self.vault
            || !crate::member_state::valid_policy(self.threshold, self.roster.len())
        {
            return Err("repair requires a canonical vault id and 2 <= t < n <= 16".into());
        }
        let mut signing = BTreeSet::new();
        let mut encryption = BTreeSet::new();
        let mut members = BTreeMap::new();
        for (i, member) in self.roster.iter().enumerate() {
            let p = member.public()?;
            if usize::from(p.id) != i + 1
                || !signing.insert(p.signing)
                || !encryption.insert(p.encryption)
            {
                return Err("invalid or duplicate roster member".into());
            }
            members.insert(
                frost::Identifier::try_from(p.id).map_err(|e| e.to_string())?,
                p,
            );
        }
        Ok(FrostRoster::from_identities(
            vault_id,
            self.threshold,
            members,
        ))
    }
    fn validate(&self) -> Result<(), String> {
        self.roster()?;
        VaultNetwork::parse(&self.network)?;
        let time = now()?;
        if self.version != 1
            || self.session_id.is_nil()
            || self.expires <= time
            || self.expires > time + LIFETIME
        {
            return Err("invalid or expired repair session; begin a fresh repair".into());
        }
        let lost = self.recipient.id;
        if !(1..=self.roster.len() as u16).contains(&lost)
            || self.helpers.len() != usize::from(self.threshold)
            || self.helpers.windows(2).any(|p| p[0] >= p[1])
            || self
                .helpers
                .iter()
                .any(|id| *id == lost || !(1..=self.roster.len() as u16).contains(id))
        {
            return Err("repair requires exactly t distinct other helpers in slot order".into());
        }
        let recipient = self.recipient.public()?;
        if self.roster.iter().filter(|m| m.id != lost).any(|m| {
            m.public().is_ok_and(|p| {
                p.signing == recipient.signing || p.encryption == recipient.encryption
            })
        }) {
            return Err("replacement identity duplicates another member".into());
        }
        Ok(())
    }
    fn context(&self) -> Result<[u8; 32], String> {
        Ok(digest(&encode(self)?))
    }
    fn participants(&self) -> Result<BTreeMap<u16, PublicIdentity>, String> {
        let mut participants: BTreeMap<_, _> = self
            .roster
            .iter()
            .filter(|m| self.helpers.contains(&m.id))
            .map(|m| Ok((m.id, m.public()?)))
            .collect::<Result<_, String>>()?;
        participants.insert(self.recipient.id, self.recipient.public()?);
        Ok(participants)
    }
}

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Metadata {
    public_package: String,
    roster_fingerprint: String,
    vault_secret: String,
    network: String,
    birth_height: u32,
}
impl Drop for Metadata {
    fn drop(&mut self) {
        self.vault_secret.zeroize();
    }
}
impl Metadata {
    fn validate(&self, invite: &Invitation) -> Result<frost::keys::PublicKeyPackage, String> {
        let roster = invite.roster()?;
        if hex32(&self.roster_fingerprint)? != roster.fingerprint()
            || self.network != invite.network
        {
            return Err("repair metadata differs from the approved roster or network".into());
        }
        let _secret = Zeroizing::new(hex32(&self.vault_secret)?);
        let public = frost::keys::PublicKeyPackage::deserialize(
            &hex::decode(&self.public_package).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        if public.min_signers() != Some(invite.threshold)
            || public.verifying_shares().keys().ne(roster.members.keys())
        {
            return Err("repair public package differs from the approved policy or members".into());
        }
        Ok(public)
    }
    fn digest(&self) -> Result<[u8; 32], String> {
        Ok(digest(&Zeroizing::new(encode(self)?)))
    }
}

struct Recovered {
    metadata: Metadata,
    parts: BTreeMap<frost::Identifier, Sigma>,
}
impl Recovered {
    fn restore(self, data: &Path, pass: &str, invite: &Invitation) -> Result<(), String> {
        invite.validate()?;
        let public = self.metadata.validate(invite)?;
        restore_vault_from_repair(
            data,
            pass,
            &hex32(&invite.vault)?,
            invite.recipient.id,
            &public,
            &self.parts,
            &hex32(&self.metadata.roster_fingerprint)?,
            &Zeroizing::new(hex32(&self.metadata.vault_secret)?),
            self.metadata.birth_height,
            VaultNetwork::parse(&self.metadata.network)?,
        )
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Hello {
    fresh: [u8; 32],
    metadata: Option<[u8; 32]>,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind", deny_unknown_fields)]
enum Part {
    Delta { value: Vec<u8> },
    Sigma { value: Vec<u8>, metadata: Metadata },
}
impl Drop for Part {
    fn drop(&mut self) {
        match self {
            Self::Delta { value } | Self::Sigma { value, .. } => value.zeroize(),
        }
    }
}

fn send<T: Transport>(tx: &T, ch: &T::Channel, to: &[Peer], wire: Vec<u8>) -> Result<(), String>
where
    T::Error: std::fmt::Display,
{
    tx.send(ch, to, &Outbound::Dkg(DkgWire::parse(wire)?))
        .map_err(|e| format!("repair send failed; begin a fresh repair: {e}"))
}
fn live(expires: u64) -> Result<(), String> {
    if now()? >= expires {
        return Err("repair timed out; begin a fresh repair".into());
    }
    Ok(())
}
fn receive<T: Transport>(tx: &T, ch: &T::Channel, expires: u64) -> Result<Vec<Incoming>, String>
where
    T::Error: std::fmt::Display,
{
    for attempt in 0..3 {
        live(expires)?;
        let result = tx.recv(ch, false);
        live(expires)?;
        match result {
            Ok(messages) if !messages.is_empty() => return Ok(messages),
            Ok(_) => {
                std::thread::sleep(Duration::from_millis(100));
                return Ok(vec![]);
            }
            Err(e) if attempt == 2 => {
                return Err(format!("repair receive failed; begin a fresh repair: {e}"))
            }
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
    unreachable!("bounded receive retries")
}
fn close_session<T: Transport>(tx: &T, ch: T::Channel) -> Result<(), String>
where
    T::Error: std::fmt::Display,
    T::Channel: Clone,
{
    for attempt in 0..3 {
        match tx.close(ch.clone()) {
            Ok(()) => return Ok(()),
            Err(e) if attempt == 2 => return Err(format!("relay session cleanup failed: {e}")),
            Err(_) => std::thread::sleep(Duration::from_millis(100)),
        }
    }
    unreachable!("bounded close retries")
}
fn sender<'a>(
    message: &Incoming,
    participants: &'a BTreeMap<u16, PublicIdentity>,
    me: u16,
) -> Result<&'a PublicIdentity, String> {
    participants
        .values()
        .find(|p| p.id != me && Peer(p.encryption) == message.from)
        .ok_or_else(|| "repair message from an unapproved sender".into())
}

/// Same Transport and v2 envelopes as DKG; only member-local code opens repair parts.
fn run_ceremony<T: Transport>(
    tx: &T,
    ch: &T::Channel,
    invite: &Invitation,
    identity: &Identity,
    helper: Option<(&frost::keys::KeyPackage, &Metadata)>,
) -> Result<Option<Recovered>, String>
where
    T::Error: std::fmt::Display,
{
    invite.validate()?;
    let participants = invite.participants()?;
    let me = identity.public().id;
    if participants.get(&me) != Some(&identity.public())
        || helper.is_some() != invite.helpers.contains(&me)
    {
        return Err("repair role or identity mismatch".into());
    }
    if let Some((key, metadata)) = helper {
        validate_helper_key(invite, me, key, metadata)?;
    }
    let context = invite.context()?;
    let fresh = FreshKey::generate();
    let hello = Hello {
        fresh: fresh.public(),
        metadata: helper.map(|(_, m)| m.digest()).transpose()?,
    };
    let wire = identity.sign_round1(&context, &encode(&hello)?)?;
    let peers: Vec<_> = participants
        .values()
        .filter(|p| p.id != me)
        .map(|p| Peer(p.encryption))
        .collect();
    live(invite.expires)?;
    send(tx, ch, &peers, wire.clone())?;
    let mut hellos = BTreeMap::from([(me, hello)]);
    let mut transcript = BTreeMap::from([(me, wire)]);
    let mut pending = Vec::new();
    while hellos.len() < participants.len() {
        for incoming in receive(tx, ch, invite.expires)? {
            let p = sender(&incoming, &participants, me)?;
            if incoming.message.starts_with(b"LOKIDKG2") {
                if pending.len() >= participants.len() {
                    return Err("too many early repair parts".into());
                }
                pending.push(incoming);
                continue;
            }
            let raw = identity.verify_round1(p, &context, &incoming.message)?;
            let hello: Hello = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
            if hellos.contains_key(&p.id)
                || hello.metadata.is_some() != invite.helpers.contains(&p.id)
                || hello.fresh == [0; 32]
            {
                return Err("duplicate or invalid repair consent".into());
            }
            hellos.insert(p.id, hello);
            transcript.insert(p.id, incoming.message);
        }
    }
    let agreed_metadata = hellos[&invite.helpers[0]]
        .metadata
        .ok_or("missing helper metadata")?;
    let mut fresh_keys = BTreeSet::new();
    for hello in hellos.values() {
        if !fresh_keys.insert(hello.fresh) || hello.metadata.is_some_and(|m| m != agreed_metadata) {
            return Err("helpers disagree on original vault metadata or fresh keys".into());
        }
    }
    let transcript = digest(&encode(&transcript)?);
    let seal = |to: u16, part: &Part| -> Result<(), String> {
        live(invite.expires)?;
        let plaintext = Zeroizing::new(encode(part)?);
        let p = &participants[&to];
        send(
            tx,
            ch,
            &[Peer(p.encryption)],
            identity.seal_round2_v2(
                &fresh,
                p,
                &hellos[&to].fresh,
                &context,
                &transcript,
                &plaintext,
            )?,
        )
    };
    live(invite.expires)?;
    let mut deltas = BTreeMap::new();
    if let Some((key, _)) = helper {
        let ids = invite
            .helpers
            .iter()
            .map(|id| frost::Identifier::try_from(*id).map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>, _>>()?;
        let parts = helper_part1(
            &ids,
            key,
            frost::Identifier::try_from(invite.recipient.id).map_err(|e| e.to_string())?,
        )?;
        for id in &invite.helpers {
            let delta = parts[&frost::Identifier::try_from(*id).map_err(|e| e.to_string())?];
            if *id == me {
                deltas.insert(me, delta);
            } else {
                seal(
                    *id,
                    &Part::Delta {
                        value: delta.serialize(),
                    },
                )?;
            }
        }
    }
    let mut sigmas = BTreeMap::new();
    let mut metadata = None;
    let mut seen = BTreeSet::new();
    let expected = usize::from(invite.threshold) - usize::from(helper.is_some());
    while seen.len() < expected {
        let incoming = if pending.is_empty() {
            receive(tx, ch, invite.expires)?
        } else {
            std::mem::take(&mut pending)
        };
        for incoming in incoming {
            live(invite.expires)?;
            let p = sender(&incoming, &participants, me)?;
            if !invite.helpers.contains(&p.id) || !seen.insert(p.id) {
                return Err("duplicate or wrong-identifier repair part".into());
            }
            let plaintext = identity.open_round2_v2(
                &fresh,
                p,
                &hellos[&p.id].fresh,
                &context,
                &transcript,
                &incoming.message,
            )?;
            let part: Part = serde_json::from_slice(&plaintext).map_err(|e| e.to_string())?;
            match &part {
                Part::Delta { value } if helper.is_some() => {
                    deltas.insert(p.id, Delta::deserialize(value).map_err(|e| e.to_string())?);
                }
                Part::Sigma { value, metadata: m } if helper.is_none() => {
                    m.validate(invite)?;
                    if m.digest()? != agreed_metadata {
                        return Err("repair metadata authentication failed".into());
                    }
                    metadata = Some(m.clone());
                    sigmas.insert(
                        frost::Identifier::try_from(p.id).map_err(|e| e.to_string())?,
                        Sigma::deserialize(value).map_err(|e| e.to_string())?,
                    );
                }
                _ => return Err("wrong repair round or recipient".into()),
            }
        }
    }
    live(invite.expires)?;
    if let Some((_, metadata)) = helper {
        let sigma = helper_part2(&deltas.values().copied().collect::<Vec<_>>());
        seal(
            invite.recipient.id,
            &Part::Sigma {
                value: sigma.serialize(),
                metadata: metadata.clone(),
            },
        )?;
        Ok(None)
    } else {
        Ok(Some(Recovered {
            metadata: metadata.ok_or("missing repair metadata")?,
            parts: sigmas,
        }))
    }
}

fn validate_helper_key(
    invite: &Invitation,
    slot: u16,
    key: &frost::keys::KeyPackage,
    metadata: &Metadata,
) -> Result<(), String> {
    let public = metadata.validate(invite)?;
    let id = frost::Identifier::try_from(slot).map_err(|e| e.to_string())?;
    if key.identifier() != &id
        || key.min_signers() != &invite.threshold
        || key.verifying_key() != public.verifying_key()
        || public.verifying_shares().get(&id) != Some(key.verifying_share())
    {
        return Err("helper key differs from original vault".into());
    }
    Ok(())
}

fn load_helper(
    data: &Path,
    pass: &str,
    invite: &Invitation,
) -> Result<(Identity, frost::keys::KeyPackage, Metadata), String> {
    let roster = super::ceremony::repair_roster(data, pass, &invite.vault)?;
    if roster.fingerprint() != invite.roster()?.fingerprint() {
        return Err("repair invitation differs from original roster".into());
    }
    let raw = Zeroizing::new(
        repair_dir(data, &invite.vault)?
            .read_sealed("vault.sealed", pass)
            .map_err(|e| e.to_string())?,
    );
    let value: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    let slot = value["my_frost_id"].as_u64().and_then(|n| u16::try_from(n).ok())
        .ok_or("invalid helper member slot")?;
    if !MemberDir::open(data, ".").exists("identity.sealed") {
        return Err("missing member identity; restore from recovery backup".into());
    }
    let identity = super::ceremony::identity(data, pass, slot)?;
    if !invite.helpers.contains(&slot)
        || invite.participants()?.get(&slot) != Some(&identity.public())
    {
        return Err("this member is not an approved repair helper".into());
    }
    if value["vault"] != invite.vault
        || value["my_frost_id"] != slot
        || value["threshold"] != invite.threshold
        || value["members"] != invite.roster.len()
        || value["key_derivation"] != crate::zip2005::VERSION
    {
        return Err("helper sealed vault identity or policy mismatch".into());
    }
    let string = |name: &str| {
        value[name]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| format!("missing {name}"))
    };
    let sdir = super::ceremony::signer_dir(data, &invite.vault)?;
    let se = crate::signer::secure_element::SoftwareSecureElement::persistent(&sdir, pass)?;
    let store = crate::signer::store::SignerStore::open(&sdir)?;
    if store.vault() != hex32(&invite.vault)? || store.member() != slot {
        return Err("helper share belongs to another signer".into());
    }
    let (_, raw) = store.read(&se, crate::signer::store::FileKind::Share)?.ok_or("missing helper share")?;
    let (key_bytes, _, vault_secret) = crate::signer::local::decode_share(&raw)?;
    let key = frost::keys::KeyPackage::deserialize(&key_bytes).map_err(|e| e.to_string())?;
    let metadata = Metadata {
        public_package: string("public_package")?,
        roster_fingerprint: string("roster_fingerprint")?,
        vault_secret: hex::encode(&*Zeroizing::new(vault_secret)),
        network: string("network")?,
        birth_height: value["birth_height"]
            .as_u64()
            .and_then(|h| u32::try_from(h).ok())
            .ok_or("missing birth height")?,
    };
    validate_helper_key(invite, slot, &key, &metadata)?;
    Ok((identity, key, metadata))
}

fn repair_dir(data: &Path, vault: &str) -> Result<MemberDir, String> {
    if hex::encode(hex32(vault)?) != vault {
        return Err("noncanonical vault id".into());
    }
    Ok(MemberDir::open(&data.join("vaults"), vault))
}
fn relay(identity: &Identity, url: &str) -> Result<FrostdTransport, String> {
    let raw = Zeroizing::new(identity.to_secret_bytes());
    FrostdTransport::new(
        url,
        FrostdLoginKey::from_secret_bytes(
            raw[34..].try_into().map_err(|_| "identity secret length")?,
        ),
    )
    .map_err(|e| e.to_string())
}
fn claim(data: &Path, pass: &str, invite: &Invitation) -> Result<(), String> {
    let dir = MemberDir::create(&data.join("vaults"), &invite.vault).map_err(|e| e.to_string())?;
    // Atomic no-replace write: even after a restart, one session can generate RTS parts only once.
    dir.write_sealed(
        &format!("repair.{}.sealed", invite.session_id),
        &encode(invite)?,
        pass,
    )
    .map_err(|e| format!("repair session already consumed or cannot be recorded: {e}"))
}
fn finish(
    data: &Path,
    pass: &str,
    invite: &Invitation,
    outcome: Result<&str, String>,
    cleanup_error: Option<String>,
) -> Result<(), String> {
    let mut status = match outcome {
        Ok(phase) => json!({"phase":phase}),
        Err(e) => json!({"phase":"failed", "error":e}),
    };
    if let Some(e) = cleanup_error {
        status["relay_cleanup_error"] = json!(e);
    }
    repair_dir(data, &invite.vault)?
        .write_sealed(
            &format!("repair.{}.result.sealed", invite.session_id),
            &encode(&status)?,
            pass,
        )
        .map_err(|e| e.to_string())
}
fn status(data: &Path, pass: &str, body: &Value) -> Result<Value, String> {
    let vault = body["vault"].as_str().ok_or("missing vault")?;
    let session: Uuid =
        serde_json::from_value(body["session_id"].clone()).map_err(|e| e.to_string())?;
    let dir = repair_dir(data, vault)?;
    let invite: Invitation = serde_json::from_slice(
        &dir.read_sealed(&format!("repair.{session}.sealed"), pass)
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if invite.vault != vault || invite.session_id != session {
        return Err("repair status identity mismatch".into());
    }
    match dir.read_sealed(&format!("repair.{session}.result.sealed"), pass) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|e| e.to_string()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            Ok(json!({"phase": if now()? < invite.expires { "running" } else { "interrupted" }}))
        }
        Err(e) => Err(e.to_string()),
    }
}

pub(super) async fn repair_begin(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    let (data, pass) = match st.session.read().await.as_ref() {
        Some(s) => (s.data.clone(), s.passphrase.clone()),
        None => return err(StatusCode::UNAUTHORIZED, "profile is locked"),
    };
    blocking(move || {
        if body.get("session_id").is_some() { return status(&data, &pass, &body); }
        let _guard = st.ceremony.lock().map_err(|e| e.to_string())?;
        let lost = body["lost"].as_u64().and_then(|n| u16::try_from(n).ok()).ok_or("missing lost slot")?;
        let recipient = Identity::new(lost);
        let mut invite = Invitation {
            version: 1, vault: body["vault"].as_str().ok_or("missing vault")?.into(),
            threshold: body["threshold"].as_u64().and_then(|n| u16::try_from(n).ok()).ok_or("missing threshold")?,
            roster: serde_json::from_value(body["roster"].clone()).map_err(|e| e.to_string())?,
            helpers: serde_json::from_value(body["helpers"].clone()).map_err(|e| e.to_string())?,
            recipient: Member::from_public(recipient.public()), session_id: Uuid::new_v4(),
            expires: now()? + LIFETIME, frostd_url: st.config.frostd_url.clone(), network: st.config.network.clone(),
        };
        invite.validate()?;
        if body["roster_fingerprint"].as_str() != Some(hex::encode(invite.roster()?.fingerprint()).as_str()) {
            return Err("original roster fingerprint must be checked before repair".into());
        }
        let dir = repair_dir(&data, &invite.vault)?;
        if dir.exists("vault.sealed") { return Err("never overwrite an existing vault".into()); }
        if dir.exists("ceremony.sealed") && super::ceremony::repair_roster(&data, &pass, &invite.vault)?.fingerprint() != invite.roster()?.fingerprint() {
            return Err("repair differs from locally stored roster".into());
        }
        let coordinator = Identity::new(0);
        let mut coord_tx = relay(&coordinator, &st.config.frostd_url)?;
        let peers = invite.participants()?.values().map(|p| Peer(p.encryption)).collect::<Vec<_>>();
        let coord_ch = coord_tx.open(&peers, 255).map_err(|e| e.to_string())?;
        invite.session_id = coord_ch.session_id();
        if let Err(e) = claim(&data, &pass, &invite) {
            if let Err(cleanup) = close_session(&coord_tx, coord_ch) { return Err(format!("{e}; {cleanup}")); }
            return Err(e);
        }
        let response = json!({"invite":invite, "fingerprint":hex::encode(invite.context()?), "session_id":invite.session_id});
        std::thread::spawn(move || {
            let result = (|| {
                let mut tx = relay(&recipient, &invite.frostd_url)?;
                let ch = tx.join(invite.session_id).map_err(|e| e.to_string())?;
                run_ceremony(&tx, &ch, &invite, &recipient, None)?.ok_or("missing repaired share")?.restore(&data, &pass, &invite)?;
                Ok("repaired")
            })();
            let cleanup = close_session(&coord_tx, coord_ch).err();
            if let Err(e) = finish(&data, &pass, &invite, result, cleanup) { eprintln!("repair status: {e}"); }
        });
        Ok(response)
    }).await
}

pub(super) async fn repair_contribute(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    let (data, pass) = match st.session.read().await.as_ref() {
        Some(s) => (s.data.clone(), s.passphrase.clone()),
        None => return err(StatusCode::UNAUTHORIZED, "profile is locked"),
    };
    blocking(move || {
        if body.get("session_id").is_some() {
            return status(&data, &pass, &body);
        }
        let invite: Invitation =
            serde_json::from_value(body["invite"].clone()).map_err(|e| e.to_string())?;
        invite.validate()?;
        // No caller-controlled URL is fetched, including redirects to creator peers.
        if invite.frostd_url != st.config.frostd_url || invite.network != st.config.network {
            return Err("repair relay or network is not locally configured".into());
        }
        if body["approve"].as_str() != Some(hex::encode(invite.context()?).as_str()) {
            return Err("explicit approval of the repair fingerprint is required".into());
        }
        let _guard = st.ceremony.lock().map_err(|e| e.to_string())?;
        let (identity, key, metadata) = load_helper(&data, &pass, &invite)?;
        claim(&data, &pass, &invite)?;
        let response = json!({"phase":"running", "session_id":invite.session_id});
        std::thread::spawn(move || {
            let result = (|| {
                let mut tx = relay(&identity, &invite.frostd_url)?;
                let ch = tx.join(invite.session_id).map_err(|e| e.to_string())?;
                run_ceremony(&tx, &ch, &invite, &identity, Some((&key, &metadata)))?;
                Ok("contributed")
            })();
            if let Err(e) = finish(&data, &pass, &invite, result, None) {
                eprintln!("repair status: {e}");
            }
        });
        Ok(response)
    })
    .await
}

/// Reconstruct and verify the lost member's key, then create its `vault.sealed`.
///
/// The caller supplies authenticated original vault metadata and exactly one decrypted
/// Sigma per approved helper from the same repair session. Map keys are authenticated
/// sender identifiers, not sender claims. This checks membership, count, and the recovered
/// public commitment; it cannot authenticate the session or the metadata itself.
/// An existing vault is never overwritten, including on concurrent repair attempts.
#[allow(clippy::too_many_arguments)]
pub(super) fn restore_vault_from_repair(
    data: &Path,
    pass: &str,
    vault_id: &[u8; 32],
    slot: u16,
    public: &frost::keys::PublicKeyPackage,
    parts: &BTreeMap<frost::Identifier, Sigma>,
    roster_fingerprint: &[u8; 32],
    vault_secret: &[u8; 32],
    birth_height: u32,
    network: VaultNetwork,
) -> Result<(), String> {
    let threshold = public.min_signers().ok_or("repair public package has no threshold")?;
    let members = public.verifying_shares().len();
    if !crate::member_state::valid_policy(threshold, members) {
        return Err("repair requires 2 <= t < n <= 16".into());
    }
    let identifier = frost::Identifier::try_from(slot).map_err(|e| e.to_string())?;
    if !public.verifying_shares().contains_key(&identifier) {
        return Err("the group has no verifying share for this member".into());
    }
    if parts.len() != usize::from(threshold) {
        return Err("repair requires exactly threshold distinct helper parts".into());
    }
    if parts.keys().any(|helper| helper == &identifier || !public.verifying_shares().contains_key(helper)) {
        return Err("repair helpers must be other members of this vault".into());
    }
    let sigmas: Vec<_> = parts.values().copied().collect();
    let key = repaired_part3(&sigmas, identifier, public)?;
    let vault = hex::encode(vault_id);
    let fvk = crate::zip2005::frost_viewing_key(
        &public.verifying_key().serialize().map_err(|e| e.to_string())?.try_into().map_err(|_| "group key length")?, vault_secret,
    ).map_err(|e| format!("viewing key: {e:?}"))?;
    let sdir = super::ceremony::signer_dir(data, &vault)?;
    let se = crate::signer::secure_element::SoftwareSecureElement::persistent(&sdir, pass)?;
    let signer_network = match network { VaultNetwork::Regtest => crate::signer::Network::Regtest, VaultNetwork::Testnet => crate::signer::Network::Testnet };
    let store = crate::signer::store::SignerStore::create(&sdir, signer_network, *vault_id, slot)?;
    store.write(&se, crate::signer::store::FileKind::Share, 0,
        &crate::signer::local::encode_share(&key.serialize().map_err(|e| e.to_string())?, &public.serialize().map_err(|e| e.to_string())?, vault_secret))?;
    let bytes = Zeroizing::new(super::ceremony::vault_sealed_bytes(
        &vault, slot, threshold, members as u16, &hex::encode(roster_fingerprint),
        public, &fvk, birth_height, network,
    )?);
    MemberDir::create(&data.join("vaults"), &vault)
        .map_err(|e| e.to_string())?
        .write_sealed("vault.sealed", &bytes, pass)
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use reddsa_frost::frost::redpallas as frost;
    use frost::keys::repairable::{Delta, Sigma};
    use serde_json::Value;

    use super::*;
    use crate::{
        network::VaultNetwork,
        signer::repair::{helper_part1, helper_part2},
        state::MemberDir,
    };

    #[test]
    fn repair_2_of_3_reconstructs_and_seals_the_original_share() {
        let data = std::env::temp_dir().join(format!("loki-repair-{}", uuid::Uuid::new_v4()));
        let vault_id = [7u8; 32];
        let vault = hex::encode(vault_id);
        let fingerprint = [8u8; 32];
        let vault_secret = [42u8; 32];
        let (shares, public) = frost::keys::generate_with_dealer(
            3, 2, frost::keys::IdentifierList::Default, &mut rand_core::OsRng,
        ).unwrap();
        let keys: BTreeMap<_, _> = shares.into_iter()
            .map(|(id, share)| (id, frost::keys::KeyPackage::try_from(share).unwrap()))
            .collect();
        let lost = frost::Identifier::try_from(2u16).unwrap();
        let helpers: Vec<_> = keys.keys().copied().filter(|id| *id != lost).collect();
        let deltas: BTreeMap<_, BTreeMap<_, Delta>> = helpers.iter()
            .map(|id| (*id, helper_part1(&helpers, &keys[id], lost).unwrap()))
            .collect();
        let parts: BTreeMap<_, Sigma> = helpers.iter().map(|recipient| {
            let received: Vec<_> = helpers.iter().map(|sender| deltas[sender][recipient]).collect();
            (*recipient, helper_part2(&received))
        }).collect();
        let restore = |parts: &BTreeMap<_, _>, slot, public: &frost::keys::PublicKeyPackage| {
            restore_vault_from_repair(
                &data, "replacement pass", &vault_id, slot, public, parts, &fingerprint,
                &vault_secret, 100, VaultNetwork::Regtest,
            )
        };
        let dir = MemberDir::open(&data.join("vaults"), &vault);

        // Invalid contributions must not create a vault, even if their sum is correct.
        let mut missing = parts.clone();
        missing.remove(&helpers[0]);
        assert!(restore(&missing, 2, &public).is_err());
        let mut extra = parts.clone();
        extra.insert(lost, helper_part2(&[]));
        assert!(restore(&extra, 2, &public).is_err());
        for wrong_sender in [lost, frost::Identifier::try_from(4u16).unwrap()] {
            let mut wrong = parts.clone();
            let sigma = wrong.remove(&helpers[0]).unwrap();
            wrong.insert(wrong_sender, sigma);
            assert!(restore(&wrong, 2, &public).is_err());
        }
        let mut corrupt = parts.clone();
        corrupt.insert(helpers[0], helper_part2(&[deltas[&helpers[0]][&helpers[0]]]));
        assert!(restore(&corrupt, 2, &public).is_err());
        for slot in [0, 4] {
            assert!(restore(&parts, slot, &public).is_err());
        }
        for threshold in [None, Some(1), Some(3)] {
            let invalid = frost::keys::PublicKeyPackage::new(
                public.verifying_shares().clone(), *public.verifying_key(), threshold,
            );
            assert!(restore(&parts, 2, &invalid).is_err());
        }
        assert!(!data.exists(), "refused repairs must not write state");

        restore(&parts, 2, &public).unwrap();
        let sealed = std::fs::read(dir.path().join("vault.sealed")).unwrap();
        assert!(dir.read_sealed("vault.sealed", "wrong pass").is_err());
        let raw = dir.read_sealed("vault.sealed", "replacement pass").unwrap();
        let stored: Value = serde_json::from_slice(&raw).unwrap();
        assert!(stored.get("key_package").is_none());
        let sdir = super::super::ceremony::signer_dir(&data, &vault).unwrap();
        let se = crate::signer::secure_element::SoftwareSecureElement::persistent(&sdir, "replacement pass").unwrap();
        let (_, raw) = crate::signer::store::SignerStore::open(&sdir).unwrap()
            .read(&se, crate::signer::store::FileKind::Share).unwrap().unwrap();
        let (key_bytes, _, _) = crate::signer::local::decode_share(&raw).unwrap();
        let restored = frost::keys::KeyPackage::deserialize(&key_bytes).unwrap();
        assert_eq!(restored.signing_share(), keys[&lost].signing_share());
        assert_eq!(restored.serialize().unwrap(), keys[&lost].serialize().unwrap());
        // The original DKG payload binds the share to its unchanged address and metadata.
        let original = super::super::ceremony::vault_sealed_bytes(
            &vault, 2, 2, 3, &hex::encode(fingerprint), &public,
            &crate::zip2005::frost_viewing_key(&public.verifying_key().serialize().unwrap().try_into().unwrap(), &vault_secret).unwrap(), 100, VaultNetwork::Regtest,
        ).unwrap();
        assert_eq!(stored, serde_json::from_slice::<Value>(&original).unwrap());

        assert!(restore(&parts, 2, &public).is_err(), "never replace an existing vault");
        assert_eq!(std::fs::read(dir.path().join("vault.sealed")).unwrap(), sealed);
        std::fs::remove_dir_all(data).unwrap();
    }
}

#[cfg(test)]
#[path = "repair_tests.rs"]
mod driver_tests;
