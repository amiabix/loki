//! WS3 transport: move the PUBLIC protocol messages (DKG wires, signing commitments,
//! signing packages, randomizer seeds, signature shares) between the coordinator and the
//! signers over the audited ZF `frostd` relay (`docs/product/ws3-transport.md`).
//!
//! `frostd` is an honest-but-curious JSON-over-HTTP(S) relay: it queues opaque bytes
//! keyed by session + recipient pubkey and hands them back on `receive`. It never
//! inspects the payload (`frostd/src/functions.rs` `send`/`receive` just move
//! `Msg { sender, msg }`).
//!
//! What may be sent is a closed set, [`Outbound`]: a [`DkgWire`] (only the signer makes
//! one; round two is a v2 envelope sealed under one-setup fresh keys, so recorded relay
//! traffic does not open even after a later compromise of the long-lived identity keys),
//! or one of the public FROST signing artifacts. [`Transport::send`] takes nothing else,
//! so raw bytes, and with them a plaintext round-two package, a share or a nonce, cannot
//! be handed to the relay. This module holds no share, nonce, or viewing key.
//!
//! The [`Transport`] trait is the stable interface (ws3 §5) so the serverless
//! Zcash-memo transport can be added later behind the same methods without touching
//! WS1/WS2. [`FrostdTransport`] is the `frostd` implementation.
//!
//! Addressing: a member's app is named on the relay by the public key of its own
//! [`FrostdLoginKey`], a dedicated X25519 key used only to log in to frostd. It is NOT
//! the member's setup identity: the setup identity's keys stay inside the signer. Login
//! proves possession of the login secret via XEdDSA over the server challenge — the
//! exact scheme `frostd` verifies (`frostd/src/functions.rs::login`, `xed25519`).
//!
//! [`RelayLog`] is the coordinator's record of every DKG wire it relayed, so it can
//! redeliver after a restart; it is deleted once the vault is active.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use reddsa_frost::frost::redpallas as frost;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::runtime::Runtime;
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub use crate::setup_transport::{DkgWire, DkgWireKind};

/// A member address on the relay: its 32-byte frostd/X25519 public key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Peer(pub [u8; 32]);

/// A dedicated frostd login key. Only logs in to the relay; it never seals, signs or
/// opens a protocol message, and it is not derived from the setup identity.
pub struct FrostdLoginKey(StaticSecret);

impl FrostdLoginKey {
    pub fn generate() -> Self {
        Self(StaticSecret::random_from_rng(rand_core::OsRng))
    }

    pub fn from_secret_bytes(secret: [u8; 32]) -> Self {
        Self(StaticSecret::from(secret))
    }

    pub fn to_secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(self.0.to_bytes())
    }

    /// This app's address on the relay.
    pub fn peer(&self) -> Peer {
        Peer(PublicKey::from(&self.0).to_bytes())
    }
}

/// Everything a member's app or the coordinator may hand the relay. Raw bytes are not
/// an option:
///
/// ```compile_fail
/// use loki_poc::transport::{FrostdChannel, FrostdTransport, Peer, Transport};
/// fn leak(t: &FrostdTransport, ch: &FrostdChannel, to: &[Peer], secret: &[u8]) {
///     t.send(ch, to, secret).unwrap();
/// }
/// ```
///
/// and only the signer makes a [`DkgWire`] or a [`crate::signer::CandidatePczt`]:
///
/// ```compile_fail
/// let wire = loki_poc::transport::DkgWire::parse(vec![0u8; 200]);
/// ```
///
/// ```compile_fail
/// let candidate = loki_poc::signer::CandidatePczt(vec![0u8; 200]);
/// ```
pub enum Outbound {
    /// A setup message produced by the signer.
    Dkg(DkgWire),
    Commitments(frost::round1::SigningCommitments),
    /// The proposer signer's unsigned candidate, for every quorum member to render.
    Candidate(crate::signer::CandidatePczt),
    Package(frost::SigningPackage),
    RandomizerSeed([u8; 32]),
    Share(frost::round2::SignatureShare),
}

impl Outbound {
    /// The bytes the relay carries.
    pub fn to_bytes(&self) -> Result<Vec<u8>, TransportError> {
        let encoding = |e: frost::Error| TransportError::Decode(e.to_string());
        match self {
            Self::Dkg(wire) => Ok(wire.as_bytes().to_vec()),
            Self::Commitments(commitments) => commitments.serialize().map_err(encoding),
            Self::Candidate(candidate) => Ok(candidate.as_bytes().to_vec()),
            Self::Package(package) => package.serialize().map_err(encoding),
            Self::RandomizerSeed(seed) => Ok(seed.to_vec()),
            Self::Share(share) => Ok(share.serialize()),
        }
    }
}

/// One inbound message: who sent it and the opaque public bytes they sent. The relay
/// authenticates `from` (it is the sender's logged-in pubkey); E2E auth of the body is
/// Loki's sealed-message layer above this seam. The relay delivery itself is the
/// "receipt" the `signing_session` relay-receipt rules consume (ws3 §5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Incoming {
    pub from: Peer,
    pub message: Vec<u8>,
}

/// WS3 §5 transport interface, stable across `frostd` and the future memo transport.
/// Sends take only an [`Outbound`]; inbound messages are opaque bytes for the receiver
/// to parse.
pub trait Transport {
    type Error;
    type Channel;

    /// Open an authenticated channel for a signing/DKG session. `peers` is the full
    /// roster (coordinator + participants) by frostd pubkey; `message_count` is the
    /// number of logical messages the coordinator will send per participant (frostd
    /// uses it to size the session). Only the coordinator calls `create`; participants
    /// join an existing `session`.
    fn open(&mut self, peers: &[Peer], message_count: u8) -> Result<Self::Channel, Self::Error>;

    /// Join an already-created session as a participant (coordinator shares `session`
    /// out of band / via the roster layer, ws3 §4).
    fn join(&mut self, session: Uuid) -> Result<Self::Channel, Self::Error>;

    /// Send one typed public message to the given recipients. Empty `to` means "to the
    /// coordinator" (frostd convention).
    fn send(&self, channel: &Self::Channel, to: &[Peer], message: &Outbound)
        -> Result<(), Self::Error>;

    /// Drain this member's inbox for the channel. `as_coordinator` selects the
    /// coordinator mailbox when this member is also the coordinator.
    fn recv(&self, channel: &Self::Channel, as_coordinator: bool)
        -> Result<Vec<Incoming>, Self::Error>;

    /// Close the session (coordinator only; frostd rejects non-coordinator closes).
    fn close(&self, channel: Self::Channel) -> Result<(), Self::Error>;
}

/// An open frostd session for one logged-in member.
#[derive(Clone, Debug)]
pub struct FrostdChannel {
    pub session: Uuid,
    me: Peer,
}

impl FrostdChannel {
    pub fn session_id(&self) -> Uuid {
        self.session
    }
    pub fn me(&self) -> &Peer {
        &self.me
    }
}

#[derive(Debug)]
pub enum TransportError {
    Http(String),
    Server(String),
    Auth(String),
    Decode(String),
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportError::Http(e) => write!(f, "frostd http error: {e}"),
            TransportError::Server(e) => write!(f, "frostd server error: {e}"),
            TransportError::Auth(e) => write!(f, "frostd auth error: {e}"),
            TransportError::Decode(e) => write!(f, "frostd decode error: {e}"),
        }
    }
}
impl std::error::Error for TransportError {}

/// `frostd` client for one member's app or the coordinator. Owns its own tokio runtime
/// (same block-on pattern as `setup_relay`) and a logged-in bearer token. Its address is
/// the public half of its [`FrostdLoginKey`], whose secret only XEdDSA-signs the login
/// challenge.
pub struct FrostdTransport {
    base_url: String,
    client: Client,
    runtime: Runtime,
    me: Peer,
    login: FrostdLoginKey,
    token: Option<Uuid>,
}

// Wire types mirrored from `frost_client::api` (frostd speaks these). Kept local so poc
// does not take the version-conflicting `frost-client` crate as a dependency (ADOPTION
// §2: poc is on frost-core 3.0.0, frost-client on 2.x — embedding it would duplicate the
// crypto crates). The audited relay binary is unchanged; only its JSON contract is here.
#[derive(Deserialize)]
struct ChallengeOut {
    challenge: Uuid,
}
#[derive(Deserialize)]
struct LoginOut {
    access_token: Uuid,
}
#[derive(Deserialize)]
struct CreateOut {
    session_id: Uuid,
}
#[derive(Serialize, Deserialize)]
struct WireMsg {
    sender: HexKey,
    #[serde(with = "hex_bytes")]
    msg: Vec<u8>,
}
#[derive(Deserialize)]
struct ReceiveOut {
    msgs: Vec<WireMsg>,
}
#[derive(Serialize, Deserialize, Clone)]
#[serde(transparent)]
struct HexKey(#[serde(with = "hex_bytes")] Vec<u8>);

// frostd serializes byte fields as lower-hex strings (`serdect` hex-or-bin). Mirror that.
mod hex_bytes {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S>(b: &[u8], s: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        s.serialize_str(&hex::encode(b))
    }
    pub fn deserialize<'de, D>(d: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(d)?;
        hex::decode(&s).map_err(D::Error::custom)
    }
}

impl FrostdTransport {
    /// `base_url` like `http://127.0.0.1:2744` (or `https://…` with TLS in production,
    /// ws3 §6). Logs in with `login`.
    pub fn new(base_url: &str, login: FrostdLoginKey) -> Result<Self, TransportError> {
        let runtime = Runtime::new().map_err(|e| TransportError::Http(e.to_string()))?;
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| TransportError::Http(e.to_string()))?;
        let mut t = Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
            runtime,
            me: login.peer(),
            login,
            token: None,
        };
        t.login()?;
        Ok(t)
    }

    async fn post<O: for<'de> Deserialize<'de>>(
        client: &Client,
        url: String,
        token: Option<Uuid>,
        body: serde_json::Value,
    ) -> Result<O, TransportError> {
        let mut req = client.post(&url).json(&body);
        if let Some(t) = token {
            req = req.bearer_auth(t.to_string());
        }
        let resp = req
            .send()
            .await
            .map_err(|e| TransportError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(TransportError::Server(format!("{status}: {text}")));
        }
        let text = resp
            .text()
            .await
            .map_err(|e| TransportError::Http(e.to_string()))?;
        let text = if text.is_empty() { "null".into() } else { text };
        serde_json::from_str(&text).map_err(|e| TransportError::Decode(e.to_string()))
    }

    /// `challenge` → XEdDSA-sign it with the X25519 secret → `login`, caching the token.
    /// This is exactly what frostd verifies in `functions.rs::login`.
    fn login(&mut self) -> Result<(), TransportError> {
        let base = self.base_url.clone();
        let client = self.client.clone();
        let secret = self.login.to_secret_bytes();
        let me = self.me.0;
        let token = self.runtime.block_on(async move {
            let ch: ChallengeOut =
                Self::post(&client, format!("{base}/challenge"), None, json!({})).await?;
            let signing = xeddsa::xed25519::PrivateKey::from(&*secret);
            // xeddsa 1.1.0's `CryptoRng` is the rand 0.10 trait shape; `rand_zp::rng()`
            // (the OS-seeded ThreadRng, a `CryptoRng`) satisfies it. poc aliases rand 0.10
            // as `rand_zp`. XEdDSA uses it only to randomize the challenge signature.
            let sig: [u8; 64] =
                xeddsa::Sign::sign(&signing, ch.challenge.as_bytes(), rand_zp::rng());
            let out: LoginOut = Self::post(
                &client,
                format!("{base}/login"),
                None,
                json!({
                    "challenge": ch.challenge,
                    "pubkey": hex::encode(me),
                    "signature": hex::encode(sig),
                }),
            )
            .await?;
            Ok::<_, TransportError>(out.access_token)
        })?;
        self.token = Some(token);
        Ok(())
    }
}

impl Transport for FrostdTransport {
    type Error = TransportError;
    type Channel = FrostdChannel;

    fn open(&mut self, peers: &[Peer], message_count: u8) -> Result<FrostdChannel, TransportError> {
        let base = self.base_url.clone();
        let client = self.client.clone();
        let token = self.token;
        let pubkeys: Vec<String> = peers.iter().map(|p| hex::encode(p.0)).collect();
        let out: CreateOut = self.runtime.block_on(Self::post(
            &client,
            format!("{base}/create_new_session"),
            token,
            json!({ "pubkeys": pubkeys, "message_count": message_count }),
        ))?;
        Ok(FrostdChannel {
            session: out.session_id,
            me: self.me.clone(),
        })
    }

    fn join(&mut self, session: Uuid) -> Result<FrostdChannel, TransportError> {
        // frostd has no explicit join: a participant is already in the session (the
        // coordinator listed its pubkey at create time). The channel is just the id.
        Ok(FrostdChannel {
            session,
            me: self.me.clone(),
        })
    }

    fn send(&self, channel: &FrostdChannel, to: &[Peer], message: &Outbound) -> Result<(), TransportError> {
        let message = message.to_bytes()?;
        let base = self.base_url.clone();
        let client = self.client.clone();
        let token = self.token;
        let recipients: Vec<String> = to.iter().map(|p| hex::encode(p.0)).collect();
        self.runtime.block_on(Self::post::<serde_json::Value>(
            &client,
            format!("{base}/send"),
            token,
            json!({
                "session_id": channel.session,
                "recipients": recipients,
                "msg": hex::encode(message),
            }),
        ))?;
        Ok(())
    }

    fn recv(&self, channel: &FrostdChannel, as_coordinator: bool) -> Result<Vec<Incoming>, TransportError> {
        let base = self.base_url.clone();
        let client = self.client.clone();
        let token = self.token;
        let out: ReceiveOut = self.runtime.block_on(Self::post(
            &client,
            format!("{base}/receive"),
            token,
            json!({ "session_id": channel.session, "as_coordinator": as_coordinator }),
        ))?;
        out.msgs
            .into_iter()
            .map(|m| {
                let key: [u8; 32] = m
                    .sender
                    .0
                    .try_into()
                    .map_err(|_| TransportError::Decode("sender pubkey length".into()))?;
                Ok(Incoming {
                    from: Peer(key),
                    message: m.msg,
                })
            })
            .collect()
    }

    fn close(&self, channel: FrostdChannel) -> Result<(), TransportError> {
        let base = self.base_url.clone();
        let client = self.client.clone();
        let token = self.token;
        self.runtime.block_on(Self::post::<serde_json::Value>(
            &client,
            format!("{base}/close_session"),
            token,
            json!({ "session_id": channel.session }),
        ))?;
        Ok(())
    }
}

const RELAY_LOG: &str = "dkg-relay.log";
const RELAY_LOG_MAGIC: &[u8; 8] = b"LOKIRLG1";
const RELAY_LOG_ENTRIES: usize = 4096;
const RELAY_LOG_WIRE: usize = 128 * 1024;

/// The coordinator's log of every DKG wire it relayed, kept so it can redeliver after a
/// restart. It holds only public wires (signed round ones, certificates and receipts,
/// and v2 round-two envelopes it cannot open). Delete it once the vault is active.
pub struct RelayLog {
    dir: PathBuf,
    members: u16,
    entries: Vec<(u16, Vec<u8>)>,
}

fn log_error(e: impl std::fmt::Display) -> TransportError {
    TransportError::Decode(format!("relay log: {e}"))
}

impl RelayLog {
    /// Open (or start) the log for a vault of `members` members in `dir`.
    pub fn open(dir: &Path, members: u16) -> Result<Self, TransportError> {
        if !(2..=crate::member_state::MAX_MEMBERS).contains(&members) {
            return Err(log_error("member count"));
        }
        std::fs::create_dir_all(dir).map_err(log_error)?;
        let mut log = Self {
            dir: dir.to_path_buf(),
            members,
            entries: Vec::new(),
        };
        let raw = match std::fs::read(dir.join(RELAY_LOG)) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(log),
            Err(e) => return Err(log_error(e)),
        };
        let mut rest = raw
            .strip_prefix(RELAY_LOG_MAGIC.as_slice())
            .ok_or_else(|| log_error("format"))?;
        while !rest.is_empty() {
            if rest.len() < 6 {
                return Err(log_error("truncated"));
            }
            let from = u16::from_be_bytes([rest[0], rest[1]]);
            let size = u32::from_be_bytes(rest[2..6].try_into().unwrap()) as usize;
            if size > RELAY_LOG_WIRE || rest.len() < 6 + size {
                return Err(log_error("truncated"));
            }
            let bytes = rest[6..6 + size].to_vec();
            log.recipients(from, &DkgWire::parse(bytes.clone()).map_err(log_error)?)?;
            log.entries.push((from, bytes));
            rest = &rest[6 + size..];
        }
        if log.entries.len() > RELAY_LOG_ENTRIES {
            return Err(log_error("too many entries"));
        }
        Ok(log)
    }

    fn recipients(&self, from: u16, wire: &DkgWire) -> Result<Vec<u16>, TransportError> {
        let valid = |id: u16| (1..=self.members).contains(&id);
        if !valid(from) || wire.sender() != from {
            return Err(log_error("the wire's sender is not the relay sender"));
        }
        match wire.recipient() {
            Some(to) if valid(to) && to != from => Ok(vec![to]),
            Some(_) => Err(log_error("recipient")),
            None => Ok((1..=self.members).filter(|id| *id != from).collect()),
        }
    }

    /// Log a wire the relay delivered from member `from`, before forwarding it. Returns
    /// the wire and its recipients, or `None` for an exact repeat already relayed (members
    /// resend their saved messages). A different second message is logged and forwarded
    /// too: the signers, not the coordinator, decide that it is a mismatch.
    pub fn relay(
        &mut self,
        from: u16,
        bytes: Vec<u8>,
    ) -> Result<Option<(DkgWire, Vec<u16>)>, TransportError> {
        let wire = DkgWire::parse(bytes).map_err(log_error)?;
        let recipients = self.recipients(from, &wire)?;
        if self
            .entries
            .iter()
            .any(|(sender, saved)| *sender == from && saved.as_slice() == wire.as_bytes())
        {
            return Ok(None);
        }
        if self.entries.len() >= RELAY_LOG_ENTRIES || wire.as_bytes().len() > RELAY_LOG_WIRE {
            return Err(log_error("full"));
        }
        self.entries.push((from, wire.as_bytes().to_vec()));
        if let Err(e) = self.save() {
            self.entries.pop();
            return Err(e);
        }
        Ok(Some((wire, recipients)))
    }

    fn save(&self) -> Result<(), TransportError> {
        let mut out = RELAY_LOG_MAGIC.to_vec();
        for (from, bytes) in &self.entries {
            out.extend_from_slice(&from.to_be_bytes());
            out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
            out.extend_from_slice(bytes);
        }
        crate::signer::durable::replace_durable(&self.dir, RELAY_LOG, &out).map_err(log_error)
    }

    /// Every logged wire addressed to `member`, in relay order, to redeliver after a
    /// restart.
    pub fn for_member(&self, member: u16) -> Vec<DkgWire> {
        self.entries
            .iter()
            .filter_map(|(from, bytes)| {
                let wire = DkgWire::parse(bytes.clone()).ok()?;
                self.recipients(*from, &wire)
                    .ok()?
                    .contains(&member)
                    .then_some(wire)
            })
            .collect()
    }

    /// Number of distinct wires logged.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// True once every member's backup receipt has been relayed: the vault is active.
    pub fn active(&self) -> bool {
        let mut receipts = BTreeMap::new();
        for (from, bytes) in &self.entries {
            if crate::setup_transport::wire_kind(bytes) == Some(DkgWireKind::BackupReceipt) {
                receipts.insert(*from, ());
            }
        }
        receipts.len() == usize::from(self.members)
    }

    /// Delete the log once the vault is active.
    pub fn delete(self) -> Result<(), TransportError> {
        if !self.active() {
            return Err(log_error("the vault is not active yet"));
        }
        crate::signer::durable::remove_durable(&self.dir, RELAY_LOG).map_err(log_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup_transport::Identity;

    #[test]
    fn relay_log_checks_senders_survives_restart_and_deletes_only_when_active() {
        let dir = std::env::temp_dir().join(format!(
            "loki-relay-log-{}-{}",
            std::process::id(),
            rand_core::RngCore::next_u64(&mut rand_core::OsRng)
        ));
        let vault = [3u8; 32];
        let identities: Vec<Identity> = (1..=3).map(Identity::new).collect();
        let round1 = identities[0].sign_round1(&vault, b"round one").unwrap();
        let mut log = RelayLog::open(&dir, 3).unwrap();
        // The relay says member 2 sent member 1's wire: dropped, nothing logged.
        assert!(log.relay(2, round1.clone()).is_err());
        assert!(log.relay(1, b"not a wire".to_vec()).is_err());
        let (_, to) = log.relay(1, round1.clone()).unwrap().unwrap();
        assert_eq!(to, vec![2, 3]);
        // Members resend saved messages: an exact repeat is not forwarded again.
        assert!(log.relay(1, round1.clone()).unwrap().is_none());
        assert!(!log.active());

        let log = RelayLog::open(&dir, 3).unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log.for_member(2)[0].as_bytes(), round1.as_slice());
        assert!(log.for_member(1).is_empty());
        assert!(log.delete().is_err(), "deleted before the vault is active");

        let mut log = RelayLog::open(&dir, 3).unwrap();
        for (i, identity) in identities.iter().enumerate() {
            let receipt = identity.sign_backup(&vault, b"receipt").unwrap();
            log.relay(i as u16 + 1, receipt).unwrap().unwrap();
        }
        assert!(log.active());
        log.delete().unwrap();
        assert!(!dir.join(RELAY_LOG).exists());

        // A damaged log does not open.
        std::fs::write(dir.join(RELAY_LOG), b"LOKIRLG1\x00\x01\x00\x00\x00\x09garbage").unwrap();
        assert!(RelayLog::open(&dir, 3).is_err());
    }
}
