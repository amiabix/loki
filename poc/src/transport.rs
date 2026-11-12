//! WS3 transport: move DKG wires and recipient-encrypted payment messages
//! (with public nonce commitments) between the coordinator and the
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
//! or a typed payment artifact. Candidates contain viewing keys and notes: they,
//! signing packages, randomizers and signature shares require [`PaymentEncryption`]
//! before sending. A bare transport refuses to serialize them.
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
use std::time::{Duration, Instant};

use reddsa_frost::frost::redpallas as frost;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::runtime::Runtime;
use uuid::Uuid;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::setup_transport::{Identity, PublicIdentity};

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
#[derive(Clone)]
pub enum Outbound {
    /// A setup message produced by the signer.
    Dkg(DkgWire),
    /// One commitment per signing lane (one lane per input note being spent).
    Commitments(Vec<frost::round1::SigningCommitments>),
    /// Private unsigned candidate (one spend per lane), encrypted to the selected quorum.
    Candidate(crate::signer::CandidatePczt),
    /// One signing package per lane; its sighash identifies the transaction.
    Package(Vec<frost::SigningPackage>),
    /// Proposer-only randomizers, distinguished from round-two seeds on redelivery.
    Randomizers(Vec<[u8; 32]>),
    /// One rerandomizer seed per lane; keep the vault-to-spend linkage private.
    RandomizerSeed(Vec<[u8; 32]>),
    /// One signature share per lane.
    Share(Vec<frost::round2::SignatureShare>),
}

/// Length-prefix a list of byte blobs into one message: `count:u16 || (len:u32 || bytes)*`.
/// Multi-note signing carries one element per lane in a single relay message, so the message
/// count and routing stay identical to single-note (which is just a one-element batch).
pub(crate) fn encode_batch(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(items.len() as u16).to_le_bytes());
    for item in items {
        out.extend_from_slice(&(item.len() as u32).to_le_bytes());
        out.extend_from_slice(item);
    }
    out
}

/// Inverse of [`encode_batch`].
pub(crate) fn decode_batch(bytes: &[u8]) -> Result<Vec<Vec<u8>>, TransportError> {
    let err = || TransportError::Decode("truncated message batch".into());
    let count = u16::from_le_bytes(bytes.get(0..2).ok_or_else(err)?.try_into().unwrap()) as usize;
    let mut cur = 2;
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        let len =
            u32::from_le_bytes(bytes.get(cur..cur + 4).ok_or_else(err)?.try_into().unwrap()) as usize;
        cur += 4;
        items.push(bytes.get(cur..cur + len).ok_or_else(err)?.to_vec());
        cur += len;
    }
    Ok(items)
}

impl Outbound {
    /// Only public artifacts can be serialized without recipient encryption.
    pub fn to_bytes(&self) -> Result<Vec<u8>, TransportError> {
        match self {
            Self::Dkg(_) | Self::Commitments(_) => self.encode_plaintext(),
            _ => Err(TransportError::Auth("payment message requires recipient encryption".into())),
        }
    }

    fn encode_plaintext(&self) -> Result<Vec<u8>, TransportError> {
        let encoding = |e: frost::Error| TransportError::Decode(e.to_string());
        match self {
            Self::Dkg(wire) => Ok(wire.as_bytes().to_vec()),
            Self::Commitments(items) => {
                let blobs: Vec<Vec<u8>> = items
                    .iter()
                    .map(|c| c.serialize())
                    .collect::<Result<_, _>>()
                    .map_err(encoding)?;
                Ok(encode_batch(&blobs))
            }
            Self::Candidate(candidate) => Ok(candidate.as_bytes().to_vec()),
            Self::Package(items) => {
                let blobs: Vec<Vec<u8>> = items
                    .iter()
                    .map(|p| p.serialize())
                    .collect::<Result<_, _>>()
                    .map_err(encoding)?;
                Ok(encode_batch(&blobs))
            }
            Self::Randomizers(items) => {
                let mut bytes = b"LOKIALP1".to_vec();
                bytes.extend(encode_batch(&items.iter().map(|s| s.to_vec()).collect::<Vec<_>>()));
                Ok(bytes)
            }
            Self::RandomizerSeed(items) => {
                Ok(encode_batch(&items.iter().map(|s| s.to_vec()).collect::<Vec<_>>()))
            }
            Self::Share(items) => {
                Ok(encode_batch(&items.iter().map(|s| s.serialize()).collect::<Vec<_>>()))
            }
        }
    }
}

/// Roster-pinned payment encryption. The id-0 coordinator runs in the proposer's
/// member app; its public identity is delivered in the authenticated payment intent.
/// Long-lived roster keys are used, so this does not claim DKG v2 forward secrecy.
pub struct PaymentEncryption {
    identity: Identity,
    members: BTreeMap<u16, PublicIdentity>,
    context: [u8; 32],
}

impl PaymentEncryption {
    pub fn new(
        identity: &Identity, members: BTreeMap<u16, PublicIdentity>,
        vault: &[u8; 32], attempt: &[u8; 32], session: Uuid,
    ) -> Result<Self, TransportError> {
        let own = identity.public();
        if members.get(&own.id) != Some(&own) || !members.contains_key(&0)
            || members.iter().any(|(id, member)| *id != member.id)
            || members.values().map(|m| m.encryption).collect::<std::collections::BTreeSet<_>>().len() != members.len()
        {
            return Err(TransportError::Auth("invalid payment roster".into()));
        }
        let mut hash = blake3::Hasher::new_derive_key("Loki frostd payment context v1");
        hash.update(vault).update(attempt).update(session.as_bytes());
        for member in members.values() {
            hash.update(&member.id.to_be_bytes()).update(&member.signing).update(&member.encryption);
        }
        Ok(Self {
            identity: Identity::from_secret_bytes(&*Zeroizing::new(identity.to_secret_bytes())).map_err(TransportError::Auth)?,
            members,
            context: hash.finalize().into(),
        })
    }

    fn member(&self, peer: &Peer) -> Result<&PublicIdentity, TransportError> {
        self.members.values().find(|member| member.encryption == peer.0)
            .ok_or_else(|| TransportError::Auth("peer outside payment roster".into()))
    }

    pub fn seal(&self, recipient: &Peer, message: &Outbound) -> Result<Vec<u8>, TransportError> {
        let recipient = self.member(recipient)?;
        if matches!(message, Outbound::Commitments(_)) {
            return message.to_bytes();
        }
        let body = Zeroizing::new(message.encode_plaintext()?);
        self.identity.seal_payment(recipient, &self.context, &body).map_err(TransportError::Auth)
    }

    pub fn open(&self, sender: &Peer, wire: &[u8]) -> Result<Vec<u8>, TransportError> {
        let sender = self.member(sender)?;
        // The only accepted plaintext payment artifact is a canonical batch of
        // public nonce commitments. PCZTs, packages, scalars and seeds fail closed.
        if let Ok(items) = decode_batch(wire) {
            if !items.is_empty() && encode_batch(&items) == wire
                && items.iter().all(|item| frost::round1::SigningCommitments::deserialize(item).is_ok())
            {
                return Ok(wire.to_vec());
            }
        }
        self.identity.open_payment(sender, &self.context, wire).map_err(TransportError::Auth)
    }
}

/// One inbound message: sender and body, decrypted and authenticated for payments
/// except public nonce commitments. The relay authenticates the commitment sender;
/// private payment bodies also authenticate against the pinned roster. Delivery is the
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

    /// Bound every blocking send/receive to this absolute deadline. Unsupported transports
    /// refuse bounded drives instead of silently leaving a host runner blocked.
    fn set_deadline(&self, deadline: Option<Instant>) -> bool { deadline.is_none() }

    /// Open an authenticated channel for a signing/DKG session. `peers` is the full
    /// roster (coordinator + participants) by frostd pubkey; `message_count` is the
    /// number of logical messages the coordinator will send per participant (frostd
    /// uses it to size the session). Only the coordinator calls `create`; participants
    /// join an existing `session`.
    fn open(&mut self, peers: &[Peer], message_count: u8) -> Result<Self::Channel, Self::Error>;

    /// Join an already-created session as a participant (coordinator shares `session`
    /// out of band / via the roster layer, ws3 §4).
    fn join(&mut self, session: Uuid) -> Result<Self::Channel, Self::Error>;

    /// Send one typed message to the given recipients. Empty `to` means "to the
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

pub(crate) async fn before_deadline<T>(
    deadline: Option<Instant>, operation: impl std::future::Future<Output = Result<T, TransportError>>,
) -> Result<T, TransportError> {
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        return Err(TransportError::Http("payment drive deadline elapsed".into()));
    }
    match deadline {
        Some(deadline) => tokio::time::timeout_at(deadline.into(), operation).await
            .map_err(|_| TransportError::Http("payment drive deadline elapsed".into()))?,
        None => operation.await,
    }
}

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
    payment: Option<PaymentEncryption>,
    deadline: std::cell::Cell<Option<Instant>>,
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
impl ReceiveOut {
    fn open(self, payment: Option<&PaymentEncryption>) -> Result<Vec<Incoming>, TransportError> {
        let mut incoming = Vec::new();
        for m in self.msgs {
            let key: [u8; 32] = m.sender.0.try_into()
                .map_err(|_| TransportError::Decode("sender pubkey length".into()))?;
            // A hosted session admits the whole vault before the approving quorum is known.
            if payment.is_some_and(|p| p.member(&Peer(key)).is_err()) { continue; }
            incoming.push(Incoming {
                from: Peer(key),
                message: match payment {
                    Some(payment) => payment.open(&Peer(key), &m.msg)?,
                    None => m.msg,
                },
            });
        }
        Ok(incoming)
    }
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
            payment: None,
            deadline: std::cell::Cell::new(None),
        };
        t.login()?;
        Ok(t)
    }

    pub fn encrypt_payments(&mut self, payment: PaymentEncryption) -> Result<(), TransportError> {
        if self.me.0 != payment.identity.public().encryption {
            return Err(TransportError::Auth("payment identity differs from relay login".into()));
        }
        self.payment = Some(payment);
        Ok(())
    }

    fn send_bytes(&self, channel: &FrostdChannel, to: &[Peer], message: Vec<u8>) -> Result<(), TransportError> {
        let recipients: Vec<String> = to.iter().map(|p| hex::encode(p.0)).collect();
        self.runtime.block_on(Self::post::<serde_json::Value>(
            &self.client, format!("{}/send", self.base_url), self.token,
            json!({ "session_id": channel.session, "recipients": recipients, "msg": hex::encode(message) }),
            self.deadline.get(),
        ))?;
        Ok(())
    }

    async fn post<O: for<'de> Deserialize<'de>>(
        client: &Client,
        url: String,
        token: Option<Uuid>,
        body: serde_json::Value,
        deadline: Option<Instant>,
    ) -> Result<O, TransportError> {
        before_deadline(deadline, async {
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
        }).await
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
                Self::post(&client, format!("{base}/challenge"), None, json!({}), None).await?;
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
                None,
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

    fn set_deadline(&self, deadline: Option<Instant>) -> bool {
        self.deadline.set(deadline);
        true
    }

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
            None,
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
        if let Some(payment) = &self.payment {
            if matches!(message, Outbound::Dkg(_)) {
                return Err(TransportError::Auth("DKG wire in payment session".into()));
            }
            let recipients = if to.is_empty() {
                vec![Peer(payment.members[&0].encryption)]
            } else {
                to.to_vec()
            };
            for recipient in recipients {
                let bytes = payment.seal(&recipient, message)?;
                // Empty recipients addresses the coordinator's separate frostd mailbox.
                let route = if to.is_empty() { vec![] } else { vec![recipient] };
                self.send_bytes(channel, &route, bytes)?;
            }
            Ok(())
        } else {
            self.send_bytes(channel, to, message.to_bytes()?)
        }
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
            self.deadline.get(),
        ))?;
        out.open(self.payment.as_ref())
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
            self.deadline.get(),
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
    fn candidate_cannot_be_serialized_without_recipient_encryption() {
        let candidate = crate::signer::CandidatePczt(b"private candidate and viewing key".to_vec());
        assert!(Outbound::Candidate(candidate).to_bytes().is_err());
    }

    #[test]
    fn payment_packages_randomizers_and_shares_are_private_but_commitments_are_public() {
        let coordinator = Identity::new(0);
        let member = Identity::new(1);
        let roster = BTreeMap::from([(0, coordinator.public()), (1, member.public())]);
        let session = Uuid::new_v4();
        let sender = PaymentEncryption::new(&coordinator, roster.clone(), &[4; 32], &[5; 32], session).unwrap();
        let receiver = PaymentEncryption::new(&member, roster, &[4; 32], &[5; 32], session).unwrap();
        let (shares, _) = frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, &mut rand_core::OsRng).unwrap();
        let keys: Vec<_> = shares.values().take(2).map(|s| frost::keys::KeyPackage::try_from(s.clone()).unwrap()).collect();
        let (nonces, commitments): (Vec<_>, Vec<_>) = keys.iter().map(|k| frost::round1::commit(k.signing_share(), &mut rand_core::OsRng)).unzip();
        let package = frost::SigningPackage::new(keys.iter().zip(&commitments).map(|(k, c)| (*k.identifier(), *c)).collect(), &[9; 32]);
        let share = frost::round2::sign(&package, &nonces[0], &keys[0]).unwrap();
        let from = Peer(coordinator.public().encryption);
        let to = Peer(member.public().encryption);
        for message in [Outbound::Package(vec![package]), Outbound::Randomizers(vec![[6; 32]]), Outbound::RandomizerSeed(vec![[7; 32]]), Outbound::Share(vec![share])] {
            let plain = message.encode_plaintext().unwrap();
            assert!(message.to_bytes().is_err());
            assert!(receiver.open(&from, &plain).is_err());
            let wire = sender.seal(&to, &message).unwrap();
            assert!(!wire.windows(plain.len()).any(|w| w == plain));
            assert_eq!(receiver.open(&from, &wire).unwrap(), plain);
        }
        let public = Outbound::Commitments(commitments);
        let wire = sender.seal(&to, &public).unwrap();
        assert_eq!(wire, public.to_bytes().unwrap());
        assert_eq!(receiver.open(&from, &wire).unwrap(), wire);
        let outsiders = ReceiveOut { msgs: vec![
            WireMsg { sender: HexKey(Identity::new(3).public().encryption.to_vec()), msg: vec![0] },
            WireMsg { sender: HexKey(from.0.to_vec()), msg: wire.clone() },
        ] }.open(Some(&receiver)).unwrap();
        assert_eq!(outsiders.len(), 1);
        assert_eq!(outsiders[0].message, wire);
        assert!(ReceiveOut { msgs: vec![WireMsg { sender: HexKey(from.0.to_vec()), msg: vec![0] }] }
            .open(Some(&receiver)).is_err(), "invalid selected-member messages must still fail closed");
    }

    #[test]
    fn payment_box_reuses_dkg_authentication_without_dkg_size_or_domain_confusion() {
        let alice = Identity::new(1);
        let bob = Identity::new(2);
        let context = [3; 32];
        let large = vec![42; 128 * 1024];
        assert!(alice.seal_round2(&bob.public(), &context, &large).is_err());
        let wire = alice.seal_payment(&bob.public(), &context, &large).unwrap();
        assert_eq!(bob.open_payment(&alice.public(), &context, &wire).unwrap(), large);
        assert!(bob.open_round2(&alice.public(), &context, &wire).is_err());
        let dkg = alice.seal_round2(&bob.public(), &context, b"share").unwrap();
        assert_eq!(bob.open_round2(&alice.public(), &context, &dkg).unwrap(), b"share");
        assert!(bob.open_payment(&alice.public(), &context, &dkg).is_err());
    }

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
