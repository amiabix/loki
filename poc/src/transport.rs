//! WS3 transport: move the PUBLIC protocol messages (DKG rounds, signing
//! commitments, signing packages, signature shares) between the coordinator and the
//! signers over the audited ZF `frostd` relay (`docs/product/ws3-transport.md`).
//!
//! `frostd` is an honest-but-curious JSON-over-HTTP(S) relay: it queues opaque bytes
//! keyed by session + recipient pubkey and hands them back on `receive`. It never
//! inspects the payload (`frostd/src/functions.rs` `send`/`receive` just move
//! `Msg { sender, msg }`). Confidentiality/integrity between members is Loki's own
//! `setup_transport` / `signing_session` authenticated-sealed-message model; what we
//! hand the relay is ALREADY sealed public ciphertext (ws3 §5/§6). This module is only
//! the delivery seam; it holds no share, nonce, or viewing key.
//!
//! The [`Transport`] trait is the stable interface (ws3 §5) so the serverless
//! Zcash-memo transport can be added later behind the same four methods without
//! touching WS1/WS2. [`FrostdTransport`] is the `frostd` implementation.
//!
//! Addressing: a member is named by its 32-byte `frostd` public key, which for Loki is
//! the member's X25519 `setup_transport` encryption key (`PublicIdentity::encryption`).
//! Login proves possession of the matching secret via XEdDSA over the server challenge
//! — the exact scheme `frostd` verifies (`frostd/src/functions.rs::login`, `xed25519`).

use std::time::Duration;

use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::runtime::Runtime;
use uuid::Uuid;

/// A member address on the relay: its 32-byte frostd/X25519 public key.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Peer(pub [u8; 32]);

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
/// Every payload is opaque PUBLIC authenticated bytes — never a secret.
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

    /// Send opaque public bytes to the given recipients. Empty `to` means "to the
    /// coordinator" (frostd convention).
    fn send(&self, channel: &Self::Channel, to: &[Peer], message: &[u8])
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

/// `frostd` client for one member. Owns its own tokio runtime (same block-on pattern as
/// `setup_relay`) and a logged-in bearer token. The member's frostd pubkey is its
/// X25519 `setup_transport` encryption key; `secret` is the matching 32-byte X25519
/// secret, used ONLY to XEdDSA-sign the login challenge — never a FROST share.
pub struct FrostdTransport {
    base_url: String,
    client: Client,
    runtime: Runtime,
    me: Peer,
    secret: [u8; 32],
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
    /// ws3 §6). `me` is this member's frostd pubkey; `secret` its matching X25519 secret.
    pub fn new(base_url: &str, me: Peer, secret: [u8; 32]) -> Result<Self, TransportError> {
        let runtime = Runtime::new().map_err(|e| TransportError::Http(e.to_string()))?;
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|e| TransportError::Http(e.to_string()))?;
        let mut t = Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            client,
            runtime,
            me,
            secret,
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
        let secret = self.secret;
        let me = self.me.0;
        let token = self.runtime.block_on(async move {
            let ch: ChallengeOut =
                Self::post(&client, format!("{base}/challenge"), None, json!({})).await?;
            let signing = xeddsa::xed25519::PrivateKey::from(&secret);
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

    fn send(&self, channel: &FrostdChannel, to: &[Peer], message: &[u8]) -> Result<(), TransportError> {
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
