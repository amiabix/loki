//! Version-one signing carriers over the member relay store.
//! The inner envelope stays sealed. Retry reuses the committed outer objects.

use crate::{
    relay_member::{open_session, routed, Session},
    setup_transport::{Identity, PublicIdentity},
    signing_session::{
        EnvelopeRoute, MessageKind, OpenedMessage, SessionContext, SessionCourier,
    },
};
use loki_relay_client::{
    outbox_intent_digest, poll_once, prepare_outbox, reopen_committed, upload_pending, ClientError,
    ClientStore, CommIdentity, RelayHttp, RelayRuntime, ThirdPass,
};
use loki_relay_protocol::types::{roster_digest, LogicalKey, MessageBody, Payload, Roster};
use rand_core::{OsRng, RngCore};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Cursor,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroizing;

const CARRIER_DOMAIN: &[u8] = b"Loki_Relay_Signing_Carrier_v1\0";
const MAX_ENVELOPE: usize = 8 * 1024 * 1024 + 53;
const MAX_CARRIER: usize = MAX_ENVELOPE + 512;
const VERSION: u64 = 1;

pub struct Carrier {
    pub context: SessionContext,
    pub author: u16,
    pub recipient: u16,
    pub kind: MessageKind,
    pub envelope_hash: [u8; 32],
    pub envelope: Zeroizing<Vec<u8>>,
}

pub struct CommittedCarrier {
    pub request: [u8; 32],
    pub message: [u8; 32],
    pub digest: [u8; 32],
}

impl Carrier {
    pub fn new(
        context: SessionContext,
        author: u16,
        recipient: u16,
        kind: MessageKind,
        envelope: Vec<u8>,
    ) -> Result<Self, String> {
        if envelope.len() > MAX_ENVELOPE || envelope.is_empty() {
            return Err("carrier_bounds".into());
        }
        let envelope_hash: [u8; 32] = blake3::hash(&envelope).into();
        let carrier = Self {
            context,
            author,
            recipient,
            kind,
            envelope_hash,
            envelope: Zeroizing::new(envelope),
        };
        carrier.check_fields()?;
        Ok(carrier)
    }

    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.check_fields()?;
        let value = ciborium::Value::Array(vec![
            integer(VERSION)?,
            bytes(&self.context.vault),
            bytes(&self.context.payment),
            bytes(&self.context.attempt.0),
            ciborium::Value::Array(vec![
                integer(u64::from(self.context.pair[0]))?,
                integer(u64::from(self.context.pair[1]))?,
            ]),
            integer(u64::from(self.author))?,
            integer(u64::from(self.recipient))?,
            integer(u64::from(self.kind as u8))?,
            bytes(&self.envelope_hash),
            bytes(&self.envelope),
        ]);
        let mut encoded = Vec::new();
        ciborium::into_writer(&value, &mut encoded).map_err(|_| "carrier_encode".to_string())?;
        if encoded.len() > MAX_CARRIER {
            return Err("carrier_bounds".into());
        }
        Ok(encoded)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > MAX_CARRIER {
            return Err("carrier_bounds".into());
        }
        let mut cursor = Cursor::new(bytes);
        let value: ciborium::Value =
            ciborium::from_reader(&mut cursor).map_err(|_| "carrier_decode".to_string())?;
        if cursor.position() as usize != bytes.len() {
            return Err("carrier_trailing".into());
        }
        let items = value.as_array().ok_or("carrier_schema")?;
        if items.len() != 10 {
            return Err("carrier_schema".into());
        }
        if unsigned(&items[0])? != VERSION {
            return Err("carrier_version".into());
        }
        let vault = exact_bytes(&items[1], 32)?;
        let payment = exact_bytes(&items[2], 32)?;
        let attempt = exact_bytes(&items[3], 32)?;
        let pair_items = items[4].as_array().ok_or("carrier_schema")?;
        if pair_items.len() != 2 {
            return Err("carrier_pair".into());
        }
        let pair = [
            u16::try_from(unsigned(&pair_items[0])?).map_err(|_| "carrier_pair".to_string())?,
            u16::try_from(unsigned(&pair_items[1])?).map_err(|_| "carrier_pair".to_string())?,
        ];
        let author = u16::try_from(unsigned(&items[5])?).map_err(|_| "carrier_id".to_string())?;
        let recipient =
            u16::try_from(unsigned(&items[6])?).map_err(|_| "carrier_id".to_string())?;
        let kind = u8::try_from(unsigned(&items[7])?).map_err(|_| "carrier_kind".to_string())?;
        let kind = MessageKind::try_from(kind).map_err(|_| "carrier_kind".to_string())?;
        let envelope_hash = exact_bytes(&items[8], 32)?;
        let envelope = items[9].as_bytes().ok_or("carrier_schema")?.to_vec();
        if envelope.len() > MAX_ENVELOPE || blake3::hash(&envelope).as_bytes() != &envelope_hash {
            return Err("carrier_hash".into());
        }
        let carrier = Self {
            context: SessionContext {
                vault,
                payment,
                attempt: crate::signing_session::AttemptId(attempt),
                pair,
            },
            author,
            recipient,
            kind,
            envelope_hash,
            envelope: Zeroizing::new(envelope),
        };
        carrier.check_fields()?;
        Ok(carrier)
    }

    pub fn request_binding(&self) -> Result<[u8; 32], String> {
        self.check_fields()?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(CARRIER_DOMAIN);
        hasher.update(&self.context.vault);
        hasher.update(&self.context.payment);
        hasher.update(&self.context.attempt.0);
        hasher.update(&self.context.pair[0].to_be_bytes());
        hasher.update(&self.context.pair[1].to_be_bytes());
        hasher.update(&self.author.to_be_bytes());
        hasher.update(&self.recipient.to_be_bytes());
        hasher.update(&[self.kind as u8]);
        hasher.update(&self.envelope_hash);
        Ok(hasher.finalize().into())
    }

    fn check_fields(&self) -> Result<(), String> {
        self.context.validate().map_err(|_| "carrier_pair")?;
        if !(1..=3).contains(&self.author) || !(1..=3).contains(&self.recipient) {
            return Err("carrier_id".into());
        }
        if self.author == self.recipient || self.envelope.is_empty() {
            return Err("carrier_id".into());
        }
        if blake3::hash(&self.envelope).as_bytes() != &self.envelope_hash {
            return Err("carrier_hash".into());
        }
        Ok(())
    }
}

pub fn commit_carrier(
    store: &mut ClientStore,
    identity: &CommIdentity,
    roster: &Roster,
    carrier: &Carrier,
) -> Result<CommittedCarrier, String> {
    let request = carrier.request_binding()?;
    let encoded = carrier.encode()?;
    let digest = roster_digest(roster).map_err(|_| "roster")?;
    if identity.public().id != carrier.author {
        return Err("carrier_author".into());
    }
    let mut body = MessageBody {
        key: LogicalKey {
            vault: roster.vault,
            roster: digest,
            sender: identity.public().id,
            message: [0; 32],
        },
        audience: vec![1, 2, 3],
        session: None,
        prerequisites: Vec::new(),
        payload: Payload::Test(encoded),
    };
    let intent = outbox_intent_digest(&body).map_err(map_client)?;
    if let Some(existing) = store
        .lookup_outbox_request(&request, &intent)
        .map_err(map_client)?
    {
        let copy = store
            .recover_recipients(&existing.key)
            .map_err(map_client)?
            .into_iter()
            .find(|recipient| recipient.recipient == identity.public().id)
            .ok_or("carrier_binding")?;
        let opened = reopen_committed(
            store,
            roster,
            identity,
            &existing.key,
            &existing.digest,
            &copy.root_hash,
        )
        .map_err(map_client)?;
        let Payload::Test(saved) = &opened.message().body().payload else {
            return Err("carrier_payload".into());
        };
        if saved.as_slice() != body_payload(&body) {
            return Err("conflict".into());
        }
        return Ok(CommittedCarrier {
            request,
            message: existing.key.message,
            digest: existing.digest,
        });
    }
    OsRng
        .try_fill_bytes(&mut body.key.message)
        .map_err(|_| "carrier_random")?;
    let prepared = prepare_outbox(identity, roster, &body).map_err(map_client)?;
    let digest = *prepared.digest();
    let message = prepared.key().message;
    store
        .commit_outbox(roster, identity, &request, &prepared)
        .map_err(map_client)?;
    wipe_payload(&mut body);
    Ok(CommittedCarrier {
        request,
        message,
        digest,
    })
}

fn body_payload(body: &MessageBody) -> &[u8] {
    match &body.payload {
        Payload::Test(bytes) => bytes,
        Payload::Received(_) => &[],
    }
}

fn wipe_payload(body: &mut MessageBody) {
    if let Payload::Test(bytes) = &mut body.payload {
        bytes.fill(0);
    }
}

pub struct RelayCourier {
    root: PathBuf,
    session: Session,
    runtime: RelayRuntime,
    http: RelayHttp,
    accepted: BTreeSet<[u8; 32]>,
}

impl RelayCourier {
    pub fn open(root: &Path, pass: &Path, roster: &Path) -> Result<Self, String> {
        let session = open_session(root, pass, roster).map_err(map_session)?;
        let runtime = RelayRuntime::new().map_err(|_| "carrier_runtime")?;
        let http = RelayHttp::new().map_err(map_client)?;
        let mut courier = Self {
            root: root.to_path_buf(),
            session,
            runtime,
            http,
            accepted: BTreeSet::new(),
        };
        courier.load_accepted()?;
        Ok(courier)
    }

    pub fn database(&self) -> &ClientStore {
        &self.session.db
    }

    fn load_accepted(&mut self) -> Result<(), String> {
        let path = self.root.join("accepted-carriers");
        if !path.exists() {
            return Ok(());
        }
        let text = fs::read_to_string(&path).map_err(|_| "carrier_state")?;
        for line in text.lines() {
            if line.len() != 64 {
                return Err("carrier_state".into());
            }
            let bytes = hex::decode(line).map_err(|_| "carrier_state")?;
            let hash: [u8; 32] = bytes.try_into().map_err(|_| "carrier_state")?;
            self.accepted.insert(hash);
        }
        Ok(())
    }

    fn remember(&mut self, hash: [u8; 32]) -> Result<(), String> {
        if !self.accepted.insert(hash) {
            return Ok(());
        }
        let path = self.root.join("accepted-carriers");
        let mut lines = String::new();
        for saved in &self.accepted {
            lines.push_str(&hex::encode(saved));
            lines.push('\n');
        }
        fs::write(&path, lines).map_err(|_| "carrier_state")?;
        Ok(())
    }
}

impl SessionCourier for RelayCourier {
    fn publish(&mut self, route: &EnvelopeRoute<'_>, wire: &[u8]) -> Result<[u8; 32], String> {
        let carrier = Carrier::new(
            route.context.clone(),
            route.author,
            route.recipient,
            route.kind,
            wire.to_vec(),
        )?;
        if carrier.author != self.session.member.identity.public().id {
            return Err("carrier_author".into());
        }
        commit_carrier(
            &mut self.session.db,
            &self.session.member.identity,
            &self.session.member.roster,
            &carrier,
        )?;
        Ok(blake3::hash(wire).into())
    }

    fn receive(
        &mut self,
        own: &Identity,
        roster: &BTreeMap<u16, PublicIdentity>,
        context: &SessionContext,
        kind: MessageKind,
        sender: u16,
    ) -> Result<Option<OpenedMessage>, String> {
        let mut after = 0u64;
        loop {
            let page = self
                .session
                .db
                .recover_incoming_originals(after, 100)
                .map_err(map_client)?;
            if page.is_empty() {
                return Ok(None);
            }
            after = page.last().map(|row| row.cursor).unwrap_or(after);
            for original in &page {
                if original.key.sender != sender {
                    continue;
                }
                let opened = reopen_committed(
                    &self.session.db,
                    &self.session.member.roster,
                    &self.session.member.identity,
                    &original.key,
                    &original.digest,
                    &original.source_root,
                )
                .map_err(map_client)?;
                let Payload::Test(bytes) = &opened.message().body().payload else {
                    continue;
                };
                let carrier = match Carrier::decode(bytes) {
                    Ok(carrier) => carrier,
                    Err(_) => continue,
                };
                if opened.message().body().key.sender != carrier.author {
                    return Err("carrier_author".into());
                }
                if &carrier.context != context
                    || carrier.kind != kind
                    || carrier.author != sender
                    || carrier.recipient != own.public().id
                {
                    continue;
                }
                if self.accepted.contains(&carrier.envelope_hash) {
                    continue;
                }
                let Some(peer) = roster.get(&carrier.author) else {
                    continue;
                };
                let message = match own.open_session(peer, context, &carrier.envelope) {
                    Ok(message) => message,
                    Err(_) => continue,
                };
                if message.kind() != kind || message.sender() != sender {
                    continue;
                }
                self.remember(carrier.envelope_hash)?;
                return Ok(Some(message));
            }
            if page.len() < 100 {
                return Ok(None);
            }
        }
    }

    fn drive_once(&mut self) -> Result<(), String> {
        let (config, self_route) = routed(&self.session).map_err(map_session)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "carrier_clock")?
            .as_millis() as u64;
        let RelayCourier {
            session,
            runtime,
            http,
            ..
        } = self;
        runtime.block_on(async {
            let mut after = 0u64;
            loop {
                let page = session.db.recover_logical(after, 100).map_err(map_client)?;
                if page.is_empty() {
                    break;
                }
                let next = page.last().map(|row| row.cursor).unwrap_or(after);
                for logical in &page {
                    upload_pending(
                        &mut session.db,
                        http,
                        logical,
                        &session.member.roster,
                        &session.member.identity,
                        &config,
                        &self_route,
                        now,
                        ThirdPass::StopAfterStored,
                    )
                    .await
                    .map_err(map_client)?;
                }
                if page.len() < 100 || next <= after {
                    break;
                }
                after = next;
            }
            poll_once(
                &mut session.db,
                http,
                &session.member.identity,
                &session.member.roster,
                &config,
                &self_route,
                now,
            )
            .await
            .map_err(map_client)?;
            Ok(())
        })
    }
}

const SEGMENT_LEN: usize = 61440;
const OBJECT_CAP: u64 = 65536;
const LOGICAL_MESSAGES: u64 = 5;
const MEMBER_BUDGET: u64 = 512 * 1024 * 1024;
const INBOX_QUOTA: u64 = 64 * 1024 * 1024;
const RELAY_QUOTA: u64 = 256 * 1024 * 1024;

#[derive(Clone, Copy)]
pub struct AttemptQuotas {
    pub inbox_bytes: u64,
    pub relay_bytes: u64,
    pub member_bytes: u64,
}

pub fn demo_quotas() -> AttemptQuotas {
    AttemptQuotas {
        inbox_bytes: INBOX_QUOTA,
        relay_bytes: RELAY_QUOTA,
        member_bytes: MEMBER_BUDGET,
    }
}

/// Reserve one full attempt. Each logical message carries one inner envelope.
pub fn reserve_attempt(max_envelope: usize, quotas: AttemptQuotas) -> Result<u64, String> {
    if max_envelope == 0 || max_envelope > MAX_ENVELOPE {
        return Err("carrier_bounds".into());
    }
    let body = max_envelope + 512;
    if body > 16 * 1024 * 1024 {
        return Err("carrier_bounds".into());
    }
    let per_copy = copy_bytes(body)?;
    let inbox = LOGICAL_MESSAGES * per_copy + LOGICAL_MESSAGES * OBJECT_CAP;
    let relay = inbox.checked_mul(3).ok_or("capacity")?;
    let retained = (max_envelope as u64).checked_mul(4).ok_or("capacity")?;
    let member = LOGICAL_MESSAGES
        .checked_mul(3)
        .and_then(|copies| copies.checked_mul(per_copy))
        .and_then(|objects| objects.checked_add(LOGICAL_MESSAGES * 3 * OBJECT_CAP))
        .and_then(|objects| objects.checked_add(retained))
        .ok_or("capacity")?;
    if inbox > quotas.inbox_bytes || relay > quotas.relay_bytes || member > quotas.member_bytes {
        return Err("capacity".into());
    }
    Ok(member)
}

fn copy_bytes(body: usize) -> Result<u64, String> {
    let record = body + 128;
    if let Ok(padded) = loki_relay_protocol::envelope::padded_wire_length(record) {
        return Ok(padded as u64);
    }
    let chunks = record.div_ceil(SEGMENT_LEN);
    if !(1..=274).contains(&chunks) {
        return Err("carrier_bounds".into());
    }
    Ok((chunks as u64 + 1) * OBJECT_CAP)
}

impl RelayCourier {
    /// Every committed logical message has two distinct relay pins covering all three copies.
    pub fn whole_attempt_stored(&mut self) -> Result<bool, String> {
        let (config, self_route) = routed(&self.session).map_err(map_session)?;
        let mut after = 0u64;
        let mut seen = false;
        loop {
            let page = self
                .session
                .db
                .recover_logical(after, 100)
                .map_err(map_client)?;
            if page.is_empty() {
                break;
            }
            seen = true;
            let next = page.last().map(|row| row.cursor).unwrap_or(after);
            for logical in &page {
                let report = self
                    .session
                    .db
                    .delivery_report(
                        &self.session.member.roster,
                        &self.session.member.identity,
                        logical,
                        &config,
                        &self_route,
                    )
                    .map_err(map_client)?;
                if !report.whole_vault() {
                    return Ok(false);
                }
            }
            if page.len() < 100 || next <= after {
                break;
            }
            after = next;
        }
        Ok(seen)
    }
}

fn map_client(error: ClientError) -> String {
    error.code().to_string()
}

fn map_session(error: crate::relay_member::SessionError) -> String {
    match error {
        crate::relay_member::SessionError::Member(error) => error.code().to_string(),
        crate::relay_member::SessionError::Client(error) => error.code().to_string(),
    }
}

fn integer(value: u64) -> Result<ciborium::Value, String> {
    Ok(ciborium::Value::Integer(
        ciborium::value::Integer::try_from(value).map_err(|_| "carrier_schema")?,
    ))
}

fn bytes(value: &[u8]) -> ciborium::Value {
    ciborium::Value::Bytes(value.to_vec())
}

fn unsigned(value: &ciborium::Value) -> Result<u64, String> {
    let integer = value.as_integer().ok_or("carrier_schema")?;
    let number: i128 = integer
        .try_into()
        .map_err(|_| "carrier_schema".to_string())?;
    u64::try_from(number).map_err(|_| "carrier_schema".to_string())
}

fn exact_bytes(value: &ciborium::Value, len: usize) -> Result<[u8; 32], String> {
    let bytes = value.as_bytes().ok_or("carrier_schema")?;
    if bytes.len() != len || len != 32 {
        return Err("carrier_schema".into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(bytes);
    Ok(out)
}
