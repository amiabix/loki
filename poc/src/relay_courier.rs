//! Version-one signing carriers over the member relay store.
//! The inner envelope stays sealed. Retry reuses the committed outer objects.

use crate::{
    relay_member::{open_session, routed, snapshot_response, PublicEventWriter, Session},
    setup_transport::{Identity, PublicIdentity},
    signing_session::{EnvelopeRoute, MessageKind, OpenedMessage, SessionContext, SessionCourier},
};
use loki_relay_client::{
    outbox_intent_digest, poll_once, poll_once_observed, prepare_outbox, reopen_committed,
    upload_pending, upload_pending_observed, ClientError, ClientStore, CommIdentity, Observation,
    ObservationKind, ObservationSink, RelayHttp, RelayRuntime, ThirdPass,
};
use loki_relay_protocol::types::{roster_digest, LogicalKey, MessageBody, Payload, Roster};
use rand_core::{OsRng, RngCore};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::{Cursor, Read, Write},
    os::fd::{AsRawFd, FromRawFd},
    path::{Path, PathBuf},
    sync::mpsc::Receiver,
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
    events: Option<PublicEventWriter>,
    observe: Option<File>,
    control: Option<File>,
    response: Option<File>,
    control_buf: Vec<u8>,
    http_sink: ObservationSink,
    journal_sink: Option<ObservationSink>,
    http_events: Option<Receiver<Observation>>,
    journal_events: Option<Receiver<Observation>>,
    seen_http_drops: u64,
    seen_journal_drops: u64,
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
            events: None,
            observe: None,
            control: None,
            response: None,
            control_buf: Vec::new(),
            http_sink: ObservationSink::disabled(),
            journal_sink: None,
            http_events: None,
            journal_events: None,
            seen_http_drops: 0,
            seen_journal_drops: 0,
        };
        courier.load_accepted()?;
        Ok(courier)
    }

    pub fn database(&self) -> &ClientStore {
        &self.session.db
    }

    pub fn set_events(&mut self, events: PublicEventWriter) {
        self.install_sinks();
        self.events = Some(events);
    }

    pub fn take_events(&mut self) -> Option<PublicEventWriter> {
        self.events.take()
    }

    pub fn pop_events(&mut self) -> Vec<Vec<u8>> {
        let mut lines = Vec::new();
        if let Some(events) = &mut self.events {
            while let Some(line) = events.pop_line() {
                lines.push(line);
            }
        }
        lines
    }

    /// Take the write end of the observation pipe and the read/write ends of the control pipes.
    /// The descriptors are inherited from the controller and are not mixed into approval stdout.
    pub fn attach_inherited(
        &mut self,
        observe: i32,
        control: i32,
        response: i32,
    ) -> Result<(), String> {
        if observe < 0 || control < 0 || response < 0 {
            return Err("export_fd".into());
        }
        let observe = unsafe { File::from_raw_fd(observe) };
        let control = unsafe { File::from_raw_fd(control) };
        set_nonblocking(&control);
        let response = unsafe { File::from_raw_fd(response) };
        let id = self.session.member.identity.public().id;
        let writer = PublicEventWriter::new(&export_run_id(&self.session), &format!("member-{id}"))
            .map_err(|_| "export_fd".to_string())?;
        self.set_events(writer);
        self.observe = Some(observe);
        self.control = Some(control);
        self.response = Some(response);
        Ok(())
    }

    pub fn note_application(&mut self, accepted: bool, message: &OpenedMessage) {
        let event = if accepted {
            "application_accepted"
        } else {
            "application_rejected"
        };
        self.emit_signing(
            event,
            message.sender(),
            Some(message.recipient()),
            message.kind(),
            message.wire_hash(),
            message.context(),
        );
        self.service_export();
    }

    pub fn note_approved(
        &mut self,
        context: &SessionContext,
        member: u16,
        envelope_hash: [u8; 32],
    ) {
        self.emit_signing(
            "approved",
            member,
            None,
            MessageKind::Share,
            envelope_hash,
            context,
        );
        self.service_export();
    }

    /// Read one snapshot request, if the control pipe has a line, and flush queued public events.
    /// A broken pipe disables export and leaves the transport result unchanged.
    pub fn service_export(&mut self) {
        self.drain_observations();
        if self.events.as_ref().is_some_and(|events| events.disabled()) {
            self.persist_gap();
            return;
        }
        let request = self.take_control_request();
        if let Some(request) = request {
            let response = match snapshot_response(&self.session, request.trim()) {
                Ok(page) => page,
                Err(_) => "{\"version\":1,\"error\":\"request\"}".to_string(),
            };
            if self.write_response(&response).is_err() {
                self.disable_export();
            }
        }
        self.flush_observe();
        self.persist_gap();
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
        let opened = self.receive_authenticated(own, roster, context, kind, sender);
        self.service_export();
        opened
    }

    fn drive_once(&mut self) -> Result<(), String> {
        let pumped = self.pump_transport();
        self.service_export();
        pumped
    }
}

impl RelayCourier {
    fn receive_authenticated(
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
                self.emit_signing(
                    "session_envelope_authenticated",
                    carrier.author,
                    Some(carrier.recipient),
                    kind,
                    carrier.envelope_hash,
                    context,
                );
                return Ok(Some(message));
            }
            if page.len() < 100 {
                return Ok(None);
            }
        }
    }

    fn pump_transport(&mut self) -> Result<(), String> {
        let (config, self_route) = routed(&self.session).map_err(map_session)?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "carrier_clock")?
            .as_millis() as u64;
        let journal = self.journal_sink.clone();
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
                    if let Some(observer) = &journal {
                        upload_pending_observed(
                            &mut session.db,
                            http,
                            logical,
                            &session.member.roster,
                            &session.member.identity,
                            &config,
                            &self_route,
                            now,
                            ThirdPass::StopAfterStored,
                            observer,
                        )
                        .await
                        .map_err(map_client)?;
                    } else {
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
                }
                if page.len() < 100 || next <= after {
                    break;
                }
                after = next;
            }
            if let Some(observer) = &journal {
                poll_once_observed(
                    &mut session.db,
                    http,
                    &session.member.identity,
                    &session.member.roster,
                    &config,
                    &self_route,
                    now,
                    observer,
                )
                .await
                .map_err(map_client)?;
            } else {
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
            }
            Ok(())
        })
    }

    fn install_sinks(&mut self) {
        let (http_sink, http_events) = ObservationSink::bounded(1024);
        let (journal_sink, journal_events) = ObservationSink::bounded(1024);
        if let Ok(http) = RelayHttp::with_observer(http_sink.clone()) {
            self.http = http;
            self.http_sink = http_sink;
            self.journal_sink = Some(journal_sink);
            self.http_events = Some(http_events);
            self.journal_events = Some(journal_events);
            self.seen_http_drops = 0;
            self.seen_journal_drops = 0;
        }
    }

    fn emit_signing(
        &mut self,
        event_type: &str,
        sender: u16,
        recipient: Option<u16>,
        kind: MessageKind,
        envelope_hash: [u8; 32],
        context: &SessionContext,
    ) {
        let Some(events) = &mut self.events else {
            return;
        };
        let mut fields = serde_json::json!({
            "authenticated_sender": sender,
            "kind": kind as u8,
            "envelope_hash": hex::encode(envelope_hash),
            "vault_id": hex::encode(context.vault),
            "payment_id": hex::encode(context.payment),
            "attempt_id": hex::encode(context.attempt.0),
        });
        if let Some(recipient) = recipient {
            fields["recipient_member"] = serde_json::json!(recipient);
        }
        let _ = events.emit(event_type, fields);
    }

    fn drain_observations(&mut self) {
        let mut batch = Vec::new();
        if let Some(events) = &self.http_events {
            while let Ok(event) = events.try_recv() {
                batch.push(event);
            }
        }
        if let Some(events) = &self.journal_events {
            while let Ok(event) = events.try_recv() {
                batch.push(event);
            }
        }
        let http_drops = self
            .http_sink
            .dropped()
            .saturating_sub(self.seen_http_drops);
        self.seen_http_drops = self.http_sink.dropped();
        let journal_now = self
            .journal_sink
            .as_ref()
            .map(ObservationSink::dropped)
            .unwrap_or(0);
        let journal_drops = journal_now.saturating_sub(self.seen_journal_drops);
        self.seen_journal_drops = journal_now;
        if let Some(events) = &mut self.events {
            events.note_gap(http_drops.saturating_add(journal_drops));
            for event in &batch {
                let _ = events.emit(public_kind(event.kind), public_fields(event));
            }
        }
    }

    fn take_control_request(&mut self) -> Option<String> {
        loop {
            if self.control_buf.iter().any(|byte| *byte == b'\n') {
                break;
            }
            let mut tmp = [0u8; 1024];
            let read = {
                let control = self.control.as_mut()?;
                control.read(&mut tmp)
            };
            match read {
                Ok(0) => {
                    self.disable_export();
                    return None;
                }
                Ok(n) => {
                    self.control_buf.extend_from_slice(&tmp[..n]);
                    if self.control_buf.len() > 16 * 1024 {
                        self.disable_export();
                        return None;
                    }
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        || error.kind() == std::io::ErrorKind::Interrupted =>
                {
                    return None;
                }
                Err(_) => {
                    self.disable_export();
                    return None;
                }
            }
        }
        let pos = self.control_buf.iter().position(|byte| *byte == b'\n')?;
        let line: Vec<u8> = self.control_buf.drain(..=pos).collect();
        String::from_utf8(line).ok()
    }

    fn write_response(&mut self, response: &str) -> std::io::Result<()> {
        let Some(response_pipe) = &mut self.response else {
            return Ok(());
        };
        response_pipe.write_all(response.as_bytes())?;
        response_pipe.write_all(b"\n")?;
        response_pipe.flush()
    }

    fn flush_observe(&mut self) {
        if self.observe.is_none() {
            return;
        }
        let mut output = self.observe.take();
        let failed = match (&mut self.events, output.as_mut()) {
            (Some(events), Some(output)) => events.write_queued(output).is_err(),
            _ => false,
        };
        if failed {
            if let Some(events) = &mut self.events {
                events.disable();
            }
            return;
        }
        self.observe = output;
    }

    fn disable_export(&mut self) {
        if let Some(events) = &mut self.events {
            events.disable();
        }
        self.observe = None;
        self.control = None;
        self.response = None;
    }

    fn persist_gap(&self) {
        let Some(events) = &self.events else {
            return;
        };
        let count = events.dropped();
        if count == 0 {
            return;
        }
        let path = self
            .session
            .configs
            .directory()
            .join("transport")
            .join("observation-gap");
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(path, count.to_string());
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

fn export_run_id(session: &Session) -> String {
    match routed(session) {
        Ok((config, _)) => config
            .own
            .first()
            .map(|inbox| hex::encode(inbox.route.pin.run))
            .filter(|value| (1..=64).contains(&value.len()))
            .unwrap_or_else(|| "pending".into()),
        Err(_) => "pending".into(),
    }
}

fn public_kind(kind: ObservationKind) -> &'static str {
    match kind {
        ObservationKind::RequestStart => "request_start",
        ObservationKind::RequestEnd => "request_end",
        ObservationKind::ReceiptValidated => "receipt_validated",
        ObservationKind::ReceiptPersisted => "receipt_persisted",
        ObservationKind::ReceiptRejected => "receipt_rejected",
        ObservationKind::OriginalAuthenticated => "original_authenticated",
        ObservationKind::OriginalCommitted => "original_committed",
        ObservationKind::ReceivedLinked => "received_linked",
        ObservationKind::RetryDue => "retry_due",
        ObservationKind::RouteFailure => "route_failure",
        ObservationKind::Quarantine => "quarantine",
    }
}

fn public_fields(event: &Observation) -> serde_json::Value {
    let mut fields = serde_json::Map::new();
    if let Some(actor) = event.actor {
        fields.insert("actor_member".into(), serde_json::json!(actor));
    }
    if let Some(sender) = event.sender {
        fields.insert("authenticated_sender".into(), serde_json::json!(sender));
    }
    if let Some(recipient) = event.recipient {
        fields.insert("recipient_member".into(), serde_json::json!(recipient));
    }
    if let Some(pin) = event.pin {
        fields.insert("relay_pin".into(), serde_json::json!(hex::encode(pin)));
    }
    if let Some(run) = event.run {
        fields.insert("relay_run".into(), serde_json::json!(hex::encode(run)));
    }
    if let Some(mailbox) = event.mailbox {
        fields.insert("mailbox_id".into(), serde_json::json!(hex::encode(mailbox)));
    }
    if let Some(message) = event.logical_message {
        fields.insert("message_id".into(), serde_json::json!(hex::encode(message)));
    }
    if let Some(digest) = event.digest {
        fields.insert(
            "message_digest".into(),
            serde_json::json!(hex::encode(digest)),
        );
    }
    if let Some(hash) = event.object_hash {
        fields.insert("object_hash".into(), serde_json::json!(hex::encode(hash)));
    }
    if let Some(ordinal) = event.ordinal {
        fields.insert("object_ordinal".into(), serde_json::json!(ordinal));
    }
    if let Some(bytes) = event.bytes {
        fields.insert("wire_bytes".into(), serde_json::json!(bytes));
    }
    if event.request != 0 {
        fields.insert("request_id".into(), serde_json::json!(event.request));
    }
    if let Some(status) = event.status {
        fields.insert("http_status".into(), serde_json::json!(status));
    }
    if let Some(duration) = event.duration {
        fields.insert(
            "duration_ms".into(),
            serde_json::json!(u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)),
        );
    }
    if let Some(result) = event.result {
        fields.insert("result_code".into(), serde_json::json!(result));
    }
    serde_json::Value::Object(fields)
}

fn set_nonblocking(file: &File) {
    extern "C" {
        fn fcntl(fd: i32, cmd: i32, arg: i32) -> i32;
    }
    const F_GETFL: i32 = 3;
    const F_SETFL: i32 = 4;
    #[cfg(target_os = "linux")]
    const O_NONBLOCK: i32 = 0o4000;
    #[cfg(not(target_os = "linux"))]
    const O_NONBLOCK: i32 = 0x4;
    unsafe {
        let flags = fcntl(file.as_raw_fd(), F_GETFL, 0);
        if flags >= 0 {
            let _ = fcntl(file.as_raw_fd(), F_SETFL, flags | O_NONBLOCK);
        }
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
