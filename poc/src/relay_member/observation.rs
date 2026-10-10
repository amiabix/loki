//! Version-one public observation events. Encoding stays in the PoC, which already uses serde_json.

use serde_json::{Map, Value};
use std::{
    collections::VecDeque,
    io::Write,
    time::{SystemTime, UNIX_EPOCH},
};

pub const MAX_EVENT_BYTES: usize = 16 * 1024;
pub const QUEUE_CAP: usize = 1024;

const FIELDS: &[&str] = &[
    "version",
    "run_id",
    "producer_id",
    "producer_sequence",
    "observed_at",
    "event_type",
    "actor_member",
    "authenticated_sender",
    "recipient_member",
    "relay_pin",
    "relay_run",
    "mailbox_id",
    "message_id",
    "message_digest",
    "object_hash",
    "object_ordinal",
    "wire_bytes",
    "request_id",
    "http_status",
    "duration_ms",
    "result_code",
    "receipt_digest",
    "gap_count",
    "kind",
    "envelope_hash",
    "vault_id",
    "payment_id",
    "attempt_id",
];

const TYPES: &[&str] = &[
    "request_start",
    "request_end",
    "receipt_validated",
    "receipt_persisted",
    "receipt_rejected",
    "original_authenticated",
    "original_committed",
    "received_linked",
    "retry_due",
    "route_failure",
    "quarantine",
    "session_envelope_authenticated",
    "application_accepted",
    "application_rejected",
    "approved",
];

pub struct PublicEventWriter {
    run_id: String,
    producer_id: String,
    sequence: u64,
    pending_gap: u64,
    dropped: u64,
    queue: VecDeque<Vec<u8>>,
    disabled: bool,
}

impl PublicEventWriter {
    pub fn new(run_id: &str, producer_id: &str) -> Result<Self, &'static str> {
        if !public_token(run_id) || !public_token(producer_id) {
            return Err("event_identity");
        }
        Ok(Self {
            run_id: run_id.to_string(),
            producer_id: producer_id.to_string(),
            sequence: 0,
            pending_gap: 0,
            dropped: 0,
            queue: VecDeque::new(),
            disabled: false,
        })
    }

    pub fn gap_count(&self) -> u64 {
        self.pending_gap
    }

    /// Gaps from this writer and from the transport observer, including ones already reported.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    pub fn note_gap(&mut self, count: u64) {
        if count == 0 || self.disabled {
            return;
        }
        self.pending_gap = self.pending_gap.saturating_add(count);
        self.dropped = self.dropped.saturating_add(count);
    }

    pub fn disable(&mut self) {
        self.disabled = true;
        self.queue.clear();
    }

    pub fn disabled(&self) -> bool {
        self.disabled
    }

    /// Queue one allowlisted event. A full queue or an oversized body counts a gap and does not block.
    pub fn emit(&mut self, event_type: &str, fields: Value) -> Result<(), &'static str> {
        if self.disabled {
            return Ok(());
        }
        if !TYPES.contains(&event_type) {
            return Err("event_type");
        }
        let Value::Object(extra) = fields else {
            return Err("event_fields");
        };
        if extra.contains_key("version") && extra.get("version") != Some(&Value::from(1)) {
            return Err("event_version");
        }
        for (name, value) in &extra {
            if !FIELDS.contains(&name.as_str())
                || matches!(
                    name.as_str(),
                    "version"
                        | "run_id"
                        | "producer_id"
                        | "producer_sequence"
                        | "observed_at"
                        | "event_type"
                        | "gap_count"
                )
            {
                return Err("event_field");
            }
            if !public_value(value) {
                return Err("event_field");
            }
        }
        if self.queue.len() >= QUEUE_CAP {
            self.note_gap(1);
            return Ok(());
        }
        self.sequence = self.sequence.saturating_add(1);
        let mut object = Map::new();
        object.insert("version".into(), Value::from(1));
        object.insert("run_id".into(), Value::String(self.run_id.clone()));
        object.insert(
            "producer_id".into(),
            Value::String(self.producer_id.clone()),
        );
        object.insert("producer_sequence".into(), Value::from(self.sequence));
        object.insert("observed_at".into(), Value::String(utc_now()));
        object.insert("event_type".into(), Value::String(event_type.to_string()));
        if self.pending_gap > 0 {
            object.insert("gap_count".into(), Value::from(self.pending_gap));
            self.pending_gap = 0;
        }
        for (name, value) in extra {
            object.insert(name, value);
        }
        let encoded = serde_json::to_vec(&Value::Object(object)).map_err(|_| "event_encode")?;
        if encoded.len() > MAX_EVENT_BYTES {
            self.sequence = self.sequence.saturating_sub(1);
            self.note_gap(1);
            return Err("event_bounds");
        }
        self.queue.push_back(encoded);
        Ok(())
    }

    pub fn pop_line(&mut self) -> Option<Vec<u8>> {
        self.queue.pop_front()
    }

    /// Write queued lines. A broken pipe disables later export and leaves the caller’s protocol result alone.
    pub fn write_queued(&mut self, output: &mut dyn Write) -> std::io::Result<()> {
        while let Some(line) = self.queue.front() {
            if let Err(error) = output.write_all(line).and_then(|_| output.write_all(b"\n")) {
                self.disabled = true;
                self.queue.clear();
                return Err(error);
            }
            self.queue.pop_front();
        }
        Ok(())
    }
}

fn public_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn public_value(value: &Value) -> bool {
    match value {
        Value::Null | Value::Number(_) | Value::Bool(_) => true,
        Value::String(text) => {
            text.len() <= 128
                && text
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() || byte == b' ')
        }
        Value::Array(_) | Value::Object(_) => false,
    }
}

fn utc_now() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    civil_utc(secs)
}

fn civil_utc(secs: u64) -> String {
    let days = secs / 86_400;
    let tod = secs % 86_400;
    let hour = tod / 3_600;
    let minute = (tod % 3_600) / 60;
    let second = tod % 60;
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    if month <= 2 {
        year += 1;
    }
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}
