//! Bounded public snapshot pages. The spool stores metadata, never decrypted bodies.

use super::{routed, Session, SessionError};
use loki_relay_client::ClientError;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

const PAGE_LIMIT: usize = 128 * 1024;
const SPOOL_LIMIT: usize = 1024 * 1024;
const SECTIONS: &[&str] = &[
    "logical",
    "recipients",
    "objects",
    "receipts",
    "incoming",
    "acknowledgements",
    "rejections",
    "application",
];

pub fn snapshot_response(session: &Session, request: &str) -> Result<String, SessionError> {
    let value: Value = serde_json::from_str(request).map_err(|_| config())?;
    let Value::Object(fields) = &value else {
        return Err(config());
    };
    if fields.len() != 6
        || fields.get("version") != Some(&Value::from(1))
        || fields.get("type") != Some(&Value::String("snapshot_page".into()))
    {
        return Err(config());
    }
    let snapshot_id = text(fields, "snapshot_id")?;
    let section = text(fields, "section")?;
    let after = text(fields, "after")?;
    let limit = match fields.get("limit") {
        Some(Value::Number(number)) => number.as_u64().and_then(|value| u16::try_from(value).ok()),
        _ => None,
    }
    .ok_or_else(config)?;
    let page = public_snapshot_page(session, snapshot_id, section, after, limit)?;
    let encoded = serde_json::to_string(&page).map_err(|_| config())?;
    if encoded.len() > PAGE_LIMIT {
        return Err(SessionError::Client(ClientError::Capacity));
    }
    Ok(encoded)
}

pub fn public_snapshot_page(
    session: &Session,
    snapshot_id: &str,
    section: &str,
    after: &str,
    limit: u16,
) -> Result<Value, SessionError> {
    if !token(snapshot_id) || !SECTIONS.contains(&section) || !(1..=100).contains(&limit) {
        return Err(config());
    }
    let index = parse_cursor(after)?;
    let path = session
        .configs
        .directory()
        .join("transport")
        .join("public-snapshot.json");
    let mut spool = load_spool(session, &path, snapshot_id, index == 0)?;
    let rows = spool.sections.get(section).cloned().ok_or_else(config)?;
    {
        let issued = spool
            .issued
            .entry(section.to_string())
            .or_insert_with(|| vec!["0".into()]);
        if !issued.iter().any(|cursor| cursor == after) {
            return Err(SessionError::Client(ClientError::Cursor));
        }
    }
    let start = usize::try_from(index).map_err(|_| SessionError::Client(ClientError::Cursor))?;
    if start > rows.len() {
        return Err(SessionError::Client(ClientError::Cursor));
    }
    let end = start.saturating_add(usize::from(limit)).min(rows.len());
    let next = end.to_string();
    if !spool
        .issued
        .get(section)
        .unwrap()
        .iter()
        .any(|cursor| cursor == &next)
    {
        spool.issued.get_mut(section).unwrap().push(next.clone());
        store_spool(&path, &spool)?;
    }
    let page = serde_json::json!({
        "version": 1,
        "snapshot_id": snapshot_id,
        "member": session.member.identity.public().id,
        "owner": session.member.identity.public().id,
        "section": section,
        "after": after,
        "next": next,
        "complete": end == rows.len(),
        "run_id": spool.run_id,
        "config_revision": spool.config_revision,
        "gap_count": spool.gap_count,
        "rows": &rows[start..end],
    });
    let encoded = serde_json::to_vec(&page).map_err(|_| config())?;
    if encoded.len() > PAGE_LIMIT {
        return Err(SessionError::Client(ClientError::Capacity));
    }
    Ok(page)
}

struct Spool {
    snapshot_id: String,
    created: u64,
    run_id: Value,
    config_revision: Value,
    gap_count: u64,
    sections: BTreeMap<String, Vec<Value>>,
    issued: BTreeMap<String, Vec<String>>,
}

fn load_spool(
    session: &Session,
    path: &Path,
    snapshot_id: &str,
    begin: bool,
) -> Result<Spool, SessionError> {
    if path.is_file() {
        let raw = fs::read(path).map_err(|_| SessionError::Client(ClientError::Storage))?;
        if raw.len() > SPOOL_LIMIT {
            return Err(SessionError::Client(ClientError::Capacity));
        }
        let value: Value =
            serde_json::from_slice(&raw).map_err(|_| SessionError::Client(ClientError::Storage))?;
        let spool = decode_spool(&value)?;
        if spool.snapshot_id == snapshot_id {
            if unix_now().saturating_sub(spool.created) > 60 {
                let _ = fs::remove_file(path);
                return Err(SessionError::Client(ClientError::Cursor));
            }
            return Ok(spool);
        }
        if !begin {
            return Err(SessionError::Client(ClientError::Conflict));
        }
    }
    let spool = freeze(session, snapshot_id)?;
    store_spool(path, &spool)?;
    Ok(spool)
}

fn freeze(session: &Session, snapshot_id: &str) -> Result<Spool, SessionError> {
    let mut sections = BTreeMap::new();
    for section in SECTIONS {
        sections.insert((*section).to_string(), Vec::new());
    }
    let mut after = 0u64;
    loop {
        let page = session
            .db
            .recover_logical(after, 100)
            .map_err(SessionError::Client)?;
        if page.is_empty() {
            break;
        }
        let next = page.last().map(|row| row.cursor).unwrap_or(after);
        for logical in &page {
            sections
                .get_mut("logical")
                .unwrap()
                .push(serde_json::json!({
                    "message_id": hex::encode(logical.key.message),
                    "authenticated_sender": logical.key.sender,
                    "message_digest": hex::encode(logical.digest),
                    "kind": logical.kind,
                    "object_hash": hex::encode(logical.source_root),
                }));
            let recipients = session
                .db
                .recover_recipients(&logical.key)
                .map_err(SessionError::Client)?;
            for recipient in &recipients {
                sections
                    .get_mut("recipients")
                    .unwrap()
                    .push(serde_json::json!({
                        "message_id": hex::encode(logical.key.message),
                        "recipient_member": recipient.recipient,
                        "object_hash": hex::encode(recipient.root_hash),
                    }));
                let mut hash_after = None;
                loop {
                    let requirements = session
                        .db
                        .recover_requirements(
                            &logical.key,
                            recipient.recipient,
                            hash_after.as_ref(),
                            100,
                        )
                        .map_err(SessionError::Client)?;
                    if requirements.is_empty() {
                        break;
                    }
                    let last = requirements.last().unwrap().clone();
                    for requirement in &requirements {
                        sections
                            .get_mut("objects")
                            .unwrap()
                            .push(serde_json::json!({
                                "message_id": hex::encode(logical.key.message),
                                "recipient_member": recipient.recipient,
                                "object_hash": hex::encode(requirement.hash),
                                "object_ordinal": requirement.ordinal,
                                "wire_bytes": requirement.length,
                            }));
                    }
                    if requirements.len() < 100 {
                        break;
                    }
                    hash_after = Some(last.hash);
                }
            }
            sections
                .get_mut("application")
                .unwrap()
                .push(serde_json::json!({
                    "message_id": hex::encode(logical.key.message),
                    "message_digest": hex::encode(logical.digest),
                    "result_code": "saved",
                }));
        }
        if page.len() < 100 || next <= after {
            break;
        }
        after = next;
    }
    let mut upload_after = 0u64;
    loop {
        let page = session
            .db
            .recover_uploads(upload_after, 100)
            .map_err(SessionError::Client)?;
        if page.is_empty() {
            break;
        }
        let next = page.last().map(|row| row.cursor).unwrap_or(upload_after);
        for upload in &page {
            if !upload.acknowledged {
                continue;
            }
            sections
                .get_mut("receipts")
                .unwrap()
                .push(serde_json::json!({
                    "message_id": hex::encode(upload.key.message),
                    "authenticated_sender": upload.key.sender,
                    "recipient_member": upload.recipient,
                    "object_hash": hex::encode(upload.hash),
                    "relay_pin": hex::encode(upload.relay_key),
                    "relay_run": hex::encode(upload.run),
                    "mailbox_id": hex::encode(upload.mailbox),
                }));
        }
        if page.len() < 100 || next <= upload_after {
            break;
        }
        upload_after = next;
    }
    page_simple(session, &mut sections)?;
    let (run_id, config_revision) = identity(session)?;
    let gap_count = read_gap(session);
    let issued = SECTIONS
        .iter()
        .map(|section| ((*section).to_string(), vec!["0".to_string()]))
        .collect();
    Ok(Spool {
        snapshot_id: snapshot_id.to_string(),
        created: unix_now(),
        run_id,
        config_revision,
        gap_count,
        sections,
        issued,
    })
}

fn page_simple(
    session: &Session,
    sections: &mut BTreeMap<String, Vec<Value>>,
) -> Result<(), SessionError> {
    let mut after = 0u64;
    loop {
        let page = session
            .db
            .recover_incoming_originals(after, 100)
            .map_err(SessionError::Client)?;
        if page.is_empty() {
            break;
        }
        let next = page.last().map(|row| row.cursor).unwrap_or(after);
        for original in &page {
            sections
                .get_mut("incoming")
                .unwrap()
                .push(serde_json::json!({
                    "message_id": hex::encode(original.key.message),
                    "authenticated_sender": original.key.sender,
                    "message_digest": hex::encode(original.digest),
                    "kind": original.kind,
                    "object_hash": hex::encode(original.source_root),
                }));
        }
        if page.len() < 100 || next <= after {
            break;
        }
        after = next;
    }
    after = 0;
    loop {
        let page = session
            .db
            .recover_ack_links(after, 100)
            .map_err(SessionError::Client)?;
        if page.is_empty() {
            break;
        }
        let next = page.last().map(|row| row.cursor).unwrap_or(after);
        for link in &page {
            sections
                .get_mut("acknowledgements")
                .unwrap()
                .push(serde_json::json!({
                    "message_id": hex::encode(link.key.message),
                    "authenticated_sender": link.key.sender,
                    "message_digest": hex::encode(link.digest),
                    "recipient_member": link.ack_author,
                    "ack_message": hex::encode(link.ack_message),
                }));
        }
        if page.len() < 100 || next <= after {
            break;
        }
        after = next;
    }
    after = 0;
    loop {
        let page = session
            .db
            .recover_source_rejections(after, 100)
            .map_err(SessionError::Client)?;
        if page.is_empty() {
            break;
        }
        let next = page.last().map(|row| row.cursor).unwrap_or(after);
        for rejection in &page {
            sections
                .get_mut("rejections")
                .unwrap()
                .push(serde_json::json!({
                    "object_hash": hex::encode(rejection.root_hash),
                    "result_code": rejection.reason,
                }));
        }
        if page.len() < 100 || next <= after {
            break;
        }
        after = next;
    }
    Ok(())
}

fn identity(session: &Session) -> Result<(Value, Value), SessionError> {
    let revision = session
        .db
        .config_reference()
        .map_err(SessionError::Client)?
        .map(|reference| Value::from(reference.revision()))
        .unwrap_or(Value::Null);
    let run = match routed(session) {
        Ok((config, _)) => config
            .own
            .first()
            .map(|inbox| Value::String(hex::encode(inbox.route.pin.run)))
            .unwrap_or(Value::Null),
        Err(_) => Value::Null,
    };
    Ok((run, revision))
}

fn read_gap(session: &Session) -> u64 {
    let path = session
        .configs
        .directory()
        .join("transport")
        .join("observation-gap");
    let Ok(text) = fs::read_to_string(path) else {
        return 0;
    };
    text.trim().parse().unwrap_or(0)
}

fn store_spool(path: &Path, spool: &Spool) -> Result<(), SessionError> {
    let mut sections = BTreeMap::new();
    for (name, rows) in &spool.sections {
        sections.insert(name.clone(), Value::Array(rows.clone()));
    }
    let mut issued = BTreeMap::new();
    for (name, cursors) in &spool.issued {
        issued.insert(
            name.clone(),
            Value::Array(cursors.iter().cloned().map(Value::String).collect()),
        );
    }
    let value = serde_json::json!({
        "version": 1,
        "snapshot_id": spool.snapshot_id,
        "created": spool.created,
        "run_id": spool.run_id,
        "config_revision": spool.config_revision,
        "gap_count": spool.gap_count,
        "sections": sections,
        "issued": issued,
    });
    let encoded =
        serde_json::to_vec(&value).map_err(|_| SessionError::Client(ClientError::Storage))?;
    if encoded.len() > SPOOL_LIMIT {
        return Err(SessionError::Client(ClientError::Capacity));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|_| SessionError::Client(ClientError::Storage))?;
    }
    let temporary = path.with_extension("json.tmp");
    {
        let mut file =
            fs::File::create(&temporary).map_err(|_| SessionError::Client(ClientError::Storage))?;
        file.write_all(&encoded)
            .map_err(|_| SessionError::Client(ClientError::Storage))?;
        file.sync_all()
            .map_err(|_| SessionError::Client(ClientError::Storage))?;
    }
    fs::rename(&temporary, path).map_err(|_| SessionError::Client(ClientError::Storage))?;
    Ok(())
}

fn decode_spool(value: &Value) -> Result<Spool, SessionError> {
    let fields = value.as_object().ok_or_else(config)?;
    if fields.get("version") != Some(&Value::from(1)) {
        return Err(config());
    }
    let snapshot_id = fields
        .get("snapshot_id")
        .and_then(Value::as_str)
        .ok_or_else(config)?
        .to_string();
    let created = fields
        .get("created")
        .and_then(Value::as_u64)
        .ok_or_else(config)?;
    let mut sections = BTreeMap::new();
    let stored = fields
        .get("sections")
        .and_then(Value::as_object)
        .ok_or_else(config)?;
    for section in SECTIONS {
        let rows = stored
            .get(*section)
            .and_then(Value::as_array)
            .ok_or_else(config)?
            .clone();
        sections.insert((*section).to_string(), rows);
    }
    let mut issued = BTreeMap::new();
    let stored_issued = fields
        .get("issued")
        .and_then(Value::as_object)
        .ok_or_else(config)?;
    for section in SECTIONS {
        let cursors = stored_issued
            .get(*section)
            .and_then(Value::as_array)
            .ok_or_else(config)?
            .iter()
            .map(|value| value.as_str().map(str::to_string))
            .collect::<Option<Vec<_>>>()
            .ok_or_else(config)?;
        issued.insert((*section).to_string(), cursors);
    }
    Ok(Spool {
        snapshot_id,
        created,
        run_id: fields.get("run_id").cloned().unwrap_or(Value::Null),
        config_revision: fields
            .get("config_revision")
            .cloned()
            .unwrap_or(Value::Null),
        gap_count: fields.get("gap_count").and_then(Value::as_u64).unwrap_or(0),
        sections,
        issued,
    })
}

fn text<'a>(
    fields: &'a serde_json::Map<String, Value>,
    name: &str,
) -> Result<&'a str, SessionError> {
    fields.get(name).and_then(Value::as_str).ok_or_else(config)
}

fn parse_cursor(after: &str) -> Result<u64, SessionError> {
    if after.is_empty() || after.len() > 20 || !after.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(SessionError::Client(ClientError::Cursor));
    }
    after
        .parse()
        .map_err(|_| SessionError::Client(ClientError::Cursor))
}

fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
}

fn config() -> SessionError {
    SessionError::Client(ClientError::Config)
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
