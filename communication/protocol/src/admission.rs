use crate::{
    canonical::{self, Value},
    http,
    setup::{self, SetupKey, SetupPhase, SetupRecord},
    types::{Id32, MemberPublic},
    WireError, WireResult,
};
pub const MAX_REQUEST: usize = 32768;
pub const MAX_RESPONSE: usize = 131072;
pub const REQUEST_DOMAIN: &[u8] = b"Loki_Setup_Admission_Request_v1\0";
pub const RESPONSE_DOMAIN: &[u8] = b"Loki_Setup_Admission_Response_v1\0";
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AdmissionCommand {
    Create {
        ceremony: Id32,
        network: String,
        threshold: u16,
        member_count: u16,
        config_digest: Id32,
        grant_digest: Id32,
        invite_hashes: Vec<Id32>,
    },
    Claim {
        ceremony: Id32,
        slot: u16,
        invite_hash: Id32,
    },
    Mailbox {
        ceremony: Id32,
        slot: u16,
        relay: u16,
        purpose: u16,
        mailbox: Id32,
        creation: Vec<u8>,
    },
    Checkpoint {
        ceremony: Id32,
        slot: u16,
        generation: u64,
        predecessor: Id32,
        checkpoint: Id32,
    },
    Terminal {
        ceremony: Id32,
        kind: u16,
    },
    State {
        ceremony: Id32,
        slot: u16,
    },
    TerminalNotice {
        ceremony: Id32,
        kind: u16,
    },
}
impl AdmissionCommand {
    pub fn ceremony(&self) -> &Id32 {
        match self {
            Self::Create { ceremony, .. }
            | Self::Claim { ceremony, .. }
            | Self::Mailbox { ceremony, .. }
            | Self::Checkpoint { ceremony, .. }
            | Self::Terminal { ceremony, .. }
            | Self::State { ceremony, .. }
            | Self::TerminalNotice { ceremony, .. } => ceremony,
        }
    }
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionRequest {
    pub operation: Id32,
    pub device: MemberPublic,
    pub command: AdmissionCommand,
}
fn n(value: impl Into<u64>) -> Value {
    Value::Integer(value.into().into())
}
fn b(id: &Id32) -> Value {
    Value::Bytes(id.to_vec())
}
fn fields(value: &Value, count: usize) -> WireResult<&[Value]> {
    match value {
        Value::Array(f) if f.len() == count => Ok(f),
        _ => Err(WireError::Schema),
    }
}
fn number(value: &Value) -> WireResult<u64> {
    match value {
        Value::Integer(n) => u64::try_from(*n).map_err(|_| WireError::Schema),
        _ => Err(WireError::Schema),
    }
}
fn small(value: &Value) -> WireResult<u16> {
    u16::try_from(number(value)?).map_err(|_| WireError::Schema)
}
fn binary(value: &Value) -> WireResult<&[u8]> {
    match value {
        Value::Bytes(b) => Ok(b),
        _ => Err(WireError::Schema),
    }
}
fn id(value: &Value) -> WireResult<Id32> {
    binary(value)?.try_into().map_err(|_| WireError::Schema)
}
fn positive(value: u64) -> WireResult<()> {
    if value == 0 || value > i64::MAX as u64 {
        Err(WireError::Bounds)
    } else {
        Ok(())
    }
}
pub fn encode_request(request: &AdmissionRequest) -> WireResult<Vec<u8>> {
    if request.operation == [0; 32]
        || request.command.ceremony() == &[0; 32]
        || !(1..=4).contains(&request.device.id)
    {
        return Err(WireError::Schema);
    }
    let command = match &request.command {
        AdmissionCommand::Create {
            ceremony,
            network,
            threshold,
            member_count,
            config_digest,
            grant_digest,
            invite_hashes,
        } => {
            setup::encode_record(&SetupRecord {
                version: setup::SETUP_VERSION,
                key: SetupKey {
                    ceremony: *ceremony,
                    phase: SetupPhase::Join,
                    author: 1,
                    recipient: 1,
                    revision: 1,
                },
                network: network.clone(),
                threshold: *threshold,
                member_count: *member_count,
                roster_digest: None,
                prerequisites: vec![],
                payload: vec![],
            })?;
            if request.device.id != 1
                || invite_hashes.len() != *member_count as usize - 1
                || invite_hashes
                    .iter()
                    .enumerate()
                    .any(|(i, h)| *h == [0; 32] || invite_hashes[..i].contains(h))
            {
                return Err(WireError::Schema);
            }
            vec![
                n(1u16),
                b(ceremony),
                Value::Text(network.clone()),
                n(*threshold),
                n(*member_count),
                b(config_digest),
                b(grant_digest),
                Value::Array(invite_hashes.iter().map(b).collect()),
            ]
        }
        AdmissionCommand::Claim {
            ceremony,
            slot,
            invite_hash,
        } => {
            if !(2..=4).contains(slot) || *slot != request.device.id || *invite_hash == [0; 32] {
                return Err(WireError::Schema);
            }
            vec![n(2u16), b(ceremony), n(*slot), b(invite_hash)]
        }
        AdmissionCommand::Mailbox {
            ceremony,
            slot,
            relay,
            purpose,
            mailbox,
            creation,
        } => {
            if *slot != request.device.id
                || !(1..=3).contains(relay)
                || !matches!(purpose, 1 | 2)
                || *mailbox == [0; 32]
            {
                return Err(WireError::Schema);
            }
            let c = http::decode_creation(creation)?;
            positive(c.quota)?;
            if c.quota > 67108864
                || c.read_verifier == [0; 32]
                || c.append_verifier == [0; 32]
                || c.admin_verifier == [0; 32]
            {
                return Err(WireError::Bounds);
            }
            vec![
                n(3u16),
                b(ceremony),
                n(*slot),
                n(*relay),
                n(*purpose),
                b(mailbox),
                Value::Bytes(creation.clone()),
            ]
        }
        AdmissionCommand::Checkpoint {
            ceremony,
            slot,
            generation,
            predecessor,
            checkpoint,
        } => {
            positive(*generation)?;
            if *slot != request.device.id
                || *checkpoint == [0; 32]
                || (*generation == 1 && *predecessor != [0; 32])
                || (*generation > 1 && *predecessor == [0; 32])
            {
                return Err(WireError::Schema);
            }
            vec![
                n(4u16),
                b(ceremony),
                n(*slot),
                n(*generation),
                b(predecessor),
                b(checkpoint),
            ]
        }
        AdmissionCommand::Terminal { ceremony, kind } => {
            if !matches!(kind, 1 | 2) {
                return Err(WireError::Schema);
            }
            vec![n(5u16), b(ceremony), n(*kind)]
        }
        AdmissionCommand::TerminalNotice { ceremony, kind } => {
            if *kind > 4 {
                return Err(WireError::Schema);
            }
            vec![n(7u16), b(ceremony), n(*kind)]
        }
        AdmissionCommand::State { ceremony, slot } => {
            if *slot != request.device.id {
                return Err(WireError::Schema);
            }
            vec![n(6u16), b(ceremony), n(*slot)]
        }
    };
    let encoded = canonical::encode(&Value::Array(vec![
        n(1u16),
        b(&request.operation),
        Value::Array(vec![
            n(request.device.id),
            b(&request.device.signing),
            b(&request.device.encryption),
        ]),
        Value::Array(command),
    ]))?;
    if encoded.len() > MAX_REQUEST - 128 {
        return Err(WireError::Bounds);
    }
    Ok(encoded)
}
pub fn decode_request(bytes: &[u8]) -> WireResult<AdmissionRequest> {
    let value = canonical::decode(bytes, MAX_REQUEST - 128)?;
    let f = fields(&value, 4)?;
    if number(&f[0])? != 1 {
        return Err(WireError::Version);
    }
    let d = fields(&f[2], 3)?;
    let Value::Array(c) = &f[3] else {
        return Err(WireError::Schema);
    };
    let tag = c.first().ok_or(WireError::Schema)?;
    let command = match number(tag)? {
        1 => {
            let c = fields(&f[3], 8)?;
            let Value::Text(network) = &c[2] else {
                return Err(WireError::Schema);
            };
            let Value::Array(hashes) = &c[7] else {
                return Err(WireError::Schema);
            };
            AdmissionCommand::Create {
                ceremony: id(&c[1])?,
                network: network.clone(),
                threshold: small(&c[3])?,
                member_count: small(&c[4])?,
                config_digest: id(&c[5])?,
                grant_digest: id(&c[6])?,
                invite_hashes: hashes.iter().map(id).collect::<WireResult<_>>()?,
            }
        }
        2 => {
            let c = fields(&f[3], 4)?;
            AdmissionCommand::Claim {
                ceremony: id(&c[1])?,
                slot: small(&c[2])?,
                invite_hash: id(&c[3])?,
            }
        }
        3 => {
            let c = fields(&f[3], 7)?;
            AdmissionCommand::Mailbox {
                ceremony: id(&c[1])?,
                slot: small(&c[2])?,
                relay: small(&c[3])?,
                purpose: small(&c[4])?,
                mailbox: id(&c[5])?,
                creation: binary(&c[6])?.to_vec(),
            }
        }
        4 => {
            let c = fields(&f[3], 6)?;
            AdmissionCommand::Checkpoint {
                ceremony: id(&c[1])?,
                slot: small(&c[2])?,
                generation: number(&c[3])?,
                predecessor: id(&c[4])?,
                checkpoint: id(&c[5])?,
            }
        }
        5 => {
            let c = fields(&f[3], 3)?;
            AdmissionCommand::Terminal {
                ceremony: id(&c[1])?,
                kind: small(&c[2])?,
            }
        }
        7 => {
            let c = fields(&f[3], 3)?;
            AdmissionCommand::TerminalNotice {
                ceremony: id(&c[1])?,
                kind: small(&c[2])?,
            }
        }
        6 => {
            let c = fields(&f[3], 3)?;
            AdmissionCommand::State {
                ceremony: id(&c[1])?,
                slot: small(&c[2])?,
            }
        }
        _ => return Err(WireError::Schema),
    };
    let request = AdmissionRequest {
        operation: id(&f[1])?,
        device: MemberPublic {
            id: small(&d[0])?,
            signing: id(&d[1])?,
            encryption: id(&d[2])?,
        },
        command,
    };
    encode_request(&request)?;
    Ok(request)
}
pub fn signature_input(domain: &[u8], body: &[u8]) -> WireResult<Vec<u8>> {
    let size = u32::try_from(body.len()).map_err(|_| WireError::Bounds)?;
    let mut input = domain.to_vec();
    input.extend_from_slice(&size.to_be_bytes());
    input.extend_from_slice(body);
    Ok(input)
}

pub fn request_target(command: &AdmissionCommand) -> (&'static str, String) {
    let mut ceremony = String::with_capacity(64);
    for byte in command.ceremony() {
        use std::fmt::Write;
        let _ = write!(ceremony, "{byte:02x}");
    }
    match command {
        AdmissionCommand::Create { .. } => ("POST", "/v1/setup".into()),
        AdmissionCommand::Claim { slot, .. } => {
            ("POST", format!("/v1/setup/{ceremony}/claims/{slot}"))
        }
        AdmissionCommand::Mailbox { .. } => ("POST", format!("/v1/setup/{ceremony}/mailboxes")),
        AdmissionCommand::Checkpoint { slot, .. } => {
            ("POST", format!("/v1/setup/{ceremony}/checkpoints/{slot}"))
        }
        AdmissionCommand::Terminal { .. } => ("POST", format!("/v1/setup/{ceremony}/terminal")),
        AdmissionCommand::State { .. } => ("GET", format!("/v1/setup/{ceremony}")),
        AdmissionCommand::TerminalNotice { kind, .. } => (
            if *kind == 0 { "GET" } else { "POST" },
            format!("/v1/setup/{ceremony}/terminal-notices"),
        ),
    }
}
