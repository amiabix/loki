use crate::{
    canonical::{self, Value},
    types::{Id32, MemberId},
    WireError, WireResult,
};

pub const MAX_PAYLOAD: usize = 1024 * 1024;
pub const MAX_RECORD: usize = MAX_PAYLOAD + 4096;
pub const MAX_PACKAGE: usize = MAX_RECORD + 128;
pub const RECORD_DOMAIN: &[u8] = b"Loki_Setup_Record_v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[repr(u8)]
pub enum SetupPhase {
    Join = 1,
    RosterProposal = 2,
    RosterAccept = 3,
    Round1 = 4,
    Round2 = 5,
    Certificate = 6,
    BackupReceipt = 7,
    PaymentDescriptor = 8,
    Activation = 9,
    Abort = 10,
}
impl TryFrom<u64> for SetupPhase {
    type Error = WireError;
    fn try_from(value: u64) -> WireResult<Self> {
        Ok(match value {
            1 => Self::Join,
            2 => Self::RosterProposal,
            3 => Self::RosterAccept,
            4 => Self::Round1,
            5 => Self::Round2,
            6 => Self::Certificate,
            7 => Self::BackupReceipt,
            8 => Self::PaymentDescriptor,
            9 => Self::Activation,
            10 => Self::Abort,
            _ => return Err(WireError::Schema),
        })
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SetupKey {
    pub ceremony: Id32,
    pub phase: SetupPhase,
    pub author: MemberId,
    pub recipient: MemberId,
    pub revision: u64,
}
#[derive(Clone, Eq, PartialEq)]
pub struct SetupRecord {
    pub version: u16,
    pub key: SetupKey,
    pub network: String,
    pub threshold: u16,
    pub member_count: u16,
    pub roster_digest: Option<Id32>,
    pub prerequisites: Vec<Id32>,
    pub payload: Vec<u8>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupCapabilities {
    pub versions: Vec<u16>,
    pub member_counts: Vec<u16>,
}
impl SetupCapabilities {
    pub fn current() -> Self {
        Self {
            versions: vec![1],
            member_counts: vec![3, 4],
        }
    }
    pub fn supports(&self, version: u16, count: u16) -> bool {
        version == 1
            && matches!(count, 3 | 4)
            && self.versions.contains(&version)
            && self.member_counts.contains(&count)
    }
    pub fn require(&self, version: u16, count: u16) -> WireResult<()> {
        if self.supports(version, count) {
            Ok(())
        } else {
            Err(WireError::Version)
        }
    }
}
fn uint(n: impl Into<u64>) -> Value {
    Value::Integer(n.into().into())
}
fn bytes(n: &Id32) -> Value {
    Value::Bytes(n.to_vec())
}
pub fn encode_record(record: &SetupRecord) -> WireResult<Vec<u8>> {
    if record.version != 1 {
        return Err(WireError::Version);
    }
    if !matches!((record.threshold, record.member_count), (2, 3) | (2, 4) | (3, 4))
        || !(1..=record.member_count).contains(&record.key.author)
        || !(1..=record.member_count).contains(&record.key.recipient)
        || record.key.revision == 0
        || record.key.revision > i64::MAX as u64
        || record.network.is_empty()
        || record.network.len() > 32
        || record.network.chars().any(char::is_control)
        || record.key.ceremony == [0; 32]
        || record.prerequisites.windows(2).any(|p| p[0] >= p[1])
        || (record.key.phase == SetupPhase::Join && record.roster_digest.is_some())
        || (!matches!(record.key.phase, SetupPhase::Join | SetupPhase::Abort)
            && record.roster_digest.is_none())
    {
        return Err(WireError::Schema);
    }
    if record.payload.len() > MAX_PAYLOAD || record.prerequisites.len() > 64 {
        return Err(WireError::Bounds);
    }
    canonical::encode(&Value::Array(vec![
        uint(record.version),
        bytes(&record.key.ceremony),
        Value::Text(record.network.clone()),
        uint(record.threshold),
        uint(record.member_count),
        uint(record.key.phase as u8),
        uint(record.key.author),
        uint(record.key.recipient),
        uint(record.key.revision),
        record
            .roster_digest
            .as_ref()
            .map(bytes)
            .unwrap_or(Value::Null),
        Value::Array(record.prerequisites.iter().map(bytes).collect()),
        Value::Bytes(record.payload.clone()),
    ]))
}
pub fn decode_record(encoded: &[u8]) -> WireResult<SetupRecord> {
    let value = canonical::decode(encoded, MAX_RECORD)?;
    let Value::Array(f) = value else {
        return Err(WireError::Schema);
    };
    if f.len() != 12 {
        return Err(WireError::Schema);
    }
    fn n(v: &Value) -> WireResult<u64> {
        match v {
            Value::Integer(n) => u64::try_from(*n).map_err(|_| WireError::Schema),
            _ => Err(WireError::Schema),
        }
    }
    fn small(v: &Value) -> WireResult<u16> {
        u16::try_from(n(v)?).map_err(|_| WireError::Schema)
    }
    fn id(v: &Value) -> WireResult<Id32> {
        match v {
            Value::Bytes(b) => b.as_slice().try_into().map_err(|_| WireError::Schema),
            _ => Err(WireError::Schema),
        }
    }
    let Value::Text(network) = &f[2] else {
        return Err(WireError::Schema);
    };
    let Value::Array(preds) = &f[10] else {
        return Err(WireError::Schema);
    };
    let Value::Bytes(payload) = &f[11] else {
        return Err(WireError::Schema);
    };
    let record = SetupRecord {
        version: small(&f[0])?,
        key: SetupKey {
            ceremony: id(&f[1])?,
            phase: SetupPhase::try_from(n(&f[5])?)?,
            author: small(&f[6])?,
            recipient: small(&f[7])?,
            revision: n(&f[8])?,
        },
        network: network.clone(),
        threshold: small(&f[3])?,
        member_count: small(&f[4])?,
        roster_digest: if f[9] == Value::Null {
            None
        } else {
            Some(id(&f[9])?)
        },
        prerequisites: preds.iter().map(id).collect::<WireResult<_>>()?,
        payload: payload.clone(),
    };
    encode_record(&record)?;
    Ok(record)
}
