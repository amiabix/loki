use crate::{
    canonical::{self, Value},
    WireError, WireResult,
};
use sha2::{Digest, Sha256};

const MAX_BODY: usize = 16 * 1024 * 1024;

pub type Id32 = [u8; 32];
pub type MemberId = u16;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MemberPublic {
    pub id: MemberId,
    pub signing: Id32,
    pub encryption: Id32,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Roster {
    pub vault: Id32,
    pub members: Vec<MemberPublic>,
}
#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct MessageRef {
    pub sender: MemberId,
    pub message: Id32,
    pub digest: Id32,
}
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub struct LogicalKey {
    pub vault: Id32,
    pub roster: Id32,
    pub sender: MemberId,
    pub message: Id32,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Payload {
    Test(Vec<u8>),
    Received(MessageRef),
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MessageBody {
    pub key: LogicalKey,
    pub audience: Vec<MemberId>,
    pub session: Option<Id32>,
    pub prerequisites: Vec<MessageRef>,
    pub payload: Payload,
}
fn uint(n: u16) -> Value {
    Value::Integer(n.into())
}
fn bytes(n: &Id32) -> Value {
    Value::Bytes(n.to_vec())
}
fn reference_value(r: &MessageRef) -> Value {
    Value::Array(vec![uint(r.sender), bytes(&r.message), bytes(&r.digest)])
}
pub fn encode_roster(roster: &Roster) -> WireResult<Vec<u8>> {
    if !matches!(roster.members.len(), 3 | 4)
        || roster
            .members
            .iter()
            .enumerate()
            .any(|(index, member)| member.id != index as u16 + 1)
        || roster.members.iter().enumerate().any(|(index, member)| {
            roster.members[..index].iter().any(|prior| {
                prior.signing == member.signing || prior.encryption == member.encryption
            })
        })
    {
        return Err(WireError::Schema);
    }
    canonical::encode(&Value::Array(vec![
        uint(1),
        bytes(&roster.vault),
        Value::Array(
            roster
                .members
                .iter()
                .map(|m| Value::Array(vec![uint(m.id), bytes(&m.signing), bytes(&m.encryption)]))
                .collect(),
        ),
    ]))
}
pub fn roster_digest(roster: &Roster) -> WireResult<Id32> {
    Ok(Sha256::digest(encode_roster(roster)?).into())
}
pub fn encode_message(body: &MessageBody) -> WireResult<Vec<u8>> {
    if !matches!(body.audience.len(), 3 | 4)
        || body
            .audience
            .iter()
            .enumerate()
            .any(|(index, member)| *member != index as u16 + 1)
        || !body.audience.contains(&body.key.sender)
    {
        return Err(WireError::Schema);
    }
    if body
        .prerequisites
        .iter()
        .any(|r| !body.audience.contains(&r.sender))
    {
        return Err(WireError::Schema);
    }
    if body.prerequisites.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(WireError::Schema);
    }
    if body.prerequisites.len() > 64 {
        return Err(WireError::Bounds);
    }
    let (kind, payload) = match &body.payload {
        Payload::Test(data) => {
            if data.len() > MAX_BODY {
                return Err(WireError::Bounds);
            }
            (1, Value::Bytes(data.clone()))
        }
        Payload::Received(r) => {
            if body.prerequisites.as_slice() != std::slice::from_ref(r) {
                return Err(WireError::Schema);
            }
            (2, reference_value(r))
        }
    };
    let encoded = canonical::encode(&Value::Array(vec![
        uint(1),
        bytes(&body.key.message),
        bytes(&body.key.vault),
        bytes(&body.key.roster),
        uint(body.key.sender),
        Value::Array(body.audience.iter().map(|id| uint(*id)).collect()),
        uint(kind),
        body.session.as_ref().map(bytes).unwrap_or(Value::Null),
        Value::Array(body.prerequisites.iter().map(reference_value).collect()),
        Value::Array(vec![payload]),
    ]))?;
    if encoded.len() > MAX_BODY {
        return Err(WireError::Bounds);
    }
    Ok(encoded)
}

fn array(value: &Value) -> WireResult<&[Value]> {
    match value {
        Value::Array(items) => Ok(items),
        _ => Err(WireError::Schema),
    }
}
fn field(items: &[Value], index: usize) -> WireResult<&Value> {
    items.get(index).ok_or(WireError::Schema)
}
fn number(value: &Value) -> WireResult<u16> {
    match value {
        Value::Integer(n) => u16::try_from(*n).map_err(|_| WireError::Schema),
        _ => Err(WireError::Schema),
    }
}
fn byte_string(value: &Value) -> WireResult<&[u8]> {
    match value {
        Value::Bytes(data) => Ok(data),
        _ => Err(WireError::Schema),
    }
}
fn id32(value: &Value) -> WireResult<Id32> {
    byte_string(value)?
        .try_into()
        .map_err(|_| WireError::Schema)
}
fn parse_reference(value: &Value) -> WireResult<MessageRef> {
    let fields = array(value)?;
    if fields.len() != 3 {
        return Err(WireError::Schema);
    }
    Ok(MessageRef {
        sender: number(field(fields, 0)?)?,
        message: id32(field(fields, 1)?)?,
        digest: id32(field(fields, 2)?)?,
    })
}
pub fn decode_message(encoded: &[u8]) -> WireResult<MessageBody> {
    let value = canonical::decode(encoded, MAX_BODY)?;
    let fields = array(&value)?;
    if fields.len() != 10 {
        return Err(WireError::Schema);
    }
    if number(field(fields, 0)?)? != 1 {
        return Err(WireError::Version);
    }
    let key = LogicalKey {
        message: id32(field(fields, 1)?)?,
        vault: id32(field(fields, 2)?)?,
        roster: id32(field(fields, 3)?)?,
        sender: number(field(fields, 4)?)?,
    };
    let audience = array(field(fields, 5)?)?
        .iter()
        .map(number)
        .collect::<WireResult<Vec<_>>>()?;
    let session = match field(fields, 7)? {
        Value::Null => None,
        v => Some(id32(v)?),
    };
    let prerequisites = array(field(fields, 8)?)?
        .iter()
        .map(parse_reference)
        .collect::<WireResult<Vec<_>>>()?;
    let payload_fields = array(field(fields, 9)?)?;
    if payload_fields.len() != 1 {
        return Err(WireError::Schema);
    }
    let kind = number(field(fields, 6)?)?;
    if kind != 1 && kind != 2 {
        return Err(WireError::Schema);
    }
    let payload = if kind == 2 {
        Payload::Received(parse_reference(field(payload_fields, 0)?)?)
    } else {
        Payload::Test(byte_string(field(payload_fields, 0)?)?.to_vec())
    };
    let body = MessageBody {
        key,
        audience,
        session,
        prerequisites,
        payload,
    };
    if encode_message(&body)? != encoded {
        return Err(WireError::Canonical);
    }
    Ok(body)
}

pub fn decode_roster(encoded: &[u8]) -> WireResult<Roster> {
    let value = canonical::decode(encoded, MAX_BODY)?;
    let fields = array(&value)?;
    if fields.len() != 3 {
        return Err(WireError::Schema);
    }
    if number(field(fields, 0)?)? != 1 {
        return Err(WireError::Version);
    }
    let vault = id32(field(fields, 1)?)?;
    let members = array(field(fields, 2)?)?
        .iter()
        .map(|value| {
            let member = array(value)?;
            if member.len() != 3 {
                return Err(WireError::Schema);
            }
            Ok(MemberPublic {
                id: number(field(member, 0)?)?,
                signing: id32(field(member, 1)?)?,
                encryption: id32(field(member, 2)?)?,
            })
        })
        .collect::<WireResult<Vec<_>>>()?;
    let roster = Roster { vault, members };
    if encode_roster(&roster)? != encoded {
        return Err(WireError::Canonical);
    }
    Ok(roster)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayPin {
    pub key: Id32,
    pub run: Id32,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayRoute {
    pub pin: RelayPin,
    pub endpoint: String,
    pub mailbox: Id32,
    pub append_revision: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Object {
    pub hash: Id32,
    pub wire: Vec<u8>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Entry {
    pub sequence: u64,
    pub hash: Id32,
    pub wire_length: u64,
    pub receipt: Vec<u8>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Page {
    pub mailbox: Id32,
    pub after: u64,
    pub next: u64,
    pub high_water: u64,
    pub entries: Vec<Entry>,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptBody {
    pub pin: RelayPin,
    pub mailbox: Id32,
    pub hash: Id32,
    pub wire_length: u64,
    pub sequence: u64,
    pub retention: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Creation {
    pub read_verifier: Id32,
    pub append_verifier: Id32,
    pub admin_verifier: Id32,
    pub quota: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppendUpdate {
    pub revision: u64,
    pub verifier: Id32,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CreationResult {
    pub created: bool,
    pub run: Id32,
    pub quota: u64,
    pub append_revision: u64,
}
