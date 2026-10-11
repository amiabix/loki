//! A relay's durable, first-writer-wins claim on one FROST nonce commitment.
use crate::{
    canonical::{self, Value},
    types::{Id32, RelayPin},
    WireError, WireResult,
};

pub const SIGNATURE_DOMAIN: &[u8] = b"Loki_Relay_Nonce_v1\0";
pub const MAX_RECORD: usize = 65_536;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NonceReceipt {
    pub pin: RelayPin,
    pub mailbox: Id32,
    pub cid: Id32,
    pub record_hash: Id32,
    pub challenge: Id32,
    pub created: bool,
}

pub fn encode_body(receipt: &NonceReceipt) -> WireResult<Vec<u8>> {
    canonical::encode(&Value::Array(vec![
        Value::Integer(1.into()),
        Value::Bytes(receipt.pin.key.to_vec()),
        Value::Bytes(receipt.pin.run.to_vec()),
        Value::Bytes(receipt.mailbox.to_vec()),
        Value::Bytes(receipt.cid.to_vec()),
        Value::Bytes(receipt.record_hash.to_vec()),
        Value::Bytes(receipt.challenge.to_vec()),
        Value::Integer(u64::from(receipt.created).into()),
    ]))
}

pub fn decode_body(raw: &[u8]) -> WireResult<NonceReceipt> {
    let value = canonical::decode(raw, 256)?;
    let Value::Array(fields) = value else {
        return Err(WireError::Schema);
    };
    if fields.len() != 8 || fields[0] != Value::Integer(1.into()) {
        return Err(WireError::Schema);
    }
    let id = |index: usize| -> WireResult<Id32> {
        let Value::Bytes(bytes) = &fields[index] else {
            return Err(WireError::Schema);
        };
        bytes.as_slice().try_into().map_err(|_| WireError::Schema)
    };
    let created = match fields[7] {
        Value::Integer(n) if n == 0.into() => false,
        Value::Integer(n) if n == 1.into() => true,
        _ => return Err(WireError::Schema),
    };
    Ok(NonceReceipt {
        pin: RelayPin {
            key: id(1)?,
            run: id(2)?,
        },
        mailbox: id(3)?,
        cid: id(4)?,
        record_hash: id(5)?,
        challenge: id(6)?,
        created,
    })
}

pub fn signature_input(body: &[u8]) -> WireResult<Vec<u8>> {
    let length = u32::try_from(body.len()).map_err(|_| WireError::Bounds)?;
    let mut input = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 4 + body.len());
    input.extend_from_slice(SIGNATURE_DOMAIN);
    input.extend_from_slice(&length.to_be_bytes());
    input.extend_from_slice(body);
    Ok(input)
}
