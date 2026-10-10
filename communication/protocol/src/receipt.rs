use crate::{
    canonical::{self, Value},
    http::{array, bytes, counter, id32, number, positive_counter, uint, version, wire_length},
    types::{ReceiptBody, RelayPin},
    WireError, WireResult,
};

pub const MAX_BODY_LEN: usize = 256;
pub const RETENTION_RUN: u64 = 1;

fn validate(body: &ReceiptBody) -> WireResult<()> {
    wire_length(body.wire_length)?;
    positive_counter(body.sequence)?;
    if body.retention != RETENTION_RUN {
        return Err(WireError::Schema);
    }
    Ok(())
}

pub fn encode_body(body: &ReceiptBody) -> WireResult<Vec<u8>> {
    validate(body)?;
    canonical::encode(&Value::Array(vec![
        uint(1),
        bytes(&body.pin.key),
        bytes(&body.pin.run),
        bytes(&body.mailbox),
        bytes(&body.hash),
        uint(body.wire_length),
        uint(body.sequence),
        uint(body.retention),
    ]))
}

pub fn decode_body(encoded: &[u8]) -> WireResult<ReceiptBody> {
    let value = canonical::decode(encoded, MAX_BODY_LEN)?;
    let fields = array(&value, 8)?;
    version(&fields[0])?;
    let body = ReceiptBody {
        pin: RelayPin {
            key: id32(&fields[1])?,
            run: id32(&fields[2])?,
        },
        mailbox: id32(&fields[3])?,
        hash: id32(&fields[4])?,
        wire_length: number(&fields[5])?,
        sequence: counter(&fields[6])?,
        retention: number(&fields[7])?,
    };
    validate(&body)?;
    Ok(body)
}
