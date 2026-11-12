use crate::{WireError, WireResult};
pub use ciborium::value::Value;
use ciborium_ll::{Decoder, Header};

const MAX_ENCODED: usize = 16 * 1024 * 1024 + 128;
const MAX_DEPTH: usize = 16;
const MAX_ARRAY: usize = 274;

fn header_len(n: u64) -> usize {
    match n {
        0..=23 => 1,
        24..=255 => 2,
        256..=65535 => 3,
        65536..=4294967295 => 5,
        _ => 9,
    }
}

fn add_size(total: usize, extra: usize) -> WireResult<usize> {
    total
        .checked_add(extra)
        .filter(|n| *n <= MAX_ENCODED)
        .ok_or(WireError::Bounds)
}

fn encoded_len(value: &Value, depth: usize) -> WireResult<usize> {
    if depth > MAX_DEPTH {
        return Err(WireError::Bounds);
    }
    match value {
        Value::Integer(n) => {
            let n = u64::try_from(*n).map_err(|_| WireError::Schema)?;
            Ok(header_len(n))
        }
        Value::Bytes(bytes) => add_size(header_len(bytes.len() as u64), bytes.len()),
        Value::Text(text) => add_size(header_len(text.len() as u64), text.len()),
        Value::Array(items) => {
            if items.len() > MAX_ARRAY {
                return Err(WireError::Bounds);
            }
            let mut size = header_len(items.len() as u64);
            for item in items {
                size = add_size(size, encoded_len(item, depth + 1)?)?;
            }
            Ok(size)
        }
        Value::Null => Ok(1),
        _ => Err(WireError::Schema),
    }
}

pub fn encode(value: &Value) -> WireResult<Vec<u8>> {
    let size = encoded_len(value, 1)?;
    let mut bytes = Vec::with_capacity(size);
    ciborium::ser::into_writer(value, &mut bytes)?;
    Ok(bytes)
}

fn screen(input: &mut &[u8], depth: usize) -> WireResult<()> {
    if depth > MAX_DEPTH {
        return Err(WireError::Bounds);
    }
    let mut decoder = Decoder::from(*input);
    let header = decoder.pull().map_err(|_| WireError::Canonical)?;
    let consumed = decoder.offset();
    *input = &input[consumed..];
    let argument = match header {
        Header::Positive(n) => n,
        Header::Bytes(Some(n)) | Header::Text(Some(n)) | Header::Array(Some(n)) => n as u64,
        Header::Simple(22) => 22,
        _ => return Err(WireError::Schema),
    };
    if consumed != header_len(argument) {
        return Err(WireError::Canonical);
    }
    match header {
        Header::Bytes(Some(n)) => {
            if n > input.len() {
                return Err(WireError::Bounds);
            }
            *input = &input[n..];
        }
        Header::Text(Some(n)) => {
            let bytes = input.get(..n).ok_or(WireError::Bounds)?;
            std::str::from_utf8(bytes).map_err(|_| WireError::Schema)?;
            *input = &input[n..];
        }
        Header::Array(Some(n)) => {
            if n > MAX_ARRAY || n > input.len() {
                return Err(WireError::Bounds);
            }
            for _ in 0..n {
                screen(input, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

pub fn decode(bytes: &[u8], max: usize) -> WireResult<Value> {
    if max > MAX_ENCODED || bytes.len() > max {
        return Err(WireError::Bounds);
    }
    let mut remaining = bytes;
    screen(&mut remaining, 1)?;
    if !remaining.is_empty() {
        return Err(WireError::Canonical);
    }
    // Screening bounds every container before the allocating decoder runs.
    let value: Value = ciborium::de::from_reader(bytes)?;
    if encode(&value)? != bytes {
        return Err(WireError::Canonical);
    }
    Ok(value)
}

/// Historical message and configuration envelopes retain the text-free subset.
pub fn decode_without_text(bytes: &[u8], max: usize) -> WireResult<Value> {
    fn reject_text(value: &Value) -> WireResult<()> {
        match value {
            Value::Text(_) => Err(WireError::Schema),
            Value::Array(values) => {
                for value in values {
                    reject_text(value)?;
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
    let value = decode(bytes, max)?;
    reject_text(&value)?;
    Ok(value)
}
