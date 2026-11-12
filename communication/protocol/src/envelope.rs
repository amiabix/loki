use crate::{WireError, WireResult};

pub const MESSAGE_MAGIC: &[u8; 8] = b"LOKIRLY1";
pub const CONFIG_MAGIC: &[u8; 8] = b"LOKICFG1";
pub const SETUP_MAGIC: &[u8; 8] = b"LOKISET1";
pub const VERSION: u8 = 1;
pub const HEADER_LEN: usize = 8 + 1 + 32;
pub const TAG_LEN: usize = 16;
pub const LENGTH_PREFIX_LEN: usize = 4;
pub const PADDING_BLOCK_LEN: usize = 1024;
pub const MAX_WIRE_LEN: usize = 65536;

pub fn padded_wire_length(record_len: usize) -> WireResult<usize> {
    let raw = record_len
        .checked_add(HEADER_LEN + TAG_LEN + LENGTH_PREFIX_LEN)
        .ok_or(WireError::Bounds)?;
    let padded = raw
        .checked_add(PADDING_BLOCK_LEN - 1)
        .ok_or(WireError::Bounds)?
        / PADDING_BLOCK_LEN
        * PADDING_BLOCK_LEN;
    if padded > MAX_WIRE_LEN {
        return Err(WireError::Bounds);
    }
    Ok(padded)
}

pub fn validate_wire(wire: &[u8]) -> WireResult<()> {
    if !(PADDING_BLOCK_LEN..=MAX_WIRE_LEN).contains(&wire.len())
        || wire.len() % PADDING_BLOCK_LEN != 0
    {
        return Err(WireError::Bounds);
    }
    if &wire[..8] != MESSAGE_MAGIC && &wire[..8] != CONFIG_MAGIC && &wire[..8] != SETUP_MAGIC {
        return Err(WireError::Schema);
    }
    if wire[8] != VERSION {
        return Err(WireError::Version);
    }
    Ok(())
}
