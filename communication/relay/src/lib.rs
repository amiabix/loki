use loki_relay_protocol::WireError;
use std::fmt;

pub type RelayResult<T> = Result<T, RelayError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelayError {
    MalformedRequest,
    Capability,
    ObjectNotFound,
    Conflict,
    CursorAhead,
    ObjectTooLarge,
    UnsupportedMediaType,
    RateLimit,
    StorageUnavailable,
    QuotaExhausted,
}

impl RelayError {
    pub const fn code(&self) -> u8 {
        match self {
            Self::MalformedRequest => 1,
            Self::Capability => 2,
            Self::ObjectNotFound => 3,
            Self::Conflict => 4,
            Self::CursorAhead => 5,
            Self::ObjectTooLarge => 6,
            Self::UnsupportedMediaType => 7,
            Self::RateLimit => 8,
            Self::StorageUnavailable => 9,
            Self::QuotaExhausted => 10,
        }
    }
}

impl From<WireError> for RelayError {
    fn from(_: WireError) -> Self {
        Self::MalformedRequest
    }
}

impl From<rusqlite::Error> for RelayError {
    fn from(_: rusqlite::Error) -> Self {
        Self::StorageUnavailable
    }
}

impl From<std::io::Error> for RelayError {
    fn from(_: std::io::Error) -> Self {
        Self::StorageUnavailable
    }
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "relay_error_{}", self.code())
    }
}

impl std::error::Error for RelayError {}

pub mod capability;
mod root;
pub use capability::{Capability, Role};
pub mod store;
pub use store::{Limits, RelayStore, StoredResult};
pub mod writer;
pub use writer::{DbHandle, DbReply, DbWriter};
pub mod http;
