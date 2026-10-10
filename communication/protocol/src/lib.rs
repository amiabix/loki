use std::fmt;

pub type WireResult<T> = Result<T, WireError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WireError {
    Bounds,
    Canonical,
    Schema,
    Version,
}

impl WireError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Bounds => "bounds",
            Self::Canonical => "canonical",
            Self::Schema => "schema",
            Self::Version => "version",
        }
    }
}

impl<E> From<ciborium::de::Error<E>> for WireError {
    fn from(_: ciborium::de::Error<E>) -> Self {
        Self::Schema
    }
}

impl<E> From<ciborium::ser::Error<E>> for WireError {
    fn from(_: ciborium::ser::Error<E>) -> Self {
        Self::Schema
    }
}

impl fmt::Display for WireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

impl std::error::Error for WireError {}

pub mod canonical;
pub mod envelope;

pub mod types;

pub mod http;
pub mod receipt;
