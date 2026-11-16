//! `loki-signer-core` — the dependency-clean FROST signer core, extracted from `loki-poc`.
//!
//! This crate holds the safety-critical signing path (DKG, FROST signing, WYSIWYS,
//! secure-element key hierarchy, and crash-safe persistence) and its coupled modules. It
//! pulls NONE of rusqlite/tonic/tokio/reqwest/axum, so it compiles to
//! `wasm32-unknown-unknown`. `loki-poc` depends on it and re-exports these modules, so the
//! rest of that crate keeps using `crate::signer`, `crate::member_state`, … unchanged.
//!
//! The `frostd` [`transport::Transport`] implementation (reqwest/tokio) stays in `loki-poc`;
//! only the trait and its public message types live here.

/// The FROST ciphersuite (reddsa/redpallas), re-exported so non-native transports (the
/// browser signer) can serialize/deserialize the public signing wire without a direct
/// reddsa-frost dependency and its version pinning.
pub use reddsa_frost::frost::redpallas as frost;

pub mod builder;
pub mod candidate;
pub mod distributed_setup;
pub mod dkg_core;
pub mod intent;
pub mod member_state;
pub mod network;
pub mod payment_manifest;
pub mod randomizer;
pub mod seal_kdf;
pub mod setup_transport;
pub mod signer;
pub mod signing_session;
pub mod state;
pub mod transport;
pub mod vault;
pub mod verify;
pub mod zip2005;
