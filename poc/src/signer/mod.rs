//! WS1 signer: the safety-critical component that keeps the FROST share out of the
//! browser (`docs/product/ws1-signer.md`). First buildable slice.
//!
//! - [`secure_element`]: at-rest key hierarchy — `SealedShare` sealed by a random DEK,
//!   DEK wrapped by a `SecureElement` KEK (software fallback now; Secure Enclave /
//!   StrongBox implement the same trait later). On-disk share is always ciphertext.
//! - [`nonce`]: crash-safe single-use nonce state machine (persist-before-emit in
//!   round 1; atomic burn+emit in round 2; hard-refuse reuse).
//! - [`wysiwys`]: parse a PCZT into the facts the member approves, derived from the
//!   bytes, not from any coordinator-supplied label.
//! - [`api`]: the keyless `SignerApi` trait — returns only public artifacts.
//!
//! Platform secure-element specifics are stubbed behind the `SecureElement` trait; the
//! real deliverables this round are the crash-safety, the WYSIWYS parse, and the
//! keyless API shape.

pub mod api;
pub mod nonce;
pub mod secure_element;
pub mod wysiwys;
