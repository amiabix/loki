//! WS1 signer: the safety-critical component that keeps the FROST share out of the
//! browser (`docs/product/ws1-signer.md`).
//!
//! - [`secure_element`]: at-rest key hierarchy — `SealedShare` sealed by a random DEK,
//!   DEK wrapped by a `SecureElement` KEK (software fallback now; Secure Enclave /
//!   StrongBox implement the same trait later). On-disk share is always ciphertext.
//! - [`nonce`]: crash-safe single-use nonce state machine (persist-before-emit in
//!   round 1; atomic burn+emit in round 2; hard-refuse reuse).
//! - [`wysiwys`]: parse a PCZT into the facts the member approves, derived from the
//!   bytes, and recompute the sighash those bytes bind to.
//! - [`local`]: [`LocalSigner`], the in-app secure-element-backed implementation of the
//!   single [`Signer`] trait below.
//!
//! The [`Signer`] trait here is the ONE seam the coordinator sees (ws1-signer §7). It
//! supersedes the earlier split `SignerApi` (WS1) / `SignerClient` (WS2) traits:
//! `coordinator_boundary` now re-exports this trait instead of defining its own.

pub mod backup;
pub mod coordination;
pub mod device_auth;
pub(crate) mod durable;
pub mod local;
#[cfg(any(test, all(feature = "apple-enclave", target_os = "macos")))]
pub mod native_member;
pub mod nonce;
pub mod recovery;
pub mod repair;
pub mod secure_element;
#[cfg(all(feature = "apple-enclave", target_os = "macos"))]
pub mod secure_element_apple;
pub mod secure_element_webauthn;
pub mod store;
pub mod wysiwys;

#[cfg(target_arch = "wasm32")]
pub fn opfs_selftest(path: &str, bytes: &[u8]) -> Result<Vec<u8>, String> {
    let p = std::path::Path::new(path);
    let dir = p.parent().ok_or("path needs a parent directory")?;
    let name = p.file_name().and_then(|n| n.to_str()).ok_or("path needs a file name")?;
    durable::write_durable(dir, name, bytes).map_err(|e| e.to_string())?;
    durable::read_file(dir, name).map_err(|e| e.to_string())
}

#[cfg(target_arch = "wasm32")]
fn opfs_split(path: &str) -> Result<(&std::path::Path, &str), String> {
    let p = std::path::Path::new(path);
    let dir = p.parent().ok_or("path needs a parent directory")?;
    let name = p
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("path needs a file name")?;
    Ok((dir, name))
}

#[cfg(target_arch = "wasm32")]
pub fn opfs_put(path: &str, bytes: &[u8], create_new: bool) -> Result<(), String> {
    let (dir, name) = opfs_split(path)?;
    if create_new {
        durable::write_durable(dir, name, bytes)
    } else {
        durable::replace_durable(dir, name, bytes)
    }
    .map_err(|e| e.to_string())
}

#[cfg(target_arch = "wasm32")]
pub fn opfs_get(path: &str) -> Result<Option<Vec<u8>>, String> {
    let (dir, name) = opfs_split(path)?;
    match durable::read_file(dir, name) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    }
}

#[cfg(target_arch = "wasm32")]
pub fn opfs_exists(path: &str) -> bool {
    match opfs_split(path) {
        Ok((dir, name)) => durable::file_exists(dir, name),
        Err(_) => false,
    }
}

pub use crate::setup_transport::{DkgWire, DkgWireKind};
use crate::signer::wysiwys::PaymentView;
use reddsa_frost::frost::redpallas as frost;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Regtest,
    Testnet,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultRef {
    pub vault_id: [u8; 32],
    pub label: String,
    pub threshold: u16,
    pub members: u16,
    pub ready: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberIdentity {
    pub id: u16,
    pub signing: [u8; 32],
    pub encryption: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Connection {
    pub session: Session,
    pub member: MemberIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DkgInput {
    pub sender: u16,
    pub bytes: Vec<u8>,
}

impl DkgInput {
    pub fn from_relay(bytes: Vec<u8>) -> Result<Self, String> {
        let wire = DkgWire::parse(bytes)?;
        Ok(Self {
            sender: wire.sender(),
            bytes: wire.into_bytes(),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleasedAddress {
    pub vault_id: [u8; 32],
    pub address: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidatePczt(pub(crate) Vec<u8>);

impl CandidatePczt {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateRef {
    pub vault_id: [u8; 32],
    pub payment_id: [u8; 32],
    pub attempt_id: [u8; 32],
}

pub fn hosted_spend_ref(vault_id: [u8; 32], attempt: [u8; 32], spend: usize) -> CandidateRef {
    let attempt_id = if spend == 0 {
        attempt
    } else {
        let mut hash = blake3::Hasher::new();
        hash.update(b"Loki_hosted_spend_v1\0");
        hash.update(&attempt);
        hash.update(&(spend as u32).to_be_bytes());
        *hash.finalize().as_bytes()
    };
    CandidateRef { vault_id, payment_id: attempt, attempt_id }
}

#[derive(Clone)]
pub struct PublicPaymentParams {
    pub recipient: orchard::Address,
    pub amount: zcash_protocol::value::Zatoshis,
    pub memo: zcash_protocol::memo::MemoBytes,
    pub target_height: u32,
    pub expiry_height: u32,
}

/// The ONE keyless signer seam (ws1-signer §7). Every parameter and return type is
/// FROST/PCZT artifacts: session handles, vault metadata, setup messages ([`DkgWire`]:
/// signed round-one bodies, certificates and backup receipts, and recipient-encrypted v2
/// round-two envelopes), signing commitments, signature shares (public partial
/// signatures), and the released receive address.
///
/// There is deliberately NO method that takes or returns a FROST share, a secret nonce,
/// a viewing key, or a spend authorization (invariants #1/#4). No method returns raw
/// bytes: setup messages are [`DkgWire`], which only `setup_transport` constructs.
///
/// On-device decisions (roster code comparison, payment approval, connect approval,
/// backup passphrase) are callbacks supplied when the signer is created, never arguments
/// from the coordinator, so the trait stays object-safe and the coordinator cannot
/// confirm or cancel for the member.
///
/// When you add a method, add its return type to the `PublicArtifact` guard in the tests
/// below by hand.
///
/// Implemented by [`local::LocalSigner`] (in-app, secure-element-wrapped share) today and
/// by a FROST hardware participant later, behind this exact interface (ws1-signer §4
/// hardware path). Local IPC or `frostd` transport (WS3) sit above it.
pub trait Signer {
    type Error;

    fn connect(
        &mut self,
        origin: &str,
        network: Network,
        challenge: &[u8],
    ) -> Result<Connection, Self::Error>;

    fn list_vaults(&self, session: &Session) -> Result<Vec<VaultRef>, Self::Error>;

    fn dkg_begin(&mut self, session: &Session, roster: &[u8]) -> Result<VaultRef, Self::Error>;

    fn dkg_step(
        &mut self,
        session: &Session,
        vault: &VaultRef,
        in_msgs: &[DkgInput],
    ) -> Result<Vec<DkgWire>, Self::Error>;

    fn backup(&mut self, session: &Session) -> Result<Vec<DkgWire>, Self::Error>;

    fn release_address(&mut self, session: &Session) -> Result<ReleasedAddress, Self::Error>;

    /// Round 1: after the member's on-device "prepare" ack, return PUBLIC commitments.
    /// The secret nonce is persisted internally (crash-safe) and never returned.
    fn sign_commit(
        &mut self,
        session: &Session,
        cand: &CandidateRef,
    ) -> Result<frost::round1::SigningCommitments, Self::Error>;

    fn build_candidate(
        &self,
        session: &Session,
        cand: &CandidateRef,
        params: &PublicPaymentParams,
        alphas: &[[u8; 32]],
    ) -> Result<CandidatePczt, Self::Error>;

    fn sign_approve(
        &mut self,
        session: &Session,
        cand: &CandidateRef,
        params: &PublicPaymentParams,
        pczt: &[u8],
        pkg: &frost::SigningPackage,
        randomizer: &[u8],
    ) -> Result<frost::round2::SignatureShare, Self::Error>;

    fn rendered_payment(
        &self,
        session: &Session,
        cand: &CandidateRef,
    ) -> Result<PaymentView, Self::Error>;

    fn disconnect(&mut self, session: Session) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Marker for types that are safe to cross the coordinator boundary. Implemented
    /// ONLY for public artifacts; never for shares, nonces, or viewing keys.
    trait PublicArtifact {}

    impl PublicArtifact for Connection {}
    impl PublicArtifact for Session {}
    impl PublicArtifact for MemberIdentity {}
    impl PublicArtifact for PaymentView {}
    impl PublicArtifact for frost::round1::SigningCommitments {}
    impl PublicArtifact for frost::round2::SignatureShare {}
    impl<T: PublicArtifact> PublicArtifact for Vec<T> {}
    impl PublicArtifact for VaultRef {}
    impl PublicArtifact for DkgWire {}
    impl PublicArtifact for ReleasedAddress {}
    impl PublicArtifact for CandidatePczt {}

    fn assert_public<T: PublicArtifact>() {}

    #[test]
    fn known_signer_return_types_are_public_artifacts() {
        assert_public::<Connection>();
        assert_public::<Vec<VaultRef>>();
        assert_public::<VaultRef>();
        assert_public::<Vec<DkgWire>>();
        assert_public::<Vec<DkgWire>>();
        assert_public::<ReleasedAddress>();
        assert_public::<CandidatePczt>();
        assert_public::<frost::round1::SigningCommitments>();
        assert_public::<frost::round2::SignatureShare>();
        assert_public::<PaymentView>();
    }
}
