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
pub mod local;
pub mod nonce;
pub mod secure_element;
#[cfg(all(feature = "apple-enclave", target_os = "macos"))]
pub mod secure_element_apple;
pub mod wysiwys;

use crate::signer::wysiwys::PaymentView;
use reddsa_frost::frost::redpallas as frost;

/// Opaque session handle. Carries no secret; it names an unlocked signer connection.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Session(pub [u8; 32]);

/// Which network a coordinator is asking to connect for. Shown to the member on-device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Regtest,
    Testnet,
}

/// Public vault metadata only — names, slots, setup status. No keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VaultRef {
    pub vault_id: [u8; 32],
    pub label: String,
    pub threshold: u16,
    pub members: u16,
    pub ready: bool,
}

/// Public identity of the connected member (its roster id + public keys).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberIdentity {
    pub id: u16,
    pub signing: [u8; 32],
    pub encryption: [u8; 32],
}

/// A session plus the public member identity it is bound to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Connection {
    pub session: Session,
    pub member: MemberIdentity,
}

/// Names a candidate the coordinator wants this member to commit/sign to. Public.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CandidateRef {
    pub vault_id: [u8; 32],
    pub payment_id: [u8; 32],
    pub attempt_id: [u8; 32],
}

/// The PUBLIC payment effects the coordinator hands a signer to build an unsigned
/// candidate. No viewing key, no note, no spend authority — just where the money goes,
/// how much, the memo, and the validity window. The signer selects its own notes and
/// uses its own held viewing key to build.
#[derive(Clone)]
pub struct PublicPaymentParams {
    pub recipient: orchard::Address,
    pub amount: zcash_protocol::value::Zatoshis,
    pub memo: zcash_protocol::memo::MemoBytes,
    pub target_height: u32,
    pub expiry_height: u32,
}

/// The ONE keyless signer seam (ws1-signer §7). Every parameter and return type is
/// FROST/PCZT artifacts: session handles, vault metadata, authenticated DKG round-one
/// messages, recipient-encrypted DKG round-two messages, signing commitments, and
/// signature shares (public partial signatures).
///
/// There is deliberately NO method that takes or returns a FROST share, a secret nonce,
/// a viewing key, or a spend authorization (invariants #1/#4). Opaque byte vectors need
/// separate tests to verify that secret material is encrypted before it crosses this seam.
///
/// Implemented by [`local::LocalSigner`] (in-app, secure-element-wrapped share) today and
/// by a FROST hardware participant later, behind this exact interface (ws1-signer §4
/// hardware path). Local IPC or `frostd` transport (WS3) sit above it.
pub trait Signer {
    type Error;

    /// Show origin + network + challenge on the signer, biometric-unlock, return a
    /// session bound to the member's PUBLIC identity. No secret crosses out.
    fn connect(
        &mut self,
        origin: &str,
        network: Network,
        challenge: &[u8],
    ) -> Result<Connection, Self::Error>;

    /// Public vault metadata the member holds a share for.
    fn list_vaults(&self, session: &Session) -> Result<Vec<VaultRef>, Self::Error>;

    /// Advance the dealerless group DKG by one step, returning signed round-one messages
    /// or recipient-encrypted round-two messages. The member's share is born INSIDE the
    /// signer and sealed via the secure element on completion; it is never returned.
    fn dkg_step(
        &mut self,
        session: &Session,
        vault: &VaultRef,
        in_msgs: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>, Self::Error>;

    /// Round 1: after the member's on-device "prepare" ack, return PUBLIC commitments.
    /// The secret nonce is persisted internally (crash-safe) and never returned.
    fn sign_commit(
        &mut self,
        session: &Session,
        cand: &CandidateRef,
    ) -> Result<frost::round1::SigningCommitments, Self::Error>;

    /// Build the UNSIGNED candidate PCZT for this payment, under the coordinator-supplied
    /// rerandomizer `alpha` (its canonical 32-byte encoding, derived from the round-1
    /// commitments). The signer uses its OWN held viewing key and selects its OWN notes;
    /// the coordinator supplies only the public effects (`params`) and `alpha`. Returns the
    /// serialized, IO-finalized candidate bytes that round 2 then renders and signs. The
    /// coordinator never sees the viewing key or chooses the note.
    fn build_candidate(
        &self,
        session: &Session,
        cand: &CandidateRef,
        params: &PublicPaymentParams,
        alpha: &[u8; 32],
    ) -> Result<Vec<u8>, Self::Error>;

    /// Round 2 (rerandomized): BLOCKS on in-signer parse + render + approval + sighash
    /// binding. The signer independently parses `pczt`, checks its payment effects against
    /// `params`, renders it (WYSIWYS), requires an approval decision, and VERIFIES that
    /// `pkg.message()` equals the sighash recomputed from the rendered bytes — refusing
    /// BEFORE touching the nonce/share if they differ. `params` comes from the coordinator;
    /// the approval decision must use the independently derived render.
    /// Only then is the PUBLIC partial signature produced under single-use nonce rules.
    /// `randomizer` is the 32-byte rerandomization seed (the coordinator's public per-pair
    /// seed; the randomizer scalar is regenerated from it + the commitments).
    fn sign_approve(
        &mut self,
        session: &Session,
        cand: &CandidateRef,
        params: &PublicPaymentParams,
        pczt: &[u8],
        pkg: &frost::SigningPackage,
        randomizer: &[u8],
    ) -> Result<frost::round2::SignatureShare, Self::Error>;

    /// What the member saw on-device for this candidate (for the coordinator's UI/audit).
    /// Public facts only, derived from the PCZT.
    fn rendered_payment(
        &self,
        session: &Session,
        cand: &CandidateRef,
    ) -> Result<PaymentView, Self::Error>;

    fn disconnect(&mut self, session: Session) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    //! Type guard for the named return types of the signer seam.
    //!
    //! Every `Signer` success type is asserted to implement `PublicArtifact`, a marker
    //! deliberately NOT implemented for any secret type. This cannot inspect the contents
    //! of opaque `Vec<u8>` messages; the local signer DKG test checks that boundary.

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
    impl PublicArtifact for Vec<u8> {} // opacity requires separate DKG boundary tests

    fn assert_public<T: PublicArtifact>() {}

    #[test]
    fn known_signer_return_types_are_public_artifacts() {
        // Each line pins one `Signer` method's current success type. Opaque bytes need
        // separate content checks; this cannot inspect newly added methods automatically.
        assert_public::<Connection>(); // connect
        assert_public::<Vec<VaultRef>>(); // list_vaults
        assert_public::<Vec<Vec<u8>>>(); // dkg_step
        assert_public::<frost::round1::SigningCommitments>(); // sign_commit
        assert_public::<frost::round2::SignatureShare>(); // sign_approve
        assert_public::<PaymentView>(); // rendered_payment
                                        // disconnect returns ()

        // Negative guard, stated in the type system: the secret types are NOT artifacts.
        // Uncommenting any line below must fail to compile:
        //   assert_public::<frost::keys::KeyPackage>();
        //   assert_public::<frost::keys::SigningShare>();
        //   assert_public::<frost::round1::SigningNonces>();
        //   assert_public::<orchard::keys::FullViewingKey>();
    }
}
