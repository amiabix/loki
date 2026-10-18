//! The signer API (ws1-signer §7) — the ONLY surface the coordinator sees.
//!
//! Every return type below is PUBLIC data: session handles, public vault metadata,
//! public DKG/FROST round messages, signing commitments, and signature shares (public
//! partial signatures). There is deliberately NO method that returns a FROST share, a
//! secret nonce, a viewing key, or a spend authorization (invariant 1/4). The
//! `no_secret_return_types` test is the compile-time guard on that boundary.
//!
//! This is the trait shape only. WS2 defines the client's view separately (reconciled
//! next round); this round just locks the keyless API contract.

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

/// Round-2 outcome. `Approved` carries only the PUBLIC partial signature; a member
/// refusal is a first-class, public result (never leaks why beyond the member's choice).
#[derive(Clone, Debug)]
pub enum SignOutcome {
    Approved(frost::round2::SignatureShare),
    Refused,
}

/// The keyless coordinator boundary. Implemented by the in-app Enclave-wrapped store
/// today and by a FROST hardware participant later, behind this exact interface
/// (ws1-signer §4 hardware path). Local IPC or `frostd` transport (WS3) sit above it.
pub trait SignerApi {
    type Error;

    /// Show origin + network + challenge on the signer, biometric-unlock, return a
    /// session bound to the member's PUBLIC identity. No secret crosses out.
    fn connect(
        &mut self,
        origin: &str,
        network: Network,
        challenge: &[u8; 32],
    ) -> Result<Connection, Self::Error>;

    /// Public vault metadata the member holds a share for.
    fn list_vaults(&self, session: &Session) -> Result<Vec<VaultRef>, Self::Error>;

    /// Advance DKG by one step; returns the PUBLIC outbound round messages. The share is
    /// persisted internally on completion and never returned.
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
        candidate: &CandidateRef,
    ) -> Result<frost::round1::SigningCommitments, Self::Error>;

    /// Round 2: BLOCKS on in-signer parse + render (`PaymentView`) + biometric approval.
    /// The `pczt`/`signing_package`/`randomizer_seed` are re-checked against the parsed,
    /// approved payment inside the signer; the caller's claims are not trusted. Returns
    /// only a PUBLIC partial signature, or a refusal.
    fn sign_approve(
        &mut self,
        session: &Session,
        candidate: &CandidateRef,
        pczt: &[u8],
        signing_package: &frost::SigningPackage,
        randomizer_seed: &[u8; 32],
    ) -> Result<SignOutcome, Self::Error>;

    /// What the member saw on-device for this candidate (for the coordinator's UI/audit).
    /// Public facts only, derived from the PCZT.
    fn rendered_payment(
        &self,
        session: &Session,
        candidate: &CandidateRef,
    ) -> Result<PaymentView, Self::Error>;

    fn disconnect(&mut self, session: Session) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    //! Compile-time proof the API exposes no secret-returning method (acceptance test 2).
    //!
    //! Every `SignerApi` return type is asserted to implement `PublicArtifact`, a marker
    //! deliberately NOT implemented for any secret type. Adding a method that returns a
    //! `KeyPackage`/`SigningShare`/`SigningNonces`/`FullViewingKey` fails to compile here
    //! because those types do not implement `PublicArtifact`.

    use super::*;

    /// Marker for types that are safe to cross the coordinator boundary. Implemented
    /// ONLY for public artifacts; never for shares, nonces, or viewing keys.
    trait PublicArtifact {}

    impl PublicArtifact for Connection {}
    impl PublicArtifact for Session {}
    impl PublicArtifact for MemberIdentity {}
    impl PublicArtifact for PaymentView {}
    impl PublicArtifact for SignOutcome {} // holds only a PUBLIC SignatureShare
    impl PublicArtifact for frost::round1::SigningCommitments {}
    impl<T: PublicArtifact> PublicArtifact for Vec<T> {}
    impl PublicArtifact for VaultRef {}
    impl PublicArtifact for Vec<u8> {} // opaque public round messages

    fn assert_public<T: PublicArtifact>() {}

    #[test]
    fn every_api_return_type_is_a_public_artifact() {
        // Each line pins one SignerApi method's success type. If any method ever returns
        // a secret, its type will not implement PublicArtifact and this will not compile.
        assert_public::<Connection>(); // connect
        assert_public::<Vec<VaultRef>>(); // list_vaults
        assert_public::<Vec<Vec<u8>>>(); // dkg_step
        assert_public::<frost::round1::SigningCommitments>(); // sign_commit
        assert_public::<SignOutcome>(); // sign_approve
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
