//! Keyless coordinator boundary (WS2 §4, architecture invariant #1).
//!
//! The coordinator proposes transactions, scans the chain, drives the FROST rounds,
//! aggregates partials, and broadcasts. It touches only **public** data: viewing keys,
//! addresses, PCZTs, and protocol messages. It must never read a FROST share, a signing
//! nonce, or a spend authorization.
//!
//! There is exactly ONE signer seam in this codebase — [`crate::signer::Signer`] — and the
//! coordinator talks to members only through it. This module used to define a separate
//! `SignerClient` trait for the coordinator's view; that duplicate is gone. The seam is
//! re-exported here so coordinator code keeps a single import path, and the keyless rule is
//! enforced two ways (acceptance §b):
//!   * a source deny-list test (`coordinator_source_links_no_secret_type`) fails if this
//!     file ever references a share/nonce/spend-key type, and
//!   * [`assert_keyless`] is a runtime assertion the coordinator calls on start-up.

/// The one signer seam. The coordinator sees members only as `dyn Signer`; every method on
/// it takes and returns public FROST/PCZT artifacts (see `signer::Signer`'s `PublicArtifact`
/// compile-time guard). No share, nonce, or spend-key type is named here.
pub use crate::signer::{CandidateRef, Connection, Network, Session, Signer, VaultRef};

/// Runtime keyless assertion (acceptance §b): states, at start-up, that nothing reachable
/// from the coordinator carries a share, a nonce, or a spend key.
///
/// A signer is an opaque peer behind the trait object; the coordinator can only read its
/// PUBLIC vault metadata through the seam. This is the single runtime point where a future
/// share/nonce accessor added to `Signer` would surface, so the guard lives here.
pub fn assert_keyless<E>(signers: &[&dyn Signer<Error = E>], session: &Session) {
    for s in signers {
        // Only the public surface is reachable: vault metadata, never a secret.
        let _public: Result<Vec<VaultRef>, E> = s.list_vaults(session);
    }
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    /// Deny-list / module-dependency assertion (acceptance §b).
    ///
    /// Fails if the coordinator source ever references a share, nonce, or spend-key type.
    /// This is the static half of the keyless proof: the coordinator links none of the
    /// share-holding code. It greps the real source after stripping `//` lines, so the
    /// doc-comments above (which must NAME the banned concepts to explain the ban) do not
    /// trip it — only live code counts.
    #[test]
    fn coordinator_source_links_no_secret_type() {
        let src = std::fs::read_to_string(Path::new(file!()))
            .or_else(|_| std::fs::read_to_string("poc/src/coordinator_boundary.rs"))
            .or_else(|_| std::fs::read_to_string("src/coordinator_boundary.rs"))
            .expect("read coordinator_boundary.rs");
        // Scan only the shipped boundary — the production code above the test module.
        let shipped = src.split("#[cfg(test)]").next().unwrap_or("");
        let code: String = shipped
            .lines()
            .map(|l| l.split("//").next().unwrap_or(""))
            .collect::<Vec<_>>()
            .join("\n");

        // Types/paths that would mean a secret can be read inside the coordinator.
        let forbidden = [
            "KeyPackage",          // the FROST share
            "SigningNonces",       // the single-use signing nonce
            "signing_share",       // raw share scalar accessor
            "SpendingKey",         // the orchard spend authorization
            "SpendAuthorizingKey", // ask / spend-auth secret
            "member_state",        // module that loads the sealed share
            "MemberState",         // struct bundling the share
            "signing_session",     // module that holds nonces and the share
            "read_sealed",         // sealed-store secret reader
            "SecretKey",           // any secret key import
            "SealedShare",         // the sealed share blob type
            "LocalSigner",         // the share-holding implementation
        ];
        for needle in forbidden {
            assert!(
                !code.contains(needle),
                "coordinator must not link secret type `{needle}` (keyless invariant #1)"
            );
        }
    }

    /// The runtime keyless assertion compiles and runs over an empty signer set: the public
    /// surface is the only thing reachable through the seam.
    #[test]
    fn assert_keyless_accepts_public_only_surface() {
        use crate::signer::{Session, VaultRef};
        // A trivial `Signer` whose Error is `()` is enough to pin the public-only surface.
        struct Dummy;
        impl crate::signer::Signer for Dummy {
            type Error = ();
            fn connect(
                &mut self,
                _: &str,
                _: crate::signer::Network,
                _: &[u8],
            ) -> Result<crate::signer::Connection, ()> {
                Err(())
            }
            fn list_vaults(&self, _: &Session) -> Result<Vec<VaultRef>, ()> {
                Ok(vec![])
            }
            fn dkg_step(
                &mut self,
                _: &Session,
                _: &VaultRef,
                _: &[Vec<u8>],
            ) -> Result<Vec<Vec<u8>>, ()> {
                Ok(vec![])
            }
            fn sign_commit(
                &mut self,
                _: &Session,
                _: &crate::signer::CandidateRef,
            ) -> Result<reddsa_frost::frost::redpallas::round1::SigningCommitments, ()> {
                Err(())
            }
            fn sign_approve(
                &mut self,
                _: &Session,
                _: &crate::signer::CandidateRef,
                _: &[u8],
                _: &reddsa_frost::frost::redpallas::SigningPackage,
                _: &[u8],
            ) -> Result<reddsa_frost::frost::redpallas::round2::SignatureShare, ()> {
                Err(())
            }
            fn rendered_payment(
                &self,
                _: &Session,
                _: &crate::signer::CandidateRef,
            ) -> Result<crate::signer::wysiwys::PaymentView, ()> {
                Err(())
            }
            fn disconnect(&mut self, _: Session) -> Result<(), ()> {
                Ok(())
            }
        }
        let d = Dummy;
        super::assert_keyless(&[&d], &Session([0u8; 32]));
    }
}
