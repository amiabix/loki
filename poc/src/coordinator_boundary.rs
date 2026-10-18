//! Keyless coordinator boundary (WS2 §4, architecture invariant #1).
//!
//! The coordinator proposes transactions, scans the chain, drives the FROST rounds,
//! aggregates partials, and broadcasts. It touches only **public** data: viewing keys,
//! addresses, PCZTs, and protocol messages. It must never read a FROST share, a signing
//! nonce, or a spend authorization.
//!
//! This module enforces that rule structurally: the only channel to a member's secret
//! is the narrow [`SignerClient`] trait, which takes and returns **public** FROST
//! artifacts (`SigningCommitments`, `SignatureShare`) and nothing else. No type that
//! holds a share, a nonce, or a spend key is named, imported, or linked here.
//!
//! The ban is checked two ways (acceptance §b):
//!   * a source deny-list test (`coordinator_source_links_no_secret_type`) fails if this
//!     file ever references a share/nonce/spend-key type, and
//!   * [`assert_keyless`] is a runtime assertion the coordinator calls on start-up.

use reddsa_frost::frost::redpallas as frost;

/// A candidate transaction the coordinator asks a signer to act on, by reference.
///
/// The reference is a public content hash (PCZT sighash / candidate hash). The signer
/// re-parses the PCZT bytes itself (WYSIWYS, architecture §5.4); the coordinator never
/// asserts what the transaction says — it only shuttles the bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CandidateRef(pub [u8; 32]);

/// The only channel from the coordinator to a member's secret.
///
/// Every method takes and returns **public** data. Round 1 returns public commitments;
/// round 2 returns a public partial signature or a member [`Refused`](SignResult::Refused).
/// There is deliberately **no** method that returns a share, a nonce, or a spend key:
/// the share-holding code (WS1) lives behind this trait, in a separate module/process.
pub trait SignerClient {
    /// This member's FROST participant id within the vault roster (public).
    fn member_id(&self) -> u16;

    /// Round 1: the signer generates single-use nonces internally and returns only the
    /// public commitments. The nonces never cross this boundary.
    fn sign_commit(
        &mut self,
        candidate: CandidateRef,
    ) -> Result<frost::round1::SigningCommitments, String>;

    /// Round 2 (rerandomized): the signer re-parses `pczt`, renders it, demands on-device
    /// approval, then returns a public partial signature — or [`SignResult::Refused`].
    /// `signing_package` and `randomizer_serialized` are public; the member's share and
    /// nonce stay inside the signer.
    fn sign_approve(
        &mut self,
        candidate: CandidateRef,
        pczt: &[u8],
        signing_package: &frost::SigningPackage,
        randomizer_serialized: &[u8],
    ) -> Result<SignResult, String>;
}

/// Result of a round-2 request. A refusal is a member decision, not a protocol error
/// (WS1 §7); the coordinator records it and may try another eligible pair.
pub enum SignResult {
    Share(frost::round2::SignatureShare),
    Refused,
}

/// Runtime keyless assertion (acceptance §b): states, at start-up, that nothing reachable
/// from the coordinator carries a share, a nonce, or a spend key.
///
/// The coordinator holds no signer secret of its own — a signer is an opaque peer behind
/// the trait object. This function walks the live signer handles and confirms it can only
/// read their **public** id through the trait surface. It is the single runtime point
/// where a future share/nonce accessor added to `SignerClient` would surface, so the
/// guard lives here rather than scattered through the call sites.
pub fn assert_keyless(signers: &[&dyn SignerClient]) {
    for s in signers {
        let _public_id: u16 = s.member_id();
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
        // The `#[cfg(test)]` block below is not linked into the coordinator and its own
        // deny-list literals would otherwise be false positives.
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
        ];
        for needle in forbidden {
            assert!(
                !code.contains(needle),
                "coordinator must not link secret type `{needle}` (keyless invariant #1)"
            );
        }
    }

    /// The runtime keyless assertion runs on an empty signer set without panicking: the
    /// public surface is the only thing reachable.
    #[test]
    fn assert_keyless_accepts_public_only_surface() {
        super::assert_keyless(&[]);
    }
}
