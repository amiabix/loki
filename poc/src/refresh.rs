//! Share refresh — retire a leaked signing share without moving the vault.
//!
//! THREAT-MODEL.md measures the blast radius: one leaked share is survivable in a
//! 2-of-3 group, two is total loss. So the only response that matters is being able to
//! invalidate the leaked share before a second one leaks, and the only response that is
//! *usable* is one that does not move the coins: the Zcash address is derived from the
//! group verifying key (`vault::test_only_fvk`), so a rotation that changed `ak` would
//! strand every existing note and be worse than doing nothing.
//!
//! The scheme that gives exactly that is additive resharing: every member adds their
//! piece of a fresh sharing of *zero*. The Lagrange interpolation of the new shares is
//! `secret + 0`, so the group key is untouched, while each individual share is a new
//! random value that has no relation to the old one. `frost_core` implements it in
//! `keys::refresh`; `reddsa`'s redpallas module does not re-export it, but its key types
//! are plain aliases of the `frost_core` generics over `PallasBlake2b512`
//! (reddsa-0.5.2/src/frost/redpallas.rs:286,300,306), so the generic functions apply
//! directly. The two wrappers below exist only to pin the ciphersuite.
//!
//! This is the trusted-dealer variant. "Trusted" overstates it: the refreshing shares
//! are shares of zero, so whoever computes them learns nothing about the group secret
//! and cannot forge with them. They do have to be delivered confidentially — a
//! refreshing share disclosed alongside the old share reconstructs the new one.
//! `frost_core::keys::refresh` also has a no-dealer DKG variant (`refresh_dkg_part1` /
//! `_part2` / `refresh_dkg_shares`) if that delivery assumption is unacceptable.

use reddsa_frost::frost::redpallas as frost;

/// The dealer half: compute one refreshing share per member, plus the new public key
/// package. `members` must list every identifier that keeps a share — anyone omitted is
/// removed from the group, which is the other thing this primitive is for.
///
/// The returned [`frost::keys::PublicKeyPackage`] carries the *same* verifying key and
/// new verifying shares.
pub fn compute_refreshing_shares(
    pubkeys: frost::keys::PublicKeyPackage,
    members: &[frost::Identifier],
    rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
) -> Result<(Vec<frost::keys::SecretShare>, frost::keys::PublicKeyPackage), frost::Error> {
    frost_core::keys::refresh::compute_refreshing_shares(pubkeys, members, rng)
}

/// The member half: fold a refreshing share into the share this member already holds.
/// The old [`frost::keys::KeyPackage`] must be destroyed afterwards — it stays valid
/// against the *old* public key package, and that is the whole point of rotating.
pub fn refresh_share(
    refreshing_share: frost::keys::SecretShare,
    current: &frost::keys::KeyPackage,
) -> Result<frost::keys::KeyPackage, frost::Error> {
    frost_core::keys::refresh::refresh_share(refreshing_share, current)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::{regtest_unified_address, test_only_fvk};
    use std::collections::BTreeMap;

    type Wallets = BTreeMap<frost::Identifier, frost::keys::KeyPackage>;

    /// A fresh 2-of-3 group, in the shape the rest of the POC uses.
    fn group() -> (Wallets, frost::keys::PublicKeyPackage) {
        let (shares, pubkeys) = frost::keys::generate_with_dealer(
            3,
            2,
            frost::keys::IdentifierList::Default,
            rand_core::OsRng,
        )
        .expect("2-of-3 keygen");

        let wallets = shares
            .into_iter()
            .map(|(id, ss)| (id, frost::keys::KeyPackage::try_from(ss).unwrap()))
            .collect();
        (wallets, pubkeys)
    }

    /// Rotate every member's share. Returns the new wallets and the new public package.
    fn rotate(
        wallets: &Wallets,
        pubkeys: frost::keys::PublicKeyPackage,
    ) -> (Wallets, frost::keys::PublicKeyPackage) {
        let ids: Vec<_> = wallets.keys().copied().collect();
        let (refreshing, new_pubkeys) =
            compute_refreshing_shares(pubkeys, &ids, &mut rand_core::OsRng)
                .expect("a zero-sharing for all three members");

        // `compute_refreshing_shares` returns the shares in the order of `ids`.
        let new_wallets = ids
            .iter()
            .zip(refreshing)
            .map(|(id, rs)| {
                (*id, refresh_share(rs, &wallets[id]).expect("fold in the zero share"))
            })
            .collect();

        (new_wallets, new_pubkeys)
    }

    fn address(pubkeys: &frost::keys::PublicKeyPackage) -> String {
        let ak: [u8; 32] = pubkeys
            .verifying_key()
            .serialize()
            .unwrap()
            .try_into()
            .expect("a RedPallas verifying key is 32 bytes");
        regtest_unified_address(&test_only_fvk(&ak).expect("a DKG group key is a valid ak"))
    }

    /// Sign `msg` with exactly the first two members of `wallets`, verifying against
    /// `pubkeys`. Mirrors `c1_1_frost_pallas_signs_under_a_caller_supplied_alpha`.
    fn sign_2_of_3(
        wallets: &Wallets,
        pubkeys: &frost::keys::PublicKeyPackage,
        msg: &[u8],
    ) -> Result<(), frost::Error> {
        sign_with(
            &wallets.keys().copied().take(2).map(|id| (id, &wallets[&id])).collect::<Vec<_>>(),
            pubkeys,
            msg,
        )
    }

    /// The signing half, with the signer set named explicitly so a test can mix an old
    /// key package in with a new one.
    fn sign_with(
        signers: &[(frost::Identifier, &frost::keys::KeyPackage)],
        pubkeys: &frost::keys::PublicKeyPackage,
        msg: &[u8],
    ) -> Result<(), frost::Error> {
        let mut rng = rand_core::OsRng;
        let alpha =
            frost_rerandomized::Randomizer::<frost::PallasBlake2b512>::deserialize(&[7u8; 32])
                .expect("a canonical scalar");

        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        for (id, kp) in signers {
            let (n, c) = frost::round1::commit(kp.signing_share(), &mut rng);
            nonces.insert(*id, n);
            commitments.insert(*id, c);
        }

        let pkg = frost::SigningPackage::new(commitments, msg);

        let mut sigshares = BTreeMap::new();
        for (id, kp) in signers {
            #[allow(deprecated)] // the seed path cannot be used: alpha is fixed by the tx
            let share = frost_rerandomized::sign(&pkg, &nonces[id], kp, alpha)?;
            sigshares.insert(*id, share);
        }

        let params =
            frost_rerandomized::RandomizedParams::from_randomizer(pubkeys.verifying_key(), alpha);
        let sig = frost_rerandomized::aggregate(&pkg, &sigshares, pubkeys, &params)?;

        params.randomized_verifying_key().verify(msg, &sig)
    }

    /// THE headline property. Rotation must be invisible from the chain's point of view:
    /// if the address moved, every note already paid to the vault would be stranded and
    /// the feature would be a liability rather than an incident response.
    #[test]
    fn c5_rotation_leaves_the_vault_address_byte_identical() {
        let (wallets, pubkeys) = group();
        let before = address(&pubkeys);

        let (_new_wallets, new_pubkeys) = rotate(&wallets, pubkeys);
        let after = address(&new_pubkeys);

        assert_eq!(before, after, "the vault address must survive a rotation");
    }

    /// Rotation is not cosmetic: every member's secret share is a different scalar
    /// afterwards, which is what makes the leaked copy worthless.
    #[test]
    fn c5_every_signing_share_actually_changes() {
        let (wallets, pubkeys) = group();
        let (new_wallets, _) = rotate(&wallets, pubkeys);

        for (id, old) in &wallets {
            assert_ne!(
                old.signing_share().serialize(),
                new_wallets[id].signing_share().serialize(),
                "member {id:?} kept its old share"
            );
        }
    }

    /// The new shares still sign, under the same group key, at the same threshold.
    #[test]
    fn c5_new_shares_sign_under_the_same_group_key() {
        let (wallets, pubkeys) = group();
        let (new_wallets, new_pubkeys) = rotate(&wallets, pubkeys);

        sign_2_of_3(&new_wallets, &new_pubkeys, b"stand-in sighash")
            .expect("two refreshed shares still produce a valid signature");

        for kp in new_wallets.values() {
            assert_eq!(*kp.min_signers(), 2, "the threshold must not move");
        }
        assert_eq!(new_wallets.len(), 3, "the group is still 2 of 3");
    }

    /// The point of the exercise. A leaked share, replayed after rotation alongside an
    /// honest refreshed one, must not aggregate into a usable signature.
    #[test]
    fn c5_a_leaked_old_share_no_longer_aggregates() {
        let (wallets, pubkeys) = group();
        let (new_wallets, new_pubkeys) = rotate(&wallets, pubkeys);

        let ids: Vec<_> = wallets.keys().copied().take(2).collect();
        let leaked = &wallets[&ids[0]]; // the attacker's stale copy
        let honest = &new_wallets[&ids[1]];

        let err = sign_with(
            &[(ids[0], leaked), (ids[1], honest)],
            &new_pubkeys,
            b"stand-in sighash",
        )
        .expect_err("a retired share must not help produce a signature");

        // Aggregation checks each signature share against the refreshed verifying share,
        // so the stale one is caught by name rather than producing a bad signature.
        assert_eq!(err, frost::Error::InvalidSignatureShare { culprits: vec![ids[0]] });
    }

    /// And the converse, so the test above is not passing for an unrelated reason: the
    /// old shares as a complete set still work against the OLD public package. Rotation
    /// invalidates them only once the group has moved on, which is why the old key
    /// packages have to be destroyed rather than merely superseded.
    #[test]
    fn c5_old_shares_remain_valid_against_the_old_package() {
        let (wallets, pubkeys) = group();
        let (_new_wallets, _new_pubkeys) = rotate(&wallets, pubkeys.clone());

        sign_2_of_3(&wallets, &pubkeys, b"stand-in sighash")
            .expect("the old quorum still signs against the old package");
    }
}
