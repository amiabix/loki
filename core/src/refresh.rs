use reddsa_frost::frost::redpallas as frost;

pub fn compute_refreshing_shares(
    pubkeys: frost::keys::PublicKeyPackage,
    members: &[frost::Identifier],
    rng: &mut (impl rand_core::RngCore + rand_core::CryptoRng),
) -> Result<(Vec<frost::keys::SecretShare>, frost::keys::PublicKeyPackage), frost::Error> {
    frost_core::keys::refresh::compute_refreshing_shares(pubkeys, members, rng)
}

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

    fn rotate(
        wallets: &Wallets,
        pubkeys: frost::keys::PublicKeyPackage,
    ) -> (Wallets, frost::keys::PublicKeyPackage) {
        let ids: Vec<_> = wallets.keys().copied().collect();
        let (refreshing, new_pubkeys) =
            compute_refreshing_shares(pubkeys, &ids, &mut rand_core::OsRng)
                .expect("a zero-sharing for all three members");

        let new_wallets = ids
            .iter()
            .zip(refreshing)
            .map(|(id, rs)| {
                (
                    *id,
                    refresh_share(rs, &wallets[id]).expect("fold in the zero share"),
                )
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

    fn sign_2_of_3(
        wallets: &Wallets,
        pubkeys: &frost::keys::PublicKeyPackage,
        msg: &[u8],
    ) -> Result<(), frost::Error> {
        sign_with(
            &wallets
                .keys()
                .copied()
                .take(2)
                .map(|id| (id, &wallets[&id]))
                .collect::<Vec<_>>(),
            pubkeys,
            msg,
        )
    }

    fn sign_with(
        signers: &[(frost::Identifier, &frost::keys::KeyPackage)],
        pubkeys: &frost::keys::PublicKeyPackage,
        msg: &[u8],
    ) -> Result<(), frost::Error> {
        let mut rng = rand_core::OsRng;
        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        for (id, kp) in signers {
            let (n, c) = frost::round1::commit(kp.signing_share(), &mut rng);
            nonces.insert(*id, n);
            commitments.insert(*id, c);
        }

        let (params, seed) = frost_rerandomized::RandomizedParams::new_from_commitments(
            pubkeys.verifying_key(),
            &commitments,
            rand_core::OsRng,
        )?;
        let pkg = frost::SigningPackage::new(commitments, msg);

        let mut sigshares = BTreeMap::new();
        for (id, kp) in signers {
            let share =
                frost_rerandomized::sign_with_randomizer_seed(&pkg, &nonces[id], kp, &seed)?;
            sigshares.insert(*id, share);
        }

        let sig = frost_rerandomized::aggregate(&pkg, &sigshares, pubkeys, &params)?;

        params.randomized_verifying_key().verify(msg, &sig)
    }

    #[test]
    fn c5_rotation_leaves_the_vault_address_byte_identical() {
        let (wallets, pubkeys) = group();
        let before = address(&pubkeys);

        let (_new_wallets, new_pubkeys) = rotate(&wallets, pubkeys);
        let after = address(&new_pubkeys);

        assert_eq!(before, after, "the vault address must survive a rotation");
    }

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

    #[test]
    fn c5_a_leaked_old_share_no_longer_aggregates() {
        let (wallets, pubkeys) = group();
        let (new_wallets, new_pubkeys) = rotate(&wallets, pubkeys);

        let ids: Vec<_> = wallets.keys().copied().take(2).collect();
        let leaked = &wallets[&ids[0]];
        let honest = &new_wallets[&ids[1]];

        let err = sign_with(
            &[(ids[0], leaked), (ids[1], honest)],
            &new_pubkeys,
            b"stand-in sighash",
        )
        .expect_err("a retired share must not help produce a signature");

        assert_eq!(
            err,
            frost::Error::InvalidSignatureShare {
                culprits: vec![ids[0]]
            }
        );
    }

    #[test]
    fn c5_old_shares_remain_valid_against_the_old_package() {
        let (wallets, pubkeys) = group();
        let (_new_wallets, _new_pubkeys) = rotate(&wallets, pubkeys.clone());

        sign_2_of_3(&wallets, &pubkeys, b"stand-in sighash")
            .expect("the old quorum still signs against the old package");
    }
}
