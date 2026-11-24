pub use loki_signer_core::{
    builder, candidate, distributed_setup, dkg_core, intent, member_state, network,
    payment_manifest, randomizer, seal_kdf, setup_transport, signer, signing_session,
    state, vault, verify, zip2005,
};
#[cfg(test)]
mod coordinator;
pub mod coordinator_boundary;
#[cfg(all(feature = "apple-enclave", target_os = "macos"))]
pub mod enclave_ffi;
pub mod frost_roster;
#[cfg(test)]
mod nonce_binding;
pub mod payment_transport;
pub mod profile;
pub mod host;
#[cfg(feature = "relay-communication")]
pub mod relay_member;
pub mod rpc;
pub mod scan;
pub mod scanstate;
pub mod setup_ceremony;
pub mod transport;
pub mod tx_finalize;
pub mod wallet_store;
pub mod witness;

#[cfg(feature = "probe-zip2005")]
pub fn probe_zip2005(ak: [u8; 32], nk: [u8; 32], qsk: [u8; 32]) -> orchard::keys::FullViewingKey {
    let qk = orchard::keys::QuantumIntermediateKey::from(&qsk);
    let rivk_ext = orchard::keys::CommitIvkRandomness::from_qk(&qk, &ak, &nk);
    orchard::keys::FullViewingKey::from_parts_with_qsk(ak, nk, rivk_ext, true)
}

#[cfg(test)]
mod checkpoint_1 {
    use reddsa_frost::frost::redpallas as frost;
    use std::collections::BTreeMap;

    #[test]
    fn c1_1_frost_pallas_signs_with_a_saved_randomizer_seed() {
        let mut rng = rand_core::OsRng;

        let (shares, pubkeys) =
            frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, rng)
                .expect("2-of-3 keygen");

        let wallets: BTreeMap<_, _> = shares
            .into_iter()
            .map(|(id, ss)| (id, frost::keys::KeyPackage::try_from(ss).unwrap()))
            .collect();
        let ids: Vec<_> = wallets.keys().copied().take(2).collect();

        let mut nonces = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        for id in &ids {
            let (n, c) = frost::round1::commit(wallets[id].signing_share(), &mut rng);
            nonces.insert(*id, n);
            commitments.insert(*id, c);
        }

        let (params, seed) = frost_rerandomized::RandomizedParams::new_from_commitments(
            pubkeys.verifying_key(),
            &commitments,
            rand_core::OsRng,
        )
        .unwrap();
        let restored = frost_rerandomized::RandomizedParams::regenerate_from_seed_and_commitments(
            pubkeys.verifying_key(),
            &seed,
            &commitments,
        )
        .unwrap();
        assert_eq!(
            params.randomizer().serialize(),
            restored.randomizer().serialize()
        );
        let pkg = frost::SigningPackage::new(commitments, b"stand-in sighash");

        let mut sigshares = BTreeMap::new();
        for id in &ids {
            let share = frost_rerandomized::sign_with_randomizer_seed(
                &pkg,
                &nonces[id],
                &wallets[id],
                &seed,
            )
            .unwrap();
            sigshares.insert(*id, share);
        }

        let sig = frost_rerandomized::aggregate(&pkg, &sigshares, &pubkeys, &params)
            .expect("two of three aggregate");

        params
            .randomized_verifying_key()
            .verify(b"stand-in sighash", &sig)
            .expect("verifies under the randomized group key");
    }

    #[test]
    fn c1_1_dkg_three_members_reach_one_group_key() {
        use frost::keys::dkg;
        let rng = rand_core::OsRng;

        let ids: Vec<frost::Identifier> = (1u16..=3).map(|i| i.try_into().unwrap()).collect();

        let mut r1_secret = BTreeMap::new();
        let mut r1_pub = BTreeMap::new();
        for id in &ids {
            let (s, p) = dkg::part1(*id, 3, 2, rng).unwrap();
            r1_secret.insert(*id, s);
            r1_pub.insert(*id, p);
        }

        let mut r2_secret = BTreeMap::new();
        let mut r2_pub: BTreeMap<_, BTreeMap<_, _>> = BTreeMap::new();
        for id in &ids {
            let others: BTreeMap<_, _> = r1_pub
                .iter()
                .filter(|(k, _)| *k != id)
                .map(|(k, v)| (*k, v.clone()))
                .collect();
            let (s, pkgs) = dkg::part2(r1_secret.remove(id).unwrap(), &others).unwrap();
            r2_secret.insert(*id, s);
            for (to, pkg) in pkgs {
                r2_pub.entry(to).or_default().insert(*id, pkg);
            }
        }

        let mut group_keys = Vec::new();
        for id in &ids {
            let others: BTreeMap<_, _> = r1_pub
                .iter()
                .filter(|(k, _)| *k != id)
                .map(|(k, v)| (*k, v.clone()))
                .collect();
            let (_kp, pubkeys) = dkg::part3(&r2_secret[id], &others, &r2_pub[id]).unwrap();
            group_keys.push(pubkeys.verifying_key().serialize().unwrap());
        }

        assert_eq!(group_keys[0], group_keys[1]);
        assert_eq!(group_keys[1], group_keys[2]);
        assert_eq!(
            group_keys[0][31] & 0x80,
            0,
            "the group key must have even y to be a valid Orchard ak"
        );
    }

    #[test]
    fn c1_2_group_key_becomes_an_address_but_only_pre_zip2005() {
        use orchard::keys::{FullViewingKey, Scope, SpendingKey};

        let rng = rand_core::OsRng;
        let (_shares, pubkeys) =
            frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, rng)
                .unwrap();

        let group_ak: [u8; 32] = pubkeys
            .verifying_key()
            .serialize()
            .unwrap()
            .try_into()
            .expect("a RedPallas verifying key is 32 bytes");

        let carrier = FullViewingKey::from(&SpendingKey::from_bytes([3u8; 32]).unwrap());
        let mut bytes = carrier.to_bytes();
        bytes[0..32].copy_from_slice(&group_ak);

        let vault =
            FullViewingKey::from_bytes(&bytes).expect("the group key is a structurally valid ak");

        assert_ne!(
            vault.address_at(0u64, Scope::External),
            carrier.address_at(0u64, Scope::External),
            "the vault has its own address"
        );
    }

    #[test]
    fn c1_3_deferred_pczt_builder_and_ironwood_roles_resolve() {
        #[allow(unused_imports)]
        use pczt::{
            roles::{io_finalizer::IoFinalizer, signer::Signer},
            Pczt,
        };
        #[allow(unused_imports)]
        use zcash_primitives::transaction::builder::DeferredPcztBuilder;

        fn _confirmed<P>(_: Option<DeferredPcztBuilder<P>>, _: Option<Pczt>) {}
    }
}

#[cfg(feature = "relay-communication")]
pub mod setup_relay;

#[cfg(feature = "relay-communication")]
pub mod member_service;

#[cfg(feature = "relay-communication")]
pub(crate) mod setup_backup;

#[cfg(feature = "relay-communication")]
pub(crate) mod setup_retry;
