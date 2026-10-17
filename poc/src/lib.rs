//! Loki G1 POC — checkpoint 1: pin and prove the library path.
//!
//! This crate exists to answer four questions from the brief with code rather than
//! with reading. Each is a named test or a compile probe.
//!
//!   C1.1  Is the FROST Pallas ciphersuite available?            -> PASS
//!   C1.2  Can an FVK be built from a DKG group `ak`
//!         plus ZIP 2005 `use_qsk = true`?                       -> LOCAL, UNREVIEWED
//!   C1.3  Does the deferred v6 PCZT path exist?                 -> PASS
//!   C1.4  Can the builder accept a caller-selected `alpha`?     -> BLOCKED
//!
//! Orchard's ZIP 2005 API is still absent. The local derivation in `zip2005` is checked
//! against an independent vector and used in a mined regtest payment, but needs review. The
//! `probe-zip2005` feature still records the missing upstream API. C1.4 is supplied by
//! an isolated patch to vendored orchard; see vendor/README.md.

pub mod candidate;
#[cfg(test)]
mod coordinator;
pub mod distributed_setup;
pub mod intent;
pub mod member_state;
#[cfg(test)]
mod nonce_binding;
pub mod payment_manifest;
pub mod randomizer;
pub mod refresh;
#[cfg(feature = "relay-communication")]
pub mod relay_member;
pub mod rpc;
pub mod scan;
pub mod scanstate;
pub mod seal_kdf;
pub mod setup_transport;
pub mod setup_ceremony;
pub mod signing_session;
pub mod state;
pub mod vault;
pub mod verify;
pub mod witness;
pub mod zip2005;

// ─────────────────────────────────────────────────────────────────────────────
// Compile probe for the one blocked requirement.
//
//   cargo build --features probe-zip2005   -> the ZIP 2005 blocker, verbatim
// ─────────────────────────────────────────────────────────────────────────────

/// C1.2 probe. The brief requires an FVK built from a DKG-derived group `ak` plus the
/// ZIP 2005 `use_qsk = true` derivation, and states that a pre-ZIP-2005 method alone is
/// not a pass. ZIP 2005 specifies, for FROST-generated keys:
///
/// ```text
///     qsk  --H^qk-->  qk
///     rivk_ext = H^rivk_ext_qk(ak, nk)          <- keyed by qk, selected by use_qsk
/// ```
///
/// None of `qsk`, `qk` or `rivk_ext` exists in orchard. This probe names them.
#[cfg(feature = "probe-zip2005")]
pub fn probe_zip2005(ak: [u8; 32], nk: [u8; 32], qsk: [u8; 32]) -> orchard::keys::FullViewingKey {
    // Each of the three lines below is the smallest call that would satisfy the
    // requirement. All three fail: the items do not exist in orchard 0.16.0.
    let qk = orchard::keys::QuantumIntermediateKey::from(&qsk);
    let rivk_ext = orchard::keys::CommitIvkRandomness::from_qk(&qk, &ak, &nk);
    orchard::keys::FullViewingKey::from_parts_with_qsk(ak, nk, rivk_ext, /* use_qsk */ true)
}

// ─────────────────────────────────────────────────────────────────────────────
// The two requirements that DO hold.
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod checkpoint_1 {
    use reddsa_frost::frost::redpallas as frost;
    use std::collections::BTreeMap;

    /// C1.1 — the FROST Pallas ciphersuite, end to end.
    ///
    /// DKG is exercised separately below; this covers key generation, preprocessing,
    /// rerandomized signing, share verification and aggregation, which is the list the
    /// brief asks to confirm.
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

    /// C1.1 — distributed key generation, no dealer.
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

    /// C1.2, as far as it can go: validate the saved group-key encoding and compose
    /// the documented test-only FVK. ZIP 2005 remains a separate setup path.
    ///
    /// **This is the pre-ZIP-2005 path and the brief says it is NOT a pass for G1.**
    /// It is recorded here to show exactly how far the available APIs reach.
    #[test]
    fn c1_2_group_key_becomes_an_address_but_only_pre_zip2005() {
        use orchard::keys::{FullViewingKey, Scope, SpendingKey};

        let rng = rand_core::OsRng;
        let (_shares, pubkeys) =
            frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, rng)
                .unwrap();

        // 32 bytes is the only common currency between the two crate universes.
        let group_ak: [u8; 32] = pubkeys
            .verifying_key()
            .serialize()
            .unwrap()
            .try_into()
            .expect("a RedPallas verifying key is 32 bytes");

        // nk and rivk still have to come from somewhere. ZIP 2005 says rivk_ext should be
        // H^rivk_ext_qk(ak, nk) keyed by the quantum intermediate key. That derivation
        // does not exist, so this borrows them from an ordinary wallet instead.
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

    /// C1.3 — the deferred v6 PCZT path exists and is Ironwood-aware.
    ///
    /// Compiling this test at all is the assertion: these paths resolve in
    /// zcash_primitives 0.31.0-pre.0 and pczt 0.10.0-pre.0.
    #[test]
    fn c1_3_deferred_pczt_builder_and_ironwood_roles_resolve() {
        #[allow(unused_imports)]
        use pczt::{
            roles::{io_finalizer::IoFinalizer, signer::Signer},
            Pczt,
        };
        #[allow(unused_imports)]
        use zcash_primitives::transaction::builder::DeferredPcztBuilder;

        // Named so a future reader can see which symbols were confirmed present.
        fn _confirmed<P>(_: Option<DeferredPcztBuilder<P>>, _: Option<Pczt>) {}
    }
}

#[cfg(feature = "relay-communication")]
pub mod setup_relay;

#[cfg(feature = "relay-communication")]
pub(crate) mod setup_backup;

#[cfg(feature = "relay-communication")]
pub(crate) mod setup_retry;
