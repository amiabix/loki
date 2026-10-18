//! ZF-stack adoption spine (WS4/WS5) integration proof.
//!
//! 1. The audited ZF crates (`frost-core`/`frost-rerandomized`/`reddsa` RedPallas)
//!    perform a 2-of-3 rerandomized FROST sign + aggregate + verify in Loki's own
//!    tree — upholding architecture invariant 5 "audited crypto only".
//! 2. WS5: compare the FVK that `zcash-sign generate` would produce (orchard's
//!    non-recoverable `from_sk_ak_incompatible_with_quantum_recoverability...`
//!    constructor: nk = sk.into(), rivk = sk.into(), ak supplied) against Loki's
//!    `zip2005.rs` quantum-recoverable `use_qsk` derivation, for the SAME fixed
//!    (group_ak, sk). They must differ, proving `zcash-sign generate` is NOT the
//!    recoverable path.

use std::collections::BTreeMap;

use loki_poc::zip2005;
use orchard::keys::{FullViewingKey, SpendingKey};
use reddsa_frost::frost::redpallas as frost;

/// Deliverable 3: audited ZF crates do a full 2-of-3 rerandomized roundtrip here.
#[test]
fn zf_crates_sign_2_of_3_rerandomized_and_verify() {
    let mut rng = rand_core::OsRng;

    let (shares, pubkeys) =
        frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, rng)
            .expect("2-of-3 trusted-dealer keygen (frost-core)");

    let wallets: BTreeMap<_, _> = shares
        .into_iter()
        .map(|(id, ss)| (id, frost::keys::KeyPackage::try_from(ss).unwrap()))
        .collect();
    let ids: Vec<_> = wallets.keys().copied().take(2).collect();

    // Round 1: two of the three members commit.
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for id in &ids {
        let (n, c) = frost::round1::commit(wallets[id].signing_share(), &mut rng);
        nonces.insert(*id, n);
        commitments.insert(*id, c);
    }

    // Randomizer = the Zcash tx `alpha` (frost-rerandomized).
    let (params, seed) = frost_rerandomized::RandomizedParams::new_from_commitments(
        pubkeys.verifying_key(),
        &commitments,
        rand_core::OsRng,
    )
    .expect("randomizer");

    let msg = b"loki zf-spine acceptance sighash";
    let pkg = frost::SigningPackage::new(commitments, msg);

    // Round 2: each selected member produces a partial signature.
    let mut sigshares = BTreeMap::new();
    for id in &ids {
        let share =
            frost_rerandomized::sign_with_randomizer_seed(&pkg, &nonces[id], &wallets[id], &seed)
                .expect("partial sig");
        sigshares.insert(*id, share);
    }

    // Aggregate 2 partials and verify under the randomized group key.
    let sig = frost_rerandomized::aggregate(&pkg, &sigshares, &pubkeys, &params)
        .expect("aggregate two-of-three");

    params
        .randomized_verifying_key()
        .verify(msg, &sig)
        .expect("group signature verifies under randomized key");

    eprintln!("[WS4] 2-of-3 rerandomized FROST (reddsa RedPallas) aggregate+verify OK");
}

/// Deliverable 1 (WS5): prove `zcash-sign generate` is the NON-recoverable path by
/// reproducing its derivation and showing it differs from Loki's `use_qsk` zip2005
/// for the SAME fixed (group_ak, sk).
#[test]
fn ws5_zcash_sign_generate_is_not_quantum_recoverable() {
    // Fixed inputs so the comparison is reproducible. Derive a canonical group_ak
    // from a 2-of-3 so it is a valid SpendValidatingKey encoding.
    let (_shares, pubkeys) = frost::keys::generate_with_dealer(
        3,
        2,
        frost::keys::IdentifierList::Default,
        rand_core::OsRng,
    )
    .expect("keygen for a real group_ak");
    let group_ak: [u8; 32] = pubkeys
        .verifying_key()
        .serialize()
        .expect("serialize group verifying key")
        .try_into()
        .expect("32-byte ak");

    // A fixed group secret `sk` fed to BOTH derivations.
    let sk_bytes = [42u8; 32];

    // --- Path A: Loki zip2005, ZIP-2005 use_qsk (quantum-recoverable) ---
    let loki_fvk = zip2005::frost_viewing_key(&group_ak, &sk_bytes)
        .expect("zip2005 FVK")
        .to_bytes();

    // --- Path B: reproduce `zcash-sign generate` exactly ---
    // zcash-sign calls orchard's
    //   from_sk_ak_incompatible_with_quantum_recoverability_and_will_be_removed(sk, ak)
    // which sets FVK { ak, nk: sk.into(), rivk: sk.into() }. Loki's orchard does not
    // export that FROST-only constructor, but `From<&SpendingKey>` uses the identical
    // `nk: sk.into(), rivk: sk.into()` derivation (orchard keys.rs). So build the
    // standard FVK from the same sk and splice the group ak into bytes[0..32] — the
    // byte-for-byte equivalent of the non-recoverable constructor.
    let sk = SpendingKey::from_bytes(sk_bytes).expect("valid spending key");
    let std_fvk = FullViewingKey::from(&sk).to_bytes(); // [ak_std ‖ nk ‖ rivk]
    let mut zcash_sign_fvk = std_fvk;
    zcash_sign_fvk[0..32].copy_from_slice(&group_ak); // ak := group_ak (as the ctor does)

    eprintln!("[WS5] group_ak      = {}", hex::encode(group_ak));
    eprintln!("[WS5] sk            = {}", hex::encode(sk_bytes));
    eprintln!("[WS5] zip2005  FVK  = {}", hex::encode(loki_fvk));
    eprintln!("[WS5] zcash-sign FVK= {}", hex::encode(zcash_sign_fvk));

    // ak slot identical (both place group_ak there); nk identical because zip2005's
    // nk = expand(sk,0x07) is exactly orchard's `sk.into()` nullifier derivation...
    assert_eq!(&loki_fvk[0..32], &zcash_sign_fvk[0..32], "ak slot shared");
    assert_eq!(&loki_fvk[32..64], &zcash_sign_fvk[32..64], "nk shared");
    // ...but RIVK differs: zip2005 routes it through qsk -> qk(blake3 derive_key)
    // -> expand(qk,0x0d, ak||nk), the use_qsk quantum-recoverable path; zcash-sign
    // uses orchard's plain `rivk = sk.into()`. That difference is the whole point.
    assert_ne!(
        &loki_fvk[64..96],
        &zcash_sign_fvk[64..96],
        "rivk differs: zip2005 qsk->qk->expand (use_qsk) vs orchard sk.into()"
    );
    assert_ne!(
        loki_fvk, zcash_sign_fvk,
        "zcash-sign generate is NOT the quantum-recoverable zip2005 FVK"
    );

    eprintln!(
        "[WS5] DETERMINATION: zcash-sign `generate` uses the non-recoverable \
         from_sk_ak_incompatible_with_quantum_recoverability constructor; \
         FVK bytes differ from Loki zip2005 use_qsk. Option B is NOT recoverable."
    );
}
