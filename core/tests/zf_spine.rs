use std::collections::BTreeMap;

use loki_poc::zip2005;
use orchard::keys::{FullViewingKey, SpendingKey};
use reddsa_frost::frost::redpallas as frost;

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
    .expect("randomizer");

    let msg = b"loki zf-spine acceptance sighash";
    let pkg = frost::SigningPackage::new(commitments, msg);

    let mut sigshares = BTreeMap::new();
    for id in &ids {
        let share =
            frost_rerandomized::sign_with_randomizer_seed(&pkg, &nonces[id], &wallets[id], &seed)
                .expect("partial sig");
        sigshares.insert(*id, share);
    }

    let sig = frost_rerandomized::aggregate(&pkg, &sigshares, &pubkeys, &params)
        .expect("aggregate two-of-three");

    params
        .randomized_verifying_key()
        .verify(msg, &sig)
        .expect("group signature verifies under randomized key");

    eprintln!("[WS4] 2-of-3 rerandomized FROST (reddsa RedPallas) aggregate+verify OK");
}

#[test]
fn ws5_zcash_sign_generate_is_not_quantum_recoverable() {
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

    let sk_bytes = [42u8; 32];

    let loki_fvk = zip2005::frost_viewing_key(&group_ak, &sk_bytes)
        .expect("zip2005 FVK")
        .to_bytes();

    let sk = SpendingKey::from_bytes(sk_bytes).expect("valid spending key");
    let std_fvk = FullViewingKey::from(&sk).to_bytes();
    let mut zcash_sign_fvk = std_fvk;
    zcash_sign_fvk[0..32].copy_from_slice(&group_ak);

    eprintln!("[WS5] group_ak      = {}", hex::encode(group_ak));
    eprintln!("[WS5] sk            = {}", hex::encode(sk_bytes));
    eprintln!("[WS5] zip2005  FVK  = {}", hex::encode(loki_fvk));
    eprintln!("[WS5] zcash-sign FVK= {}", hex::encode(zcash_sign_fvk));

    assert_eq!(&loki_fvk[0..32], &zcash_sign_fvk[0..32], "ak slot shared");
    assert_eq!(&loki_fvk[32..64], &zcash_sign_fvk[32..64], "nk shared");
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
