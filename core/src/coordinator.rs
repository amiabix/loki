#![cfg(test)]

use std::collections::BTreeMap;

use reddsa_frost::frost::redpallas as frost;

struct Group {
    packages: BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    public: frost::keys::PublicKeyPackage,
    ids: Vec<frost::Identifier>,
}

fn group() -> Group {
    let (shares, public) = frost::keys::generate_with_dealer(
        3,
        2,
        frost::keys::IdentifierList::Default,
        rand_core::OsRng,
    )
    .expect("2-of-3 keygen");
    let packages: BTreeMap<_, _> = shares
        .into_iter()
        .map(|(id, ss)| {
            (
                id,
                frost::keys::KeyPackage::try_from(ss).expect("key package"),
            )
        })
        .collect();
    let ids: Vec<_> = packages.keys().copied().collect();
    Group {
        packages,
        public,
        ids,
    }
}

fn commit_all(
    g: &Group,
    signers: &[frost::Identifier],
) -> (
    BTreeMap<frost::Identifier, frost::round1::SigningNonces>,
    BTreeMap<frost::Identifier, frost::round1::SigningCommitments>,
) {
    let mut rng = rand_core::OsRng;
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for id in signers {
        let (n, c) = frost::round1::commit(g.packages[id].signing_share(), &mut rng);
        commitments.insert(*id, c);
        nonces.insert(*id, n);
    }
    (nonces, commitments)
}

#[test]
fn co1_equivocation_does_not_aggregate() {
    let g = group();
    let signers = [g.ids[0], g.ids[1]];
    let (nonces, commitments) = commit_all(&g, &signers);
    let (params, seed) = frost_rerandomized::RandomizedParams::new_from_commitments(
        g.public.verifying_key(),
        &commitments,
        rand_core::OsRng,
    )
    .expect("library randomizer seed");

    let pkg_alice = frost::SigningPackage::new(commitments.clone(), b"pay alice 1");
    let pkg_carol = frost::SigningPackage::new(commitments.clone(), b"pay mallory 99");

    let s_alice = frost_rerandomized::sign_with_randomizer_seed(
        &pkg_alice,
        &nonces[&signers[0]],
        &g.packages[&signers[0]],
        &seed,
    )
    .expect("alice signs what she was shown");
    let s_carol = frost_rerandomized::sign_with_randomizer_seed(
        &pkg_carol,
        &nonces[&signers[1]],
        &g.packages[&signers[1]],
        &seed,
    )
    .expect("carol signs what she was shown");

    let shares: BTreeMap<_, _> = [(signers[0], s_alice), (signers[1], s_carol)].into();

    for pkg in [&pkg_alice, &pkg_carol] {
        assert!(
            frost_rerandomized::aggregate(pkg, &shares, &g.public, &params).is_err(),
            "equivocated shares must not aggregate",
        );
    }
}

#[test]
fn co2_one_share_is_not_enough() {
    let g = group();
    let signers = [g.ids[0], g.ids[1]];
    let (nonces, commitments) = commit_all(&g, &signers);
    let (params, seed) = frost_rerandomized::RandomizedParams::new_from_commitments(
        g.public.verifying_key(),
        &commitments,
        rand_core::OsRng,
    )
    .expect("library randomizer seed");
    let pkg = frost::SigningPackage::new(commitments, b"the-message");

    let only_one = frost_rerandomized::sign_with_randomizer_seed(
        &pkg,
        &nonces[&signers[0]],
        &g.packages[&signers[0]],
        &seed,
    )
    .expect("one signer signs");

    let shares: BTreeMap<_, _> = [(signers[0], only_one)].into();

    assert!(
        frost_rerandomized::aggregate(&pkg, &shares, &g.public, &params).is_err(),
        "a 2-of-3 group must not produce a signature from one share",
    );
}

#[test]
fn co3_two_leaked_shares_spend_without_their_owners() {
    let g = group();
    let signers = [g.ids[0], g.ids[1]];

    let stolen: BTreeMap<_, _> = signers
        .iter()
        .map(|id| (*id, g.packages[id].clone()))
        .collect();

    let mut rng = rand_core::OsRng;
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for (id, kp) in &stolen {
        let (n, c) = frost::round1::commit(kp.signing_share(), &mut rng);
        commitments.insert(*id, c);
        nonces.insert(*id, n);
    }

    let (params, seed) = frost_rerandomized::RandomizedParams::new_from_commitments(
        g.public.verifying_key(),
        &commitments,
        rand_core::OsRng,
    )
    .expect("library randomizer seed");
    let pkg = frost::SigningPackage::new(commitments, b"drain the account");
    let mut shares = BTreeMap::new();
    for (id, kp) in &stolen {
        let s = frost_rerandomized::sign_with_randomizer_seed(&pkg, &nonces[id], kp, &seed)
            .expect("sign");
        shares.insert(*id, s);
    }

    let sig = frost_rerandomized::aggregate(&pkg, &shares, &g.public, &params)
        .expect("two shares are a signature");

    params
        .randomized_verifying_key()
        .verify(pkg.message(), &sig)
        .expect("RECORDED: two leaked shares produce a signature the network accepts");
}

#[test]
fn co4_a_forged_share_is_rejected_and_the_culprit_named() {
    let g = group();
    let signers = [g.ids[0], g.ids[1]];
    let (nonces, commitments) = commit_all(&g, &signers);
    let (params, seed) = frost_rerandomized::RandomizedParams::new_from_commitments(
        g.public.verifying_key(),
        &commitments,
        rand_core::OsRng,
    )
    .expect("library randomizer seed");
    let pkg = frost::SigningPackage::new(commitments, b"the-message");

    let real = frost_rerandomized::sign_with_randomizer_seed(
        &pkg,
        &nonces[&signers[0]],
        &g.packages[&signers[0]],
        &seed,
    )
    .expect("alice signs");

    let forged =
        frost::round2::SignatureShare::deserialize(&real.serialize()).expect("a well-formed share");

    let shares: BTreeMap<_, _> = [(signers[0], real), (signers[1], forged)].into();

    let err = frost_rerandomized::aggregate(&pkg, &shares, &g.public, &params)
        .expect_err("a forged share must be rejected");
    let named = format!("{err:?}");
    assert!(
        named.contains("InvalidSignatureShare") || named.contains("culprit"),
        "the error should identify the bad share, got: {named}",
    );
}
