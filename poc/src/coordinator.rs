//! What can a coordinator actually do, and what does a leaked share cost?
//!
//! These two questions are one question. `nonce-reuse-drill.sh` showed that the party who
//! rebuilds the candidate is what makes a nonce leak reachable at all: moving the
//! commitment set alone is caught by the `rk` check, and only becomes dangerous when the
//! candidate is rebuilt to match. That party is the coordinator.
//!
//! So this module establishes two things against real `reddsa` FROST:
//!
//! * **the coordinator's limits** — what it cannot do, so the residual risk is the part
//!   that is left rather than the part nobody looked at;
//! * **the blast radius** — what a leaked share is actually worth, which decides how
//!   urgent everything else is.
//!
//! None of this is about the Zcash layer. `verify.rs` and `tamper-tests.sh` already cover
//! what a signer checks about a *payment*. This is about the signing protocol itself.

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

/// Round 1 for a chosen set of signers.
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

/// CO.1 A coordinator cannot show two signers different work and combine the results.
///
/// Equivocation is the classic coordinator attack: tell Alice she is signing one thing and
/// Carol another, then assemble a signature neither agreed to. In FROST the signing
/// package is an input to every share, so shares produced under different packages are not
/// combinable. This asserts that the library actually enforces it rather than assuming it.
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

    // The coordinator builds two packages over the same commitments, differing only in
    // the message, and hands one to each signer.
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

    // Whichever package the coordinator presents, one of the two shares was made under a
    // different one, so aggregation cannot succeed.
    for pkg in [&pkg_alice, &pkg_carol] {
        assert!(
            frost_rerandomized::aggregate(pkg, &shares, &g.public, &params).is_err(),
            "equivocated shares must not aggregate",
        );
    }
}

/// CO.2 A coordinator cannot reach the threshold on its own.
///
/// The floor the whole design rests on: one share is not a signature. If this ever passed,
/// nothing else in this file would matter.
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

/// CO.3 The blast radius: two leaked shares spend without either owner present.
///
/// This is what decides how urgent the nonce work is. `nonce-reuse-drill.sh` shows a
/// rollback plus a rebuilt candidate yields a signer's long-term share. The question is
/// what one of those is worth.
///
/// Here the holder of two signing shares produces a valid group signature with no
/// cooperation from anyone. It verifies under the group key, so the chain would accept it.
///
/// Read together with CO.2 that gives the real answer: **one** rolled-back member is
/// survivable, because the attacker holds one share and one share signs nothing. **Two**
/// is total loss. A malicious co-signer counts as one of the two for free.
#[test]
fn co3_two_leaked_shares_spend_without_their_owners() {
    let g = group();
    let signers = [g.ids[0], g.ids[1]];

    // The attacker holds two key packages and nothing else: no device, no approval, no
    // cooperation from the owners.
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

/// CO.4 A coordinator cannot fabricate a share for a member who did not sign.
///
/// If it could, the threshold would be decorative: a coordinator plus one honest signer
/// would be enough. `aggregate` verifies each share against that member's verifying share,
/// so a forged one is rejected and the culprit is named rather than silently producing a
/// signature that fails later on chain.
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

    // The coordinator invents carol's share by reusing alice's bytes.
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
