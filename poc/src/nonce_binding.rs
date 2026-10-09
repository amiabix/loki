//! Phase A: can a package-bound nonce remove the storage-rollback hole?
//!
//! G3 showed that a rolled-back browser profile re-uses a nonce and leaks the signing
//! share. The relay gate mitigates that; it does not close it. G3's own conclusion named
//! one relay-free fix, never tested: bind each nonce to the exact package at publication,
//! so replaying it can only reproduce the identical share.
//!
//! See NONCE-BINDING-PLAN.md. This file is Phase A, against real `reddsa` FROST rather
//! than G3's Schnorr stand-in, because the difficulty lives in a place the stand-in does
//! not model. In FROST a signer's share is
//!
//! ```text
//!     z_i = d_i + (e_i * rho_i) + (lambda_i * s_i * c)
//! ```
//!
//! where `rho_i` is a binding factor over the message AND the full commitment set. Two
//! shares over one `(d_i, e_i)` are dangerous whenever anything feeding `rho_i` or `c`
//! differs, which is a strictly larger set of conditions than "the message differed".
//!
//! ## What these tests do and do not prove
//!
//! They do NOT recover a key. `compute_group_commitment` and the challenge hash are
//! private in `frost-core`, so reconstructing `c` would mean reimplementing part of the
//! ciphersuite, and a reimplementation that silently diverged from the library would
//! prove nothing at all.
//!
//! The argument is split instead, with each half doing what it is actually good at:
//!
//! * **G3 already demonstrates the damage.** `g3/nonce-store.js::extractOnReuse` recovers
//!   a signing key outright from two shares over one nonce, and
//!   `restore-all-acknowledgers-lying` prints the recovered key on every run. That nonce
//!   reuse is catastrophic is established, not assumed.
//! * **These tests decide whether a scheme PRODUCES reuse**, against the real library.
//!
//! So the oracle here is byte identity, which is airtight in both directions:
//!
//! * replay yields a byte-identical share  -> the counterparty learns nothing new, safe
//! * replay yields a different share over the same commitment -> the reuse precondition
//!   from G3 is met, unsafe
//!
//! A test that asserts safety is only admissible because [`a2_baseline_reuse_is_detectable`]
//! first shows the oracle firing on a known-bad case in this same file.

#![cfg(test)]

use std::collections::BTreeMap;

use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use reddsa_frost::frost::redpallas as frost;

/// A 2-of-3 group with its key packages.
struct Group {
    packages: BTreeMap<frost::Identifier, frost::keys::KeyPackage>,
    ids: Vec<frost::Identifier>,
}

fn group() -> Group {
    let (shares, _public) = frost::keys::generate_with_dealer(
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
    let ids: Vec<_> = packages.keys().copied().take(2).collect();
    Group { packages, ids }
}

/// Scheme 1: a nonce pair derived deterministically from a seed and a package digest.
///
/// The signer's randomness is replaced by a stream keyed on what it is about to sign, so
/// re-running the same publication reproduces the same nonce and a different package
/// produces a different one. Only public API: `SigningNonces` is built through its normal
/// constructor with a seeded stream standing in for the OS RNG.
fn bound_nonces(
    share: &frost::keys::SigningShare,
    seed: &[u8; 32],
    package_digest: &[u8],
) -> frost::round1::SigningNonces {
    let mut h = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"loki-noncebind01")
        .to_state();
    h.update(seed);
    h.update(package_digest);
    let stream_seed: [u8; 32] = h.finalize().as_bytes().try_into().expect("32 bytes");
    frost::round1::SigningNonces::new(share, &mut ChaCha20Rng::from_seed(stream_seed))
}

fn alpha(byte: u8) -> frost_rerandomized::Randomizer<frost::PallasBlake2b512> {
    frost_rerandomized::Randomizer::deserialize(&[byte; 32]).expect("canonical scalar")
}

/// Produce one share under a deliberately fixed scalar to isolate nonce binding.
/// These adversarial tests vary the scalar independently of commitments; production
/// review reconstructs parameters and signs using the saved library-generated seed.
fn sign_one(
    g: &Group,
    me: &frost::Identifier,
    nonces: &frost::round1::SigningNonces,
    commitments: BTreeMap<frost::Identifier, frost::round1::SigningCommitments>,
    message: &[u8],
    a: frost_rerandomized::Randomizer<frost::PallasBlake2b512>,
) -> Vec<u8> {
    let pkg = frost::SigningPackage::new(commitments, message);
    #[allow(deprecated)] // Deliberately test independent scalar changes and nonce reuse.
    let share = frost_rerandomized::sign(&pkg, nonces, &g.packages[me], a).expect("sign");
    share.serialize()
}

fn commitment_bytes(n: &frost::round1::SigningNonces) -> Vec<u8> {
    n.commitments().serialize().expect("commitment serializes")
}

/// A.2 Baseline. The oracle has to fire on a known-bad case before any "safe" result in
/// this file counts for anything.
///
/// One nonce pair, two different messages, which is the classic reuse G3 shows recovers a
/// key outright. Here the point is narrower and is the precondition for that: the shares
/// differ while the published commitment is identical.
#[test]
fn a2_baseline_reuse_is_detectable() {
    let g = group();
    let (me, other) = (g.ids[0], g.ids[1]);

    let mut rng = rand_core::OsRng;
    let mine = frost::round1::SigningNonces::new(g.packages[&me].signing_share(), &mut rng);
    let theirs = frost::round1::SigningNonces::new(g.packages[&other].signing_share(), &mut rng);

    let set: BTreeMap<_, _> = [(me, *mine.commitments()), (other, *theirs.commitments())].into();

    let z1 = sign_one(&g, &me, &mine, set.clone(), b"pay alice 1", alpha(7));
    let z2 = sign_one(&g, &me, &mine, set, b"pay mallory 99", alpha(7));

    assert_ne!(
        z1, z2,
        "two messages over one nonce must give different shares"
    );
    assert_eq!(
        commitment_bytes(&mine),
        commitment_bytes(&mine),
        "the published commitment is the same in both runs, which is what makes this reuse",
    );
    // This is the shape G3's extractOnReuse turns into a recovered key.
}

/// A.3 Scheme 1, same package replayed.
///
/// The decisive safety case: a rolled-back device re-runs the identical publication. If
/// everything is byte-identical there is nothing new for a counterparty to learn, so the
/// rollback is harmless.
#[test]
fn a3_same_package_replay_is_byte_identical() {
    let g = group();
    let (me, other) = (g.ids[0], g.ids[1]);
    let seed = [11u8; 32];
    let digest = b"proposal-1|pair-AC|sighash-abc";

    // The co-signer is deterministic too, so the whole publication is reproducible.
    let theirs = bound_nonces(g.packages[&other].signing_share(), &[22u8; 32], digest);

    let first = bound_nonces(g.packages[&me].signing_share(), &seed, digest);
    let again = bound_nonces(g.packages[&me].signing_share(), &seed, digest);

    assert_eq!(
        commitment_bytes(&first),
        commitment_bytes(&again),
        "the same package must reproduce the same commitment",
    );

    let set: BTreeMap<_, _> = [(me, *first.commitments()), (other, *theirs.commitments())].into();
    let z1 = sign_one(&g, &me, &first, set.clone(), b"the-message", alpha(7));
    let z2 = sign_one(&g, &me, &again, set, b"the-message", alpha(7));

    assert_eq!(
        z1, z2,
        "replaying the same package must reproduce the same share"
    );
}

/// A.4 Scheme 1, a different package.
///
/// A rolled-back device asked to sign something else must not reach the same nonce, or
/// there is reuse to exploit.
#[test]
fn a4_a_different_package_changes_the_nonce() {
    let g = group();
    let me = g.ids[0];
    let seed = [11u8; 32];

    let a = bound_nonces(
        g.packages[&me].signing_share(),
        &seed,
        b"proposal-1|pair-AC",
    );
    let b = bound_nonces(
        g.packages[&me].signing_share(),
        &seed,
        b"proposal-2|pair-AC",
    );

    assert_ne!(
        commitment_bytes(&a),
        commitment_bytes(&b),
        "a different package must produce a different nonce, so there is no reuse",
    );
}

/// A.5 Scheme 1 under a re-committing co-signer. The step that decides whether binding to
/// the package digest alone is sufficient.
///
/// Our nonce is bound to the package, so it does not move. But `rho` covers the whole
/// commitment set, so if the other signer publishes a fresh commitment the binding factor
/// changes underneath us. Same nonce, different share: the G3 reuse precondition, reached
/// without the message changing at all.
#[test]
fn a5_a_recommitting_cosigner_defeats_package_binding() {
    let g = group();
    let (me, other) = (g.ids[0], g.ids[1]);
    let digest = b"proposal-1|pair-AC|sighash-abc";

    // Bound, and identical across both runs by construction.
    let mine = bound_nonces(g.packages[&me].signing_share(), &[11u8; 32], digest);

    // The co-signer commits twice. Nothing stops them: a commitment is cheap and public.
    let mut rng = rand_core::OsRng;
    let theirs_1 = frost::round1::SigningNonces::new(g.packages[&other].signing_share(), &mut rng);
    let theirs_2 = frost::round1::SigningNonces::new(g.packages[&other].signing_share(), &mut rng);
    assert_ne!(commitment_bytes(&theirs_1), commitment_bytes(&theirs_2));

    let set_1: BTreeMap<_, _> =
        [(me, *mine.commitments()), (other, *theirs_1.commitments())].into();
    let set_2: BTreeMap<_, _> =
        [(me, *mine.commitments()), (other, *theirs_2.commitments())].into();

    // Same package digest, same message, same alpha, same nonce. Only the co-signer's
    // commitment differs.
    let z1 = sign_one(&g, &me, &mine, set_1, b"the-message", alpha(7));
    let z2 = sign_one(&g, &me, &mine, set_2, b"the-message", alpha(7));

    assert_ne!(
        z1, z2,
        "RECORDED RESULT: binding the nonce to the package digest alone is NOT sufficient. \
         The co-signer re-committed, the binding factor moved, and the same nonce produced \
         two different shares. That is the precondition G3 turns into a recovered key.",
    );
}

/// A.6 Scheme 2, ordered binding. Does committing in a fixed order break the circle?
///
/// The obvious repair for A.5 is to bind the nonce to the co-signer's commitment as well,
/// so a re-commitment moves our nonce instead of only moving `rho`. That is circular if
/// both parties do it, since each would depend on the other's commitment. A fixed order
/// looks like a way out: the lower identifier commits first bound to the package alone,
/// and the higher binds to the package AND the lower's commitment.
///
/// This test runs both halves of that scheme and shows the asymmetry it produces.
#[test]
fn a6_ordered_binding_protects_only_the_second_signer() {
    let g = group();
    let (lo, hi) = (g.ids[0], g.ids[1]);
    let digest = b"proposal-1|pair-AC|sighash-abc";

    // The lower identifier binds to the package only: it has nothing else yet.
    let lo_n = bound_nonces(g.packages[&lo].signing_share(), &[11u8; 32], digest);

    // The higher binds to the package AND what the lower published.
    let mut ctx_1 = digest.to_vec();
    ctx_1.extend_from_slice(&commitment_bytes(&lo_n));
    let hi_n_1 = bound_nonces(g.packages[&hi].signing_share(), &[22u8; 32], &ctx_1);

    // ── half one: the LOWER re-commits. The higher is protected. ────────────
    let lo_n_alt = bound_nonces(g.packages[&lo].signing_share(), &[99u8; 32], digest);
    let mut ctx_2 = digest.to_vec();
    ctx_2.extend_from_slice(&commitment_bytes(&lo_n_alt));
    let hi_n_2 = bound_nonces(g.packages[&hi].signing_share(), &[22u8; 32], &ctx_2);

    assert_ne!(
        commitment_bytes(&hi_n_1),
        commitment_bytes(&hi_n_2),
        "the second signer's nonce moves when the first re-commits, so it is never reused",
    );

    // ── half two: the HIGHER re-commits. The lower is NOT protected. ────────
    let hi_other = {
        let mut c = ctx_1.clone();
        c.extend_from_slice(b"|a second commitment from the same signer");
        bound_nonces(g.packages[&hi].signing_share(), &[22u8; 32], &c)
    };
    assert_ne!(commitment_bytes(&hi_n_1), commitment_bytes(&hi_other));

    let set_1: BTreeMap<_, _> = [(lo, *lo_n.commitments()), (hi, *hi_n_1.commitments())].into();
    let set_2: BTreeMap<_, _> = [(lo, *lo_n.commitments()), (hi, *hi_other.commitments())].into();

    let z1 = sign_one(&g, &lo, &lo_n, set_1, b"the-message", alpha(7));
    let z2 = sign_one(&g, &lo, &lo_n, set_2, b"the-message", alpha(7));

    assert_ne!(
        z1, z2,
        "RECORDED RESULT: ordering does not close the hole, it only moves it. The first \
         signer binds to the package alone, because nothing else exists yet, so a \
         re-committing second signer still moves its binding factor while its nonce stays \
         fixed. Same nonce, two shares: the G3 reuse precondition, now for the first \
         signer instead of the second.",
    );
}
