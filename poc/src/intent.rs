//! The payment intent, its proposal ID, and the per-pair `alpha` derivation.
//!
//! # Serialization and domain separation, stated exactly
//!
//! The brief requires both to be documented, because a signer has to recompute them
//! from the same bytes the proposer used.
//!
//! **`canonical_cbor(intent)`** is a CBOR *definite-length array* holding the fields in
//! the declaration order of [`Intent`]. An array, not a map: CBOR map ordering is not
//! canonical by default in `ciborium`, and a fixed array removes the question. Integers
//! are CBOR unsigned, byte strings are CBOR byte strings. No transaction randomness is
//! included, so the three candidates AB, AC and BC share one proposal ID.
//!
//! ```text
//! proposal_id = BLAKE2b-256(personal = "Loki_intent_v1", canonical_cbor(intent))
//! seed        = BLAKE2b-256(personal = "Loki_alpha_v1",
//!                           proposal_id || id_lo || id_hi || spend_index_be32)
//! alpha       = Randomizer::regenerate_from_seed_and_commitments(seed, commitments)
//! ```
//!
//! `id_lo`/`id_hi` are the two members' serialized FROST identifiers, ordered by their
//! byte encoding. `spend_index_be32` is the spend's index within the transaction, big
//! endian.
//!
//! # An assumption, not a result
//!
//! `frost-rerandomized` generates the randomizer seed itself in
//! `Randomizer::new_from_commitments`, and its own documentation says it is "strongly
//! suggested to not attempt generating the randomizer seed yourself". This module does
//! generate it, from the proposal, so that all three candidates are reproducible by every
//! signer without trusting a coordinator's RNG.
//!
//! The library's derivation from seed to alpha is unchanged: only the seed's origin
//! differs. **This is a research assumption pending O1 review, not a security result
//! from the crate.**

use blake2b_simd::Params;
use reddsa_frost::frost::redpallas as frost;
use std::collections::BTreeMap;

/// Where change goes. G1 has exactly one policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChangePolicy {
    /// Back to the vault's own internal address.
    VaultInternal,
}

impl ChangePolicy {
    fn as_u64(self) -> u64 {
        match self {
            ChangePolicy::VaultInternal => 0,
        }
    }
}

/// One payment intent. Every field a signer checks lives here, and nothing else does.
///
/// Field order is the canonical CBOR array order; do not reorder without bumping the
/// `Loki_intent_v1` domain string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Intent {
    /// Serialized FROST identifier of the proposing member.
    pub proposer: Vec<u8>,
    /// Chain height the intent was created at.
    pub created_height: u32,
    /// Nullifiers of the inputs being spent, in the order they appear in the transaction.
    pub input_nullifiers: Vec<[u8; 32]>,
    /// Raw Orchard address bytes of the recipient.
    pub recipient: Vec<u8>,
    /// Payment amount, zatoshis.
    pub amount_zat: u64,
    /// Memo bytes. G1 requires this to be nonempty.
    pub memo: Vec<u8>,
    /// Where change goes.
    pub change_policy: ChangePolicy,
    /// Exact fee, zatoshis. Builder-calculated ZIP 317, fixed into the intent.
    pub fee_zat: u64,
    /// Exact change amount, zatoshis.
    pub change_zat: u64,
    /// Expiry height, rounded up to a 1,152-block boundary.
    pub expiry_height: u32,
}

impl Intent {
    /// The canonical CBOR encoding described in the module docs.
    pub fn canonical_cbor(&self) -> Vec<u8> {
        use ciborium::value::Value;

        let v = Value::Array(vec![
            Value::Bytes(self.proposer.clone()),
            Value::Integer(self.created_height.into()),
            Value::Array(
                self.input_nullifiers
                    .iter()
                    .map(|n| Value::Bytes(n.to_vec()))
                    .collect(),
            ),
            Value::Bytes(self.recipient.clone()),
            Value::Integer(self.amount_zat.into()),
            Value::Bytes(self.memo.clone()),
            Value::Integer(self.change_policy.as_u64().into()),
            Value::Integer(self.fee_zat.into()),
            Value::Integer(self.change_zat.into()),
            Value::Integer(self.expiry_height.into()),
        ]);

        let mut out = Vec::new();
        ciborium::into_writer(&v, &mut out).expect("writing to a Vec cannot fail");
        out
    }

    /// `BLAKE2b-256(personal = "Loki_intent_v1", canonical_cbor(intent))`.
    ///
    /// Carries no transaction randomness, so AB, AC and BC share it.
    pub fn proposal_id(&self) -> [u8; 32] {
        Params::new()
            .hash_length(32)
            .personal(b"Loki_intent_v1")
            .hash(&self.canonical_cbor())
            .as_bytes()
            .try_into()
            .expect("hash_length(32)")
    }
}

/// `BLAKE2b-256(personal = "Loki_alpha_v1", proposal_id || id_lo || id_hi || index_be32)`.
///
/// The pair is sorted by serialized identifier so both members compute the same seed
/// regardless of who proposed.
pub fn alpha_seed(
    proposal_id: &[u8; 32],
    pair: (&frost::Identifier, &frost::Identifier),
    spend_index: u32,
) -> [u8; 32] {
    let mut a = pair.0.serialize();
    let mut b = pair.1.serialize();
    if a > b {
        core::mem::swap(&mut a, &mut b);
    }

    let mut h = Params::new()
        .hash_length(32)
        .personal(b"Loki_alpha_v1")
        .to_state();
    h.update(proposal_id);
    h.update(&a);
    h.update(&b);
    h.update(&spend_index.to_be_bytes());

    h.finalize().as_bytes().try_into().expect("hash_length(32)")
}

/// Derive this candidate's `alpha` with the pinned library, from our seed and that
/// pair's commitments.
///
/// Uses `regenerate_from_seed_and_commitments`, **not** `new_from_commitments`: the seed
/// is ours, derived from the proposal, so every signer can recompute it. See the module
/// docs for why that is an assumption rather than a result.
pub fn alpha_for_candidate(
    seed: &[u8; 32],
    commitments: &BTreeMap<frost::Identifier, frost::round1::SigningCommitments>,
) -> Result<frost_rerandomized::Randomizer<frost::PallasBlake2b512>, frost::Error> {
    frost_rerandomized::Randomizer::regenerate_from_seed_and_commitments(seed, commitments)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent() -> Intent {
        Intent {
            proposer: vec![1u8; 32],
            created_height: 100,
            input_nullifiers: vec![[7u8; 32]],
            recipient: vec![9u8; 43],
            amount_zat: 40_000_000,
            memo: b"loki g1-tx".to_vec(),
            change_policy: ChangePolicy::VaultInternal,
            fee_zat: 15_000,
            change_zat: 59_985_000,
            expiry_height: 1_152,
        }
    }

    /// The proposal ID is a pure function of the intent: no randomness, so all three
    /// candidates share it.
    #[test]
    fn c3_proposal_id_is_deterministic() {
        assert_eq!(intent().proposal_id(), intent().proposal_id());
    }

    /// And it is sensitive to every field a signer is supposed to check.
    #[test]
    fn c3_proposal_id_changes_with_every_checked_field() {
        let base = intent().proposal_id();

        let m = |f: &dyn Fn(&mut Intent)| {
            let mut i = intent();
            f(&mut i);
            assert_ne!(i.proposal_id(), base);
        };

        m(&|i| i.amount_zat += 1);
        m(&|i| i.fee_zat += 1);
        m(&|i| i.change_zat += 1);
        m(&|i| i.expiry_height += 1);
        m(&|i| i.created_height += 1);
        m(&|i| i.memo.push(b'!'));
        m(&|i| i.recipient[0] ^= 1);
        m(&|i| i.input_nullifiers[0][0] ^= 1);
        m(&|i| i.proposer[0] ^= 1);
    }

    /// The seed depends on the pair but not on the order the pair is written in.
    #[test]
    fn c3_alpha_seed_is_pair_sorted_and_index_sensitive() {
        let pid = intent().proposal_id();
        let a: frost::Identifier = 1u16.try_into().unwrap();
        let b: frost::Identifier = 2u16.try_into().unwrap();
        let c: frost::Identifier = 3u16.try_into().unwrap();

        assert_eq!(
            alpha_seed(&pid, (&a, &b), 0),
            alpha_seed(&pid, (&b, &a), 0),
            "sorted: AB and BA are the same candidate"
        );
        assert_ne!(alpha_seed(&pid, (&a, &b), 0), alpha_seed(&pid, (&a, &c), 0));
        assert_ne!(alpha_seed(&pid, (&a, &b), 0), alpha_seed(&pid, (&a, &b), 1));
    }

    /// Each candidate gets a distinct alpha, and a signer recomputes it exactly.
    #[test]
    fn c3_each_pair_derives_a_distinct_alpha_that_a_signer_can_recompute() {
        let mut rng = rand_core::OsRng;
        let (shares, _pub) =
            frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, rng)
                .unwrap();

        let packages: BTreeMap<_, _> = shares
            .into_iter()
            .map(|(id, ss)| (id, frost::keys::KeyPackage::try_from(ss).unwrap()))
            .collect();
        let ids: Vec<_> = packages.keys().copied().collect();
        let pid = intent().proposal_id();

        let mut alphas = Vec::new();
        for (x, y) in [(0, 1), (0, 2), (1, 2)] {
            let mut commitments = BTreeMap::new();
            for k in [x, y] {
                let (_n, c) = frost::round1::commit(packages[&ids[k]].signing_share(), &mut rng);
                commitments.insert(ids[k], c);
            }

            let seed = alpha_seed(&pid, (&ids[x], &ids[y]), 0);
            let alpha = alpha_for_candidate(&seed, &commitments).unwrap();

            // The signer recomputes from the same inputs and must agree.
            let recomputed = alpha_for_candidate(&seed, &commitments).unwrap();
            assert_eq!(alpha.serialize(), recomputed.serialize());

            alphas.push(alpha.serialize());
        }

        assert_ne!(alphas[0], alphas[1]);
        assert_ne!(alphas[1], alphas[2]);
        assert_ne!(alphas[0], alphas[2]);
    }
}
