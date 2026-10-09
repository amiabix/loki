//! Checkpoint 3: build the three unproved pair candidates from one payment intent.
//!
//! Each candidate spends the same note and pays the same recipient the same amount with
//! the same memo, fee, change and expiry. What differs is the pair that will sign it, and
//! therefore the `alpha` derived for that pair, and therefore the `rk` in the spend.
//!
//! Every candidate is built with the anchor and witness **absent**. They are installed
//! after signing, which is the property G1-TX exists to test.

use orchard::{keys::FullViewingKey, Note};
use pasta_curves::pallas;
use zcash_primitives::transaction::{
    builder::{BundlePadding, DeferredPcztBuilder},
    fees::zip317::FeeRule,
};
use zcash_protocol::{
    consensus::{BlockHeight, Parameters},
    memo::MemoBytes,
    value::Zatoshis,
};

/// Regtest consensus parameters, matching the THS regtest chain: every upgrade
/// active from height 1.
#[derive(Clone)]
pub struct Regtest;

impl Parameters for Regtest {
    fn network_type(&self) -> zcash_protocol::consensus::NetworkType {
        zcash_protocol::consensus::NetworkType::Regtest
    }

    /// Everything up to and including NU6.3 is active from height 1; nothing later is.
    ///
    /// This must match the active THS consensus branch. Activating NU7 here too
    /// would make `BranchId::for_height` pick a later branch than the node accepts, and
    /// the transaction is rejected with "incorrect consensus branch id" only at
    /// broadcast, after proving.
    fn activation_height(
        &self,
        nu: zcash_protocol::consensus::NetworkUpgrade,
    ) -> Option<BlockHeight> {
        use zcash_protocol::consensus::NetworkUpgrade::*;
        match nu {
            Overwinter | Sapling | Blossom | Heartwood | Canopy | Nu5 | Nu6 | Nu6_1 | Nu6_2
            | Nu6_3 => Some(BlockHeight::from_u32(1)),
            _ => None,
        }
    }
}

/// Convert a FROST randomizer's canonical 32-byte encoding into the builder's scalar
/// type, rejecting anything noncanonical.
///
/// The two halves of the graph use different `pasta_curves` majors, so this crossing is
/// by bytes and is checked on arrival (`DEPENDENCIES.md` finding F3).
pub fn alpha_from_canonical_bytes(bytes: &[u8; 32]) -> Option<pallas::Scalar> {
    use ff_zp::PrimeField;
    Option::from(pallas::Scalar::from_repr(*bytes))
}

/// What a candidate needs besides the intent.
pub struct CandidateInputs<'a> {
    pub vault_fvk: &'a FullViewingKey,
    /// The notes to spend. One Orchard action each, so each one needs its own
    /// randomiser and, later, its own FROST signature.
    pub notes: Vec<Note>,
    pub recipient: orchard::Address,
    pub amount: Zatoshis,
    pub memo: MemoBytes,
    pub change: Zatoshis,
    pub target_height: u32,
    pub expiry_height: u32,
}

/// Ask the builder what ZIP 317 fee this transaction shape costs.
///
/// The intent fixes the fee, so it has to come from the builder rather than a constant.
/// All three candidates have the same shape, so they share one fee.
pub fn quote_fee<P: Parameters + Clone>(
    params: &P,
    inputs: &CandidateInputs<'_>,
) -> Result<Zatoshis, String> {
    type Fe = zcash_primitives::transaction::fees::zip317::FeeError;

    let mut builder = DeferredPcztBuilder::new::<Fe>(
        params.clone(),
        BlockHeight::from_u32(inputs.target_height),
        BundlePadding::DEFAULT,
        BundlePadding::DEFAULT,
    )
    .map_err(|e| format!("deferred builder: {e:?}"))?;

    // Every note is its own action, and ZIP 317 prices by action count, so the quote has
    // to include them all or the fee comes out too low.
    for note in &inputs.notes {
        builder
            .add_ironwood_spend::<Fe>(inputs.vault_fvk.clone(), *note)
            .map_err(|e| format!("quote spend: {e:?}"))?;
    }
    builder
        .add_ironwood_output::<Fe>(None, inputs.recipient, inputs.amount, inputs.memo.clone())
        .map_err(|e| format!("quote output: {e:?}"))?;
    builder
        .add_ironwood_output::<Fe>(
            None,
            inputs
                .vault_fvk
                .address_at(0u64, orchard::keys::Scope::Internal),
            Zatoshis::ZERO,
            MemoBytes::empty(),
        )
        .map_err(|e| format!("quote change: {e:?}"))?;

    builder
        .get_fee(&FeeRule::standard())
        .map_err(|e| format!("get_fee: {e:?}"))
}

/// Build one unproved candidate under a specific `alpha`.
///
/// Returns the PCZT parts the Creator role turns into a PCZT. The spend carries no
/// witness and the bundle no anchor; `rk` is already committed to `alpha`.
pub fn build_candidate<P: Parameters + Clone>(
    params: &P,
    inputs: &CandidateInputs<'_>,
    alphas: &[pallas::Scalar],
    rng: impl rand_core_zp::CryptoRng,
) -> Result<zcash_primitives::transaction::builder::PcztResult<P>, String> {
    let mut builder =
        DeferredPcztBuilder::new::<zcash_primitives::transaction::fees::zip317::FeeError>(
            params.clone(),
            BlockHeight::from_u32(inputs.target_height),
            BundlePadding::DEFAULT,
            BundlePadding::DEFAULT,
        )
        .map_err(|e| format!("deferred builder: {e:?}"))?
        .with_expiry_height(BlockHeight::from_u32(inputs.expiry_height));

    // Each spend carries its own alpha and no witness. One alpha per note: every spend
    // becomes its own Orchard action with its own `rk`, so they cannot share one.
    if alphas.len() != inputs.notes.len() {
        return Err(format!(
            "{} notes but {} randomisers; each spend needs exactly one",
            inputs.notes.len(),
            alphas.len(),
        ));
    }
    for (note, alpha) in inputs.notes.iter().zip(alphas) {
        builder
            .add_ironwood_spend_with_alpha::<zcash_primitives::transaction::fees::zip317::FeeError>(
                inputs.vault_fvk.clone(),
                *note,
                *alpha,
            )
            .map_err(|e| format!("add ironwood spend: {e:?}"))?;
    }

    builder
        .add_ironwood_output::<zcash_primitives::transaction::fees::zip317::FeeError>(
            None,
            inputs.recipient,
            inputs.amount,
            inputs.memo.clone(),
        )
        .map_err(|e| format!("add ironwood output: {e:?}"))?;

    // Change goes back to the vault's own address, which is the only policy G1 has.
    builder
        .add_ironwood_output::<zcash_primitives::transaction::fees::zip317::FeeError>(
            None,
            inputs
                .vault_fvk
                .address_at(0u64, orchard::keys::Scope::Internal),
            inputs.change,
            MemoBytes::empty(),
        )
        .map_err(|e| format!("add change output: {e:?}"))?;

    builder
        .build_for_pczt(rng, &FeeRule::standard())
        .map_err(|e| format!("build_for_pczt: {e:?}"))
}

/// TEST-ONLY: build a candidate whose change may be sent somewhere other than the vault.
///
/// `build_candidate` always sends change to the vault's own internal address, which is
/// the honest behaviour. The tamper harness needs to produce the dishonest variant so the
/// signer's change-address check has something real to refuse.
pub fn build_tampered<P: Parameters + Clone>(
    params: &P,
    inputs: &CandidateInputs<'_>,
    alpha: pallas::Scalar,
    change_to_vault: bool,
    rng: impl rand_core_zp::CryptoRng,
) -> Result<zcash_primitives::transaction::builder::PcztResult<P>, String> {
    type Fe = zcash_primitives::transaction::fees::zip317::FeeError;

    let mut builder = DeferredPcztBuilder::new::<Fe>(
        params.clone(),
        BlockHeight::from_u32(inputs.target_height),
        BundlePadding::DEFAULT,
        BundlePadding::DEFAULT,
    )
    .map_err(|e| format!("deferred builder: {e:?}"))?
    .with_expiry_height(BlockHeight::from_u32(inputs.expiry_height));

    builder
        .add_ironwood_spend_with_alpha::<Fe>(inputs.vault_fvk.clone(), inputs.notes[0], alpha)
        .map_err(|e| format!("add ironwood spend: {e:?}"))?;

    builder
        .add_ironwood_output::<Fe>(None, inputs.recipient, inputs.amount, inputs.memo.clone())
        .map_err(|e| format!("add ironwood output: {e:?}"))?;

    let change_addr = if change_to_vault {
        inputs
            .vault_fvk
            .address_at(0u64, orchard::keys::Scope::Internal)
    } else {
        // Somewhere else entirely: still the vault's key, but an external diversifier the
        // intent's change policy does not name.
        inputs
            .vault_fvk
            .address_at(11u64, orchard::keys::Scope::External)
    };

    builder
        .add_ironwood_output::<Fe>(None, change_addr, inputs.change, MemoBytes::empty())
        .map_err(|e| format!("add change output: {e:?}"))?;

    builder
        .build_for_pczt(rng, &FeeRule::standard())
        .map_err(|e| format!("build_for_pczt: {e:?}"))
}

/// TEST-ONLY: a transparent PCZT bundle carrying one output.
///
/// `DeferredPcztBuilder` has no transparent methods, so a forbidden-pool candidate cannot
/// be built the ordinary way. It can still be *constructed*: `PcztParts.transparent` is a
/// public field and `zcash_transparent::pczt::Bundle::parse` is a public constructor, so
/// the component can be grafted onto an otherwise honest candidate. The result will never
/// prove or mine, which is the point: the signer has to refuse it before the prover is
/// ever reached.
pub fn forbidden_transparent_bundle() -> Result<zcash_transparent::pczt::Bundle, String> {
    use std::collections::BTreeMap;
    use zcash_transparent::pczt::{Bundle, Output};

    // P2PKH to an all-0x11 hash. The script only has to parse.
    let mut script = vec![0x76u8, 0xa9, 0x14];
    script.extend_from_slice(&[0x11u8; 20]);
    script.extend_from_slice(&[0x88u8, 0xac]);

    let output = Output::parse(0, script, None, BTreeMap::new(), None, BTreeMap::new())
        .map_err(|e| format!("transparent output: {e:?}"))?;

    Bundle::parse(Vec::new(), vec![output]).map_err(|e| format!("transparent bundle: {e:?}"))
}

/// TEST-ONLY: a Sapling PCZT bundle carrying one output. See
/// [`forbidden_transparent_bundle`] for why this is constructed rather than built.
///
/// `cv` has to be a real non-small-order point, so it is derived properly; everything
/// else is the smallest value that parses.
pub fn forbidden_sapling_bundle() -> Result<sapling_crypto::pczt::Bundle, String> {
    use sapling_crypto::{
        pczt::{Bundle, Output},
        value::{NoteValue, ValueCommitTrapdoor},
    };
    use std::collections::BTreeMap;

    // rcv = 1, the smallest canonical nonzero trapdoor. A zero trapdoor on a zero value
    // would give the identity, which `Output::parse` rejects as small order.
    let mut rcv_bytes = [0u8; 32];
    rcv_bytes[0] = 1;
    let rcv = ValueCommitTrapdoor::from_bytes(rcv_bytes)
        .into_option()
        .ok_or("rcv")?;
    let cv = sapling_crypto::value::ValueCommitment::derive(NoteValue::from_raw(0), rcv);

    let output = Output::parse(
        cv.to_bytes(),
        [0u8; 32], // cmu: the canonical zero field element parses
        [0u8; 32], // ephemeral_key: opaque bytes
        vec![0u8; 580],
        vec![0u8; 80],
        None,            // zkproof: this candidate is never meant to prove
        None,            // recipient
        None,            // value
        None,            // rseed
        Some(rcv_bytes), // rcv: the IO Finalizer needs it to derive bsk
        None,            // ock
        None,            // zip32_derivation
        None,            // user_address
        BTreeMap::new(),
    )
    .map_err(|e| format!("sapling output: {e:?}"))?;

    Bundle::parse(
        Vec::new(),
        vec![output],
        0,
        sapling_crypto::Anchor::empty_tree().to_bytes(),
        None,
    )
    .map_err(|e| format!("sapling bundle: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{intent::*, zip2005};
    use reddsa_frost::frost::redpallas as frost;
    use std::collections::BTreeMap;

    /// A real group verifying key with the proposed ZIP 2005 viewing-key derivation.
    fn a_test_fvk() -> FullViewingKey {
        let (_, public) = frost::keys::generate_with_dealer(
            3,
            2,
            frost::keys::IdentifierList::Default,
            rand_core::OsRng,
        )
        .expect("keygen");
        let ak: [u8; 32] = public
            .verifying_key()
            .serialize()
            .expect("vk")
            .as_slice()
            .try_into()
            .expect("32 bytes");
        zip2005::frost_viewing_key(&ak, &[42u8; 32]).expect("a derived test fvk")
    }

    /// A vault note of a chosen value. `seed` distinguishes notes: rho must differ or
    /// two notes would be the same note.
    fn vault_note_of(fvk: &FullViewingKey, value: u64, seed: u8) -> Note {
        use orchard::{
            note::{RandomSeed, Rho},
            value::NoteValue,
            NoteVersion,
        };
        let rho = Rho::from_bytes(&[seed.wrapping_add(1); 32]).unwrap();
        let rseed = RandomSeed::from_bytes([seed.wrapping_add(2); 32], &rho).unwrap();
        Note::from_parts(
            fvk.address_at(0u64, orchard::keys::Scope::External),
            NoteValue::from_raw(value),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .unwrap()
    }

    /// A candidate spending two notes must produce two Ironwood spend actions, each with
    /// its own `rk`, because each one needs its own FROST signature later.
    #[test]
    fn two_notes_become_two_spends_with_distinct_rk() {
        let fvk = a_test_fvk();
        let notes = vec![
            vault_note_of(&fvk, 625_000_000, 10),
            vault_note_of(&fvk, 100_000_000, 20),
        ];
        let total: u64 = notes.iter().map(|n| n.value().inner()).sum();

        let mut inputs = CandidateInputs {
            vault_fvk: &fvk,
            notes,
            recipient: fvk.address_at(7u64, orchard::keys::Scope::External),
            amount: Zatoshis::const_from_u64(700_000_000),
            memo: MemoBytes::empty(),
            change: Zatoshis::ZERO,
            target_height: 100,
            expiry_height: 1_152,
        };
        let fee = quote_fee(&Regtest, &inputs).expect("a fee for two spends");
        inputs.change = Zatoshis::from_u64(total - 700_000_000 - u64::from(fee)).expect("change");

        let a1 = alpha_from_canonical_bytes(&[3u8; 32]).expect("alpha");
        let a2 = alpha_from_canonical_bytes(&[5u8; 32]).expect("alpha");
        let built = build_candidate(
            &Regtest,
            &inputs,
            &[a1, a2],
            rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng),
        );
        let built = match built {
            Ok(b) => b,
            Err(e) => panic!("a two-input candidate must build: {e}"),
        };

        let bundle = built.pczt_parts.ironwood.expect("an ironwood bundle");
        let real: Vec<_> = bundle
            .actions()
            .iter()
            .filter(|a| a.spend().value().map(|v| v.inner() > 0).unwrap_or(false))
            .collect();
        assert_eq!(real.len(), 2, "two notes must give two real spend actions");

        let rk0 = <[u8; 32]>::from(real[0].spend().rk());
        let rk1 = <[u8; 32]>::from(real[1].spend().rk());
        assert_ne!(
            rk0, rk1,
            "each spend is randomised separately, so rk must differ"
        );
    }

    /// One randomiser per note. Getting this wrong would silently reuse a randomiser
    /// across two actions.
    #[test]
    fn the_randomiser_count_must_match_the_note_count() {
        let fvk = a_test_fvk();
        let inputs = CandidateInputs {
            vault_fvk: &fvk,
            notes: vec![
                vault_note_of(&fvk, 625_000_000, 10),
                vault_note_of(&fvk, 1_000, 20),
            ],
            recipient: fvk.address_at(7u64, orchard::keys::Scope::External),
            amount: Zatoshis::const_from_u64(1_000),
            memo: MemoBytes::empty(),
            change: Zatoshis::ZERO,
            target_height: 100,
            expiry_height: 1_152,
        };
        let a1 = alpha_from_canonical_bytes(&[3u8; 32]).expect("alpha");
        let err = match build_candidate(
            &Regtest,
            &inputs,
            &[a1],
            rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng),
        ) {
            Err(e) => e,
            Ok(_) => panic!("two notes and one randomiser must be refused"),
        };
        assert!(err.contains("randomiser"), "got: {err}");
    }

    /// A vault note, built the way the chain would have created one.
    fn vault_note(fvk: &FullViewingKey) -> Note {
        use orchard::{
            note::{RandomSeed, Rho},
            value::NoteValue,
            NoteVersion,
        };
        let rho = Rho::from_bytes(&[1u8; 32]).unwrap();
        let rseed = RandomSeed::from_bytes([2u8; 32], &rho).unwrap();
        Note::from_parts(
            fvk.address_at(0u64, orchard::keys::Scope::External),
            NoteValue::from_raw(625_000_000),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .unwrap()
    }

    /// Checkpoint 3, evidence item 2: three candidate families with identical effects
    /// and nullifiers, distinct per-pair `rk`, and absent anchor/witness/proof.
    #[test]
    fn c3_three_candidates_share_effects_and_differ_only_in_rk() {
        let mut frost_rng = rand_core::OsRng;

        let (shares, pubkeys) = frost::keys::generate_with_dealer(
            3,
            2,
            frost::keys::IdentifierList::Default,
            frost_rng,
        )
        .unwrap();
        let packages: BTreeMap<_, _> = shares
            .into_iter()
            .map(|(id, ss)| (id, frost::keys::KeyPackage::try_from(ss).unwrap()))
            .collect();
        let ids: Vec<_> = packages.keys().copied().collect();

        let ak: [u8; 32] = pubkeys
            .verifying_key()
            .serialize()
            .unwrap()
            .try_into()
            .unwrap();
        let fvk = zip2005::frost_viewing_key(&ak, &[42u8; 32]).unwrap();
        let note = vault_note(&fvk);

        let intent = Intent {
            proposer: ids[0].serialize(),
            created_height: 700,
            input_nullifiers: vec![note.nullifier(&fvk).to_bytes()],
            recipient: fvk
                .address_at(7u64, orchard::keys::Scope::External)
                .to_raw_address_bytes()
                .to_vec(),
            amount_zat: 40_000_000,
            memo: b"loki g1-tx".to_vec(),
            change_policy: ChangePolicy::VaultInternal,
            fee_zat: 0,
            change_zat: 0,
            expiry_height: 1_152,
        };

        let mut rks = Vec::new();
        let mut nullifiers = Vec::new();

        for (x, y) in [(0usize, 1usize), (0, 2), (1, 2)] {
            // Each pair commits, so each pair's alpha is bound to its own commitments.
            let mut commitments = BTreeMap::new();
            for k in [x, y] {
                let (_n, c) =
                    frost::round1::commit(packages[&ids[k]].signing_share(), &mut frost_rng);
                commitments.insert(ids[k], c);
            }
            let (params, seed) = frost_rerandomized::RandomizedParams::new_from_commitments(
                pubkeys.verifying_key(),
                &commitments,
                rand_core::OsRng,
            )
            .unwrap();
            let restored =
                frost_rerandomized::RandomizedParams::regenerate_from_seed_and_commitments(
                    pubkeys.verifying_key(),
                    &seed,
                    &commitments,
                )
                .unwrap();
            assert_eq!(
                params.randomizer().serialize(),
                restored.randomizer().serialize()
            );
            let alpha_bytes = params.randomizer().serialize();

            // Cross the version boundary as canonical 32 bytes, and reject anything else.
            let alpha_arr: [u8; 32] = alpha_bytes.as_slice().try_into().unwrap();
            let alpha = crate::candidate::alpha_from_canonical_bytes(&alpha_arr)
                .expect("the derived alpha is a canonical Pallas scalar");

            // The fee is what the builder says it is; change is the remainder.
            let amount = Zatoshis::const_from_u64(40_000_000);
            let total = Zatoshis::const_from_u64(625_000_000);

            let mut inputs = CandidateInputs {
                vault_fvk: &fvk,
                notes: vec![note],
                recipient: orchard::Address::from_raw_address_bytes(
                    &intent.recipient.clone().try_into().unwrap(),
                )
                .unwrap(),
                amount,
                memo: MemoBytes::from_bytes(&intent.memo).unwrap(),
                change: Zatoshis::ZERO,
                target_height: 700,
                expiry_height: 1_152,
            };

            let fee = quote_fee(&Regtest, &inputs).expect("the builder quotes a fee");
            inputs.change =
                Zatoshis::const_from_u64(u64::from(total) - u64::from(amount) - u64::from(fee));

            let built = build_candidate(
                &Regtest,
                &inputs,
                &[alpha],
                rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng),
            )
            .expect("a candidate builds");

            let bundle = built
                .pczt_parts
                .ironwood
                .as_ref()
                .expect("an ironwood bundle");

            // Anchor deferred: the flag that makes a PCZT serializer emit it as ABSENT,
            // with the empty-tree root standing in as a placeholder.
            assert!(
                *bundle.anchor_deferred(),
                "the anchor must be deferred before proving"
            );
            assert_eq!(
                *bundle.anchor(),
                orchard::Anchor::empty_tree(),
                "a deferred anchor carries the empty-tree placeholder"
            );
            assert!(
                bundle.zkproof().is_none(),
                "the proof must be absent before proving"
            );

            // The real spend is the one spending OUR note. Padding actions are dummy
            // spends of notes the builder invented, and they do carry dummy witnesses.
            let real_nf = note.nullifier(&fvk).to_bytes();
            let real: Vec<_> = bundle
                .actions()
                .iter()
                .filter(|a| a.spend().nullifier().to_bytes() == real_nf)
                .collect();
            assert_eq!(real.len(), 1, "exactly one action spends the vault note");
            assert!(
                real[0].spend().witness().is_none(),
                "the real spend's witness must be absent before proving"
            );

            // The spend committed to the alpha we chose, which is the B2 patch working
            // through the whole deferred builder rather than only in isolation.
            assert_eq!(
                real[0].spend().alpha(),
                &Some(alpha),
                "the spend must carry the derived alpha"
            );
            rks.push(<[u8; 32]>::from(real[0].spend().rk()));
            nullifiers.push(real_nf);
        }

        // Same note spent by all three.
        assert_eq!(nullifiers[0], nullifiers[1]);
        assert_eq!(nullifiers[1], nullifiers[2]);

        // Different pair, different rk.
        assert_ne!(rks[0], rks[1]);
        assert_ne!(rks[1], rks[2]);
        assert_ne!(rks[0], rks[2]);
    }
}
