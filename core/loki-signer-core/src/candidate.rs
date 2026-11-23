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

#[derive(Clone)]
pub struct Regtest;

impl Parameters for Regtest {
    fn network_type(&self) -> zcash_protocol::consensus::NetworkType {
        zcash_protocol::consensus::NetworkType::Regtest
    }

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

pub fn alpha_from_canonical_bytes(bytes: &[u8; 32]) -> Option<pallas::Scalar> {
    use ff::PrimeField;
    Option::from(pallas::Scalar::from_repr(*bytes))
}

pub fn quorums(threshold: u16, members: u16) -> Vec<Vec<u16>> {
    if threshold < 1 || threshold > members {
        return Vec::new();
    }
    let mut out = Vec::new();
    let mut pick = Vec::with_capacity(usize::from(threshold));
    fn walk(next: u16, members: u16, threshold: u16, pick: &mut Vec<u16>, out: &mut Vec<Vec<u16>>) {
        if pick.len() == usize::from(threshold) {
            out.push(pick.clone());
            return;
        }
        for id in next..=members {
            if pick.len() as u16 + (members - id + 1) < threshold {
                break;
            }
            pick.push(id);
            walk(id + 1, members, threshold, pick, out);
            pick.pop();
        }
    }
    walk(1, members, threshold, &mut pick, &mut out);
    out
}

pub struct CandidateInputs<'a> {
    pub vault_fvk: &'a FullViewingKey,
    pub notes: Vec<Note>,
    pub recipient: orchard::Address,
    pub amount: Zatoshis,
    pub memo: MemoBytes,
    pub change: Zatoshis,
    pub target_height: u32,
    pub expiry_height: u32,
}

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

pub fn forbidden_transparent_bundle() -> Result<zcash_transparent::pczt::Bundle, String> {
    use std::collections::BTreeMap;
    use zcash_transparent::pczt::{Bundle, Output};

    let mut script = vec![0x76u8, 0xa9, 0x14];
    script.extend_from_slice(&[0x11u8; 20]);
    script.extend_from_slice(&[0x88u8, 0xac]);

    let output = Output::parse(0, script, None, BTreeMap::new(), None, BTreeMap::new())
        .map_err(|e| format!("transparent output: {e:?}"))?;

    Bundle::parse(Vec::new(), vec![output]).map_err(|e| format!("transparent bundle: {e:?}"))
}

pub fn forbidden_sapling_bundle() -> Result<sapling_crypto::pczt::Bundle, String> {
    use sapling_crypto::{
        pczt::{Bundle, Output},
        value::{NoteValue, ValueCommitTrapdoor},
    };
    use std::collections::BTreeMap;

    let mut rcv_bytes = [0u8; 32];
    rcv_bytes[0] = 1;
    let rcv = ValueCommitTrapdoor::from_bytes(rcv_bytes)
        .into_option()
        .ok_or("rcv")?;
    let cv = sapling_crypto::value::ValueCommitment::derive(NoteValue::from_raw(0), rcv);

    let output = Output::parse(
        cv.to_bytes(),
        [0u8; 32],
        [0u8; 32],
        vec![0u8; 580],
        vec![0u8; 80],
        None,
        None,
        None,
        None,
        Some(rcv_bytes),
        None,
        None,
        None,
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

    #[test]
    fn deferred_ironwood_candidate_uses_testnet_nu7_branch() {
        use zcash_protocol::consensus::{BranchId, TEST_NETWORK};

        let fvk = a_test_fvk();
        let mut inputs = CandidateInputs {
            vault_fvk: &fvk,
            notes: vec![vault_note_of(&fvk, 100_000_000, 44)],
            recipient: fvk.address_at(7u64, orchard::keys::Scope::External),
            amount: Zatoshis::const_from_u64(40_000_000),
            memo: MemoBytes::empty(),
            change: Zatoshis::ZERO,
            target_height: 4_465_056,
            expiry_height: 4_465_156,
        };
        let fee = quote_fee(&TEST_NETWORK, &inputs).unwrap();
        inputs.change = Zatoshis::from_u64(60_000_000 - u64::from(fee)).unwrap();
        let built = build_candidate(
            &TEST_NETWORK,
            &inputs,
            &[pallas::Scalar::from(3)],
            rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng),
        )
        .unwrap();
        assert_eq!(built.pczt_parts.consensus_branch_id, BranchId::Nu7);
        assert!(built.pczt_parts.ironwood.is_some());
    }

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

    #[test]
    fn shuffled_spends_keep_each_notes_original_alpha_by_nullifier() {
        let fvk = a_test_fvk();
        let notes = vec![
            vault_note_of(&fvk, 625_000_000, 10),
            vault_note_of(&fvk, 100_000_000, 20),
        ];
        let alphas = [pallas::Scalar::from(3), pallas::Scalar::from(5)];
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
        inputs.change =
            Zatoshis::from_u64(25_000_000 - u64::from(quote_fee(&Regtest, &inputs).unwrap()))
                .unwrap();
        let ak = orchard::keys::SpendValidatingKey::from(fvk.clone());
        let mut reordered = false;
        for seed in 0..16 {
            let rng = <rand_zp::rngs::StdRng as rand_core_zp::SeedableRng>::from_seed([seed; 32]);
            let built = build_candidate(&Regtest, &inputs, &alphas, rng).unwrap();
            let bundle = built.pczt_parts.ironwood.unwrap();
            let indices = inputs
                .notes
                .iter()
                .zip(alphas)
                .map(|(note, alpha)| {
                    let nf = note.nullifier(&fvk);
                    let (index, action) = bundle
                        .actions()
                        .iter()
                        .enumerate()
                        .find(|(_, action)| action.spend().nullifier() == &nf)
                        .unwrap();
                    assert_eq!(*action.spend().alpha(), Some(alpha));
                    assert_eq!(
                        <[u8; 32]>::from(action.spend().rk()),
                        <[u8; 32]>::from(&ak.randomize(&alpha))
                    );
                    index
                })
                .collect::<Vec<_>>();
            reordered |= indices[0] > indices[1];
        }
        assert!(
            reordered,
            "exercise reversed real-spend order, not only insertion order"
        );
    }

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

            let alpha_arr: [u8; 32] = alpha_bytes.as_slice().try_into().unwrap();
            let alpha = crate::candidate::alpha_from_canonical_bytes(&alpha_arr)
                .expect("the derived alpha is a canonical Pallas scalar");

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

            assert_eq!(
                real[0].spend().alpha(),
                &Some(alpha),
                "the spend must carry the derived alpha"
            );
            rks.push(<[u8; 32]>::from(real[0].spend().rk()));
            nullifiers.push(real_nf);
        }

        assert_eq!(nullifiers[0], nullifiers[1]);
        assert_eq!(nullifiers[1], nullifiers[2]);

        assert_ne!(rks[0], rks[1]);
        assert_ne!(rks[1], rks[2]);
        assert_ne!(rks[0], rks[2]);
    }

    #[test]
    fn quorums_enumerate_all_t_of_n_combinations() {
        fn binom(n: u64, k: u64) -> u64 {
            (0..k).fold(1u64, |acc, i| acc * (n - i) / (i + 1))
        }
        for (t, n) in [(1u16, 1u16), (2, 3), (2, 5), (3, 5), (4, 7), (7, 7)] {
            let qs = quorums(t, n);
            assert_eq!(
                qs.len() as u64,
                binom(u64::from(n), u64::from(t)),
                "{t}-of-{n} must give C(n,t) quorums"
            );
            let unique: std::collections::BTreeSet<_> = qs.iter().cloned().collect();
            assert_eq!(unique.len(), qs.len(), "{t}-of-{n} has a duplicate quorum");
            for q in &qs {
                assert_eq!(q.len(), usize::from(t), "quorum has the wrong size");
                assert!(q.windows(2).all(|w| w[0] < w[1]), "quorum not sorted distinct");
                assert!(q.iter().all(|&id| (1..=n).contains(&id)), "id out of roster");
            }
        }
        assert!(quorums(0, 3).is_empty());
        assert!(quorums(4, 3).is_empty());
    }

    fn roundtrip_every_quorum(threshold: u16, members: u16) {
        let mut rng = rand_core::OsRng;
        let (shares, pubkeys) = frost::keys::generate_with_dealer(
            members,
            threshold,
            frost::keys::IdentifierList::Default,
            rng,
        )
        .expect("dealer keygen");
        let keys: BTreeMap<_, _> = shares
            .into_iter()
            .map(|(id, ss)| (id, frost::keys::KeyPackage::try_from(ss).unwrap()))
            .collect();

        let ak: [u8; 32] = pubkeys
            .verifying_key()
            .serialize()
            .unwrap()
            .try_into()
            .unwrap();
        let fvk = zip2005::frost_viewing_key(&ak, &[9u8; 32]).unwrap();
        let note = vault_note(&fvk);

        let mut rks = std::collections::BTreeSet::new();
        for quorum in quorums(threshold, members) {
            let ids: Vec<_> = quorum
                .iter()
                .map(|n| frost::Identifier::try_from(*n).unwrap())
                .collect();

            let mut nonces = BTreeMap::new();
            let mut commitments = BTreeMap::new();
            for id in &ids {
                let (nonce, commitment) =
                    frost::round1::commit(keys[id].signing_share(), &mut rng);
                nonces.insert(*id, nonce);
                commitments.insert(*id, commitment);
            }

            let (params, seed) = frost_rerandomized::RandomizedParams::new_from_commitments(
                pubkeys.verifying_key(),
                &commitments,
                rng,
            )
            .unwrap();
            let alpha_arr: [u8; 32] = params.randomizer().serialize().as_slice().try_into().unwrap();
            let alpha = alpha_from_canonical_bytes(&alpha_arr).expect("canonical alpha");

            let mut inputs = CandidateInputs {
                vault_fvk: &fvk,
                notes: vec![note],
                recipient: fvk.address_at(7u64, orchard::keys::Scope::External),
                amount: Zatoshis::const_from_u64(40_000_000),
                memo: MemoBytes::from_bytes(b"loki ws7").unwrap(),
                change: Zatoshis::ZERO,
                target_height: 700,
                expiry_height: 1_152,
            };
            let fee = quote_fee(&Regtest, &inputs).unwrap();
            inputs.change =
                Zatoshis::const_from_u64(625_000_000 - 40_000_000 - u64::from(fee));
            let built = build_candidate(
                &Regtest,
                &inputs,
                &[alpha],
                rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng),
            )
            .expect("candidate builds for this quorum");

            let candidate = pczt::roles::creator::Creator::build_from_parts(built.pczt_parts)
                .expect("create PCZT from parts");
            let checked = pczt::roles::signer::Signer::new(candidate).unwrap();
            let sighash = checked.shielded_sighash();
            let package = frost::SigningPackage::new(commitments.clone(), &sighash);
            let mut sig_shares = BTreeMap::new();
            for id in &ids {
                let share = frost_rerandomized::sign_with_randomizer_seed(
                    &package,
                    &nonces[id],
                    &keys[id],
                    &seed,
                )
                .unwrap();
                sig_shares.insert(*id, share);
            }
            let sig =
                frost_rerandomized::aggregate(&package, &sig_shares, &pubkeys, &params).unwrap();
            params
                .randomized_verifying_key()
                .verify(&sighash, &sig)
                .expect("aggregate signature verifies against randomized group key");

            let rk: [u8; 32] = params.randomized_verifying_key().serialize().unwrap().as_slice().try_into().unwrap();
            assert!(rks.insert(rk), "two quorums shared a randomized key");
        }
    }

    #[test]
    fn dkg_sign_aggregate_verify_2_of_3() {
        roundtrip_every_quorum(2, 3);
    }

    #[test]
    fn dkg_sign_aggregate_verify_2_of_5() {
        roundtrip_every_quorum(2, 5);
    }

    #[test]
    fn dkg_sign_aggregate_verify_3_of_5() {
        roundtrip_every_quorum(3, 5);
    }

    #[test]
    fn dkg_sign_aggregate_verify_4_of_7() {
        roundtrip_every_quorum(4, 7);
    }
}
