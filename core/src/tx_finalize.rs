use zcash_primitives::transaction::{Transaction, TxId};

pub fn finalized_sighash(tx: &Transaction) -> Result<[u8; 32], String> {
    use zcash_primitives::transaction::{Authorization, TransactionData};
    struct ShieldedOnly;
    impl Authorization for ShieldedOnly {
        type TransparentAuth = zcash_transparent::bundle::EffectsOnly;
        type SaplingAuth = sapling_crypto::bundle::Authorized;
        type OrchardAuth = orchard::bundle::Authorized;
    }
    if tx.transparent_bundle().is_some()
        || tx.sapling_bundle().is_some()
        || tx.orchard_bundle().is_some()
    {
        return Err("the finalized transaction has an unexpected pool".into());
    }
    let data: TransactionData<ShieldedOnly> = tx.clone().into_data().try_map_bundles(
        |_| Ok::<_, String>(None),
        |_| Ok::<_, String>(None),
        Ok::<_, String>,
    )?;
    let digest = zcash_primitives::transaction::sighash::signature_hash(
        &data,
        &zcash_primitives::transaction::sighash::SignableInput::Shielded,
        &data.digest(zcash_primitives::transaction::txid::TxIdDigester),
    );
    Ok(*digest.as_ref())
}

fn ironwood_verifying_key() -> &'static orchard::circuit::VerifyingKey {
    static KEY: std::sync::OnceLock<orchard::circuit::VerifyingKey> = std::sync::OnceLock::new();
    KEY.get_or_init(|| {
        orchard::circuit::VerifyingKey::build(orchard::circuit::OrchardCircuitVersion::PostNu6_3)
    })
}

pub fn verify_ironwood_authorization(tx: &Transaction, sighash: [u8; 32]) -> Result<(), String> {
    use rand_zp::{rand_core::UnwrapErr, rngs::SysRng};
    let bundle = tx.ironwood_bundle().ok_or("missing Ironwood bundle")?;
    let mut validator = orchard::bundle::BatchValidator::new(ironwood_verifying_key());
    validator.add_bundle(bundle, sighash).map_err(|e| format!("Ironwood proof: {e:?}"))?;
    if !validator.validate(UnwrapErr(SysRng)) {
        return Err("invalid Ironwood proof or signatures".into());
    }
    Ok(())
}

pub fn prove(
    signed: pczt::Pczt,
    sighash: [u8; 32],
    witnesses: Vec<(usize, orchard::tree::MerklePath)>,
    anchor: [u8; 32],
) -> Result<(Vec<u8>, TxId), String> {
    use pczt::roles::{
        prover::Prover, signer::Signer, spend_finalizer::SpendFinalizer,
        tx_extractor::TransactionExtractor, updater::Updater,
    };
    let updated = Updater::new(signed)
        .set_ironwood_anchor(
            orchard::Anchor::from_bytes(anchor)
                .into_option()
                .ok_or("invalid chain anchor")?,
        )
        .map_err(|e| format!("anchor: {e:?}"))?
        .set_ironwood_spend_witnesses(witnesses)
        .map_err(|e| format!("witness: {e:?}"))?
        .finish();
    if Signer::new(updated.clone())
        .map_err(|e| format!("sighash: {e:?}"))?
        .shielded_sighash()
        != sighash
    {
        return Err("anchor or witnesses changed the approved transaction effects".into());
    }
    let pk =
        orchard::circuit::ProvingKey::build(orchard::circuit::OrchardCircuitVersion::PostNu6_3);
    let proved = Prover::new(updated)
        .create_ironwood_proof(&pk)
        .map_err(|e| format!("proof: {e:?}"))?
        .finish();
    let finalized = SpendFinalizer::new(proved)
        .finalize_spends()
        .map_err(|e| format!("spend finalizer: {e:?}"))?;
    let tx = TransactionExtractor::new(finalized)
        .with_orchard(ironwood_verifying_key())
        .extract()
        .map_err(|e| format!("extract transaction: {e:?}"))?;
    let mut raw = Vec::new();
    tx.write(&mut raw)
        .map_err(|e| format!("serialize transaction: {e}"))?;
    Ok((raw, tx.txid()))
}
