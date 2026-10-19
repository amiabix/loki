//! Shared PCZT finalization used by both payment binaries, so the Ironwood proving +
//! extraction path lives in exactly one place.
//!
//! [`prove`] sets the chain anchor and spend witnesses on an approved, signed PCZT,
//! refuses if that changes the approved sighash, proves the Ironwood (Orchard NU6.3)
//! spends, and extracts the broadcastable transaction bytes + its txid.

use zcash_primitives::transaction::TxId;

/// Finalize an approved, signed PCZT into a broadcastable transaction.
///
/// `sighash` is the sighash the members approved; proving refuses if applying the anchor
/// or witnesses changes it (`anchor or witnesses changed the approved transaction effects`).
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
    let vk =
        orchard::circuit::VerifyingKey::build(orchard::circuit::OrchardCircuitVersion::PostNu6_3);
    let tx = TransactionExtractor::new(finalized)
        .with_orchard(&vk)
        .extract()
        .map_err(|e| format!("extract transaction: {e:?}"))?;
    let mut raw = Vec::new();
    tx.write(&mut raw)
        .map_err(|e| format!("serialize transaction: {e}"))?;
    Ok((raw, tx.txid()))
}
