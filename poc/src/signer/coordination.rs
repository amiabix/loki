//! UNIT U2: the keyless coordination loop.
//!
//! [`drive_to_signed_pczt`] drives a quorum of [`Signer`]s from a payment intent to a
//! signed PCZT. It links NO share/nonce code: every secret stays inside the signers, and
//! the coordinator only ever moves PUBLIC artifacts (commitments, a `SigningPackage`, a
//! randomizer seed, signature shares) between them — the same seam the `PublicArtifact`
//! guard in [`crate::signer`] pins.
//!
//! The loop is, for a one-note candidate:
//!   1. round 1: [`Signer::sign_commit`] on each quorum member → public commitments,
//!   2. derive the rerandomizer from those commitments and the candidate's `alpha` from it,
//!   3. build the unproved candidate PCZT under that alpha ([`crate::candidate`]),
//!   4. assemble the FROST [`SigningPackage`] from the commitments + the candidate sighash,
//!   5. round 2: [`Signer::sign_approve`] on each member (pczt + package + randomizer seed),
//!   6. aggregate the shares ([`frost_rerandomized::aggregate`]), apply the signature to the
//!      PCZT, and return the signed bytes.
//!
//! It stops at the signed PCZT: no prove, broadcast, scan, or chain contact.

use crate::candidate::{alpha_from_canonical_bytes, build_candidate, quote_fee, CandidateInputs};
use crate::signer::{CandidateRef, Session, Signer};
use orchard::keys::FullViewingKey;
use reddsa_frost::frost::redpallas as frost;
use std::collections::BTreeMap;
use zcash_protocol::consensus::Parameters;

/// What the coordinator knows to build the candidate: the public vault key, the single note
/// being spent, and the payment effects. All public — no share, nonce, or spend authority.
pub struct PaymentIntent<'a> {
    pub vault_fvk: &'a FullViewingKey,
    pub note: orchard::Note,
    pub recipient: orchard::Address,
    pub amount: zcash_protocol::value::Zatoshis,
    pub memo: zcash_protocol::memo::MemoBytes,
    pub target_height: u32,
    pub expiry_height: u32,
}

/// One quorum member as the coordinator sees it: its FROST identifier, the session handle
/// returned by [`Signer::connect`], and the signer itself. No key material.
pub struct QuorumMember<'a, S: Signer> {
    pub id: frost::Identifier,
    pub session: Session,
    pub signer: &'a mut S,
}

/// Drive the quorum to a signed PCZT. `public` is the group public key package (public).
/// `cand` names the candidate for the signers' nonce/render bookkeeping.
///
/// Returns the signed PCZT bytes. Errors are plain strings: this is a coordinator, it has
/// no secrets to leak in a message.
pub fn drive_to_signed_pczt<P, S>(
    params: &P,
    public: &frost::keys::PublicKeyPackage,
    intent: &PaymentIntent<'_>,
    cand: &CandidateRef,
    quorum: &mut [QuorumMember<'_, S>],
) -> Result<Vec<u8>, String>
where
    P: Parameters + Clone,
    S: Signer,
    S::Error: std::fmt::Display,
{
    if quorum.is_empty() {
        return Err("empty quorum".into());
    }

    // 1. Round 1: each member commits. The secret nonce stays inside the signer; only the
    //    public commitment comes back.
    let mut commitments = BTreeMap::new();
    for m in quorum.iter_mut() {
        let c = m
            .signer
            .sign_commit(&m.session, cand)
            .map_err(|e| format!("member {:?} sign_commit: {e}", m.id))?;
        commitments.insert(m.id, c);
    }

    // 2. The rerandomizer is bound to THIS quorum's commitments; alpha is derived from it.
    let (fparams, seed) = frost_rerandomized::RandomizedParams::new_from_commitments(
        public.verifying_key(),
        &commitments,
        rand_core::OsRng,
    )
    .map_err(|e| format!("randomizer: {e}"))?;
    let seed_bytes: [u8; 32] = seed
        .as_slice()
        .try_into()
        .map_err(|_| "randomizer seed is not 32 bytes")?;
    let alpha_bytes: [u8; 32] = fparams
        .randomizer()
        .serialize()
        .as_slice()
        .try_into()
        .map_err(|_| "randomizer alpha is not 32 bytes")?;
    let alpha = alpha_from_canonical_bytes(&alpha_bytes).ok_or("noncanonical alpha")?;

    // 3. Build the unproved candidate under that alpha. Fee is what the builder quotes;
    //    change is the remainder of the single note.
    let mut inputs = CandidateInputs {
        vault_fvk: intent.vault_fvk,
        notes: vec![intent.note],
        recipient: intent.recipient,
        amount: intent.amount,
        memo: intent.memo.clone(),
        change: zcash_protocol::value::Zatoshis::ZERO,
        target_height: intent.target_height,
        expiry_height: intent.expiry_height,
    };
    let fee = u64::from(quote_fee(params, &inputs)?);
    let spend = intent.note.value().inner();
    let amount = u64::from(intent.amount);
    let change = spend
        .checked_sub(amount)
        .and_then(|r| r.checked_sub(fee))
        .ok_or("note does not cover amount + fee")?;
    inputs.change = zcash_protocol::value::Zatoshis::from_u64(change).map_err(|e| format!("{e:?}"))?;
    let built = build_candidate(
        params,
        &inputs,
        &[alpha],
        rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng),
    )?;

    // Serialize the candidate and compute the sighash the signers will independently redo.
    let candidate = pczt::roles::creator::Creator::build_from_parts(built.pczt_parts)
        .ok_or("create pczt: build_from_parts returned None")?;
    let candidate = pczt::roles::io_finalizer::IoFinalizer::new(candidate)
        .finalize_io()
        .map_err(|e| format!("io finalize: {e:?}"))?;
    let sighash = pczt::roles::signer::Signer::new(candidate.clone())
        .map_err(|e| format!("signer: {e:?}"))?
        .shielded_sighash();
    let pczt_bytes = candidate.serialize().map_err(|e| format!("serialize: {e:?}"))?;

    // 4. Assemble the FROST signing package from the commitments + the candidate sighash.
    let package = frost::SigningPackage::new(commitments.clone(), &sighash);

    // 5. Round 2: each member renders+approves the bytes and returns a public share.
    let mut shares = BTreeMap::new();
    for m in quorum.iter_mut() {
        let share = m
            .signer
            .sign_approve(&m.session, cand, &pczt_bytes, &package, &seed_bytes)
            .map_err(|e| format!("member {:?} sign_approve: {e}", m.id))?;
        shares.insert(m.id, share);
    }

    // 6. Aggregate, verify under the randomized group key, apply, and return signed bytes.
    let group_sig = frost_rerandomized::aggregate(&package, &shares, public, &fparams)
        .map_err(|e| format!("aggregate: {e}"))?;
    fparams
        .randomized_verifying_key()
        .verify(&sighash, &group_sig)
        .map_err(|e| format!("aggregate does not verify under randomized group key: {e}"))?;
    let sig_bytes: [u8; 64] = group_sig
        .serialize()
        .map_err(|e| format!("{e}"))?
        .as_slice()
        .try_into()
        .map_err(|_| "signature is not 64 bytes")?;
    let orchard_sig = orchard::primitives::redpallas::Signature::<
        orchard::primitives::redpallas::SpendAuth,
    >::from(sig_bytes);

    let parsed = pczt::Pczt::parse(&pczt_bytes).map_err(|e| format!("reparse: {e:?}"))?;
    let want_nf = intent.note.nullifier(intent.vault_fvk).to_bytes();
    let index = parsed
        .ironwood()
        .actions()
        .iter()
        .position(|a| a.spend().nullifier() == &want_nf)
        .ok_or("candidate does not spend the intended note")?;
    let mut signer =
        pczt::roles::signer::Signer::new(parsed).map_err(|e| format!("signer: {e:?}"))?;
    signer
        .apply_ironwood_signature(index, orchard_sig)
        .map_err(|e| format!("apply signature: {e:?}"))?;
    signer
        .finish()
        .serialize()
        .map_err(|e| format!("serialize signed: {e:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::candidate::Regtest;
    use crate::signer::local::LocalSigner;
    use crate::signer::secure_element::SoftwareSecureElement;
    use crate::signer::Network;
    use crate::zip2005;
    use orchard::keys::Scope;
    use orchard::note::{RandomSeed, Rho};
    use orchard::value::NoteValue;
    use orchard::NoteVersion;
    use zcash_protocol::{memo::MemoBytes, value::Zatoshis};

    const SPEND_VALUE: u64 = 625_000_000;
    const AMOUNT: u64 = 40_000_000;

    fn tempdir(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "loki-coord-{tag}-{}-{}",
            std::process::id(),
            rand_core::RngCore::next_u64(&mut rand_core::OsRng)
        ));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    fn vault_note(fvk: &FullViewingKey) -> orchard::Note {
        let rho = Rho::from_bytes(&[1u8; 32]).unwrap();
        let rseed = RandomSeed::from_bytes([2u8; 32], &rho).unwrap();
        orchard::Note::from_parts(
            fvk.address_at(0u64, Scope::External),
            NoteValue::from_raw(SPEND_VALUE),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .unwrap()
    }

    /// Dealer-keygen a t-of-n vault, connect every member, and drive the FIRST quorum
    /// (members 1..=t) through the keyless loop. The loop itself verifies the aggregated
    /// signature under the randomized group key before returning — the exact bytes a prover
    /// would accept — so a non-error return IS the acceptance.
    fn roundtrip(threshold: u16, members: u16) {
        let (shares, public) = frost::keys::generate_with_dealer(
            members,
            threshold,
            frost::keys::IdentifierList::Default,
            &mut rand_core::OsRng,
        )
        .expect("dealer keygen");
        let ak: [u8; 32] = public
            .verifying_key()
            .serialize()
            .unwrap()
            .try_into()
            .unwrap();
        let fvk = zip2005::frost_viewing_key(&ak, &[42u8; 32]).unwrap();
        let note = vault_note(&fvk);
        let pp_bytes = public.serialize().unwrap();

        // One LocalSigner per quorum member (ids 1..=threshold), each with its dealt share.
        let mut signers: Vec<LocalSigner<SoftwareSecureElement>> = (1..=threshold)
            .map(|id| {
                let ident = frost::Identifier::try_from(id).unwrap();
                let kp =
                    frost::keys::KeyPackage::try_from(shares.get(&ident).unwrap().clone()).unwrap();
                LocalSigner::with_sealed_share(
                    id,
                    threshold,
                    members,
                    [id as u8; 32],
                    "coord vault".into(),
                    Network::Regtest,
                    SoftwareSecureElement::generate(),
                    &kp.serialize().unwrap(),
                    pp_bytes.clone(),
                    fvk.clone(),
                    tempdir(&format!("t{threshold}n{members}m{id}")),
                    Box::new(|_view| true), // approval policy returns true in the test
                )
                .unwrap()
            })
            .collect();

        let sessions: Vec<Session> = signers
            .iter_mut()
            .map(|s| {
                s.connect("http://coordinator.test", Network::Regtest, b"u2-challenge")
                    .unwrap()
                    .session
            })
            .collect();

        let intent = PaymentIntent {
            vault_fvk: &fvk,
            note,
            recipient: fvk.address_at(7u64, Scope::External),
            amount: Zatoshis::const_from_u64(AMOUNT),
            memo: MemoBytes::from_bytes(b"loki u2").unwrap(),
            target_height: 700,
            expiry_height: 1_152,
        };
        let cand = CandidateRef {
            vault_id: [1u8; 32],
            payment_id: [7u8; 32],
            attempt_id: [9u8; 32],
        };

        let mut quorum: Vec<QuorumMember<'_, _>> = signers
            .iter_mut()
            .zip(sessions)
            .enumerate()
            .map(|(i, (signer, session))| QuorumMember {
                id: frost::Identifier::try_from((i as u16) + 1).unwrap(),
                session,
                signer,
            })
            .collect();

        let signed = drive_to_signed_pczt(&Regtest, &public, &intent, &cand, &mut quorum)
            .expect("the keyless loop produces a verified signed PCZT");

        // The returned bytes parse and the intended spend now carries a spend-auth sig.
        let parsed = pczt::Pczt::parse(&signed).unwrap();
        let nf = note.nullifier(&fvk).to_bytes();
        let action = parsed
            .ironwood()
            .actions()
            .iter()
            .find(|a| a.spend().nullifier() == &nf)
            .expect("signed pczt still spends the intended note");
        assert!(
            action.spend().spend_auth_sig().is_some(),
            "the aggregated signature must be applied to the spend"
        );
    }

    #[test]
    fn keyless_loop_signs_2_of_3() {
        roundtrip(2, 3);
    }

    #[test]
    fn keyless_loop_signs_3_of_5() {
        roundtrip(3, 5);
    }
}
