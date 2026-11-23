use crate::signer::{CandidateRef, DkgInput, PublicPaymentParams, Session, Signer, VaultRef};
use crate::transport::{Outbound, Peer, RelayLog, Transport};
use reddsa_frost::frost::redpallas as frost;
use std::collections::BTreeMap;

pub type PaymentIntent = PublicPaymentParams;

pub struct QuorumMember<'a, S: Signer> {
    pub id: frost::Identifier,
    pub session: Session,
    pub signer: &'a mut S,
}

pub fn drive_to_signed_pczt<S>(
    public: &frost::keys::PublicKeyPackage,
    intent: &PaymentIntent,
    cand: &CandidateRef,
    quorum: &mut [QuorumMember<'_, S>],
) -> Result<Vec<u8>, String>
where
    S: Signer,
    S::Error: std::fmt::Display,
{
    if quorum.is_empty() {
        return Err("empty quorum".into());
    }

    let mut commitments = BTreeMap::new();
    for m in quorum.iter_mut() {
        let c = m
            .signer
            .sign_commit(&m.session, cand)
            .map_err(|e| format!("member {:?} sign_commit: {e}", m.id))?;
        commitments.insert(m.id, c);
    }

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

    let pczt_bytes = {
        let proposer = &quorum[0];
        proposer
            .signer
            .build_candidate(&proposer.session, cand, intent, &[alpha_bytes])
            .map_err(|e| format!("proposer {:?} build_candidate: {e}", proposer.id))?
            .0
    };

    let candidate = pczt::Pczt::parse(&pczt_bytes).map_err(|e| format!("parse candidate: {e:?}"))?;
    let sighash = pczt::roles::signer::Signer::new(candidate)
        .map_err(|e| format!("signer: {e:?}"))?
        .shielded_sighash();

    let package = frost::SigningPackage::new(commitments.clone(), &sighash);

    let mut shares = BTreeMap::new();
    for m in quorum.iter_mut() {
        let share = m
            .signer
            .sign_approve(&m.session, cand, intent, &pczt_bytes, &package, &seed_bytes)
            .map_err(|e| format!("member {:?} sign_approve: {e}", m.id))?;
        shares.insert(m.id, share);
    }

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
    let want_rk: [u8; 32] = fparams
        .randomized_verifying_key()
        .serialize()
        .map_err(|e| format!("{e}"))?
        .as_slice()
        .try_into()
        .map_err(|_| "randomized vk is not 32 bytes")?;
    let index = parsed
        .ironwood()
        .actions()
        .iter()
        .position(|a| a.spend().rk() == &want_rk)
        .ok_or("candidate has no spend under the randomized group key")?;
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

pub fn member_dkg_step<S, T>(
    signer: &mut S,
    session: &Session,
    vault: &VaultRef,
    transport: &T,
    channel: &T::Channel,
    coordinator: &Peer,
) -> Result<usize, String>
where
    S: Signer,
    S::Error: std::fmt::Display,
    T: Transport,
    T::Error: std::fmt::Display,
{
    let inputs = transport
        .recv(channel, false)
        .map_err(|e| format!("recv: {e}"))?
        .into_iter()
        .filter(|incoming| incoming.from == *coordinator)
        .filter_map(|incoming| DkgInput::from_relay(incoming.message).ok())
        .collect::<Vec<_>>();
    let (wires, refused) = match signer.dkg_step(session, vault, &inputs) {
        Ok(wires) => (wires, None),
        Err(error) => match signer.dkg_step(session, vault, &[]) {
            Ok(wires) => (wires, Some(error)),
            Err(_) => return Err(format!("dkg_step: {error}")),
        },
    };
    let sent = wires.len();
    for wire in wires {
        transport
            .send(channel, &[], &Outbound::Dkg(wire))
            .map_err(|e| format!("send: {e}"))?;
    }
    match refused {
        Some(error) => Err(format!("dkg_step: {error}")),
        None => Ok(sent),
    }
}

pub fn relay_dkg<T>(
    log: &mut RelayLog,
    transport: &T,
    channel: &T::Channel,
    members: &BTreeMap<u16, Peer>,
) -> Result<usize, String>
where
    T: Transport,
    T::Error: std::fmt::Display,
{
    let mut forwarded = 0;
    for incoming in transport
        .recv(channel, true)
        .map_err(|e| format!("recv: {e}"))?
    {
        let Some(from) = members
            .iter()
            .find(|(_, peer)| **peer == incoming.from)
            .map(|(id, _)| *id)
        else {
            continue;
        };
        let Ok(relayed) = log.relay(from, incoming.message) else {
            continue;
        };
        if let Some((wire, recipients)) = relayed {
            let to: Vec<Peer> = recipients.iter().map(|id| members[id].clone()).collect();
            transport
                .send(channel, &to, &Outbound::Dkg(wire))
                .map_err(|e| format!("send: {e}"))?;
            forwarded += 1;
        }
    }
    Ok(forwarded)
}

pub fn redeliver_dkg<T>(
    log: &RelayLog,
    transport: &T,
    channel: &T::Channel,
    members: &BTreeMap<u16, Peer>,
) -> Result<usize, String>
where
    T: Transport,
    T::Error: std::fmt::Display,
{
    let mut sent = 0;
    for (id, peer) in members {
        for wire in log.for_member(*id) {
            transport
                .send(channel, std::slice::from_ref(peer), &Outbound::Dkg(wire))
                .map_err(|e| format!("send: {e}"))?;
            sent += 1;
        }
    }
    Ok(sent)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::local::LocalSigner;
    use crate::signer::secure_element::SoftwareSecureElement;
    use crate::signer::Network;
    use crate::zip2005;
    use orchard::keys::{FullViewingKey, Scope};
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
                    Box::new(|_view| true),
                )
                .unwrap()
            })
            .collect();

        for s in signers.iter_mut() {
            s.set_candidate_notes(vec![note]);
        }

        let sessions: Vec<Session> = signers
            .iter_mut()
            .map(|s| {
                s.connect("http://coordinator.test", Network::Regtest, b"u2-challenge")
                    .unwrap()
                    .session
            })
            .collect();

        let intent = PaymentIntent {
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

        let signed = drive_to_signed_pczt(&public, &intent, &cand, &mut quorum)
            .expect("the keyless loop produces a verified signed PCZT");

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
