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
//!   3. ASK THE PROPOSER SIGNER to build the unproved candidate PCZT under that alpha
//!      ([`Signer::build_candidate`]) — using ITS own viewing key and ITS own selected note.
//!      The coordinator passes only the public payment effects + alpha and never sees the
//!      viewing key, the note, or selects a note.
//!   4. assemble the FROST [`SigningPackage`] from the commitments + the candidate sighash,
//!   5. round 2: [`Signer::sign_approve`] on each member (pczt + package + randomizer seed),
//!   6. aggregate the shares ([`frost_rerandomized::aggregate`]), apply the signature to the
//!      PCZT, and return the signed bytes.
//!
//! It stops at the signed PCZT: no prove, broadcast, scan, or chain contact.
//!
//! The setup drivers [`member_dkg_step`], [`relay_dkg`] and [`redeliver_dkg`] carry the
//! signer's DKG wires over a [`Transport`]: members send to the coordinator, which logs
//! each wire in its [`RelayLog`] before forwarding it, and redelivers from the log after a
//! restart. The coordinator only moves wires; it cannot open round two.

use crate::signer::{CandidateRef, DkgInput, PublicPaymentParams, Session, Signer, VaultRef};
use crate::transport::{Outbound, Peer, RelayLog, Transport};
use reddsa_frost::frost::redpallas as frost;
use std::collections::BTreeMap;

/// What the coordinator knows to drive the payment: the PUBLIC effects only. No viewing
/// key, no note, no share, no nonce, no spend authority. The signer selects its own note
/// and builds under its own viewing key.
pub type PaymentIntent = PublicPaymentParams;

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

    // One rerandomized FROST session ("lane") per input note the proposer will spend. Lane 0
    // reuses `cand` unchanged (its attempt_id XOR 0), so a single-note payment is byte-for-byte
    // identical to before; lanes 1.. get a distinct attempt_id, hence a distinct single-use
    // nonce, from the SAME signers.
    let lanes = quorum[0].signer.candidate_note_count();
    let lane_cand = |i: usize| {
        let mut c = *cand;
        c.attempt_id[0] ^= i as u8;
        c
    };

    // 1. Round 1, per lane: each member commits (secret nonce stays inside); derive that lane's
    //    rerandomizer alpha_i from its commitments.
    type Commitments = BTreeMap<frost::Identifier, frost::round1::SigningCommitments>;
    let mut lane_commits: Vec<Commitments> = Vec::with_capacity(lanes);
    let mut lane_fparams = Vec::with_capacity(lanes);
    let mut lane_seeds: Vec<[u8; 32]> = Vec::with_capacity(lanes);
    let mut alphas: Vec<[u8; 32]> = Vec::with_capacity(lanes);
    for i in 0..lanes {
        let ci = lane_cand(i);
        let mut commitments = Commitments::new();
        for m in quorum.iter_mut() {
            let c = m
                .signer
                .sign_commit(&m.session, &ci)
                .map_err(|e| format!("member {:?} sign_commit lane {i}: {e}", m.id))?;
            commitments.insert(m.id, c);
        }
        let (fparams, seed) = frost_rerandomized::RandomizedParams::new_from_commitments(
            public.verifying_key(),
            &commitments,
            rand_core::OsRng,
        )
        .map_err(|e| format!("randomizer lane {i}: {e}"))?;
        lane_seeds.push(
            seed.as_slice()
                .try_into()
                .map_err(|_| "randomizer seed is not 32 bytes")?,
        );
        alphas.push(
            fparams
                .randomizer()
                .serialize()
                .as_slice()
                .try_into()
                .map_err(|_| "randomizer alpha is not 32 bytes")?,
        );
        lane_commits.push(commitments);
        lane_fparams.push(fparams);
    }

    // 2. The PROPOSER builds the candidate: one spend per lane, each under its alpha_i. It uses
    //    its OWN viewing key and OWN selected notes; the coordinator hands over only the public
    //    effects + the per-lane alphas, never the viewing key or the notes.
    let pczt_bytes = {
        let proposer = &quorum[0];
        proposer
            .signer
            .build_candidate(&proposer.session, cand, intent, &alphas)
            .map_err(|e| format!("proposer {:?} build_candidate: {e}", proposer.id))?
            .0
    };
    let candidate = pczt::Pczt::parse(&pczt_bytes).map_err(|e| format!("parse candidate: {e:?}"))?;
    let sighash = pczt::roles::signer::Signer::new(candidate)
        .map_err(|e| format!("signer: {e:?}"))?
        .shielded_sighash();

    // 3. Round 2, per lane: every member renders+approves the SAME candidate (WYSIWYS binding
    //    against the shared sighash) and returns a share bound to its lane's nonce; aggregate
    //    into that lane's group signature under its randomized key.
    let mut lane_sigs: Vec<[u8; 64]> = Vec::with_capacity(lanes);
    let mut lane_rks: Vec<[u8; 32]> = Vec::with_capacity(lanes);
    for i in 0..lanes {
        let ci = lane_cand(i);
        let package = frost::SigningPackage::new(lane_commits[i].clone(), &sighash);
        let mut shares = BTreeMap::new();
        for m in quorum.iter_mut() {
            let share = m
                .signer
                .sign_approve(&m.session, &ci, &pczt_bytes, &package, &lane_seeds[i])
                .map_err(|e| format!("member {:?} sign_approve lane {i}: {e}", m.id))?;
            shares.insert(m.id, share);
        }
        let group_sig = frost_rerandomized::aggregate(&package, &shares, public, &lane_fparams[i])
            .map_err(|e| format!("aggregate lane {i}: {e}"))?;
        lane_fparams[i]
            .randomized_verifying_key()
            .verify(&sighash, &group_sig)
            .map_err(|e| format!("lane {i} does not verify under the randomized group key: {e}"))?;
        lane_sigs.push(
            group_sig
                .serialize()
                .map_err(|e| format!("{e}"))?
                .as_slice()
                .try_into()
                .map_err(|_| "signature is not 64 bytes")?,
        );
        lane_rks.push(
            lane_fparams[i]
                .randomized_verifying_key()
                .serialize()
                .map_err(|e| format!("{e}"))?
                .as_slice()
                .try_into()
                .map_err(|_| "randomized vk is not 32 bytes")?,
        );
    }

    // 4. Apply each lane's signature to the spend whose `rk` equals that lane's randomized
    //    verifying key (ak·alpha_i). The coordinator has no viewing key, so it matches by rk,
    //    never by nullifier; padding actions carry independent dummy `rk`s.
    let parsed = pczt::Pczt::parse(&pczt_bytes).map_err(|e| format!("reparse: {e:?}"))?;
    let mut indices = Vec::with_capacity(lanes);
    for (i, want_rk) in lane_rks.iter().enumerate() {
        let index = parsed
            .ironwood()
            .actions()
            .iter()
            .position(|a| a.spend().rk() == want_rk)
            .ok_or_else(|| format!("no spend under lane {i}'s randomized group key"))?;
        if indices.contains(&index) {
            return Err(format!("two lanes matched the same spend (index {index})"));
        }
        indices.push(index);
    }
    let mut signer =
        pczt::roles::signer::Signer::new(parsed).map_err(|e| format!("signer: {e:?}"))?;
    for (sig_bytes, index) in lane_sigs.iter().zip(indices) {
        let orchard_sig = orchard::primitives::redpallas::Signature::<
            orchard::primitives::redpallas::SpendAuth,
        >::from(*sig_bytes);
        signer
            .apply_ironwood_signature(index, orchard_sig)
            .map_err(|e| format!("apply signature: {e:?}"))?;
    }
    signer
        .finish()
        .serialize()
        .map_err(|e| format!("serialize signed: {e:?}"))
}

/// Member side of one setup pass: hand the signer what the coordinator relayed, then
/// send every setup message the signer returns to the coordinator. Only messages from
/// `coordinator` are taken: frostd lets any session participant write to a member, and
/// the coordinator's relay log is what checks each wire against its real sender. If the
/// signer refuses an input it still re-sends what it has saved, then the refusal is
/// returned. Returns how many messages it sent.
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

/// Drive a saved DKG until every certificate and backup receipt has arrived.
/// Expiry leaves the signer's checkpoint and relay log intact for the next runner.
#[allow(clippy::too_many_arguments)]
pub fn drive_dkg<S, T>(
    signer: &mut S,
    session: &Session,
    vault: &VaultRef,
    transport: &T,
    channel: &T::Channel,
    coordinator_peer: &Peer,
    coordinator: Option<(&T, &T::Channel)>,
    mut log: Option<&mut RelayLog>,
    peers: &BTreeMap<u16, Peer>,
    deadline: std::time::Instant,
) -> Result<(), String>
where
    S: Signer<Error = crate::signer::local::SignerError>,
    T: Transport,
    T::Error: std::fmt::Display,
{
    use crate::signer::local::SignerError;
    use std::time::{Duration, Instant};
    let mut backed_up = false;
    let mut redeliver_at = Instant::now();
    while Instant::now() < deadline {
        if let (Some((coord_tx, coord_ch)), Some(log)) = (&coordinator, &mut log) {
            relay_dkg(log, *coord_tx, *coord_ch, peers)?;
            if Instant::now() >= redeliver_at {
                // A peer may have restarted after draining its mailbox but before saving.
                redeliver_dkg(log, *coord_tx, *coord_ch, peers)?;
                redeliver_at = Instant::now() + Duration::from_secs(5);
            }
        }
        member_dkg_step(signer, session, vault, transport, channel, coordinator_peer)?;
        if !backed_up {
            match signer.backup(session) {
                Ok(wires) => {
                    for wire in wires {
                        transport.send(channel, &[], &Outbound::Dkg(wire))
                            .map_err(|e| e.to_string())?;
                    }
                    backed_up = true;
                }
                Err(SignerError::NotReady) => {}
                Err(e) => return Err(format!("backup: {e}")),
            }
        }
        if let (Some((coord_tx, coord_ch)), Some(log)) = (&coordinator, &mut log) {
            relay_dkg(log, *coord_tx, *coord_ch, peers)?;
        }
        if signer.list_vaults(session).map_err(|e| e.to_string())?[0].ready {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(250));
    }
    Err("DKG receipts did not complete; saved setup can be resumed".into())
}

/// Coordinator side of one setup pass: log each wire a member sent, then forward it to
/// its recipients. A message from outside the roster, or one that is not a well-formed
/// wire from its relay sender, is dropped. Returns how many new wires it forwarded.
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

/// After a coordinator restart: send every logged wire to its recipients again. Members
/// ignore exact repeats.
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

/// Dealer-keygen a t-of-n vault, seal each member's share under the element `make_se` hands
/// back, connect the first quorum (ids 1..=t), and drive the keyless loop to a signed PCZT.
/// `drive_to_signed_pczt` verifies the aggregated signature under the randomized group key
/// before returning, and we re-confirm the intended spend now carries a spend-auth sig — so
/// `Ok(())` means that `SecureElement` unwrapped every member's DEK inside the real sign flow.
/// Test-only: the shipped signer never constructs a dealer-generated vault.
#[cfg(test)]
pub(crate) fn prove_keyless_loop<SE: crate::signer::secure_element::SecureElement>(
    threshold: u16,
    members: u16,
    mut make_se: impl FnMut(u16) -> SE,
) -> Result<(), String> {
    use crate::signer::local::LocalSigner;
    use crate::signer::Network;
    use orchard::keys::Scope;

    let tempdir = |tag: &str| -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!(
            "loki-prove-{tag}-{}-{}",
            std::process::id(),
            rand_core::RngCore::next_u64(&mut rand_core::OsRng)
        ));
        let _ = std::fs::remove_dir_all(&p);
        p
    };

    let (shares, public) = frost::keys::generate_with_dealer(
        members,
        threshold,
        frost::keys::IdentifierList::Default,
        &mut rand_core::OsRng,
    )
    .map_err(|e| format!("dealer keygen: {e}"))?;
    let ak: [u8; 32] = public
        .verifying_key()
        .serialize()
        .map_err(|e| format!("verifying key: {e}"))?
        .try_into()
        .map_err(|_| "verifying key length".to_string())?;
    let fvk =
        crate::zip2005::frost_viewing_key(&ak, &[42u8; 32]).map_err(|e| format!("fvk: {e:?}"))?;

    let rho = orchard::note::Rho::from_bytes(&[1u8; 32]).unwrap();
    let rseed = orchard::note::RandomSeed::from_bytes([2u8; 32], &rho).unwrap();
    let note = orchard::Note::from_parts(
        fvk.address_at(0u64, Scope::External),
        orchard::value::NoteValue::from_raw(625_000_000),
        rho,
        rseed,
        orchard::NoteVersion::V3,
    )
    .unwrap();
    let pp_bytes = public.serialize().map_err(|e| format!("public package: {e}"))?;

    // One LocalSigner per quorum member (ids 1..=threshold), each share sealed via make_se.
    let mut signers: Vec<LocalSigner<SE>> = Vec::new();
    for id in 1..=threshold {
        let ident = frost::Identifier::try_from(id).unwrap();
        let kp = frost::keys::KeyPackage::try_from(shares.get(&ident).unwrap().clone()).unwrap();
        signers.push(
            LocalSigner::with_sealed_share(
                id,
                threshold,
                members,
                [id as u8; 32],
                "enclave vault".into(),
                Network::Regtest,
                make_se(id),
                &kp.serialize().unwrap(),
                pp_bytes.clone(),
                fvk.clone(),
                tempdir(&format!("t{threshold}n{members}m{id}")),
                Box::new(|_view| true),
            )
            .map_err(|e| format!("build signer {id}: {e}"))?,
        );
    }

    // Each signer scans its own note member-side; the coordinator never sees fvk or note.
    for s in signers.iter_mut() {
        s.set_candidate_notes(vec![note]);
    }

    let mut sessions: Vec<Session> = Vec::new();
    for s in signers.iter_mut() {
        sessions.push(
            s.connect("http://coordinator.test", Network::Regtest, b"u2-challenge")
                .map_err(|e| format!("connect: {e}"))?
                .session,
        );
    }

    let intent = PaymentIntent {
        recipient: fvk.address_at(7u64, Scope::External),
        amount: zcash_protocol::value::Zatoshis::const_from_u64(40_000_000),
        memo: zcash_protocol::memo::MemoBytes::from_bytes(b"loki u2").unwrap(),
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
        .map_err(|e| format!("keyless loop: {e}"))?;

    let parsed = pczt::Pczt::parse(&signed).map_err(|e| format!("parse signed pczt: {e:?}"))?;
    let nf = note.nullifier(&fvk).to_bytes();
    let action = parsed
        .ironwood()
        .actions()
        .iter()
        .find(|a| a.spend().nullifier() == &nf)
        .ok_or_else(|| "signed pczt no longer spends the intended note".to_string())?;
    if action.spend().spend_auth_sig().is_none() {
        return Err("aggregated signature was not applied to the spend".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::signer::secure_element::SoftwareSecureElement;

    /// Dealer-keygen a t-of-n vault and drive the first quorum through the keyless loop,
    /// sealing every share with the software element. See [`super::prove_keyless_loop`].
    fn roundtrip(threshold: u16, members: u16) {
        super::prove_keyless_loop(threshold, members, |_| SoftwareSecureElement::generate())
            .expect("the keyless loop produces a verified signed PCZT");
    }

    #[test]
    fn keyless_loop_signs_2_of_3() {
        roundtrip(2, 3);
    }

    #[test]
    fn keyless_loop_signs_3_of_5() {
        roundtrip(3, 5);
    }

    /// End-to-end proof of the native Enclave-gated signer: a 2-of-3 vault whose every share
    /// is sealed under a DEK wrapped by a real Apple Secure Enclave key drives the keyless
    /// loop to a signature the prover accepts. Ephemeral Enclave keys (no signing identity),
    /// so it runs unsigned from `cargo test`; the persistent, Face-ID-gated key is the same
    /// `SecureElement` surface in the provisioned signer-app (poc/signer-app/).
    #[cfg(all(feature = "apple-enclave", target_os = "macos"))]
    #[test]
    fn keyless_loop_signs_via_apple_enclave() {
        use crate::signer::secure_element_apple::AppleSecureElement;
        super::prove_keyless_loop(2, 3, |_| {
            AppleSecureElement::ephemeral().expect("open ephemeral Secure Enclave")
        })
        .expect("the keyless loop produces a verified signed PCZT via the Secure Enclave");
    }

    /// #4 multi-note: a payment that draws TWO notes ends with BOTH spends carrying a
    /// spend-auth signature — the N-lane signing loop runs one rerandomized FROST session per
    /// spend (its own nonce, alpha, aggregation) and applies each sig to the spend whose `rk`
    /// matches that lane's randomized key.
    #[test]
    fn two_note_payment_signs_both_spends() {
        use crate::signer::local::LocalSigner;
        use crate::signer::{Network, Signer};
        use orchard::keys::Scope;
        use reddsa_frost::frost::redpallas as frost;

        let (shares, public) = frost::keys::generate_with_dealer(
            3,
            2,
            frost::keys::IdentifierList::Default,
            &mut rand_core::OsRng,
        )
        .expect("dealer keygen");
        let ak: [u8; 32] = public.verifying_key().serialize().unwrap().try_into().unwrap();
        let fvk = crate::zip2005::frost_viewing_key(&ak, &[42u8; 32]).unwrap();
        // Two distinct notes to the vault, each enough to cover the payment on its own.
        let note = |seed: u8, pos: u64| {
            let rho = orchard::note::Rho::from_bytes(&[seed; 32]).unwrap();
            orchard::Note::from_parts(
                fvk.address_at(pos, Scope::External),
                orchard::value::NoteValue::from_raw(625_000_000),
                rho,
                orchard::note::RandomSeed::from_bytes([seed.wrapping_add(1); 32], &rho).unwrap(),
                orchard::NoteVersion::V3,
            )
            .unwrap()
        };
        let notes = vec![note(1, 0), note(3, 1)];
        let pp_bytes = public.serialize().unwrap();

        let tempdir = |tag: &str| {
            let p = std::env::temp_dir().join(format!(
                "loki-multinote-{tag}-{}-{}",
                std::process::id(),
                rand_core::RngCore::next_u64(&mut rand_core::OsRng)
            ));
            let _ = std::fs::remove_dir_all(&p);
            p
        };
        let mut signers: Vec<LocalSigner<SoftwareSecureElement>> = (1..=2u16)
            .map(|id| {
                let kp = frost::keys::KeyPackage::try_from(
                    shares.get(&frost::Identifier::try_from(id).unwrap()).unwrap().clone(),
                )
                .unwrap();
                LocalSigner::with_sealed_share(
                    id,
                    2,
                    3,
                    [id as u8; 32],
                    "multinote vault".into(),
                    Network::Regtest,
                    SoftwareSecureElement::generate(),
                    &kp.serialize().unwrap(),
                    pp_bytes.clone(),
                    fvk.clone(),
                    tempdir(&format!("m{id}")),
                    Box::new(|_| true),
                )
                .unwrap()
            })
            .collect();
        // The proposer selects BOTH notes for this payment.
        signers[0].set_candidate_notes(notes.clone());
        for s in signers.iter_mut().skip(1) {
            s.set_candidate_notes(notes.clone());
        }

        let sessions: Vec<super::Session> = signers
            .iter_mut()
            .map(|s| {
                s.connect("http://coordinator.test", Network::Regtest, b"u2")
                    .unwrap()
                    .session
            })
            .collect();
        let intent = super::PaymentIntent {
            recipient: fvk.address_at(7u64, Scope::External),
            amount: zcash_protocol::value::Zatoshis::const_from_u64(900_000_000), // needs both notes
            memo: zcash_protocol::memo::MemoBytes::from_bytes(b"multi-note").unwrap(),
            target_height: 700,
            expiry_height: 1_152,
        };
        let cand = super::CandidateRef { vault_id: [1u8; 32], payment_id: [7u8; 32], attempt_id: [9u8; 32] };
        let mut quorum: Vec<super::QuorumMember<'_, _>> = signers
            .iter_mut()
            .zip(sessions)
            .enumerate()
            .map(|(i, (signer, session))| super::QuorumMember {
                id: frost::Identifier::try_from((i as u16) + 1).unwrap(),
                session,
                signer,
            })
            .collect();

        let signed = super::drive_to_signed_pczt(&public, &intent, &cand, &mut quorum)
            .expect("the keyless loop signs the payment");
        let parsed = pczt::Pczt::parse(&signed).unwrap();
        let signed_spends = parsed
            .ironwood()
            .actions()
            .iter()
            .filter(|a| a.spend().spend_auth_sig().is_some())
            .count();
        assert_eq!(signed_spends, 2, "both input notes must be signed, got {signed_spends}");
    }
}
