//! In-process native-member proof: a real v2 DKG (no dealer) + a signed payment, with each
//! member's FROST share held by a [`SecureElement`] — the Secure Enclave for the Apple backend.
//!
//! The ephemeral cargo test and the signed-app *persistent* selftest both call
//! [`prove_dkg_member`]; the ONLY difference is which key `make_se` hands back. So flipping a
//! member from ephemeral (process-lifetime, runs unsigned) to persistent (survives restart,
//! Face-ID-gated, needs a signed binary) is a one-argument change — this is "step 2". The
//! members route DKG wires in-process here; the live version routes them over the frostd relay
//! ("step 3").

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use reddsa_frost::frost::redpallas as frost;
use zeroize::Zeroizing;

use super::backup::BackupArtifact;
use super::coordination::{drive_to_signed_pczt, PaymentIntent, QuorumMember};
use super::local::{ApprovalPolicy, BackupDevice, DevicePrompts, LocalSigner, RosterDecision};
use super::secure_element::SecureElement;
use super::{CandidateRef, DkgInput, Network, Session, Signer};
use super::wysiwys::PaymentView;
use crate::setup_transport::{DkgWire, PublicIdentity};

struct Member<SE: SecureElement> {
    id: u16,
    signer: LocalSigner<SE>,
    session: Session,
    public: PublicIdentity,
}

/// An in-memory backup store with no recovery identity — enough to satisfy the signer's
/// save-and-prove-load step during DKG.
#[derive(Clone, Default)]
struct MemBackup(Arc<Mutex<Option<Vec<u8>>>>);

impl BackupDevice for MemBackup {
    fn passphrase(&mut self) -> Option<Zeroizing<String>> {
        Some(Zeroizing::new("native member backup".into()))
    }
    fn save(&mut self, artifact: &BackupArtifact) -> Result<(), String> {
        *self.0.lock().unwrap() = Some(artifact.0.clone());
        Ok(())
    }
    fn load(&mut self) -> Result<BackupArtifact, String> {
        self.0
            .lock()
            .unwrap()
            .clone()
            .map(BackupArtifact)
            .ok_or_else(|| "no stored backup".into())
    }
}

fn prompts(
    reviewed: Arc<Mutex<Option<(CandidateRef, PaymentView)>>>,
    mut native: Option<ApprovalPolicy>,
) -> DevicePrompts {
    let mut approved_sighash = None;
    DevicePrompts {
        connect: Box::new(|_origin, _net| true),
        roster: Box::new(|_code| RosterDecision::Match),
        roster_deadline: Duration::from_secs(30),
        backup: Box::new(MemBackup::default()),
        approval: Box::new(move |request| {
            let Ok(reviewed) = reviewed.lock() else { return false; };
            if reviewed.as_ref() != Some(&(*request.candidate, request.view.clone())) {
                return false;
            }
            // The native selftest explicitly approves one intent and pins its first candidate.
            if *approved_sighash.get_or_insert(request.sighash) != request.sighash {
                return false;
            }
            // Then the member's own decision, when a native approval channel is attached.
            native.as_mut().map_or(true, |approve| approve(request))
        }),
    }
}

type Inbox = BTreeMap<u16, Vec<DkgInput>>;

fn route(from: u16, wires: Vec<DkgWire>, count: u16, inbox: &mut Inbox) {
    for wire in wires {
        let recipients: Vec<u16> = match wire.recipient() {
            Some(r) => vec![r],
            None => (1..=count).filter(|r| *r != from).collect(),
        };
        for r in recipients {
            inbox.entry(r).or_default().push(DkgInput {
                sender: from,
                bytes: wire.as_bytes().to_vec(),
            });
        }
    }
}

fn tempdir(id: u16) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "loki-native-m{id}-{}-{}",
        std::process::id(),
        rand_core::RngCore::next_u64(&mut rand_core::OsRng)
    ));
    let _ = std::fs::remove_dir_all(&p);
    p
}

/// Build `members` real signers whose shares are held by `make_se(id)`, run the full v2 DKG
/// in-process, then have the first `threshold` of them sign a payment the prover accepts.
/// `Ok(())` means every share was generated and sealed through its SecureElement and the
/// quorum produced a verified signature — the native-member lifecycle end to end.
pub fn prove_dkg_member<SE: SecureElement>(
    threshold: u16,
    members: u16,
    make_se: impl FnMut(u16) -> SE,
) -> Result<(), String> {
    prove_dkg_member_with(threshold, members, make_se, |_| None)
}

/// [`prove_dkg_member`] where member `id`'s payment approval also asks `native(id)`, the
/// member's own decision (the signer app's dialog). A refusal stops the payment.
pub fn prove_dkg_member_with<SE: SecureElement>(
    threshold: u16,
    members: u16,
    mut make_se: impl FnMut(u16) -> SE,
    mut native: impl FnMut(u16) -> Option<ApprovalPolicy>,
) -> Result<(), String> {
    let vault = [61u8; 32];

    let mut ms: Vec<Member<SE>> = Vec::new();
    let mut approvals = Vec::new();
    for id in 1..=members {
        let reviewed = Arc::new(Mutex::new(None));
        approvals.push(reviewed.clone());
        let mut signer = LocalSigner::create(
            &tempdir(id),
            make_se(id),
            Network::Regtest,
            vault,
            id,
            "native vault".into(),
            prompts(reviewed, native(id)),
        )
        .map_err(|e| format!("create member {id}: {e:?}"))?;
        let conn = signer
            .connect("https://coordinator.test", Network::Regtest, b"challenge")
            .map_err(|e| format!("connect member {id}: {e:?}"))?;
        let public = PublicIdentity {
            id: conn.member.id,
            signing: conn.member.signing,
            encryption: conn.member.encryption,
        };
        ms.push(Member { id, signer, session: conn.session, public });
    }

    let document = serde_json::to_vec(&serde_json::json!({
        "vault": hex::encode(vault),
        "threshold": threshold,
        "setup_version": 2,
        "members": ms.iter().map(|m| serde_json::json!({
            "id": m.public.id,
            "signing": hex::encode(m.public.signing),
            "encryption": hex::encode(m.public.encryption),
        })).collect::<Vec<_>>(),
    }))
    .map_err(|e| e.to_string())?;

    let mut vref = None;
    for m in ms.iter_mut() {
        vref = Some(
            m.signer
                .dkg_begin(&m.session, &document)
                .map_err(|e| format!("dkg_begin {}: {e:?}", m.id))?,
        );
    }
    let vref = vref.ok_or("no members")?;

    let mut inbox = Inbox::new();
    for _ in 0..6 {
        for m in ms.iter_mut() {
            let inputs = inbox.remove(&m.id).unwrap_or_default();
            let out = m
                .signer
                .dkg_step(&m.session, &vref, &inputs)
                .map_err(|e| format!("dkg_step {}: {e:?}", m.id))?;
            route(m.id, out, members, &mut inbox);
        }
    }
    for m in ms.iter_mut() {
        let receipt = m
            .signer
            .backup(&m.session)
            .map_err(|e| format!("backup {}: {e:?}", m.id))?;
        route(m.id, receipt, members, &mut inbox);
    }
    for m in ms.iter_mut() {
        let inputs = inbox.remove(&m.id).unwrap_or_default();
        let out = m
            .signer
            .dkg_step(&m.session, &vref, &inputs)
            .map_err(|e| format!("dkg_step(final) {}: {e:?}", m.id))?;
        route(m.id, out, members, &mut inbox);
    }
    let ready = ms.iter().all(|m| {
        m.signer
            .list_vaults(&m.session)
            .map(|v| v.first().map(|s| s.ready).unwrap_or(false))
            .unwrap_or(false)
    });
    if !ready {
        return Err("not every member reached ready after DKG".into());
    }

    // Every member derives the same vault address; a quorum signs a payment to it.
    let mut addresses = Vec::new();
    for m in ms.iter_mut() {
        addresses.push(
            m.signer
                .release_address(&m.session)
                .map_err(|e| format!("release_address {}: {e:?}", m.id))?
                .address,
        );
    }
    if !addresses.iter().all(|a| a == &addresses[0]) {
        return Err("members derived different vault addresses".into());
    }
    let recipient = crate::vault::orchard_receiver_from_ua(
        &addresses[0],
        zcash_protocol::consensus::NetworkType::Regtest,
    )
    .map_err(|e| format!("recipient: {e:?}"))?;
    let rho = orchard::note::Rho::from_bytes(&[1u8; 32]).unwrap();
    let note = orchard::Note::from_parts(
        recipient,
        orchard::value::NoteValue::from_raw(625_000_000),
        rho,
        orchard::note::RandomSeed::from_bytes([2u8; 32], &rho).unwrap(),
        orchard::NoteVersion::V3,
    )
    .unwrap();
    let public = frost::keys::PublicKeyPackage::deserialize(
        ms[0].signer.public_package_bytes().ok_or("no public package")?,
    )
    .map_err(|e| e.to_string())?;
    let intent = PaymentIntent {
        recipient,
        amount: zcash_protocol::value::Zatoshis::const_from_u64(40_000_000),
        memo: zcash_protocol::memo::MemoBytes::from_bytes(b"native member").unwrap(),
        target_height: 700,
        expiry_height: 1_152,
    };
    let cand = CandidateRef { vault_id: vault, payment_id: [7; 32], attempt_id: [9; 32] };
    let (_, fvk) = ms[0].signer.hosted_metadata().map_err(|e| e.to_string())?;
    let fee: u64 = crate::candidate::quote_fee(&crate::candidate::Regtest, &crate::candidate::CandidateInputs {
        vault_fvk: &fvk, notes: vec![note], recipient, amount: intent.amount, memo: intent.memo.clone(),
        change: zcash_protocol::value::Zatoshis::ZERO, target_height: intent.target_height, expiry_height: intent.expiry_height,
    })?.into();
    let view = PaymentView {
        to: recipient.to_raw_address_bytes(), amount_zat: 40_000_000, fee_zat: fee,
        change_zat: 625_000_000 - 40_000_000 - fee, memo: intent.memo.as_array().to_vec(),
        network_branch_id: u32::from(zcash_protocol::consensus::BranchId::for_height(
            &crate::candidate::Regtest, zcash_protocol::consensus::BlockHeight::from_u32(intent.target_height))), fee_verified: true, expiry_height: intent.expiry_height,
    };
    for approval in &approvals {
        *approval.lock().map_err(|e| e.to_string())? = Some((cand, view.clone()));
    }
    let mut quorum: Vec<QuorumMember<'_, _>> = ms
        .iter_mut()
        .skip(usize::from(members - threshold))
        .map(|m| {
            m.signer.set_candidate_notes(vec![note]);
            QuorumMember {
                id: frost::Identifier::try_from(m.id).unwrap(),
                session: m.session.clone(),
                signer: &mut m.signer,
            }
        })
        .collect();
    drive_to_signed_pczt(&public, &intent, &cand, &mut quorum)
        .map_err(|e| format!("keyless signing: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_consent_requires_recorded_intent_and_pins_sighash() {
        let reviewed = Arc::new(Mutex::new(None));
        let mut device = prompts(reviewed.clone(), None);
        let candidate = CandidateRef { vault_id: [1; 32], payment_id: [2; 32], attempt_id: [3; 32] };
        let view = PaymentView { to: [4; 43], amount_zat: 1, fee_zat: 1, change_zat: 1,
            memo: vec![], expiry_height: 1, network_branch_id: 1, fee_verified: true };
        let request = super::super::local::ApprovalRequest { candidate: &candidate, sighash: [5; 32], view: &view };
        assert!(!(device.approval)(&request));
        *reviewed.lock().unwrap() = Some((candidate, view.clone()));
        assert!((device.approval)(&request));
        assert!(!(device.approval)(&super::super::local::ApprovalRequest { sighash: [6; 32], ..request }));
        // The member's native refusal overrides a recorded intent.
        let mut refusing = prompts(reviewed.clone(), Some(Box::new(|_| false)));
        assert!(!(refusing.approval)(&request));
    }

    #[test]
    fn software_native_member_runs_real_dkg_and_signs_reviewed_payment() {
        prove_dkg_member(2, 3, |_| super::super::secure_element::SoftwareSecureElement::generate()).unwrap();
    }
}
