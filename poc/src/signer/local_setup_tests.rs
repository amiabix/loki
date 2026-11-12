//! New-signer setup tests: the v2 DKG through `LocalSigner`'s own storage, the on-device
//! roster code, resume, cleanup, and the round-two leak the v2 envelopes close.

use super::*;
use crate::setup_transport::PublicIdentity;
use crate::signer::secure_element::SoftwareSecureElement;
use std::sync::{Arc, Mutex};

const PASS: &str = "member passphrase";
const ORIGIN: &str = "https://coordinator.test";

#[cfg(feature = "relay-communication")]
pub(crate) fn completed_signers(vault: [u8; 32]) -> Vec<(LocalSigner<SoftwareSecureElement>, PathBuf)> {
    let (mut members, document) = setup_members(2, 3, vault);
    let vault_ref = begin(&mut members, &document);
    complete(&mut members, &vault_ref, &mut Vec::new());
    members.into_iter().map(|m| (m.signer, m.dir)).collect()
}

fn tempdir(tag: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "loki-setup-{tag}-{}-{}",
        std::process::id(),
        rand_core::RngCore::next_u64(&mut rand_core::OsRng)
    ));
    let _ = std::fs::remove_dir_all(&p);
    p
}

/// Where the member keeps its backup in these tests.
#[derive(Clone, Default)]
struct Shelf(Arc<Mutex<Option<Vec<u8>>>>);

struct TestBackup {
    shelf: Shelf,
    passphrase: String,
    recovery_pub: Option<[u8; 32]>,
    recovery_shelf: Shelf,
}

impl BackupDevice for TestBackup {
    fn passphrase(&mut self) -> Option<Zeroizing<String>> {
        Some(Zeroizing::new(self.passphrase.clone()))
    }
    fn save(&mut self, artifact: &BackupArtifact) -> Result<(), String> {
        *self.shelf.0.lock().unwrap() = Some(artifact.0.clone());
        Ok(())
    }
    fn load(&mut self) -> Result<BackupArtifact, String> {
        self.shelf
            .0
            .lock()
            .unwrap()
            .clone()
            .map(BackupArtifact)
            .ok_or_else(|| "no stored backup".to_string())
    }
    fn recovery_public(&mut self) -> Option<[u8; 32]> {
        self.recovery_pub
    }
    fn save_recovery(&mut self, blob: &[u8]) -> Result<(), String> {
        *self.recovery_shelf.0.lock().unwrap() = Some(blob.to_vec());
        Ok(())
    }
}

/// The member's device: what it showed, and what the member answers.
#[derive(Clone)]
struct Device {
    codes: Arc<Mutex<Vec<String>>>,
    decision: Arc<Mutex<RosterDecision>>,
    delay: Duration,
    deadline: Duration,
    approve_connect: bool,
    shelf: Shelf,
    recovery_pub: Option<[u8; 32]>,
    recovery_shelf: Shelf,
}

impl Device {
    fn new() -> Self {
        Self {
            codes: Arc::default(),
            decision: Arc::new(Mutex::new(RosterDecision::Match)),
            delay: Duration::ZERO,
            deadline: Duration::from_secs(30),
            approve_connect: true,
            shelf: Shelf::default(),
            recovery_pub: None,
            recovery_shelf: Shelf::default(),
        }
    }

    fn prompts(&self) -> DevicePrompts {
        let codes = self.codes.clone();
        let decision = self.decision.clone();
        let delay = self.delay;
        let approve = self.approve_connect;
        DevicePrompts {
            connect: Box::new(move |origin, _| approve && origin == ORIGIN),
            roster: Box::new(move |code| {
                codes.lock().unwrap().push(code.to_owned());
                std::thread::sleep(delay);
                *decision.lock().unwrap()
            }),
            roster_deadline: self.deadline,
            backup: Box::new(TestBackup {
                shelf: self.shelf.clone(),
                passphrase: "backup words".into(),
                recovery_pub: self.recovery_pub,
                recovery_shelf: self.recovery_shelf.clone(),
            }),
            approval: Box::new(|_| true),
        }
    }
}

struct Member {
    id: u16,
    dir: PathBuf,
    device: Device,
    signer: LocalSigner<SoftwareSecureElement>,
    session: Session,
    public: PublicIdentity,
}

impl Member {
    fn create(id: u16, vault: [u8; 32], device: Device) -> Self {
        let dir = tempdir(&format!("m{id}"));
        let se = SoftwareSecureElement::persistent(&dir, PASS).unwrap();
        let mut signer = LocalSigner::create(
            &dir,
            se,
            Network::Regtest,
            vault,
            id,
            "setup vault".into(),
            device.prompts(),
        )
        .unwrap();
        let connection = signer
            .connect(ORIGIN, Network::Regtest, b"challenge")
            .unwrap();
        Self {
            id,
            dir,
            device,
            signer,
            session: connection.session,
            public: PublicIdentity {
                id: connection.member.id,
                signing: connection.member.signing,
                encryption: connection.member.encryption,
            },
        }
    }

    /// Restart: reopen the signer from its data directory and reconnect.
    fn reopen(&mut self) {
        let se = SoftwareSecureElement::persistent(&self.dir, PASS).unwrap();
        self.signer =
            LocalSigner::open(&self.dir, se, "setup vault".into(), self.device.prompts()).unwrap();
        self.session = self
            .signer
            .connect(ORIGIN, Network::Regtest, b"challenge-2")
            .unwrap()
            .session;
    }

    fn step(&mut self, vault: &VaultRef, inputs: &[DkgInput]) -> Result<Vec<DkgWire>, SignerError> {
        self.signer.dkg_step(&self.session, vault, inputs)
    }

    fn begin(&mut self, document: &[u8]) -> Result<VaultRef, SignerError> {
        self.signer.dkg_begin(&self.session, document)
    }

    fn release(&mut self) -> Result<ReleasedAddress, SignerError> {
        self.signer.release_address(&self.session)
    }

    fn try_reopen(&self) -> Result<LocalSigner<SoftwareSecureElement>, SignerError> {
        let se = SoftwareSecureElement::persistent(&self.dir, PASS).unwrap();
        LocalSigner::open(&self.dir, se, "setup vault".into(), self.device.prompts())
    }
}

fn roster_json(members: &[PublicIdentity], threshold: u16, vault: [u8; 32]) -> serde_json::Value {
    serde_json::json!({
        "vault": hex::encode(vault),
        "threshold": threshold,
        "setup_version": 2,
        "members": members.iter().map(|p| serde_json::json!({
            "id": p.id,
            "signing": hex::encode(p.signing),
            "encryption": hex::encode(p.encryption),
        })).collect::<Vec<_>>(),
    })
}

fn setup_members(threshold: u16, count: u16, vault: [u8; 32]) -> (Vec<Member>, Vec<u8>) {
    let members: Vec<Member> = (1..=count)
        .map(|id| Member::create(id, vault, Device::new()))
        .collect();
    let publics: Vec<_> = members.iter().map(|m| m.public.clone()).collect();
    let document = serde_json::to_vec(&roster_json(&publics, threshold, vault)).unwrap();
    (members, document)
}

fn begin(members: &mut [Member], document: &[u8]) -> VaultRef {
    let mut vault = None;
    for m in members.iter_mut() {
        vault = Some(m.signer.dkg_begin(&m.session, document).unwrap());
    }
    vault.unwrap()
}

type Inbox = BTreeMap<u16, Vec<DkgInput>>;

fn route(from: u16, wires: Vec<DkgWire>, count: u16, inbox: &mut Inbox, tape: &mut Vec<Vec<u8>>) {
    for wire in wires {
        // The relay tape keeps each distinct message once; members resend saved ones.
        if !tape.iter().any(|t| t.as_slice() == wire.as_bytes()) {
            tape.push(wire.as_bytes().to_vec());
        }
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

/// One coordinator pass: every member steps with what arrived, and its outgoing messages
/// are routed and recorded on the relay tape.
fn exchange(
    members: &mut [Member],
    vault: &VaultRef,
    inbox: &mut Inbox,
    tape: &mut Vec<Vec<u8>>,
) -> Result<(), SignerError> {
    let count = members.len() as u16;
    for m in members.iter_mut() {
        let inputs = inbox.remove(&m.id).unwrap_or_default();
        let out = m.signer.dkg_step(&m.session, vault, &inputs)?;
        route(m.id, out, count, inbox, tape);
    }
    Ok(())
}

fn phase(m: &Member) -> DkgPhase {
    m.signer.setup.as_ref().unwrap().core.phase()
}

/// Drive a confirmed setup to `ready`: rounds, certificates, backups and receipts.
fn complete(members: &mut [Member], vault: &VaultRef, tape: &mut Vec<Vec<u8>>) {
    let mut inbox = Inbox::new();
    for _ in 0..6 {
        exchange(members, vault, &mut inbox, tape).unwrap();
    }
    assert!(members.iter().all(|m| phase(m) == DkgPhase::Certified));
    for m in members.iter() {
        assert!(!m.signer.list_vaults(&m.session).unwrap()[0].ready);
    }
    let count = members.len() as u16;
    for m in members.iter_mut() {
        let receipt = m.signer.backup(&m.session).unwrap();
        route(m.id, receipt, count, &mut inbox, tape);
    }
    exchange(members, vault, &mut inbox, tape).unwrap();
    for m in members.iter() {
        assert!(
            m.signer.list_vaults(&m.session).unwrap()[0].ready,
            "member {}",
            m.id
        );
    }
}

/// Rebuild the group signing key from plaintext round-two packages, keyed by
/// (sender, recipient): interpolate each sender's constant term from the shares it sent
/// and add them up. Returns the group key it implies.
fn rebuild_group_key(packages: &BTreeMap<(u16, u16), Vec<u8>>, threshold: u16) -> Option<[u8; 32]> {
    use frost_core::Group;
    use std::collections::BTreeSet;
    let senders: BTreeSet<u16> = packages.keys().map(|(s, _)| *s).collect();
    let mut secret = pasta_curves::pallas::Scalar::zero();
    for sender in senders {
        let shares: Vec<(u16, pasta_curves::pallas::Scalar)> = packages
            .iter()
            .filter(|((s, _), _)| *s == sender)
            .take(usize::from(threshold))
            .map(|((_, r), bytes)| {
                let package = frost::keys::dkg::round2::Package::deserialize(bytes).ok()?;
                Some((*r, package.signing_share().to_scalar()))
            })
            .collect::<Option<_>>()?;
        if shares.len() < usize::from(threshold) {
            return None;
        }
        let ids: BTreeSet<frost::Identifier> = shares
            .iter()
            .map(|(r, _)| frost::Identifier::try_from(*r).unwrap())
            .collect();
        for (r, share) in &shares {
            let lambda = frost_core::compute_lagrange_coefficient::<frost::PallasBlake2b512>(
                &ids,
                None,
                frost::Identifier::try_from(*r).unwrap(),
            )
            .ok()?;
            secret += lambda * share;
        }
    }
    let point = frost::PallasGroup::generator() * secret;
    let bytes: [u8; 32] = {
        let s = frost::PallasGroup::serialize(&point).ok()?;
        let r: &[u8] = s.as_ref();
        r.try_into().ok()?
    };
    Some(bytes)
}

/// The group key with either Y parity, since part 3 normalizes it to even Y.
fn same_group_key(rebuilt: [u8; 32], group: [u8; 32]) -> bool {
    use frost_core::Group;
    let point = frost::PallasGroup::deserialize(&rebuilt).unwrap();
    let serialized = frost::PallasGroup::serialize(&(-point)).unwrap();
    let negated: &[u8] = serialized.as_ref();
    let negated: [u8; 32] = negated.try_into().unwrap();
    rebuilt == group || negated == group
}

fn group_key(m: &Member) -> [u8; 32] {
    frost::keys::PublicKeyPackage::deserialize(m.signer.public_package_bytes().unwrap())
        .unwrap()
        .verifying_key()
        .serialize()
        .unwrap()
        .try_into()
        .unwrap()
}

#[test]
fn new_signer_setup_reaches_ready_only_after_every_receipt_and_signs() {
    for (threshold, count) in [(2u16, 3u16), (3, 4)] {
        let vault = [count as u8 + 40; 32];
        let (mut members, document) = setup_members(threshold, count, vault);
        let vault_ref = begin(&mut members, &document);
        assert_eq!((vault_ref.threshold, vault_ref.members), (threshold, count));
        let codes: Vec<String> = members
            .iter()
            .map(|m| m.device.codes.lock().unwrap()[0].clone())
            .collect();
        assert!(
            codes.iter().all(|c| c == &codes[0]),
            "every device shows the same code"
        );

        // Before ready: no address, and signing is refused.
        assert!(matches!(members[0].release(), Err(SignerError::NotReady)));
        let mut tape = Vec::new();
        complete(&mut members, &vault_ref, &mut tape);

        let key = group_key(&members[0]);
        assert!(members.iter().all(|m| group_key(m) == key));
        let addresses: Vec<_> = members
            .iter_mut()
            .map(|m| m.signer.release_address(&m.session).unwrap())
            .collect();
        assert!(addresses
            .iter()
            .all(|a| a == &addresses[0] && a.vault_id == vault));
        assert!(addresses[0].address.starts_with("uregtest"));

        // The fresh setup key is gone from every saved checkpoint.
        for m in &members {
            let store = SignerStore::open(&m.dir).unwrap();
            let (_, raw) = store.read(&m.signer.se, FileKind::Setup).unwrap().unwrap();
            assert!(!SetupCheckpoint::decode(&raw).unwrap().core.has_fresh_key());
        }

        // The DKG-born share signs a candidate for the group key (2-of-n fixture).
        if threshold != 2 {
            continue;
        }
        let first = &mut members[0];
        let fvk = first.signer.vault_fvk.clone().unwrap();
        let key1 = first.signer.open_key().unwrap();
        let public = frost::keys::PublicKeyPackage::deserialize(
            first.signer.public_package_bytes().unwrap(),
        )
        .unwrap();
        let cand = CandidateRef {
            vault_id: vault,
            payment_id: [7; 32],
            attempt_id: [9; 32],
        };
        let own_commit = first.signer.sign_commit(&first.session, &cand).unwrap();
        let (_n, peer_commit) = frost::round1::commit(key1.signing_share(), &mut rand_core::OsRng);
        let (pczt, pkg, seed) = super::tests::candidate_and_package(
            &fvk,
            &key1,
            &public,
            frost::Identifier::try_from(2u16).unwrap(),
            peer_commit,
            own_commit,
            true,
        );
        let share = first
            .signer
            .sign_approve(&first.session, &cand, &pczt, &pkg, &seed)
            .expect("a DKG-born share signs");
        assert_eq!(share.serialize().len(), 32);
    }
}

/// Guard 1: record every setup message the relay carried and try to rebuild the vault's
/// group key, even with every member's long-lived identity keys. It must fail on v2. The
/// same attacker succeeds against the formats it replaces: plaintext round-two packages,
/// and v1 envelopes sealed to the long-lived encryption keys.
#[test]
fn recorded_relay_traffic_cannot_rebuild_the_group_key() {
    let (threshold, count, vault) = (2u16, 3u16, [61u8; 32]);
    let (mut members, document) = setup_members(threshold, count, vault);
    let vault_ref = begin(&mut members, &document);
    let mut tape = Vec::new();
    complete(&mut members, &vault_ref, &mut tape);
    let group = group_key(&members[0]);

    // The attacker also holds every member's long-lived identity (signing + encryption).
    let identities: BTreeMap<u16, Identity> = members
        .iter()
        .map(|m| {
            let secret = Zeroizing::new(m.signer.identity.as_ref().unwrap().to_secret_bytes());
            (m.id, Identity::from_secret_bytes(&secret[..]).unwrap())
        })
        .collect();
    let mut recovered = BTreeMap::new();
    let mut envelopes = 0;
    for wire in &tape {
        assert!(
            frost::keys::dkg::round2::Package::deserialize(wire).is_err(),
            "a plaintext round-two package crossed the relay"
        );
        if crate::setup_transport::wire_kind(wire) != Some(DkgWireKind::Round2) {
            continue;
        }
        envelopes += 1;
        let parsed = DkgWire::parse(wire.clone()).unwrap();
        let recipient = parsed.recipient().unwrap();
        let sender = identities[&parsed.sender()].public();
        // Long-lived keys do not open v2 envelopes.
        if let Ok(plain) = identities[&recipient].open_round2(&sender, &vault, wire) {
            recovered.insert((parsed.sender(), recipient), plain[32..].to_vec());
        }
    }
    assert_eq!(envelopes, usize::from(count * (count - 1)));
    assert!(recovered.is_empty());
    assert!(rebuild_group_key(&recovered, threshold).is_none());

    // Control: the same attacker against the formats v2 replaces.
    let mut starting = BTreeMap::new();
    let mut round1 = BTreeMap::new();
    for id in 1..=count {
        let (member, public) =
            crate::distributed_setup::Member::start_with_policy(id, threshold, count).unwrap();
        starting.insert(id, member);
        round1.insert(id, public);
    }
    let mut plaintext = BTreeMap::new();
    let mut v1_tape = Vec::new();
    let mut finished = Vec::new();
    let mut outgoing_all = BTreeMap::new();
    for (id, member) in starting {
        let (r2, outgoing) = member.advance(&round1).unwrap();
        for (recipient, package) in &outgoing {
            plaintext.insert((id, *recipient), package.clone());
            v1_tape.push((
                id,
                *recipient,
                identities[&id]
                    .seal_round2(&identities[recipient].public(), &vault, package)
                    .unwrap(),
            ));
        }
        outgoing_all.insert(id, outgoing);
        finished.push((id, r2));
    }
    let (own, r2) = &finished[0];
    let incoming = outgoing_all
        .iter()
        .filter(|(sender, _)| *sender != own)
        .map(|(sender, out)| (*sender, out[own].clone()))
        .collect();
    let control_group = r2.finish(&incoming).unwrap();
    let control_key: [u8; 32] =
        frost::keys::PublicKeyPackage::deserialize(control_group.public_package())
            .unwrap()
            .verifying_key()
            .serialize()
            .unwrap()
            .try_into()
            .unwrap();
    // Plaintext packages (the leak in the earlier signer path): immediate rebuild.
    let rebuilt = rebuild_group_key(&plaintext, threshold).unwrap();
    assert!(same_group_key(rebuilt, control_key));
    // v1 envelopes: a later compromise of the long-lived encryption keys opens them all.
    let opened: BTreeMap<_, _> = v1_tape
        .iter()
        .map(|(sender, recipient, wire)| {
            (
                (*sender, *recipient),
                identities[recipient]
                    .open_round2(&identities[sender].public(), &vault, wire)
                    .unwrap(),
            )
        })
        .collect();
    let rebuilt = rebuild_group_key(&opened, threshold).unwrap();
    assert!(same_group_key(rebuilt, control_key));
    assert!(!same_group_key(rebuilt, group));
}

#[test]
fn restart_between_rounds_re_emits_identical_bytes_and_completes() {
    let vault = [62u8; 32];
    let (mut members, document) = setup_members(2, 3, vault);
    let vault_ref = begin(&mut members, &document);
    // Restart right after the roster confirmation too.
    for m in members.iter_mut() {
        m.reopen();
    }
    let mut inbox = Inbox::new();
    let mut tape = Vec::new();
    for round in 0..3 {
        let before: Vec<Vec<DkgWire>> = members
            .iter_mut()
            .map(|m| m.signer.dkg_step(&m.session, &vault_ref, &[]).unwrap())
            .collect();
        for m in members.iter_mut() {
            m.reopen();
        }
        let after: Vec<Vec<DkgWire>> = members
            .iter_mut()
            .map(|m| m.signer.dkg_step(&m.session, &vault_ref, &[]).unwrap())
            .collect();
        assert_eq!(
            before, after,
            "round {round}: a restart must resend the saved bytes"
        );
        exchange(&mut members, &vault_ref, &mut inbox, &mut tape).unwrap();
    }
    // Peers saw only identical copies, so nobody raised equivocation.
    complete(&mut members, &vault_ref, &mut tape);
    for m in members.iter_mut() {
        m.reopen();
        assert!(m.signer.list_vaults(&m.session).unwrap()[0].ready);
        m.signer.release_address(&m.session).unwrap();
    }
}

#[test]
fn swapped_or_rolled_back_files_are_rejected_or_only_abort() {
    let vault = [63u8; 32];
    let (mut members, document) = setup_members(2, 3, vault);
    let vault_ref = begin(&mut members, &document);
    let mut inbox = Inbox::new();
    let mut tape = Vec::new();
    exchange(&mut members, &vault_ref, &mut inbox, &mut tape).unwrap();
    let round1_checkpoint = std::fs::read(members[0].dir.join("setup.sealed")).unwrap();

    // Rolled back while no share exists yet: member 1 reopens in round one, re-encrypts
    // round two with new randomness, and its peers see a second, different envelope.
    exchange(&mut members, &vault_ref, &mut inbox, &mut tape).unwrap();
    assert_eq!(phase(&members[0]), DkgPhase::Round2);
    let saved: Vec<_> = members
        .iter()
        .map(|m| std::fs::read(m.dir.join("setup.sealed")).unwrap())
        .collect();
    std::fs::write(members[0].dir.join("setup.sealed"), &round1_checkpoint).unwrap();
    members[0].reopen();
    assert_eq!(phase(&members[0]), DkgPhase::Round1);
    let mut aborted = false;
    for _ in 0..3 {
        if exchange(&mut members, &vault_ref, &mut inbox, &mut tape).is_err() {
            aborted = true;
            break;
        }
    }
    assert!(
        aborted,
        "a rolled-back member's new round two must make a peer abort"
    );

    // Fresh vault to check swapped files and a rollback across the share.
    let vault = [64u8; 32];
    let (mut members, document) = setup_members(2, 3, vault);
    let vault_ref = begin(&mut members, &document);
    let mut inbox = Inbox::new();
    exchange(&mut members, &vault_ref, &mut inbox, &mut tape).unwrap();
    let early = std::fs::read(members[0].dir.join("setup.sealed")).unwrap();
    complete(&mut members, &vault_ref, &mut tape);
    drop(saved);
    for file in [
        "setup.sealed",
        "share.sealed",
        "roster.sealed",
        "identity.sealed",
    ] {
        let own = std::fs::read(members[0].dir.join(file)).unwrap();
        // Another member's file of the same type.
        std::fs::copy(members[1].dir.join(file), members[0].dir.join(file)).unwrap();
        assert!(
            members[0].try_reopen().is_err(),
            "{file} from another member must not open"
        );
        // The same member's file under another type's name.
        let other = if file == "setup.sealed" {
            "share.sealed"
        } else {
            "setup.sealed"
        };
        std::fs::write(
            members[0].dir.join(file),
            std::fs::read(members[0].dir.join(other)).unwrap(),
        )
        .unwrap();
        assert!(
            members[0].try_reopen().is_err(),
            "{other} under {file} must not open"
        );
        std::fs::write(members[0].dir.join(file), &own).unwrap();
        members[0].try_reopen().unwrap();
    }
    // A setup checkpoint rolled back behind the saved share.
    let own = std::fs::read(members[0].dir.join("setup.sealed")).unwrap();
    std::fs::write(members[0].dir.join("setup.sealed"), &early).unwrap();
    assert!(members[0].try_reopen().is_err());
    std::fs::write(members[0].dir.join("setup.sealed"), &own).unwrap();
    // A crash after the certified checkpoint was saved but before the share file was
    // written: the checkpoint holds the share, so reopening writes the same share again.
    let share = std::fs::read(members[0].dir.join("share.sealed")).unwrap();
    std::fs::remove_file(members[0].dir.join("share.sealed")).unwrap();
    members[0].reopen();
    assert!(members[0].dir.join("share.sealed").exists());
    assert!(members[0].signer.list_vaults(&members[0].session).unwrap()[0].ready);
    assert_eq!(
        members[0].signer.open_key().unwrap().serialize().unwrap(),
        {
            std::fs::write(members[0].dir.join("share.sealed"), &share).unwrap();
            members[0].reopen();
            members[0].signer.open_key().unwrap().serialize().unwrap()
        }
    );

    // A crash between saving the confirmed roster and its empty setup.
    let (mut members, document) = setup_members(2, 3, [65u8; 32]);
    let vault_ref = begin(&mut members, &document);
    std::fs::remove_file(members[0].dir.join("setup.sealed")).unwrap();
    members[0].reopen();
    assert_eq!(phase(&members[0]), DkgPhase::Empty);
    complete(&mut members, &vault_ref, &mut tape);
}

#[test]
fn a_bad_message_after_the_share_exists_is_refused_and_the_share_kept() {
    let vault = [66u8; 32];
    let (mut members, document) = setup_members(2, 3, vault);
    let vault_ref = begin(&mut members, &document);
    let mut inbox = Inbox::new();
    let mut tape = Vec::new();
    for _ in 0..6 {
        exchange(&mut members, &vault_ref, &mut inbox, &mut tape).unwrap();
    }
    assert!(members.iter().all(|m| phase(m) == DkgPhase::Certified));

    // Member 2 signs messages that differ from what member 1 saved: a backup receipt
    // over another body, and a second certificate.
    let liar = members[1].signer.identity.as_ref().unwrap();
    let forged = [
        liar.sign_backup(&vault, b"a different backup body")
            .unwrap(),
        liar.sign_certificate(&vault, b"a different certificate")
            .unwrap(),
    ];
    for bytes in forged {
        let input = DkgInput { sender: 2, bytes };
        match members[0].step(&vault_ref, &[input]) {
            Err(SignerError::MessageRefused(_)) => {}
            other => panic!("a bad message after the share must be refused, got {other:?}"),
        }
        assert_eq!(phase(&members[0]), DkgPhase::Certified);
        members[0].try_reopen().expect("the signer still opens");
    }
    // The setup carries on: backups, every real receipt, ready, and the same group key.
    let before = group_key(&members[0]);
    members[0].reopen();
    let count = members.len() as u16;
    for m in members.iter_mut() {
        let receipt = m.signer.backup(&m.session).unwrap();
        route(m.id, receipt, count, &mut inbox, &mut tape);
    }
    exchange(&mut members, &vault_ref, &mut inbox, &mut tape).unwrap();
    for m in &members {
        assert!(
            m.signer.list_vaults(&m.session).unwrap()[0].ready,
            "member {}",
            m.id
        );
    }
    assert_eq!(group_key(&members[0]), before);
}

#[test]
fn delayed_certificates_are_saved_across_restart_without_redealing() {
    let (mut members, document) = setup_members(2, 3, [96; 32]);
    let vault_ref = begin(&mut members, &document);
    let mut inbox = Inbox::new();
    let mut tape = Vec::new();
    let mut delayed = BTreeMap::new();
    for _ in 0..6 {
        for m in &mut members {
            let mut inputs = inbox.remove(&m.id).unwrap_or_default();
            if m.id == 1 {
                inputs.retain(|input| {
                    if DkgWire::parse(input.bytes.clone()).unwrap().kind() == DkgWireKind::Certificate {
                        delayed.insert(input.sender, input.clone());
                        false
                    } else { true }
                });
            }
            let out = m.step(&vault_ref, &inputs).unwrap();
            route(m.id, out, 3, &mut inbox, &mut tape);
        }
    }
    assert_eq!(phase(&members[0]), DkgPhase::Certificate);
    let share = members[0].signer.open_key().unwrap().serialize().unwrap();
    members[0].step(&vault_ref, &[delayed.remove(&2).unwrap()]).unwrap();
    members[0].reopen();
    assert_eq!(phase(&members[0]), DkgPhase::Certificate);
    assert!(matches!(members[0].release(), Err(SignerError::NotReady)));
    let certificate = delayed.remove(&3).unwrap();
    let mut forged = certificate.clone();
    *forged.bytes.last_mut().unwrap() ^= 1;
    assert!(matches!(members[0].step(&vault_ref, &[forged]), Err(SignerError::MessageRefused(_))));
    members[0].step(&vault_ref, &[certificate]).unwrap();
    assert_eq!(phase(&members[0]), DkgPhase::Certified);
    assert_eq!(members[0].signer.open_key().unwrap().serialize().unwrap(), share);
    complete(&mut members, &vault_ref, &mut tape);
}

#[test]
fn abandoned_setup_is_wiped_and_final() {
    let vault = [65u8; 32];
    let (mut members, document) = setup_members(2, 3, vault);
    let vault_ref = begin(&mut members, &document);
    let mut inbox = Inbox::new();
    let mut tape = Vec::new();
    exchange(&mut members, &vault_ref, &mut inbox, &mut tape).unwrap();
    assert!(members[0]
        .signer
        .setup
        .as_ref()
        .unwrap()
        .core
        .has_fresh_key());
    members[0].signer.abandon_setup().unwrap();
    let check = |m: &Member| {
        let setup = m.signer.setup.as_ref().unwrap();
        assert!(setup.aborted);
        assert!(setup.core.is_wiped());
        assert!(setup.outgoing.is_empty() && setup.pending.is_empty());
    };
    check(&members[0]);
    assert!(matches!(
        members[0].step(&vault_ref, &[]),
        Err(SignerError::SetupAborted(_))
    ));
    members[0].reopen();
    check(&members[0]);
    assert!(matches!(
        members[0].step(&vault_ref, &[]),
        Err(SignerError::SetupAborted(_))
    ));
    assert!(members[0].begin(&document).is_err());
}

fn expect_rejected(member: &mut Member, document: &serde_json::Value, case: &str) {
    let shown = member.device.codes.lock().unwrap().len();
    let result = member
        .signer
        .dkg_begin(&member.session, &serde_json::to_vec(document).unwrap());
    assert!(
        matches!(result, Err(SignerError::RosterRejected(_))),
        "{case}: expected a roster rejection, got {result:?}"
    );
    assert_eq!(
        member.device.codes.lock().unwrap().len(),
        shown,
        "{case}: no code may be shown for a rejected roster"
    );
    assert!(
        !member.dir.join("roster.sealed").exists(),
        "{case}: nothing saved"
    );
    assert!(
        !member.dir.join("setup.sealed").exists(),
        "{case}: nothing saved"
    );
}

#[test]
fn roster_gate_rejects_bad_rosters_before_showing_a_code() {
    let vault = [66u8; 32];
    let (mut members, document) = setup_members(2, 3, vault);
    let base: serde_json::Value = serde_json::from_slice(&document).unwrap();
    let first = &mut members[0];
    let set = |field: &str, member: usize, value: serde_json::Value| {
        let mut doc = base.clone();
        doc["members"][member][field] = value;
        doc
    };
    // A small-order (weak) Ed25519 key: the identity point.
    let mut weak = [0u8; 32];
    weak[0] = 1;
    expect_rejected(
        first,
        &set("signing", 1, hex::encode(weak).into()),
        "weak signing key",
    );
    let duplicate_signing = base["members"][2]["signing"].clone();
    expect_rejected(
        first,
        &set("signing", 1, duplicate_signing),
        "duplicate signing key",
    );
    let duplicate_encryption = base["members"][2]["encryption"].clone();
    expect_rejected(
        first,
        &set("encryption", 1, duplicate_encryption),
        "duplicate encryption key",
    );
    expect_rejected(
        first,
        &set("encryption", 1, hex::encode([0u8; 32]).into()),
        "non-contributory key",
    );
    let other = Identity::new(1).public();
    expect_rejected(
        first,
        &set("encryption", 0, hex::encode(other.encryption).into()),
        "own identity with a wrong encryption key",
    );
    let mut doc = base.clone();
    doc["threshold"] = 3.into();
    expect_rejected(first, &doc, "t = n");
    let mut doc = base.clone();
    let mut list = doc["members"].as_array().unwrap().clone();
    for id in 4..=17u16 {
        let p = Identity::new(id).public();
        list.push(serde_json::json!({"id": id, "signing": hex::encode(p.signing), "encryption": hex::encode(p.encryption)}));
    }
    doc["members"] = list.into();
    expect_rejected(first, &doc, "n > 16");
    let mut doc = base.clone();
    doc["network"] = "testnet".into();
    doc["birth_height"] = crate::network::TESTNET_NU7_BIRTH.into();
    expect_rejected(first, &doc, "wrong network");
    let mut doc = base.clone();
    doc["vault"] = hex::encode([67u8; 32]).into();
    expect_rejected(first, &doc, "another vault");
    let mut doc = base.clone();
    doc.as_object_mut().unwrap().remove("setup_version");
    expect_rejected(first, &doc, "missing setup_version");
    let mut doc = base.clone();
    doc["setup_version"] = 1.into();
    expect_rejected(first, &doc, "setup_version 1");
    // The untouched roster still goes through.
    first.signer.dkg_begin(&first.session, &document).unwrap();
}

#[test]
fn coordinator_key_swap_changes_the_code_and_the_signer_refuses() {
    let vault = [68u8; 32];
    let (mut members, document) = setup_members(2, 3, vault);
    let base: serde_json::Value = serde_json::from_slice(&document).unwrap();
    // The coordinator swaps member 2's keys for its own in member 1's list only.
    let attacker = Identity::new(2).public();
    let mut swapped = base.clone();
    swapped["members"][1]["signing"] = hex::encode(attacker.signing).into();
    swapped["members"][1]["encryption"] = hex::encode(attacker.encryption).into();
    *members[0].device.decision.lock().unwrap() = RosterDecision::NoMatch;
    let refused = members[0].begin(&serde_json::to_vec(&swapped).unwrap());
    assert!(matches!(refused, Err(SignerError::RosterRejected(_))));
    members[1].begin(&document).unwrap();
    let first_code = members[0].device.codes.lock().unwrap()[0].clone();
    let second_code = members[1].device.codes.lock().unwrap()[0].clone();
    assert_ne!(
        first_code, second_code,
        "a swapped key must change the code"
    );
    assert!(!members[0].dir.join("roster.sealed").exists());

    // One fake list sent to everyone: member 3 is replaced, so member 3 refuses outright.
    let mut fake = base.clone();
    let impostor = Identity::new(3).public();
    fake["members"][2]["signing"] = hex::encode(impostor.signing).into();
    fake["members"][2]["encryption"] = hex::encode(impostor.encryption).into();
    expect_rejected(&mut members[2], &fake, "own identity missing");
}

#[test]
fn roster_code_is_24_digits_and_covers_every_field() {
    let identities: Vec<_> = (1..=3).map(|id| Identity::new(id).public()).collect();
    let base = roster_json(&identities, 2, [69; 32]);
    let code = |doc: &serde_json::Value| {
        roster_code(
            &Roster::from_bytes(&serde_json::to_vec(doc).unwrap())
                .unwrap()
                .fingerprint(),
        )
    };
    let shown = code(&base);
    assert_eq!(shown.len(), 29);
    let groups: Vec<_> = shown.split(' ').collect();
    assert_eq!(groups.len(), 6);
    assert!(groups
        .iter()
        .all(|g| g.len() == 4 && g.bytes().all(|b| b.is_ascii_digit())));
    let mut variants = Vec::new();
    let mut doc = base.clone();
    doc["vault"] = hex::encode([70u8; 32]).into();
    variants.push(doc);
    let mut doc = base.clone();
    doc["threshold"] = 1.into();
    variants.push(doc);
    let mut doc = base.clone();
    doc["setup_version"] = 3.into();
    variants.push(doc);
    let mut doc = base.clone();
    doc["network"] = "testnet".into();
    doc["birth_height"] = crate::network::TESTNET_NU7_BIRTH.into();
    variants.push(doc);
    let mut doc = base.clone();
    doc["network"] = "regtest".into();
    variants.push(doc.clone());
    for field in ["signing", "encryption"] {
        let mut doc = base.clone();
        doc["members"][2][field] = hex::encode(Identity::new(3).public().signing).into();
        variants.push(doc);
    }
    let mut doc = base.clone();
    doc["members"][1]["id"] = 4.into();
    doc["members"][2]["id"] = 2.into();
    variants.push(doc);
    for (i, variant) in variants.iter().enumerate() {
        if i == 4 {
            continue;
        }
        if let Ok(roster) = Roster::from_bytes(&serde_json::to_vec(variant).unwrap()) {
            assert_ne!(roster_code(&roster.fingerprint()), shown, "{variant}");
        }
    }
    // An explicit regtest network is the default network: same roster, same code.
    assert_eq!(code(&variants[4]), shown);
}

/// Sign a second, different round one as `member` (a member running modified software).
fn equivocating_round1(member: &Member, document: &[u8]) -> Vec<u8> {
    let roster = ValidatedRoster::new(Roster::from_bytes(document).unwrap()).unwrap();
    let identity = member.signer.identity.as_ref().unwrap();
    let (_, out) = DkgCore::new(&roster, identity).unwrap().start().unwrap();
    out[&1].clone()
}

#[test]
fn equivocation_on_frost_round1_aborts_and_the_abort_is_final() {
    let vault = [71u8; 32];
    let (mut members, document) = setup_members(2, 3, vault);
    let vault_ref = begin(&mut members, &document);
    let mut inbox = Inbox::new();
    let mut tape = Vec::new();
    // Everyone emits round one.
    for m in members.iter_mut() {
        let out = m.signer.dkg_step(&m.session, &vault_ref, &[]).unwrap();
        route(m.id, out, 3, &mut inbox, &mut tape);
    }
    // Member 2 shows member 1 a different, validly signed round one than member 3 saw.
    let other = equivocating_round1(&members[1], &document);
    for input in inbox.get_mut(&1).unwrap().iter_mut() {
        if input.sender == 2 {
            input.bytes = other.clone();
        }
    }
    let mut aborted = None;
    for _ in 0..4 {
        if let Err(e) = exchange(&mut members, &vault_ref, &mut inbox, &mut tape) {
            aborted = Some(e);
            break;
        }
    }
    assert!(
        matches!(aborted, Some(SignerError::SetupAborted(_))),
        "the round-two transcript check must catch it, got {aborted:?}"
    );
    let stopped: Vec<_> = members
        .iter()
        .filter(|m| m.signer.setup.as_ref().unwrap().aborted)
        .map(|m| m.id)
        .collect();
    assert!(!stopped.is_empty());
    for m in members.iter_mut().filter(|m| stopped.contains(&m.id)) {
        assert!(m.signer.setup.as_ref().unwrap().core.is_wiped());
        // Final: the same or fresh inputs never restart it.
        assert!(matches!(
            m.signer.dkg_step(&m.session, &vault_ref, &[]),
            Err(SignerError::SetupAborted(_))
        ));
    }

    // Two different round ones from one member, seen by the same member: immediate abort.
    let vault = [72u8; 32];
    let (mut members, document) = setup_members(2, 3, vault);
    let vault_ref = begin(&mut members, &document);
    let first = members[1].step(&vault_ref, &[]).unwrap();
    let second = equivocating_round1(&members[1], &document);
    let inputs = vec![
        DkgInput {
            sender: 2,
            bytes: first[0].as_bytes().to_vec(),
        },
        DkgInput {
            sender: 2,
            bytes: second,
        },
    ];
    assert!(matches!(
        members[0].step(&vault_ref, &inputs),
        Err(SignerError::SetupAborted(_))
    ));
}

#[test]
fn forged_or_unsigned_round1_and_substituted_fresh_keys_are_rejected() {
    let cases: [(&str, fn(&mut Vec<u8>, &Identity, &[u8; 32])); 4] = [
        ("corrupted signature", |wire, _, _| {
            *wire.last_mut().unwrap() ^= 1;
        }),
        ("signed by another key", |wire, impostor, vault| {
            let body = wire[46..wire.len() - 64].to_vec();
            *wire = impostor.sign_round1(vault, &body).unwrap();
        }),
        ("substituted fresh key", |wire, _, _| {
            // Body: commitment (32) then fresh key (32), after the 46-byte header.
            wire[46 + 32] ^= 1;
        }),
        ("unsigned", |wire, _, _| {
            let len = wire.len();
            wire[len - 64..].fill(0);
        }),
    ];
    for (case, tamper) in cases {
        let vault = [73u8; 32];
        let (mut members, document) = setup_members(2, 3, vault);
        let vault_ref = begin(&mut members, &document);
        let mut wire = members[1].step(&vault_ref, &[]).unwrap()[0]
            .as_bytes()
            .to_vec();
        tamper(&mut wire, &Identity::new(2), &vault);
        let result = members[0].step(
            &vault_ref,
            &[DkgInput {
                sender: 2,
                bytes: wire,
            }],
        );
        assert!(
            matches!(result, Err(SignerError::SetupAborted(_))),
            "{case}: {result:?}"
        );
    }
}

#[test]
fn cancel_timeout_and_no_match_save_nothing() {
    let vault = [74u8; 32];
    let (mut members, document) = setup_members(2, 3, vault);
    *members[0].device.decision.lock().unwrap() = RosterDecision::Cancelled;
    assert!(matches!(
        members[0].begin(&document),
        Err(SignerError::Cancelled)
    ));
    assert!(!members[0].dir.join("roster.sealed").exists());

    let mut slow = Device::new();
    slow.delay = Duration::from_millis(60);
    slow.deadline = Duration::from_millis(10);
    let mut late = Member::create(2, vault, slow);
    let publics = vec![
        members[0].public.clone(),
        late.public.clone(),
        members[2].public.clone(),
    ];
    let doc = serde_json::to_vec(&roster_json(&publics, 2, vault)).unwrap();
    assert!(matches!(
        late.signer.dkg_begin(&late.session, &doc),
        Err(SignerError::TimedOut)
    ));
    assert!(!late.dir.join("roster.sealed").exists());
    late.reopen();
    assert!(late.signer.list_vaults(&late.session).unwrap().is_empty());

    // After a cancel the member can still compare and confirm.
    *members[0].device.decision.lock().unwrap() = RosterDecision::Match;
    members[0].begin(&document).unwrap();
}

#[test]
fn address_release_needs_ready_and_an_approved_session() {
    let vault = [75u8; 32];
    let mut refusing = Device::new();
    refusing.approve_connect = false;
    let dir = tempdir("refuse-connect");
    let se = SoftwareSecureElement::persistent(&dir, PASS).unwrap();
    let mut signer = LocalSigner::create(
        &dir,
        se,
        Network::Regtest,
        vault,
        1,
        "v".into(),
        refusing.prompts(),
    )
    .unwrap();
    assert!(matches!(
        signer.connect(ORIGIN, Network::Regtest, b"c"),
        Err(SignerError::ConnectRefused)
    ));

    let (mut members, document) = setup_members(2, 3, vault);
    let vault_ref = begin(&mut members, &document);
    let mut tape = Vec::new();
    complete(&mut members, &vault_ref, &mut tape);
    members[0].release().unwrap();
    // A wrong passphrase cannot open the signer's KEK.
    assert!(SoftwareSecureElement::persistent(&members[0].dir, "wrong").is_err());
}

/// General t-of-n on the new signer path: a DKG to ready, then a quorum of exactly `t`
/// DKG-born signers drives the keyless loop to a signed candidate.
#[test]
fn recovery_backup_is_sealed_to_the_words_not_the_passphrase() {
    use crate::signer::backup::{verify, verify_recovery, BackupArtifact};
    use crate::signer::recovery::RecoveryKey;

    let vault = [71u8; 32];
    let (threshold, count) = (2u16, 3u16);
    // Each member establishes its own recovery identity before setup.
    let keys: Vec<RecoveryKey> = (0..count).map(|_| RecoveryKey::generate().unwrap().1).collect();
    let mut members: Vec<Member> = (1..=count)
        .map(|id| {
            let mut device = Device::new();
            device.recovery_pub = Some(keys[(id - 1) as usize].public_bytes());
            Member::create(id, vault, device)
        })
        .collect();
    let publics: Vec<_> = members.iter().map(|m| m.public.clone()).collect();
    let document = serde_json::to_vec(&roster_json(&publics, threshold, vault)).unwrap();
    let vault_ref = begin(&mut members, &document);
    let mut tape = Vec::new();
    complete(&mut members, &vault_ref, &mut tape);

    for (i, m) in members.iter().enumerate() {
        let recovery_blob = m.device.recovery_shelf.0.lock().unwrap().clone().unwrap();
        let passphrase_blob = m.device.shelf.0.lock().unwrap().clone().unwrap();
        assert_ne!(recovery_blob, passphrase_blob, "two distinct artifacts");

        // The recovery copy opens with the member's words-derived key...
        let material = verify_recovery(&BackupArtifact(recovery_blob.clone()), &keys[i], &vault)
            .expect("recovery backup opens with the recovery words");
        assert_eq!(material.member_id, (i as u16) + 1);

        // ...but the account passphrase canNOT open the recovery copy (no login/backup conflation),
        // and the recovery words are not the passphrase artifact either.
        assert!(
            verify(&BackupArtifact(recovery_blob), "backup words", &vault).is_err(),
            "the account passphrase must not open the recovery backup"
        );
        assert!(
            verify_recovery(&BackupArtifact(passphrase_blob), &keys[i], &vault).is_err(),
            "the recovery key must not open the passphrase backup"
        );
    }
}

// A real member whose FROST share lives in its own Secure Enclave, run end to end on this
// Mac: real v2 DKG (no dealer), share sealed/unsealed through the Enclave, then a signed
// payment the prover accepts. Ephemeral key (process-lifetime, so no reopen) — runs unsigned
// from `cargo test`; the persistent, Face-ID-gated key is the same surface in a signed binary.
// A real member whose FROST share lives in its own Secure Enclave, run end to end on this
// Mac: real v2 DKG (no dealer), share sealed/unsealed through the Enclave, then a signed
// payment the prover accepts. Ephemeral key here (process-lifetime, runs unsigned from
// `cargo test`); the persistent, Face-ID-gated key is the same call with `persistent(tag)` —
// see `signer::native_member` + the signed-app `member` selftest.
#[cfg(all(feature = "apple-enclave", target_os = "macos"))]
#[test]
fn real_enclave_member_runs_dkg_and_signs() {
    use crate::signer::secure_element_apple::AppleSecureElement;
    crate::signer::native_member::prove_dkg_member(2, 3, |_| {
        AppleSecureElement::ephemeral().expect("open ephemeral Secure Enclave")
    })
    .expect("a real Enclave-backed member runs the DKG and signs a payment");
}

#[test]
fn general_policies_run_the_dkg_and_sign() {
    use crate::signer::coordination::{drive_to_signed_pczt, PaymentIntent, QuorumMember};
    for (threshold, count) in [(2u16, 3u16), (3, 5), (15, 16)] {
        let vault = [count as u8 + 80; 32];
        let (mut members, document) = setup_members(threshold, count, vault);
        let vault_ref = begin(&mut members, &document);
        let mut tape = Vec::new();
        complete(&mut members, &vault_ref, &mut tape);
        let addresses: Vec<String> = members
            .iter_mut()
            .map(|m| m.release().unwrap().address)
            .collect();
        assert!(addresses.iter().all(|a| a == &addresses[0]));
        let recipient = crate::vault::orchard_receiver_from_ua(
            &addresses[0],
            zcash_protocol::consensus::NetworkType::Regtest,
        )
        .unwrap();
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
            members[0].signer.public_package_bytes().unwrap(),
        )
        .unwrap();
        // The quorum is the last `threshold` members, so member 1 is not always in it.
        let mut quorum: Vec<QuorumMember<'_, _>> = members
            .iter_mut()
            .skip(usize::from(count - threshold))
            .map(|m| {
                m.signer.set_candidate_notes(vec![note]);
                QuorumMember {
                    id: frost::Identifier::try_from(m.id).unwrap(),
                    session: m.session.clone(),
                    signer: &mut m.signer,
                }
            })
            .collect();
        let intent = PaymentIntent {
            recipient,
            amount: zcash_protocol::value::Zatoshis::const_from_u64(40_000_000),
            memo: zcash_protocol::memo::MemoBytes::from_bytes(b"t-of-n").unwrap(),
            target_height: 700,
            expiry_height: 1_152,
        };
        let cand = CandidateRef {
            vault_id: vault,
            payment_id: [7; 32],
            attempt_id: [9; 32],
        };
        drive_to_signed_pczt(&public, &intent, &cand, &mut quorum)
            .unwrap_or_else(|e| panic!("{threshold}-of-{count}: {e}"));
    }
}
