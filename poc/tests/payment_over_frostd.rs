use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    thread,
};

use loki_poc::candidate::{quote_fee, CandidateInputs};
use loki_poc::network::VaultNetwork;
use loki_poc::payment_transport::{coordinate_resumable, signer_loop_resumable, Progress, SigningRun, DRIVE_YIELDED};
use loki_poc::setup_transport::Identity;
use loki_poc::signer::{
    local::LocalSigner, secure_element::SoftwareSecureElement, CandidateRef, Network,
    PublicPaymentParams, Signer,
};
use loki_poc::transport::{FrostdLoginKey, FrostdTransport, Incoming, Outbound, PaymentEncryption, Peer, Transport};
use loki_poc::zip2005;
use orchard::{
    keys::{FullViewingKey, Scope},
    note::{RandomSeed, Rho},
    value::NoteValue,
    NoteVersion,
};
use reddsa_frost::frost::redpallas as frost;
use uuid::Uuid;
use zcash_protocol::{memo::MemoBytes, value::Zatoshis};

struct MemoryTransport {
    payment: Option<PaymentEncryption>,
    me: Peer,
    coordinator: Peer,
    inboxes: Arc<Mutex<BTreeMap<[u8; 32], Vec<Incoming>>>>,
}

impl Transport for MemoryTransport {
    type Error = String;
    type Channel = Uuid;

    fn set_deadline(&self, _: Option<std::time::Instant>) -> bool { true }
    fn open(&mut self, _peers: &[Peer], _message_count: u8) -> Result<Uuid, String> {
        Ok(Uuid::new_v4())
    }
    fn join(&mut self, session: Uuid) -> Result<Uuid, String> {
        Ok(session)
    }
    fn send(&self, _channel: &Uuid, to: &[Peer], message: &Outbound) -> Result<(), String> {
        let recipients = if to.is_empty() {
            std::slice::from_ref(&self.coordinator)
        } else {
            to
        };
        let mut inboxes = self.inboxes.lock().unwrap();
        for recipient in recipients {
            inboxes.entry(recipient.0).or_default().push(Incoming {
                from: self.me.clone(),
                message: self.payment.as_ref().unwrap().seal(recipient, message).map_err(|e| e.to_string())?,
            });
        }
        Ok(())
    }
    fn recv(&self, _channel: &Uuid, _as_coordinator: bool) -> Result<Vec<Incoming>, String> {
        Ok(self
            .inboxes
            .lock()
            .unwrap()
            .remove(&self.me.0)
            .unwrap_or_default().into_iter().map(|incoming| {
                Ok(Incoming { message: self.payment.as_ref().unwrap().open(&incoming.from, &incoming.message).map_err(|e| e.to_string())?, ..incoming })
            }).collect::<Result<_, String>>()?)
    }
    fn close(&self, _channel: Uuid) -> Result<(), String> {
        Ok(())
    }
}

const NOTE_VALUE: u64 = 625_000_000;

fn vault_note(fvk: &FullViewingKey, seed: u8) -> orchard::Note {
    let rho = Rho::from_bytes(&[seed; 32]).unwrap();
    let rseed = RandomSeed::from_bytes([seed.wrapping_add(1); 32], &rho).unwrap();
    orchard::Note::from_parts(
        fvk.address_at(0u64, Scope::External),
        NoteValue::from_raw(NOTE_VALUE),
        rho,
        rseed,
        NoteVersion::V3,
    )
    .unwrap()
}

#[test]
fn two_of_three_payment_pczt_verifies_over_frostd() {
    let url = std::env::var("FROSTD_URL").expect("set FROSTD_URL to the running frostd relay");
    roundtrip(
        Identity::new(0),
        VaultNetwork::Regtest,
        1,
        |identity| {
            let secret: [u8; 32] = identity.to_secret_bytes()[34..].try_into().unwrap();
            FrostdTransport::new(&url, FrostdLoginKey::from_secret_bytes(secret)).unwrap()
        },
        |channel| channel.session_id(),
    );
    eprintln!("payment over frostd: 2-of-3 PCZT signature verifies under randomized group key");
}

/// #4 multi-note over the REAL frostd relay: a 2-note payment signs both spends across the
/// network relay (not in-memory). Set FROSTD_URL to the live relay.
#[test]
fn multi_note_payment_signs_every_spend_over_frostd() {
    let url = std::env::var("FROSTD_URL").expect("set FROSTD_URL to the running frostd relay");
    roundtrip(
        Identity::new(0),
        VaultNetwork::Regtest,
        2,
        |identity| {
            let secret: [u8; 32] = identity.to_secret_bytes()[34..].try_into().unwrap();
            FrostdTransport::new(&url, FrostdLoginKey::from_secret_bytes(secret)).unwrap()
        },
        |channel| channel.session_id(),
    );
    eprintln!("multi-note over frostd: both spends carry valid randomized spend-auth sigs");
}

#[test]
fn two_of_three_payment_pczt_verifies_in_memory() {
    let inboxes = Arc::new(Mutex::new(BTreeMap::new()));
    let coordinator = Identity::new(0);
    let coordinator_peer = Peer(coordinator.public().encryption);
    roundtrip(
        coordinator,
        VaultNetwork::Regtest,
        1,
        |identity| MemoryTransport {
            payment: None,
            me: Peer(identity.public().encryption),
            coordinator: coordinator_peer.clone(),
            inboxes: inboxes.clone(),
        },
        |channel| *channel,
    );
}

/// #4 multi-note over the relay: a payment drawing TWO notes signs BOTH spends over the
/// (in-memory) frostd transport — `signer_loop`/`coordinate` run one rerandomized FROST lane
/// per spend, batched into one message per phase so the wire flow matches single-note.
#[test]
fn multi_note_payment_signs_every_spend_in_memory() {
    let inboxes = Arc::new(Mutex::new(BTreeMap::new()));
    let coordinator = Identity::new(0);
    let coordinator_peer = Peer(coordinator.public().encryption);
    roundtrip(
        coordinator,
        VaultNetwork::Regtest,
        2,
        |identity| MemoryTransport {
            payment: None,
            me: Peer(identity.public().encryption),
            coordinator: coordinator_peer.clone(),
            inboxes: inboxes.clone(),
        },
        |channel| *channel,
    );
}

#[test]
fn testnet_payment_uses_nu7_over_in_memory_transport() {
    let inboxes = Arc::new(Mutex::new(BTreeMap::new()));
    let coordinator = Identity::new(0);
    let coordinator_peer = Peer(coordinator.public().encryption);
    roundtrip(
        coordinator,
        VaultNetwork::Testnet,
        1,
        |identity| MemoryTransport {
            payment: None,
            me: Peer(identity.public().encryption),
            coordinator: coordinator_peer.clone(),
            inboxes: inboxes.clone(),
        },
        |channel| *channel,
    );
}

trait EncryptedTransport: Transport {
    fn encrypt(&mut self, encryption: PaymentEncryption);
}
impl EncryptedTransport for MemoryTransport {
    fn encrypt(&mut self, encryption: PaymentEncryption) { self.payment = Some(encryption); }
}
impl EncryptedTransport for FrostdTransport {
    fn encrypt(&mut self, encryption: PaymentEncryption) { self.encrypt_payments(encryption).unwrap(); }
}

#[test]
fn staggered_approval_after_old_ten_second_window() {
    let inboxes = Arc::new(Mutex::new(BTreeMap::new()));
    let coordinator = Identity::new(0);
    let coordinator_peer = Peer(coordinator.public().encryption);
    roundtrip_delayed(
        coordinator, VaultNetwork::Regtest, 1,
        |identity| MemoryTransport { payment: None, me: Peer(identity.public().encryption),
            coordinator: coordinator_peer.clone(), inboxes: inboxes.clone() },
        |channel| *channel, std::time::Duration::from_secs(20), Faults::default(),
    );
}

#[test]
fn payment_resumes_round_one_and_burned_shares_after_restart() {
    let inboxes = Arc::new(Mutex::new(BTreeMap::new()));
    let coordinator = Identity::new(0);
    let coordinator_peer = Peer(coordinator.public().encryption);
    roundtrip_delayed(
        coordinator, VaultNetwork::Regtest, 2,
        |identity| MemoryTransport { payment: None, me: Peer(identity.public().encryption),
            coordinator: coordinator_peer.clone(), inboxes: inboxes.clone() },
        |channel| *channel, std::time::Duration::from_millis(300), Faults { restart: true, ..Faults::default() },
    );
}

#[derive(Default, Clone, Copy)]
struct Faults { restart: bool, drop_package: bool, lose_shares: bool, sliced: bool }

fn payment_with_delivery_faults(faults: Faults) {
    let inboxes = Arc::new(Mutex::new(BTreeMap::new()));
    let coordinator = Identity::new(0);
    let coordinator_peer = Peer(coordinator.public().encryption);
    roundtrip_delayed(coordinator, if faults.sliced { VaultNetwork::Testnet } else { VaultNetwork::Regtest }, 2,
        |identity| MemoryTransport { payment: None, me: Peer(identity.public().encryption),
            coordinator: coordinator_peer.clone(), inboxes: inboxes.clone() },
        |channel| *channel, std::time::Duration::ZERO, faults);
}

#[test]
fn payment_accepts_seed_before_redelivered_package() {
    payment_with_delivery_faults(Faults { drop_package: true, ..Faults::default() });
}

#[test]
fn payment_recovers_shares_lost_by_destructive_receive() {
    payment_with_delivery_faults(Faults { lose_shares: true, ..Faults::default() });
}

#[test]
fn testnet_payment_converges_across_bounded_coordinator_and_signer_drives() {
    payment_with_delivery_faults(Faults { sliced: true, ..Faults::default() });
}

#[derive(Clone, Copy)]
enum Interrupt { None, Commitment, Package, Share, DropPackage, LoseShares, SlowReceive }
struct Interrupted<T> { inner: T, at: Interrupt, fired: std::cell::Cell<bool>, deadline: std::cell::Cell<Option<std::time::Instant>> }
impl<T: Transport> Transport for Interrupted<T> where T::Error: std::fmt::Display {
    type Error = String;
    type Channel = T::Channel;
    fn set_deadline(&self, deadline: Option<std::time::Instant>) -> bool {
        self.deadline.set(deadline);
        self.inner.set_deadline(deadline)
    }
    fn open(&mut self, peers: &[Peer], n: u8) -> Result<T::Channel, String> { self.inner.open(peers, n).map_err(|e| e.to_string()) }
    fn join(&mut self, session: Uuid) -> Result<T::Channel, String> { self.inner.join(session).map_err(|e| e.to_string()) }
    fn send(&self, channel: &T::Channel, to: &[Peer], message: &Outbound) -> Result<(), String> {
        if matches!((self.at, message), (Interrupt::DropPackage, Outbound::Package(_))) && !self.fired.replace(true) {
            return Ok(()); // The relay accepted the package but its delivery was lost.
        }
        let interrupt = matches!((self.at, message),
            (Interrupt::Commitment, Outbound::Commitments(_)) | (Interrupt::Package, Outbound::Package(_)) | (Interrupt::Share, Outbound::Share(_)));
        if interrupt && !self.fired.replace(true) { return Err("injected process interruption".into()); }
        self.inner.send(channel, to, message).map_err(|e| e.to_string())
    }
    fn recv(&self, channel: &T::Channel, coordinator: bool) -> Result<Vec<Incoming>, String> {
        if matches!(self.at, Interrupt::SlowReceive) && !self.fired.replace(true) {
            let delay = std::time::Duration::from_millis(250);
            thread::sleep(self.deadline.get().map_or(delay, |deadline|
                deadline.saturating_duration_since(std::time::Instant::now()).min(delay)));
            if self.deadline.get().is_some_and(|deadline| std::time::Instant::now() >= deadline) {
                return Err("injected receive timeout".into());
            }
        }
        let messages = self.inner.recv(channel, coordinator).map_err(|e| e.to_string())?;
        // This fixture has two 32-byte shares: count:u16 + 2 * (len:u32 + share).
        if matches!(self.at, Interrupt::LoseShares) && messages.iter().any(|m| m.message.len() == 74)
            && !self.fired.replace(true) {
            return Err("injected lost receive response".into());
        }
        Ok(messages)
    }
    fn close(&self, channel: T::Channel) -> Result<(), String> { self.inner.close(channel).map_err(|e| e.to_string()) }
}

fn resumed_run(dir: &loki_poc::state::MemberDir) -> SigningRun<'_> {
    let progress = if dir.exists("progress.sealed") {
        serde_json::from_slice(&dir.read_sealed("progress.sealed", "test pass").unwrap()).unwrap()
    } else { Progress::default() };
    SigningRun::new(progress, std::time::Duration::from_secs(60), |progress| {
        let bytes = serde_json::to_vec(progress).unwrap();
        dir.write_sealed("next.sealed", &bytes, "test pass").unwrap();
        std::fs::rename(dir.path().join("next.sealed"), dir.path().join("progress.sealed")).unwrap();
        Ok(())
    }, || Ok(())).unwrap()
}

fn roundtrip<T: EncryptedTransport + Send>(
    coordinator: Identity,
    network: VaultNetwork,
    notes_wanted: usize,
    make_transport: impl Fn(&Identity) -> T,
    session_id: impl Fn(&T::Channel) -> Uuid,
) where T::Channel: Send, T::Error: std::fmt::Debug + std::fmt::Display {
    roundtrip_delayed(coordinator, network, notes_wanted, make_transport, session_id, std::time::Duration::ZERO, Faults::default());
}

fn roundtrip_delayed<T: EncryptedTransport + Send>(
    coordinator: Identity,
    network: VaultNetwork,
    notes_wanted: usize,
    make_transport: impl Fn(&Identity) -> T,
    session_id: impl Fn(&T::Channel) -> Uuid,
    delay: std::time::Duration,
    faults: Faults,
) where
    T::Channel: Send,
    T::Error: std::fmt::Debug + std::fmt::Display,
{
    let restart = faults.restart;
    let received = std::sync::atomic::AtomicBool::new(false);
    let (shares, public) = frost::keys::generate_with_dealer(
        3,
        2,
        frost::keys::IdentifierList::Default,
        &mut rand_core::OsRng,
    )
    .unwrap();
    let keys: BTreeMap<_, _> = shares
        .into_iter()
        .map(|(id, share)| (id, frost::keys::KeyPackage::try_from(share).unwrap()))
        .collect();
    let ak: [u8; 32] = public
        .verifying_key()
        .serialize()
        .unwrap()
        .try_into()
        .unwrap();
    let fvk = zip2005::frost_viewing_key(&ak, &[42u8; 32]).unwrap();
    let notes: Vec<orchard::Note> = (0..notes_wanted)
        .map(|i| vault_note(&fvk, (i + 1) as u8))
        .collect();
    // Amount chosen to require every note (for N>1, more than N-1 notes can cover).
    let amount = (notes_wanted as u64 - 1) * NOTE_VALUE + 40_000_000;
    let mut inputs = CandidateInputs {
        vault_fvk: &fvk,
        notes: notes.clone(),
        recipient: fvk.address_at(7u64, Scope::External),
        amount: Zatoshis::from_u64(amount).unwrap(),
        memo: MemoBytes::from_bytes(b"loki u2").unwrap(),
        change: Zatoshis::ZERO,
        target_height: if network == VaultNetwork::Testnet {
            4_465_056
        } else {
            700
        },
        expiry_height: if network == VaultNetwork::Testnet {
            4_466_208
        } else {
            1_152
        },
    };
    let fee = quote_fee(&network, &inputs).unwrap();
    inputs.change =
        Zatoshis::from_u64(notes_wanted as u64 * NOTE_VALUE - amount - u64::from(fee)).unwrap();

    let slots = if faults.sliced { [2u16, 3] } else { [1u16, 2] };
    let ids: Vec<_> = slots.into_iter()
        .map(|id| frost::Identifier::try_from(id).unwrap())
        .collect();
    let identities: Vec<_> = slots.into_iter().map(Identity::new).collect();
    let peer_of: BTreeMap<_, _> = ids
        .iter()
        .copied()
        .zip(
            identities
                .iter()
                .map(|identity| Peer(identity.public().encryption)),
        )
        .collect();
    let mut tx = make_transport(&coordinator);
    let peers: Vec<_> = ids.iter().map(|id| peer_of[id].clone()).collect();
    let channel = tx.open(&peers, 4).unwrap();
    let session = session_id(&channel);
    let roster: BTreeMap<_, _> = std::iter::once(coordinator.public()).chain(identities.iter().map(Identity::public))
        .map(|identity| (identity.id, identity)).collect();
    tx.encrypt(PaymentEncryption::new(&coordinator, roster.clone(), &[1; 32], &[9; 32], session).unwrap());
    let member_transports: Vec<_> = identities.iter().map(|identity| {
        let mut transport = make_transport(identity);
        transport.encrypt(PaymentEncryption::new(identity, roster.clone(), &[1; 32], &[9; 32], session).unwrap());
        transport
    }).collect();
    let signer_network = if network == VaultNetwork::Testnet { Network::Testnet } else { Network::Regtest };
    let candidate = CandidateRef { vault_id: [1; 32], payment_id: [7; 32], attempt_id: [9; 32] };
    let params = PublicPaymentParams {
        recipient: inputs.recipient, amount: inputs.amount, memo: inputs.memo.clone(),
        target_height: inputs.target_height, expiry_height: inputs.expiry_height,
    };

    let coord_dir = loki_poc::state::MemberDir::create(&std::env::temp_dir(), &format!("loki-coord-{}", Uuid::new_v4())).unwrap();
    let tx = Interrupted { inner: tx, at: if restart { Interrupt::Package } else if faults.drop_package { Interrupt::DropPackage } else if faults.lose_shares { Interrupt::LoseShares } else if faults.sliced { Interrupt::SlowReceive } else { Interrupt::None }, fired: std::cell::Cell::new(false), deadline: std::cell::Cell::new(None) };
    thread::scope(|scope| {
        let handles: Vec<_> = identities
            .into_iter()
            .zip(member_transports)
            .zip(ids.iter().copied())
            .map(|((identity, mut member_tx), id)| {
                let key = keys[&id].clone();
                let proposer_inputs = if id == ids[0] { Some(&params) } else { None };
                let other_signers: Vec<_> = if proposer_inputs.is_some() { peers.iter().skip(1).cloned().collect() } else { Vec::new() };
                let proposer_peer = peer_of[&ids[0]].clone();
                let public_bytes = public.serialize().unwrap();
                let signer_public = public.clone();
                let signer_fvk = fvk.clone();
                let candidate = candidate.clone();
                let notes = notes.clone();
                let received = &received;
                scope.spawn(move || {
                    if proposer_inputs.is_none() { thread::sleep(delay); }
                    let channel = member_tx.join(session).unwrap();
                    let nonce_dir = std::env::temp_dir().join(format!("loki-payment-{}-{}", std::process::id(), rand_core::RngCore::next_u64(&mut rand_core::OsRng)));
                    let saved = loki_poc::state::MemberDir::create(&nonce_dir, "exchange").unwrap();
                    let member_tx = Interrupted { inner: member_tx,
                        at: if faults.sliced { Interrupt::SlowReceive } else if !restart { Interrupt::None } else if proposer_inputs.is_some() { Interrupt::Commitment } else { Interrupt::Share },
                        fired: std::cell::Cell::new(false), deadline: std::cell::Cell::new(None) };
                    for attempt in 0..if faults.lose_shares || faults.sliced { 100 } else { 2 } {
                        let mut signer = LocalSigner::with_sealed_share(
                            identity.public().id, 2, 3, [1; 32], "payment test".into(), signer_network,
                            SoftwareSecureElement::persistent(&nonce_dir, "test pass").unwrap(), &key.serialize().unwrap(),
                            public_bytes.clone(), signer_fvk.clone(), nonce_dir.clone(), Box::new(|_| true),
                        ).unwrap();
                        signer.set_candidate_notes(notes.clone());
                        let signer_session = signer.connect("payment test", signer_network, b"test").unwrap().session;
                        let mut run = resumed_run(&saved);
                        if faults.sliced { run = run.with_drive_limit(std::time::Duration::from_millis(200)); }
                        let result = signer_loop_resumable(
                            &member_tx, &channel, &mut signer, &signer_session, &candidate, &signer_public, id,
                            proposer_inputs, &proposer_peer, &other_signers, notes_wanted, &mut run,
                        );
                        if faults.sliced && result.as_ref().is_err_and(|e| e == DRIVE_YIELDED) { continue; }
                        if restart && attempt == 0 {
                            assert!(result.unwrap_err().contains("injected process interruption"));
                        } else {
                            result.unwrap();
                            if !faults.lose_shares || received.load(std::sync::atomic::Ordering::SeqCst) { break; }
                            thread::sleep(std::time::Duration::from_millis(100));
                        }
                        // Drop both signer and transcript, then reopen their sealed files.
                    }
                    std::fs::remove_dir_all(nonce_dir).unwrap();
                })
            })
            .collect();
        let mut run = resumed_run(&coord_dir);
        if faults.sliced { run = run.with_drive_limit(std::time::Duration::from_millis(200)); }
        let mut signed = coordinate_resumable(&tx, &channel, &public, &ids, &peer_of, 2, notes_wanted, rand_core::OsRng, &mut run);
        if restart || faults.lose_shares {
            assert!(signed.unwrap_err().contains("injected"));
            drop(run);
            run = resumed_run(&coord_dir);
            signed = coordinate_resumable(&tx, &channel, &public, &ids, &peer_of, 2, notes_wanted, rand_core::OsRng, &mut run);
        }
        if faults.sliced {
            let mut yields = 0;
            while signed.as_ref().is_err_and(|e| e == DRIVE_YIELDED) {
                yields += 1;
                assert!(yields < 100, "coordinator made no progress across resumes");
                drop(run);
                run = resumed_run(&coord_dir).with_drive_limit(std::time::Duration::from_millis(200));
                signed = coordinate_resumable(&tx, &channel, &public, &ids, &peer_of, 2, notes_wanted, rand_core::OsRng, &mut run);
            }
            assert!(yields > 0, "slow receive never released the coordinator drive");
        }
        let signed = signed.unwrap();
        received.store(true, std::sync::atomic::Ordering::SeqCst);
        for handle in handles {
            handle.join().unwrap();
        }
        tx.close(channel).unwrap();

        let parsed = pczt::Pczt::parse(&signed).unwrap();
        let branch = if network == VaultNetwork::Testnet {
            zcash_protocol::consensus::BranchId::Nu7
        } else {
            zcash_protocol::consensus::BranchId::Nu6_3
        };
        assert_eq!(*parsed.global().consensus_branch_id(), u32::from(branch));
        let sighash = pczt::roles::signer::Signer::new(parsed.clone())
            .unwrap()
            .shielded_sighash();
        // Every input note's spend must carry a valid spend-auth signature.
        for note in &notes {
            let action = parsed
                .ironwood()
                .actions()
                .iter()
                .find(|action| action.spend().nullifier() == &note.nullifier(&fvk).to_bytes())
                .expect("each input note has a spend in the signed pczt");
            let signature = action.spend().spend_auth_sig().expect("signed spend");
            let rk = orchard::primitives::redpallas::VerificationKey::<
                orchard::primitives::redpallas::SpendAuth,
            >::try_from(*action.spend().rk())
            .unwrap();
            rk.verify(
                &sighash,
                &orchard::primitives::redpallas::Signature::from(signature),
            )
            .unwrap();
        }
    });
    std::fs::remove_dir_all(coord_dir.path()).unwrap();
}
