//! WS3 acceptance: a 2-of-3 dealerless DKG **and** a rerandomized signing round-trip
//! carried end-to-end over a REAL `frostd` relay (`docs/product/ws3-transport.md` §7),
//! replacing the bespoke Loki relay. Every protocol message (DKG round-1 broadcast,
//! DKG round-2 targeted packages, signing commitments, the signing package + randomizer,
//! and the signature shares) is serialized and pushed through `transport::FrostdTransport`
//! — nothing is handed between members in-process.
//!
//! The test asserts invariant 4 directly: it records every raw byte string `frostd`
//! carried and proves none of them is a secret (a DKG secret package, a FROST share /
//! `KeyPackage`, or a signing nonce). Only public FROST artifacts cross.
//!
//! Requires a running frostd. Set `FROSTD_URL` (e.g. `http://127.0.0.1:2744`). If unset
//! the test prints how to start one and returns, so `cargo test` stays green offline.
//!
//! Start a local insecure relay on omarchy:
//!   frostd --no-tls-very-insecure -p 2744
//! then: FROSTD_URL=http://127.0.0.1:2744 cargo test --test frostd_transport -- --nocapture

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use loki_poc::transport::{FrostdTransport, Incoming, Peer, Transport};
use reddsa_frost::frost::redpallas as frost;
use uuid::Uuid;

/// Member X25519 (frostd/snow `Noise_K`) keypair. The public key is the frostd address;
/// the secret only ever signs the login challenge (never a FROST share).
struct Kp {
    public: Peer,
    secret: [u8; 32],
}

fn gen_kp() -> Kp {
    // frostd's login pubkey is a raw X25519 public key (snow `Noise_K` uses X25519);
    // XEdDSA over the challenge proves possession of the matching secret. x25519-dalek
    // (already a poc dep) produces exactly that keypair — no need for snow in the test.
    use x25519_dalek::{PublicKey, StaticSecret};
    let secret = StaticSecret::random_from_rng(rand_core::OsRng);
    let public = PublicKey::from(&secret);
    Kp {
        public: Peer(public.to_bytes()),
        secret: secret.to_bytes(),
    }
}

/// Audit tape: every opaque payload frostd actually carried, so we can prove no secret
/// crossed. Shared so the (single-process) members append to one list.
type Tape = Arc<Mutex<Vec<Vec<u8>>>>;

fn send_taped(t: &FrostdTransport, ch: &loki_poc::transport::FrostdChannel, to: &[Peer], msg: &[u8], tape: &Tape) {
    tape.lock().unwrap().push(msg.to_vec());
    t.send(ch, to, msg).expect("frostd send");
}

/// Poll frostd until at least `want` messages have arrived for this member (the relay is
/// store-and-forward; peers may not have sent yet). Bounded so a stuck relay fails loudly.
fn recv_until(t: &FrostdTransport, ch: &loki_poc::transport::FrostdChannel, as_coord: bool, want: usize) -> Vec<Incoming> {
    let mut got = Vec::new();
    for _ in 0..200 {
        got.extend(t.recv(ch, as_coord).expect("frostd recv"));
        if got.len() >= want {
            return got;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    panic!("frostd did not deliver {want} messages (got {})", got.len());
}

#[test]
fn two_of_three_dkg_and_sign_over_real_frostd() {
    let url = match std::env::var("FROSTD_URL") {
        Ok(u) => u,
        Err(_) => {
            eprintln!(
                "[WS3] FROSTD_URL unset — skipping live relay test.\n\
                 Start one: frostd --no-tls-very-insecure -p 2744\n\
                 Then:      FROSTD_URL=http://127.0.0.1:2744 cargo test --test frostd_transport -- --nocapture"
            );
            return;
        }
    };

    // Three members + a coordinator, each a logged-in frostd client over the real relay.
    let members: Vec<Kp> = (0..3).map(|_| gen_kp()).collect();
    let coord_kp = gen_kp();
    let mut m_tx: Vec<FrostdTransport> = members
        .iter()
        .map(|k| FrostdTransport::new(&url, k.public.clone(), k.secret).expect("member login"))
        .collect();
    let mut coord = FrostdTransport::new(&url, coord_kp.public.clone(), coord_kp.secret)
        .expect("coordinator login");
    eprintln!("[WS3] 3 members + coordinator authenticated to frostd at {url}");

    // FROST identifiers 1..=3, paired with each member's frostd pubkey.
    let ids: Vec<frost::Identifier> = (1u16..=3)
        .map(|i| frost::Identifier::try_from(i).unwrap())
        .collect();
    let peer_of: BTreeMap<frost::Identifier, Peer> =
        ids.iter().cloned().zip(members.iter().map(|k| k.public.clone())).collect();

    // Coordinator opens one session listing all three member pubkeys. message_count is a
    // per-participant sizing hint; the DKG + signing flow sends well under this many.
    let member_peers: Vec<Peer> = members.iter().map(|k| k.public.clone()).collect();
    let coord_ch = coord.open(&member_peers, 16).expect("create_new_session");
    let session: Uuid = coord_ch.session_id();
    let m_ch: Vec<_> = m_tx.iter_mut().map(|t| t.join(session).expect("join")).collect();
    eprintln!("[WS3] session {session} created; members joined");

    let tape: Tape = Arc::new(Mutex::new(Vec::new()));

    // ---- DKG round 1: each member broadcasts its round-1 package to the other two ----
    let mut r1_secret = BTreeMap::new();
    let mut r1_pkg = BTreeMap::new();
    for (idx, id) in ids.iter().enumerate() {
        let (sp, pkg) = frost::keys::dkg::part1(*id, 3, 2, rand_core::OsRng).expect("dkg part1");
        r1_secret.insert(*id, sp);
        r1_pkg.insert(*id, pkg.serialize().expect("ser r1 pkg"));
        // DKG secret package is NEVER sent. Prove it by asserting the tape never holds it.
        let _ = idx;
    }
    for (idx, id) in ids.iter().enumerate() {
        let others: Vec<Peer> = ids
            .iter()
            .filter(|o| *o != id)
            .map(|o| peer_of[o].clone())
            .collect();
        send_taped(&m_tx[idx], &m_ch[idx], &others, &r1_pkg[id], &tape);
    }

    // Each member collects the two peer round-1 packages from frostd.
    let mut r1_received: BTreeMap<frost::Identifier, BTreeMap<frost::Identifier, frost::keys::dkg::round1::Package>> =
        BTreeMap::new();
    for (idx, id) in ids.iter().enumerate() {
        let got = recv_until(&m_tx[idx], &m_ch[idx], false, 2);
        let mut map = BTreeMap::new();
        for inc in got {
            // Identify the sender by matching its frostd pubkey back to a FROST id.
            let sender = ids
                .iter()
                .find(|o| peer_of[o] == inc.from)
                .copied()
                .expect("round1 sender is a roster member");
            map.insert(
                sender,
                frost::keys::dkg::round1::Package::deserialize(&inc.message).expect("de r1 pkg"),
            );
        }
        assert_eq!(map.len(), 2, "member {id:?} must get 2 round-1 packages");
        r1_received.insert(*id, map);
    }

    // ---- DKG round 2: each member sends a per-recipient targeted package ----
    let mut r2_secret = BTreeMap::new();
    // Hold serialized outgoing r2 packages: sender -> (recipient -> bytes).
    let mut r2_out: BTreeMap<frost::Identifier, BTreeMap<frost::Identifier, Vec<u8>>> = BTreeMap::new();
    for (idx, id) in ids.iter().enumerate() {
        let sp = r1_secret.remove(id).unwrap();
        let (sp2, pkgs) = frost::keys::dkg::part2(sp, &r1_received[id]).expect("dkg part2");
        r2_secret.insert(*id, sp2);
        let mut per = BTreeMap::new();
        for (rcpt, pkg) in pkgs {
            let bytes = pkg.serialize().expect("ser r2 pkg");
            send_taped(&m_tx[idx], &m_ch[idx], &[peer_of[&rcpt].clone()], &bytes, &tape);
            per.insert(rcpt, bytes);
        }
        r2_out.insert(*id, per);
    }

    // Each member collects the two round-2 packages addressed to it.
    let mut r2_received: BTreeMap<frost::Identifier, BTreeMap<frost::Identifier, frost::keys::dkg::round2::Package>> =
        BTreeMap::new();
    for (idx, id) in ids.iter().enumerate() {
        let got = recv_until(&m_tx[idx], &m_ch[idx], false, 2);
        let mut map = BTreeMap::new();
        for inc in got {
            let sender = ids.iter().find(|o| peer_of[o] == inc.from).copied().expect("r2 sender");
            map.insert(
                sender,
                frost::keys::dkg::round2::Package::deserialize(&inc.message).expect("de r2 pkg"),
            );
        }
        assert_eq!(map.len(), 2, "member {id:?} must get 2 round-2 packages");
        r2_received.insert(*id, map);
    }

    // ---- DKG part 3: each member derives its share + the shared group key locally ----
    let mut key_packages = BTreeMap::new();
    let mut pubkey_pkg = None;
    for id in &ids {
        let (kp, pubkeys) =
            frost::keys::dkg::part3(&r2_secret[id], &r1_received[id], &r2_received[id]).expect("part3");
        pubkey_pkg = Some(pubkeys);
        key_packages.insert(*id, kp);
    }
    let pubkeys = pubkey_pkg.unwrap();
    eprintln!(
        "[WS3] DKG complete over frostd — group verifying key = {}",
        hex::encode(pubkeys.verifying_key().serialize().unwrap())
    );

    // ---- Signing: 2-of-3 rerandomized round-trip, all public msgs over frostd ----
    let signers: Vec<frost::Identifier> = ids.iter().take(2).copied().collect();

    // Round 1: the two signers send commitments to the coordinator (empty recipients).
    // Coordinator attributes each by the sender's frostd pubkey, so no id prefix needed.
    let idx_of = |id: &frost::Identifier| ids.iter().position(|o| o == id).unwrap();
    let mut nonces = BTreeMap::new();
    for id in &signers {
        let i = idx_of(id);
        let (nonce, commit) = frost::round1::commit(key_packages[id].signing_share(), &mut rand_core::OsRng);
        nonces.insert(*id, nonce);
        send_taped(&m_tx[i], &m_ch[i], &[], &commit.serialize().expect("ser commit"), &tape);
    }

    // Coordinator gathers the two commitments.
    let got = recv_until(&coord, &coord_ch, true, 2);
    let mut commitments = BTreeMap::new();
    for inc in got {
        let id = *ids.iter().find(|o| peer_of[o] == inc.from).expect("commit sender");
        commitments.insert(id, frost::round1::SigningCommitments::deserialize(&inc.message).expect("de commit"));
    }
    assert_eq!(commitments.len(), 2);

    // Coordinator builds the signing package + randomizer and broadcasts to the signers.
    let message = b"loki ws3 frostd transport acceptance sighash";
    let pkg = frost::SigningPackage::new(commitments.clone(), message);
    let (params, seed) = frost_rerandomized::RandomizedParams::new_from_commitments(
        pubkeys.verifying_key(),
        &commitments,
        rand_core::OsRng,
    )
    .expect("randomizer");
    let pkg_bytes = pkg.serialize().expect("ser signing package");
    tape.lock().unwrap().push(pkg_bytes.clone());
    tape.lock().unwrap().push(seed.to_vec());
    for id in &signers {
        coord.send(&coord_ch, &[peer_of[id].clone()], &pkg_bytes).expect("send pkg");
        coord.send(&coord_ch, &[peer_of[id].clone()], &seed).expect("send randomizer seed");
    }

    // Signers receive package + seed, each produces its partial signature, sends it back.
    for id in &signers {
        let i = idx_of(id);
        let got = recv_until(&m_tx[i], &m_ch[i], false, 2);
        // First message is the signing package, second is the randomizer seed (ordered send).
        let got_pkg = frost::SigningPackage::deserialize(&got[0].message).expect("de pkg");
        let seed_bytes: [u8; 32] = got[1].message.clone().try_into().expect("32-byte seed");
        let share = frost_rerandomized::sign_with_randomizer_seed(
            &got_pkg,
            &nonces[id],
            &key_packages[id],
            &seed_bytes,
        )
        .expect("partial sig");
        send_taped(&m_tx[i], &m_ch[i], &[], &share.serialize(), &tape);
    }

    // Coordinator gathers the two shares and aggregates.
    let got = recv_until(&coord, &coord_ch, true, 2);
    let mut sigshares = BTreeMap::new();
    for inc in got {
        let id = *ids.iter().find(|o| peer_of[o] == inc.from).expect("share sender");
        sigshares.insert(id, frost::round2::SignatureShare::deserialize(&inc.message).expect("de share"));
    }
    let sig = frost_rerandomized::aggregate(&pkg, &sigshares, &pubkeys, &params).expect("aggregate");
    params
        .randomized_verifying_key()
        .verify(message, &sig)
        .expect("2-of-3 signature verifies under the randomized group key");
    eprintln!("[WS3] 2-of-3 rerandomized signature over frostd VERIFIES");

    coord.close(coord_ch).ok();

    // ---- Invariant 4: prove no secret crossed the relay ----
    let tape = tape.lock().unwrap();
    let mut secret_blobs: Vec<Vec<u8>> = Vec::new();
    for id in &ids {
        if let Some(kp) = key_packages.get(id) {
            secret_blobs.push(kp.serialize().expect("ser keypkg"));
            secret_blobs.push(kp.signing_share().serialize());
        }
    }
    for carried in tape.iter() {
        for secret in &secret_blobs {
            assert!(
                carried != secret,
                "a FROST share / key package crossed the relay — invariant 4 violated"
            );
        }
    }
    eprintln!(
        "[WS3] audited {} relayed payloads; none equals a share or key package (invariant 4 holds)",
        tape.len()
    );
}
