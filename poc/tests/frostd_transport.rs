//! WS3 acceptance: a 2-of-3 dealerless DKG **and** a rerandomized signing round-trip
//! carried end-to-end over a REAL `frostd` relay (`docs/product/ws3-transport.md` §7),
//! replacing the bespoke Loki relay. Every protocol message (DKG round-1 broadcast,
//! DKG round-2 targeted packages, signing commitments, the signing package + randomizer,
//! and the signature shares) is serialized and pushed through `transport::FrostdTransport`
//! — nothing is handed between members in-process.
//!
//! SECURITY: a DKG round-2 package (`frost::keys::dkg::round2::Package`) is SECRET — it is
//! that recipient's signing-share contribution. A relay observer who collects a threshold
//! of round-2 packages reconstructs the vault key. So round-2 is NEVER sent raw: each
//! package is sealed to its recipient's X25519 encryption key with the existing Loki
//! `Identity::seal_round2` primitive (`setup_transport.rs`) BEFORE it reaches the relay,
//! and `open_round2` after `recv`. The relay only ever carries ciphertext. This is the
//! same sealed-round-2 model the production ceremony uses (`setup_ceremony/engine.rs`).
//!
//! `frostd` itself is run insecure here (`--no-tls-very-insecure`) only for the test;
//! real deployments MUST run frostd with TLS. The insecure relay is acceptable ONLY
//! because every secret-bearing payload is already sealed before it is handed to the relay.
//!
//! The test asserts invariant 4 directly: it records every raw byte string `frostd`
//! carried and proves none of them is a secret — not a DKG secret package, not a FROST
//! share / `KeyPackage`, not a signing nonce, not a plaintext round-2 package — and (the
//! regression) that every sealed round-2 blob on the wire is opaque ciphertext that does
//! NOT decode as a round-2 package. Only public FROST artifacts and sealed ciphertext
//! cross. (The check is scoped to the round-2 blobs, not every wire byte: a round-2
//! package and a public `SignatureShare` share the same `Header`+scalar wire shape, so a
//! blanket "nothing decodes as round2" would false-positive on the public signature share.)
//!
//! Requires a running frostd. Set `FROSTD_URL` (e.g. `http://127.0.0.1:2744`). If unset
//! the test prints how to start one and returns, so `cargo test` stays green offline.
//! The seal/transport regression (`relay_observer_cannot_recover_round2`) is OFFLINE and
//! always runs.
//!
//! Start a local insecure relay on the build host:
//!   frostd --no-tls-very-insecure -p 2744
//! then: FROSTD_URL=http://127.0.0.1:2744 cargo test --test frostd_transport -- --nocapture

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use loki_poc::setup_transport::{Identity, PublicIdentity};
use loki_poc::transport::{FrostdTransport, Incoming, Peer, Transport};
use reddsa_frost::frost::redpallas as frost;
use uuid::Uuid;

/// A test member. Its Loki `Identity` carries the X25519 encryption key that frostd uses
/// as the member's address (`transport.rs` doc: frostd pubkey == `PublicIdentity::encryption`)
/// AND seals DKG round-2 packages to peers. The frostd login secret is that same X25519
/// secret; it never signs a FROST share.
struct Member {
    id: u16,
    identity: Identity,
    public: PublicIdentity,
    peer: Peer,
    secret: [u8; 32],
}

fn gen_member(id: u16) -> Member {
    let identity = Identity::new(id);
    let public = identity.public();
    // frostd addresses a member by its 32-byte X25519 encryption pubkey (transport.rs §
    // Addressing); the matching secret logs in via XEdDSA. to_secret_bytes()[34..] is that
    // X25519 secret (see Identity::to_secret_bytes layout in setup_transport.rs).
    let secret: [u8; 32] = identity.to_secret_bytes()[34..].try_into().unwrap();
    Member {
        id,
        identity,
        peer: Peer(public.encryption),
        public,
        secret,
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
    // Members carry Loki identities (id 1..=3) so round-2 packages can be sealed to peers.
    let members: Vec<Member> = (1u16..=3).map(gen_member).collect();
    let coord_kp = gen_member(4);
    let mut m_tx: Vec<FrostdTransport> = members
        .iter()
        .map(|k| FrostdTransport::new(&url, k.peer.clone(), k.secret).expect("member login"))
        .collect();
    let mut coord = FrostdTransport::new(&url, coord_kp.peer.clone(), coord_kp.secret)
        .expect("coordinator login");
    eprintln!("[WS3] 3 members + coordinator authenticated to frostd at {url}");

    // FROST identifiers 1..=3, paired with each member's frostd pubkey.
    let ids: Vec<frost::Identifier> = (1u16..=3)
        .map(|i| frost::Identifier::try_from(i).unwrap())
        .collect();
    let peer_of: BTreeMap<frost::Identifier, Peer> =
        ids.iter().cloned().zip(members.iter().map(|k| k.peer.clone())).collect();
    // FROST id <-> Loki member id (1..=3) and the roster of public identities, so a member
    // can seal round-2 to the recipient's encryption key and verify the sender's signature.
    let loki_id = |id: &frost::Identifier| -> u16 {
        (ids.iter().position(|o| o == id).unwrap() + 1) as u16
    };
    let roster: BTreeMap<u16, PublicIdentity> =
        members.iter().map(|m| (m.id, m.public.clone())).collect();
    // Shared vault binding for the sealed round-2 envelopes (AAD). Fixed for this ceremony.
    let vault = [7u8; 32];

    // Coordinator opens one session listing all three member pubkeys. message_count is a
    // per-participant sizing hint; the DKG + signing flow sends well under this many.
    let member_peers: Vec<Peer> = members.iter().map(|k| k.peer.clone()).collect();
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

    // ---- DKG round 2: each member SEALS its per-recipient package to that recipient's
    // X25519 encryption key before handing it to the relay. round2::Package is SECRET;
    // only sealed ciphertext ever crosses frostd. ----
    let mut r2_secret = BTreeMap::new();
    // The plaintext round-2 packages (SECRET) and the exact sealed blobs we hand the relay,
    // captured so the invariant-4 audit below can prove: no plaintext round-2 package ever
    // crosses, and every sealed round-2 blob is opaque ciphertext (does not decode).
    let mut r2_plaintext: Vec<Vec<u8>> = Vec::new();
    let mut r2_sealed: Vec<Vec<u8>> = Vec::new();
    for (idx, id) in ids.iter().enumerate() {
        let sp = r1_secret.remove(id).unwrap();
        let (sp2, pkgs) = frost::keys::dkg::part2(sp, &r1_received[id]).expect("dkg part2");
        r2_secret.insert(*id, sp2);
        for (rcpt, pkg) in pkgs {
            let plaintext = pkg.serialize().expect("ser r2 pkg");
            let sealed = members[idx]
                .identity
                .seal_round2(&roster[&loki_id(&rcpt)], &vault, &plaintext)
                .expect("seal round2");
            r2_plaintext.push(plaintext);
            r2_sealed.push(sealed.clone());
            send_taped(&m_tx[idx], &m_ch[idx], &[peer_of[&rcpt].clone()], &sealed, &tape);
        }
    }

    // Each member collects the two sealed round-2 packages addressed to it, unseals each
    // (verifying the sender's signature + recipient binding), then deserializes.
    let mut r2_received: BTreeMap<frost::Identifier, BTreeMap<frost::Identifier, frost::keys::dkg::round2::Package>> =
        BTreeMap::new();
    for (idx, id) in ids.iter().enumerate() {
        let got = recv_until(&m_tx[idx], &m_ch[idx], false, 2);
        let mut map = BTreeMap::new();
        for inc in got {
            let sender = ids.iter().find(|o| peer_of[o] == inc.from).copied().expect("r2 sender");
            let plaintext = members[idx]
                .identity
                .open_round2(&roster[&loki_id(&sender)], &vault, &inc.message)
                .expect("open round2");
            map.insert(
                sender,
                frost::keys::dkg::round2::Package::deserialize(&plaintext).expect("de r2 pkg"),
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
    // SECRET = DKG secret packages, FROST shares / key packages, signing nonces, AND
    // DKG round-2 packages (each is a recipient's share contribution). The old audit
    // mis-classified round2::Package as public; it is not.
    let tape = tape.lock().unwrap();
    let mut secret_blobs: Vec<Vec<u8>> = Vec::new();
    for id in &ids {
        if let Some(kp) = key_packages.get(id) {
            secret_blobs.push(kp.serialize().expect("ser keypkg"));
            secret_blobs.push(kp.signing_share().serialize());
        }
        if let Some(sp2) = r2_secret.get(id) {
            secret_blobs.push(sp2.serialize().expect("ser dkg r2 secret"));
        }
        // Signing nonces are secret: leaking one forges a signature for that signer.
        if let Some(n) = nonces.get(id) {
            secret_blobs.push(n.serialize().expect("ser nonce"));
        }
    }
    // A plaintext DKG round-2 package is a recipient's share contribution: a threshold of
    // them reconstructs the vault key, so it is secret too.
    secret_blobs.extend(r2_plaintext.iter().cloned());
    for carried in tape.iter() {
        for secret in &secret_blobs {
            assert!(
                carried != secret,
                "a secret (share / key package / dkg r2 secret / nonce / plaintext round-2 package) crossed the relay — invariant 4 violated"
            );
        }
    }
    // Regression (relay_observer_cannot_recover_round2, live): every round-2 blob that
    // crossed the relay is sealed ciphertext — none decodes as a round-2 package, so a
    // relay observer collecting them cannot reconstruct the vault key. The blanket
    // "no wire byte decodes as round2" check cannot be used here: a round-2 package and a
    // public `SignatureShare` share the same wire shape (`Header` + one 32-byte scalar in
    // frost-core 3.0.0), so a legitimately-public signature share also deserializes as a
    // round-2 package. The security property is about the round-2 payloads specifically.
    for sealed in &r2_sealed {
        assert!(
            frost::keys::dkg::round2::Package::deserialize(sealed).is_err(),
            "a sealed round-2 blob decoded as a plaintext round-2 package — the vault key is leakable"
        );
    }
    eprintln!(
        "[WS3] audited {} relayed payloads; no secret crossed and all {} round-2 blobs are opaque ciphertext (invariant 4 holds)",
        tape.len(),
        r2_sealed.len()
    );
}

/// OFFLINE regression (no frostd): a relay observer who records every byte that crossed
/// the transport during DKG round-2 CANNOT recover any `round2::Package`, ONLY the intended
/// recipient can unseal its package, and DKG still completes to the same group key with the
/// sealed round-2. This is the proof that the plaintext-round-2 leak is closed.
#[test]
fn relay_observer_cannot_recover_round2() {
    let ids: Vec<frost::Identifier> = (1u16..=3)
        .map(|i| frost::Identifier::try_from(i).unwrap())
        .collect();
    let members: Vec<Member> = (1u16..=3).map(gen_member).collect();
    let roster: BTreeMap<u16, PublicIdentity> =
        members.iter().map(|m| (m.id, m.public.clone())).collect();
    let loki_id = |id: &frost::Identifier| -> u16 {
        (ids.iter().position(|o| o == id).unwrap() + 1) as u16
    };
    let vault = [9u8; 32];

    // Round 1 (public; exchanged in-process here — the leak under test is round 2).
    let mut r1_secret = BTreeMap::new();
    let mut r1_pkg = BTreeMap::new();
    for id in &ids {
        let (sp, pkg) = frost::keys::dkg::part1(*id, 3, 2, rand_core::OsRng).expect("part1");
        r1_secret.insert(*id, sp);
        r1_pkg.insert(*id, pkg);
    }
    let mut r1_received: BTreeMap<frost::Identifier, BTreeMap<frost::Identifier, frost::keys::dkg::round1::Package>> =
        BTreeMap::new();
    for id in &ids {
        let map: BTreeMap<_, _> = ids
            .iter()
            .filter(|o| *o != id)
            .map(|o| (*o, r1_pkg[o].clone()))
            .collect();
        r1_received.insert(*id, map);
    }

    // Round 2: seal every package to its recipient. The "wire" is what the relay observer
    // holds: sealed bytes only, tagged with (sender, recipient) so each can be routed.
    let mut r2_secret = BTreeMap::new();
    let mut wire: Vec<(frost::Identifier, frost::Identifier, Vec<u8>)> = Vec::new();
    for (idx, id) in ids.iter().enumerate() {
        let sp = r1_secret.remove(id).unwrap();
        let (sp2, pkgs) = frost::keys::dkg::part2(sp, &r1_received[id]).expect("part2");
        r2_secret.insert(*id, sp2);
        for (rcpt, pkg) in pkgs {
            let sealed = members[idx]
                .identity
                .seal_round2(&roster[&loki_id(&rcpt)], &vault, &pkg.serialize().unwrap())
                .expect("seal round2");
            wire.push((*id, rcpt, sealed));
        }
    }

    // 1) The observer CANNOT deserialize any round-2 package from any wire byte string.
    for (_, _, sealed) in &wire {
        assert!(
            frost::keys::dkg::round2::Package::deserialize(sealed).is_err(),
            "observer recovered a plaintext round-2 package from the wire"
        );
    }

    // 2) ONLY the intended recipient can unseal; a non-recipient fails.
    let mut r2_received: BTreeMap<frost::Identifier, BTreeMap<frost::Identifier, frost::keys::dkg::round2::Package>> =
        ids.iter().map(|id| (*id, BTreeMap::new())).collect();
    for (sender, rcpt, sealed) in &wire {
        let rcpt_idx = ids.iter().position(|o| o == rcpt).unwrap();
        // A non-recipient member cannot open it.
        let wrong = ids.iter().find(|o| *o != rcpt && *o != sender).unwrap();
        let wrong_idx = ids.iter().position(|o| o == wrong).unwrap();
        assert!(
            members[wrong_idx]
                .identity
                .open_round2(&roster[&loki_id(sender)], &vault, sealed)
                .is_err(),
            "a non-recipient unsealed a round-2 package"
        );
        // The intended recipient opens it.
        let plaintext = members[rcpt_idx]
            .identity
            .open_round2(&roster[&loki_id(sender)], &vault, sealed)
            .expect("recipient opens round2");
        r2_received.get_mut(rcpt).unwrap().insert(
            *sender,
            frost::keys::dkg::round2::Package::deserialize(&plaintext).expect("de r2"),
        );
    }

    // 3) DKG still completes to ONE shared group key despite the sealed round-2.
    let mut group_key = None;
    for id in &ids {
        let (_kp, pubkeys) =
            frost::keys::dkg::part3(&r2_secret[id], &r1_received[id], &r2_received[id]).expect("part3");
        let vk = pubkeys.verifying_key().serialize().unwrap();
        match &group_key {
            None => group_key = Some(vk),
            Some(prev) => assert_eq!(prev, &vk, "DKG produced divergent group keys"),
        }
    }
    assert!(group_key.is_some(), "DKG did not complete");
}
