//! The reusable `sign_transport` driver, exercised over a real frostd relay: a keyless
//! coordinator + two signers produce a 2-of-3 rerandomized signature that verifies under the
//! randomized group key. Offline (no `FROSTD_URL`) it skips.
//!
//!   frostd --no-tls-very-insecure -p 2744
//!   FROSTD_URL=http://127.0.0.1:2744 cargo test --features relay-communication --test sign_driver -- --nocapture

use std::collections::BTreeMap;
use std::thread;

use loki_poc::setup_transport::Identity;
use loki_poc::sign_transport::{coordinate, sign_as_participant};
use loki_poc::transport::{FrostdTransport, Peer, Transport};
use reddsa_frost::frost::redpallas as frost;

#[test]
fn sign_driver_two_of_three_verifies_over_frostd() {
    let Ok(url) = std::env::var("FROSTD_URL") else {
        eprintln!("[WS3] FROSTD_URL unset — skipping (start: frostd --no-tls-very-insecure -p 2744)");
        return;
    };

    // Keys via a dealer (the DKG driver has its own test); here we exercise signing.
    let (shares, pubkeys) =
        frost::keys::generate_with_dealer(3, 2, frost::keys::IdentifierList::Default, rand_core::OsRng)
            .expect("keygen");
    let key_packages: BTreeMap<frost::Identifier, frost::keys::KeyPackage> = shares
        .into_iter()
        .map(|(id, share)| (id, frost::keys::KeyPackage::try_from(share).unwrap()))
        .collect();
    let ids: Vec<frost::Identifier> = key_packages.keys().copied().collect();

    // Member frostd addresses, paired to FROST ids by order.
    let identities: Vec<Identity> = (1u16..=3).map(Identity::new).collect();
    let peers: Vec<Peer> = identities.iter().map(|i| Peer(i.public().encryption)).collect();
    let peer_of: BTreeMap<frost::Identifier, Peer> = ids.iter().copied().zip(peers.iter().cloned()).collect();

    let signers: Vec<frost::Identifier> = ids.iter().take(2).copied().collect();
    let signer_peers: Vec<Peer> = signers.iter().map(|id| peer_of[id].clone()).collect();
    let message: &[u8] = b"loki payment sighash (test)";

    // Coordinator opens the session listing the two signers; signers join by its id.
    let coord = Identity::new(9);
    let coord_secret: [u8; 32] = coord.to_secret_bytes()[34..].try_into().unwrap();
    let mut coord_tx =
        FrostdTransport::new(&url, Peer(coord.public().encryption), coord_secret).expect("coordinator login");
    let coord_ch = coord_tx.open(&signer_peers, 4).expect("open session");
    let session = coord_ch.session_id();

    let coord_handle = {
        let (peer_of, pubkeys, signers) = (peer_of.clone(), pubkeys.clone(), signers.clone());
        thread::spawn(move || {
            let (signature, params) =
                coordinate(&coord_tx, &coord_ch, &signers, &peer_of, &pubkeys, message).expect("coordinate");
            params
                .randomized_verifying_key()
                .verify(message, &signature)
                .expect("2-of-3 signature verifies under the randomized group key");
            let _ = coord_tx.close(coord_ch);
        })
    };

    let mut signer_handles = Vec::new();
    for (index, me) in identities.into_iter().enumerate().take(2) {
        let (url, id) = (url.clone(), ids[index]);
        let key_package = key_packages[&id].clone();
        signer_handles.push(thread::spawn(move || {
            let secret: [u8; 32] = me.to_secret_bytes()[34..].try_into().unwrap();
            let mut tx = FrostdTransport::new(&url, Peer(me.public().encryption), secret).expect("member login");
            let channel = tx.join(session).expect("join session");
            sign_as_participant(&tx, &channel, &key_package).expect("sign");
        }));
    }

    for handle in signer_handles {
        handle.join().unwrap();
    }
    coord_handle.join().unwrap();
    eprintln!("[WS3] sign driver: 2-of-3 rerandomized signature verifies over frostd");
}
