//! The reusable `dkg_transport::run_dkg` driver, exercised over a real frostd relay. Mirrors
//! the hand-wired `frostd_transport.rs` DKG but through the library driver the coordinator
//! will call. Offline (no `FROSTD_URL`) it skips, so `cargo test` stays green.
//!
//!   frostd --no-tls-very-insecure -p 2744
//!   FROSTD_URL=http://127.0.0.1:2744 cargo test --features relay-communication --test dkg_driver -- --nocapture

use std::collections::BTreeMap;
use std::collections::HashSet;
use std::thread;

use loki_poc::dkg_transport::run_dkg;
use loki_poc::setup_transport::{Identity, PublicIdentity};
use loki_poc::transport::{FrostdTransport, Peer, Transport};
use reddsa_frost::frost::redpallas as frost;

#[test]
fn dkg_driver_reaches_one_group_key_over_frostd() {
    let Ok(url) = std::env::var("FROSTD_URL") else {
        eprintln!("[WS3] FROSTD_URL unset — skipping (start: frostd --no-tls-very-insecure -p 2744)");
        return;
    };
    let vault = [7u8; 32];

    // Three members (ids 1..=3). Identity::new is random, so build them once and move each
    // into its thread; derive the public roster + relay addresses first.
    let identities: Vec<Identity> = (1u16..=3).map(Identity::new).collect();
    let publics: Vec<PublicIdentity> = identities.iter().map(Identity::public).collect();
    let peers: Vec<Peer> = publics.iter().map(|p| Peer(p.encryption)).collect();
    let ids: Vec<frost::Identifier> = (1u16..=3).map(|i| frost::Identifier::try_from(i).unwrap()).collect();
    let roster: BTreeMap<frost::Identifier, PublicIdentity> =
        ids.iter().copied().zip(publics.iter().cloned()).collect();
    let peer_of: BTreeMap<frost::Identifier, Peer> =
        ids.iter().copied().zip(peers.iter().cloned()).collect();

    // Coordinator (not a DKG participant) opens the session; members join by its id.
    let coord = Identity::new(9);
    let coord_secret: [u8; 32] = coord.to_secret_bytes()[34..].try_into().unwrap();
    let mut coord_tx =
        FrostdTransport::new(&url, Peer(coord.public().encryption), coord_secret).expect("coordinator login");
    let coord_ch = coord_tx.open(&peers, 16).expect("open session");
    let session = coord_ch.session_id();

    let mut handles = Vec::new();
    for (index, me) in identities.into_iter().enumerate() {
        let (url, my_id, roster, peer_of) = (url.clone(), ids[index], roster.clone(), peer_of.clone());
        handles.push(thread::spawn(move || {
            let secret: [u8; 32] = me.to_secret_bytes()[34..].try_into().unwrap();
            let mut tx = FrostdTransport::new(&url, Peer(me.public().encryption), secret).expect("member login");
            let channel = tx.join(session).expect("join session");
            let (_key, public) =
                run_dkg(&tx, &channel, &me, my_id, &roster, &peer_of, &vault, 2).expect("run_dkg");
            public.verifying_key().serialize().expect("serialize group key")
        }));
    }

    let group_keys: HashSet<Vec<u8>> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert_eq!(group_keys.len(), 1, "members disagree on the group verifying key");
    let _ = coord_tx.close(coord_ch);
    eprintln!("[WS3] run_dkg: 3 members reached one group key over frostd");
}
