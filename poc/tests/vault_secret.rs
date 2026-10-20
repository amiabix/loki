//! Three members derive the same viewing key after DKG and a sealed contribution exchange.

use std::{collections::BTreeMap, thread};

use loki_poc::{
    dkg_transport::run_dkg,
    setup_transport::{Identity, PublicIdentity},
    transport::{FrostdTransport, Peer, Transport},
    vault, vault_secret, zip2005,
};
use reddsa_frost::frost::redpallas as frost;
use zcash_protocol::consensus::NetworkType;

#[test]
fn three_members_derive_one_secret_and_address_over_frostd() {
    let Ok(url) = std::env::var("FROSTD_URL") else {
        eprintln!("FROSTD_URL unset — skipping frostd vault secret test");
        return;
    };
    let vault_id = [7u8; 32];
    let identities: Vec<_> = (1u16..=3).map(Identity::new).collect();
    let publics: Vec<PublicIdentity> = identities.iter().map(Identity::public).collect();
    let peers: Vec<Peer> = publics.iter().map(|p| Peer(p.encryption)).collect();
    let ids: Vec<frost::Identifier> = (1u16..=3)
        .map(|id| frost::Identifier::try_from(id).unwrap())
        .collect();
    let roster: BTreeMap<_, _> = ids.iter().copied().zip(publics).collect();
    let peer_of: BTreeMap<_, _> = ids.iter().copied().zip(peers.iter().cloned()).collect();

    let coordinator = Identity::new(9);
    let coordinator_secret = coordinator.to_secret_bytes();
    let mut coordinator_transport = FrostdTransport::new(
        &url,
        Peer(coordinator.public().encryption),
        coordinator_secret[34..].try_into().unwrap(),
    )
    .unwrap();
    let dkg_coord_channel = coordinator_transport.open(&peers, 16).unwrap();
    let dkg_session = dkg_coord_channel.session_id();
    // A separate session for the vault-secret commit-reveal: its sealed reveals must not
    // interleave with DKG round-2 on the same channel.
    let vs_coordinator = Identity::new(8);
    let mut vs_coordinator_transport = FrostdTransport::new(
        &url,
        Peer(vs_coordinator.public().encryption),
        vs_coordinator.to_secret_bytes()[34..].try_into().unwrap(),
    )
    .unwrap();
    let vs_coord_channel = vs_coordinator_transport.open(&peers, 16).unwrap();
    let vs_session = vs_coord_channel.session_id();

    let handles: Vec<_> = identities
        .into_iter()
        .zip(ids)
        .map(|(me, my_id)| {
            let (url, roster, peer_of) = (url.clone(), roster.clone(), peer_of.clone());
            thread::spawn(move || {
                let secret = me.to_secret_bytes();
                let mut transport = FrostdTransport::new(
                    &url,
                    Peer(me.public().encryption),
                    secret[34..].try_into().unwrap(),
                )
                .unwrap();
                let channel = transport.join(dkg_session).unwrap();
                let (_, public) = run_dkg(
                    &transport, &channel, &me, my_id, &roster, &peer_of, &vault_id, 2,
                )
                .unwrap();
                let ak: [u8; 32] = public
                    .verifying_key()
                    .serialize()
                    .unwrap()
                    .try_into()
                    .unwrap();
                let vs_channel = transport.join(vs_session).unwrap();
                let vs = vault_secret::contribute(
                    &transport, &vs_channel, &me, my_id, &roster, &peer_of, &vault_id, &ak,
                )
                .unwrap();
                let fvk = zip2005::frost_viewing_key(&ak, &vs).unwrap();
                let address = vault::unified_address(&fvk, NetworkType::Regtest);
                (vs, fvk.to_bytes(), address)
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert!(results.windows(2).all(|pair| pair[0] == pair[1]));
    let _ = coordinator_transport.close(dkg_coord_channel);
    let _ = vs_coordinator_transport.close(vs_coord_channel);
    eprintln!("PASS: three members share one vault secret, FVK, and address over frostd");
}
