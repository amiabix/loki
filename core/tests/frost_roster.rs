use loki_poc::frost_roster::FrostRoster;
use loki_poc::setup_transport::Identity;
use reddsa_frost::frost::redpallas as frost;

#[test]
fn roster_fingerprint_ignores_insertion_order_and_maps_relay_peers() {
    let members: Vec<_> = (1u16..=3)
        .map(|id| {
            (
                frost::Identifier::try_from(id).unwrap(),
                Identity::new(id).public(),
            )
        })
        .collect();
    let first = FrostRoster::from_identities([7; 32], 2, members.clone());
    let again = FrostRoster::from_identities([7; 32], 2, members.clone());
    let reversed = FrostRoster::from_identities([7; 32], 2, members.iter().cloned().rev());
    assert_eq!(first.fingerprint(), again.fingerprint());
    assert_eq!(first.fingerprint(), reversed.fingerprint());
    for (id, member) in &members {
        assert_eq!(first.peer_of(id).unwrap().0, member.encryption);
    }
    assert_eq!(first.peer_list().len(), 3);
}
