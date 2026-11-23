use std::collections::BTreeMap;

use loki_poc::distributed_setup::Member;

#[test]
fn three_members_generate_one_group_key_without_a_dealer() {
    let mut members = BTreeMap::new();
    let mut round1 = BTreeMap::new();
    for id in 1u16..=3 {
        let (member, message) = Member::start(id).unwrap();
        members.insert(id, member);
        round1.insert(id, message);
    }

    let mut round2 = BTreeMap::new();
    for (id, member) in members {
        let (member, outgoing) = member.advance(&round1).unwrap();
        round2.insert(id, (member, outgoing));
    }

    let mut completed = BTreeMap::new();
    for (id, (member, _)) in &round2 {
        let incoming = round2
            .iter()
            .filter(|(sender, _)| *sender != id)
            .map(|(sender, (_, outgoing))| (*sender, outgoing[id].clone()))
            .collect();
        completed.insert(*id, member.finish(&incoming).unwrap());
    }
    let digests: BTreeMap<_, _> = completed
        .iter()
        .map(|(id, c)| (*id, c.certificate_digest()))
        .collect();
    assert!(digests.values().all(|digest| digest == &digests[&1]));
    let mut altered = digests.clone();
    altered.get_mut(&2).unwrap()[0] ^= 1;
    assert!(completed.remove(&1).unwrap().certify(&altered).is_err());
    let certified: Vec<_> = completed
        .into_values()
        .map(|c| c.certify(&digests).unwrap())
        .collect();
    let keys: Vec<_> = certified.iter().map(|c| c.group_ak).collect();
    let shares: Vec<_> = certified.iter().map(|c| c.key_package.as_slice()).collect();
    assert!(keys.windows(2).all(|pair| pair[0] == pair[1]));
    assert_ne!(shares[0], shares[1]);
}

#[test]
fn a_changed_round_one_package_changes_the_transcript() {
    let mut members = BTreeMap::new();
    let mut round1 = BTreeMap::new();
    for id in 1u16..=3 {
        let (member, message) = Member::start(id).unwrap();
        members.insert(id, member);
        round1.insert(id, message);
    }
    let (_, alternate_bob) = Member::start(2).unwrap();
    let mut alice_view = round1.clone();
    alice_view.insert(2, alternate_bob);

    let (alice, _) = members.remove(&1).unwrap().advance(&alice_view).unwrap();
    let (carol, _) = members.remove(&3).unwrap().advance(&round1).unwrap();
    assert_ne!(alice.transcript, carol.transcript);
}

#[test]
fn four_members_certify_one_group_key_at_each_supported_threshold() {
    for threshold in [2, 3] {
    let mut members = BTreeMap::new();
    let mut round1 = BTreeMap::new();
    for id in 1u16..=4 {
        let (member, message) = Member::start_with_policy(id, threshold, 4).unwrap();
        members.insert(id, member);
        round1.insert(id, message);
    }
    let mut round2 = BTreeMap::new();
    for (id, member) in members {
        round2.insert(id, member.advance(&round1).unwrap());
    }
    let completed: BTreeMap<_, _> = round2
        .iter()
        .map(|(id, (member, _))| {
            let incoming = round2
                .iter()
                .filter(|(sender, _)| *sender != id)
                .map(|(sender, (_, outgoing))| (*sender, outgoing[id].clone()))
                .collect();
            (*id, member.finish(&incoming).unwrap())
        })
        .collect();
    let digests = completed
        .iter()
        .map(|(id, c)| (*id, c.certificate_digest()))
        .collect();
    let keys: Vec<_> = completed
        .into_values()
        .map(|c| c.certify(&digests).unwrap().group_ak)
        .collect();
    assert_eq!(keys.len(), 4);
    assert!(keys.windows(2).all(|pair| pair[0] == pair[1]));
    }
    assert!(Member::start_with_policy(1, 3, 3).is_ok());
    assert!(Member::start_with_policy(1, 4, 4).is_ok());
    assert!(Member::start_with_policy(1, 0, 3).is_err());
    assert!(Member::start_with_policy(1, 4, 3).is_err());
    assert!(Member::start_with_policy(5, 2, 4).is_err());
}
