use loki_poc::{
    member_state::Roster,
    setup_ceremony::{
        generate_local_context, local_roster_vote, verify_local_roster, AcceptedCeremonyRoster,
        LocalRosterVote,
    },
    setup_transport::Identity,
};
use serde_json::{json, Value};

fn document(identities: &[Identity]) -> Value {
    json!({
        "setup_version": 2,
        "vault": hex::encode([7; 32]),
        "network": "testnet",
        "birth_height": 4_465_026,
        "threshold": 2,
        "members": identities.iter().map(|identity| {
            let public = identity.public();
            json!({"id": public.id, "signing": hex::encode(public.signing),
                "encryption": hex::encode(public.encryption)})
        }).collect::<Vec<_>>()
    })
}

fn roster(value: &Value) -> Roster {
    Roster::from_bytes(&serde_json::to_vec(value).unwrap()).unwrap()
}

fn votes(value: &Value, identities: &[Identity], context: [u8; 32]) -> Vec<LocalRosterVote> {
    identities
        .iter()
        .map(|identity| local_roster_vote(&roster(value), context, identity).unwrap())
        .collect()
}

#[test]
fn accepts_exact_signed_context_after_serialization_and_restart() {
    let identities: Vec<_> = (1..=3).map(Identity::new).collect();
    let value = document(&identities);
    let context = [9; 32];
    let saved =
        serde_json::to_vec(&(value.clone(), context, votes(&value, &identities, context))).unwrap();
    let (reopened_roster, reopened_context, reopened_votes): (
        Value,
        [u8; 32],
        Vec<LocalRosterVote>,
    ) = serde_json::from_slice(&saved).unwrap();
    let accepted = verify_local_roster(
        roster(&reopened_roster),
        reopened_context,
        &identities[0],
        &reopened_votes,
    )
    .unwrap();
    assert_eq!(
        accepted.roster().fingerprint(),
        roster(&value).fingerprint()
    );
    assert_ne!(accepted.context_digest(), [0; 32]);
    assert_eq!(
        accepted.context_digest(),
        verify_local_roster(roster(&value), context, &identities[1], &reopened_votes)
            .unwrap()
            .context_digest()
    );
    assert_ne!(
        accepted.context_digest(),
        verify_local_roster(
            roster(&value),
            [8; 32],
            &identities[0],
            &votes(&value, &identities, [8; 32])
        )
        .unwrap()
        .context_digest()
    );
}

#[test]
fn accepts_regtest_without_birth_height() {
    let identities: Vec<_> = (1..=3).map(Identity::new).collect();
    let mut value = document(&identities);
    value["network"] = json!("regtest");
    value.as_object_mut().unwrap().remove("birth_height");
    let votes = votes(&value, &identities, [9; 32]);
    assert!(verify_local_roster(roster(&value), [9; 32], &identities[0], &votes).is_ok());
}

#[test]
fn rejects_replay_across_context_vault_network_birth_policy_and_member() {
    let identities: Vec<_> = (1..=4).map(Identity::new).collect();
    let value = document(&identities);
    let original = votes(&value, &identities, [9; 32]);
    assert!(verify_local_roster(roster(&value), [8; 32], &identities[0], &original).is_err());
    for (field, replacement) in [
        ("vault", json!(hex::encode([8; 32]))),
        ("network", json!("regtest")),
        ("birth_height", json!(4_465_027)),
        ("threshold", json!(3)),
    ] {
        let mut changed = value.clone();
        changed[field] = replacement;
        if field == "network" {
            changed.as_object_mut().unwrap().remove("birth_height");
        }
        assert!(
            verify_local_roster(roster(&changed), [9; 32], &identities[0], &original).is_err(),
            "replayed {field}"
        );
    }
    let mut changed = value.clone();
    changed["members"][1]["encryption"] = json!(hex::encode(Identity::new(2).public().encryption));
    assert!(verify_local_roster(roster(&changed), [9; 32], &identities[0], &original).is_err());
}

#[test]
fn rejects_duplicates_missing_slots_wrong_signer_and_weak_member_keys() {
    let identities: Vec<_> = (1..=3).map(Identity::new).collect();
    let value = document(&identities);
    let original = votes(&value, &identities, [9; 32]);
    let mut duplicate = original.clone();
    duplicate.push(original[0].clone());
    assert!(verify_local_roster(roster(&value), [9; 32], &identities[0], &duplicate).is_err());
    assert!(verify_local_roster(roster(&value), [9; 32], &identities[0], &original[..2]).is_err());
    let mut wrong_slot = original.clone();
    wrong_slot[0].slot = 2;
    assert!(verify_local_roster(roster(&value), [9; 32], &identities[0], &wrong_slot).is_err());
    let mut wrong_signer = original.clone();
    wrong_signer[0].wire = original[1].wire.clone();
    assert!(verify_local_roster(roster(&value), [9; 32], &identities[0], &wrong_signer).is_err());
    assert!(local_roster_vote(&roster(&value), [9; 32], &Identity::new(1)).is_err());
    assert!(verify_local_roster(roster(&value), [0; 32], &identities[0], &original).is_err());

    let mut weak = value.clone();
    weak["members"][1]["encryption"] = json!(hex::encode([0; 32]));
    assert!(local_roster_vote(&roster(&weak), [9; 32], &identities[0]).is_err());
    let mut weak_signing = value.clone();
    weak_signing["members"][1]["signing"] = json!(hex::encode([0; 32]));
    assert!(
        Roster::from_bytes(&serde_json::to_vec(&weak_signing).unwrap())
            .map(|roster| local_roster_vote(&roster, [9; 32], &identities[0]).is_err())
            .unwrap_or(true)
    );
    let mut duplicated_key = value.clone();
    duplicated_key["members"][1]["encryption"] = value["members"][0]["encryption"].clone();
    assert!(local_roster_vote(&roster(&duplicated_key), [9; 32], &identities[0]).is_err());
    let mut legacy = value.clone();
    legacy.as_object_mut().unwrap().remove("setup_version");
    assert!(local_roster_vote(&roster(&legacy), [9; 32], &identities[0]).is_err());
}

#[test]
fn hosted_votes_cannot_be_used_as_local_votes() {
    let identities: Vec<_> = (1..=3).map(Identity::new).collect();
    let value = document(&identities);
    let roster = roster(&value);
    let hosted_payload =
        AcceptedCeremonyRoster::agreement_payload(&roster, "testnet", &[9; 32]).unwrap();
    let hosted_votes: Vec<_> = identities
        .iter()
        .map(|identity| LocalRosterVote {
            slot: identity.public().id,
            wire: identity
                .sign_setup_agreement(&roster.vault, &hosted_payload)
                .unwrap(),
        })
        .collect();
    assert!(verify_local_roster(roster, [9; 32], &identities[0], &hosted_votes).is_err());
}

#[test]
fn largest_supported_roster_fits_the_signed_vote_limit() {
    let identities: Vec<_> = (1..=16).map(Identity::new).collect();
    let mut value = document(&identities);
    value["threshold"] = json!(15);
    let votes = votes(&value, &identities, [9; 32]);
    assert!(votes.iter().all(|vote| vote.wire.len() <= 2048));
    assert_eq!(
        verify_local_roster(roster(&value), [9; 32], &identities[0], &votes)
            .unwrap()
            .validated()
            .member_count(),
        16
    );
    let mut oversized = votes;
    oversized[0].wire.resize(2049, 0);
    assert!(verify_local_roster(roster(&value), [9; 32], &identities[0], &oversized).is_err());
}

#[test]
fn generated_local_context_is_nonzero_and_unique_per_attempt() {
    let first = generate_local_context();
    let second = generate_local_context();
    assert_ne!(first, [0; 32]);
    assert_ne!(second, [0; 32]);
    assert_ne!(first, second);
}
