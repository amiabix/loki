use loki_poc::{member_state::Roster, setup_transport::Identity};
use std::fs;

#[test]
fn roster_certifies_policy_and_keeps_legacy_fingerprint() {
    let path = std::env::temp_dir().join(format!(
        "loki-roster-policy-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let members: Vec<_> = (1..=4)
        .map(|id| {
            let public = Identity::new(id).public();
            serde_json::json!({"id": id, "signing": hex::encode(public.signing),
                               "encryption": hex::encode(public.encryption)})
        })
        .collect();
    let mut document = serde_json::json!({"vault": hex::encode([7u8; 32]),
                                           "threshold": 2, "members": members});
    fs::write(&path, document.to_string()).unwrap();
    let four = Roster::load(&path).unwrap();
    assert_eq!(four.threshold, 2);
    assert_eq!(four.members.len(), 4);

    document["members"].as_array_mut().unwrap().pop();
    fs::write(&path, document.to_string()).unwrap();
    let new_three = Roster::load(&path).unwrap().fingerprint();
    document.as_object_mut().unwrap().remove("threshold");
    fs::write(&path, document.to_string()).unwrap();
    let old_three = Roster::load(&path).unwrap().fingerprint();
    assert_ne!(new_three, old_three);

    document["threshold"] = 3.into();
    fs::write(&path, document.to_string()).unwrap();
    assert!(Roster::load(&path).is_err());
    fs::remove_file(path).unwrap();
}
