use loki_relay_protocol::{
    canonical::{self, Value},
    setup::{decode_record, encode_record, SetupCapabilities, SetupKey, SetupPhase, SetupRecord},
};
fn record() -> SetupRecord {
    SetupRecord {
        version: 1,
        key: SetupKey {
            ceremony: [7; 32],
            phase: SetupPhase::Round1,
            author: 1,
            recipient: 4,
            revision: 1,
        },
        network: "regtest".into(),
        threshold: 2,
        member_count: 4,
        roster_digest: Some([8; 32]),
        prerequisites: vec![[9; 32]],
        payload: vec![10; 100],
    }
}
#[test]
fn setup_canonical_record_roundtrip_and_exact_context() {
    let input = record();
    let encoded = encode_record(&input).unwrap();
    let opened = decode_record(&encoded).unwrap();
    assert_eq!(opened.key, input.key);
    assert_eq!(opened.network, "regtest");
    assert_eq!(opened.threshold, 2);
    assert_eq!(opened.member_count, 4);
    assert_eq!(opened.payload, input.payload);
    assert_eq!(encode_record(&opened).unwrap(), encoded);
    let Value::Array(fields) = canonical::decode(&encoded, 1100000).unwrap() else {
        panic!()
    };
    assert_eq!(fields.len(), 12);
    assert_eq!(fields[2], Value::Text("regtest".into()));
    assert_eq!(fields[7], Value::Integer(4.into()));
}
#[test]
fn setup_rejects_malformed_and_out_of_range_fields() {
    for case in 0..10 {
        let mut input = record();
        match case {
            0 => input.version = 2,
            1 => input.threshold = 1,
            2 => input.member_count = 5,
            3 => input.key.author = 0,
            4 => input.key.recipient = 5,
            5 => input.key.revision = 0,
            6 => input.network = "".into(),
            7 => input.prerequisites = vec![[9; 32]; 2],
            8 => input.payload.resize(1048577, 0),
            9 => input.roster_digest = None,
            _ => unreachable!(),
        };
        assert!(encode_record(&input).is_err(), "case {case}");
    }
    let encoded = encode_record(&record()).unwrap();
    let Value::Array(mut fields) = canonical::decode(&encoded, 1100000).unwrap() else {
        panic!()
    };
    fields[5] = Value::Integer(11.into());
    assert!(decode_record(&canonical::encode(&Value::Array(fields)).unwrap()).is_err());
}
#[test]
fn setup_payload_limit_and_both_policies() {
    for count in [3, 4] {
        let mut input = record();
        input.member_count = count;
        input.key.recipient = count;
        input.payload = vec![23; 1048576];
        let encoded = encode_record(&input).unwrap();
        assert_eq!(decode_record(&encoded).unwrap().payload.len(), 1048576);
    }
}
#[test]
fn setup_negotiation_rejects_incapable_peer_before_dkg() {
    assert!(SetupCapabilities::current().supports(1, 3));
    assert!(SetupCapabilities::current().supports(1, 4));
    assert!(!SetupCapabilities::current().supports(2, 4));
    let legacy = SetupCapabilities {
        versions: vec![1],
        member_counts: vec![3],
    };
    assert!(!legacy.supports(1, 4));
    assert!(legacy.require(1, 4).is_err());
}
