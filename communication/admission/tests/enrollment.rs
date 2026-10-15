use ed25519_dalek::{Signer, SigningKey};
use loki_relay_protocol::canonical::{self, Value};
use loki_setup_admission::{AdmissionError, EnrollmentVerifier};
fn key(seed: u8) -> [u8; 32] {
    SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes()
}
fn grant(change: impl FnOnce(&mut Vec<Value>)) -> Vec<u8> {
    let mut f = vec![
        Value::Integer(1.into()),
        Value::Bytes(vec![7; 32]),
        Value::Bytes(key(2).to_vec()),
        Value::Integer(1000.into()),
        Value::Integer(2.into()),
        Value::Integer(48.into()),
        Value::Bytes(vec![8; 32]),
    ];
    change(&mut f);
    let body = canonical::encode(&Value::Array(f)).unwrap();
    let mut input = b"Loki_Setup_Enrollment_v1\0".to_vec();
    input.extend_from_slice(&(body.len() as u32).to_be_bytes());
    input.extend_from_slice(&body);
    canonical::encode(&Value::Array(vec![
        Value::Bytes(body),
        Value::Bytes(
            SigningKey::from_bytes(&[1; 32])
                .sign(&input)
                .to_bytes()
                .to_vec(),
        ),
    ]))
    .unwrap()
}
#[test]
fn absent_issuer_denies_all_creation() {
    assert!(matches!(
        EnrollmentVerifier::new(None).verify(&grant(|_| {}), &key(2), 100),
        Err(AdmissionError::Enrollment)
    ));
}
#[test]
fn scoped_grant_is_bound_to_device_expiry_and_budget() {
    let verifier = EnrollmentVerifier::new(Some(key(1)));
    let raw = grant(|_| {});
    let budget = verifier.verify(&raw, &key(2), 100).unwrap();
    assert_eq!(budget.grant_id(), &[7; 32]);
    assert_eq!(budget.max_creations(), 2);
    assert_eq!(budget.mailbox_budget(), 48);
    assert_eq!(budget.config_digest(), &[8; 32]);
    assert!(verifier.verify(&raw, &key(3), 100).is_err());
    assert!(verifier.verify(&raw, &key(2), 1000).is_err());
    assert!(EnrollmentVerifier::new(Some(key(9)))
        .verify(&raw, &key(2), 100)
        .is_err());
    let mut altered = raw.clone();
    let end = altered.len() - 1;
    altered[end] ^= 1;
    assert!(verifier.verify(&altered, &key(2), 100).is_err());
}
#[test]
fn authenticated_malformed_grants_fail_closed() {
    let verifier = EnrollmentVerifier::new(Some(key(1)));
    for (field, value) in [
        (0, Value::Integer(2.into())),
        (1, Value::Bytes(vec![7; 31])),
        (3, Value::Integer(u64::MAX.into())),
        (4, Value::Integer(0.into())),
        (4, Value::Integer(101.into())),
        (5, Value::Integer(0.into())),
        (5, Value::Integer(2401.into())),
    ] {
        assert!(verifier
            .verify(&grant(|f| f[field] = value), &key(2), 100)
            .is_err());
    }
    assert!(verifier.verify(&vec![0; 4097], &key(2), 100).is_err());
}
