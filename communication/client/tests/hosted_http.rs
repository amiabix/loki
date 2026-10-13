use loki_relay_client::{validate_endpoint, ClientError};

#[test]
fn hosted_origins_require_https() {
    for raw in [
        "https://relay.example",
        "https://relay.example:443",
        "https://relay.example:8443/",
        "https://127.0.0.1:8443",
        "https://[::1]:8443",
    ] {
        assert!(validate_endpoint(raw, false).is_ok(), "{raw}");
    }
    for raw in [
        "http://relay.example:80",
        "http://192.168.1.2:8080",
        "http://127.0.0.1:8000",
        "http://[::1]:8000",
    ] {
        assert_eq!(
            validate_endpoint(raw, false),
            Err(ClientError::Config),
            "{raw}"
        );
    }
}

#[test]
fn development_http_requires_literal_loopback_and_nonzero_port() {
    for raw in [
        "http://127.0.0.1:80",
        "http://127.0.0.1:65535/",
        "http://[::1]:8001",
    ] {
        assert!(validate_endpoint(raw, true).is_ok(), "{raw}");
    }
    for raw in [
        "http://localhost:8000",
        "http://127.1:8000",
        "http://2130706433:8000",
        "http://0x7f000001:8000",
        "http://127.0.0.2:8000",
        "http://127.0.0.1",
        "http://127.0.0.1:0",
        "http://127.0.0.1:+80",
        "http://[::1]",
        "http://192.168.0.1:80",
    ] {
        assert_eq!(
            validate_endpoint(raw, true),
            Err(ClientError::Config),
            "{raw}"
        );
    }
}

#[test]
fn reject_credentials_paths_and_parser_normalization() {
    for raw in [
        "https://u@relay.example",
        "https://u:p@relay.example",
        "https://@relay.example",
        "https://relay.example?",
        "https://relay.example#",
        "https://relay.example/?q=1",
        "https://relay.example/path",
        "https://relay.example/..",
        "https://relay.example/%2f",
        "https://relay.example//",
        "https://relay.example:0",
        "https://relay.example:",
        "https://relay.example:+443",
        "https://relay.example:65536",
        "https://relay.example\\",
        "https://relay.example\n",
        " https://relay.example",
        "https:///relay.example",
        "ftp://relay.example",
    ] {
        assert!(validate_endpoint(raw, false).is_err(), "{raw}");
    }
}

use ed25519_dalek::{Signer, SigningKey};
use loki_relay_client::OperatorSet;
use loki_relay_protocol::canonical::{self, Value};

fn bundle(signer: &SigningKey, change: impl FnOnce(&mut Vec<Value>)) -> Vec<u8> {
    let mut fields = vec![
        Value::Integer(1.into()),
        Value::Array(
            (1u8..=3)
                .map(|i| {
                    Value::Array(vec![
                        Value::Bytes(
                            SigningKey::from_bytes(&[i; 32])
                                .verifying_key()
                                .to_bytes()
                                .to_vec(),
                        ),
                        Value::Bytes(vec![i + 10; 32]),
                        Value::Bytes(format!("https://relay{i}.example").into_bytes()),
                    ])
                })
                .collect(),
        ),
        Value::Array(vec![
            Value::Bytes(b"https://admission.example".to_vec()),
            Value::Bytes(
                SigningKey::from_bytes(&[8; 32])
                    .verifying_key()
                    .to_bytes()
                    .to_vec(),
            ),
        ]),
        Value::Array(vec![Value::Integer(1.into())]),
        Value::Array(vec![
            Value::Integer(86400.into()),
            Value::Integer(2592000.into()),
            Value::Integer(1048576.into()),
            Value::Integer(67108864.into()),
            Value::Integer(30.into()),
            Value::Integer(1.into()),
            Value::Integer(60.into()),
        ]),
    ];
    if let Value::Array(routes) = &mut fields[1] {
        routes.sort_by_key(|r| canonical::encode(r).unwrap());
    }
    change(&mut fields);
    let body = canonical::encode(&Value::Array(fields)).unwrap();
    let mut input = b"Loki_Operator_Config_v1\0".to_vec();
    input.extend_from_slice(&(body.len() as u32).to_be_bytes());
    input.extend_from_slice(&body);
    canonical::encode(&Value::Array(vec![
        Value::Bytes(body),
        Value::Bytes(signer.sign(&input).to_bytes().to_vec()),
    ]))
    .unwrap()
}

#[test]
fn operator_bundle_trust_and_routes() {
    let signer = SigningKey::from_bytes(&[9; 32]);
    let raw = bundle(&signer, |_| {});
    let config = OperatorSet::verify(&raw, &signer.verifying_key().to_bytes()).unwrap();
    assert_eq!(config.relay_routes().len(), 3);
    assert_eq!(config.admission_origin(), "https://admission.example");
    assert_eq!(config.setup_versions(), &[1]);
    assert!(OperatorSet::verify(
        &raw,
        &SigningKey::from_bytes(&[10; 32]).verifying_key().to_bytes()
    )
    .is_err());
    let mut changed = raw.clone();
    let pos = changed.windows(6).position(|b| b == b"relay1").unwrap();
    changed[pos + 5] = b'9';
    assert!(OperatorSet::verify(&changed, &signer.verifying_key().to_bytes()).is_err());
}

#[test]
fn operator_bundle_rejects_unusable_authenticated_config() {
    let signer = SigningKey::from_bytes(&[9; 32]);
    for case in 0..7 {
        let raw = bundle(&signer, |fields| match case {
            0 => fields[0] = Value::Integer(2.into()),
            1 => {
                if let Value::Array(routes) = &mut fields[1] {
                    routes.pop();
                }
            }
            2 => {
                if let Value::Array(routes) = &mut fields[1] {
                    routes[1] = routes[0].clone();
                }
            }
            3 => {
                if let Value::Array(admission) = &mut fields[2] {
                    admission[0] = Value::Bytes(b"http://127.0.0.1:8000".to_vec());
                }
            }
            4 => fields[3] = Value::Array(vec![Value::Integer(2.into())]),
            5 => {
                if let Value::Array(limits) = &mut fields[4] {
                    limits[2] = Value::Integer(1048577.into());
                }
            }
            6 => fields.push(Value::Null),
            _ => unreachable!(),
        });
        assert!(
            OperatorSet::verify(&raw, &signer.verifying_key().to_bytes()).is_err(),
            "case {case}"
        );
    }
}

#[tokio::test]
async fn hosted_client_refuses_http_before_connecting() {
    let client = loki_relay_client::RelayHttp::hosted().unwrap();
    let pin = loki_relay_protocol::types::RelayPin {
        key: [1; 32],
        run: [2; 32],
    };
    assert_eq!(
        client
            .authenticate_endpoint(&pin, "http://127.0.0.1:1")
            .await,
        Err(ClientError::Config)
    );
}

#[test]
fn owned_development_bundle_is_explicit_and_only_literal_loopback() {
    let signer = SigningKey::from_bytes(&[9; 32]);
    let raw = bundle(&signer, |f| {
        let Value::Array(routes) = &mut f[1] else {
            panic!()
        };
        for (i, route) in routes.iter_mut().enumerate() {
            let Value::Array(route) = route else { panic!() };
            route[2] = Value::Bytes(format!("http://127.0.0.1:{}", 8000 + i).into_bytes());
        }
        let Value::Array(a) = &mut f[2] else { panic!() };
        a[0] = Value::Bytes(b"http://127.0.0.1:9000".to_vec());
    });
    assert!(OperatorSet::verify(&raw, &signer.verifying_key().to_bytes()).is_err());
    assert!(OperatorSet::verify_development(&raw, &signer.verifying_key().to_bytes()).is_ok());
    let bad = bundle(&signer, |f| {
        let Value::Array(a) = &mut f[2] else { panic!() };
        a[0] = Value::Bytes(b"http://localhost:9000".to_vec());
    });
    assert!(OperatorSet::verify_development(&bad, &signer.verifying_key().to_bytes()).is_err());
}
