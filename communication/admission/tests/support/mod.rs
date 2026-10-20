use ed25519_dalek::{Signer, SigningKey};
use loki_relay_client::{sign_admission_request, CommIdentity, OperatorSet};
use loki_relay_protocol::{
    admission::{AdmissionCommand, AdmissionRequest},
    canonical::{self, Value},
    types::Id32,
};
use loki_setup_admission::{AdmissionStore, EnrollmentVerifier};
use sha2::{Digest, Sha256};
use std::{
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
pub fn bundle(signer: &SigningKey, change: impl FnOnce(&mut Vec<Value>)) -> Vec<u8> {
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
        Value::Array(vec![Value::Integer(2.into())]),
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

pub fn identity(id: u16, seed: u8) -> CommIdentity {
    let mut b = [0; 66];
    b[..2].copy_from_slice(&id.to_be_bytes());
    b[2..34].fill(seed);
    b[34..].fill(seed + 20);
    CommIdentity::from_serialized(&b).unwrap()
}
pub fn config() -> OperatorSet {
    let signer = SigningKey::from_bytes(&[90; 32]);
    OperatorSet::verify(&bundle(&signer, |_| {}), &signer.verifying_key().to_bytes()).unwrap()
}
pub fn grant(max: u64, mailboxes: u64) -> Vec<u8> {
    grant_for(&config(), max, mailboxes, 9000000)
}
pub fn grant_for(cfg: &OperatorSet, max: u64, mailboxes: u64, expires: u64) -> Vec<u8> {
    let fields = vec![
        Value::Integer(1.into()),
        Value::Bytes(vec![7; 32]),
        Value::Bytes(identity(1, 1).public().signing.to_vec()),
        Value::Integer(expires.into()),
        Value::Integer(max.into()),
        Value::Integer(mailboxes.into()),
        Value::Bytes(cfg.digest().to_vec()),
    ];
    let body = canonical::encode(&Value::Array(fields)).unwrap();
    let input =
        loki_relay_protocol::admission::signature_input(b"Loki_Setup_Enrollment_v1\0", &body)
            .unwrap();
    canonical::encode(&Value::Array(vec![
        Value::Bytes(body),
        Value::Bytes(
            SigningKey::from_bytes(&[9; 32])
                .sign(&input)
                .to_bytes()
                .to_vec(),
        ),
    ]))
    .unwrap()
}
pub struct OwnedDb {
    pub root: PathBuf,
}
impl OwnedDb {
    pub fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let tmp = std::env::temp_dir().canonicalize().unwrap();
        let root = tmp.join(format!(
            "loki-admission-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self { root }
    }
    pub fn open(&self) -> AdmissionStore {
        AdmissionStore::open(
            &self.root,
            &config(),
            EnrollmentVerifier::new(Some(
                SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
            )),
            SigningKey::from_bytes(&[8; 32]),
        )
        .unwrap()
    }
}
impl Drop for OwnedDb {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.root).unwrap();
    }
}
pub fn request(op: u8, identity: &CommIdentity, command: AdmissionCommand) -> Vec<u8> {
    sign_admission_request(
        identity,
        &AdmissionRequest {
            operation: [op; 32],
            device: identity.public(),
            command,
        },
    )
    .unwrap()
}
pub fn create(op: u8, ceremony: Id32, n: u16, grant: &[u8]) -> Vec<u8> {
    create_for(op, ceremony, n, grant, &config())
}
pub fn create_for(op: u8, ceremony: Id32, n: u16, grant: &[u8], cfg: &OperatorSet) -> Vec<u8> {
    request(
        op,
        &identity(1, 1),
        AdmissionCommand::Create {
            ceremony,
            network: "regtest".into(),
            threshold: 2,
            member_count: n,
            config_digest: *cfg.digest(),
            grant_digest: Sha256::digest(grant).into(),
            invite_hashes: (2..=n)
                .map(|slot| Sha256::digest([slot as u8; 32]).into())
                .collect(),
        },
    )
}
pub fn claim(op: u8, ceremony: Id32, slot: u16, seed: u8) -> Vec<u8> {
    request(
        op,
        &identity(slot, seed),
        AdmissionCommand::Claim {
            ceremony,
            slot,
            invite_hash: Sha256::digest([slot as u8; 32]).into(),
        },
    )
}

pub fn config_with_admission(origin: &str) -> OperatorSet {
    let signer = SigningKey::from_bytes(&[90; 32]);
    let raw = bundle(&signer, |fields| {
        let Value::Array(a) = &mut fields[2] else {
            panic!()
        };
        a[0] = Value::Bytes(origin.as_bytes().to_vec());
    });
    OperatorSet::verify_development(&raw, &signer.verifying_key().to_bytes()).unwrap()
}

pub fn config_with_routes(
    routes: &[loki_relay_protocol::types::RelayRoute],
    origin: &str,
) -> OperatorSet {
    let signer = SigningKey::from_bytes(&[90; 32]);
    let raw = bundle(&signer, |fields| {
        fields[1] = Value::Array(
            routes
                .iter()
                .map(|r| {
                    Value::Array(vec![
                        Value::Bytes(r.pin.key.to_vec()),
                        Value::Bytes(r.pin.run.to_vec()),
                        Value::Bytes(r.endpoint.as_bytes().to_vec()),
                    ])
                })
                .collect(),
        );
        let Value::Array(a) = &mut fields[2] else {
            panic!()
        };
        a[0] = Value::Bytes(origin.as_bytes().to_vec());
    });
    OperatorSet::verify_development(&raw, &signer.verifying_key().to_bytes()).unwrap()
}
