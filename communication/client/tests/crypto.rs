use loki_relay_client::{ClientError, CommIdentity};

fn synthetic_identity(id: u16) -> [u8; 66] {
    let mut bytes = [0u8; 66];
    bytes[..2].copy_from_slice(&id.to_be_bytes());
    for (index, byte) in bytes[2..34].iter_mut().enumerate() {
        *byte = index as u8;
    }
    for (index, byte) in bytes[34..].iter_mut().enumerate() {
        *byte = (index + 32) as u8;
    }
    bytes
}

#[test]
fn identity_import_member_ids() {
    for id in 1..=4 {
        assert_eq!(
            CommIdentity::from_serialized(&synthetic_identity(id))
                .unwrap()
                .public()
                .id,
            id
        );
    }
}

#[test]
fn identity_import_ed25519_public_fixture() {
    let public = CommIdentity::from_serialized(&synthetic_identity(2))
        .unwrap()
        .public();
    assert_eq!(
        hex::encode(public.signing),
        "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
    );
}

#[test]
fn identity_import_x25519_public_fixture() {
    let public = CommIdentity::from_serialized(&synthetic_identity(2))
        .unwrap()
        .public();
    assert_eq!(
        hex::encode(public.encryption),
        "358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254"
    );
}

fn assert_invalid_id(id: u16) {
    assert!(matches!(
        CommIdentity::from_serialized(&synthetic_identity(id)),
        Err(ClientError::Identity)
    ));
}

#[test]
fn identity_import_rejects_zero() {
    assert_invalid_id(0);
}

#[test]
fn identity_import_rejects_seventeen() {
    assert_invalid_id(17);
}

#[test]
fn identity_import_rejects_256() {
    assert_invalid_id(256);
}

#[test]
fn identity_import_rejects_u16_max() {
    assert_invalid_id(u16::MAX);
}

use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, setup_receiver, setup_sender,
    Deserializable, Kem, OpModeR, OpModeS, Serializable,
};
use loki_relay_client::{open_record, seal_record, SealContext, SealDomain};
use loki_relay_protocol::{
    canonical::{self, Value},
    WireError,
};
use sha2::{Digest, Sha256};
type K = X25519HkdfSha256;

fn fixture(domain: SealDomain) -> (SealContext, CommIdentity) {
    let identity = CommIdentity::from_serialized(&synthetic_identity(1)).unwrap();
    (
        SealContext {
            vault: [7; 32],
            roster: [8; 32],
            recipient: identity.public(),
            domain,
        },
        identity,
    )
}
fn record() -> Vec<u8> {
    vec![0x82, 1, 0x43, 9, 8, 7]
}
fn domains() -> [SealDomain; 3] {
    [SealDomain::Message, SealDomain::Config, SealDomain::Setup]
}
fn info(ctx: &SealContext) -> Vec<u8> {
    canonical::encode(&Value::Array(vec![
        Value::Bytes(match ctx.domain {
            SealDomain::Message => b"Loki_Relay_Seal_v1".to_vec(),
            SealDomain::Config => b"Loki_Relay_Config_Seal_v1".to_vec(),
            SealDomain::Setup => b"Loki_Setup_Seal_v1".to_vec(),
        }),
        Value::Integer(1.into()),
        Value::Bytes(ctx.vault.to_vec()),
        Value::Bytes(ctx.roster.to_vec()),
        Value::Integer(ctx.recipient.id.into()),
        Value::Bytes(ctx.recipient.encryption.to_vec()),
    ]))
    .unwrap()
}
fn aad(ctx: &SealContext, header: &[u8]) -> Vec<u8> {
    let mut aad = match ctx.domain {
        SealDomain::Message => b"Loki_Relay_Envelope_v1\0".to_vec(),
        SealDomain::Config => b"Loki_Relay_Config_Envelope_v1\0".to_vec(),
        SealDomain::Setup => b"Loki_Setup_Envelope_v1\0".to_vec(),
    };
    aad.extend_from_slice(header);
    aad
}
fn authenticated_fixture(
    ctx: &SealContext,
    inner: &[u8],
    length: u32,
    bad_padding: bool,
) -> Vec<u8> {
    let pk = <K as Kem>::PublicKey::from_bytes(&ctx.recipient.encryption).unwrap();
    let (enc, mut sender) =
        setup_sender::<ChaCha20Poly1305, HkdfSha256, K>(&OpModeS::Base, &pk, &info(ctx)).unwrap();
    let mut header = match ctx.domain {
        SealDomain::Message => b"LOKIRLY1".to_vec(),
        SealDomain::Config => b"LOKICFG1".to_vec(),
        SealDomain::Setup => b"LOKISET1".to_vec(),
    };
    header.push(1);
    header.extend_from_slice(&enc.to_bytes());
    let mut padded = length.to_be_bytes().to_vec();
    padded.extend_from_slice(inner);
    padded.resize(967, 0);
    if bad_padding {
        padded[966] = 1;
    }
    let cipher = sender.seal(&padded, &aad(ctx, &header)).unwrap();
    drop(sender);
    header.extend_from_slice(&cipher);
    header
}
#[test]
fn hpke_binding_self_copy() {
    for domain in domains() {
        let (ctx, identity) = fixture(domain);
        let object = seal_record(&ctx, &record()).unwrap();
        assert_eq!(
            open_record(&ctx, &identity, &object.wire).unwrap(),
            record()
        );
        assert_eq!(object.hash, <[u8; 32]>::from(Sha256::digest(&object.wire)));
        assert_eq!(object.wire.len(), 1024);
        let private = <K as Kem>::PrivateKey::from_bytes(&synthetic_identity(1)[34..]).unwrap();
        let enc = <K as Kem>::EncappedKey::from_bytes(&object.wire[9..41]).unwrap();
        let mut receiver = setup_receiver::<ChaCha20Poly1305, HkdfSha256, K>(
            &OpModeR::Base,
            &private,
            &enc,
            &info(&ctx),
        )
        .unwrap();
        let clear = receiver
            .open(&object.wire[41..], &aad(&ctx, &object.wire[..41]))
            .unwrap();
        assert_eq!(&clear[..4], &[0, 0, 0, 6]);
        assert_eq!(&clear[4..10], record());
        assert!(clear[10..].iter().all(|b| *b == 0));
    }
}
#[test]
fn hpke_binding_fresh_saved_bytes() {
    for domain in domains() {
        let (ctx, identity) = fixture(domain);
        let first = seal_record(&ctx, &record()).unwrap();
        let saved = first.clone();
        let fresh = seal_record(&ctx, &record()).unwrap();
        assert_ne!(first.wire, fresh.wire);
        assert_ne!(first.hash, fresh.hash);
        assert_eq!(first, saved);
        assert_eq!(open_record(&ctx, &identity, &saved.wire).unwrap(), record());
        let mut other = ctx.clone();
        other.recipient.id = 2;
        let copy = seal_record(&other, &record()).unwrap();
        assert_ne!(first.wire, copy.wire);
    }
}

fn reject(case: &str) {
    for domain in domains() {
        let (mut ctx, identity) = fixture(domain);
        let mut wire = authenticated_fixture(&ctx, &record(), 6, false);
        let expected = match case {
            "vault" => {
                ctx.vault[0] ^= 1;
                ClientError::Crypto
            }
            "roster" => {
                ctx.roster[0] ^= 1;
                ClientError::Crypto
            }
            "recipient_id" => {
                ctx.recipient.id = 2;
                ClientError::Identity
            }
            "recipient_key" => {
                ctx.recipient.encryption[0] ^= 1;
                ClientError::Identity
            }
            "recipient_signing" => {
                ctx.recipient.signing[0] ^= 1;
                ClientError::Identity
            }
            "wrong_identity" => {
                let wrong = CommIdentity::from_serialized(&synthetic_identity(2)).unwrap();
                assert_eq!(open_record(&ctx, &wrong, &wire), Err(ClientError::Identity));
                continue;
            }
            "domain" => {
                ctx.domain = if domain == SealDomain::Message {
                    SealDomain::Config
                } else {
                    SealDomain::Message
                };
                ClientError::Wire(WireError::Schema)
            }
            "rewritten_domain" => {
                ctx.domain = if domain == SealDomain::Message {
                    SealDomain::Config
                } else {
                    SealDomain::Message
                };
                wire[..8].copy_from_slice(if ctx.domain == SealDomain::Message {
                    b"LOKIRLY1"
                } else {
                    b"LOKICFG1"
                });
                ClientError::Crypto
            }
            "magic" => {
                wire[0] ^= 1;
                ClientError::Wire(WireError::Schema)
            }
            "version" => {
                wire[8] = 2;
                ClientError::Wire(WireError::Version)
            }
            "enc" => {
                wire[9] ^= 1;
                ClientError::Crypto
            }
            "tag" => {
                wire[1023] ^= 1;
                ClientError::Crypto
            }
            "ciphertext" => {
                wire[42] ^= 1;
                ClientError::Crypto
            }
            "short" => {
                wire.truncate(40);
                ClientError::Wire(WireError::Bounds)
            }
            "unaligned" => {
                wire.pop();
                ClientError::Wire(WireError::Bounds)
            }
            "oversized" => {
                wire.resize(66560, 0);
                ClientError::Wire(WireError::Bounds)
            }
            "padding" => {
                wire = authenticated_fixture(&ctx, &record(), 6, true);
                ClientError::Wire(WireError::Canonical)
            }
            "length" => {
                wire = authenticated_fixture(&ctx, &record(), u32::MAX, false);
                ClientError::Wire(WireError::Bounds)
            }
            "zero_length" => {
                wire = authenticated_fixture(&ctx, &[], 0, false);
                ClientError::Wire(WireError::Bounds)
            }
            "noncanonical" => {
                wire = authenticated_fixture(&ctx, &[0x18, 1], 2, false);
                ClientError::Wire(WireError::Canonical)
            }
            "schema" => {
                wire = if ctx.domain == SealDomain::Setup {
                    authenticated_fixture(&ctx, &[0xa0], 1, false)
                } else {
                    authenticated_fixture(&ctx, &[0x61, 0x61], 2, false)
                };
                ClientError::Wire(WireError::Schema)
            }
            "depth" => {
                let mut deep = vec![0x81; 16];
                deep.push(0xf6);
                wire = authenticated_fixture(&ctx, &deep, 17, false);
                ClientError::Wire(WireError::Bounds)
            }
            "array" => {
                wire = authenticated_fixture(&ctx, &[0x99, 1, 19], 3, false);
                ClientError::Wire(WireError::Bounds)
            }
            "trailing" => {
                wire = authenticated_fixture(&ctx, &[1, 1], 2, false);
                ClientError::Wire(WireError::Canonical)
            }
            "enc_zero" | "enc_one" => {
                wire[9..41].fill(0);
                if case == "enc_one" {
                    wire[9] = 1;
                }
                ClientError::Crypto
            }
            _ => panic!("unknown fault"),
        };
        assert_eq!(
            open_record(&ctx, &identity, &wire),
            Err(expected),
            "{case} {domain:?}"
        );
    }
}
#[test]
fn hpke_binding_vault() {
    reject("vault");
}
#[test]
fn hpke_binding_roster() {
    reject("roster");
}
#[test]
fn hpke_binding_recipient_id() {
    reject("recipient_id");
}
#[test]
fn hpke_binding_recipient_key() {
    reject("recipient_key");
}
#[test]
fn hpke_binding_recipient_signing() {
    reject("recipient_signing");
}
#[test]
fn hpke_binding_wrong_identity() {
    reject("wrong_identity");
}
#[test]
fn hpke_binding_domain() {
    reject("domain");
}
#[test]
fn hpke_binding_rewritten_domain() {
    reject("rewritten_domain");
}
#[test]
fn hpke_binding_magic() {
    reject("magic");
}
#[test]
fn hpke_binding_version() {
    reject("version");
}
#[test]
fn hpke_binding_enc() {
    reject("enc");
}
#[test]
fn hpke_binding_tag() {
    reject("tag");
}
#[test]
fn hpke_binding_ciphertext() {
    reject("ciphertext");
}
#[test]
fn hpke_binding_short() {
    reject("short");
}
#[test]
fn hpke_binding_unaligned() {
    reject("unaligned");
}
#[test]
fn hpke_binding_oversized() {
    reject("oversized");
}
#[test]
fn hpke_binding_padding() {
    reject("padding");
}
#[test]
fn hpke_binding_length() {
    reject("length");
}
#[test]
fn hpke_binding_zero_length() {
    reject("zero_length");
}
#[test]
fn hpke_binding_noncanonical() {
    reject("noncanonical");
}
#[test]
fn hpke_binding_schema() {
    reject("schema");
}
#[test]
fn hpke_binding_depth() {
    reject("depth");
}
#[test]
fn hpke_binding_array() {
    reject("array");
}
#[test]
fn hpke_binding_trailing() {
    reject("trailing");
}
#[test]
fn hpke_binding_enc_zero() {
    reject("enc_zero");
}
#[test]
fn hpke_binding_enc_one() {
    reject("enc_one");
}

#[test]
fn hpke_binding_recipient_zero() {
    noncontributory_recipient(0);
}
#[test]
fn hpke_binding_recipient_one() {
    noncontributory_recipient(1);
}
fn noncontributory_recipient(first: u8) {
    for domain in domains() {
        let (mut ctx, _) = fixture(domain);
        ctx.recipient.encryption = [0; 32];
        ctx.recipient.encryption[0] = first;
        assert_eq!(seal_record(&ctx, &record()), Err(ClientError::Crypto));
    }
}
#[test]
fn hpke_binding_seal_noncanonical() {
    for domain in domains() {
        let (ctx, _) = fixture(domain);
        assert_eq!(
            seal_record(&ctx, &[0x18, 1]),
            Err(ClientError::Wire(WireError::Canonical))
        );
    }
}
#[test]
fn hpke_binding_wire_boundary() {
    for domain in domains() {
        let (ctx, identity) = fixture(domain);
        let mut max = vec![0x59, 0xff, 0xc0];
        max.resize(65475, 0);
        let object = seal_record(&ctx, &max).unwrap();
        assert_eq!(object.wire.len(), 65536);
        assert_eq!(open_record(&ctx, &identity, &object.wire).unwrap(), max);
        let mut excess = vec![0x59, 0xff, 0xc1];
        excess.resize(65476, 0);
        assert_eq!(
            seal_record(&ctx, &excess),
            Err(ClientError::Wire(WireError::Bounds))
        );
    }
}

#[test]
fn hpke_binding_member_zero() {
    invalid_member(0);
}
#[test]
fn hpke_binding_member_seventeen() {
    invalid_member(17);
}
fn invalid_member(id: u16) {
    for domain in domains() {
        let (mut ctx, _) = fixture(domain);
        ctx.recipient.id = id;
        assert_eq!(seal_record(&ctx, &record()), Err(ClientError::Identity));
    }
}

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use loki_relay_client::{authenticate, sign_message};
use loki_relay_protocol::types::{self, LogicalKey, MessageBody, MessageRef, Payload, Roster};

const BODY_LIMIT: usize = 16 * 1024 * 1024;

fn message_identity(id: u16) -> CommIdentity {
    let mut bytes = synthetic_identity(id);
    bytes[2..34].fill(id as u8);
    bytes[34..].fill((id + 3) as u8);
    CommIdentity::from_serialized(&bytes).unwrap()
}
fn message_fixture() -> (Roster, MessageBody) {
    let roster = Roster {
        vault: [7; 32],
        members: (1..=3).map(|id| message_identity(id).public()).collect(),
    };
    let body = MessageBody {
        key: LogicalKey {
            vault: roster.vault,
            roster: types::roster_digest(&roster).unwrap(),
            sender: 1,
            message: [9; 32],
        },
        audience: vec![1, 2, 3],
        session: None,
        prerequisites: vec![],
        payload: Payload::Test(vec![10, 11, 12]),
    };
    (roster, body)
}
fn signature_input(body: &[u8]) -> Vec<u8> {
    let mut input = b"Loki_Relay_Message_v1\0".to_vec();
    input.extend_from_slice(&(body.len() as u32).to_be_bytes());
    input.extend_from_slice(body);
    input
}
fn package_parts(body: &[u8], signature: &[u8]) -> Vec<u8> {
    canonical::encode(&Value::Array(vec![
        Value::Bytes(body.to_vec()),
        Value::Bytes(signature.to_vec()),
    ]))
    .unwrap()
}
fn raw_package(body: &[u8], signer: u8) -> Vec<u8> {
    let signature = SigningKey::from_bytes(&[signer; 32]).sign(&signature_input(body));
    package_parts(body, &signature.to_bytes())
}
fn message_fields(body: &MessageBody) -> Vec<Value> {
    match canonical::decode(&types::encode_message(body).unwrap(), BODY_LIMIT).unwrap() {
        Value::Array(fields) => fields,
        _ => unreachable!(),
    }
}
fn reject_message_fields(roster: &Roster, fields: Vec<Value>) {
    let encoded = canonical::encode(&Value::Array(fields)).unwrap();
    assert!(authenticate(roster, &raw_package(&encoded, 1)).is_err());
}

#[test]
fn inner_signature_common_package_digest_and_domain() {
    let (roster, mut body) = message_fixture();
    for sender in 1..=3 {
        body.key.sender = sender;
        body.session = Some([13; 32]);
        let package = sign_message(&message_identity(sender), &roster, &body).unwrap();
        let encoded = types::encode_message(&body).unwrap();
        assert_eq!(package, raw_package(&encoded, sender as u8));
        let Value::Array(parts) = canonical::decode(&package, BODY_LIMIT + 128).unwrap() else {
            panic!()
        };
        let Value::Bytes(signature) = &parts[1] else {
            panic!()
        };
        VerifyingKey::from_bytes(&roster.members[(sender - 1) as usize].signing)
            .unwrap()
            .verify_strict(
                &signature_input(&encoded),
                &Signature::from_slice(signature).unwrap(),
            )
            .unwrap();
        for recipient in &roster.members {
            assert!(body.audience.contains(&recipient.id));
            let authenticated = authenticate(&roster, &package).unwrap();
            assert_eq!(authenticated.body(), &body);
            assert_eq!(authenticated.canonical_body(), encoded);
            assert_eq!(
                *authenticated.digest(),
                <[u8; 32]>::from(Sha256::digest(&encoded))
            );
        }
    }
}
#[test]
fn inner_signature_signer_certification() {
    let (roster, mut body) = message_fixture();
    assert!(sign_message(&message_identity(2), &roster, &body).is_err());
    let mut changed = roster.clone();
    changed.members[0].signing = message_identity(4).public().signing;
    body.key.roster = types::roster_digest(&changed).unwrap();
    assert!(sign_message(&message_identity(1), &changed, &body).is_err());
    changed = roster.clone();
    changed.members[0].encryption[0] ^= 1;
    body.key.roster = types::roster_digest(&changed).unwrap();
    assert!(sign_message(&message_identity(1), &changed, &body).is_err());
}
#[test]
fn inner_signature_vault_binding() {
    let (roster, mut body) = message_fixture();
    body.key.vault[0] ^= 1;
    assert!(sign_message(&message_identity(1), &roster, &body).is_err());
    assert!(authenticate(
        &roster,
        &raw_package(&types::encode_message(&body).unwrap(), 1)
    )
    .is_err());
}
#[test]
fn inner_signature_roster_digest_binding() {
    let (roster, mut body) = message_fixture();
    body.key.roster[0] ^= 1;
    assert!(sign_message(&message_identity(1), &roster, &body).is_err());
    assert!(authenticate(
        &roster,
        &raw_package(&types::encode_message(&body).unwrap(), 1)
    )
    .is_err());
}
#[test]
fn inner_signature_roster_validation() {
    let (roster, body) = message_fixture();
    for fault in 0..4 {
        let mut invalid = roster.clone();
        match fault {
            0 => {
                invalid.members.pop();
            }
            1 => invalid.members.swap(0, 1),
            2 => invalid.members[0].id = 0,
            _ => invalid.members[1].id = 1,
        }
        assert!(sign_message(&message_identity(1), &invalid, &body).is_err());
        assert!(authenticate(
            &invalid,
            &raw_package(&types::encode_message(&body).unwrap(), 1)
        )
        .is_err());
    }
}
#[test]
fn inner_signature_wrong_certified_sender() {
    let (roster, mut body) = message_fixture();
    body.key.sender = 2;
    assert!(authenticate(
        &roster,
        &raw_package(&types::encode_message(&body).unwrap(), 1)
    )
    .is_err());
    let mut changed = roster.clone();
    changed.members[1].signing = message_identity(4).public().signing;
    body.key.roster = types::roster_digest(&changed).unwrap();
    assert!(authenticate(
        &changed,
        &raw_package(&types::encode_message(&body).unwrap(), 2)
    )
    .is_err());
}
#[test]
fn inner_signature_tampered_signature_and_session() {
    let (roster, body) = message_fixture();
    let encoded = types::encode_message(&body).unwrap();
    let mut signature = SigningKey::from_bytes(&[1; 32])
        .sign(&signature_input(&encoded))
        .to_bytes();
    signature[0] ^= 1;
    assert!(authenticate(&roster, &package_parts(&encoded, &signature)).is_err());
    let mut changed = body.clone();
    changed.session = Some([14; 32]);
    let good_signature = SigningKey::from_bytes(&[1; 32])
        .sign(&signature_input(&encoded))
        .to_bytes();
    assert!(authenticate(
        &roster,
        &package_parts(&types::encode_message(&changed).unwrap(), &good_signature)
    )
    .is_err());
    for input in [
        encoded.clone(),
        [
            b"Loki_Relay_Message_v2\0".as_slice(),
            &(encoded.len() as u32).to_be_bytes(),
            &encoded,
        ]
        .concat(),
        [
            b"Loki_Relay_Message_v1\0".as_slice(),
            &((encoded.len() + 1) as u32).to_be_bytes(),
            &encoded,
        ]
        .concat(),
    ] {
        let wrong = SigningKey::from_bytes(&[1; 32]).sign(&input);
        assert!(authenticate(&roster, &package_parts(&encoded, &wrong.to_bytes())).is_err());
    }
}
#[test]
fn inner_signature_strict_weak_key() {
    let (mut roster, mut body) = message_fixture();
    roster.members[0].signing = [0; 32];
    roster.members[0].signing[0] = 1;
    body.key.roster = types::roster_digest(&roster).unwrap();
    let encoded = types::encode_message(&body).unwrap();
    let mut forged = [0; 64];
    forged[0] = 1;
    assert!(authenticate(&roster, &package_parts(&encoded, &forged)).is_err());
}
#[test]
fn inner_signature_audience_and_schema() {
    let (roster, mut body) = message_fixture();
    for audience in [vec![1, 2], vec![1, 1, 3], vec![3, 2, 1], vec![1, 2, 4]] {
        body.audience = audience.clone();
        assert!(sign_message(&message_identity(1), &roster, &body).is_err());
        let (_, valid) = message_fixture();
        let mut fields = message_fields(&valid);
        fields[5] = Value::Array(
            audience
                .into_iter()
                .map(|id| Value::Integer(id.into()))
                .collect(),
        );
        reject_message_fields(&roster, fields);
    }
    let (_, valid) = message_fixture();
    for (index, replacement) in [
        (0, Value::Integer(2.into())),
        (4, Value::Integer(0.into())),
        (4, Value::Integer(4.into())),
        (6, Value::Integer(3.into())),
        (7, Value::Bytes(vec![0; 31])),
        (7, Value::Integer(1.into())),
        (1, Value::Bytes(vec![0; 31])),
        (9, Value::Array(vec![])),
    ] {
        let mut fields = message_fields(&valid);
        fields[index] = replacement;
        reject_message_fields(&roster, fields);
    }
    let mut fields = message_fields(&valid);
    fields.push(Value::Null);
    reject_message_fields(&roster, fields);
}
#[test]
fn inner_signature_received_reference_association() {
    let (roster, mut body) = message_fixture();
    let reference = MessageRef {
        sender: 2,
        message: [20; 32],
        digest: [21; 32],
    };
    body.payload = Payload::Received(reference.clone());
    body.session = Some([22; 32]);
    assert!(sign_message(&message_identity(1), &roster, &body).is_err());
    let mut fields = message_fields(&message_fixture().1);
    fields[6] = Value::Integer(2.into());
    fields[9] = Value::Array(vec![Value::Array(vec![
        Value::Integer(2.into()),
        Value::Bytes(vec![20; 32]),
        Value::Bytes(vec![21; 32]),
    ])]);
    reject_message_fields(&roster, fields);
    body.prerequisites = vec![reference];
    let signed = sign_message(&message_identity(1), &roster, &body).unwrap();
    assert_eq!(authenticate(&roster, &signed).unwrap().body(), &body);
    body.prerequisites[0].digest[0] ^= 1;
    assert!(sign_message(&message_identity(1), &roster, &body).is_err());
}
#[test]
fn inner_signature_prerequisite_bounds_order() {
    let (roster, mut body) = message_fixture();
    body.prerequisites = (0..64)
        .map(|n| MessageRef {
            sender: 2,
            message: [n; 32],
            digest: [1; 32],
        })
        .collect();
    let signed = sign_message(&message_identity(1), &roster, &body).unwrap();
    assert_eq!(authenticate(&roster, &signed).unwrap().body(), &body);
    body.prerequisites.push(MessageRef {
        sender: 2,
        message: [64; 32],
        digest: [1; 32],
    });
    assert!(sign_message(&message_identity(1), &roster, &body).is_err());
    body.prerequisites.pop();
    body.prerequisites.swap(0, 1);
    assert!(sign_message(&message_identity(1), &roster, &body).is_err());
    body.prerequisites[0] = body.prerequisites[1].clone();
    assert!(sign_message(&message_identity(1), &roster, &body).is_err());
}
#[test]
fn inner_signature_package_schema_canonical_limits() {
    let (roster, body) = message_fixture();
    let encoded = types::encode_message(&body).unwrap();
    for length in [0, 63, 65] {
        assert!(authenticate(&roster, &package_parts(&encoded, &vec![0; length])).is_err());
    }
    for value in [
        Value::Array(vec![]),
        Value::Array(vec![Value::Bytes(encoded.clone()), Value::Null]),
        Value::Array(vec![
            Value::Bytes(encoded.clone()),
            Value::Bytes(vec![0; 64]),
            Value::Null,
        ]),
        Value::Array(vec![Value::Integer(1.into()), Value::Bytes(vec![0; 64])]),
    ] {
        assert!(authenticate(&roster, &canonical::encode(&value).unwrap()).is_err());
    }
    let good = raw_package(&encoded, 1);
    let mut noncanonical = vec![0x98, 2];
    noncanonical.extend_from_slice(&good[1..]);
    assert!(authenticate(&roster, &noncanonical).is_err());
    let mut trailing = good;
    trailing.push(0);
    assert!(authenticate(&roster, &trailing).is_err());
    assert!(authenticate(&roster, &vec![0; BODY_LIMIT + 129]).is_err());
    assert!(authenticate(&roster, &[0x82, 0x5a, 0xff, 0xff, 0xff, 0xff]).is_err());
    let mut deep = vec![0x81; 16];
    deep.push(0xf6);
    assert!(authenticate(&roster, &deep).is_err());
    let mut noncanonical_body = vec![0x98, 10];
    noncanonical_body.extend_from_slice(&encoded[1..]);
    assert!(authenticate(&roster, &raw_package(&noncanonical_body, 1)).is_err());
}
#[test]
fn inner_signature_body_size_boundary() {
    let (roster, mut body) = message_fixture();
    body.payload = Payload::Test(vec![]);
    let overhead = types::encode_message(&body).unwrap().len() + 4;
    body.payload = Payload::Test(vec![0; BODY_LIMIT - overhead]);
    let encoded = types::encode_message(&body).unwrap();
    assert_eq!(encoded.len(), BODY_LIMIT);
    let signed = sign_message(&message_identity(1), &roster, &body).unwrap();
    assert!(signed.len() <= BODY_LIMIT + 128);
    let authenticated = authenticate(&roster, &signed).unwrap();
    assert_eq!(authenticated.canonical_body().len(), BODY_LIMIT);
    assert_eq!(
        *authenticated.digest(),
        <[u8; 32]>::from(Sha256::digest(&encoded))
    );
    if let Payload::Test(data) = &mut body.payload {
        data.push(0);
    }
    assert!(sign_message(&message_identity(1), &roster, &body).is_err());
    let mut fields = message_fields(&message_fixture().1);
    fields[9] = Value::Array(vec![Value::Bytes(vec![0; BODY_LIMIT - overhead + 1])]);
    reject_message_fields(&roster, fields);
}
