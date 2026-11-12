use loki_relay_protocol::{
    canonical::{decode, encode, Value},
    WireError,
};

const MAX: usize = 16 * 1024 * 1024 + 128;

fn uint(n: u64) -> Value {
    Value::Integer(n.into())
}
fn nested(depth: usize) -> Value {
    (1..depth).fold(Value::Null, |v, _| Value::Array(vec![v]))
}

#[test]
fn canonical_subset_shortest_uints_roundtrip() {
    for (n, bytes) in [
        (0, vec![0]),
        (23, vec![23]),
        (24, vec![24, 24]),
        (255, vec![24, 255]),
        (256, vec![25, 1, 0]),
        (65535, vec![25, 255, 255]),
        (65536, vec![26, 0, 1, 0, 0]),
        (u32::MAX as u64, vec![26, 255, 255, 255, 255]),
        (u32::MAX as u64 + 1, vec![27, 0, 0, 0, 1, 0, 0, 0, 0]),
        (u64::MAX, vec![27, 255, 255, 255, 255, 255, 255, 255, 255]),
    ] {
        assert_eq!(encode(&uint(n)).unwrap(), bytes);
        assert_eq!(decode(&bytes, MAX).unwrap(), uint(n));
    }
    for n in [0, 23, 24, 255, 256, 65535] {
        let v = Value::Bytes(vec![7; n]);
        let bytes = encode(&v).unwrap();
        assert_eq!(decode(&bytes, MAX).unwrap(), v);
    }
    assert_eq!(encode(&Value::Bytes(vec![0; 32])).unwrap()[..2], [0x58, 32]);
    assert_eq!(encode(&Value::Bytes(vec![0; 64])).unwrap()[..2], [0x58, 64]);
}

#[test]
fn canonical_subset_nonshortest() {
    for bytes in [
        vec![0x18, 1],
        vec![0x19, 0, 24],
        vec![0x1a, 0, 0, 1, 0],
        vec![0x1b, 0, 0, 0, 0, 0, 1, 0, 0],
        vec![0x58, 0],
        vec![0x98, 0],
    ] {
        assert_eq!(decode(&bytes, MAX), Err(WireError::Canonical));
    }
}

#[test]
fn canonical_subset_depth() {
    let valid = nested(16);
    assert_eq!(decode(&encode(&valid).unwrap(), MAX).unwrap(), valid);
    assert_eq!(encode(&nested(17)), Err(WireError::Bounds));
    let mut bytes = vec![0x81; 16];
    bytes.push(0xf6);
    assert_eq!(decode(&bytes, MAX), Err(WireError::Bounds));
}

#[test]
fn canonical_subset_declared_lengths() {
    for bytes in [
        vec![0x5b, 255, 255, 255, 255, 255, 255, 255, 255],
        vec![0x9b, 255, 255, 255, 255, 255, 255, 255, 255],
        vec![0x43, 1],
        vec![0x83, 0],
    ] {
        assert_eq!(decode(&bytes, MAX), Err(WireError::Bounds));
    }
}

#[test]
fn canonical_subset_forbidden_types() {
    for bytes in [
        vec![0x20],
        vec![0xa0],
        vec![0xc0, 0],
        vec![0xf9, 0, 0],
        vec![0xfa, 0, 0, 0, 0],
        vec![0xfb, 0, 0, 0, 0, 0, 0, 0, 0],
        vec![0xf4],
        vec![0xf5],
        vec![0xf7],
        vec![0xff],
        vec![0x9f, 0xff],
        vec![0x5f, 0xff],
        vec![0x7f, 0xff],
        vec![0xbf, 0xff],
    ] {
        assert!(decode(&bytes, MAX).is_err(), "accepted {bytes:02x?}");
    }
    for v in [
        Value::Integer((-1).into()),
        Value::Map(vec![]),
        Value::Tag(0, Box::new(uint(0))),
        Value::Float(0.0),
        Value::Bool(false),
    ] {
        assert_eq!(encode(&v), Err(WireError::Schema));
    }
}

#[test]
fn canonical_subset_trailing_and_truncated() {
    assert_eq!(decode(&[0, 0], MAX), Err(WireError::Canonical));
    for bytes in [vec![], vec![0x18], vec![0x19, 0], vec![0x81]] {
        assert!(decode(&bytes, MAX).is_err());
    }
}

#[test]
fn canonical_subset_cardinality() {
    let valid = Value::Array(vec![Value::Null; 274]);
    assert_eq!(decode(&encode(&valid).unwrap(), MAX).unwrap(), valid);
    assert_eq!(
        encode(&Value::Array(vec![Value::Null; 275])),
        Err(WireError::Bounds)
    );
    let mut bytes = vec![0x99, 1, 19];
    bytes.extend([0xf6; 275]);
    assert_eq!(decode(&bytes, MAX), Err(WireError::Bounds));
}

#[test]
fn canonical_subset_size_limits() {
    assert_eq!(decode(&[0], 0), Err(WireError::Bounds));
    assert_eq!(decode(&[0], MAX + 1), Err(WireError::Bounds));
    let v = Value::Bytes(vec![0; MAX - 5]);
    let bytes = encode(&v).unwrap();
    assert_eq!(bytes.len(), MAX);
    assert_eq!(decode(&bytes, MAX).unwrap(), v);
    assert_eq!(decode(&bytes, MAX - 1), Err(WireError::Bounds));
    assert_eq!(
        encode(&Value::Bytes(vec![0; MAX - 4])),
        Err(WireError::Bounds)
    );
}

#[test]
fn canonical_subset_tags() {
    assert!(decode(&[0xc0, 0], MAX).is_err());
}

#[test]
fn canonical_subset_maps() {
    assert!(decode(&[0xa0], MAX).is_err());
}

#[test]
fn canonical_subset_floats() {
    for bytes in [
        vec![0xf9, 0, 0],
        vec![0xfa, 0, 0, 0, 0],
        vec![0xfb, 0, 0, 0, 0, 0, 0, 0, 0],
    ] {
        assert!(decode(&bytes, MAX).is_err());
    }
}

#[test]
fn canonical_subset_indefinite() {
    for bytes in [
        vec![0x9f, 0xff],
        vec![0x5f, 0xff],
        vec![0x7f, 0xff],
        vec![0xbf, 0xff],
    ] {
        assert!(decode(&bytes, MAX).is_err());
    }
}

use loki_relay_protocol::types::{
    encode_message, encode_roster, roster_digest, LogicalKey, MemberPublic, MessageBody,
    MessageRef, Payload, Roster,
};

fn schema_roster() -> Roster {
    Roster {
        vault: [9; 32],
        members: (1..=3)
            .map(|id| MemberPublic {
                id,
                signing: [id as u8; 32],
                encryption: [id as u8 + 10; 32],
            })
            .collect(),
    }
}
fn schema_body() -> MessageBody {
    MessageBody {
        key: LogicalKey {
            vault: [9; 32],
            roster: [8; 32],
            sender: 1,
            message: [7; 32],
        },
        audience: vec![1, 2, 3],
        session: None,
        prerequisites: vec![],
        payload: Payload::Test(vec![4, 5]),
    }
}
fn schema_ref(sender: u16, message: u8) -> MessageRef {
    MessageRef {
        sender,
        message: [message; 32],
        digest: [6; 32],
    }
}

#[test]
fn message_schema_exact_audience_and_roster_digest() {
    let body = schema_body();
    assert_eq!(
        decode_message(&encode_message(&body).unwrap()).unwrap(),
        body
    );
    let expected = Value::Array(vec![
        uint(1),
        Value::Bytes(vec![7; 32]),
        Value::Bytes(vec![9; 32]),
        Value::Bytes(vec![8; 32]),
        uint(1),
        Value::Array(vec![uint(1), uint(2), uint(3)]),
        uint(1),
        Value::Null,
        Value::Array(vec![]),
        Value::Array(vec![Value::Bytes(vec![4, 5])]),
    ]);
    assert_eq!(encode_message(&body).unwrap(), encode(&expected).unwrap());
    let roster = schema_roster();
    assert_eq!(
        decode_roster(&encode_roster(&roster).unwrap()).unwrap(),
        roster
    );
    let expected = Value::Array(vec![
        uint(1),
        Value::Bytes(vec![9; 32]),
        Value::Array(
            (1..=3)
                .map(|id| {
                    Value::Array(vec![
                        uint(id),
                        Value::Bytes(vec![id as u8; 32]),
                        Value::Bytes(vec![id as u8 + 10; 32]),
                    ])
                })
                .collect(),
        ),
    ]);
    assert_eq!(encode_roster(&roster).unwrap(), encode(&expected).unwrap());
    let digest: [u8; 32] = [
        0xef, 0xcc, 0xae, 0x3e, 0x27, 0x32, 0xe1, 0x99, 0xa1, 0x08, 0xe7, 0x25, 0xb1, 0x46, 0xd9,
        0xdf, 0xf3, 0xfc, 0x33, 0xa1, 0xe8, 0xf0, 0x61, 0x19, 0x1e, 0xc3, 0x9a, 0x43, 0xc0, 0x6a,
        0xa1, 0xe8,
    ];
    assert_eq!(roster_digest(&roster).unwrap(), digest);
    assert_ne!(
        digest,
        [
            0xdf, 0x45, 0x1f, 0x48, 0xaa, 0xa8, 0x5f, 0x89, 0x32, 0x7b, 0x04, 0x2f, 0x36, 0xb2,
            0x00, 0x85, 0xe3, 0xa2, 0xd5, 0xc9, 0x21, 0x7f, 0xd7, 0x19, 0x23, 0x9c, 0x55, 0xce,
            0x0d, 0xf0, 0x50, 0x7a
        ]
    );
}

#[test]
fn message_schema_duplicate_audience() {
    let mut body = schema_body();
    body.audience = vec![1, 2, 2];
    assert_eq!(encode_message(&body), Err(WireError::Schema));
}

#[test]
fn message_schema_unsorted_audience() {
    let mut body = schema_body();
    body.audience = vec![2, 1, 3];
    assert_eq!(encode_message(&body), Err(WireError::Schema));
}

#[test]
fn message_schema_member0_sender() {
    let mut body = schema_body();
    body.key.sender = 0;
    assert_eq!(encode_message(&body), Err(WireError::Schema));
}

#[test]
fn message_schema_member0_roster() {
    let mut roster = schema_roster();
    roster.members[0].id = 0;
    assert_eq!(encode_roster(&roster).map(|_| ()), Err(WireError::Schema));
}

#[test]
fn message_schema_duplicate_roster() {
    let mut roster = schema_roster();
    roster.members[2].id = 2;
    assert_eq!(encode_roster(&roster).map(|_| ()), Err(WireError::Schema));
}

#[test]
fn message_schema_unsorted_roster() {
    let mut roster = schema_roster();
    roster.members.swap(0, 1);
    assert_eq!(encode_roster(&roster).map(|_| ()), Err(WireError::Schema));
}

#[test]
fn message_schema_roster_cardinality() {
    let mut roster = schema_roster();
    roster.members.pop();
    assert_eq!(encode_roster(&roster).map(|_| ()), Err(WireError::Schema));
}

#[test]
fn message_schema_member0_reference() {
    let mut body = schema_body();
    body.prerequisites = vec![schema_ref(0, 1)];
    assert_eq!(encode_message(&body).map(|_| ()), Err(WireError::Schema));
}

#[test]
fn message_schema_unsorted_references() {
    let mut body = schema_body();
    body.prerequisites = vec![schema_ref(2, 1), schema_ref(1, 1)];
    assert_eq!(encode_message(&body).map(|_| ()), Err(WireError::Schema));
}

#[test]
fn message_schema_duplicate_references() {
    let mut body = schema_body();
    body.prerequisites = vec![schema_ref(1, 1), schema_ref(1, 1)];
    assert_eq!(encode_message(&body).map(|_| ()), Err(WireError::Schema));
}

#[test]
fn message_schema_reference_limit() {
    let mut body = schema_body();
    body.prerequisites = (0..65).map(|n| schema_ref(1, n)).collect();
    assert_eq!(encode_message(&body).map(|_| ()), Err(WireError::Bounds));
}

#[test]
fn message_schema_received_prerequisite() {
    let mut body = schema_body();
    body.payload = Payload::Received(schema_ref(2, 1));
    assert_eq!(encode_message(&body).map(|_| ()), Err(WireError::Schema));
}

#[test]
fn message_schema_body_over16mib() {
    let mut body = schema_body();
    body.payload = Payload::Test(vec![0; 16 * 1024 * 1024 - 118]);
    let encoded = encode_message(&body).unwrap();
    assert_eq!(encoded.len(), 16 * 1024 * 1024);
    assert_eq!(decode_message(&encoded).unwrap(), body);
    body.payload = Payload::Test(vec![0; 16 * 1024 * 1024 - 100]);
    assert_eq!(encode_message(&body).map(|_| ()), Err(WireError::Bounds));
}

use loki_relay_protocol::types::decode_message;
fn schema_message_value() -> Vec<Value> {
    match decode(&encode_message(&schema_body()).unwrap(), MAX).unwrap() {
        Value::Array(fields) => fields,
        _ => unreachable!(),
    }
}
#[test]
fn message_schema_wrong_message_length() {
    let mut fields = schema_message_value();
    fields[1] = Value::Bytes(vec![7; 31]);
    assert_eq!(
        decode_message(&encode(&Value::Array(fields)).unwrap()),
        Err(WireError::Schema)
    );
}

#[test]
fn message_schema_unknown_type() {
    let mut fields = schema_message_value();
    fields[6] = uint(3);
    assert_eq!(
        decode_message(&encode(&Value::Array(fields)).unwrap()),
        Err(WireError::Schema)
    );
}

#[test]
fn message_schema_body_version() {
    let mut fields = schema_message_value();
    fields[0] = uint(2);
    assert_eq!(
        decode_message(&encode(&Value::Array(fields)).unwrap()),
        Err(WireError::Version)
    );
}

#[test]
fn message_schema_body_field_count() {
    let mut fields = schema_message_value();
    fields.push(Value::Null);
    assert_eq!(
        decode_message(&encode(&Value::Array(fields)).unwrap()),
        Err(WireError::Schema)
    );
}

#[test]
fn message_schema_payload_field_count() {
    let mut fields = schema_message_value();
    fields[9] = Value::Array(vec![Value::Bytes(vec![4, 5]), Value::Null]);
    assert_eq!(
        decode_message(&encode(&Value::Array(fields)).unwrap()),
        Err(WireError::Schema)
    );
}

#[test]
fn message_schema_reference_field_count() {
    let mut fields = schema_message_value();
    fields[8] = Value::Array(vec![Value::Array(vec![
        uint(1),
        Value::Bytes(vec![1; 32]),
        Value::Bytes(vec![6; 32]),
        Value::Null,
    ])]);
    assert_eq!(
        decode_message(&encode(&Value::Array(fields)).unwrap()),
        Err(WireError::Schema)
    );
}

use loki_relay_protocol::types::decode_roster;
fn schema_roster_value() -> Vec<Value> {
    match decode(&encode_roster(&schema_roster()).unwrap(), MAX).unwrap() {
        Value::Array(fields) => fields,
        _ => unreachable!(),
    }
}
#[test]
fn message_schema_wrong_signing_length() {
    let mut fields = schema_roster_value();
    if let Value::Array(members) = &mut fields[2] {
        if let Value::Array(member) = &mut members[0] {
            member[1] = Value::Bytes(vec![1; 31]);
        }
    }
    assert_eq!(
        decode_roster(&encode(&Value::Array(fields)).unwrap()),
        Err(WireError::Schema)
    );
}

#[test]
fn message_schema_roster_version() {
    let mut fields = schema_roster_value();
    fields[0] = uint(2);
    assert_eq!(
        decode_roster(&encode(&Value::Array(fields)).unwrap()),
        Err(WireError::Version)
    );
}

#[test]
fn message_schema_roster_field_count() {
    let mut fields = schema_roster_value();
    fields.push(Value::Null);
    assert_eq!(
        decode_roster(&encode(&Value::Array(fields)).unwrap()),
        Err(WireError::Schema)
    );
}

#[test]
fn message_schema_member_field_count() {
    let mut fields = schema_roster_value();
    if let Value::Array(members) = &mut fields[2] {
        if let Value::Array(member) = &mut members[0] {
            member.push(Value::Null);
        }
    }
    assert_eq!(
        decode_roster(&encode(&Value::Array(fields)).unwrap()),
        Err(WireError::Schema)
    );
}

#[test]
fn message_schema_valid_received_and_reference_order() {
    let mut body = schema_body();
    body.session = Some([5; 32]);
    let original = schema_ref(2, 1);
    body.prerequisites = vec![original.clone()];
    body.payload = Payload::Received(original);
    let encoded = encode_message(&body).unwrap();
    assert_eq!(decode_message(&encoded).unwrap(), body);
    let fields = match decode(&encoded, MAX).unwrap() {
        Value::Array(fields) => fields,
        _ => unreachable!(),
    };
    assert_eq!(fields[6], uint(2));
    assert_eq!(fields[7], Value::Bytes(vec![5; 32]));
    assert_eq!(fields[8], fields[9]);
    body.payload = Payload::Test(vec![]);
    body.prerequisites = (0..64).map(|n| schema_ref(1, n)).collect();
    assert_eq!(
        decode_message(&encode_message(&body).unwrap()).unwrap(),
        body
    );
    body.prerequisites = vec![schema_ref(1, 1), schema_ref(1, 2), schema_ref(2, 0)];
    let mut same_message = schema_ref(1, 1);
    same_message.digest = [7; 32];
    body.prerequisites.insert(1, same_message);
    assert_eq!(
        decode_message(&encode_message(&body).unwrap()).unwrap(),
        body
    );
}

use loki_relay_protocol::{
    http,
    types::{AppendUpdate, Creation, CreationResult, Entry, Page},
};
fn metadata_id(n: u8) -> Value {
    Value::Bytes(vec![n; 32])
}
fn metadata_bytes(fields: Vec<Value>) -> Vec<u8> {
    encode(&Value::Array(fields)).unwrap()
}
fn metadata_creation_fields() -> Vec<Value> {
    vec![
        uint(1),
        metadata_id(1),
        metadata_id(2),
        metadata_id(3),
        uint(4096),
    ]
}
fn metadata_page() -> Page {
    Page {
        mailbox: [3; 32],
        after: 0,
        next: 1,
        high_water: 1,
        entries: vec![Entry {
            sequence: 1,
            hash: [4; 32],
            wire_length: 1024,
            receipt: vec![0x80],
        }],
    }
}
#[test]
fn metadata_schema_http_golden() {
    let creation = Creation {
        read_verifier: [1; 32],
        append_verifier: [2; 32],
        admin_verifier: [3; 32],
        quota: 4096,
    };
    let mut golden = vec![0x85, 1];
    for n in 1..=3 {
        golden.extend([0x58, 32]);
        golden.extend([n; 32]);
    }
    golden.extend([0x19, 0x10, 0]);
    assert_eq!(http::encode_creation(&creation).unwrap(), golden);
    assert_eq!(http::decode_creation(&golden).unwrap(), creation);
    let update = AppendUpdate {
        revision: 2,
        verifier: [4; 32],
    };
    let mut golden = vec![0x83, 1, 2, 0x58, 32];
    golden.extend([4; 32]);
    assert_eq!(http::encode_append_update(&update).unwrap(), golden);
    assert_eq!(http::decode_append_update(&golden).unwrap(), update);
    let result = CreationResult {
        created: true,
        run: [2; 32],
        quota: 4096,
        append_revision: 1,
    };
    let mut golden = vec![0x85, 1, 0x58, 32];
    golden.extend([3; 32]);
    golden.extend([0x58, 32]);
    golden.extend([2; 32]);
    golden.extend([0x19, 0x10, 0, 1]);
    assert_eq!(
        http::encode_creation_result(&[3; 32], &result).unwrap(),
        golden
    );
    assert_eq!(
        http::decode_creation_result(&golden, true).unwrap(),
        ([3; 32], result.clone())
    );
    assert!(
        !http::decode_creation_result(&golden, false)
            .unwrap()
            .1
            .created
    );
    let mut golden = vec![0x83, 1, 0x58, 32];
    golden.extend([3; 32]);
    golden.push(2);
    assert_eq!(http::encode_append_result(&[3; 32], 2).unwrap(), golden);
    assert_eq!(http::decode_append_result(&golden).unwrap(), ([3; 32], 2));
    let mut golden = vec![0x86, 1, 0x58, 32];
    golden.extend([3; 32]);
    golden.extend([0, 1, 1, 0x81, 0x84, 1, 0x58, 32]);
    golden.extend([4; 32]);
    golden.extend([0x19, 4, 0, 0x41, 0x80]);
    assert_eq!(http::encode_page(&metadata_page()).unwrap(), golden);
    assert_eq!(http::decode_page(&golden).unwrap(), metadata_page());
}
macro_rules! metadata_error_row {
    ($name:ident,$code:expr,$status:expr) => {
        #[test]
        fn $name() {
            let error = http::ErrorCode::try_from($code as u64).unwrap();
            assert_eq!(error.status(), $status);
            assert_eq!(http::encode_error(error).unwrap(), vec![0x82, 1, $code]);
            assert_eq!(http::decode_error(&[0x82, 1, $code]).unwrap(), error);
        }
    };
}
metadata_error_row!(metadata_schema_error_1, 1, 400);
metadata_error_row!(metadata_schema_error_2, 2, 401);
metadata_error_row!(metadata_schema_error_3, 3, 404);
metadata_error_row!(metadata_schema_error_4, 4, 409);
metadata_error_row!(metadata_schema_error_5, 5, 409);
metadata_error_row!(metadata_schema_error_6, 6, 413);
metadata_error_row!(metadata_schema_error_7, 7, 415);
metadata_error_row!(metadata_schema_error_8, 8, 429);
metadata_error_row!(metadata_schema_error_9, 9, 503);
metadata_error_row!(metadata_schema_error_10, 10, 507);
#[test]
fn metadata_schema_http_field_counts() {
    let schemas: Vec<(Vec<Value>, fn(&[u8]) -> bool)> = vec![
        (metadata_creation_fields(), |b| {
            http::decode_creation(b).is_err()
        }),
        (vec![uint(1), uint(2), metadata_id(1)], |b| {
            http::decode_append_update(b).is_err()
        }),
        (
            vec![uint(1), metadata_id(1), metadata_id(2), uint(4096), uint(1)],
            |b| http::decode_creation_result(b, true).is_err(),
        ),
        (vec![uint(1), metadata_id(1), uint(2)], |b| {
            http::decode_append_result(b).is_err()
        }),
        (vec![uint(1), uint(1)], |b| http::decode_error(b).is_err()),
        (
            vec![
                uint(1),
                metadata_id(3),
                uint(0),
                uint(0),
                uint(0),
                Value::Array(vec![]),
            ],
            |b| http::decode_page(b).is_err(),
        ),
    ];
    for (fields, reject) in schemas {
        assert!(!reject(&metadata_bytes(fields.clone())));
        for extra in [false, true] {
            let mut f = fields.clone();
            if extra {
                f.push(Value::Null);
            } else {
                f.pop();
            }
            assert!(reject(&metadata_bytes(f)));
        }
    }
    let mut f = match decode(&http::encode_page(&metadata_page()).unwrap(), MAX).unwrap() {
        Value::Array(f) => f,
        _ => unreachable!(),
    };
    if let Value::Array(entries) = &mut f[5] {
        if let Value::Array(entry) = &mut entries[0] {
            entry.push(Value::Null);
        }
    }
    assert!(http::decode_page(&metadata_bytes(f)).is_err());
}
#[test]
fn metadata_schema_http_byte_lengths() {
    for field in 1..=3 {
        for n in [0, 31, 33] {
            let mut f = metadata_creation_fields();
            f[field] = Value::Bytes(vec![0; n]);
            assert!(http::decode_creation(&metadata_bytes(f)).is_err());
        }
    }
    for n in [0, 31, 33] {
        assert!(http::decode_append_update(&metadata_bytes(vec![
            uint(1),
            uint(2),
            Value::Bytes(vec![0; n])
        ]))
        .is_err());
        assert!(http::decode_append_result(&metadata_bytes(vec![
            uint(1),
            Value::Bytes(vec![0; n]),
            uint(2)
        ]))
        .is_err());
        for field in [1, 2] {
            let mut f = vec![uint(1), metadata_id(1), metadata_id(2), uint(4096), uint(1)];
            f[field] = Value::Bytes(vec![0; n]);
            assert!(http::decode_creation_result(&metadata_bytes(f), true).is_err());
        }
        for field in [1, 5] {
            let mut f = vec![
                uint(1),
                metadata_id(3),
                uint(0),
                uint(1),
                uint(1),
                Value::Array(vec![Value::Array(vec![
                    uint(1),
                    metadata_id(4),
                    uint(1024),
                    Value::Bytes(vec![0x80]),
                ])]),
            ];
            if field == 1 {
                f[1] = Value::Bytes(vec![0; n]);
            } else if let Value::Array(e) = &mut f[5] {
                if let Value::Array(entry) = &mut e[0] {
                    entry[1] = Value::Bytes(vec![0; n]);
                }
            }
            assert!(http::decode_page(&metadata_bytes(f)).is_err());
        }
    }
}
#[test]
fn metadata_schema_http_persisted_counters() {
    let max = i64::MAX as u64;
    let overflow = max + 1;
    let c = Creation {
        read_verifier: [1; 32],
        append_verifier: [2; 32],
        admin_verifier: [3; 32],
        quota: max,
    };
    assert_eq!(
        http::decode_creation(&http::encode_creation(&c).unwrap()).unwrap(),
        c
    );
    let mut c = c;
    c.quota = overflow;
    assert!(http::encode_creation(&c).is_err());
    let mut f = metadata_creation_fields();
    f[4] = uint(overflow);
    assert!(http::decode_creation(&metadata_bytes(f)).is_err());
    let u = AppendUpdate {
        revision: overflow,
        verifier: [1; 32],
    };
    assert!(http::encode_append_update(&u).is_err());
    assert!(http::decode_append_update(&metadata_bytes(vec![
        uint(1),
        uint(overflow),
        metadata_id(1)
    ]))
    .is_err());
    assert!(http::encode_append_result(&[1; 32], overflow).is_err());
    assert!(http::decode_append_result(&metadata_bytes(vec![
        uint(1),
        metadata_id(1),
        uint(overflow)
    ]))
    .is_err());
    for field in [3, 4] {
        let mut f = vec![uint(1), metadata_id(1), metadata_id(2), uint(4096), uint(1)];
        f[field] = uint(overflow);
        assert!(http::decode_creation_result(&metadata_bytes(f), true).is_err());
        let mut r = CreationResult {
            created: true,
            run: [2; 32],
            quota: 4096,
            append_revision: 1,
        };
        if field == 3 {
            r.quota = overflow;
        } else {
            r.append_revision = overflow;
        }
        assert!(http::encode_creation_result(&[1; 32], &r).is_err());
    }
    for field in [2, 3, 4] {
        let mut f = vec![
            uint(1),
            metadata_id(1),
            uint(0),
            uint(0),
            uint(0),
            Value::Array(vec![]),
        ];
        f[field] = uint(overflow);
        assert!(http::decode_page(&metadata_bytes(f)).is_err());
    }
    let p = Page {
        mailbox: [1; 32],
        after: max,
        next: max,
        high_water: max,
        entries: vec![],
    };
    assert_eq!(
        http::decode_page(&http::encode_page(&p).unwrap()).unwrap(),
        p
    );
    let mut p = p;
    p.after = overflow;
    p.next = overflow;
    p.high_water = overflow;
    assert!(http::encode_page(&p).is_err());
}
#[test]
fn metadata_schema_http_bounds_and_semantics() {
    assert!(http::decode_error(&[0x82, 1, 0]).is_err());
    assert!(http::decode_error(&[0x82, 1, 11]).is_err());
    assert_eq!(http::decode_error(&[0x82, 2, 1]), Err(WireError::Version));
    assert!(http::decode_error(&[0x82, 1, 0x18, 1]).is_err());
    assert_eq!(http::validate_limit(None).unwrap(), 100);
    for n in [1, 100] {
        assert_eq!(http::validate_limit(Some(n)).unwrap(), n);
    }
    for n in [0, 101, u64::MAX] {
        assert!(http::validate_limit(Some(n)).is_err());
    }
    let mut p = metadata_page();
    p.entries[0].receipt = vec![0; 128 * 1024];
    assert_eq!(http::encode_page(&p), Err(WireError::Bounds));
    assert_eq!(
        http::decode_page(&vec![0; 128 * 1024 + 1]),
        Err(WireError::Bounds)
    );
    let mut p = metadata_page();
    p.next = 0;
    assert!(http::encode_page(&p).is_err());
    p = metadata_page();
    p.entries[0].sequence = 2;
    p.high_water = 2;
    p.next = 2;
    assert!(http::encode_page(&p).is_err());
    p = metadata_page();
    p.entries.clear();
    p.next = p.after;
    assert_eq!(
        http::decode_page(&http::encode_page(&p).unwrap()).unwrap(),
        p
    );
    p.high_water = 0;
    p.after = 1;
    p.next = 1;
    assert!(http::encode_page(&p).is_err());
    p = metadata_page();
    p.entries = vec![p.entries[0].clone(); 101];
    assert!(http::encode_page(&p).is_err());
}

#[test]
fn metadata_schema_page_invalid_wire_for_quarantine() {
    let mut expected = metadata_page();
    expected.entries[0].wire_length = 1025;
    let entry = vec![
        uint(1),
        metadata_id(4),
        uint(1025),
        Value::Bytes(vec![0x80]),
    ];
    let fields = vec![
        uint(1),
        metadata_id(3),
        uint(0),
        uint(1),
        uint(1),
        Value::Array(vec![Value::Array(entry.clone())]),
    ];
    let encoded = metadata_bytes(fields.clone());
    assert_eq!(http::decode_page(&encoded), Ok(expected.clone()));
    assert_eq!(http::encode_page(&expected), Err(WireError::Bounds));

    for length in [0, 65537, i64::MAX as u64] {
        let mut invalid_entry = entry.clone();
        invalid_entry[2] = uint(length);
        let mut f = fields.clone();
        f[5] = Value::Array(vec![Value::Array(invalid_entry)]);
        expected.entries[0].wire_length = length;
        assert_eq!(http::decode_page(&metadata_bytes(f)), Ok(expected.clone()));
        assert_eq!(http::encode_page(&expected), Err(WireError::Bounds));
    }
    for invalid_entry in [
        vec![uint(1), metadata_id(4), uint(1025)],
        vec![
            uint(1),
            Value::Bytes(vec![4; 31]),
            uint(1025),
            Value::Bytes(vec![0x80]),
        ],
        vec![
            uint(2),
            metadata_id(4),
            uint(1025),
            Value::Bytes(vec![0x80]),
        ],
        vec![
            uint(1),
            metadata_id(4),
            uint(i64::MAX as u64 + 1),
            Value::Bytes(vec![0x80]),
        ],
    ] {
        let mut f = fields.clone();
        f[5] = Value::Array(vec![Value::Array(invalid_entry)]);
        assert!(http::decode_page(&metadata_bytes(f)).is_err());
    }
}

#[test]
fn metadata_schema_zero_quota_golden() {
    let mut creation = Creation {
        read_verifier: [1; 32],
        append_verifier: [2; 32],
        admin_verifier: [3; 32],
        quota: 0,
    };
    let mut golden = vec![0x85, 1];
    for n in 1..=3 {
        golden.extend([0x58, 32]);
        golden.extend([n; 32]);
    }
    golden.push(0);
    assert_eq!(http::encode_creation(&creation), Ok(golden.clone()));
    assert_eq!(http::decode_creation(&golden), Ok(creation.clone()));
    let mut result = CreationResult {
        created: true,
        run: [2; 32],
        quota: 0,
        append_revision: 1,
    };
    let mut golden_result = vec![0x85, 1, 0x58, 32];
    golden_result.extend([3; 32]);
    golden_result.extend([0x58, 32]);
    golden_result.extend([2; 32]);
    golden_result.extend([0, 1]);
    assert_eq!(
        http::encode_creation_result(&[3; 32], &result),
        Ok(golden_result.clone())
    );
    assert_eq!(
        http::decode_creation_result(&golden_result, true),
        Ok(([3; 32], result.clone()))
    );
    result.created = false;
    assert_eq!(
        http::decode_creation_result(&golden_result, false),
        Ok(([3; 32], result.clone()))
    );

    creation.quota = i64::MAX as u64;
    assert_eq!(
        http::decode_creation(&http::encode_creation(&creation).unwrap()),
        Ok(creation.clone())
    );
    result.quota = i64::MAX as u64;
    assert_eq!(
        http::decode_creation_result(
            &http::encode_creation_result(&[3; 32], &result).unwrap(),
            false
        ),
        Ok(([3; 32], result.clone()))
    );
    creation.quota += 1;
    result.quota += 1;
    assert_eq!(http::encode_creation(&creation), Err(WireError::Bounds));
    assert_eq!(
        http::encode_creation_result(&[3; 32], &result),
        Err(WireError::Bounds)
    );
    let mut fields = metadata_creation_fields();
    fields[4] = uint(creation.quota);
    assert_eq!(
        http::decode_creation(&metadata_bytes(fields)),
        Err(WireError::Bounds)
    );
    assert_eq!(
        http::decode_creation_result(
            &metadata_bytes(vec![
                uint(1),
                metadata_id(3),
                metadata_id(2),
                uint(result.quota),
                uint(1)
            ]),
            false
        ),
        Err(WireError::Bounds)
    );

    result.quota = 0;
    result.append_revision = 0;
    assert_eq!(
        http::encode_creation_result(&[3; 32], &result),
        Err(WireError::Schema)
    );
    *golden_result.last_mut().unwrap() = 0;
    assert_eq!(
        http::decode_creation_result(&golden_result, false),
        Err(WireError::Schema)
    );
    assert_eq!(
        http::encode_append_update(&AppendUpdate {
            revision: 0,
            verifier: [4; 32]
        }),
        Err(WireError::Schema)
    );
    assert_eq!(
        http::decode_append_update(&metadata_bytes(vec![uint(1), uint(0), metadata_id(4)])),
        Err(WireError::Schema)
    );
    assert_eq!(
        http::encode_append_result(&[3; 32], 0),
        Err(WireError::Schema)
    );
    assert_eq!(
        http::decode_append_result(&metadata_bytes(vec![uint(1), metadata_id(3), uint(0)])),
        Err(WireError::Schema)
    );
}

#[test]
fn canonical_setup_text_is_bounded_and_preserves_utf8() {
    assert_eq!(
        encode(&Value::Text("regtest".into())).unwrap(),
        b"\x67regtest"
    );
    assert_eq!(
        decode(b"\x67regtest", 8).unwrap(),
        Value::Text("regtest".into())
    );
    assert!(decode(b"\x61\xff", 2).is_err());
    assert!(decode(b"\x78\x07regtest", 9).is_err());
    assert!(decode(b"\x67regtest", 7).is_err());
}
