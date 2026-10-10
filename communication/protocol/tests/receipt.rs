use loki_relay_protocol::{
    canonical::{encode, Value},
    receipt,
    types::{ReceiptBody, RelayPin},
    WireError,
};

fn body() -> ReceiptBody {
    ReceiptBody {
        pin: RelayPin {
            key: [1; 32],
            run: [2; 32],
        },
        mailbox: [3; 32],
        hash: [4; 32],
        wire_length: 1024,
        sequence: 1,
        retention: 1,
    }
}
fn fields() -> Vec<Value> {
    vec![
        Value::Integer(1.into()),
        Value::Bytes(vec![1; 32]),
        Value::Bytes(vec![2; 32]),
        Value::Bytes(vec![3; 32]),
        Value::Bytes(vec![4; 32]),
        Value::Integer(1024.into()),
        Value::Integer(1.into()),
        Value::Integer(1.into()),
    ]
}
#[test]
fn metadata_schema_receipt_golden() {
    let mut golden = vec![0x88, 1];
    for n in 1..=4 {
        golden.extend([0x58, 32]);
        golden.extend([n; 32]);
    }
    golden.extend([0x19, 4, 0, 1, 1]);
    assert_eq!(receipt::encode_body(&body()).unwrap(), golden);
    assert_eq!(receipt::decode_body(&golden).unwrap(), body());
}
#[test]
fn metadata_schema_receipt_field_counts() {
    for extra in [false, true] {
        let mut f = fields();
        if extra {
            f.push(Value::Null);
        } else {
            f.pop();
        }
        assert_eq!(
            receipt::decode_body(&encode(&Value::Array(f)).unwrap()),
            Err(WireError::Schema)
        );
    }
}
#[test]
fn metadata_schema_receipt_byte_lengths() {
    for field in 1..=4 {
        for length in [0, 31, 33] {
            let mut f = fields();
            f[field] = Value::Bytes(vec![0; length]);
            assert_eq!(
                receipt::decode_body(&encode(&Value::Array(f)).unwrap()),
                Err(WireError::Schema)
            );
        }
    }
}
#[test]
fn metadata_schema_receipt_persisted_counter() {
    let mut b = body();
    b.sequence = i64::MAX as u64;
    assert_eq!(
        receipt::decode_body(&receipt::encode_body(&b).unwrap()).unwrap(),
        b
    );
    b.sequence += 1;
    assert_eq!(receipt::encode_body(&b), Err(WireError::Bounds));
    let mut f = fields();
    f[6] = Value::Integer(b.sequence.into());
    assert_eq!(
        receipt::decode_body(&encode(&Value::Array(f)).unwrap()),
        Err(WireError::Bounds)
    );
}
#[test]
fn metadata_schema_receipt_semantics() {
    for n in [0, 1, 1023, 1025, 65537] {
        let mut b = body();
        b.wire_length = n;
        assert!(receipt::encode_body(&b).is_err());
    }
    for n in [1024, 65536] {
        let mut b = body();
        b.wire_length = n;
        assert_eq!(
            receipt::decode_body(&receipt::encode_body(&b).unwrap()).unwrap(),
            b
        );
    }
    let mut b = body();
    b.sequence = 0;
    assert!(receipt::encode_body(&b).is_err());
    b = body();
    b.retention = 2;
    assert!(receipt::encode_body(&b).is_err());
    let mut f = fields();
    f[0] = Value::Integer(2.into());
    assert_eq!(
        receipt::decode_body(&encode(&Value::Array(f)).unwrap()),
        Err(WireError::Version)
    );
}
