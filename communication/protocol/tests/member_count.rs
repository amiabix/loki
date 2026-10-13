use loki_relay_protocol::types::{
    decode_message, encode_message, encode_roster, roster_digest, LogicalKey, MemberPublic,
    MessageBody, Payload, Roster,
};

fn roster(n: u16) -> Roster {
    Roster {
        vault: [70; 32],
        members: (1..=n)
            .map(|id| MemberPublic {
                id,
                signing: [id as u8 + 10; 32],
                encryption: [id as u8 + 20; 32],
            })
            .collect(),
    }
}

#[test]
fn existing_three_member_canonical_bytes_and_digest_are_unchanged() {
    let roster = roster(3);
    assert_eq!(
        encode_roster(&roster).unwrap(),
        include_bytes!("fixtures/roster3.cbor")
    );
    assert_eq!(roster_digest(&roster).unwrap(), ROSTER3_DIGEST);
    let body = MessageBody {
        key: LogicalKey {
            vault: roster.vault,
            roster: ROSTER3_DIGEST,
            sender: 1,
            message: [80; 32],
        },
        audience: vec![1, 2, 3],
        session: None,
        prerequisites: vec![],
        payload: Payload::Test(b"fixture".to_vec()),
    };
    assert_eq!(
        encode_message(&body).unwrap(),
        include_bytes!("fixtures/message3.cbor")
    );
    assert_eq!(
        decode_message(include_bytes!("fixtures/message3.cbor")).unwrap(),
        body
    );
}

#[test]
fn four_member_roster_and_audience_roundtrip() {
    let roster = roster(4);
    assert_eq!(
        encode_roster(&roster).unwrap(),
        include_bytes!("fixtures/roster4.cbor")
    );
    assert_eq!(roster_digest(&roster).unwrap(), ROSTER4_DIGEST);
    let body = MessageBody {
        key: LogicalKey {
            vault: roster.vault,
            roster: ROSTER4_DIGEST,
            sender: 4,
            message: [80; 32],
        },
        audience: vec![1, 2, 3, 4],
        session: None,
        prerequisites: vec![],
        payload: Payload::Test(b"fixture".to_vec()),
    };
    assert_eq!(
        decode_message(&encode_message(&body).unwrap()).unwrap(),
        body
    );
}

#[test]
fn roster_rejects_gaps_extra_slots_and_duplicate_keys() {
    for n in [0, 1, 2, 5] {
        assert!(encode_roster(&roster(n)).is_err());
    }
    for case in 0..5 {
        let mut value = roster(4);
        match case {
            0 => value.members[3].id = 5,
            1 => value.members[2].id = 2,
            2 => value.members.swap(1, 2),
            3 => value.members[3].signing = value.members[0].signing,
            4 => value.members[3].encryption = value.members[0].encryption,
            _ => unreachable!(),
        }
        assert!(encode_roster(&value).is_err(), "case {case}");
    }
    let mut value = roster(3);
    value.members[2].signing = value.members[0].signing;
    assert!(encode_roster(&value).is_err());
}

const ROSTER3_DIGEST: [u8; 32] = [
    169, 96, 76, 103, 123, 188, 216, 243, 8, 177, 63, 165, 167, 36, 202, 11, 245, 127, 217, 248, 3,
    33, 41, 174, 131, 208, 24, 247, 218, 82, 131, 176,
];

const ROSTER4_DIGEST: [u8; 32] = [
    152, 29, 71, 76, 73, 35, 223, 33, 5, 19, 25, 86, 120, 233, 214, 113, 211, 6, 73, 44, 201, 6, 3,
    219, 184, 237, 1, 50, 229, 113, 219, 226,
];
