use ed25519_dalek::{Signature, VerifyingKey};
use loki_relay_client::{
    authenticate, open_record, prepare_outbox, CommIdentity, SealContext, SealDomain,
};
use loki_relay_protocol::{
    canonical::{self, Value},
    types::{self, LogicalKey, MessageBody, Payload, Roster},
};
use sha2::{Digest, Sha256};

fn array(value: &Value) -> &[Value] {
    let Value::Array(items) = value else { panic!() };
    items
}
fn bytes(value: &Value) -> &[u8] {
    let Value::Bytes(data) = value else { panic!() };
    data
}
fn number(value: &Value) -> usize {
    let Value::Integer(n) = value else { panic!() };
    usize::try_from(*n).unwrap()
}

fn check_chunks(roster: &Roster, body: &MessageBody, prepared: &loki_relay_client::PreparedOutbox) {
    let mut packages = Vec::new();
    let mut transfers = Vec::new();
    for recipient in prepared.recipients() {
        let ctx = context(roster, recipient.recipient());
        let owner = identity(recipient.recipient());
        let objects = recipient.objects();
        let root = objects.last().unwrap();
        assert_eq!(recipient.root_hash(), &root.hash);
        let record = open_record(&ctx, &owner, &root.wire).unwrap();
        let inner = canonical::decode(&record, 65536).unwrap();
        let fields = array(&inner);
        assert_eq!(fields.len(), 3);
        assert_eq!(number(&fields[0]), 2);
        let manifest_bytes = bytes(&fields[1]);
        let mut input = b"Loki_Relay_Manifest_v1\0".to_vec();
        input.extend_from_slice(&(manifest_bytes.len() as u32).to_be_bytes());
        input.extend_from_slice(manifest_bytes);
        VerifyingKey::from_bytes(&roster.members[0].signing)
            .unwrap()
            .verify_strict(&input, &Signature::from_slice(bytes(&fields[2])).unwrap())
            .unwrap();
        let manifest = canonical::decode(manifest_bytes, 65536).unwrap();
        let fields = array(&manifest);
        assert_eq!(fields.len(), 11);
        assert_eq!(number(&fields[0]), 1);
        assert_eq!(bytes(&fields[1]), body.key.vault);
        assert_eq!(bytes(&fields[2]), body.key.roster);
        assert_eq!(number(&fields[3]), body.key.sender as usize);
        assert_eq!(number(&fields[4]), recipient.recipient() as usize);
        assert_eq!(bytes(&fields[5]), recipient.transfer().unwrap());
        assert_eq!(bytes(&fields[6]), body.key.message);
        assert_eq!(bytes(&fields[7]), prepared.digest());
        let entries = array(&fields[10]);
        assert_eq!(objects.len(), entries.len() + 1);
        assert!((1..=274).contains(&entries.len()));
        let mut package = Vec::new();
        for (index, (object, entry)) in objects[..objects.len() - 1].iter().zip(entries).enumerate()
        {
            assert_eq!(object.hash, <[u8; 32]>::from(Sha256::digest(&object.wire)));
            assert!((1024..=65536).contains(&object.wire.len()));
            assert_eq!(object.wire.len() % 1024, 0);
            let entry = array(entry);
            assert_eq!(bytes(&entry[0]), object.hash);
            assert_eq!(number(&entry[1]), object.wire.len());
            let record = open_record(&ctx, &owner, &object.wire).unwrap();
            let chunk = canonical::decode(&record, 65536).unwrap();
            let chunk = array(&chunk);
            assert_eq!(chunk.len(), 4);
            assert_eq!(number(&chunk[0]), 3);
            assert_eq!(bytes(&chunk[1]), recipient.transfer().unwrap());
            assert_eq!(number(&chunk[2]), index);
            let segment = bytes(&chunk[3]);
            assert_eq!(number(&entry[2]), segment.len());
            if index + 1 < entries.len() {
                assert_eq!(segment.len(), 61440);
            } else {
                assert!((1..=61440).contains(&segment.len()));
            }
            package.extend_from_slice(segment);
        }
        assert_eq!(number(&fields[9]), package.len());
        assert_eq!(
            bytes(&fields[8]),
            <[u8; 32]>::from(Sha256::digest(&package))
        );
        let authenticated = authenticate(roster, &package).unwrap();
        assert_eq!(authenticated.body(), body);
        assert_eq!(authenticated.digest(), prepared.digest());
        transfers.push(*recipient.transfer().unwrap());
        packages.push(package);
    }
    assert!(packages.windows(2).all(|p| p[0] == p[1]));
    for i in 0..3 {
        for j in 0..i {
            assert_ne!(transfers[i], transfers[j]);
            assert_ne!(
                prepared.recipients()[i].root_hash(),
                prepared.recipients()[j].root_hash()
            );
        }
    }
}

#[test]
fn recipient_set_single_boundary() {
    for (size, count) in [(65284, 1), (65285, 3)] {
        let (roster, body) = fixture(size);
        let prepared = prepare_outbox(&identity(1), &roster, &body).unwrap();
        assert!(prepared
            .recipients()
            .iter()
            .all(|r| r.objects().len() == count));
        if count == 1 {
            assert!(prepared
                .recipients()
                .iter()
                .all(|r| r.objects()[0].wire.len() == 65536));
        } else {
            check_chunks(&roster, &body, &prepared);
        }
    }
}

#[test]
fn recipient_set_manifest() {
    let (roster, body) = fixture(150000);
    let prepared = prepare_outbox(&identity(1), &roster, &body).unwrap();
    check_chunks(&roster, &body, &prepared);
    let retry = prepare_outbox(&identity(1), &roster, &body).unwrap();
    for (saved, fresh) in prepared.recipients().iter().zip(retry.recipients()) {
        assert_ne!(saved.transfer(), fresh.transfer());
        assert_ne!(saved.root_hash(), fresh.root_hash());
        let saved_copy = saved.objects().to_vec();
        assert_eq!(saved_copy.as_slice(), saved.objects());
    }
}

#[test]
fn recipient_set_sender_binding() {
    let (roster, body) = fixture(3);
    let mut impostor = [8; 66];
    impostor[..2].copy_from_slice(&1u16.to_be_bytes());
    assert!(prepare_outbox(
        &CommIdentity::from_serialized(&impostor).unwrap(),
        &roster,
        &body
    )
    .is_err());
    for changed in 0..4 {
        let mut invalid = body.clone();
        match changed {
            0 => invalid.key.vault[0] ^= 1,
            1 => invalid.key.roster[0] ^= 1,
            2 => invalid.key.sender = 2,
            _ => {
                invalid.audience.pop();
            }
        }
        assert!(prepare_outbox(&identity(1), &roster, &invalid).is_err());
    }
    let mut mismatched = roster.clone();
    mismatched.members[0].encryption = identity(4).public().encryption;
    let mut scoped = body.clone();
    scoped.key.roster = types::roster_digest(&mismatched).unwrap();
    assert!(prepare_outbox(&identity(1), &mismatched, &scoped).is_err());
}

#[test]
fn recipient_set_body_limit() {
    let (roster, mut body) = fixture(0);
    let overhead = types::encode_message(&body).unwrap().len() + 4;
    body.payload = Payload::Test(vec![0; 16 * 1024 * 1024 - overhead]);
    assert_eq!(
        types::encode_message(&body).unwrap().len(),
        16 * 1024 * 1024
    );
    let prepared = prepare_outbox(&identity(1), &roster, &body).unwrap();
    assert!(prepared
        .recipients()
        .iter()
        .all(|r| r.objects().len() == 275));
    check_chunks(&roster, &body, &prepared);
    if let Payload::Test(data) = &mut body.payload {
        data.push(0);
    }
    assert!(prepare_outbox(&identity(1), &roster, &body).is_err());
}

fn identity(id: u16) -> CommIdentity {
    let mut bytes = [0u8; 66];
    bytes[..2].copy_from_slice(&id.to_be_bytes());
    bytes[2..34].fill(id as u8);
    bytes[34..].fill((id + 3) as u8);
    CommIdentity::from_serialized(&bytes).unwrap()
}

fn fixture(size: usize) -> (Roster, MessageBody) {
    let roster = Roster {
        vault: [7; 32],
        members: (1..=3).map(|id| identity(id).public()).collect(),
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
        payload: Payload::Test(vec![10; size]),
    };
    (roster, body)
}

fn context(roster: &Roster, id: u16) -> SealContext {
    SealContext {
        vault: roster.vault,
        roster: types::roster_digest(roster).unwrap(),
        recipient: roster.members[(id - 1) as usize].clone(),
        domain: SealDomain::Message,
    }
}

#[test]
fn recipient_set() {
    let (roster, body) = fixture(3);
    let prepared = prepare_outbox(&identity(1), &roster, &body).unwrap();
    assert_eq!(prepared.key(), &body.key);
    assert_eq!(
        prepared
            .recipients()
            .iter()
            .map(|r| r.recipient())
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
    let mut packages = Vec::new();
    for recipient in prepared.recipients() {
        assert_eq!(recipient.transfer(), None);
        assert_eq!(recipient.objects().len(), 1);
        let object = &recipient.objects()[0];
        assert_eq!(recipient.root_hash(), &object.hash);
        assert_eq!(object.hash, <[u8; 32]>::from(Sha256::digest(&object.wire)));
        let record = open_record(
            &context(&roster, recipient.recipient()),
            &identity(recipient.recipient()),
            &object.wire,
        )
        .unwrap();
        let Value::Array(fields) = canonical::decode(&record, 65536).unwrap() else {
            panic!()
        };
        assert_eq!(fields[0], Value::Integer(1.into()));
        let Value::Bytes(package) = &fields[1] else {
            panic!()
        };
        let authenticated = authenticate(&roster, package).unwrap();
        assert_eq!(authenticated.body(), &body);
        assert_eq!(authenticated.digest(), prepared.digest());
        packages.push(package.clone());
    }
    assert!(packages.windows(2).all(|p| p[0] == p[1]));
    for i in 0..3 {
        for j in 0..i {
            assert_ne!(
                prepared.recipients()[i].root_hash(),
                prepared.recipients()[j].root_hash()
            );
        }
    }
}

#[test]
fn transfer_complete_single() {
    let (roster, body) = fixture(3);
    let prepared = prepare_outbox(&identity(1), &roster, &body).unwrap();
    for recipient in prepared.recipients() {
        let root = &recipient.objects()[0];
        let opened = loki_relay_client::TransferAssembler::open(
            &roster,
            &identity(recipient.recipient()),
            root,
            &Default::default(),
        )
        .unwrap();
        assert_eq!(opened.message().body(), &body);
        assert_eq!(opened.source().key(), &body.key);
        assert_eq!(opened.source().digest(), prepared.digest());
        assert_eq!(opened.source().recipient(), recipient.recipient());
        assert_eq!(opened.source().required_hashes(), &[root.hash]);
    }
}

use ed25519_dalek::{Signer, SigningKey};
use loki_relay_client::{seal_record, ClientError, TransferAssembler};
use loki_relay_protocol::types::{Id32, Object};
use std::collections::BTreeMap;

struct AssemblyFixture {
    roster: Roster,
    body: MessageBody,
    root: Object,
    objects: BTreeMap<Id32, Object>,
    manifest: Vec<Value>,
}
impl AssemblyFixture {
    fn new() -> Self {
        let (roster, body) = fixture(150000);
        let prepared = prepare_outbox(&identity(1), &roster, &body).unwrap();
        let recipient = &prepared.recipients()[1];
        let root = recipient.objects().last().unwrap().clone();
        let raw = open_record(&context(&roster, 2), &identity(2), &root.wire).unwrap();
        let inner = canonical::decode(&raw, 65536).unwrap();
        let manifest = array(&canonical::decode(bytes(&array(&inner)[1]), 65536).unwrap()).to_vec();
        let objects = recipient.objects()[..recipient.objects().len() - 1]
            .iter()
            .map(|o| (o.hash, o.clone()))
            .collect();
        Self {
            roster,
            body,
            root,
            objects,
            manifest,
        }
    }
    fn resign(&mut self) {
        let encoded = canonical::encode(&Value::Array(self.manifest.clone())).unwrap();
        let mut input = b"Loki_Relay_Manifest_v1\0".to_vec();
        input.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
        input.extend_from_slice(&encoded);
        let signature = SigningKey::from_bytes(&[1; 32]).sign(&input);
        let raw = canonical::encode(&Value::Array(vec![
            Value::Integer(2.into()),
            Value::Bytes(encoded),
            Value::Bytes(signature.to_bytes().to_vec()),
        ]))
        .unwrap();
        self.root = seal_record(&context(&self.roster, 2), &raw).unwrap();
    }
    fn change_chunk(&mut self, field: usize, value: Value) {
        let Value::Array(entries) = &mut self.manifest[10] else {
            panic!()
        };
        let Value::Array(entry) = &mut entries[0] else {
            panic!()
        };
        let hash: Id32 = bytes(&entry[0]).try_into().unwrap();
        let old = self.objects.remove(&hash).unwrap();
        let raw = open_record(&context(&self.roster, 2), &identity(2), &old.wire).unwrap();
        let mut chunk = array(&canonical::decode(&raw, 65536).unwrap()).to_vec();
        chunk[field] = value;
        let new = seal_record(
            &context(&self.roster, 2),
            &canonical::encode(&Value::Array(chunk)).unwrap(),
        )
        .unwrap();
        entry[0] = Value::Bytes(new.hash.to_vec());
        entry[1] = Value::Integer((new.wire.len() as u64).into());
        self.objects.insert(new.hash, new);
        self.resign();
    }
    fn open(&self) -> Result<loki_relay_client::AuthenticatedTransfer, ClientError> {
        TransferAssembler::open(&self.roster, &identity(2), &self.root, &self.objects)
    }
}

#[test]
fn transfer_complete_missing_restore() {
    let mut f = AssemblyFixture::new();
    let hash: Id32 = bytes(&array(&array(&f.manifest[10])[1])[0])
        .try_into()
        .unwrap();
    let original = f.objects.remove(&hash).unwrap();
    assert!(matches!(f.open(), Err(ClientError::MissingObjects(h)) if h == vec![hash]));
    f.objects.insert(hash, original);
    let extra = seal_record(&context(&f.roster, 2), &[0x81, 0]).unwrap();
    f.objects.insert(extra.hash, extra.clone());
    let opened = f.open().unwrap();
    assert_eq!(opened.message().body(), &f.body);
    assert_eq!(opened.source().digest(), opened.message().digest());
    assert_eq!(opened.source().key(), &f.body.key);
    assert_eq!(opened.source().recipient(), 2);
    let expected: Vec<Id32> = std::iter::once(f.root.hash)
        .chain(
            array(&f.manifest[10])
                .iter()
                .map(|e| bytes(&array(e)[0]).try_into().unwrap()),
        )
        .collect();
    assert_eq!(opened.source().required_hashes(), expected);
    assert!(!opened.source().required_hashes().contains(&extra.hash));
}

macro_rules! manifest_fault {
    ($name:ident, $field:expr, $value:expr, $error:pat) => {
        #[test]
        fn $name() {
            let mut f = AssemblyFixture::new();
            f.manifest[$field] = $value;
            f.resign();
            assert!(matches!(f.open(), Err($error)));
        }
    };
}
manifest_fault!(
    transfer_complete_recipient,
    4,
    Value::Integer(3.into()),
    ClientError::Identity
);
manifest_fault!(
    transfer_complete_sender,
    3,
    Value::Integer(2.into()),
    ClientError::Crypto
);
manifest_fault!(
    transfer_complete_message,
    6,
    Value::Bytes(vec![8; 32]),
    ClientError::Identity
);
manifest_fault!(
    transfer_complete_digest,
    7,
    Value::Bytes(vec![8; 32]),
    ClientError::Identity
);
manifest_fault!(
    transfer_complete_package_hash,
    8,
    Value::Bytes(vec![8; 32]),
    ClientError::Wire(loki_relay_protocol::WireError::Schema)
);
manifest_fault!(
    transfer_complete_total,
    9,
    Value::Integer(1.into()),
    ClientError::Wire(loki_relay_protocol::WireError::Bounds)
);
manifest_fault!(
    transfer_complete_total_bound,
    9,
    Value::Integer(16_777_345u64.into()),
    ClientError::Wire(loki_relay_protocol::WireError::Bounds)
);
manifest_fault!(
    transfer_complete_version,
    0,
    Value::Integer(2.into()),
    ClientError::Identity
);
manifest_fault!(
    transfer_complete_vault,
    1,
    Value::Bytes(vec![8; 32]),
    ClientError::Identity
);
manifest_fault!(
    transfer_complete_roster,
    2,
    Value::Bytes(vec![8; 32]),
    ClientError::Identity
);
manifest_fault!(
    transfer_complete_empty_entries,
    10,
    Value::Array(vec![]),
    ClientError::Wire(loki_relay_protocol::WireError::Bounds)
);

#[test]
fn transfer_complete_index() {
    let mut f = AssemblyFixture::new();
    f.change_chunk(2, Value::Integer(1.into()));
    assert!(matches!(
        f.open(),
        Err(ClientError::Wire(loki_relay_protocol::WireError::Schema))
    ));
}
#[test]
fn transfer_complete_transfer() {
    let mut f = AssemblyFixture::new();
    f.change_chunk(1, Value::Bytes(vec![8; 32]));
    assert!(matches!(
        f.open(),
        Err(ClientError::Wire(loki_relay_protocol::WireError::Schema))
    ));
}
#[test]
fn transfer_complete_segment() {
    let mut f = AssemblyFixture::new();
    f.change_chunk(3, Value::Bytes(vec![8; 61439]));
    assert!(matches!(
        f.open(),
        Err(ClientError::Wire(loki_relay_protocol::WireError::Schema))
    ));
}
#[test]
fn transfer_complete_altered_chunk() {
    let mut f = AssemblyFixture::new();
    f.objects.values_mut().next().unwrap().wire[100] ^= 1;
    assert!(matches!(f.open(), Err(ClientError::Wire(_))));
}
#[test]
fn transfer_complete_object_hash() {
    let mut f = AssemblyFixture::new();
    f.objects.values_mut().next().unwrap().hash = [8; 32];
    assert!(f.open().is_err());
}
#[test]
fn transfer_complete_root_hash() {
    let mut f = AssemblyFixture::new();
    f.root.hash = [8; 32];
    assert!(f.open().is_err());
}
#[test]
fn transfer_complete_duplicate() {
    let mut f = AssemblyFixture::new();
    let Value::Array(entries) = &mut f.manifest[10] else {
        panic!()
    };
    entries[1] = entries[0].clone();
    f.resign();
    assert!(f.open().is_err());
}
#[test]
fn transfer_complete_stale_root_reference() {
    let mut f = AssemblyFixture::new();
    let Value::Array(entries) = &mut f.manifest[10] else {
        panic!()
    };
    let Value::Array(entry) = &mut entries[0] else {
        panic!()
    };
    entry[0] = Value::Bytes(f.root.hash.to_vec());
    f.resign();
    assert!(matches!(f.open(), Err(ClientError::MissingObjects(_))));
}
#[test]
fn transfer_complete_wire_length() {
    let mut f = AssemblyFixture::new();
    let Value::Array(entries) = &mut f.manifest[10] else {
        panic!()
    };
    let Value::Array(entry) = &mut entries[0] else {
        panic!()
    };
    entry[1] = Value::Integer(1024.into());
    f.resign();
    assert!(matches!(
        f.open(),
        Err(ClientError::Wire(loki_relay_protocol::WireError::Bounds))
    ));
}
#[test]
fn transfer_complete_segmentation() {
    let mut f = AssemblyFixture::new();
    let Value::Array(entries) = &mut f.manifest[10] else {
        panic!()
    };
    let Value::Array(entry) = &mut entries[0] else {
        panic!()
    };
    entry[2] = Value::Integer(61439.into());
    f.resign();
    assert!(f.open().is_err());
}
#[test]
fn transfer_complete_canonical_package() {
    let (roster, body) = fixture(3);
    let package = loki_relay_client::sign_message(&identity(1), &roster, &body).unwrap();
    let mut invalid = vec![0x98, 0x02];
    invalid.extend_from_slice(&package[1..]);
    let raw = canonical::encode(&Value::Array(vec![
        Value::Integer(1.into()),
        Value::Bytes(invalid),
    ]))
    .unwrap();
    let root = seal_record(&context(&roster, 2), &raw).unwrap();
    assert!(matches!(
        TransferAssembler::open(&roster, &identity(2), &root, &BTreeMap::new()),
        Err(ClientError::Wire(loki_relay_protocol::WireError::Canonical))
    ));
}
#[test]
fn transfer_complete_maximum274() {
    let (roster, mut body) = fixture(0);
    let overhead = types::encode_message(&body).unwrap().len() + 4;
    body.payload = Payload::Test(vec![0; 16 * 1024 * 1024 - overhead]);
    let prepared = prepare_outbox(&identity(1), &roster, &body).unwrap();
    let recipient = &prepared.recipients()[1];
    let objects = recipient.objects()[..274]
        .iter()
        .map(|o| (o.hash, o.clone()))
        .collect();
    let opened =
        TransferAssembler::open(&roster, &identity(2), &recipient.objects()[274], &objects)
            .unwrap();
    assert_eq!(opened.message().body(), &body);
    assert_eq!(opened.source().required_hashes().len(), 275);
    assert_eq!(opened.source().digest(), prepared.digest());
}

#[test]
fn transfer_complete_common_sender() {
    let mut f = AssemblyFixture::new();
    f.body.key.sender = 2;
    let package = loki_relay_client::sign_message(&identity(2), &f.roster, &f.body).unwrap();
    let transfer = bytes(&f.manifest[5]).to_vec();
    let mut entries = Vec::new();
    f.objects.clear();
    for (index, segment) in package.chunks(61440).enumerate() {
        let record = canonical::encode(&Value::Array(vec![
            Value::Integer(3.into()),
            Value::Bytes(transfer.clone()),
            Value::Integer((index as u64).into()),
            Value::Bytes(segment.to_vec()),
        ]))
        .unwrap();
        let object = seal_record(&context(&f.roster, 2), &record).unwrap();
        entries.push(Value::Array(vec![
            Value::Bytes(object.hash.to_vec()),
            Value::Integer((object.wire.len() as u64).into()),
            Value::Integer((segment.len() as u64).into()),
        ]));
        f.objects.insert(object.hash, object);
    }
    f.manifest[7] = Value::Bytes(Sha256::digest(types::encode_message(&f.body).unwrap()).to_vec());
    f.manifest[8] = Value::Bytes(Sha256::digest(&package).to_vec());
    f.manifest[9] = Value::Integer((package.len() as u64).into());
    f.manifest[10] = Value::Array(entries);
    f.resign();
    assert!(matches!(f.open(), Err(ClientError::Identity)));
}

#[test]
fn transfer_complete_identity() {
    let f = AssemblyFixture::new();
    let mut serialized = [0u8; 66];
    serialized[..2].copy_from_slice(&2u16.to_be_bytes());
    serialized[2..34].fill(7);
    serialized[34..].fill(5);
    let impostor = CommIdentity::from_serialized(&serialized).unwrap();
    assert!(matches!(
        TransferAssembler::open(&f.roster, &impostor, &f.root, &f.objects),
        Err(ClientError::Identity)
    ));
    assert!(TransferAssembler::open(&f.roster, &identity(3), &f.root, &f.objects).is_err());
}

#[test]
fn transfer_complete_invalid_present_with_missing() {
    let mut f = AssemblyFixture::new();
    let hash = *f.objects.keys().next().unwrap();
    f.objects.remove(&hash);
    f.objects.values_mut().next().unwrap().wire[100] ^= 1;
    assert!(matches!(f.open(), Err(ClientError::Wire(_))));
}

#[test]
fn transfer_complete_invalid_extra() {
    let mut f = AssemblyFixture::new();
    let extra = seal_record(&context(&f.roster, 2), &[0x81, 0]).unwrap();
    f.objects.insert([8; 32], extra);
    assert!(matches!(
        f.open(),
        Err(ClientError::Wire(loki_relay_protocol::WireError::Schema))
    ));
}

manifest_fault!(
    transfer_complete_sender_zero,
    3,
    Value::Integer(0.into()),
    ClientError::Identity
);
manifest_fault!(
    transfer_complete_recipient_zero,
    4,
    Value::Integer(0.into()),
    ClientError::Identity
);
manifest_fault!(
    transfer_complete_short_id,
    6,
    Value::Bytes(vec![8; 31]),
    ClientError::Wire(loki_relay_protocol::WireError::Schema)
);
manifest_fault!(
    transfer_complete_zero_total,
    9,
    Value::Integer(0.into()),
    ClientError::Wire(loki_relay_protocol::WireError::Bounds)
);

#[test]
fn transfer_complete_manifest_signature() {
    let mut f = AssemblyFixture::new();
    let raw = open_record(&context(&f.roster, 2), &identity(2), &f.root.wire).unwrap();
    let mut inner = array(&canonical::decode(&raw, 65536).unwrap()).to_vec();
    let Value::Bytes(signature) = &mut inner[2] else {
        panic!()
    };
    signature[0] ^= 1;
    f.root = seal_record(
        &context(&f.roster, 2),
        &canonical::encode(&Value::Array(inner)).unwrap(),
    )
    .unwrap();
    assert!(matches!(f.open(), Err(ClientError::Crypto)));
}

#[test]
fn transfer_complete_manifest_schema() {
    let mut f = AssemblyFixture::new();
    f.manifest.pop();
    f.resign();
    assert!(matches!(
        f.open(),
        Err(ClientError::Wire(loki_relay_protocol::WireError::Schema))
    ));
}

#[test]
fn transfer_complete_final_segment_bound() {
    let mut f = AssemblyFixture::new();
    let Value::Array(entries) = &mut f.manifest[10] else {
        panic!()
    };
    let Value::Array(entry) = entries.last_mut().unwrap() else {
        panic!()
    };
    entry[2] = Value::Integer(0.into());
    f.resign();
    assert!(f.open().is_err());
}

#[test]
fn transfer_complete_wire_bound() {
    let mut f = AssemblyFixture::new();
    let Value::Array(entries) = &mut f.manifest[10] else {
        panic!()
    };
    let Value::Array(entry) = &mut entries[0] else {
        panic!()
    };
    entry[1] = Value::Integer(65537.into());
    f.resign();
    assert!(f.open().is_err());
}

#[test]
fn transfer_complete_manifest_chunk_bound() {
    let mut f = AssemblyFixture::new();
    let mut manifest = f.manifest.clone();
    let entry = array(&manifest[10])[0].clone();
    manifest[10] = Value::Array(vec![entry.clone(); 274]);
    let encoded = canonical::encode(&Value::Array(manifest)).unwrap();
    let entry_bytes = canonical::encode(&entry).unwrap();
    let offset = encoded.len() - 274 * entry_bytes.len() - 3;
    assert_eq!(&encoded[offset..offset + 3], &[0x99, 0x01, 0x12]);
    let mut malformed = encoded;
    malformed[offset + 2] = 0x13;
    malformed.extend_from_slice(&entry_bytes);
    let mut input = b"Loki_Relay_Manifest_v1\0".to_vec();
    input.extend_from_slice(&(malformed.len() as u32).to_be_bytes());
    input.extend_from_slice(&malformed);
    let signature = SigningKey::from_bytes(&[1; 32]).sign(&input);
    let raw = canonical::encode(&Value::Array(vec![
        Value::Integer(2.into()),
        Value::Bytes(malformed),
        Value::Bytes(signature.to_bytes().to_vec()),
    ]))
    .unwrap();
    f.root = seal_record(&context(&f.roster, 2), &raw).unwrap();
    assert!(matches!(
        f.open(),
        Err(ClientError::Wire(loki_relay_protocol::WireError::Bounds))
    ));
}
