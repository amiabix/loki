use ed25519_dalek::{Signer, SigningKey};
use loki_relay_client::{
    open_record, seal_record, sign_roster_acceptance, AcceptedSetupRoster, BootstrapContext,
    CommIdentity, OperatorSet, SealContext, SealDomain, SetupInvite, SetupPolicy, SetupRecordIndex,
};
use loki_relay_protocol::{
    canonical::{self, Value},
    setup::{SetupCapabilities, SetupKey, SetupPhase, SetupRecord},
    types::{roster_digest, Roster},
};
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

fn identity(id: u16) -> CommIdentity {
    let mut raw = [0; 66];
    raw[..2].copy_from_slice(&id.to_be_bytes());
    raw[2..34].fill(id as u8);
    raw[34..].fill(id as u8 + 10);
    CommIdentity::from_serialized(&raw).unwrap()
}
fn config() -> (Vec<u8>, [u8; 32], OperatorSet) {
    let signer = SigningKey::from_bytes(&[90; 32]);
    let b = bundle(&signer, |_| {});
    let key = signer.verifying_key().to_bytes();
    let op = OperatorSet::verify(&b, &key).unwrap();
    (b, key, op)
}
fn policy(count: u16, op: &OperatorSet) -> SetupPolicy {
    SetupPolicy {
        ceremony: [70; 32],
        network: "regtest".into(),
        threshold: 2,
        member_count: count,
        config_digest: *op.digest(),
    }
}
fn roster(count: u16) -> Roster {
    Roster {
        vault: [70; 32],
        members: (1..=count).map(|id| identity(id).public()).collect(),
    }
}
fn record(p: &SetupPolicy, r: &Roster) -> SetupRecord {
    SetupRecord {
        version: loki_relay_protocol::setup::SETUP_VERSION,
        key: SetupKey {
            ceremony: p.ceremony,
            phase: SetupPhase::Round1,
            author: 1,
            recipient: p.member_count,
            revision: 1,
        },
        network: p.network.clone(),
        threshold: p.threshold,
        member_count: p.member_count,
        roster_digest: Some(roster_digest(r).unwrap()),
        prerequisites: vec![],
        payload: vec![4; 100],
    }
}
#[test]
fn private_invitation_verified_before_network_and_bound_to_configuration() {
    let (bundle, key, op) = config();
    for n in [3, 4] {
        let p = policy(n, &op);
        let raw = SetupInvite::create(&identity(1), &p, n, 1000, [42; 32], &op).unwrap();
        let invite = SetupInvite::verify(&raw, &identity(1).public(), &bundle, &key, 100).unwrap();
        assert_eq!(invite.slot(), n);
        assert_eq!(invite.secret().as_bytes(), &[42; 32]);
        assert_eq!(invite.context().policy(), &p);
        assert!(SetupInvite::verify(&raw, &identity(2).public(), &bundle, &key, 100).is_err());
        assert!(SetupInvite::verify(&raw, &identity(1).public(), &bundle, &key, 1000).is_err());
        let other = bundle_with_changed_origin();
        assert!(SetupInvite::verify(&raw, &identity(1).public(), &other, &key, 100).is_err());
        let mut bad = raw.to_vec();
        let end = bad.len() - 1;
        bad[end] ^= 1;
        assert!(SetupInvite::verify(&bad, &identity(1).public(), &bundle, &key, 100).is_err());
        let fragment = SetupInvite::to_fragment(&raw).unwrap();
        assert!(!fragment.contains('?'));
        let decoded = SetupInvite::from_fragment(&fragment).unwrap();
        assert_eq!(&*decoded, &*raw);
        assert!(
            SetupInvite::from_fragment(&format!("https://host/?invite={}", &*fragment)).is_err()
        );
    }
}
fn bundle_with_changed_origin() -> Vec<u8> {
    bundle(&SigningKey::from_bytes(&[90; 32]), |f| {
        let Value::Array(a) = &mut f[2] else { panic!() };
        a[0] = Value::Bytes(b"https://other.example".to_vec());
    })
}
#[test]
fn every_slot_must_accept_identical_roster_and_support_policy_before_dkg() {
    let (_, _, op) = config();
    for n in [3, 4] {
        let p = policy(n, &op);
        let ctx = BootstrapContext::creator(p.clone(), identity(1).public(), &op).unwrap();
        let r = roster(n);
        let a: Vec<_> = (1..=n)
            .map(|id| {
                sign_roster_acceptance(&identity(id), &ctx, &r, &SetupCapabilities::current())
                    .unwrap()
            })
            .collect();
        assert!(AcceptedSetupRoster::verify(&ctx, r.clone(), &a[..a.len() - 1]).is_err());
        let accepted = AcceptedSetupRoster::verify(&ctx, r.clone(), &a).unwrap();
        assert_eq!(accepted.roster(), &r);
        let mut dup = a.clone();
        dup[n as usize - 1] = a[0].clone();
        assert!(AcceptedSetupRoster::verify(&ctx, r.clone(), &dup).is_err());
        let old = SetupCapabilities {
            versions: vec![1],
            member_counts: vec![3],
        };
        if n == 4 {
            assert!(sign_roster_acceptance(&identity(4), &ctx, &r, &old).is_err());
        }
        let mut changed = r.clone();
        changed.members[1] = identity(4).public();
        changed.members[1].id = 2;
        assert!(AcceptedSetupRoster::verify(&ctx, changed, &a).is_err());
        let body = record(&p, &r);
        let signed = accepted.sign(&identity(1), &body).unwrap();
        let auth = accepted.authenticate(n, &signed).unwrap();
        assert_eq!(auth.body().payload, body.payload);
        let mut seen = SetupRecordIndex::default();
        assert!(seen.observe(&auth).unwrap());
        assert!(!seen.observe(&auth).unwrap());
        let mut conflict = body.clone();
        conflict.payload.push(9);
        let other = accepted
            .authenticate(n, &accepted.sign(&identity(1), &conflict).unwrap())
            .unwrap();
        assert!(seen.observe(&other).is_err());
        assert!(seen.observe(&auth).is_err());
        for case in 0..6 {
            let mut bad = body.clone();
            match case {
                0 => bad.key.ceremony = [8; 32],
                1 => bad.network = "mainnet".into(),
                2 => bad.threshold = 1,
                3 => bad.member_count = 5,
                4 => bad.roster_digest = Some([5; 32]),
                5 => bad.key.author = 2,
                _ => unreachable!(),
            };
            assert!(accepted.sign(&identity(1), &bad).is_err());
        }
        assert!(accepted.authenticate(1, &signed).is_err());
        let mut bad = signed.clone();
        let end = bad.len() - 1;
        bad[end] ^= 1;
        assert!(accepted.authenticate(n, &bad).is_err());
    }
}
#[test]
fn setup_envelopes_cannot_be_opened_as_payment_or_config() {
    let owner = identity(4);
    let ctx = SealContext {
        vault: [70; 32],
        roster: [8; 32],
        recipient: owner.public(),
        domain: SealDomain::Setup,
    };
    let bytes = canonical::encode(&Value::Array(vec![Value::Bytes(vec![4; 20])])).unwrap();
    let object = seal_record(&ctx, &bytes).unwrap();
    assert_eq!(open_record(&ctx, &owner, &object.wire).unwrap(), bytes);
    for domain in [SealDomain::Message, SealDomain::Config] {
        let mut wrong = ctx.clone();
        wrong.domain = domain;
        assert!(open_record(&wrong, &owner, &object.wire).is_err());
    }
}

fn raw_signed(domain: &[u8], body: Vec<u8>, author: u16) -> Vec<u8> {
    let mut input = domain.to_vec();
    input.extend_from_slice(&(body.len() as u32).to_be_bytes());
    input.extend_from_slice(&body);
    canonical::encode(&Value::Array(vec![
        Value::Bytes(body),
        Value::Bytes(
            SigningKey::from_bytes(&[author as u8; 32])
                .sign(&input)
                .to_bytes()
                .to_vec(),
        ),
    ]))
    .unwrap()
}
#[test]
fn receiver_rejects_signed_wrong_context_unsupported_and_cross_domain() {
    let (_, _, op) = config();
    let p = policy(4, &op);
    let ctx = BootstrapContext::creator(p.clone(), identity(1).public(), &op).unwrap();
    let r = roster(4);
    let a: Vec<_> = (1..=4)
        .map(|id| {
            sign_roster_acceptance(&identity(id), &ctx, &r, &SetupCapabilities::current()).unwrap()
        })
        .collect();
    let accepted = AcceptedSetupRoster::verify(&ctx, r.clone(), &a).unwrap();
    let body = record(&p, &r);
    let encoded = loki_relay_protocol::setup::encode_record(&body).unwrap();
    for (field, replacement) in [
        (0, Value::Integer(1.into())),
        (1, Value::Bytes(vec![90; 32])),
        (2, Value::Text("mainnet".into())),
        (3, Value::Integer(1.into())),
        (4, Value::Integer(3.into())),
        (6, Value::Integer(2.into())),
        (7, Value::Integer(3.into())),
        (9, Value::Bytes(vec![91; 32])),
    ] {
        let Value::Array(mut f) = canonical::decode(&encoded, 1100000).unwrap() else {
            panic!()
        };
        f[field] = replacement;
        let bad = raw_signed(
            loki_relay_protocol::setup::RECORD_DOMAIN,
            canonical::encode(&Value::Array(f)).unwrap(),
            1,
        );
        assert!(accepted.authenticate(4, &bad).is_err(), "field {field}");
    }
    let cross = raw_signed(b"Loki_Relay_Message_v1\0", encoded, 1);
    assert!(accepted.authenticate(4, &cross).is_err());
    let mut wrong = a.clone();
    let Value::Array(mut package) = canonical::decode(&a[3], 1100000).unwrap() else {
        panic!()
    };
    let Value::Bytes(bytes) = &package[0] else {
        panic!()
    };
    let Value::Array(mut record) = canonical::decode(bytes, 1100000).unwrap() else {
        panic!()
    };
    let Value::Bytes(payload) = &record[11] else {
        panic!()
    };
    let Value::Array(mut cap) = canonical::decode(payload, 4096).unwrap() else {
        panic!()
    };
    cap[2] = Value::Array(vec![Value::Integer(3.into())]);
    record[11] = Value::Bytes(canonical::encode(&Value::Array(cap)).unwrap());
    wrong[3] = raw_signed(
        loki_relay_protocol::setup::RECORD_DOMAIN,
        canonical::encode(&Value::Array(record)).unwrap(),
        4,
    );
    package.clear();
    assert!(AcceptedSetupRoster::verify(&ctx, r, &wrong).is_err());
}
#[test]
fn private_invite_rejects_secret_policy_and_version_substitution() {
    let (bundle, key, op) = config();
    let raw = SetupInvite::create(&identity(1), &policy(4, &op), 4, 1000, [42; 32], &op).unwrap();
    let Value::Array(mut outer) = canonical::decode(&raw, 4096).unwrap() else {
        panic!()
    };
    outer[1] = Value::Bytes(vec![43; 32]);
    let bad = canonical::encode(&Value::Array(outer)).unwrap();
    assert!(SetupInvite::verify(&bad, &identity(1).public(), &bundle, &key, 100).is_err());
    for (field, replacement) in [
        (0, Value::Integer(2.into())),
        (3, Value::Integer(1.into())),
        (4, Value::Integer(17.into())),
        (5, Value::Integer(1.into())),
        (8, Value::Bytes(vec![8; 32])),
    ] {
        let Value::Array(mut outer) = canonical::decode(&raw, 4096).unwrap() else {
            panic!()
        };
        let Value::Bytes(package) = &outer[0] else {
            panic!()
        };
        let Value::Array(package) = canonical::decode(package, 4096).unwrap() else {
            panic!()
        };
        let Value::Bytes(body) = &package[0] else {
            panic!()
        };
        let Value::Array(mut fields) = canonical::decode(body, 4096).unwrap() else {
            panic!()
        };
        fields[field] = replacement;
        outer[0] = Value::Bytes(raw_signed(
            b"Loki_Setup_Invite_v1\0",
            canonical::encode(&Value::Array(fields)).unwrap(),
            1,
        ));
        let bad = canonical::encode(&Value::Array(outer)).unwrap();
        assert!(
            SetupInvite::verify(&bad, &identity(1).public(), &bundle, &key, 100).is_err(),
            "field {field}"
        );
    }
}
#[test]
fn bootstrap_messages_bind_claimed_peer_and_refuse_dkg_before_acceptance() {
    let (_, _, op) = config();
    let p = policy(4, &op);
    let ctx = BootstrapContext::creator(p.clone(), identity(1).public(), &op).unwrap();
    let mut body = record(&p, &roster(4));
    body.key.phase = SetupPhase::Join;
    body.roster_digest = None;
    body.key.author = 4;
    body.key.recipient = 1;
    let signed = ctx.sign_bootstrap(&identity(4), &body).unwrap();
    assert!(ctx
        .authenticate_bootstrap(&identity(4).public(), 1, &signed)
        .is_ok());
    assert!(ctx
        .authenticate_bootstrap(&identity(3).public(), 1, &signed)
        .is_err());
    assert!(ctx
        .authenticate_bootstrap(&identity(4).public(), 4, &signed)
        .is_err());
    body.key.phase = SetupPhase::Round1;
    body.roster_digest = Some(roster_digest(&roster(4)).unwrap());
    assert!(ctx.sign_bootstrap(&identity(4), &body).is_err());
    body.key.phase = SetupPhase::RosterProposal;
    assert!(ctx.sign_bootstrap(&identity(4), &body).is_err());
    body.key.author = 1;
    assert!(ctx.sign_bootstrap(&identity(1), &body).is_ok());
}

#[test]
fn owned_development_invite_keeps_signature_and_bundle_checks() {
    let signer = SigningKey::from_bytes(&[90; 32]);
    let raw_bundle = bundle(&signer, |f| {
        let Value::Array(a) = &mut f[2] else { panic!() };
        a[0] = Value::Bytes(b"http://127.0.0.1:9000".to_vec());
    });
    let key = signer.verifying_key().to_bytes();
    let op = OperatorSet::verify_development(&raw_bundle, &key).unwrap();
    let p = policy(4, &op);
    let raw = SetupInvite::create(&identity(1), &p, 4, 1000, [42; 32], &op).unwrap();
    assert!(SetupInvite::verify(&raw, &identity(1).public(), &raw_bundle, &key, 100).is_err());
    assert!(
        SetupInvite::verify_development(&raw, &identity(1).public(), &raw_bundle, &key, 100)
            .is_ok()
    );
    assert!(
        SetupInvite::verify_development(&raw, &identity(2).public(), &raw_bundle, &key, 100)
            .is_err()
    );
}
