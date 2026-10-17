mod support;
use loki_relay_protocol::admission::AdmissionCommand;
use loki_setup_admission::AdmissionError;
use support::*;
#[test]
fn same_claim_is_retrievable_after_first_claim_window_and_reopen() {
    for n in [3, 4] {
        let db = OwnedDb::new();
        let mut store = db.open();
        let grant = grant(2, 48);
        let c = create(1, [70; 32], n, &grant);
        let created = store.apply(&c, Some(&grant), 100).unwrap();
        assert_eq!(store.apply(&c, Some(&grant), 100).unwrap(), created);
        let req = claim(2, [70; 32], n, n as u8);
        let saved = store.apply(&req, Some(&[n as u8; 32]), 101).unwrap();
        assert_eq!(store.apply(&req, None, 100000).unwrap(), saved);
        drop(store);
        let mut store = db.open();
        assert_eq!(store.apply(&req, None, 100001).unwrap(), saved);
        let changed = claim(2, [70; 32], n, 10);
        assert_eq!(
            store
                .apply(&changed, Some(&[n as u8; 32]), 102)
                .unwrap_err(),
            AdmissionError::Conflict
        );
        let claimant = claim(3, [70; 32], n, 10);
        assert_eq!(
            store
                .apply(&claimant, Some(&[n as u8; 32]), 102)
                .unwrap_err(),
            AdmissionError::Conflict
        );
        let unclaimed = claim(4, [70; 32], 2, 2);
        if n != 2 {
            assert_eq!(
                store.apply(&unclaimed, Some(&[2; 32]), 100000).unwrap_err(),
                AdmissionError::Expired
            );
        }
    }
}
#[test]
fn three_members_resume_checkpoints_days_apart_after_claiming() {
    let db = OwnedDb::new();
    let grant = grant(1, 24);
    let start = 100;
    let ceremony = [79; 32];
    let mut store = db.open();
    store
        .apply(&create(1, ceremony, 3, &grant), Some(&grant), start)
        .unwrap();
    for slot in 2..=3 {
        store
            .apply(
                &claim(slot as u8, ceremony, slot, slot as u8),
                Some(&[slot as u8; 32]),
                start + 60,
            )
            .unwrap();
    }
    drop(store);

    for (slot, day) in [(1, 1), (2, 3), (3, 5)] {
        let mut store = db.open();
        let checkpoint = request(
            slot as u8 + 3,
            &identity(slot, slot as u8),
            AdmissionCommand::Checkpoint {
                ceremony,
                slot,
                generation: 1,
                predecessor: [0; 32],
                checkpoint: [slot as u8; 32],
            },
        );
        let at = start + day * 86400;
        let saved = store.apply(&checkpoint, None, at).unwrap();
        drop(store);
        let mut store = db.open();
        assert_eq!(store.apply(&checkpoint, None, at + 1).unwrap(), saved);
    }
    let mut store = db.open();
    let late = request(
        9,
        &identity(1, 1),
        AdmissionCommand::Checkpoint {
            ceremony,
            slot: 1,
            generation: 2,
            predecessor: [1; 32],
            checkpoint: [9; 32],
        },
    );
    assert_eq!(
        store.apply(&late, None, start + 30 * 86400).unwrap_err(),
        AdmissionError::Expired
    );
}
#[test]
fn scoped_creation_budget_consumption_is_durable() {
    let db = OwnedDb::new();
    let mut store = db.open();
    let g = grant(1, 24);
    store
        .apply(&create(1, [70; 32], 4, &g), Some(&g), 100)
        .unwrap();
    assert_eq!(
        store
            .apply(&create(2, [71; 32], 4, &g), Some(&g), 100)
            .unwrap_err(),
        AdmissionError::Quota
    );
    drop(store);
    let mut store = db.open();
    assert_eq!(
        store
            .apply(&create(3, [72; 32], 4, &g), Some(&g), 100)
            .unwrap_err(),
        AdmissionError::Quota
    );
}
#[test]
fn checkpoint_cas_and_terminal_tombstones_never_restart_ceremony() {
    let db = OwnedDb::new();
    let mut store = db.open();
    let g = grant(2, 48);
    store
        .apply(&create(1, [70; 32], 4, &g), Some(&g), 100)
        .unwrap();
    let who = identity(1, 1);
    let cp = request(
        2,
        &who,
        AdmissionCommand::Checkpoint {
            ceremony: [70; 32],
            slot: 1,
            generation: 1,
            predecessor: [0; 32],
            checkpoint: [80; 32],
        },
    );
    let saved = store.apply(&cp, None, 101).unwrap();
    assert_eq!(store.apply(&cp, None, 102).unwrap(), saved);
    let bad = request(
        3,
        &who,
        AdmissionCommand::Checkpoint {
            ceremony: [70; 32],
            slot: 1,
            generation: 2,
            predecessor: [81; 32],
            checkpoint: [82; 32],
        },
    );
    assert_eq!(
        store.apply(&bad, None, 103).unwrap_err(),
        AdmissionError::Conflict
    );
    let good = request(
        4,
        &who,
        AdmissionCommand::Checkpoint {
            ceremony: [70; 32],
            slot: 1,
            generation: 2,
            predecessor: [80; 32],
            checkpoint: [82; 32],
        },
    );
    assert_eq!(
        store.apply(&good, None, 104).unwrap_err(),
        AdmissionError::Terminal
    );
    drop(store);
    let mut store = db.open();
    assert_eq!(
        store.apply(&good, None, 104).unwrap_err(),
        AdmissionError::Terminal
    );
    assert_eq!(
        store
            .apply(&create(5, [70; 32], 4, &g), Some(&g), 104)
            .unwrap_err(),
        AdmissionError::Conflict
    );
}
#[test]
fn abort_and_expiry_allow_only_saved_reconciliation() {
    let db = OwnedDb::new();
    let mut store = db.open();
    let g = grant(2, 48);
    let c = create(1, [70; 32], 3, &g);
    store.apply(&c, Some(&g), 100).unwrap();
    let abort = request(
        2,
        &identity(1, 1),
        AdmissionCommand::Terminal {
            ceremony: [70; 32],
            kind: 1,
        },
    );
    let receipt = store.apply(&abort, None, 101).unwrap();
    assert_eq!(store.apply(&abort, None, 102).unwrap(), receipt);
    assert_eq!(
        store
            .apply(&claim(3, [70; 32], 2, 2), Some(&[2; 32]), 102)
            .unwrap_err(),
        AdmissionError::Terminal
    );
    store
        .apply(&create(4, [71; 32], 4, &g), Some(&g), 100)
        .unwrap();
    let cp = request(
        5,
        &identity(1, 1),
        AdmissionCommand::Checkpoint {
            ceremony: [71; 32],
            slot: 1,
            generation: 1,
            predecessor: [0; 32],
            checkpoint: [80; 32],
        },
    );
    assert_eq!(
        store.apply(&cp, None, 2592100).unwrap_err(),
        AdmissionError::Expired
    );
    store.cleanup(2592100).unwrap();
    drop(store);
    let mut store = db.open();
    assert_eq!(
        store
            .apply(&create(6, [71; 32], 4, &g), Some(&g), 2592101)
            .unwrap_err(),
        AdmissionError::Conflict
    );
}
#[test]
fn two_database_connections_cannot_both_win_one_slot() {
    let db = OwnedDb::new();
    let mut store = db.open();
    let g = grant(2, 48);
    store
        .apply(&create(1, [70; 32], 4, &g), Some(&g), 100)
        .unwrap();
    drop(store);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
    let mut threads = vec![];
    for (op, seed) in [(2, 2), (3, 12)] {
        let path = db.root.clone();
        let barrier = barrier.clone();
        threads.push(std::thread::spawn(move || {
            let mut store = loki_setup_admission::AdmissionStore::open(
                &path,
                &config(),
                loki_setup_admission::EnrollmentVerifier::new(Some(
                    ed25519_dalek::SigningKey::from_bytes(&[9; 32])
                        .verifying_key()
                        .to_bytes(),
                )),
                ed25519_dalek::SigningKey::from_bytes(&[8; 32]),
            )
            .unwrap();
            barrier.wait();
            store.apply(&claim(op, [70; 32], 2, seed), Some(&[2; 32]), 101)
        }));
    }
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(AdmissionError::Conflict)))
            .count(),
        1
    );
}

#[test]
fn activation_requires_two_common_stores_and_each_slot_vote() {
    use loki_relay_protocol::{http::encode_creation, types::Creation};
    for n in [3u16, 4] {
        let db = OwnedDb::new();
        let mut store = db.open();
        let g = grant(2, 48);
        store
            .apply(&create(1, [70; 32], n, &g), Some(&g), 100)
            .unwrap();
        let mut op = 2;
        for slot in 2..=n {
            store
                .apply(
                    &claim(op, [70; 32], slot, slot as u8),
                    Some(&[slot as u8; 32]),
                    101,
                )
                .unwrap();
            op += 1;
        }
        for slot in 1..=n {
            for relay in 1..=3 {
                let req = request(
                    op,
                    &identity(slot, slot as u8),
                    AdmissionCommand::Mailbox {
                        ceremony: [70; 32],
                        slot,
                        relay,
                        purpose: 2,
                        mailbox: [slot as u8 * 10 + relay as u8; 32],
                        creation: encode_creation(&Creation {
                            read_verifier: [1; 32],
                            append_verifier: [2; 32],
                            admin_verifier: [3; 32],
                            quota: 1024,
                        })
                        .unwrap(),
                    },
                );
                store.apply(&req, None, 102).unwrap();
                op += 1;
            }
        }
        let external = rusqlite::Connection::open(db.root.join("admission.sqlite")).unwrap();
        external.execute_batch("UPDATE mailboxes SET provisioned=1 WHERE (slot=1 AND relay IN(1,2)) OR (slot=2 AND relay IN(2,3)) OR (slot=3 AND relay IN(1,3)) OR (slot=4 AND relay IN(1,2));").unwrap();
        let activate = request(
            op,
            &identity(1, 1),
            AdmissionCommand::Terminal {
                ceremony: [70; 32],
                kind: 2,
            },
        );
        assert_eq!(
            store.apply(&activate, None, 103).unwrap_err(),
            AdmissionError::Unavailable
        );
        op += 1;
        external
            .execute_batch("UPDATE mailboxes SET provisioned=1 WHERE relay<=2;")
            .unwrap();
        store.apply(&activate, None, 104).unwrap();
        for slot in 2..=n {
            let vote = request(
                op,
                &identity(slot, slot as u8),
                AdmissionCommand::Terminal {
                    ceremony: [70; 32],
                    kind: 2,
                },
            );
            store.apply(&vote, None, 104).unwrap();
            op += 1;
            let terminal: u64 = external
                .query_row(
                    "SELECT terminal FROM ceremonies WHERE id=?1",
                    [[70u8; 32].as_slice()],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(terminal, if slot == n { 2 } else { 0 });
        }
        external
            .execute_batch("UPDATE mailboxes SET provisioned=0 WHERE relay=3;")
            .unwrap();
        store.cleanup(2592100).unwrap();
        assert_eq!(
            store.pending(2592101, 3).unwrap().len(),
            usize::from(n).min(3)
        );
    }
}

#[test]
fn terminal_member_notifications_survive_retirement_and_reopen_for_both_policies() {
    use loki_relay_client::{verify_admission_reply, AdmissionOutcome};
    use loki_relay_protocol::canonical::Value;
    for count in [3u16, 4] {
        let db = OwnedDb::new();
        let mut store = db.open();
        let g = grant(2, 48);
        store
            .apply(&create(31, [77; 32], count, &g), Some(&g), 100)
            .unwrap();
        store
            .apply(
                &claim(32, [77; 32], count, count as u8),
                Some(&[count as u8; 32]),
                101,
            )
            .unwrap();
        let abort = request(
            33,
            &identity(1, 1),
            AdmissionCommand::Terminal {
                ceremony: [77; 32],
                kind: 1,
            },
        );
        store.apply(&abort, None, 102).unwrap();
        store.cleanup(103).unwrap();
        drop(store);
        let mut store = db.open();
        let fetch = request(
            34,
            &identity(count, count as u8),
            AdmissionCommand::TerminalNotice {
                ceremony: [77; 32],
                kind: 0,
            },
        );
        let reply = store.apply(&fetch, None, 104).unwrap();
        let verified = verify_admission_reply(&config(), &fetch, &reply).unwrap();
        let AdmissionOutcome::Accepted(Value::Array(fields)) = verified.outcome() else {
            panic!()
        };
        assert_eq!(
            fields,
            &vec![
                Value::Integer(1.into()),
                Value::Array(vec![Value::Bytes(abort)])
            ]
        );
        let notices = loki_relay_client::verify_terminal_notices(
            &[77; 32],
            &[
                identity(1, 1).public(),
                identity(count, count as u8).public(),
            ],
            &verified,
        )
        .unwrap();
        assert_eq!(notices.terminal_kind(), 1);
        assert_eq!(notices.notifying_members(), &[1]);
        let external = rusqlite::Connection::open(db.root.join("admission.sqlite")).unwrap();
        let mut changed = match &fields[1] {
            Value::Array(notices) => match &notices[0] {
                Value::Bytes(b) => b.clone(),
                _ => panic!(),
            },
            _ => panic!(),
        };
        let end = changed.len() - 1;
        changed[end] ^= 1;
        external
            .execute(
                "UPDATE terminal_notices SET request=?1 WHERE ceremony=?2",
                rusqlite::params![changed, [77u8; 32].as_slice()],
            )
            .unwrap();
        let fresh = request(
            41,
            &identity(count, count as u8),
            AdmissionCommand::TerminalNotice {
                ceremony: [77; 32],
                kind: 0,
            },
        );
        let reply = store.apply(&fresh, None, 105).unwrap();
        let verified_changed = verify_admission_reply(&config(), &fresh, &reply).unwrap();
        assert!(loki_relay_client::verify_terminal_notices(
            &[77; 32],
            &[
                identity(1, 1).public(),
                identity(count, count as u8).public()
            ],
            &verified_changed
        )
        .is_err());
        let stranger = request(
            35,
            &identity(2, 12),
            AdmissionCommand::TerminalNotice {
                ceremony: [77; 32],
                kind: 0,
            },
        );
        assert_eq!(
            store.apply(&stranger, None, 104).unwrap_err(),
            AdmissionError::Identity
        );
        let incorrect = request(
            36,
            &identity(count, count as u8),
            AdmissionCommand::TerminalNotice {
                ceremony: [77; 32],
                kind: 4,
            },
        );
        assert_eq!(
            store.apply(&incorrect, None, 104).unwrap_err(),
            AdmissionError::Terminal
        );
        store
            .apply(&create(37, [78; 32], count, &g), Some(&g), 100)
            .unwrap();
        let state = request(
            38,
            &identity(1, 1),
            AdmissionCommand::State {
                ceremony: [78; 32],
                slot: 1,
            },
        );
        let reply = store.apply(&state, None, 2592100).unwrap();
        let verified = verify_admission_reply(&config(), &state, &reply).unwrap();
        let AdmissionOutcome::Accepted(Value::Array(fields)) = verified.outcome() else {
            panic!()
        };
        assert_eq!(fields[3], Value::Integer(4.into()));
        let notice = request(
            39,
            &identity(1, 1),
            AdmissionCommand::TerminalNotice {
                ceremony: [78; 32],
                kind: 4,
            },
        );
        store.apply(&notice, None, 2592100).unwrap();
        drop(store);
        let mut store = db.open();
        let fetch = request(
            40,
            &identity(1, 1),
            AdmissionCommand::TerminalNotice {
                ceremony: [78; 32],
                kind: 0,
            },
        );
        let reply = store.apply(&fetch, None, 2592101).unwrap();
        let verified = verify_admission_reply(&config(), &fetch, &reply).unwrap();
        let AdmissionOutcome::Accepted(Value::Array(fields)) = verified.outcome() else {
            panic!()
        };
        assert_eq!(
            fields,
            &vec![
                Value::Integer(4.into()),
                Value::Array(vec![Value::Bytes(notice)])
            ]
        );
    }
}
