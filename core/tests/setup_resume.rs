use loki_poc::distributed_setup::{Completed, Member, Round2Member};
use std::collections::BTreeMap;

#[test]
fn checkpoint_restores_exact_dkg_packages_for_both_policies() {
    for (threshold, count) in [(2, 3u16), (2, 4), (3, 4), (3, 5), (15, 16)] {
        let mut live = BTreeMap::new();
        let mut restored = BTreeMap::new();
        let mut round1 = BTreeMap::new();
        for id in 1..=count {
            let (member, public) = Member::start_with_policy(id, threshold, count).unwrap();
            let checkpoint = member.checkpoint().unwrap();
            let recovered = Member::restore_checkpoint(&checkpoint).unwrap();
            assert_eq!(&*checkpoint, &*recovered.checkpoint().unwrap());
            round1.insert(id, public);
            live.insert(id, member);
            restored.insert(id, recovered);
        }
        let mut round2 = BTreeMap::new();
        let mut resumed_round2 = BTreeMap::new();
        for (id, member) in live {
            let (member, outgoing) = member.advance(&round1).unwrap();
            let (other, same) = restored.remove(&id).unwrap().advance(&round1).unwrap();
            assert_eq!(outgoing, same);
            assert_eq!(member.transcript, other.transcript);
            let checkpoint = member.checkpoint().unwrap();
            let recovered = Round2Member::restore_checkpoint(&checkpoint).unwrap();
            assert_eq!(&*checkpoint, &*recovered.checkpoint().unwrap());
            round2.insert(id, (member, outgoing));
            resumed_round2.insert(id, recovered);
        }
        let mut certificates = BTreeMap::new();
        let mut results = BTreeMap::new();
        for (id, (member, _)) in &round2 {
            let incoming = round2
                .iter()
                .filter(|(sender, _)| *sender != id)
                .map(|(sender, (_, outgoing))| (*sender, outgoing[id].clone()))
                .collect();
            let completed = member.finish(&incoming).unwrap();
            let bytes = completed.checkpoint().unwrap();
            {
                use reddsa_frost::frost::redpallas as frost;
                let key_len = u32::from_be_bytes(bytes[13..17].try_into().unwrap()) as usize;
                let public_offset = 17 + key_len;
                let public_len =
                    u32::from_be_bytes(bytes[public_offset..public_offset + 4].try_into().unwrap())
                        as usize;
                let public_start = public_offset + 4;
                let public = frost::keys::PublicKeyPackage::deserialize(
                    &bytes[public_start..public_start + public_len],
                )
                .unwrap();
                let mut shares = public.verifying_shares().clone();
                let own = frost::Identifier::try_from(*id).unwrap();
                let peer = *shares.keys().find(|peer| **peer != own).unwrap();
                shares.insert(peer, shares[&own]);
                let changed =
                    frost::keys::PublicKeyPackage::new(shares, *public.verifying_key(), Some(threshold))
                        .serialize()
                        .unwrap();
                let mut corrupt = bytes[..public_offset].to_vec();
                corrupt.extend_from_slice(&(changed.len() as u32).to_be_bytes());
                corrupt.extend_from_slice(&changed);
                corrupt.extend_from_slice(&bytes[public_start + public_len..]);
                assert!(Completed::restore_checkpoint(&corrupt).is_err());
            }
            let recovered_completed = Completed::restore_checkpoint(&bytes).unwrap();
            assert_eq!(&*bytes, &*recovered_completed.checkpoint().unwrap());
            assert_eq!(
                completed.certificate_digest(),
                recovered_completed.certificate_digest()
            );
            let restored = resumed_round2[id].finish(&incoming).unwrap();
            assert_eq!(
                completed.certificate_digest(),
                restored.certificate_digest()
            );
            certificates.insert(*id, completed.certificate_digest());
            results.insert(*id, (completed, restored));
        }
        for (_, (live, restored)) in results {
            let live = live.certify(&certificates).unwrap();
            let restored = restored.certify(&certificates).unwrap();
            assert_eq!(live.key_package, restored.key_package);
            assert_eq!(live.public_package, restored.public_package);
            assert_eq!(live.group_ak, restored.group_ak);
        }
    }
}

#[test]
fn checkpoint_rejects_wrong_phase_trailing_bytes_and_damaged_material() {
    let (member, _) = Member::start_with_policy(4, 2, 4).unwrap();
    let checkpoint = member.checkpoint().unwrap();
    assert!(Round2Member::restore_checkpoint(&checkpoint).is_err());
    let mut trailing = checkpoint.to_vec();
    trailing.push(0);
    assert!(Member::restore_checkpoint(&trailing).is_err());
    for offset in [0, 8, 9, 10, checkpoint.len() - 1] {
        let mut corrupt = checkpoint.to_vec();
        corrupt[offset] ^= 0xff;
        assert!(Member::restore_checkpoint(&corrupt).is_err());
    }
}

#[test]
fn accepted_core_roster_requires_every_slot_and_exact_policy_signatures() {
    use loki_poc::{
        member_state::Roster, setup_ceremony::AcceptedCeremonyRoster, setup_transport::Identity,
    };
    for (threshold, count) in [(2u16, 3u16), (2, 4), (3, 4), (3, 5), (15, 16)] {
        let identities: Vec<_> = (1..=count).map(Identity::new).collect();
        let document=serde_json::to_vec(&serde_json::json!({"vault":hex::encode([70;32]),"threshold":threshold,"members":identities.iter().map(|i|{let p=i.public();serde_json::json!({"id":p.id,"signing":hex::encode(p.signing),"encryption":hex::encode(p.encryption)})}).collect::<Vec<_>>()})).unwrap();
        let roster = Roster::from_bytes(&document).unwrap();
        let payload =
            AcceptedCeremonyRoster::agreement_payload(&roster, "regtest", &[77; 32]).unwrap();
        let votes: BTreeMap<_, _> = identities
            .iter()
            .map(|i| {
                (
                    i.public().id,
                    i.sign_setup_agreement(&roster.vault, &payload).unwrap(),
                )
            })
            .collect();
        let accepted =
            AcceptedCeremonyRoster::verify(roster, "regtest", [77; 32], &identities[0], &votes)
                .unwrap();
        assert_eq!(accepted.roster().members.len(), count as usize);
        let mut missing = votes.clone();
        missing.remove(&count);
        assert!(AcceptedCeremonyRoster::verify(
            Roster::from_bytes(&document).unwrap(),
            "regtest",
            [77; 32],
            &identities[0],
            &missing
        )
        .is_err());
        assert!(AcceptedCeremonyRoster::verify(
            Roster::from_bytes(&document).unwrap(),
            "regtest",
            [78; 32],
            &identities[0],
            &votes
        )
        .is_err());
        assert!(AcceptedCeremonyRoster::verify(
            Roster::from_bytes(&document).unwrap(),
            "mainnet",
            [77; 32],
            &identities[0],
            &votes
        )
        .is_err());
        assert!(identities[0]
            .verify_certificate(&identities[0].public(), &[70; 32], &votes[&1])
            .is_err());
    }
}

#[test]
fn ceremony_restarts_every_complete_phase_and_preserves_saved_ciphertext() {
    use loki_poc::{
        member_state::Roster,
        setup_ceremony::{
            AcceptedCeremonyRoster, CeremonyPhase, CeremonyRecord, CheckpointAuthority,
            CheckpointState, SavedCheckpoint, SetupCeremony,
        },
        setup_transport::Identity,
        state::MemberDir,
    };
    struct Anchor {
        last: Option<SavedCheckpoint>,
        lose_next_reply: bool,
    }
    impl CheckpointAuthority for Anchor {
        fn reconcile(&mut self, expected: &SavedCheckpoint) -> Result<CheckpointState, String> {
            if let Some(old) = &self.last {
                if old.generation != expected.generation
                    && (old.generation + 1 != expected.generation
                        || old.digest != expected.predecessor)
                {
                    return Err("checkpoint_conflict".into());
                }
                if old.generation == expected.generation && old != expected {
                    return Err("checkpoint_conflict".into());
                }
            } else if expected.generation != 1 || expected.predecessor != [0; 32] {
                return Err("checkpoint_conflict".into());
            }
            self.last = Some(expected.clone());
            if self.lose_next_reply {
                self.lose_next_reply = false;
                return Err("owned_lost_reply".into());
            }
            Ok(CheckpointState {
                generation: expected.generation,
                digest: expected.digest,
                terminal: false,
            })
        }
    }
    for (threshold, count) in [(2u16, 3u16), (2, 4), (3, 4), (3, 5), (15, 16)] {
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "loki-engine-{}",
            hex::encode(Identity::new(1).public().signing)
        ));
        let identities: Vec<_> = (1..=count).map(Identity::new).collect();
        let document=serde_json::to_vec(&serde_json::json!({"vault":hex::encode([78;32]),"threshold":threshold,"members":identities.iter().map(|i|{let p=i.public();serde_json::json!({"id":p.id,"signing":hex::encode(p.signing),"encryption":hex::encode(p.encryption)})}).collect::<Vec<_>>()})).unwrap();
        let payload = AcceptedCeremonyRoster::agreement_payload(
            &Roster::from_bytes(&document).unwrap(),
            "regtest",
            &[77; 32],
        )
        .unwrap();
        let votes: BTreeMap<_, _> = identities
            .iter()
            .map(|i| {
                (
                    i.public().id,
                    i.sign_setup_agreement(&[78; 32], &payload).unwrap(),
                )
            })
            .collect();
        let accepted = |id: u16| {
            AcceptedCeremonyRoster::verify(
                Roster::from_bytes(&document).unwrap(),
                "regtest",
                [77; 32],
                &identities[id as usize - 1],
                &votes,
            )
            .unwrap()
        };
        let mut engines = BTreeMap::new();
        let mut anchors = BTreeMap::new();
        let mut paths = BTreeMap::new();
        for identity in &identities {
            let id = identity.public().id;
            let member = MemberDir::create(&root, &format!("member-{id}")).unwrap();
            let secrets = MemberDir::create(member.path(), "secrets").unwrap();
            secrets
                .write_sealed("identity.sealed", &identity.to_secret_bytes(), "pass")
                .unwrap();
            let mut engine = SetupCeremony::open(member.path(), "pass", accepted(id)).unwrap();
            let mut anchor = Anchor {
                last: None,
                lose_next_reply: false,
            };
            engine.synchronize(&mut anchor).unwrap();
            assert_eq!(engine.phase(), CeremonyPhase::AwaitingRoster);
            engine.step(&[]).unwrap();
            assert_eq!(engine.phase(), CeremonyPhase::Starting);
            engine.synchronize(&mut anchor).unwrap();
            engine
                .step_with_preparation(&[], |_, _| Ok(vec![id as u8; 32]))
                .unwrap();
            assert!(engine.outgoing().is_err());
            anchor.lose_next_reply = true;
            assert!(engine.synchronize(&mut anchor).is_err());
            assert!(engine.outgoing().is_err());
            let pending = engine.checkpoint();
            drop(engine);
            let mut engine = SetupCeremony::open(member.path(), "pass", accepted(id)).unwrap();
            assert_eq!(engine.checkpoint(), pending);
            engine.synchronize(&mut anchor).unwrap();
            assert_eq!(engine.phase(), CeremonyPhase::Round1Saved);
            let round1 = engine.outgoing().unwrap().get(&id).unwrap();
            let body = identity
                .verify_round1(&identity.public(), &[78; 32], round1)
                .unwrap();
            let package = reddsa_frost::frost::redpallas::keys::dkg::round1::Package::deserialize(&body[64..]).unwrap();
            assert_eq!(package.commitment().serialize().unwrap().len(), threshold as usize);
            let checkpoint = engine.checkpoint();
            let ciphertext = engine.prepared_delivery().unwrap().to_vec();
            drop(engine);
            let mut engine = SetupCeremony::open(member.path(), "pass", accepted(id)).unwrap();
            engine.synchronize(&mut anchor).unwrap();
            assert_eq!(engine.checkpoint(), checkpoint);
            assert_eq!(engine.prepared_delivery().unwrap(), ciphertext);
            paths.insert(id, member.path().to_owned());
            anchors.insert(id, anchor);
            engines.insert(id, engine);
        }
        for next in [
            CeremonyPhase::Round2Saved,
            CeremonyPhase::CertificateSaved,
            CeremonyPhase::AwaitingBackups,
        ] {
            let mut deliveries: BTreeMap<u16, Vec<CeremonyRecord>> = BTreeMap::new();
            for (&id, engine) in &engines {
                for (&recipient, bytes) in engine.outgoing().unwrap() {
                    deliveries
                        .entry(recipient)
                        .or_default()
                        .push(CeremonyRecord {
                            phase: engine.phase(),
                            author: id,
                            bytes: bytes.clone(),
                        });
                }
            }
            for id in 1..=count {
                let mut engine = engines.remove(&id).unwrap();
                engine
                    .step_with_preparation(&deliveries[&id], |_, _| Ok(vec![next as u8; 64]))
                    .unwrap();
                engine.synchronize(anchors.get_mut(&id).unwrap()).unwrap();
                assert_eq!(engine.phase(), next);
                let checkpoint = engine.checkpoint();
                let outbound = engine.outgoing().unwrap().clone();
                let prepared = engine.prepared_delivery().unwrap().to_vec();
                drop(engine);
                let mut engine = SetupCeremony::open(&paths[&id], "pass", accepted(id)).unwrap();
                engine.synchronize(anchors.get_mut(&id).unwrap()).unwrap();
                assert_eq!(engine.checkpoint(), checkpoint);
                assert_eq!(engine.outgoing().unwrap(), &outbound);
                assert_eq!(engine.prepared_delivery().unwrap(), prepared);
                engines.insert(id, engine);
            }
        }
        let addresses: Vec<_> = engines
            .values()
            .map(|e| e.certified_address().unwrap())
            .collect();
        assert!(addresses.iter().all(|a| a == &addresses[0]));
        let mut keys = BTreeMap::new();
        let mut group = None;
        for id in 1..=count {
            let engine = engines.get_mut(&id).unwrap();
            let state = engine.certified_vault_state().unwrap();
            let state_json: serde_json::Value = serde_json::from_slice(&state).unwrap();
            assert_eq!(state_json["threshold"], threshold);
            let key = reddsa_frost::frost::redpallas::keys::KeyPackage::deserialize(
                &hex::decode(state_json["key_package"].as_str().unwrap()).unwrap(),
            ).unwrap();
            let public = reddsa_frost::frost::redpallas::keys::PublicKeyPackage::deserialize(
                &hex::decode(state_json["public_package"].as_str().unwrap()).unwrap(),
            ).unwrap();
            assert_eq!(*key.min_signers(), threshold);
            assert_eq!(public.min_signers(), Some(threshold));
            keys.insert(id, key);
            group = Some(public);
            let before = engine.checkpoint();
            let premature = (1..=count).map(|slot| (slot, vec![slot as u8; 32]))
                .collect::<BTreeMap<_, _>>();
            assert!(engine.begin_payment_handoff(&premature,
                |_, _| panic!("handoff must wait for every backup receipt")).is_err());
            assert_eq!(engine.checkpoint(), before);
            let mut wrong = state.to_vec();
            wrong[0] ^= 1;
            assert!(engine
                .confirm_local_backup(&wrong, |_, _| Ok(vec![]))
                .is_err());
            engine
                .confirm_local_backup(&state, |_, _| Ok(vec![id as u8; 48]))
                .unwrap();
            engine.synchronize(anchors.get_mut(&id).unwrap()).unwrap();
        }
        let mut backups: BTreeMap<u16, Vec<CeremonyRecord>> = BTreeMap::new();
        for (&id, engine) in &engines {
            for (&recipient, wire) in engine.outgoing().unwrap() {
                backups.entry(recipient).or_default().push(CeremonyRecord {
                    phase: CeremonyPhase::AwaitingBackups,
                    author: id,
                    bytes: wire.clone(),
                });
            }
        }
        for id in 1..=count {
            let mut engine = engines.remove(&id).unwrap();
            let original = engine.certified_vault_state().unwrap();
            engine.step(&backups[&id]).unwrap();
            engine.synchronize(anchors.get_mut(&id).unwrap()).unwrap();
            assert_eq!(engine.phase(), CeremonyPhase::Certified);
            drop(engine);
            let mut engine = SetupCeremony::open(&paths[&id], "pass", accepted(id)).unwrap();
            engine.synchronize(anchors.get_mut(&id).unwrap()).unwrap();
            assert_eq!(&*engine.certified_vault_state().unwrap(), &*original);
            assert_eq!(engine.backup_receipts().unwrap().len(), count as usize);
            let before = engine.checkpoint();
            let outgoing = (1..=count).map(|recipient| (recipient, vec![id as u8, recipient as u8]))
                .collect::<BTreeMap<_, _>>();
            let mut missing = outgoing.clone();
            missing.remove(&count);
            assert!(engine.begin_payment_handoff(&missing,
                |_, _| panic!("incomplete audience must fail before preparation")).is_err());
            assert!(engine.begin_payment_handoff(&outgoing, |_, _| Ok(vec![])).is_err());
            assert_eq!(engine.checkpoint(), before);
            let prepared = vec![id as u8; 48];
            engine.begin_payment_handoff(&outgoing, |phase, copies| {
                assert_eq!(phase, CeremonyPhase::PaymentHandoff);
                assert_eq!(copies, &outgoing);
                Ok(prepared.clone())
            }).unwrap();
            assert_eq!(engine.phase(), CeremonyPhase::PaymentHandoff);
            let checkpoint = engine.checkpoint();
            assert_eq!(checkpoint.generation, before.generation + 1);
            assert_eq!(checkpoint.predecessor, before.digest);
            assert!(engine.outgoing().is_err());
            assert!(engine.prepared_delivery().is_err());
            anchors.get_mut(&id).unwrap().lose_next_reply = true;
            assert!(engine.synchronize(anchors.get_mut(&id).unwrap()).is_err());
            drop(engine);
            let mut engine = SetupCeremony::open(&paths[&id], "pass", accepted(id)).unwrap();
            engine.synchronize(anchors.get_mut(&id).unwrap()).unwrap();
            assert_eq!(engine.checkpoint(), checkpoint);
            assert_eq!(engine.outgoing().unwrap(), &outgoing);
            assert_eq!(engine.prepared_delivery().unwrap(), prepared);
            engine.begin_payment_handoff(&outgoing,
                |_, _| panic!("a saved handoff must replay its exact ciphertext")).unwrap();
            let mut changed = outgoing.clone();
            changed.get_mut(&1).unwrap().push(99);
            assert!(engine.begin_payment_handoff(&changed,
                |_, _| panic!("conflicting handoff must never prepare new ciphertext")).is_err());
            engine.step(&[]).unwrap();
            assert_eq!(engine.checkpoint(), checkpoint);
            assert_eq!(&*engine.certified_vault_state().unwrap(), &*original);
            assert_eq!(engine.backup_receipts().unwrap().len(), count as usize);
            engines.insert(id, engine);
        }
        drop(engines);
        std::fs::remove_dir_all(root).unwrap();
        sign_with_quorum(&keys, &group.unwrap(), threshold, count);
    }
}

fn sign_with_quorum(
    keys: &BTreeMap<u16, reddsa_frost::frost::redpallas::keys::KeyPackage>,
    public: &reddsa_frost::frost::redpallas::keys::PublicKeyPackage,
    threshold: u16,
    count: u16,
) {
    use reddsa_frost::frost::redpallas as frost;
    let quorum: Vec<u16> = (count - threshold + 1..=count).collect();
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for id in &quorum {
        let (nonce, commitment) = frost::round1::commit(keys[id].signing_share(), &mut rand_core::OsRng);
        let identifier = frost::Identifier::try_from(*id).unwrap();
        nonces.insert(identifier, nonce);
        commitments.insert(identifier, commitment);
    }
    let message = b"hosted t-of-n signing";
    let package = frost::SigningPackage::new(commitments.clone(), message);
    let (params, seed) = frost_rerandomized::RandomizedParams::new_from_commitments(
        public.verifying_key(),
        &commitments,
        rand_core::OsRng,
    )
    .unwrap();
    let shares: BTreeMap<_, _> = quorum
        .iter()
        .map(|id| {
            let identifier = frost::Identifier::try_from(*id).unwrap();
            let share = frost_rerandomized::sign_with_randomizer_seed(
                &package,
                &nonces[&identifier],
                &keys[id],
                &seed,
            )
            .unwrap();
            (identifier, share)
        })
        .collect();
    let signature = frost_rerandomized::aggregate(&package, &shares, public, &params).unwrap();
    params
        .randomized_verifying_key()
        .verify(message, &signature)
        .unwrap_or_else(|e| panic!("{threshold}-of-{count} signature: {e}"));
}

#[test]
fn initial_start_intent_and_deleted_ready_marker_cannot_authorize_regeneration() {
    use loki_poc::{
        member_state::Roster,
        setup_ceremony::{
            AcceptedCeremonyRoster, CeremonyPhase, CheckpointAuthority, CheckpointState,
            SavedCheckpoint, SetupCeremony,
        },
        setup_transport::Identity,
        state::MemberDir,
    };
    struct Current {
        expected: Option<SavedCheckpoint>,
        terminal: bool,
    }
    impl CheckpointAuthority for Current {
        fn reconcile(&mut self, checkpoint: &SavedCheckpoint) -> Result<CheckpointState, String> {
            let expected = self.expected.get_or_insert_with(|| checkpoint.clone());
            Ok(CheckpointState {
                generation: expected.generation,
                digest: expected.digest,
                terminal: self.terminal,
            })
        }
    }
    for count in [3u16, 4] {
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "loki-start-boundary-{}",
            hex::encode(Identity::new(1).public().signing)
        ));
        let identities: Vec<_> = (1..=count).map(Identity::new).collect();
        let document=serde_json::to_vec(&serde_json::json!({"vault":hex::encode([71;32]),"threshold":2,"members":identities.iter().map(|i|{let p=i.public();serde_json::json!({"id":p.id,"signing":hex::encode(p.signing),"encryption":hex::encode(p.encryption)})}).collect::<Vec<_>>()})).unwrap();
        let accepted = |case: u8| {
            let mut data: serde_json::Value = serde_json::from_slice(&document).unwrap();
            data["vault"] = serde_json::Value::String(hex::encode([case; 32]));
            let roster = Roster::from_bytes(&serde_json::to_vec(&data).unwrap()).unwrap();
            let payload =
                AcceptedCeremonyRoster::agreement_payload(&roster, "regtest", &[73; 32]).unwrap();
            let votes = identities
                .iter()
                .map(|i| {
                    (
                        i.public().id,
                        i.sign_setup_agreement(&[case; 32], &payload).unwrap(),
                    )
                })
                .collect();
            AcceptedCeremonyRoster::verify(roster, "regtest", [73; 32], &identities[0], &votes)
                .unwrap()
        };
        let member = MemberDir::create(&root, "member").unwrap();
        MemberDir::create(member.path(), "secrets")
            .unwrap()
            .write_sealed("identity.sealed", &identities[0].to_secret_bytes(), "pass")
            .unwrap();
        let mut engine = SetupCeremony::open(member.path(), "pass", accepted(71)).unwrap();
        assert!(SetupCeremony::open(member.path(), "pass", accepted(71)).is_err());
        let initial = engine.checkpoint();
        let mut authority = Current {
            expected: None,
            terminal: false,
        };
        engine.synchronize(&mut authority).unwrap();
        drop(engine);
        assert!(SetupCeremony::open(member.path(), "wrong", accepted(71)).is_err());
        std::fs::remove_file(
            member
                .path()
                .join("setup-ceremony/generation-00000001.sealed"),
        )
        .unwrap();
        let mut engine = SetupCeremony::open(member.path(), "pass", accepted(71)).unwrap();
        assert_ne!(engine.checkpoint(), initial);
        assert!(engine.synchronize(&mut authority).is_err());
        assert!(engine.step(&[]).is_err());
        assert!(engine.outgoing().is_err());
        drop(engine);
        assert!(SetupCeremony::open(member.path(), "pass", accepted(71)).is_err());
        let terminal_member = MemberDir::create(&root, "terminal-member").unwrap();
        MemberDir::create(terminal_member.path(), "secrets")
            .unwrap()
            .write_sealed("identity.sealed", &identities[0].to_secret_bytes(), "pass")
            .unwrap();
        let mut engine = SetupCeremony::open(terminal_member.path(), "pass", accepted(72)).unwrap();
        let mut terminal = Current {
            expected: None,
            terminal: true,
        };
        assert!(engine.synchronize(&mut terminal).is_err());
        drop(engine);
        assert!(SetupCeremony::open(terminal_member.path(), "pass", accepted(72)).is_err());
        let starting_member = MemberDir::create(&root, "starting-member").unwrap();
        MemberDir::create(starting_member.path(), "secrets")
            .unwrap()
            .write_sealed("identity.sealed", &identities[0].to_secret_bytes(), "pass")
            .unwrap();
        let mut engine = SetupCeremony::open(starting_member.path(), "pass", accepted(73)).unwrap();
        let mut owned = Current {
            expected: None,
            terminal: false,
        };
        engine.synchronize(&mut owned).unwrap();
        engine.step(&[]).unwrap();
        assert_eq!(engine.phase(), CeremonyPhase::Starting);
        let starting = engine.checkpoint();
        assert_ne!(starting.digest, initial.digest);
        drop(engine);
        assert!(SetupCeremony::open(starting_member.path(), "pass", accepted(73)).is_err());
        std::fs::remove_dir_all(root).unwrap();
    }
}
