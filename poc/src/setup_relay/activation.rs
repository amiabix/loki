use super::payment::SavedPaymentHandoff;
use super::*;
use crate::relay_member::{ConfigStore, LoadedMember};
use loki_relay_client::{AcceptedSetupRoster, ClientStore, ConfigReference};
pub(super) struct SavedActivation {
    handoff: Zeroizing<Vec<u8>>,
    reference: ConfigReference,
    pub(super) request: Vec<u8>,
    delivery: Vec<u8>,
}
impl SavedActivation {
    fn records(
        &self,
        member: &LoadedMember,
        operators: &OperatorSet,
        accepted: &AcceptedSetupRoster,
        transport: &SetupTransport<'_>,
    ) -> Result<SecretRecords, String> {
        let handoff =
            SavedPaymentHandoff::decode(&self.handoff, member, operators, accepted, transport)?;
        let request = signed_request(&self.request, &member.identity)?;
        if request.device != member.identity.public()
            || request.operation == [0; 32]
            || request.command
                != (AdmissionCommand::Terminal {
                    ceremony: member.roster.vault,
                    kind: 2,
                })
            || self.reference.revision() != 1
            || self.reference.hash() == &[0; 32]
        {
            return Err(ERROR.into());
        }
        let prepared = transport
            .restore_prepared(&handoff.delivery)
            .map_err(|_| ERROR)?;
        let policy = accepted.context().policy();
        Ok(SecretRecords(
            member
                .roster
                .members
                .iter()
                .map(|peer| {
                    Ok(SetupRecord {
                        version: 1,
                        key: SetupKey {
                            ceremony: policy.ceremony,
                            phase: SetupPhase::Activation,
                            author: member.identity.public().id,
                            recipient: peer.id,
                            revision: 1,
                        },
                        network: policy.network.clone(),
                        threshold: policy.threshold,
                        member_count: policy.member_count,
                        roster_digest: Some(*accepted.digest()),
                        prerequisites: vec![prepared
                            .recipient_digest(peer.id)
                            .map_err(|_| ERROR)?],
                        payload: self.request.clone(),
                    })
                })
                .collect::<Result<_, String>>()?,
        ))
    }
    pub(super) fn prepare(
        handoff: &[u8],
        reference: ConfigReference,
        member: &LoadedMember,
        operators: &OperatorSet,
        accepted: &AcceptedSetupRoster,
        transport: &SetupTransport<'_>,
    ) -> Result<Self, String> {
        let request = sign_admission_request(
            &member.identity,
            &AdmissionRequest {
                operation: random(),
                device: member.identity.public(),
                command: AdmissionCommand::Terminal {
                    ceremony: member.roster.vault,
                    kind: 2,
                },
            },
        )
        .map_err(|_| ERROR)?;
        let mut saved = Self {
            handoff: Zeroizing::new(handoff.to_vec()),
            reference,
            request,
            delivery: Vec::new(),
        };
        let records = saved.records(member, operators, accepted, transport)?;
        saved.delivery = transport
            .checkpoint_prepared(&transport.prepare(&records.0).map_err(|_| ERROR)?)
            .map_err(|_| ERROR)?;
        Ok(saved)
    }
    fn validate(
        &self,
        member: &LoadedMember,
        operators: &OperatorSet,
        accepted: &AcceptedSetupRoster,
        transport: &SetupTransport<'_>,
    ) -> Result<(), String> {
        let prepared = transport
            .restore_prepared(&self.delivery)
            .map_err(|_| ERROR)?;
        for record in &self.records(member, operators, accepted, transport)?.0 {
            let digest: [u8; 32] = Sha256::digest(
                loki_relay_protocol::setup::encode_record(record).map_err(|_| ERROR)?,
            )
            .into();
            if prepared
                .recipient_digest(record.key.recipient)
                .map_err(|_| ERROR)?
                != digest
            {
                return Err(ERROR.into());
            }
        }
        Ok(())
    }
    pub(super) fn encode(
        &self,
        member: &LoadedMember,
        operators: &OperatorSet,
        accepted: &AcceptedSetupRoster,
        transport: &SetupTransport<'_>,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        self.validate(member, operators, accepted, transport)?;
        let value = PrivateValue(Value::Array(vec![
            Value::Integer(1.into()),
            Value::Bytes(self.handoff.to_vec()),
            Value::Integer(self.reference.revision().into()),
            Value::Bytes(self.reference.hash().to_vec()),
            Value::Bytes(self.request.clone()),
            Value::Bytes(self.delivery.clone()),
        ]));
        canonical::encode(&value.0)
            .map(Zeroizing::new)
            .map_err(|_| ERROR.into())
    }
    pub(super) fn decode(
        raw: &[u8],
        member: &LoadedMember,
        operators: &OperatorSet,
        accepted: &AcceptedSetupRoster,
        transport: &SetupTransport<'_>,
    ) -> Result<Self, String> {
        let value = PrivateValue(canonical::decode(raw, 8 * 1024 * 1024).map_err(|_| ERROR)?);
        let Value::Array(fields) = &value.0 else {
            return Err(ERROR.into());
        };
        if fields.len() != 6 || fields[0] != Value::Integer(1.into()) {
            return Err(ERROR.into());
        }
        let (
            Value::Bytes(handoff),
            Value::Integer(revision),
            Value::Bytes(hash),
            Value::Bytes(request),
            Value::Bytes(delivery),
        ) = (&fields[1], &fields[2], &fields[3], &fields[4], &fields[5])
        else {
            return Err(ERROR.into());
        };
        let saved = Self {
            handoff: Zeroizing::new(handoff.clone()),
            reference: ConfigReference::new(
                u64::try_from(*revision).map_err(|_| ERROR)?,
                hash.as_slice().try_into().map_err(|_| ERROR)?,
            )
            .map_err(|_| ERROR)?,
            request: request.clone(),
            delivery: delivery.clone(),
        };
        saved.validate(member, operators, accepted, transport)?;
        if saved
            .encode(member, operators, accepted, transport)?
            .as_slice()
            != raw
        {
            return Err(ERROR.into());
        }
        Ok(saved)
    }
}
impl HostedSetup {
    pub(super) fn activation_step(
        &self,
        engine: &mut SetupCeremony,
        store: &mut SetupStore,
        transport: &SetupTransport<'_>,
        routes: &SetupRoutes,
        accepted: &AcceptedSetupRoster,
        may_drive: bool,
    ) -> Result<HandoffStatus, String> {
        if engine.phase() != CeremonyPhase::Active {
            return Err("setup_payment_pending".into());
        }
        let member = LoadedMember {
            identity: Self::identity(&self.root, &self.passphrase)?,
            roster: accepted.roster().clone(),
            threshold: accepted.context().policy().threshold,
        };
        let saved = SavedActivation::decode(
            engine.prepared_delivery()?,
            &member,
            &self.operators,
            accepted,
            transport,
        )?;
        let outgoing = member
            .roster
            .members
            .iter()
            .map(|peer| (peer.id, saved.request.clone()))
            .collect::<BTreeMap<_, _>>();
        if engine.outgoing()? != &outgoing {
            return Err("setup_payment_conflict".into());
        }
        let mut handoff = SavedPaymentHandoff::decode(
            &saved.handoff,
            &member,
            &self.operators,
            accepted,
            transport,
        )?;
        for peer in &member.roster.members {
            let record = store
                .receive(
                    transport,
                    &SetupKey {
                        ceremony: member.roster.vault,
                        phase: SetupPhase::PaymentDescriptor,
                        author: peer.id,
                        recipient: member.identity.public().id,
                        revision: 1,
                    },
                )
                .map_err(|_| "setup_transport")?
                .ok_or("setup_payment_descriptor")?;
            if peer.id != member.identity.public().id {
                handoff
                    .intent
                    .config
                    .import(&member, &record.body().payload)
                    .map_err(|_| "setup_payment_descriptor")?;
            }
        }
        let db = ClientStore::open(
            &self.root.join("transport"),
            &member.roster,
            member.identity.public().id,
        )
        .map_err(|_| "setup_payment_store")?;
        if db
            .config_reference()
            .map_err(|_| "setup_payment_store")?
            .as_ref()
            != Some(&saved.reference)
        {
            return Err("setup_payment_conflict".into());
        }
        let config = ConfigStore::open_with_passphrase(&self.root, &self.passphrase)
            .map_err(|_| "setup_payment_store")?
            .load(&db, &member)
            .map_err(|_| "setup_payment_store")?
            .ok_or("setup_payment_store")?;
        if config.encode(&member, 1).map_err(|_| ERROR)?.as_slice()
            != handoff
                .intent
                .config
                .encode(&member, 1)
                .map_err(|_| ERROR)?
                .as_slice()
        {
            return Err("setup_payment_conflict".into());
        }
        drop(db);
        let prepared = transport
            .restore_prepared(&saved.delivery)
            .map_err(|_| "setup_transport")?;
        let state_before_drive = self.state()?.ok_or("setup_admission_pending")?;
        let AdmissionOutcome::Accepted(Value::Array(state_fields)) = state_before_drive.outcome()
        else {
            return Err("setup_activation".into());
        };
        if state_fields.len() != 7 {
            return Err("setup_activation".into());
        }
        let Value::Integer(terminal) = state_fields[3] else {
            return Err("setup_activation".into());
        };
        let terminal = u16::try_from(terminal).map_err(|_| "setup_activation")?;
        if matches!(terminal, 1 | 3 | 4) {
            return Ok(HandoffStatus {
                ready: false,
                missing_slots: (1..=self.context.count).collect(),
            });
        }
        if !matches!(terminal, 0 | 2) {
            return Err("setup_activation".into());
        }
        let already_activated = terminal == 2;
        store
            .commit_outgoing(transport, &prepared)
            .map_err(|_| "setup_transport")?;
        if may_drive && !already_activated {
            self.runtime
                .block_on(transport.drive_once_with(store, routes, &self.net))
                .map_err(|_| "setup_transport")?;
        }
        let key = SetupKey {
            ceremony: member.roster.vault,
            phase: SetupPhase::Activation,
            author: member.identity.public().id,
            recipient: member.identity.public().id,
            revision: 1,
        };
        let mut requests = BTreeMap::new();
        let mut missing_slots = Vec::new();
        for peer in &member.roster.members {
            if let Some(record) = store
                .receive(
                    transport,
                    &SetupKey {
                        author: peer.id,
                        ..key.clone()
                    },
                )
                .map_err(|_| "setup_transport")?
            {
                requests.insert(peer.id, record.body().payload.clone());
            } else {
                missing_slots.push(peer.id);
            }
        }
        let pending = HandoffStatus {
            ready: false,
            missing_slots,
        };
        let progress = store
            .progress_for(transport, routes, &key)
            .map_err(|_| "setup_transport")?;
        if !pending.missing_slots.is_empty() || progress.stored_groups != 1 {
            return Ok(pending);
        }
        if may_drive && !already_activated {
            match self.execute_admission(&saved.request, None, false) {
                Ok(reply) if matches!(reply.outcome(),AdmissionOutcome::Accepted(Value::Integer(n)) if u64::try_from(*n).is_ok_and(|n|n>=1&&n<=u64::from(self.context.count))) => {
                    ()
                }
                Err(loki_relay_client::ClientError::Transport) => return Ok(pending),
                _ => return Err("setup_activation".into()),
            }
        }
        let Some(state) = self.state()? else {
            return Ok(pending);
        };
        let AdmissionOutcome::Accepted(Value::Array(fields)) = state.outcome() else {
            return Err("setup_activation".into());
        };
        if fields.len() != 7
            || fields[0] != Value::Integer(self.context.count.into())
            || self.validate_claims(&fields[4])? != member.roster.members
        {
            return Err("setup_activation".into());
        }
        if fields[3] == Value::Integer(0.into()) {
            return Ok(pending);
        }
        if fields[3] != Value::Integer(2.into()) {
            return Err("setup_activation".into());
        }
        let query = sign_admission_request(
            &self.identity,
            &AdmissionRequest {
                operation: random(),
                device: self.identity.public(),
                command: AdmissionCommand::TerminalNotice {
                    ceremony: member.roster.vault,
                    kind: 0,
                },
            },
        )
        .map_err(|_| ERROR)?;
        let reply = match self.execute_admission(&query, None, false) {
            Ok(reply) => reply,
            Err(loki_relay_client::ClientError::Transport) => return Ok(pending),
            Err(_) => return Err("setup_activation".into()),
        };
        let notices = loki_relay_client::verify_terminal_notices(
            &member.roster.vault,
            &member.roster.members,
            &reply,
        )
        .map_err(|_| "setup_activation")?;
        if notices.terminal_kind() != 2
            || notices.notifying_members()
                != member
                    .roster
                    .members
                    .iter()
                    .map(|p| p.id)
                    .collect::<Vec<_>>()
                    .as_slice()
        {
            return Err("setup_activation".into());
        }
        let AdmissionOutcome::Accepted(Value::Array(notice_fields)) = reply.outcome() else {
            return Err("setup_activation".into());
        };
        let Value::Array(rows) = &notice_fields[1] else {
            return Err("setup_activation".into());
        };
        for (slot, row) in notices.notifying_members().iter().zip(rows) {
            let Value::Bytes(package) = row else {
                return Err("setup_activation".into());
            };
            if requests.get(slot) != Some(package) {
                return Err("setup_activation".into());
            }
        }
        self.install_activated_state(engine, accepted)?;
        store
            .clear_retries_for_stored_routes()
            .map_err(|_| "setup_transport")?;
        Ok(HandoffStatus {
            ready: true,
            missing_slots: Vec::new(),
        })
    }
    fn install_activated_state(
        &self,
        engine: &SetupCeremony,
        accepted: &AcceptedSetupRoster,
    ) -> Result<(), String> {
        let state = engine.certified_vault_state()?;
        let secrets = MemberDir::open(&self.root, "secrets");
        let marker = engine.activation_marker()?;
        for (name, expected) in [
            ("vault.sealed", state.as_slice()),
            ("activation.sealed", marker.as_slice()),
        ] {
            if secrets.exists(name) {
                let stored = Zeroizing::new(
                    secrets
                        .read_sealed(name, &self.passphrase)
                        .map_err(|_| ERROR)?,
                );
                if stored.as_slice() != expected {
                    return Err("setup_payment_conflict".into());
                }
            } else {
                secrets
                    .write_sealed(name, expected, &self.passphrase)
                    .map_err(|_| ERROR)?;
            }
        }
        let roster=serde_json::to_vec(&serde_json::json!({"vault":hex::encode(accepted.roster().vault),"threshold":accepted.context().policy().threshold,"members":accepted.roster().members.iter().map(|peer|serde_json::json!({"id":peer.id,"signing":hex::encode(peer.signing),"encryption":hex::encode(peer.encryption)})).collect::<Vec<_>>()})).map_err(|_| ERROR)?;
        crate::relay_member::exchange::atomic_publish(&self.root, "roster.json", &roster)
            .map_err(|_| ERROR)?;
        Ok(())
    }
}
