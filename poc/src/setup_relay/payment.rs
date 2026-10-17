use super::*;
use crate::relay_member::{CourierFile, LoadedMember, LocalConfig};
use loki_relay_client::{open_descriptor, seal_descriptor, AcceptedSetupRoster, Descriptor};
use loki_relay_protocol::types::roster_digest;
#[cfg(test)]
#[path = "../../tests/support/hosted_services.rs"]
mod hosted_services;
pub(super) struct PaymentIntent {
    pub(super) config: LocalConfig,
    pub(super) requests: Vec<Vec<u8>>,
}
impl PaymentIntent {
    pub(super) fn prepare(member: &LoadedMember, operators: &OperatorSet) -> Result<Self, String> {
        let digest = roster_digest(&member.roster).map_err(|_| ERROR)?;
        if !member.roster.members.contains(&member.identity.public()) {
            return Err(ERROR.into());
        }
        let mut unique = Zeroizing::new(Vec::<[u8; 32]>::new());
        let mut fresh = || -> Result<[u8; 32], String> {
            let value = Zeroizing::new(random());
            if *value == [0; 32] || unique.contains(&*value) {
                return Err(ERROR.into());
            }
            unique.push(*value);
            Ok(*value)
        };
        let mut config = LocalConfig::empty();
        let mut requests = Vec::new();
        for (index, operator) in operators.relay_routes().iter().enumerate() {
            let inbox = OwnerInbox {
                route: RelayRoute {
                    mailbox: fresh()?,
                    append_revision: 1,
                    ..operator.clone()
                },
                read: Secret32::from_bytes(fresh()?),
                append: Secret32::from_bytes(fresh()?),
                admin: Secret32::from_bytes(fresh()?),
            };
            requests.push(
                sign_admission_request(
                    &member.identity,
                    &AdmissionRequest {
                        operation: fresh()?,
                        device: member.identity.public(),
                        command: Self::command(member, operators, index, &inbox)?,
                    },
                )
                .map_err(|_| ERROR)?,
            );
            config.own.push(inbox);
        }
        let descriptor = Descriptor::new(
            member.roster.vault,
            digest,
            member.identity.public().id,
            1,
            config
                .own
                .iter()
                .map(|inbox| DescriptorRelay {
                    route: inbox.route.clone(),
                    append: Secret32::from_bytes(*inbox.append.as_bytes()),
                })
                .collect(),
        );
        config.self_wire = Some(
            seal_descriptor(
                &member.identity,
                &member.roster,
                &descriptor,
                &member.identity.public(),
            )
            .map_err(|_| ERROR)?
            .wire,
        );
        let authenticated = open_descriptor(
            &member.identity,
            &member.roster,
            config.self_wire.as_ref().ok_or(ERROR)?,
        )
        .map_err(|_| ERROR)?;
        for peer in &member.roster.members {
            if peer.id != member.identity.public().id {
                config
                    .couriers
                    .push(CourierFile::prepare(member, &authenticated, peer).map_err(|_| ERROR)?);
            }
        }
        let intent = Self { config, requests };
        intent.validate(member, operators)?;
        Ok(intent)
    }
    fn command(
        member: &LoadedMember,
        operators: &OperatorSet,
        index: usize,
        inbox: &OwnerInbox,
    ) -> Result<AdmissionCommand, String> {
        Ok(AdmissionCommand::Mailbox {
            ceremony: member.roster.vault,
            slot: member.identity.public().id,
            relay: index as u16 + 1,
            purpose: 2,
            mailbox: inbox.route.mailbox,
            creation: http::encode_creation(&Creation {
                read_verifier: verifier(&inbox.route.mailbox, 1, &inbox.read),
                append_verifier: verifier(&inbox.route.mailbox, 2, &inbox.append),
                admin_verifier: verifier(&inbox.route.mailbox, 3, &inbox.admin),
                quota: operators.limits().storage_bytes_per_relay
                    / member.roster.members.len() as u64,
            })
            .map_err(|_| ERROR)?,
        })
    }
    fn validate(&self, member: &LoadedMember, operators: &OperatorSet) -> Result<(), String> {
        self.config.authenticated(member).map_err(|_| ERROR)?;
        let descriptor = open_descriptor(
            &member.identity,
            &member.roster,
            self.config.self_wire.as_ref().ok_or(ERROR)?,
        )
        .map_err(|_| ERROR)?;
        if descriptor.body().revision != 1 {
            return Err(ERROR.into());
        }
        if self.config.own.len() != 3
            || self.requests.len() != 3
            || operators.relay_routes().len() != 3
            || self.config.couriers.len() != member.roster.members.len() - 1
            || !self.config.peer_wires.is_empty()
            || !self.config.pending.is_empty()
            || self.config.operation.is_some()
            || self.config.provisioned.is_some()
            || self.config.rotated.is_some()
            || self.config.predecessor.is_some()
        {
            return Err(ERROR.into());
        }
        let mut unique = Zeroizing::new(Vec::<[u8; 32]>::new());
        for (index, (inbox, operator)) in self
            .config
            .own
            .iter()
            .zip(operators.relay_routes())
            .enumerate()
        {
            if inbox.route
                != (RelayRoute {
                    mailbox: inbox.route.mailbox,
                    append_revision: 1,
                    ..operator.clone()
                })
            {
                return Err(ERROR.into());
            }
            let request = signed_request(&self.requests[index], &member.identity)?;
            if request.device != member.identity.public()
                || request.command != Self::command(member, operators, index, inbox)?
            {
                return Err(ERROR.into());
            }
            for value in [
                &inbox.route.mailbox,
                inbox.read.as_bytes(),
                inbox.append.as_bytes(),
                inbox.admin.as_bytes(),
                &request.operation,
            ] {
                if *value == [0; 32] || unique.contains(value) {
                    return Err(ERROR.into());
                }
                unique.push(*value);
            }
        }
        self.outgoing(member)?;
        Ok(())
    }
    pub(super) fn outgoing(&self, member: &LoadedMember) -> Result<BTreeMap<u16, Vec<u8>>, String> {
        let mut outgoing = BTreeMap::from([(
            member.identity.public().id,
            self.config.self_wire.as_ref().ok_or(ERROR)?.clone(),
        )]);
        for courier in &self.config.couriers {
            if outgoing
                .insert(courier.peer(), courier.wire().to_vec())
                .is_some()
            {
                return Err(ERROR.into());
            }
        }
        if outgoing.keys().copied().collect::<BTreeSet<_>>()
            != member.roster.members.iter().map(|m| m.id).collect()
        {
            return Err(ERROR.into());
        }
        Ok(outgoing)
    }
    pub(super) fn encode(
        &self,
        member: &LoadedMember,
        operators: &OperatorSet,
    ) -> Result<Zeroizing<Vec<u8>>, String> {
        self.validate(member, operators)?;
        let config = self.config.encode(member, 1).map_err(|_| ERROR)?;
        let value = PrivateValue(Value::Array(vec![
            Value::Integer(1.into()),
            Value::Bytes(operators.digest().to_vec()),
            Value::Bytes(roster_digest(&member.roster).map_err(|_| ERROR)?.to_vec()),
            Value::Integer(member.identity.public().id.into()),
            Value::Bytes(config.to_vec()),
            Value::Array(
                self.requests
                    .iter()
                    .map(|r| Value::Bytes(r.clone()))
                    .collect(),
            ),
        ]));
        canonical::encode(&value.0)
            .map(Zeroizing::new)
            .map_err(|_| ERROR.into())
    }
    pub(super) fn decode(
        bytes: &[u8],
        member: &LoadedMember,
        operators: &OperatorSet,
    ) -> Result<Self, String> {
        let value = PrivateValue(canonical::decode(bytes, 2 * 1024 * 1024).map_err(|_| ERROR)?);
        let Value::Array(fields) = &value.0 else {
            return Err(ERROR.into());
        };
        if fields.len() != 6
            || fields[0] != Value::Integer(1.into())
            || fields[1] != Value::Bytes(operators.digest().to_vec())
            || fields[2] != Value::Bytes(roster_digest(&member.roster).map_err(|_| ERROR)?.to_vec())
            || fields[3] != Value::Integer(member.identity.public().id.into())
        {
            return Err(ERROR.into());
        }
        let (Value::Bytes(config), Value::Array(requests)) = (&fields[4], &fields[5]) else {
            return Err(ERROR.into());
        };
        if requests.len() != 3 {
            return Err(ERROR.into());
        }
        let requests = requests
            .iter()
            .map(|r| match r {
                Value::Bytes(r) if r.len() <= admission::MAX_REQUEST => Ok(r.clone()),
                _ => Err(ERROR.to_owned()),
            })
            .collect::<Result<_, _>>()?;
        let intent = Self {
            config: LocalConfig::decode(member, 1, config).map_err(|_| ERROR)?,
            requests,
        };
        intent.validate(member, operators)?;
        Ok(intent)
    }
}
pub(super) struct SavedPaymentHandoff {
    pub(super) intent: PaymentIntent,
    pub(super) delivery: Vec<u8>,
    parents: BTreeMap<u16, Vec<[u8; 32]>>,
}
impl SavedPaymentHandoff {
    fn records(
        &self,
        member: &LoadedMember,
        operators: &OperatorSet,
        accepted: &AcceptedSetupRoster,
    ) -> Result<Vec<SetupRecord>, String> {
        self.intent.validate(member, operators)?;
        let policy = accepted.context().policy();
        let outgoing = self.intent.outgoing(member)?;
        if accepted.roster() != &member.roster
            || policy.config_digest != *operators.digest()
            || self.parents.keys().copied().collect::<Vec<_>>()
                != outgoing.keys().copied().collect::<Vec<_>>()
        {
            return Err(ERROR.into());
        }
        outgoing
            .into_iter()
            .map(|(recipient, payload)| {
                let parents = &self.parents[&recipient];
                if parents.is_empty()
                    || parents.len() > 4
                    || parents.contains(&[0; 32])
                    || parents.windows(2).any(|p| p[0] >= p[1])
                {
                    return Err(ERROR.into());
                }
                Ok(SetupRecord {
                    version: 1,
                    key: SetupKey {
                        ceremony: policy.ceremony,
                        phase: SetupPhase::PaymentDescriptor,
                        author: member.identity.public().id,
                        recipient,
                        revision: 1,
                    },
                    network: policy.network.clone(),
                    threshold: 2,
                    member_count: policy.member_count,
                    roster_digest: Some(*accepted.digest()),
                    prerequisites: parents.clone(),
                    payload,
                })
            })
            .collect()
    }
    pub(super) fn prepare(
        intent: PaymentIntent,
        member: &LoadedMember,
        operators: &OperatorSet,
        accepted: &AcceptedSetupRoster,
        transport: &SetupTransport<'_>,
        parents: &BTreeMap<u16, Vec<[u8; 32]>>,
    ) -> Result<Self, String> {
        let mut saved = Self {
            intent,
            delivery: Vec::new(),
            parents: parents.clone(),
        };
        let records = SecretRecords(saved.records(member, operators, accepted)?);
        let prepared = transport.prepare(&records.0).map_err(|_| ERROR)?;
        saved.delivery = transport
            .checkpoint_prepared(&prepared)
            .map_err(|_| ERROR)?;
        saved.validate(member, operators, accepted, transport)?;
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
        let records = SecretRecords(self.records(member, operators, accepted)?);
        for record in &records.0 {
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
        let (root, objects) = prepared
            .recipient_objects(member.identity.public().id)
            .map_err(|_| ERROR)?;
        let own = transport
            .authenticate_objects(&root, &objects)
            .map_err(|_| ERROR)?;
        if !records.0.contains(own.body()) {
            return Err(ERROR.into());
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
        let intent = self.intent.encode(member, operators)?;
        let value = PrivateValue(Value::Array(vec![
            Value::Integer(1.into()),
            Value::Bytes(intent.to_vec()),
            Value::Bytes(self.delivery.clone()),
            Value::Array(
                self.parents
                    .iter()
                    .map(|(recipient, parents)| {
                        Value::Array(vec![
                            Value::Integer((*recipient).into()),
                            Value::Array(
                                parents.iter().map(|p| Value::Bytes(p.to_vec())).collect(),
                            ),
                        ])
                    })
                    .collect(),
            ),
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
        if fields.len() != 4 || fields[0] != Value::Integer(1.into()) {
            return Err(ERROR.into());
        }
        let (Value::Bytes(intent), Value::Bytes(delivery), Value::Array(entries)) =
            (&fields[1], &fields[2], &fields[3])
        else {
            return Err(ERROR.into());
        };
        if entries.len() != member.roster.members.len() {
            return Err(ERROR.into());
        }
        let mut parents = BTreeMap::new();
        for entry in entries {
            let Value::Array(entry) = entry else {
                return Err(ERROR.into());
            };
            if entry.len() != 2 {
                return Err(ERROR.into());
            }
            let (Value::Integer(recipient), Value::Array(values)) = (&entry[0], &entry[1]) else {
                return Err(ERROR.into());
            };
            let recipient = u16::try_from(*recipient).map_err(|_| ERROR)?;
            if values.len() > 4 {
                return Err(ERROR.into());
            }
            let values = values
                .iter()
                .map(|v| match v {
                    Value::Bytes(v) => v.as_slice().try_into().map_err(|_| ERROR.to_owned()),
                    _ => Err(ERROR.to_owned()),
                })
                .collect::<Result<Vec<[u8; 32]>, String>>()?;
            if parents.insert(recipient, values).is_some() {
                return Err(ERROR.into());
            }
        }
        let saved = Self {
            intent: PaymentIntent::decode(intent, member, operators)?,
            delivery: delivery.clone(),
            parents,
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
    pub(super) fn payment_handoff_step(
        &self,
        engine: &mut SetupCeremony,
        authority: &mut AdmissionCheckpointAuthority,
        store: &mut SetupStore,
        transport: &SetupTransport<'_>,
        routes: &SetupRoutes,
        accepted: &AcceptedSetupRoster,
        may_drive: bool,
    ) -> Result<super::HandoffStatus, String> {
        if engine.phase() == CeremonyPhase::Active {
            return self.activation_step(engine, store, transport, routes, accepted, may_drive);
        }
        engine.backup_receipts()?;
        let member = LoadedMember {
            identity: Self::identity(&self.root, &self.passphrase)?,
            roster: accepted.roster().clone(),
        };
        if engine.phase() == CeremonyPhase::Certified {
            let certificate_parents = self.certificate_predecessors(transport, store)?;
            let own_backup = engine
                .backup_receipts()?
                .get(&self.context.own_slot)
                .ok_or(ERROR)?;
            let policy = accepted.context().policy();
            let parents = certificate_parents
                .into_iter()
                .map(|(recipient, prerequisites)| {
                    let record = SecretRecords(vec![SetupRecord {
                        version: 1,
                        key: SetupKey {
                            ceremony: policy.ceremony,
                            phase: SetupPhase::BackupReceipt,
                            author: self.context.own_slot,
                            recipient,
                            revision: 1,
                        },
                        network: policy.network.clone(),
                        threshold: 2,
                        member_count: policy.member_count,
                        roster_digest: Some(*accepted.digest()),
                        prerequisites,
                        payload: own_backup.clone(),
                    }]);
                    let digest = Sha256::digest(
                        loki_relay_protocol::setup::encode_record(&record.0[0])
                            .map_err(|_| ERROR)?,
                    )
                    .into();
                    Ok((recipient, vec![digest]))
                })
                .collect::<Result<BTreeMap<_, _>, String>>()?;
            let saved = SavedPaymentHandoff::prepare(
                PaymentIntent::prepare(&member, &self.operators)?,
                &member,
                &self.operators,
                accepted,
                transport,
                &parents,
            )?;
            let outgoing = saved.intent.outgoing(&member)?;
            let encoded = saved.encode(&member, &self.operators, accepted, transport)?;
            engine.begin_payment_handoff(&outgoing, |_, copies| {
                if copies != &outgoing {
                    return Err(ERROR.into());
                }
                Ok(encoded.to_vec())
            })?;
            engine.synchronize(authority)?;
        }
        if engine.phase() != CeremonyPhase::PaymentHandoff {
            return Err("setup_backups_pending".into());
        }
        let mut saved = SavedPaymentHandoff::decode(
            engine.prepared_delivery()?,
            &member,
            &self.operators,
            accepted,
            transport,
        )?;
        if engine.outgoing()? != &saved.intent.outgoing(&member)? {
            return Err("setup_payment_conflict".into());
        }
        let prepared = transport
            .restore_prepared(&saved.delivery)
            .map_err(|_| "setup_transport")?;
        store
            .commit_outgoing(transport, &prepared)
            .map_err(|_| "setup_transport")?;
        if may_drive {
            self.runtime
                .block_on(transport.drive_once_with(store, routes, &self.net))
                .map_err(|_| "setup_transport")?;
        }
        let key = SetupKey {
            ceremony: member.roster.vault,
            phase: SetupPhase::PaymentDescriptor,
            author: member.identity.public().id,
            recipient: member.identity.public().id,
            revision: 1,
        };
        let mut missing = Vec::new();
        for peer in &member.roster.members {
            let record = store
                .receive(
                    transport,
                    &SetupKey {
                        author: peer.id,
                        ..key.clone()
                    },
                )
                .map_err(|_| "setup_transport")?;
            match record {
                Some(record) => {
                    let descriptor =
                        open_descriptor(&member.identity, &member.roster, &record.body().payload)
                            .map_err(|_| "setup_payment_descriptor")?;
                    if descriptor.body().owner != peer.id
                        || descriptor.body().revision != 1
                        || descriptor
                            .body()
                            .relays
                            .iter()
                            .zip(self.operators.relay_routes())
                            .any(|(relay, operator)| {
                                relay.route
                                    != (RelayRoute {
                                        mailbox: relay.route.mailbox,
                                        append_revision: 1,
                                        ..operator.clone()
                                    })
                            })
                    {
                        return Err("setup_payment_descriptor".into());
                    }
                    if peer.id == member.identity.public().id {
                        if saved.intent.config.self_wire.as_ref() != Some(&record.body().payload) {
                            return Err("setup_payment_conflict".into());
                        }
                    } else {
                        saved
                            .intent
                            .config
                            .import(&member, &record.body().payload)
                            .map_err(|_| "setup_payment_descriptor")?;
                    }
                }
                None => missing.push(peer.id),
            }
        }
        let pending = || super::HandoffStatus {
            ready: false,
            missing_slots: missing.clone(),
        };
        let Some(reply) = self.state()? else {
            return Ok(pending());
        };
        let AdmissionOutcome::Accepted(Value::Array(state)) = reply.outcome() else {
            return Err("setup_admission".into());
        };
        if state.len() != 7
            || state[0] != Value::Integer(self.context.count.into())
            || state[3] != Value::Integer(0.into())
            || self.validate_claims(&state[4])? != member.roster.members
        {
            return Err("setup_admission".into());
        }
        let Value::Array(rows) = &state[5] else {
            return Err("setup_admission".into());
        };
        let mut registered = BTreeSet::new();
        let mut provisioned = BTreeSet::new();
        for row in rows {
            let Value::Array(fields) = row else {
                return Err("setup_admission".into());
            };
            if fields.len() != 5 {
                return Err("setup_admission".into());
            }
            if fields[1] == Value::Integer(1.into()) {
                continue;
            }
            let Value::Integer(index) = fields[0] else {
                return Err("setup_admission".into());
            };
            let index = usize::try_from(index)
                .map_err(|_| ERROR)?
                .checked_sub(1)
                .filter(|i| *i < 3)
                .ok_or(ERROR)?;
            if fields[1] != Value::Integer(2.into())
                || fields[2] != Value::Bytes(saved.intent.config.own[index].route.mailbox.to_vec())
                || fields[4] != Value::Integer(0.into())
                || !registered.insert(index)
                || !matches!(&fields[3], Value::Integer(n) if *n == 0.into() || *n == 1.into())
            {
                return Err("setup_admission".into());
            }
            if fields[3] == Value::Integer(1.into()) {
                provisioned.insert(index);
            }
        }
        if may_drive {
            // Every unregistered handoff mailbox in one step: the requests are saved and
            // signed, and a re-send is idempotent.
            let unregistered: Vec<usize> = (0..3).filter(|index| !registered.contains(index)).collect();
            if !unregistered.is_empty() {
                let packages: Vec<&[u8]> = unregistered
                    .iter()
                    .map(|index| saved.intent.requests[*index].as_slice())
                    .collect();
                for (index, reply) in unregistered.iter().zip(self.execute_admissions(&packages)) {
                    match reply {
                        Ok(reply)
                            if matches!(reply.outcome(), AdmissionOutcome::Accepted(Value::Bytes(mailbox))
                            if mailbox.as_slice() == saved.intent.config.own[*index].route.mailbox) => {}
                        Err(loki_relay_client::ClientError::Transport) => {}
                        _ => return Err("setup_admission".into()),
                    }
                }
                return Ok(pending());
            }
        }
        let progress = store
            .progress_for(transport, routes, &key)
            .map_err(|_| "setup_transport")?;
        if registered.len() != 3
            || provisioned.len() < 2
            || !missing.is_empty()
            || progress.stored_groups != 1
        {
            return Ok(pending());
        }
        let mut db = loki_relay_client::ClientStore::open(
            &self.root.join("transport"),
            &member.roster,
            member.identity.public().id,
        )
        .map_err(|_| "setup_payment_store")?;
        let config_store =
            crate::relay_member::ConfigStore::open_with_passphrase(&self.root, &self.passphrase)
                .map_err(|_| "setup_payment_store")?;
        let reference = config_store
            .install_scoped_configuration(&mut db, &member, &saved.intent.config)
            .map_err(|_| "setup_payment_store")?;
        drop(db);
        let activation = super::activation::SavedActivation::prepare(
            engine.prepared_delivery()?,
            reference,
            &member,
            &self.operators,
            accepted,
            transport,
        )?;
        let outgoing = member
            .roster
            .members
            .iter()
            .map(|peer| (peer.id, activation.request.clone()))
            .collect();
        let encoded = activation.encode(&member, &self.operators, accepted, transport)?;
        engine.begin_activation(&outgoing, |_, copies| {
            if copies != &outgoing {
                return Err("setup_payment_conflict".into());
            }
            Ok(encoded.to_vec())
        })?;
        engine.synchronize(authority)?;
        self.activation_step(engine, store, transport, routes, accepted, may_drive)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{relay_member::LoadedMember, setup_transport::Identity};
    use loki_relay_client::{sign_roster_acceptance, AcceptedSetupRoster, BootstrapContext};
    use loki_relay_protocol::setup::SetupCapabilities;
    #[test]
    fn private_payment_intent_restores_every_owner_and_exact_admission_requests() {
        let services = hosted_services::HostedServices::start();
        let operators =
            OperatorSet::verify_development(&services.bundle, &services.config_key).unwrap();
        for count in [3u16, 4] {
            let keys = Zeroizing::new(
                (1..=count)
                    .map(|id| Identity::new(id).to_secret_bytes())
                    .collect::<Vec<_>>(),
            );
            let identities = keys
                .iter()
                .map(|bytes| CommIdentity::from_serialized(bytes).unwrap())
                .collect::<Vec<_>>();
            let roster = loki_relay_protocol::types::Roster {
                vault: [count as u8 + 40; 32],
                members: identities.iter().map(CommIdentity::public).collect(),
            };
            for owner in &identities {
                let member = LoadedMember {
                    identity: CommIdentity::from_serialized(
                        &keys[usize::from(owner.public().id - 1)],
                    )
                    .unwrap(),
                    roster: roster.clone(),
                };
                let intent = PaymentIntent::prepare(&member, &operators).unwrap();
                let outgoing = intent.outgoing(&member).unwrap();
                assert_eq!(outgoing.len(), usize::from(count));
                for peer in &identities {
                    let imported =
                        open_descriptor(peer, &roster, &outgoing[&peer.public().id]).unwrap();
                    assert_eq!(imported.body().owner, owner.public().id);
                    assert_eq!(imported.body().relays.len(), 3);
                }
                let encoded = intent.encode(&member, &operators).unwrap();
                let restored = PaymentIntent::decode(&encoded, &member, &operators).unwrap();
                assert_eq!(restored.requests, intent.requests);
                assert_eq!(restored.outgoing(&member).unwrap(), outgoing);
                assert_eq!(
                    restored.encode(&member, &operators).unwrap().as_slice(),
                    encoded.as_slice()
                );
                for (saved, original) in restored.config.own.iter().zip(&intent.config.own) {
                    assert_eq!(saved.read.as_bytes(), original.read.as_bytes());
                    assert_eq!(saved.admin.as_bytes(), original.admin.as_bytes());
                }
                let other = &identities[usize::from(owner.public().id % count)];
                let wrong_owner = LoadedMember {
                    identity: CommIdentity::from_serialized(
                        &keys[usize::from(other.public().id - 1)],
                    )
                    .unwrap(),
                    roster: roster.clone(),
                };
                assert!(PaymentIntent::decode(&encoded, &wrong_owner, &operators).is_err());
                let mut wrong_roster = roster.clone();
                wrong_roster.vault[0] ^= 1;
                let wrong_context = LoadedMember {
                    identity: CommIdentity::from_serialized(
                        &keys[usize::from(owner.public().id - 1)],
                    )
                    .unwrap(),
                    roster: wrong_roster,
                };
                assert!(PaymentIntent::decode(&encoded, &wrong_context, &operators).is_err());
                let mut wrong_bundle =
                    PrivateValue(canonical::decode(&encoded, 2 * 1024 * 1024).unwrap());
                if let Value::Array(fields) = &mut wrong_bundle.0 {
                    fields[1] = Value::Bytes(vec![0; 32]);
                }
                let wrong_bundle = Zeroizing::new(canonical::encode(&wrong_bundle.0).unwrap());
                assert!(PaymentIntent::decode(&wrong_bundle, &member, &operators).is_err());
                let mut malformed = PaymentIntent::decode(&encoded, &member, &operators).unwrap();
                let mut request =
                    super::super::signed_request(&malformed.requests[0], &member.identity).unwrap();
                if let AdmissionCommand::Mailbox { purpose, .. } = &mut request.command {
                    *purpose = 1;
                }
                malformed.requests[0] = sign_admission_request(&member.identity, &request).unwrap();
                assert!(malformed.encode(&member, &operators).is_err());
                let mut reused = PaymentIntent::decode(&encoded, &member, &operators).unwrap();
                let mut request =
                    super::super::signed_request(&reused.requests[1], &member.identity).unwrap();
                request.operation =
                    super::super::signed_request(&reused.requests[0], &member.identity)
                        .unwrap()
                        .operation;
                reused.requests[1] = sign_admission_request(&member.identity, &request).unwrap();
                assert!(reused.encode(&member, &operators).is_err());
                let mut changed_cap = PaymentIntent::decode(&encoded, &member, &operators).unwrap();
                changed_cap.config.own[0].read = Secret32::from_bytes([199; 32]);
                assert!(changed_cap.encode(&member, &operators).is_err());
            }
        }
    }
    #[test]
    fn saved_payment_handoff_binds_private_intent_to_exact_transport_copies() {
        let services = hosted_services::HostedServices::start();
        let operators =
            OperatorSet::verify_development(&services.bundle, &services.config_key).unwrap();
        for count in [3u16, 4] {
            let keys = Zeroizing::new(
                (1..=count)
                    .map(|id| Identity::new(id).to_secret_bytes())
                    .collect::<Vec<_>>(),
            );
            let identities = keys
                .iter()
                .map(|bytes| CommIdentity::from_serialized(bytes).unwrap())
                .collect::<Vec<_>>();
            let roster = Roster {
                vault: [count as u8 + 60; 32],
                members: identities.iter().map(CommIdentity::public).collect(),
            };
            let context = BootstrapContext::creator(
                SetupPolicy {
                    ceremony: roster.vault,
                    network: "regtest".into(),
                    threshold: 2,
                    member_count: count,
                    config_digest: *operators.digest(),
                },
                identities[0].public(),
                &operators,
            )
            .unwrap();
            let votes = identities
                .iter()
                .map(|identity| {
                    sign_roster_acceptance(
                        identity,
                        &context,
                        &roster,
                        &SetupCapabilities::current(),
                    )
                    .unwrap()
                })
                .collect::<Vec<_>>();
            let accepted = AcceptedSetupRoster::verify(&context, roster.clone(), &votes).unwrap();
            for owner in &identities {
                let member = LoadedMember {
                    identity: CommIdentity::from_serialized(
                        &keys[usize::from(owner.public().id - 1)],
                    )
                    .unwrap(),
                    roster: roster.clone(),
                };
                let transport = SetupTransport::new(
                    owner,
                    &operators,
                    SetupAuthority::Accepted(&accepted),
                    true,
                )
                .unwrap();
                let parents = roster
                    .members
                    .iter()
                    .map(|peer| (peer.id, vec![[peer.id as u8 + 20; 32]]))
                    .collect();
                let saved = SavedPaymentHandoff::prepare(
                    PaymentIntent::prepare(&member, &operators).unwrap(),
                    &member,
                    &operators,
                    &accepted,
                    &transport,
                    &parents,
                )
                .unwrap();
                let mut broadcast =
                    SecretRecords(saved.records(&member, &operators, &accepted).unwrap());
                for record in &mut broadcast.0 {
                    record.key.phase = SetupPhase::Certificate;
                }
                assert!(transport.prepare(&broadcast.0).is_err());
                let encoded = saved
                    .encode(&member, &operators, &accepted, &transport)
                    .unwrap();
                let reopened = SavedPaymentHandoff::decode(
                    &encoded, &member, &operators, &accepted, &transport,
                )
                .unwrap();
                assert_eq!(reopened.delivery, saved.delivery);
                assert_eq!(reopened.intent.requests, saved.intent.requests);
                assert_eq!(
                    reopened
                        .encode(&member, &operators, &accepted, &transport)
                        .unwrap()
                        .as_slice(),
                    encoded.as_slice()
                );
                let prepared = transport.restore_prepared(&reopened.delivery).unwrap();
                for peer in &identities {
                    let recipient = SetupTransport::new(
                        peer,
                        &operators,
                        SetupAuthority::Accepted(&accepted),
                        true,
                    )
                    .unwrap();
                    let (root, objects) = prepared.recipient_objects(peer.public().id).unwrap();
                    let record = recipient.authenticate_objects(&root, &objects).unwrap();
                    assert_eq!(record.body().key.phase, SetupPhase::PaymentDescriptor);
                    let descriptor =
                        open_descriptor(peer, &roster, &record.body().payload).unwrap();
                    assert_eq!(descriptor.body().owner, owner.public().id);
                    assert_eq!(record.body().prerequisites, parents[&peer.public().id]);
                }
                let activation = super::super::activation::SavedActivation::prepare(
                    &encoded,
                    loki_relay_client::ConfigReference::new(1, [77; 32]).unwrap(),
                    &member,
                    &operators,
                    &accepted,
                    &transport,
                )
                .unwrap();
                let activation_bytes = activation
                    .encode(&member, &operators, &accepted, &transport)
                    .unwrap();
                let reopened_activation = super::super::activation::SavedActivation::decode(
                    &activation_bytes,
                    &member,
                    &operators,
                    &accepted,
                    &transport,
                )
                .unwrap();
                assert_eq!(activation.request, reopened_activation.request);
                assert_eq!(
                    activation_bytes.as_slice(),
                    reopened_activation
                        .encode(&member, &operators, &accepted, &transport)
                        .unwrap()
                        .as_slice()
                );
                let mut damaged =
                    PrivateValue(canonical::decode(&activation_bytes, 8 * 1024 * 1024).unwrap());
                let Value::Array(fields) = &mut damaged.0 else {
                    panic!("private activation envelope");
                };
                fields[2] = Value::Integer(2.into());
                let damaged_bytes = Zeroizing::new(canonical::encode(&damaged.0).unwrap());
                assert!(super::super::activation::SavedActivation::decode(
                    &damaged_bytes,
                    &member,
                    &operators,
                    &accepted,
                    &transport
                )
                .is_err());
                let substituted = SavedPaymentHandoff::prepare(
                    PaymentIntent::prepare(&member, &operators).unwrap(),
                    &member,
                    &operators,
                    &accepted,
                    &transport,
                    &parents,
                )
                .unwrap();
                let mut changed = SavedPaymentHandoff::decode(
                    &encoded, &member, &operators, &accepted, &transport,
                )
                .unwrap();
                changed.delivery = substituted.delivery;
                assert!(changed
                    .encode(&member, &operators, &accepted, &transport)
                    .is_err());
                let mut changed = SavedPaymentHandoff::decode(
                    &encoded, &member, &operators, &accepted, &transport,
                )
                .unwrap();
                changed.parents.get_mut(&owner.public().id).unwrap()[0][0] ^= 1;
                assert!(changed
                    .encode(&member, &operators, &accepted, &transport)
                    .is_err());
            }
        }
    }
}
