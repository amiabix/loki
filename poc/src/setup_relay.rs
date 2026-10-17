mod activation;
mod payment;
use crate::{
    network::{VaultNetwork, TESTNET_NU7_BIRTH},
    setup_ceremony::{
        journal::{self, Journal, MemberLock},
        AcceptedCeremonyRoster, AdmissionCheckpointAuthority, CeremonyPhase, CeremonyRecord,
        SetupCeremony,
    },
    setup_transport::Identity,
    state::MemberDir,
};
use loki_relay_client::{
    sign_admission_request, AdmissionHttp, AdmissionOutcome, CommIdentity, DescriptorRelay,
    OperatorSet, OwnerInbox, RelayRuntime, Secret32, SetupAuthority, SetupInboxDescriptor,
    SetupInvite, SetupPolicy, SetupRoutes, SetupStore, SetupTransport,
};
use loki_relay_protocol::{
    admission::{self, AdmissionCommand, AdmissionRequest},
    canonical::{self, Value},
    http,
    setup::{SetupKey, SetupPhase, SetupRecord},
    types::{Creation, MemberPublic, RelayRoute, Roster},
};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, Zeroizing};
const ERROR: &str = "setup_hosted";
const CONTEXT: &str = "hosted-context.sealed";
const LIMIT: usize = 65536;
fn random() -> [u8; 32] {
    let mut bytes = [0; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}
fn field(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > LIMIT {
        return Err(ERROR.into());
    }
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}
struct Reader<'a> {
    raw: &'a [u8],
    offset: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, size: usize) -> Result<&'a [u8], String> {
        let end = self.offset.checked_add(size).ok_or(ERROR)?;
        let bytes = self.raw.get(self.offset..end).ok_or(ERROR)?;
        self.offset = end;
        Ok(bytes)
    }
    fn field(&mut self) -> Result<&'a [u8], String> {
        let size = u32::from_be_bytes(self.take(4)?.try_into().map_err(|_| ERROR)?) as usize;
        if size > LIMIT {
            return Err(ERROR.into());
        }
        self.take(size)
    }
}
struct PrivateValue(Value);
impl Drop for PrivateValue {
    fn drop(&mut self) {
        fn wipe(value: &mut Value) {
            match value {
                Value::Bytes(bytes) => bytes.zeroize(),
                Value::Text(text) => text.zeroize(),
                Value::Array(values) => {
                    for value in values {
                        wipe(value);
                    }
                }
                _ => {}
            }
        }
        wipe(&mut self.0);
    }
}
fn verified_invite(
    private: &[u8],
    bundle: &[u8],
    key: &[u8; 32],
    development: bool,
    now: u64,
) -> Result<SetupInvite, String> {
    if private.len() > 4096 {
        return Err(ERROR.into());
    }
    let value = PrivateValue(canonical::decode(private, 4096).map_err(|_| ERROR)?);
    let Value::Array(outer) = &value.0 else {
        return Err(ERROR.into());
    };
    if outer.len() != 3 {
        return Err(ERROR.into());
    }
    let Value::Bytes(package) = &outer[0] else {
        return Err(ERROR.into());
    };
    let Value::Array(signed) = canonical::decode(package, 4096).map_err(|_| ERROR)? else {
        return Err(ERROR.into());
    };
    if signed.len() != 2 {
        return Err(ERROR.into());
    }
    let Value::Bytes(body) = &signed[0] else {
        return Err(ERROR.into());
    };
    let Value::Array(fields) = canonical::decode(body, 4096).map_err(|_| ERROR)? else {
        return Err(ERROR.into());
    };
    if fields.len() != 10 {
        return Err(ERROR.into());
    }
    let Value::Array(member) = &fields[7] else {
        return Err(ERROR.into());
    };
    if member.len() != 3 || member[0] != Value::Integer(1.into()) {
        return Err(ERROR.into());
    }
    let (Value::Bytes(signing), Value::Bytes(encryption)) = (&member[1], &member[2]) else {
        return Err(ERROR.into());
    };
    let creator = loki_relay_protocol::types::MemberPublic {
        id: 1,
        signing: signing.as_slice().try_into().map_err(|_| ERROR)?,
        encryption: encryption.as_slice().try_into().map_err(|_| ERROR)?,
    };
    if development {
        SetupInvite::verify_development(private, &creator, bundle, key, now)
    } else {
        SetupInvite::verify(private, &creator, bundle, key, now)
    }
    .map_err(|_| ERROR.into())
}
struct Context {
    own_slot: u16,
    count: u16,
    development: bool,
    key: [u8; 32],
    bundle: Vec<u8>,
    create: Vec<u8>,
    grant: Zeroizing<Vec<u8>>,
    invitations: Zeroizing<Vec<[u8; 32]>>,
}
impl Context {
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        let mut raw = Zeroizing::new(if self.own_slot == 1 {
            b"LOKIHST1".to_vec()
        } else {
            b"LOKIHST2".to_vec()
        });
        if self.own_slot != 1 {
            raw.extend_from_slice(&self.own_slot.to_be_bytes());
        }
        raw.extend_from_slice(&self.count.to_be_bytes());
        raw.push(self.development as u8);
        raw.extend_from_slice(&self.key);
        field(&mut raw, &self.bundle)?;
        field(&mut raw, &self.create)?;
        field(&mut raw, &self.grant)?;
        for secret in self.invitations.iter() {
            raw.extend_from_slice(secret);
        }
        if raw.len() > LIMIT {
            return Err(ERROR.into());
        }
        Ok(raw)
    }
    fn decode(raw: &[u8]) -> Result<Self, String> {
        if raw.len() > LIMIT {
            return Err(ERROR.into());
        }
        let mut reader = Reader { raw, offset: 0 };
        let own_slot = match reader.take(8)? {
            b"LOKIHST1" => 1,
            b"LOKIHST2" => u16::from_be_bytes(reader.take(2)?.try_into().map_err(|_| ERROR)?),
            _ => return Err(ERROR.into()),
        };
        let count = u16::from_be_bytes(reader.take(2)?.try_into().map_err(|_| ERROR)?);
        if !matches!(count, 3 | 4) || own_slot == 0 || own_slot > count {
            return Err(ERROR.into());
        }
        let development = match reader.take(1)?[0] {
            0 => false,
            1 => true,
            _ => return Err(ERROR.into()),
        };
        let key = reader.take(32)?.try_into().map_err(|_| ERROR)?;
        let bundle = reader.field()?.to_vec();
        let create = reader.field()?.to_vec();
        let grant = Zeroizing::new(reader.field()?.to_vec());
        let mut invitations = Zeroizing::new(Vec::new());
        if own_slot == 1 {
            for _ in 1..count {
                invitations.push(reader.take(32)?.try_into().map_err(|_| ERROR)?);
            }
        }
        if reader.offset != raw.len() || grant.is_empty() || grant.len() > 4096 {
            return Err(ERROR.into());
        }
        Ok(Self {
            own_slot,
            count,
            development,
            key,
            bundle,
            create,
            grant,
            invitations,
        })
    }
    fn operators(&self) -> Result<OperatorSet, String> {
        if self.development {
            OperatorSet::verify_development(&self.bundle, &self.key)
        } else {
            OperatorSet::verify(&self.bundle, &self.key)
        }
        .map_err(|_| ERROR.into())
    }
    fn request(
        &self,
        identity: &CommIdentity,
        operators: &OperatorSet,
    ) -> Result<AdmissionRequest, String> {
        if identity.public().id != self.own_slot {
            return Err(ERROR.into());
        }
        if self.own_slot != 1 {
            let invite =
                verified_invite(&self.grant, &self.bundle, &self.key, self.development, 0)?;
            let policy = invite.context().policy();
            let request = signed_request(&self.create, identity)?;
            if invite.slot() != self.own_slot
                || policy.member_count != self.count
                || VaultNetwork::parse(&policy.network).is_err()
                || !matches!((policy.threshold, policy.member_count), (2, 3) | (2, 4) | (3, 4))
                || policy.config_digest != *operators.digest()
                || invite.bootstrap_descriptor().is_none()
                || request.device != identity.public()
                || request.command
                    != (AdmissionCommand::Claim {
                        ceremony: policy.ceremony,
                        slot: self.own_slot,
                        invite_hash: Sha256::digest(invite.secret().as_bytes()).into(),
                    })
            {
                return Err(ERROR.into());
            }
            return Ok(request);
        }
        let Value::Array(fields) =
            canonical::decode(&self.create, admission::MAX_REQUEST).map_err(|_| ERROR)?
        else {
            return Err(ERROR.into());
        };
        if fields.len() != 2 {
            return Err(ERROR.into());
        }
        let Value::Bytes(body) = &fields[0] else {
            return Err(ERROR.into());
        };
        let request = admission::decode_request(body).map_err(|_| ERROR)?;
        let AdmissionCommand::Create {
            ceremony,
            network,
            threshold,
            member_count,
            config_digest,
            grant_digest,
            invite_hashes,
        } = &request.command
        else {
            return Err(ERROR.into());
        };
        if *ceremony == [0; 32]
            || VaultNetwork::parse(network).is_err()
            || !matches!((*threshold, *member_count), (2, 3) | (2, 4) | (3, 4))
            || *member_count != self.count
            || config_digest != operators.digest()
            || *grant_digest != <[u8; 32]>::from(Sha256::digest(&*self.grant))
            || invite_hashes
                != &self
                    .invitations
                    .iter()
                    .map(|secret| <[u8; 32]>::from(Sha256::digest(secret)))
                    .collect::<Vec<_>>()
            || sign_admission_request(identity, &request).map_err(|_| ERROR)? != self.create
        {
            return Err(ERROR.into());
        }
        Ok(request)
    }
}

struct SecretRecords(Vec<SetupRecord>);
impl Drop for SecretRecords {
    fn drop(&mut self) {
        for record in &mut self.0 {
            record.payload.zeroize();
        }
    }
}
struct VerifiedProposal {
    body: SecretRecords,
    prerequisites: BTreeMap<u16, Vec<[u8; 32]>>,
    roster: Roster,
    fingerprint: [u8; 32],
    descriptors: Vec<SetupInboxDescriptor>,
}
struct Inventory {
    ready: bool,
    claim: u64,
    deadline: u64,
    registered: u8,
    inboxes: Vec<OwnerInbox>,
    requests: Vec<Vec<u8>>,
    invites: BTreeMap<u16, Zeroizing<Vec<u8>>>,
}
fn verifier(mailbox: &[u8; 32], role: u8, secret: &Secret32) -> [u8; 32] {
    let mut input = Zeroizing::new(b"Loki_Relay_Capability_v1\0".to_vec());
    input.push(role);
    input.extend_from_slice(mailbox);
    input.extend_from_slice(secret.as_bytes());
    Sha256::digest(&*input).into()
}
fn signed_request(package: &[u8], identity: &CommIdentity) -> Result<AdmissionRequest, String> {
    let Value::Array(f) = canonical::decode(package, admission::MAX_REQUEST).map_err(|_| ERROR)?
    else {
        return Err(ERROR.into());
    };
    if f.len() != 2 {
        return Err(ERROR.into());
    }
    let Value::Bytes(body) = &f[0] else {
        return Err(ERROR.into());
    };
    let request = admission::decode_request(body).map_err(|_| ERROR)?;
    if sign_admission_request(identity, &request).map_err(|_| ERROR)? != package {
        return Err(ERROR.into());
    }
    Ok(request)
}
impl Inventory {
    fn encode(&self) -> Result<Zeroizing<Vec<u8>>, String> {
        let mut out = Zeroizing::new(vec![if self.ready { 3 } else { 2 }]);
        out.extend_from_slice(&self.claim.to_be_bytes());
        out.extend_from_slice(&self.deadline.to_be_bytes());
        out.push(self.registered);
        if self.inboxes.len() != 3 || self.requests.len() != 3 {
            return Err(ERROR.into());
        }
        for (inbox, request) in self.inboxes.iter().zip(&self.requests) {
            out.extend_from_slice(&inbox.route.mailbox);
            for cap in [&inbox.read, &inbox.append, &inbox.admin] {
                out.extend_from_slice(cap.as_bytes());
            }
            field(&mut out, request)?;
        }
        for (slot, invite) in &self.invites {
            out.extend_from_slice(&slot.to_be_bytes());
            field(&mut out, invite)?;
        }
        if out.len() > LIMIT {
            return Err(ERROR.into());
        }
        Ok(out)
    }
    fn decode(
        raw: &[u8],
        context: &Context,
        operators: &OperatorSet,
        identity: &CommIdentity,
    ) -> Result<Self, String> {
        if raw.len() > LIMIT {
            return Err(ERROR.into());
        }
        let mut reader = Reader { raw, offset: 0 };
        let phase = reader.take(1)?[0];
        if !matches!(phase, 2 | 3) {
            return Err(ERROR.into());
        }
        let claim = u64::from_be_bytes(reader.take(8)?.try_into().map_err(|_| ERROR)?);
        let deadline = u64::from_be_bytes(reader.take(8)?.try_into().map_err(|_| ERROR)?);
        let registered = reader.take(1)?[0];
        if registered > 7 || (phase == 3 && registered != 7) {
            return Err(ERROR.into());
        }
        let mut inboxes = Vec::new();
        let mut requests = Vec::new();
        let mut unique = BTreeSet::new();
        let creation = context.request(identity, operators)?;
        for (index, operator) in operators.relay_routes().iter().enumerate() {
            let mailbox: [u8; 32] = reader.take(32)?.try_into().map_err(|_| ERROR)?;
            if mailbox == [0; 32] || !unique.insert(mailbox) {
                return Err(ERROR.into());
            }
            let mut caps = Vec::new();
            for _ in 0..3 {
                let value = reader.take(32)?.try_into().map_err(|_| ERROR)?;
                if value == [0; 32] || !unique.insert(value) {
                    return Err(ERROR.into());
                }
                caps.push(Secret32::from_bytes(value));
            }
            let mut caps = caps.into_iter();
            let inbox = OwnerInbox {
                route: RelayRoute {
                    mailbox,
                    append_revision: 1,
                    ..operator.clone()
                },
                read: caps.next().ok_or(ERROR)?,
                append: caps.next().ok_or(ERROR)?,
                admin: caps.next().ok_or(ERROR)?,
            };
            let request = reader.field()?.to_vec();
            let signed = signed_request(&request, identity)?;
            let expected = http::encode_creation(&Creation {
                read_verifier: verifier(&mailbox, 1, &inbox.read),
                append_verifier: verifier(&mailbox, 2, &inbox.append),
                admin_verifier: verifier(&mailbox, 3, &inbox.admin),
                quota: operators.limits().storage_bytes_per_relay / u64::from(context.count),
            })
            .map_err(|_| ERROR)?;
            if signed.command
                != (AdmissionCommand::Mailbox {
                    ceremony: *creation.command.ceremony(),
                    slot: context.own_slot,
                    relay: index as u16 + 1,
                    purpose: 1,
                    mailbox,
                    creation: expected,
                })
            {
                return Err(ERROR.into());
            }
            inboxes.push(inbox);
            requests.push(request);
        }
        let mut invites = BTreeMap::new();
        if phase == 3 && context.own_slot == 1 {
            for expected in 2..=context.count {
                let slot = u16::from_be_bytes(reader.take(2)?.try_into().map_err(|_| ERROR)?);
                if slot != expected {
                    return Err(ERROR.into());
                }
                let package = Zeroizing::new(reader.field()?.to_vec());
                let invite = if context.development {
                    SetupInvite::verify_development(
                        &package,
                        &identity.public(),
                        &context.bundle,
                        &context.key,
                        claim.checked_sub(1).ok_or(ERROR)?,
                    )
                } else {
                    SetupInvite::verify(
                        &package,
                        &identity.public(),
                        &context.bundle,
                        &context.key,
                        claim.checked_sub(1).ok_or(ERROR)?,
                    )
                }
                .map_err(|_| ERROR)?;
                let policy = SetupPolicy {
                    ceremony: *creation.command.ceremony(),
                    network: match &creation.command {
                        AdmissionCommand::Create { network, .. } => network.clone(),
                        _ => return Err(ERROR.into()),
                    },
                    threshold: match &creation.command {
                        AdmissionCommand::Create { threshold, .. } => *threshold,
                        _ => return Err(ERROR.into()),
                    },
                    member_count: context.count,
                    config_digest: *operators.digest(),
                };
                if invite.context().policy() != &policy
                    || invite.slot() != slot
                    || invite.expires() != claim
                    || invite.context().policy().ceremony != *creation.command.ceremony()
                    || invite.secret().as_bytes() != &context.invitations[slot as usize - 2]
                {
                    return Err(ERROR.into());
                }
                let descriptor = invite.bootstrap_descriptor().ok_or(ERROR)?;
                if descriptor.relays().len() != 3
                    || descriptor.relays().iter().zip(&inboxes).any(|(r, own)| {
                        r.route != own.route || r.append.as_bytes() != own.append.as_bytes()
                    })
                {
                    return Err(ERROR.into());
                }
                invites.insert(slot, package);
            }
        }
        if reader.offset != raw.len() {
            return Err(ERROR.into());
        }
        Ok(Self {
            ready: phase == 3,
            claim,
            deadline,
            registered,
            inboxes,
            requests,
            invites,
        })
    }
}
pub struct HandoffStatus {
    ready: bool,
    missing_slots: Vec<u16>,
}
impl HandoffStatus {
    pub fn is_ready(&self) -> bool {
        self.ready
    }
    pub fn public_json(&self) -> ValueJson {
        serde_json::json!({"handoff": if self.ready { "ready" } else { "pending" }, "missing_slots":self.missing_slots})
    }
}
pub fn install_payment_configuration(
    root: &Path,
    passphrase: &str,
) -> Result<HandoffStatus, String> {
    let setup = HostedSetup::open(root, passphrase)?;
    setup.with_accepted_ceremony(|engine, authority, store, transport, routes, accepted| {
        setup.payment_handoff_step(engine, authority, store, transport, routes, accepted, true)
    })
}
pub struct SetupStatus {
    own_slot: u16,
    phase: &'static str,
    threshold: u16,
    count: u16,
    joined: Vec<u16>,
    agreed: Option<[u8; 32]>,
    waiting: Option<Vec<u16>>,
    retryable: bool,
}
impl SetupStatus {
    pub fn public_json(&self) -> ValueJson {
        serde_json::json!({"phase":self.phase,"policy":format!("{}-of-{}",self.threshold,self.count),"own_slot":self.own_slot,
            "joined_slots":self.joined,
            "missing_slots":self.waiting.clone().unwrap_or_else(|| (1..=self.count).filter(|slot| !self.joined.contains(slot)).collect::<Vec<_>>()),"agreed_fingerprint":self.agreed.map(hex::encode),
            "retryable":self.retryable,"handoff":if self.phase == "active" { "ready" } else { "pending" }})
    }
}
type ValueJson = serde_json::Value;
struct CachedStatus {
    phase: String,
    policy: String,
    own_slot: u16,
    joined_slots: Vec<u16>,
    missing_slots: Vec<u16>,
    agreed_fingerprint: Option<String>,
    retryable: bool,
    handoff: String,
}
impl CachedStatus {
    fn parse(value: &ValueJson) -> Result<Self, String> {
        let object = value.as_object().ok_or("setup_status")?;
        let keys = [
            "phase",
            "policy",
            "own_slot",
            "joined_slots",
            "missing_slots",
            "agreed_fingerprint",
            "retryable",
            "handoff",
        ];
        if object.len() != keys.len() || keys.iter().any(|key| !object.contains_key(*key)) {
            return Err("setup_status".into());
        }
        let string = |key: &str| value[key].as_str().map(str::to_owned).ok_or("setup_status");
        let slots = |key: &str| -> Result<Vec<u16>, String> {
            value[key]
                .as_array()
                .ok_or("setup_status")?
                .iter()
                .map(|id| {
                    u16::try_from(id.as_u64().ok_or("setup_status")?)
                        .map_err(|_| "setup_status".into())
                })
                .collect()
        };
        Ok(Self {
            phase: string("phase")?,
            policy: string("policy")?,
            own_slot: u16::try_from(value["own_slot"].as_u64().ok_or("setup_status")?)
                .map_err(|_| "setup_status")?,
            joined_slots: slots("joined_slots")?,
            missing_slots: slots("missing_slots")?,
            agreed_fingerprint: if value["agreed_fingerprint"].is_null() {
                None
            } else {
                Some(string("agreed_fingerprint")?)
            },
            retryable: value["retryable"].as_bool().ok_or("setup_status")?,
            handoff: string("handoff")?,
        })
    }
    fn validate(&self) -> Result<(), String> {
        let count = match self.policy.as_str() {
            "2-of-3" => 3,
            "2-of-4" => 4,
            "3-of-4" => 4,
            _ => return Err("setup_status".into()),
        };
        if !(1..=count).contains(&self.own_slot)
            || self.handoff
                != if self.phase == "active" {
                    "ready"
                } else {
                    "pending"
                }
            || !matches!(
                self.phase.as_str(),
                "admission_pending"
                    | "admission_rejected"
                    | "provisioning"
                    | "invites_ready"
                    | "inbox_ready"
                    | "join_pending"
                    | "join_published"
                    | "waiting_joins"
                    | "joins_received"
                    | "proposal_pending"
                    | "roster_proposed"
                    | "agreement_saved"
                    | "acceptance_pending"
                    | "roster_accepted"
                    | "terminal_pending"
                    | "aborted"
                    | "checkpoint_conflict"
                    | "expired"
                    | "activation_unverified"
                    | "round1_saved"
                    | "round2_saved"
                    | "certificate_saved"
                    | "awaiting_backups"
                    | "certified"
                    | "payment_handoff"
                    | "active"
            )
            || self.joined_slots.iter().any(|id| !(1..=count).contains(id))
            || self.joined_slots.windows(2).any(|ids| ids[0] >= ids[1])
            || self
                .missing_slots
                .iter()
                .any(|id| !(1..=count).contains(id))
            || self.missing_slots.windows(2).any(|ids| ids[0] >= ids[1])
            || (matches!(self.phase.as_str(), "certified" | "active")
                && !self.missing_slots.is_empty())
            || (self.phase == "active" && self.joined_slots != (1..=count).collect::<Vec<_>>())
            || (!matches!(
                self.phase.as_str(),
                "acceptance_pending"
                    | "round1_saved"
                    | "round2_saved"
                    | "certificate_saved"
                    | "awaiting_backups"
                    | "certified"
                    | "payment_handoff"
                    | "active"
            ) && self.missing_slots
                != (1..=count)
                    .filter(|id| !self.joined_slots.contains(id))
                    .collect::<Vec<_>>())
            || self.agreed_fingerprint.as_ref().is_some_and(|fp| {
                fp.len() != 64
                    || hex::decode(fp).map_or(true, |bytes| bytes.len() != 32)
                    || fp != &fp.to_ascii_lowercase()
            })
        {
            return Err("setup_status".into());
        }
        Ok(())
    }
}

pub struct HostedSetup {
    root: PathBuf,
    context: Context,
    threshold: u16,
    operators: OperatorSet,
    identity: CommIdentity,
    journal: Journal,
    approval: Journal,
    runtime: RelayRuntime,
    http: AdmissionHttp,
    retry: std::sync::Arc<crate::setup_retry::AdmissionRetry>,
    _member_lock: MemberLock,
    passphrase: Zeroizing<String>,
}
impl HostedSetup {
    pub fn create(
        root: &Path,
        passphrase: &str,
        bundle: &[u8],
        key: &[u8; 32],
        grant: &[u8],
        count: u16,
        network: &str,
        development: bool,
    ) -> Result<Self, String> {
        Self::create_with_policy(root, passphrase, bundle, key, grant, 2, count, network, development)
    }
    pub fn create_with_policy(
        root: &Path,
        passphrase: &str,
        bundle: &[u8],
        key: &[u8; 32],
        grant: &[u8],
        threshold: u16,
        count: u16,
        network: &str,
        development: bool,
    ) -> Result<Self, String> {
        if !matches!((threshold, count), (2, 3) | (2, 4) | (3, 4))
            || VaultNetwork::parse(network).is_err()
            || grant.is_empty()
            || grant.len() > 4096
        {
            return Err(ERROR.into());
        }
        let operators = if development {
            OperatorSet::verify_development(bundle, key)
        } else {
            OperatorSet::verify(bundle, key)
        }
        .map_err(|_| ERROR)?;
        journal::check_private_root(root)?;
        journal::check_private_root(&root.join("secrets"))?;
        let lock = journal::lock_file(&root.join("secrets/.setup.lock"))?;
        let identity = Self::identity(root, passphrase)?;
        if identity.public().id != 1 {
            return Err(ERROR.into());
        }
        let secrets = MemberDir::open(root, "secrets");
        if secrets.exists(CONTEXT) {
            drop(lock);
            let existing = Self::open(root, passphrase)?;
            if existing.context.bundle != bundle
                || existing.context.key != *key
                || existing.context.count != count
                || existing.policy()?.threshold != threshold
                || existing.policy()?.network != network
                || existing.context.development != development
                || existing.context.grant.as_slice() != grant
            {
                return Err(ERROR.into());
            }
            return Ok(existing);
        }
        let invitations = Zeroizing::new((1..count).map(|_| random()).collect::<Vec<_>>());
        let request = AdmissionRequest {
            operation: random(),
            device: identity.public(),
            command: AdmissionCommand::Create {
                ceremony: random(),
                network: network.into(),
                threshold,
                member_count: count,
                config_digest: *operators.digest(),
                grant_digest: Sha256::digest(grant).into(),
                invite_hashes: invitations
                    .iter()
                    .map(|secret| Sha256::digest(secret).into())
                    .collect(),
            },
        };
        let context = Context {
            own_slot: 1,
            count,
            development,
            key: *key,
            bundle: bundle.to_vec(),
            create: sign_admission_request(&identity, &request).map_err(|_| ERROR)?,
            grant: Zeroizing::new(grant.to_vec()),
            invitations,
        };
        secrets
            .write_sealed(CONTEXT, &context.encode()?, passphrase)
            .map_err(|_| ERROR)?;
        Self::finish_open(root, passphrase, context, identity, lock)
    }
    pub fn join(
        root: &Path,
        passphrase: &str,
        invitation: &[u8],
        bundle: &[u8],
        key: &[u8; 32],
        expected_network: &str,
        development: bool,
    ) -> Result<Self, String> {
        VaultNetwork::parse(expected_network)?;
        journal::check_private_root(root)?;
        if root
            .join("secrets")
            .join(CONTEXT)
            .try_exists()
            .map_err(|_| ERROR)?
        {
            let existing = Self::open(root, passphrase)?;
            if existing.context.own_slot == 1
                || existing.context.bundle != bundle
                || existing.context.key != *key
                || existing.policy()?.network != expected_network
                || existing.context.development != development
                || existing.context.grant.as_slice() != invitation
            {
                return Err(ERROR.into());
            }
            return Ok(existing);
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ERROR)?
            .as_secs();
        let invite = verified_invite(invitation, bundle, key, development, now)?;
        let policy = invite.context().policy();
        if policy.network != expected_network
            || !matches!((policy.threshold, policy.member_count), (2, 3) | (2, 4) | (3, 4))
            || invite.bootstrap_descriptor().is_none()
            || invitation.len() > 4096
        {
            return Err(ERROR.into());
        }
        let secrets_path = root.join("secrets");
        if !secrets_path.try_exists().map_err(|_| ERROR)? {
            MemberDir::create(root, "secrets").map_err(|_| ERROR)?;
        }
        journal::check_private_root(&secrets_path)?;
        let lock = journal::lock_file(&secrets_path.join(".setup.lock"))?;
        let secrets = MemberDir::open(root, "secrets");
        if !secrets.exists("identity.sealed") {
            let identity = Identity::new(invite.slot());
            secrets
                .write_sealed(
                    "identity.sealed",
                    Zeroizing::new(identity.to_secret_bytes()).as_slice(),
                    passphrase,
                )
                .map_err(|_| ERROR)?;
        }
        let identity = Self::identity(root, passphrase)?;
        if identity.public().id != invite.slot() {
            return Err(ERROR.into());
        }
        let request = AdmissionRequest {
            operation: random(),
            device: identity.public(),
            command: AdmissionCommand::Claim {
                ceremony: policy.ceremony,
                slot: invite.slot(),
                invite_hash: Sha256::digest(invite.secret().as_bytes()).into(),
            },
        };
        let context = Context {
            own_slot: invite.slot(),
            count: policy.member_count,
            development,
            key: *key,
            bundle: bundle.to_vec(),
            create: sign_admission_request(&identity, &request).map_err(|_| ERROR)?,
            grant: Zeroizing::new(invitation.to_vec()),
            invitations: Zeroizing::new(Vec::new()),
        };
        secrets
            .write_sealed(CONTEXT, &context.encode()?, passphrase)
            .map_err(|_| ERROR)?;
        Self::finish_open(root, passphrase, context, identity, lock)
    }
    fn identity(root: &Path, passphrase: &str) -> Result<CommIdentity, String> {
        let file = journal::checked_file(&root.join("secrets/identity.sealed"))?;
        if file.metadata().map_err(|_| ERROR)?.len() != 49 + 66 + 16 {
            return Err(ERROR.into());
        }
        let raw = Zeroizing::new(
            MemberDir::open(root, "secrets")
                .read_sealed("identity.sealed", passphrase)
                .map_err(|_| ERROR)?,
        );
        let native = Identity::from_secret_bytes(&raw).map_err(|_| ERROR)?;
        CommIdentity::from_serialized(&Zeroizing::new(native.to_secret_bytes()))
            .map_err(|_| ERROR.into())
    }
    pub fn open(root: &Path, passphrase: &str) -> Result<Self, String> {
        journal::check_private_root(root)?;
        journal::check_private_root(&root.join("secrets"))?;
        let lock = journal::lock_file(&root.join("secrets/.setup.lock"))?;
        let identity = Self::identity(root, passphrase)?;
        let file = journal::checked_file(&root.join("secrets").join(CONTEXT))?;
        if file.metadata().map_err(|_| ERROR)?.len() > LIMIT as u64 + 65 {
            return Err(ERROR.into());
        }
        let raw = Zeroizing::new(
            MemberDir::open(root, "secrets")
                .read_sealed(CONTEXT, passphrase)
                .map_err(|_| ERROR)?,
        );
        Self::finish_open(root, passphrase, Context::decode(&raw)?, identity, lock)
    }
    fn finish_open(
        root: &Path,
        passphrase: &str,
        context: Context,
        identity: CommIdentity,
        lock: MemberLock,
    ) -> Result<Self, String> {
        let operators = context.operators()?;
        let request = context.request(&identity, &operators)?;
        let threshold = match request.command {
            AdmissionCommand::Create { threshold, .. } => threshold,
            AdmissionCommand::Claim { .. } => verified_invite(
                &context.grant, &context.bundle, &context.key, context.development, 0,
            )?.context().policy().threshold,
            _ => return Err(ERROR.into()),
        };
        let mut journal = Journal::open(
            &root.join("setup-bootstrap"),
            passphrase,
            *blake3::hash(&context.encode()?).as_bytes(),
            context.own_slot,
        )?;
        if journal.latest().is_none() {
            journal.append(&[0])?;
        }
        Self::validate_snapshot(&operators, &journal.latest().ok_or(ERROR)?.payload)?;
        if matches!(journal.latest().ok_or(ERROR)?.payload[0], 2 | 3) {
            Inventory::decode(
                &journal.latest().ok_or(ERROR)?.payload,
                &context,
                &operators,
                &identity,
            )?;
        }
        if journal.latest().ok_or(ERROR)?.payload[0] == 4 {
            let raw = &journal.latest().ok_or(ERROR)?.payload;
            let mut reader = Reader { raw, offset: 2 };
            let request = signed_request(reader.field()?, &identity)?;
            let ceremony = *context.request(&identity, &operators)?.command.ceremony();
            if reader.offset != raw.len()
                || request.device != identity.public()
                || !matches!(request.command,
                    AdmissionCommand::Terminal { ceremony: id, kind: 1 } if id == ceremony && raw[1] == 1)
                    && !matches!(request.command,
                        AdmissionCommand::TerminalNotice { ceremony: id, kind } if id == ceremony && kind == u16::from(raw[1]))
            {
                return Err(ERROR.into());
            }
        }
        let mut approval_binding = blake3::Hasher::new();
        approval_binding.update(b"Loki_Hosted_Human_Approval_v1\0");
        approval_binding.update(&context.encode()?);
        let approval = Journal::open(
            &root.join("setup-approval"),
            passphrase,
            *approval_binding.finalize().as_bytes(),
            context.own_slot,
        )?;
        let http = if context.development {
            AdmissionHttp::development(&operators)
        } else {
            AdmissionHttp::new(&operators)
        }
        .map_err(|_| ERROR)?;
        let retry = std::sync::Arc::new(crate::setup_retry::AdmissionRetry::new(
            root,
            passphrase,
            *blake3::hash(&context.encode()?).as_bytes(),
            operators.limits().retry_min_seconds,
            operators.limits().retry_max_seconds,
            &lock,
        )?);
        let hosted = Self {
            root: root.to_owned(),
            context,
            threshold,
            operators,
            identity,
            journal,
            approval,
            runtime: RelayRuntime::new().map_err(|_| ERROR)?,
            http,
            retry,
            _member_lock: lock,
            passphrase: Zeroizing::new(passphrase.to_owned()),
        };
        hosted.saved_approval()?;
        if hosted.journal.latest().ok_or(ERROR)?.payload[0] == 7 {
            hosted.rejection_status()?;
        }
        Ok(hosted)
    }
    fn policy(&self) -> Result<SetupPolicy, String> {
        let request = self.context.request(&self.identity, &self.operators)?;
        let (network, threshold) = if self.context.own_slot == 1 {
            match &request.command {
                AdmissionCommand::Create { network, threshold, .. } => (network.clone(), *threshold),
                _ => return Err(ERROR.into()),
            }
        } else {
            let invite = verified_invite(
                &self.context.grant,
                &self.context.bundle,
                &self.context.key,
                self.context.development,
                0,
            )?;
            let policy = invite.context().policy();
            (policy.network.clone(), policy.threshold)
        };
        Ok(SetupPolicy {
            ceremony: *request.command.ceremony(),
            network,
            threshold,
            member_count: self.context.count,
            config_digest: *self.operators.digest(),
        })
    }
    fn validate_claims(
        &self,
        value: &Value,
    ) -> Result<Vec<loki_relay_protocol::types::MemberPublic>, String> {
        let Value::Array(rows) = value else {
            return Err(ERROR.into());
        };
        if rows.is_empty() || rows.len() > self.context.count as usize {
            return Err(ERROR.into());
        }
        let mut claimed = Vec::new();
        let mut signing_keys = BTreeSet::new();
        let mut encryption_keys = BTreeSet::new();
        for value in rows {
            let Value::Array(row) = value else {
                return Err(ERROR.into());
            };
            if row.len() != 3 {
                return Err(ERROR.into());
            }
            let (Value::Integer(id), Value::Bytes(signing), Value::Bytes(encryption)) =
                (&row[0], &row[1], &row[2])
            else {
                return Err(ERROR.into());
            };
            let id = u16::try_from(*id).map_err(|_| ERROR)?;
            let signing: [u8; 32] = signing.as_slice().try_into().map_err(|_| ERROR)?;
            let encryption: [u8; 32] = encryption.as_slice().try_into().map_err(|_| ERROR)?;
            if id == 0
                || id > self.context.count
                || signing == [0; 32]
                || encryption == [0; 32]
                || !signing_keys.insert(signing)
                || !encryption_keys.insert(encryption)
                || claimed
                    .last()
                    .is_some_and(|peer: &loki_relay_protocol::types::MemberPublic| peer.id >= id)
            {
                return Err(ERROR.into());
            }
            claimed.push(loki_relay_protocol::types::MemberPublic {
                id,
                signing,
                encryption,
            });
        }
        if !claimed.contains(&self.identity.public()) {
            return Err(ERROR.into());
        }
        let creator = if self.context.own_slot == 1 {
            self.identity.public()
        } else {
            verified_invite(
                &self.context.grant,
                &self.context.bundle,
                &self.context.key,
                self.context.development,
                0,
            )?
            .context()
            .creator_identity()
            .clone()
        };
        if claimed.first() != Some(&creator) {
            return Err("setup_creator_identity".into());
        }
        Ok(claimed)
    }
    fn provisioning_status(&self, ready: bool) -> SetupStatus {
        SetupStatus {
            agreed: None,
            waiting: None,
            own_slot: self.context.own_slot,
            phase: if ready {
                if self.context.own_slot == 1 {
                    "invites_ready"
                } else {
                    "inbox_ready"
                }
            } else {
                "provisioning"
            },
            threshold: self.threshold,
            count: self.context.count,
            joined: vec![self.context.own_slot],
            retryable: !ready,
        }
    }
    pub fn invitations(&self) -> Result<BTreeMap<u16, Zeroizing<Vec<u8>>>, String> {
        let payload = &self.journal.latest().ok_or(ERROR)?.payload;
        if payload[0] != 3 || self.context.own_slot != 1 {
            return Err("setup_waiting".into());
        }
        Ok(Inventory::decode(payload, &self.context, &self.operators, &self.identity)?.invites)
    }
    pub fn export_invitation(&self, slot: u16, output: &Path) -> Result<(), String> {
        if self.context.own_slot != 1 || !(2..=self.context.count).contains(&slot) {
            return Err("setup_invitation".into());
        }
        let inventory = Inventory::decode(
            &self.journal.latest().ok_or(ERROR)?.payload,
            &self.context,
            &self.operators,
            &self.identity,
        )?;
        if !inventory.ready {
            return Err("setup_waiting".into());
        }
        let state = self.state()?.ok_or("setup_admission_pending")?;
        let AdmissionOutcome::Accepted(Value::Array(fields)) = state.outcome() else {
            return Err("setup_admission".into());
        };
        if fields.len() != 7
            || fields[0] != Value::Integer(self.context.count.into())
            || fields[1] != Value::Integer(inventory.claim.into())
            || fields[2] != Value::Integer(inventory.deadline.into())
            || fields[3] != Value::Integer(0.into())
        {
            return Err("setup_invitation".into());
        }
        self.validate_claims(&fields[4])?;
        let invitation = inventory.invites.get(&slot).ok_or("setup_invitation")?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| ERROR)?
            .as_secs();
        verified_invite(
            invitation,
            &self.context.bundle,
            &self.context.key,
            self.context.development,
            now,
        )?;
        let parent = output.parent().ok_or("setup_file")?;
        journal::check_private_root(parent)?;
        if output.try_exists().map_err(|_| "setup_file")? {
            if private_file(output, 4096)?.as_slice() != invitation.as_slice() {
                return Err("setup_file".into());
            }
            return Ok(());
        }
        let temporary = parent.join(format!(".setup-invite.{}.tmp", hex::encode(random())));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let result = (|| {
            let mut file = options.open(&temporary).map_err(|_| "setup_file")?;
            file.write_all(invitation).map_err(|_| "setup_file")?;
            file.sync_all().map_err(|_| "setup_file")?;
            std::fs::hard_link(&temporary, output).map_err(|_| "setup_file")?;
            std::fs::remove_file(&temporary).map_err(|_| "setup_file")?;
            File::open(parent)
                .map_err(|_| "setup_file")?
                .sync_all()
                .map_err(|_| "setup_file")?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }
    fn execute_admission(
        &self,
        package: &[u8],
        credential: Option<&[u8]>,
        authenticated: bool,
    ) -> loki_relay_client::ClientResult<loki_relay_client::VerifiedAdmissionReply> {
        self.runtime.block_on(self.retry.execute(package, async {
            if authenticated {
                self.http
                    .execute_authenticated(&self.identity, package, credential)
                    .await
            } else {
                self.http.execute(package, credential).await
            }
        }))
    }
    fn state(&self) -> Result<Option<loki_relay_client::VerifiedAdmissionReply>, String> {
        let request = sign_admission_request(
            &self.identity,
            &AdmissionRequest {
                operation: random(),
                device: self.identity.public(),
                command: AdmissionCommand::State {
                    ceremony: self.policy()?.ceremony,
                    slot: self.context.own_slot,
                },
            },
        )
        .map_err(|_| ERROR)?;
        match self.execute_admission(&request, None, false) {
            Ok(reply) => Ok(Some(reply)),
            Err(loki_relay_client::ClientError::Transport) => Ok(None),
            Err(_) => Err("setup_admission".into()),
        }
    }
    fn provision_step(&mut self) -> Result<SetupStatus, String> {
        let Some(state) = self.state()? else {
            return Ok(self.provisioning_status(false));
        };
        let AdmissionOutcome::Accepted(Value::Array(state)) = state.outcome() else {
            return Err("setup_admission".into());
        };
        if state.len() != 7 || state[0] != Value::Integer(u64::from(self.context.count).into()) {
            return Err(ERROR.into());
        }
        let Value::Integer(kind) = state[3] else {
            return Err(ERROR.into());
        };
        let kind = u16::try_from(kind).map_err(|_| ERROR)?;
        if kind > 4 {
            return Err(ERROR.into());
        }
        if kind != 0 && !(kind == 2 && self.native_saved_phase()? == Some(CeremonyPhase::Active)) {
            self.save_terminal(kind, false)?;
            return self.terminal_step();
        }
        let claimed = self.validate_claims(&state[4])?;
        let raw = &self.journal.latest().ok_or(ERROR)?.payload;
        if state[1]
            != Value::Integer(u64::from_be_bytes(raw[1..9].try_into().map_err(|_| ERROR)?).into())
            || state[2]
                != Value::Integer(
                    u64::from_be_bytes(raw[9..17].try_into().map_err(|_| ERROR)?).into(),
                )
        {
            return Err(ERROR.into());
        }
        if raw[0] == 3 {
            if self.approval.latest().is_some() {
                return self.acceptance_step(&claimed);
            }
            if self.context.own_slot > 1 {
                return self.publish_join(&claimed);
            }
            return self.receive_joins(&claimed);
        }
        if raw[0] == 1 {
            let policy = self.policy()?;
            let mut inventory = Inventory {
                ready: false,
                claim: u64::from_be_bytes(raw[1..9].try_into().map_err(|_| ERROR)?),
                deadline: u64::from_be_bytes(raw[9..17].try_into().map_err(|_| ERROR)?),
                registered: 0,
                inboxes: Vec::new(),
                requests: Vec::new(),
                invites: BTreeMap::new(),
            };
            let mut unique = BTreeSet::new();
            for (index, operator) in self.operators.relay_routes().iter().enumerate() {
                let mut values = Zeroizing::new([[0u8; 32]; 4]);
                for value in values.iter_mut() {
                    *value = random();
                    if *value == [0; 32] || !unique.insert(*value) {
                        return Err(ERROR.into());
                    }
                }
                let inbox = OwnerInbox {
                    route: RelayRoute {
                        mailbox: values[0],
                        append_revision: 1,
                        ..operator.clone()
                    },
                    read: Secret32::from_bytes(values[1]),
                    append: Secret32::from_bytes(values[2]),
                    admin: Secret32::from_bytes(values[3]),
                };
                let creation = http::encode_creation(&Creation {
                    read_verifier: verifier(&inbox.route.mailbox, 1, &inbox.read),
                    append_verifier: verifier(&inbox.route.mailbox, 2, &inbox.append),
                    admin_verifier: verifier(&inbox.route.mailbox, 3, &inbox.admin),
                    quota: self.operators.limits().storage_bytes_per_relay
                        / u64::from(self.context.count),
                })
                .map_err(|_| ERROR)?;
                let request = sign_admission_request(
                    &self.identity,
                    &AdmissionRequest {
                        operation: random(),
                        device: self.identity.public(),
                        command: AdmissionCommand::Mailbox {
                            ceremony: policy.ceremony,
                            slot: self.context.own_slot,
                            relay: index as u16 + 1,
                            purpose: 1,
                            mailbox: inbox.route.mailbox,
                            creation,
                        },
                    },
                )
                .map_err(|_| ERROR)?;
                inventory.inboxes.push(inbox);
                inventory.requests.push(request);
            }
            self.journal.append(&inventory.encode()?)?;
            return Ok(self.provisioning_status(false));
        }
        let mut inventory = Inventory::decode(raw, &self.context, &self.operators, &self.identity)?;
        if let Some(index) = (0..3).find(|index| inventory.registered & (1 << index) == 0) {
            let reply = match self.execute_admission(&inventory.requests[index], None, false) {
                Ok(reply) => reply,
                Err(loki_relay_client::ClientError::Transport) => {
                    return Ok(self.provisioning_status(false))
                }
                Err(_) => return Err("setup_admission".into()),
            };
            if !matches!(reply.outcome(),AdmissionOutcome::Accepted(Value::Bytes(mailbox)) if mailbox.as_slice()==inventory.inboxes[index].route.mailbox)
            {
                return Err("setup_admission".into());
            }
            inventory.registered |= 1 << index;
            self.journal.append(&inventory.encode()?)?;
            return Ok(self.provisioning_status(false));
        }
        let Value::Array(mailboxes) = &state[5] else {
            return Err(ERROR.into());
        };
        let mut provisioned = BTreeSet::new();
        for row in mailboxes {
            let Value::Array(f) = row else {
                return Err(ERROR.into());
            };
            if f.len() != 5 {
                return Err(ERROR.into());
            }
            if f[1] != Value::Integer(1.into()) {
                continue;
            }
            let Value::Integer(index) = f[0] else {
                return Err(ERROR.into());
            };
            let index = usize::try_from(index)
                .map_err(|_| ERROR)?
                .checked_sub(1)
                .filter(|i| *i < 3)
                .ok_or(ERROR)?;
            if f[2] != Value::Bytes(inventory.inboxes[index].route.mailbox.to_vec())
                || f[4] != Value::Integer(0.into())
            {
                return Err(ERROR.into());
            }
            if f[3] == Value::Integer(1.into()) {
                provisioned.insert(index);
            }
        }
        if provisioned.len() < 2 {
            return Ok(self.provisioning_status(false));
        }
        if self.context.own_slot != 1 {
            inventory.ready = true;
            self.journal.append(&inventory.encode()?)?;
            return Ok(self.provisioning_status(true));
        }
        let policy = self.policy()?;
        let descriptor = SetupInboxDescriptor::sign(
            &self.identity,
            &policy,
            &self.operators,
            inventory
                .inboxes
                .iter()
                .map(|inbox| DescriptorRelay {
                    route: inbox.route.clone(),
                    append: Secret32::from_bytes(*inbox.append.as_bytes()),
                })
                .collect(),
        )
        .map_err(|_| ERROR)?;
        for slot in 2..=self.context.count {
            let invite = SetupInvite::create_with_bootstrap(
                &self.identity,
                &policy,
                slot,
                inventory.claim,
                self.context.invitations[slot as usize - 2],
                &self.operators,
                &descriptor,
            )
            .map_err(|_| ERROR)?;
            inventory
                .invites
                .insert(slot, Zeroizing::new(invite.to_vec()));
        }
        inventory.ready = true;
        self.journal.append(&inventory.encode()?)?;
        Ok(self.provisioning_status(true))
    }
    fn bootstrap_context(&self) -> Result<loki_relay_client::BootstrapContext, String> {
        let creator = if self.context.own_slot == 1 {
            self.identity.public()
        } else {
            verified_invite(
                &self.context.grant,
                &self.context.bundle,
                &self.context.key,
                self.context.development,
                0,
            )?
            .context()
            .creator_identity()
            .clone()
        };
        loki_relay_client::BootstrapContext::creator(self.policy()?, creator, &self.operators)
            .map_err(|_| ERROR.into())
    }
    fn proposal_key(&self) -> Result<SetupKey, String> {
        Ok(SetupKey {
            ceremony: self.policy()?.ceremony,
            phase: SetupPhase::RosterProposal,
            author: 1,
            recipient: self.context.own_slot,
            revision: 1,
        })
    }
    fn authenticated_proposal(
        &self,
        store: &SetupStore,
        transport: &SetupTransport<'_>,
        claimed: &[MemberPublic],
        own: &[OwnerInbox],
    ) -> Result<Option<VerifiedProposal>, String> {
        let Some(record) = store
            .receive(transport, &self.proposal_key()?)
            .map_err(|_| "setup_transport")?
        else {
            return Ok(None);
        };
        let value = PrivateValue(
            canonical::decode(&record.body().payload, 65536).map_err(|_| "setup_roster")?,
        );
        let Value::Array(fields) = &value.0 else {
            return Err("setup_roster".into());
        };
        if fields.len() != 4 || fields[0] != Value::Integer(1.into()) {
            return Err("setup_roster".into());
        }
        let Value::Bytes(encoded) = &fields[1] else {
            return Err("setup_roster".into());
        };
        let roster =
            loki_relay_protocol::types::decode_roster(encoded).map_err(|_| "setup_roster")?;
        if roster.vault != transport.context().policy().ceremony
            || roster.members != claimed
            || roster.members.len() != self.context.count as usize
            || record.body().roster_digest
                != Some(
                    loki_relay_protocol::types::roster_digest(&roster)
                        .map_err(|_| "setup_roster")?,
                )
        {
            return Err("setup_roster".into());
        }
        let Value::Array(packages) = &fields[2] else {
            return Err("setup_roster".into());
        };
        if packages.len() != roster.members.len() {
            return Err("setup_roster".into());
        }
        let mut descriptors = Vec::new();
        for (package, peer) in packages.iter().zip(&roster.members) {
            let Value::Bytes(package) = package else {
                return Err("setup_roster".into());
            };
            let descriptor = SetupInboxDescriptor::verify(
                package,
                transport.context().policy(),
                &self.operators,
                peer,
            )
            .map_err(|_| "setup_roster")?;
            if peer.id == self.context.own_slot
                && (descriptor.relays().len() != own.len()
                    || descriptor.relays().iter().zip(own).any(|(r, inbox)| {
                        r.route != inbox.route || r.append.as_bytes() != inbox.append.as_bytes()
                    }))
            {
                return Err("setup_roster".into());
            }
            descriptors.push(descriptor);
        }
        let Value::Array(table) = &fields[3] else {
            return Err("setup_roster".into());
        };
        if table.len() != roster.members.len() {
            return Err("setup_roster".into());
        }
        let mut prerequisites = BTreeMap::new();
        for (index, value) in table.iter().enumerate() {
            let Value::Array(row) = value else {
                return Err("setup_roster".into());
            };
            let recipient = index as u16 + 1;
            if row.len() != 2 || row[0] != Value::Integer(u64::from(recipient).into()) {
                return Err("setup_roster".into());
            }
            let Value::Array(values) = &row[1] else {
                return Err("setup_roster".into());
            };
            if values.len()
                != if recipient == 1 {
                    roster.members.len() - 1
                } else {
                    1
                }
            {
                return Err("setup_roster".into());
            }
            let mut parents = Vec::new();
            for value in values {
                let Value::Bytes(bytes) = value else {
                    return Err("setup_roster".into());
                };
                let digest: [u8; 32] = bytes.as_slice().try_into().map_err(|_| "setup_roster")?;
                if digest == [0; 32] || parents.last().is_some_and(|p| *p >= digest) {
                    return Err("setup_roster".into());
                }
                parents.push(digest);
            }
            prerequisites.insert(recipient, parents);
        }
        if prerequisites.get(&self.context.own_slot) != Some(&record.body().prerequisites) {
            return Err("setup_roster".into());
        }
        let native = Self::native_roster(&roster, &self.policy()?)?;
        Ok(Some(VerifiedProposal {
            body: SecretRecords(vec![record.body().clone()]),
            prerequisites,
            roster,
            fingerprint: native.fingerprint(),
            descriptors,
        }))
    }
    fn prepare_roster_proposal(
        &self,
        store: &mut SetupStore,
        transport: &SetupTransport<'_>,
        routes: &SetupRoutes,
        claimed: &[MemberPublic],
    ) -> Result<(), String> {
        if self
            .authenticated_proposal(store, transport, claimed, &routes.own)?
            .is_some()
        {
            return Ok(());
        }
        if self.context.own_slot != 1
            || claimed.len() != self.context.count as usize
            || routes.peers.len() + 1 != claimed.len()
        {
            return Err("setup_waiting".into());
        }
        let roster = Roster {
            vault: self.policy()?.ceremony,
            members: claimed.to_vec(),
        };
        let own = SetupInboxDescriptor::sign(
            &self.identity,
            transport.context().policy(),
            &self.operators,
            routes
                .own
                .iter()
                .map(|r| DescriptorRelay {
                    route: r.route.clone(),
                    append: Secret32::from_bytes(*r.append.as_bytes()),
                })
                .collect(),
        )
        .map_err(|_| "setup_roster")?;
        let mut packages = vec![Value::Bytes(own.to_vec())];
        for (descriptor, peer) in routes.peers.iter().zip(claimed.iter().skip(1)) {
            if descriptor.owner_identity() != peer {
                return Err("setup_roster".into());
            }
            packages.push(Value::Bytes(descriptor.to_package().to_vec()));
        }
        let mut table = BTreeMap::new();
        for recipient in 1..=self.context.count {
            let mut prerequisites = Vec::new();
            for author in 2..=self.context.count {
                if recipient != 1 && recipient != author {
                    continue;
                }
                let join = store
                    .receive(
                        transport,
                        &SetupKey {
                            ceremony: roster.vault,
                            phase: SetupPhase::Join,
                            author,
                            recipient: 1,
                            revision: 1,
                        },
                    )
                    .map_err(|_| "setup_transport")?
                    .ok_or("setup_waiting")?;
                if recipient == 1 {
                    prerequisites.push(*join.digest());
                } else {
                    let mut copy = SecretRecords(vec![join.body().clone()]);
                    copy.0[0].key.recipient = recipient;
                    let encoded = Zeroizing::new(
                        loki_relay_protocol::setup::encode_record(&copy.0[0])
                            .map_err(|_| "setup_roster")?,
                    );
                    prerequisites.push(Sha256::digest(&*encoded).into());
                }
            }
            prerequisites.sort_unstable();
            prerequisites.dedup();
            table.insert(recipient, prerequisites);
        }
        let value = PrivateValue(Value::Array(vec![
            Value::Integer(1.into()),
            Value::Bytes(
                loki_relay_protocol::types::encode_roster(&roster).map_err(|_| "setup_roster")?,
            ),
            Value::Array(packages),
            Value::Array(
                table
                    .iter()
                    .map(|(recipient, parents)| {
                        Value::Array(vec![
                            Value::Integer(u64::from(*recipient).into()),
                            Value::Array(
                                parents.iter().map(|p| Value::Bytes(p.to_vec())).collect(),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ]));
        let payload = Zeroizing::new(canonical::encode(&value.0).map_err(|_| "setup_roster")?);
        let digest =
            loki_relay_protocol::types::roster_digest(&roster).map_err(|_| "setup_roster")?;
        let mut records = SecretRecords(Vec::new());
        for recipient in 1..=self.context.count {
            let prerequisites = table.get(&recipient).ok_or(ERROR)?.clone();
            records.0.push(SetupRecord {
                version: 1,
                key: SetupKey {
                    ceremony: roster.vault,
                    phase: SetupPhase::RosterProposal,
                    author: 1,
                    recipient,
                    revision: 1,
                },
                network: transport.context().policy().network.clone(),
                threshold: transport.context().policy().threshold,
                member_count: self.context.count,
                roster_digest: Some(digest),
                prerequisites,
                payload: payload.to_vec(),
            });
        }
        let prepared = transport.prepare(&records.0).map_err(|_| "setup_roster")?;
        store
            .commit_outgoing(transport, &prepared)
            .map_err(|_| "setup_transport")?;
        Ok(())
    }
    fn current_proposal(&self) -> Result<VerifiedProposal, String> {
        let raw = &self.journal.latest().ok_or(ERROR)?.payload;
        if raw[0] != 3 {
            return Err("setup_waiting".into());
        }
        let Some(state) = self.state()? else {
            return Err("setup_waiting".into());
        };
        let AdmissionOutcome::Accepted(Value::Array(fields)) = state.outcome() else {
            return Err("setup_admission".into());
        };
        if fields.len() != 7
            || fields[0] != Value::Integer(u64::from(self.context.count).into())
            || (fields[3] != Value::Integer(0.into())
                && !(fields[3] == Value::Integer(2.into())
                    && self.native_saved_phase()? == Some(CeremonyPhase::Active)))
        {
            return Err("setup_terminal".into());
        }
        let claimed = self.validate_claims(&fields[4])?;
        if claimed.len() != self.context.count as usize {
            return Err("setup_waiting".into());
        }
        let inventory = Inventory::decode(raw, &self.context, &self.operators, &self.identity)?;
        let context = self.bootstrap_context()?;
        let transport = SetupTransport::new(
            &self.identity,
            &self.operators,
            SetupAuthority::Bootstrap(&context, &claimed),
            self.context.development,
        )
        .map_err(|_| "setup_transport")?;
        let store = SetupStore::open(&self.root.join("setup-relay-store"), &transport)
            .map_err(|_| "setup_transport")?;
        let proposal = self
            .authenticated_proposal(&store, &transport, &claimed, &inventory.inboxes)?
            .ok_or("setup_waiting")?;
        Ok(proposal)
    }
    pub fn proposed_fingerprint(&self) -> Result<[u8; 32], String> {
        Ok(self.current_proposal()?.fingerprint)
    }
    fn native_fingerprint(roster: &Roster, policy: &SetupPolicy) -> Result<[u8; 32], String> {
        Ok(Self::native_roster(roster, policy)?.fingerprint())
    }
    fn native_roster(roster: &Roster, policy: &SetupPolicy) -> Result<crate::member_state::Roster, String> {
        let mut value = serde_json::json!({"vault":hex::encode(roster.vault), "threshold":policy.threshold,
            "members":roster.members.iter().map(|peer| serde_json::json!({"id":peer.id,
                "signing":hex::encode(peer.signing), "encryption":hex::encode(peer.encryption)})).collect::<Vec<_>>()});
        match VaultNetwork::parse(&policy.network)? {
            VaultNetwork::Regtest => {}
            VaultNetwork::Testnet => {
                value["network"] = serde_json::json!("testnet");
                // shortcut: scanning starts at NU7 activation; add a signed birth height if scans become too slow.
                value["birth_height"] = serde_json::json!(TESTNET_NU7_BIRTH);
            }
        }
        crate::member_state::Roster::from_bytes(&serde_json::to_vec(&value).map_err(|_| ERROR)?)
            .map_err(|_| "setup_roster".into())
    }
    fn saved_approval(&self) -> Result<Option<(Roster, [u8; 32], Vec<u8>)>, String> {
        let Some(generation) = self.approval.latest() else {
            return Ok(None);
        };
        if generation.number != 1 {
            return Err("setup_approval".into());
        }
        let Value::Array(fields) =
            canonical::decode(&generation.payload, 8192).map_err(|_| "setup_approval")?
        else {
            return Err("setup_approval".into());
        };
        if fields.len() != 4 || fields[0] != Value::Integer(1.into()) {
            return Err("setup_approval".into());
        }
        let (Value::Bytes(roster), Value::Bytes(fingerprint), Value::Bytes(package)) =
            (&fields[1], &fields[2], &fields[3])
        else {
            return Err("setup_approval".into());
        };
        let roster =
            loki_relay_protocol::types::decode_roster(roster).map_err(|_| "setup_approval")?;
        let fingerprint: [u8; 32] = fingerprint
            .as_slice()
            .try_into()
            .map_err(|_| "setup_approval")?;
        if roster.members.len() != self.context.count as usize
            || Self::native_fingerprint(&roster, &self.policy()?)? != fingerprint
        {
            return Err("setup_approval".into());
        }
        let expected = loki_relay_client::sign_roster_acceptance(
            &self.identity,
            &self.bootstrap_context()?,
            &roster,
            &loki_relay_protocol::setup::SetupCapabilities::current(),
        )
        .map_err(|_| "setup_approval")?;
        if expected != *package {
            return Err("setup_approval".into());
        }
        Ok(Some((roster, fingerprint, package.clone())))
    }
    pub fn agree(&mut self, expected: [u8; 32]) -> Result<SetupStatus, String> {
        let status = self.agree_inner(expected)?;
        self.cache_status(&status)?;
        Ok(status)
    }
    fn agree_inner(&mut self, expected: [u8; 32]) -> Result<SetupStatus, String> {
        let proposal = self.current_proposal()?;
        if proposal.fingerprint != expected {
            return Err("setup_fingerprint".into());
        }
        let package = loki_relay_client::sign_roster_acceptance(
            &self.identity,
            &self.bootstrap_context()?,
            &proposal.roster,
            &loki_relay_protocol::setup::SetupCapabilities::current(),
        )
        .map_err(|_| "setup_approval")?;
        if let Some((roster, fingerprint, saved)) = self.saved_approval()? {
            if roster != proposal.roster || fingerprint != expected || saved != package {
                return Err("setup_approval_conflict".into());
            }
        } else {
            let encoded = canonical::encode(&Value::Array(vec![
                Value::Integer(1.into()),
                Value::Bytes(
                    loki_relay_protocol::types::encode_roster(&proposal.roster)
                        .map_err(|_| ERROR)?,
                ),
                Value::Bytes(expected.to_vec()),
                Value::Bytes(package),
            ]))
            .map_err(|_| ERROR)?;
            self.approval.append(&encoded)?;
        }
        Ok(SetupStatus {
            own_slot: self.context.own_slot,
            threshold: self.threshold,
            count: self.context.count,
            phase: "agreement_saved",
            joined: proposal.roster.members.iter().map(|p| p.id).collect(),
            agreed: Some(expected),
            waiting: None,
            retryable: true,
        })
    }
    fn acceptance_key(&self) -> Result<SetupKey, String> {
        Ok(SetupKey {
            ceremony: self.policy()?.ceremony,
            phase: SetupPhase::RosterAccept,
            author: self.context.own_slot,
            recipient: self.context.own_slot,
            revision: 1,
        })
    }
    fn accepted_from_store(
        &self,
        store: &SetupStore,
        transport: &SetupTransport<'_>,
        roster: &Roster,
    ) -> Result<Option<loki_relay_client::AcceptedSetupRoster>, String> {
        let mut packages = Vec::new();
        for peer in &roster.members {
            let Some(record) = store
                .receive(
                    transport,
                    &SetupKey {
                        ceremony: roster.vault,
                        phase: SetupPhase::RosterAccept,
                        author: peer.id,
                        recipient: self.context.own_slot,
                        revision: 1,
                    },
                )
                .map_err(|_| "setup_transport")?
            else {
                return Ok(None);
            };
            packages.push(record.body().payload.clone());
        }
        Ok(Some(
            loki_relay_client::AcceptedSetupRoster::verify(
                transport.context(),
                roster.clone(),
                &packages,
            )
            .map_err(|_| "setup_acceptance")?,
        ))
    }
    fn acceptance_step(&self, claimed: &[MemberPublic]) -> Result<SetupStatus, String> {
        let (roster, fingerprint, package) = self.saved_approval()?.ok_or("setup_waiting")?;
        if roster.members != claimed {
            return Err("setup_approval_conflict".into());
        }
        let inventory = Inventory::decode(
            &self.journal.latest().ok_or(ERROR)?.payload,
            &self.context,
            &self.operators,
            &self.identity,
        )?;
        let context = self.bootstrap_context()?;
        let transport = SetupTransport::new(
            &self.identity,
            &self.operators,
            SetupAuthority::Bootstrap(&context, claimed),
            self.context.development,
        )
        .map_err(|_| "setup_transport")?;
        let mut store = SetupStore::open(&self.root.join("setup-relay-store"), &transport)
            .map_err(|_| "setup_transport")?;
        let proposal = self
            .authenticated_proposal(&store, &transport, claimed, &inventory.inboxes)?
            .ok_or("setup_waiting")?;
        if proposal.roster != roster || proposal.fingerprint != fingerprint {
            return Err("setup_approval_conflict".into());
        }
        let routes = SetupRoutes {
            own: inventory.inboxes,
            peers: proposal
                .descriptors
                .into_iter()
                .filter(|d| d.owner() != self.context.own_slot)
                .collect(),
        };
        let previous = if self.context.own_slot == 1 {
            self.proposal_key()?
        } else {
            SetupKey {
                ceremony: roster.vault,
                phase: SetupPhase::Join,
                author: self.context.own_slot,
                recipient: self.context.own_slot,
                revision: 1,
            }
        };
        let ready = store
            .progress_for(&transport, &routes, &previous)
            .map_err(|_| "setup_transport")?;
        let key = self.acceptance_key()?;
        if ready.stored_groups == 1 && ready.received_groups == 1 {
            if let Some(record) = store
                .receive(&transport, &key)
                .map_err(|_| "setup_transport")?
            {
                if record.body().payload != package {
                    return Err("setup_approval_conflict".into());
                }
            } else {
                let mut records = SecretRecords(Vec::new());
                for recipient in 1..=self.context.count {
                    let mut parent = SecretRecords(vec![proposal.body.0[0].clone()]);
                    parent.0[0].key.recipient = recipient;
                    parent.0[0].prerequisites = proposal
                        .prerequisites
                        .get(&recipient)
                        .ok_or("setup_roster")?
                        .clone();
                    let encoded = Zeroizing::new(
                        loki_relay_protocol::setup::encode_record(&parent.0[0])
                            .map_err(|_| "setup_roster")?,
                    );
                    let predecessor = Sha256::digest(&*encoded).into();
                    records.0.push(SetupRecord {
                        version: 1,
                        key: SetupKey {
                            recipient,
                            ..key.clone()
                        },
                        network: context.policy().network.clone(),
                        threshold: context.policy().threshold,
                        member_count: self.context.count,
                        roster_digest: Some(
                            loki_relay_protocol::types::roster_digest(&roster)
                                .map_err(|_| "setup_roster")?,
                        ),
                        prerequisites: vec![predecessor],
                        payload: package.clone(),
                    });
                }
                let prepared = transport
                    .prepare(&records.0)
                    .map_err(|_| "setup_acceptance")?;
                store
                    .commit_outgoing(&transport, &prepared)
                    .map_err(|_| "setup_transport")?;
            }
        }
        if let Some(accepted) = self.accepted_from_store(&store, &transport, &roster)? {
            return self.ceremony_step(
                &accepted,
                &mut store,
                &routes,
                &proposal.body.0[0],
                &proposal.prerequisites,
                fingerprint,
                true,
            );
        }
        self.runtime
            .block_on(transport.drive_once(&mut store, &routes))
            .map_err(|_| "setup_transport")?;
        if let Some(accepted) = self.accepted_from_store(&store, &transport, &roster)? {
            return self.ceremony_step(
                &accepted,
                &mut store,
                &routes,
                &proposal.body.0[0],
                &proposal.prerequisites,
                fingerprint,
                false,
            );
        }
        let progress = store
            .progress_for(&transport, &routes, &key)
            .map_err(|_| "setup_transport")?;
        let accepted = if progress.stored_groups == 1 && progress.received_groups == 1 {
            self.accepted_from_store(&store, &transport, &roster)?
                .is_some()
        } else {
            false
        };
        let mut missing_acceptances = Vec::new();
        for peer in &roster.members {
            if store
                .receive(
                    &transport,
                    &SetupKey {
                        author: peer.id,
                        ..key.clone()
                    },
                )
                .map_err(|_| "setup_transport")?
                .is_none()
            {
                missing_acceptances.push(peer.id);
            }
        }
        Ok(SetupStatus {
            own_slot: self.context.own_slot,
            threshold: self.threshold,
            count: self.context.count,
            joined: roster.members.iter().map(|p| p.id).collect(),
            agreed: Some(fingerprint),
            waiting: Some(missing_acceptances),
            phase: if accepted {
                "roster_accepted"
            } else {
                "acceptance_pending"
            },
            retryable: !accepted,
        })
    }
    fn native_setup_phase(phase: CeremonyPhase) -> Option<SetupPhase> {
        match phase {
            CeremonyPhase::Round1Saved => Some(SetupPhase::Round1),
            CeremonyPhase::Round2Saved => Some(SetupPhase::Round2),
            CeremonyPhase::CertificateSaved => Some(SetupPhase::Certificate),
            CeremonyPhase::AwaitingBackups => Some(SetupPhase::BackupReceipt),
            _ => None,
        }
    }
    fn prepare_native_delivery(
        &self,
        transport: &SetupTransport<'_>,
        phase: CeremonyPhase,
        outgoing: &BTreeMap<u16, Vec<u8>>,
        prerequisites: &BTreeMap<u16, Vec<[u8; 32]>>,
        digest: [u8; 32],
    ) -> Result<Vec<u8>, String> {
        if outgoing.is_empty() {
            return Ok(Vec::new());
        }
        let phase = Self::native_setup_phase(phase).ok_or("setup_ceremony")?;
        let policy = self.policy()?;
        let mut records = SecretRecords(Vec::new());
        for (&recipient, wire) in outgoing {
            records.0.push(SetupRecord {
                version: 1,
                key: SetupKey {
                    ceremony: policy.ceremony,
                    phase,
                    author: self.context.own_slot,
                    recipient,
                    revision: 1,
                },
                network: policy.network.clone(),
                threshold: policy.threshold,
                member_count: policy.member_count,
                roster_digest: Some(digest),
                prerequisites: prerequisites
                    .get(&recipient)
                    .ok_or("setup_prerequisite")?
                    .clone(),
                payload: wire.clone(),
            });
        }
        let prepared = transport
            .prepare(&records.0)
            .map_err(|_| "setup_transport")?;
        transport
            .checkpoint_prepared(&prepared)
            .map_err(|_| "setup_transport".into())
    }
    fn ceremony_step(
        &self,
        accepted: &loki_relay_client::AcceptedSetupRoster,
        store: &mut SetupStore,
        routes: &SetupRoutes,
        proposal: &SetupRecord,
        proposal_parents: &BTreeMap<u16, Vec<[u8; 32]>>,
        fingerprint: [u8; 32],
        may_drive: bool,
    ) -> Result<SetupStatus, String> {
        let transport = SetupTransport::new(
            &self.identity,
            &self.operators,
            SetupAuthority::Accepted(accepted),
            self.context.development,
        )
        .map_err(|_| "setup_transport")?;
        let progress = store
            .progress_for(&transport, routes, &self.acceptance_key()?)
            .map_err(|_| "setup_transport")?;
        let status = |phase: &'static str| SetupStatus {
            own_slot: self.context.own_slot,
            threshold: self.threshold,
            count: self.context.count,
            phase,
            joined: accepted.roster().members.iter().map(|p| p.id).collect(),
            agreed: Some(fingerprint),
            waiting: None,
            retryable: true,
        };
        if progress.stored_groups != 1 || progress.received_groups != 1 {
            if self.root.join("setup-ceremony").exists() {
                return Err("setup_transport".into());
            }
            if may_drive {
                self.runtime
                    .block_on(transport.drive_once(store, routes))
                    .map_err(|_| "setup_transport")?;
            }
            return Ok(status("acceptance_pending"));
        }
        let native_accepted = AcceptedCeremonyRoster::from_transport(accepted)?;
        let raw = Zeroizing::new(
            MemberDir::open(&self.root, "secrets")
                .read_sealed("identity.sealed", &self.passphrase)
                .map_err(|_| "setup_identity")?,
        );
        let native_identity = Identity::from_secret_bytes(&raw).map_err(|_| "setup_identity")?;
        let mut authority = AdmissionCheckpointAuthority::new(
            &native_identity,
            &self.operators,
            &native_accepted,
            self.context.development,
        )?
        .with_retry(self.retry.clone());
        let mut engine = SetupCeremony::open_with_member_lock(
            &self.root,
            &self.passphrase,
            native_accepted,
            &self._member_lock,
        )?;
        engine.synchronize(&mut authority)?;
        if matches!(
            engine.phase(),
            CeremonyPhase::Certified | CeremonyPhase::PaymentHandoff | CeremonyPhase::Active
        ) {
            let handoff = self.payment_handoff_step(
                &mut engine,
                &mut authority,
                store,
                &transport,
                routes,
                accepted,
                may_drive,
            )?;
            let mut result = status(if handoff.ready {
                "active"
            } else {
                "payment_handoff"
            });
            result.waiting = Some(handoff.missing_slots);
            return Ok(result);
        }
        if engine.phase() == CeremonyPhase::AwaitingRoster {
            let mut predecessors = BTreeMap::new();
            for recipient in 1..=self.context.count {
                let mut proposal_copy = SecretRecords(vec![proposal.clone()]);
                proposal_copy.0[0].key.recipient = recipient;
                proposal_copy.0[0].prerequisites = proposal_parents
                    .get(&recipient)
                    .ok_or("setup_prerequisite")?
                    .clone();
                let proposal_digest: [u8; 32] = Sha256::digest(
                    loki_relay_protocol::setup::encode_record(&proposal_copy.0[0])
                        .map_err(|_| ERROR)?,
                )
                .into();
                let mut parents = Vec::new();
                for peer in &accepted.roster().members {
                    let key = SetupKey {
                        author: peer.id,
                        ..self.acceptance_key()?
                    };
                    let vote = store
                        .receive(&transport, &key)
                        .map_err(|_| "setup_transport")?
                        .ok_or("setup_acceptance")?;
                    let mut copy = SecretRecords(vec![vote.body().clone()]);
                    copy.0[0].key.recipient = recipient;
                    copy.0[0].prerequisites = vec![proposal_digest];
                    parents.push(
                        Sha256::digest(
                            loki_relay_protocol::setup::encode_record(&copy.0[0])
                                .map_err(|_| ERROR)?,
                        )
                        .into(),
                    );
                }
                parents.sort();
                parents.dedup();
                predecessors.insert(recipient, parents);
            }
            engine.step_with_preparation(&[], |phase, outgoing| {
                self.prepare_native_delivery(
                    &transport,
                    phase,
                    outgoing,
                    &predecessors,
                    *accepted.digest(),
                )
            })?;
            engine.synchronize(&mut authority)?;
            engine.step_with_preparation(&[], |phase, outgoing| {
                self.prepare_native_delivery(
                    &transport,
                    phase,
                    outgoing,
                    &predecessors,
                    *accepted.digest(),
                )
            })?;
            engine.synchronize(&mut authority)?;
        } else if matches!(
            engine.phase(),
            CeremonyPhase::Round1Saved
                | CeremonyPhase::Round2Saved
                | CeremonyPhase::CertificateSaved
        ) || (engine.phase() == CeremonyPhase::AwaitingBackups
            && !engine.prepared_delivery()?.is_empty())
        {
            let phase = engine.phase();
            let prepared = transport
                .restore_prepared(engine.prepared_delivery()?)
                .map_err(|_| "setup_transport")?;
            store
                .commit_outgoing(&transport, &prepared)
                .map_err(|_| "setup_transport")?;
            let key = SetupKey {
                ceremony: accepted.roster().vault,
                phase: Self::native_setup_phase(phase).ok_or("setup_ceremony")?,
                author: self.context.own_slot,
                recipient: self.context.own_slot,
                revision: 1,
            };
            let progress = store
                .progress_for(&transport, routes, &key)
                .map_err(|_| "setup_transport")?;
            if progress.stored_groups == 1 && progress.received_groups == 1 {
                struct Incoming(Vec<CeremonyRecord>);
                impl Drop for Incoming {
                    fn drop(&mut self) {
                        for r in &mut self.0 {
                            r.bytes.zeroize();
                        }
                    }
                }
                let mut incoming = Incoming(Vec::new());
                for peer in &accepted.roster().members {
                    if let Some(record) = store
                        .receive(
                            &transport,
                            &SetupKey {
                                author: peer.id,
                                ..key.clone()
                            },
                        )
                        .map_err(|_| "setup_transport")?
                    {
                        incoming.0.push(CeremonyRecord {
                            phase,
                            author: peer.id,
                            bytes: record.body().payload.clone(),
                        });
                    }
                }
                if incoming.0.len() == self.context.count as usize {
                    let predecessors = (1..=self.context.count)
                        .map(|recipient| {
                            Ok((
                                recipient,
                                vec![prepared
                                    .recipient_digest(recipient)
                                    .map_err(|_| "setup_transport")?],
                            ))
                        })
                        .collect::<Result<BTreeMap<_, _>, String>>()?;
                    if phase == CeremonyPhase::CertificateSaved {
                        self.save_certificate_delivery(engine.prepared_delivery()?)?;
                    }
                    engine.step_with_preparation(&incoming.0, |phase, outgoing| {
                        self.prepare_native_delivery(
                            &transport,
                            phase,
                            outgoing,
                            &predecessors,
                            *accepted.digest(),
                        )
                    })?;
                    engine.synchronize(&mut authority)?;
                }
            }
        }
        if !engine.prepared_delivery()?.is_empty() {
            let prepared = transport
                .restore_prepared(engine.prepared_delivery()?)
                .map_err(|_| "setup_transport")?;
            store
                .commit_outgoing(&transport, &prepared)
                .map_err(|_| "setup_transport")?;
        }
        if may_drive {
            self.runtime
                .block_on(transport.drive_once(store, routes))
                .map_err(|_| "setup_transport")?;
        }
        let phase = match engine.phase() {
            CeremonyPhase::Round1Saved => "round1_saved",
            CeremonyPhase::Round2Saved => "round2_saved",
            CeremonyPhase::CertificateSaved => "certificate_saved",
            CeremonyPhase::AwaitingBackups => "awaiting_backups",
            CeremonyPhase::Certified => "certified",
            _ => return Err("setup_ceremony".into()),
        };
        let mut result = status(phase);
        let mut missing = Vec::new();
        if let Some(current) = Self::native_setup_phase(engine.phase()) {
            for author in 1..=self.context.count {
                let key = SetupKey {
                    ceremony: accepted.roster().vault,
                    phase: current,
                    author,
                    recipient: self.context.own_slot,
                    revision: 1,
                };
                if store
                    .receive(&transport, &key)
                    .map_err(|_| "setup_transport")?
                    .is_none()
                {
                    missing.push(author);
                }
            }
        }
        result.waiting = Some(missing);
        Ok(result)
    }
    fn backup_journal(&self) -> Result<Journal, String> {
        let mut binding = blake3::Hasher::new();
        binding.update(b"Loki_Hosted_Backup_Context_v1\0");
        binding.update(&self.context.encode()?);
        Journal::open(
            &self.root.join("setup-backup"),
            &self.passphrase,
            *binding.finalize().as_bytes(),
            self.context.own_slot,
        )
    }
    fn save_certificate_delivery(&self, raw: &[u8]) -> Result<(), String> {
        if raw.is_empty() || raw.len() > 8 * 1024 * 1024 {
            return Err("setup_backup".into());
        }
        let encoded = canonical::encode(&Value::Array(vec![
            Value::Integer(1.into()),
            Value::Bytes(raw.to_vec()),
        ]))
        .map_err(|_| "setup_backup")?;
        let mut journal = self.backup_journal()?;
        if let Some(saved) = journal.latest() {
            if saved.number != 1 || saved.payload.as_slice() != encoded {
                return Err("setup_backup".into());
            }
        } else {
            journal.append(&encoded)?;
        }
        Ok(())
    }
    fn certificate_predecessors(
        &self,
        transport: &SetupTransport<'_>,
        store: &SetupStore,
    ) -> Result<BTreeMap<u16, Vec<[u8; 32]>>, String> {
        let journal = self.backup_journal()?;
        let saved = journal.latest().ok_or("setup_backup")?;
        if saved.number != 1 {
            return Err("setup_backup".into());
        }
        let value = PrivateValue(
            canonical::decode(&saved.payload, 8 * 1024 * 1024 + 64).map_err(|_| "setup_backup")?,
        );
        let Value::Array(fields) = &value.0 else {
            return Err("setup_backup".into());
        };
        if fields.len() != 2 || fields[0] != Value::Integer(1.into()) {
            return Err("setup_backup".into());
        }
        let Value::Bytes(raw) = &fields[1] else {
            return Err("setup_backup".into());
        };
        let prepared = transport
            .restore_prepared(raw)
            .map_err(|_| "setup_backup")?;
        let certificate = store
            .receive(
                transport,
                &SetupKey {
                    ceremony: self.policy()?.ceremony,
                    phase: SetupPhase::Certificate,
                    author: self.context.own_slot,
                    recipient: self.context.own_slot,
                    revision: 1,
                },
            )
            .map_err(|_| "setup_backup")?
            .ok_or("setup_backup")?;
        if prepared
            .recipient_digest(self.context.own_slot)
            .map_err(|_| "setup_backup")?
            != *certificate.digest()
        {
            return Err("setup_backup".into());
        }
        (1..=self.context.count)
            .map(|recipient| {
                Ok((
                    recipient,
                    vec![prepared
                        .recipient_digest(recipient)
                        .map_err(|_| "setup_backup")?],
                ))
            })
            .collect()
    }
    fn with_accepted_ceremony<T, F>(&self, action: F) -> Result<T, String>
    where
        F: FnOnce(
            &mut SetupCeremony,
            &mut AdmissionCheckpointAuthority,
            &mut SetupStore,
            &SetupTransport<'_>,
            &SetupRoutes,
            &loki_relay_client::AcceptedSetupRoster,
        ) -> Result<T, String>,
    {
        let proposal = self.current_proposal()?;
        let (roster, fingerprint, _) = self.saved_approval()?.ok_or("setup_approval")?;
        if roster != proposal.roster || fingerprint != proposal.fingerprint {
            return Err("setup_approval_conflict".into());
        }
        let inventory = Inventory::decode(
            &self.journal.latest().ok_or(ERROR)?.payload,
            &self.context,
            &self.operators,
            &self.identity,
        )?;
        let context = self.bootstrap_context()?;
        let bootstrap = SetupTransport::new(
            &self.identity,
            &self.operators,
            SetupAuthority::Bootstrap(&context, &roster.members),
            self.context.development,
        )
        .map_err(|_| "setup_transport")?;
        let mut store = SetupStore::open(&self.root.join("setup-relay-store"), &bootstrap)
            .map_err(|_| "setup_transport")?;
        let accepted = self
            .accepted_from_store(&store, &bootstrap, &roster)?
            .ok_or("setup_waiting")?;
        let transport = SetupTransport::new(
            &self.identity,
            &self.operators,
            SetupAuthority::Accepted(&accepted),
            self.context.development,
        )
        .map_err(|_| "setup_transport")?;
        let routes = SetupRoutes {
            own: inventory.inboxes,
            peers: proposal
                .descriptors
                .into_iter()
                .filter(|d| d.owner() != self.context.own_slot)
                .collect(),
        };
        let progress = store
            .progress_for(&transport, &routes, &self.acceptance_key()?)
            .map_err(|_| "setup_transport")?;
        if progress.stored_groups != 1 || progress.received_groups != 1 {
            return Err("setup_waiting".into());
        }
        let native_accepted = AcceptedCeremonyRoster::from_transport(&accepted)?;
        let raw = Zeroizing::new(
            MemberDir::open(&self.root, "secrets")
                .read_sealed("identity.sealed", &self.passphrase)
                .map_err(|_| "setup_identity")?,
        );
        let identity = Identity::from_secret_bytes(&raw).map_err(|_| "setup_identity")?;
        let mut authority = AdmissionCheckpointAuthority::new(
            &identity,
            &self.operators,
            &native_accepted,
            self.context.development,
        )?
        .with_retry(self.retry.clone());
        let mut engine = SetupCeremony::open_with_member_lock(
            &self.root,
            &self.passphrase,
            native_accepted,
            &self._member_lock,
        )?;
        engine.synchronize(&mut authority)?;
        action(
            &mut engine,
            &mut authority,
            &mut store,
            &transport,
            &routes,
            &accepted,
        )
    }
    pub fn backup_create(&self, path: &Path) -> Result<Zeroizing<String>, String> {
        self.with_accepted_ceremony(|engine, _, _, _, _, _| {
            if !matches!(
                engine.phase(),
                CeremonyPhase::AwaitingBackups
                    | CeremonyPhase::Certified
                    | CeremonyPhase::PaymentHandoff
                    | CeremonyPhase::Active
            ) {
                return Err("setup_backups_pending".into());
            }
            let state = engine.certified_vault_state()?;
            crate::setup_backup::create(
                &self.root,
                &self.passphrase,
                path,
                &state,
                &self._member_lock,
            )
        })
    }
    pub fn backup_verify(&self, path: &Path, words: &str) -> Result<(), String> {
        self.with_accepted_ceremony(|engine, authority, store, transport, _, accepted| {
            let recovered = crate::setup_backup::recover(path, words)?;
            if matches!(
                engine.phase(),
                CeremonyPhase::Certified | CeremonyPhase::PaymentHandoff | CeremonyPhase::Active
            ) {
                if recovered.as_slice() != engine.certified_vault_state()?.as_slice() {
                    return Err("setup_backup".into());
                }
                engine.backup_receipts()?;
                return Ok(());
            }
            let predecessors = self.certificate_predecessors(transport, store)?;
            engine.confirm_local_backup(&recovered, |phase, outgoing| {
                self.prepare_native_delivery(
                    transport,
                    phase,
                    outgoing,
                    &predecessors,
                    *accepted.digest(),
                )
            })?;
            engine.synchronize(authority)?;
            let prepared = transport
                .restore_prepared(engine.prepared_delivery()?)
                .map_err(|_| "setup_transport")?;
            store
                .commit_outgoing(transport, &prepared)
                .map_err(|_| "setup_transport")?;
            Ok(())
        })
    }
    pub fn backup_finalize(
        &self,
        provisional: &Path,
        destination: &Path,
        words: &str,
    ) -> Result<ValueJson, String> {
        self.with_accepted_ceremony(|engine,_,_,_,_,accepted| {
            if !matches!(engine.phase(), CeremonyPhase::Certified | CeremonyPhase::PaymentHandoff | CeremonyPhase::Active) { return Err("setup_backups_pending".into()); }
            let state = engine.certified_vault_state()?;
            let private_state = crate::setup_backup::PrivateJson(serde_json::from_slice(&state).map_err(|_| "setup_backup")?);
            let mut roster = serde_json::json!({"vault":hex::encode(accepted.roster().vault),"threshold":accepted.context().policy().threshold,
                "members":accepted.roster().members.iter().map(|peer| serde_json::json!({
                    "id":peer.id,"signing":hex::encode(peer.signing),"encryption":hex::encode(peer.encryption)
                })).collect::<Vec<_>>()});
            if accepted.context().policy().network == "testnet" {
                roster["network"] = serde_json::json!("testnet");
                roster["birth_height"] = serde_json::json!(TESTNET_NU7_BIRTH);
            }
            let receipts = engine.backup_receipts()?.iter().map(|(id,wire)| (id.to_string(),hex::encode(wire)))
                .collect::<BTreeMap<_,_>>();
            let evidence = crate::setup_backup::PrivateJson(serde_json::json!({"recovery_version":2,
                "state":private_state.0,"roster":roster,"receipts":receipts}));
            let encoded = Zeroizing::new(serde_json::to_vec(&evidence.0).map_err(|_| "setup_backup")?);
            crate::setup_backup::finish(&self.root,&self.passphrase,provisional,destination,words,&state,&encoded,&self._member_lock)?;
            Ok(serde_json::json!({"final_card":"checked"}))
        })
    }
    pub fn roster_accepted(&self) -> Result<bool, String> {
        let Some((roster, _, _)) = self.saved_approval()? else {
            return Ok(false);
        };
        let proposal = self.current_proposal()?;
        if proposal.roster != roster {
            return Err("setup_approval_conflict".into());
        }
        let inventory = Inventory::decode(
            &self.journal.latest().ok_or(ERROR)?.payload,
            &self.context,
            &self.operators,
            &self.identity,
        )?;
        let context = self.bootstrap_context()?;
        let transport = SetupTransport::new(
            &self.identity,
            &self.operators,
            SetupAuthority::Bootstrap(&context, &roster.members),
            self.context.development,
        )
        .map_err(|_| "setup_transport")?;
        let store = SetupStore::open(&self.root.join("setup-relay-store"), &transport)
            .map_err(|_| "setup_transport")?;
        let routes = SetupRoutes {
            own: inventory.inboxes,
            peers: proposal
                .descriptors
                .into_iter()
                .filter(|d| d.owner() != self.context.own_slot)
                .collect(),
        };
        let progress = store
            .progress_for(&transport, &routes, &self.acceptance_key()?)
            .map_err(|_| "setup_transport")?;
        if progress.stored_groups != 1 || progress.received_groups != 1 {
            return Ok(false);
        }
        Ok(self
            .accepted_from_store(&store, &transport, &roster)?
            .is_some())
    }
    fn received_join_descriptors(
        &self,
        store: &SetupStore,
        transport: &SetupTransport<'_>,
        claimed: &[loki_relay_protocol::types::MemberPublic],
    ) -> Result<Vec<SetupInboxDescriptor>, String> {
        use loki_relay_protocol::setup::{SetupCapabilities, SetupKey, SetupPhase};
        let policy = transport.context().policy();
        let mut descriptors = Vec::new();
        for peer in claimed.iter().filter(|p| p.id != 1) {
            let key = SetupKey {
                ceremony: policy.ceremony,
                phase: SetupPhase::Join,
                author: peer.id,
                recipient: 1,
                revision: 1,
            };
            let Some(record) = store
                .receive(transport, &key)
                .map_err(|_| "setup_transport")?
            else {
                continue;
            };
            let value = PrivateValue(
                canonical::decode(&record.body().payload, 4096).map_err(|_| "setup_join")?,
            );
            let Value::Array(fields) = &value.0 else {
                return Err("setup_join".into());
            };
            if fields.len() != 4 || fields[0] != Value::Integer(1.into()) {
                return Err("setup_join".into());
            }
            fn list(value: &Value) -> Result<Vec<u16>, String> {
                let Value::Array(values) = value else {
                    return Err("setup_join".into());
                };
                if values.is_empty() || values.len() > 32 {
                    return Err("setup_join".into());
                }
                let mut result = Vec::new();
                for value in values {
                    let Value::Integer(number) = value else {
                        return Err("setup_join".into());
                    };
                    let number = u16::try_from(*number).map_err(|_| "setup_join")?;
                    if number == 0 || result.last().is_some_and(|prior| *prior >= number) {
                        return Err("setup_join".into());
                    }
                    result.push(number);
                }
                Ok(result)
            }
            SetupCapabilities {
                versions: list(&fields[1])?,
                member_counts: list(&fields[2])?,
            }
            .require(1, policy.member_count)
            .map_err(|_| "setup_capabilities")?;
            let Value::Bytes(package) = &fields[3] else {
                return Err("setup_join".into());
            };
            descriptors.push(
                SetupInboxDescriptor::verify(package, policy, &self.operators, peer)
                    .map_err(|_| "setup_join")?,
            );
        }
        Ok(descriptors)
    }
    fn receive_joins(
        &self,
        claimed: &[loki_relay_protocol::types::MemberPublic],
    ) -> Result<SetupStatus, String> {
        let inventory = Inventory::decode(
            &self.journal.latest().ok_or(ERROR)?.payload,
            &self.context,
            &self.operators,
            &self.identity,
        )?;
        let context = loki_relay_client::BootstrapContext::creator(
            self.policy()?,
            self.identity.public(),
            &self.operators,
        )
        .map_err(|_| ERROR)?;
        let transport = SetupTransport::new(
            &self.identity,
            &self.operators,
            SetupAuthority::Bootstrap(&context, claimed),
            self.context.development,
        )
        .map_err(|_| "setup_transport")?;
        let mut store = SetupStore::open(&self.root.join("setup-relay-store"), &transport)
            .map_err(|_| "setup_transport")?;
        let routes = SetupRoutes {
            own: inventory.inboxes,
            peers: self.received_join_descriptors(&store, &transport, claimed)?,
        };
        let proposal_prepared = routes.peers.len() + 1 == self.context.count as usize;
        if proposal_prepared {
            self.prepare_roster_proposal(&mut store, &transport, &routes, claimed)?;
        }
        self.runtime
            .block_on(transport.drive_once(&mut store, &routes))
            .map_err(|_| "setup_transport")?;
        let proposal_progress = if proposal_prepared {
            Some(
                store
                    .progress_for(&transport, &routes, &self.proposal_key()?)
                    .map_err(|_| "setup_transport")?,
            )
        } else {
            None
        };
        let descriptors = self.received_join_descriptors(&store, &transport, claimed)?;
        let mut joined = vec![1];
        joined.extend(descriptors.iter().map(SetupInboxDescriptor::owner));
        let complete = joined.len() == self.context.count as usize;
        Ok(SetupStatus {
            agreed: self.saved_approval()?.map(|(_, fp, _)| fp),
            waiting: None,
            own_slot: 1,
            phase: if let Some(progress) = &proposal_progress {
                if progress.stored_groups == 1 {
                    "roster_proposed"
                } else {
                    "proposal_pending"
                }
            } else if complete {
                "joins_received"
            } else {
                "waiting_joins"
            },
            threshold: self.threshold,
            count: self.context.count,
            joined,
            retryable: proposal_progress
                .as_ref()
                .map_or(!complete, |p| p.received_groups != 1),
        })
    }
    fn publish_join(&self, claimed: &[MemberPublic]) -> Result<SetupStatus, String> {
        use loki_relay_protocol::setup::{SetupCapabilities, SetupKey, SetupPhase, SetupRecord};
        struct Records(Vec<SetupRecord>);
        impl Drop for Records {
            fn drop(&mut self) {
                for record in &mut self.0 {
                    record.payload.zeroize();
                }
            }
        }
        let inventory = Inventory::decode(
            &self.journal.latest().ok_or(ERROR)?.payload,
            &self.context,
            &self.operators,
            &self.identity,
        )?;
        let invite = verified_invite(
            &self.context.grant,
            &self.context.bundle,
            &self.context.key,
            self.context.development,
            0,
        )?;
        let policy = invite.context().policy();
        let creator = invite.context().creator_identity();
        let peers = claimed;
        let transport = SetupTransport::new(
            &self.identity,
            &self.operators,
            SetupAuthority::Bootstrap(invite.context(), peers),
            self.context.development,
        )
        .map_err(|_| ERROR)?;
        let descriptor = SetupInboxDescriptor::sign(
            &self.identity,
            policy,
            &self.operators,
            inventory
                .inboxes
                .iter()
                .map(|inbox| DescriptorRelay {
                    route: inbox.route.clone(),
                    append: Secret32::from_bytes(*inbox.append.as_bytes()),
                })
                .collect(),
        )
        .map_err(|_| ERROR)?;
        let capabilities = SetupCapabilities::current();
        capabilities
            .require(1, policy.member_count)
            .map_err(|_| ERROR)?;
        let value = PrivateValue(Value::Array(vec![
            Value::Integer(1.into()),
            Value::Array(
                capabilities
                    .versions
                    .iter()
                    .map(|n| Value::Integer(u64::from(*n).into()))
                    .collect(),
            ),
            Value::Array(
                capabilities
                    .member_counts
                    .iter()
                    .map(|n| Value::Integer(u64::from(*n).into()))
                    .collect(),
            ),
            Value::Bytes(descriptor.to_vec()),
        ]));
        let payload = Zeroizing::new(canonical::encode(&value.0).map_err(|_| ERROR)?);
        let key = SetupKey {
            ceremony: policy.ceremony,
            phase: SetupPhase::Join,
            author: self.context.own_slot,
            recipient: self.context.own_slot,
            revision: 1,
        };
        let mut store = SetupStore::open(&self.root.join("setup-relay-store"), &transport)
            .map_err(|_| "setup_transport")?;
        if let Some(saved) = store
            .receive(&transport, &key)
            .map_err(|_| "setup_transport")?
        {
            if saved.body().payload != *payload {
                return Err("setup_transport_conflict".into());
            }
        } else {
            let records = Records(
                [1, self.context.own_slot]
                    .into_iter()
                    .map(|recipient| SetupRecord {
                        version: 1,
                        key: SetupKey {
                            recipient,
                            ..key.clone()
                        },
                        network: policy.network.clone(),
                        threshold: policy.threshold,
                        member_count: policy.member_count,
                        roster_digest: None,
                        prerequisites: Vec::new(),
                        payload: payload.to_vec(),
                    })
                    .collect(),
            );
            let prepared = transport
                .prepare(&records.0)
                .map_err(|_| "setup_transport")?;
            store
                .commit_outgoing(&transport, &prepared)
                .map_err(|_| "setup_transport")?;
        }
        let imported = invite.bootstrap_descriptor().ok_or(ERROR)?;
        let creator_descriptor =
            SetupInboxDescriptor::verify(&imported.to_package(), policy, &self.operators, creator)
                .map_err(|_| ERROR)?;
        let routes = SetupRoutes {
            own: inventory.inboxes,
            peers: vec![creator_descriptor],
        };
        self.runtime
            .block_on(transport.drive_once(&mut store, &routes))
            .map_err(|_| "setup_transport")?;
        let progress = store
            .progress_for(&transport, &routes, &key)
            .map_err(|_| "setup_transport")?;
        Ok(SetupStatus {
            agreed: self.saved_approval()?.map(|(_, fp, _)| fp),
            waiting: None,
            own_slot: self.context.own_slot,
            phase: if progress.stored_groups == 1 {
                "join_published"
            } else {
                "join_pending"
            },
            threshold: self.threshold,
            count: self.context.count,
            joined: vec![self.context.own_slot],
            retryable: progress.stored_groups != 1,
        })
    }
    fn validate_snapshot(operators: &OperatorSet, bytes: &[u8]) -> Result<(), String> {
        if bytes == [0] || bytes == [6] {
            return Ok(());
        }
        if bytes.first() == Some(&7) {
            let mut reader = Reader {
                raw: bytes,
                offset: 1,
            };
            let reply = reader.field()?;
            if reply.len() <= admission::MAX_RESPONSE && reader.offset == bytes.len() {
                return Ok(());
            }
            return Err(ERROR.into());
        }
        if bytes.first() == Some(&5) && bytes.len() == 2 && (1..=4).contains(&bytes[1]) {
            return Ok(());
        }
        if bytes.first() == Some(&4) && bytes.len() >= 6 && (1..=4).contains(&bytes[1]) {
            let mut reader = Reader {
                raw: bytes,
                offset: 2,
            };
            let package = reader.field()?;
            if package.len() <= 1024 && reader.offset == bytes.len() {
                return Ok(());
            }
            return Err(ERROR.into());
        }
        if bytes.len() < 17
            || !matches!(bytes[0], 1 | 2 | 3)
            || (bytes[0] == 1 && bytes.len() != 17)
        {
            return Err(ERROR.into());
        }
        let claim = u64::from_be_bytes(bytes[1..9].try_into().map_err(|_| ERROR)?);
        let deadline = u64::from_be_bytes(bytes[9..17].try_into().map_err(|_| ERROR)?);
        let expected = operators
            .limits()
            .ceremony_seconds
            .checked_sub(operators.limits().first_claim_seconds)
            .ok_or(ERROR)?;
        if claim == 0 || deadline > i64::MAX as u64 || deadline.checked_sub(claim) != Some(expected)
        {
            return Err(ERROR.into());
        }
        Ok(())
    }
    fn rejection_status(&self) -> Result<SetupStatus, String> {
        let raw = &self.journal.latest().ok_or(ERROR)?.payload;
        if raw.first() != Some(&7) {
            return Err(ERROR.into());
        }
        let mut reader = Reader { raw, offset: 1 };
        let reply = loki_relay_client::verify_admission_reply(
            &self.operators,
            &self.context.create,
            reader.field()?,
        )
        .map_err(|_| "setup_admission")?;
        if reader.offset != raw.len()
            || !matches!(reply.outcome(), AdmissionOutcome::Rejected(code) if !matches!(*code, "storage"|"unavailable"))
        {
            return Err("setup_admission".into());
        }
        Ok(SetupStatus {
            agreed: None,
            waiting: None,
            own_slot: self.context.own_slot,
            phase: "admission_rejected",
            threshold: self.threshold,
            count: self.context.count,
            joined: Vec::new(),
            retryable: false,
        })
    }
    fn save_rejection(
        &mut self,
        reply: &loki_relay_client::VerifiedAdmissionReply,
    ) -> Result<SetupStatus, String> {
        if !matches!(self.journal.latest().ok_or(ERROR)?.payload[0], 0 | 6) {
            return Err(ERROR.into());
        }
        let mut next = Zeroizing::new(vec![7]);
        field(&mut next, reply.package())?;
        Self::validate_snapshot(&self.operators, &next)?;
        self.journal.append(&next)?;
        self.rejection_status()
    }
    fn terminal_status(&self, kind: u16, pending: bool) -> SetupStatus {
        SetupStatus {
            agreed: None,
            waiting: None,
            own_slot: self.context.own_slot,
            phase: if pending {
                "terminal_pending"
            } else {
                match kind {
                    1 => "aborted",
                    3 => "checkpoint_conflict",
                    4 => "expired",
                    _ => "activation_unverified",
                }
            },
            threshold: self.threshold,
            count: self.context.count,
            joined: vec![self.context.own_slot],
            retryable: pending,
        }
    }
    fn save_terminal(&mut self, kind: u16, initiate: bool) -> Result<(), String> {
        if !(1..=4).contains(&kind) || (initiate && kind != 1) {
            return Err(ERROR.into());
        }
        let ceremony = self.policy()?.ceremony;
        let request = sign_admission_request(
            &self.identity,
            &AdmissionRequest {
                operation: random(),
                device: self.identity.public(),
                command: if initiate {
                    AdmissionCommand::Terminal { ceremony, kind }
                } else {
                    AdmissionCommand::TerminalNotice { ceremony, kind }
                },
            },
        )
        .map_err(|_| ERROR)?;
        let mut next = Zeroizing::new(vec![4, kind as u8]);
        field(&mut next, &request)?;
        self.journal.append(&next)?;
        Ok(())
    }
    fn native_journal_context(&self) -> Result<Option<[u8; 32]>, String> {
        if !self
            .root
            .join("setup-ceremony")
            .try_exists()
            .map_err(|_| ERROR)?
        {
            return Ok(None);
        }
        let (roster, _, _) = self.saved_approval()?.ok_or("setup_approval")?;
        let policy = self.policy()?;
        let digest = AcceptedCeremonyRoster::hosted_context_digest(
            &Self::native_roster(&roster, &policy)?,
            &policy.network,
            &policy.config_digest,
        )?;
        Ok(Some(digest))
    }
    fn native_saved_phase(&self) -> Result<Option<CeremonyPhase>, String> {
        match self.native_journal_context()? {
            Some(context) => SetupCeremony::saved_phase(
                &self.root,
                &self.passphrase,
                context,
                self.context.own_slot,
                &self._member_lock,
            ),
            None => Ok(None),
        }
    }
    fn retire_native_checkpoint(&self) -> Result<(), String> {
        let Some(context) = self.native_journal_context()? else {
            return Ok(());
        };
        let confirmed_terminal = if self.native_saved_phase()? == Some(CeremonyPhase::Active) {
            let state = self.state()?.ok_or("setup_admission_pending")?;
            let AdmissionOutcome::Accepted(Value::Array(fields)) = state.outcome() else {
                return Err("setup_admission".into());
            };
            if fields.len() != 7 || fields[0] != Value::Integer(self.context.count.into()) {
                return Err("setup_admission".into());
            }
            let Value::Integer(kind) = fields[3] else {
                return Err("setup_admission".into());
            };
            let kind = u16::try_from(kind).map_err(|_| "setup_admission")?;
            if !matches!(kind, 1 | 3 | 4)
                || self.journal.latest().ok_or(ERROR)?.payload[1] != kind as u8
            {
                return Err("setup_already_active".into());
            }
            Some(kind)
        } else {
            None
        };
        SetupCeremony::abort_saved_checkpoint(
            &self.root,
            &self.passphrase,
            context,
            self.context.own_slot,
            &self._member_lock,
            confirmed_terminal,
        )
    }
    fn failure_requires_abort(&self) -> Result<bool, String> {
        if !matches!(self.journal.latest().ok_or(ERROR)?.payload[0], 0..=3) {
            return Ok(false);
        }
        if let Some(context) = self.native_journal_context()? {
            if matches!(
                SetupCeremony::saved_phase(
                    &self.root,
                    &self.passphrase,
                    context,
                    self.context.own_slot,
                    &self._member_lock,
                )?,
                Some(CeremonyPhase::Starting | CeremonyPhase::Aborted),
            ) {
                return Ok(true);
            }
        }
        self.transport_is_terminal()
    }
    fn transport_is_terminal(&self) -> Result<bool, String> {
        let path = self.root.join("setup-relay-store");
        if !path.try_exists().map_err(|_| ERROR)? {
            return Ok(false);
        }
        let context = self.bootstrap_context()?;
        let mut peers = vec![context.creator_identity().clone(), self.identity.public()];
        peers.sort_by_key(|peer| peer.id);
        peers.dedup();
        let transport = SetupTransport::new(
            &self.identity,
            &self.operators,
            SetupAuthority::Bootstrap(&context, &peers),
            self.context.development,
        )
        .map_err(|_| "setup_transport")?;
        SetupStore::open(&path, &transport)
            .map_err(|_| "setup_transport")?
            .is_terminal()
            .map_err(|_| "setup_transport".into())
    }
    fn terminal_step(&mut self) -> Result<SetupStatus, String> {
        let kind = u16::from(self.journal.latest().ok_or(ERROR)?.payload[1]);
        if kind != 2 {
            self.retire_native_checkpoint()?;
        }
        let raw = &self.journal.latest().ok_or(ERROR)?.payload;
        if raw[0] == 5 {
            return Ok(self.terminal_status(kind, false));
        }
        let mut reader = Reader { raw, offset: 2 };
        let package = reader.field()?.to_vec();
        match self.execute_admission(&package, None, false) {
            Err(loki_relay_client::ClientError::Transport) => {
                return Ok(self.terminal_status(kind, true))
            }
            Err(_) => return Err("setup_admission".into()),
            Ok(_) => {}
        }
        let Some(state) = self.state()? else {
            return Ok(self.terminal_status(kind, true));
        };
        let AdmissionOutcome::Accepted(Value::Array(fields)) = state.outcome() else {
            return Err(ERROR.into());
        };
        if fields.len() != 7 || fields[0] != Value::Integer(u64::from(self.context.count).into()) {
            return Err(ERROR.into());
        }
        let Value::Integer(actual) = fields[3] else {
            return Err(ERROR.into());
        };
        let actual = u16::try_from(actual).map_err(|_| ERROR)?;
        if actual == 0 {
            return Ok(self.terminal_status(kind, true));
        }
        if actual > 4 {
            return Err(ERROR.into());
        }
        if actual != kind {
            self.save_terminal(actual, false)?;
            return Ok(self.terminal_status(actual, true));
        }
        let Value::Array(rows) = &fields[4] else {
            return Err(ERROR.into());
        };
        let mut claimed = Vec::new();
        for row in rows {
            let Value::Array(row) = row else {
                return Err(ERROR.into());
            };
            if row.len() != 3 {
                return Err(ERROR.into());
            }
            let (Value::Integer(id), Value::Bytes(signing), Value::Bytes(encryption)) =
                (&row[0], &row[1], &row[2])
            else {
                return Err(ERROR.into());
            };
            let id = u16::try_from(*id).map_err(|_| ERROR)?;
            if id == 0
                || id > self.context.count
                || claimed
                    .last()
                    .is_some_and(|p: &loki_relay_protocol::types::MemberPublic| p.id >= id)
            {
                return Err(ERROR.into());
            }
            claimed.push(loki_relay_protocol::types::MemberPublic {
                id,
                signing: signing.as_slice().try_into().map_err(|_| ERROR)?,
                encryption: encryption.as_slice().try_into().map_err(|_| ERROR)?,
            });
        }
        if !claimed.contains(&self.identity.public()) {
            return Err(ERROR.into());
        }
        let query = sign_admission_request(
            &self.identity,
            &AdmissionRequest {
                operation: random(),
                device: self.identity.public(),
                command: AdmissionCommand::TerminalNotice {
                    ceremony: self.policy()?.ceremony,
                    kind: 0,
                },
            },
        )
        .map_err(|_| ERROR)?;
        let reply = match self.execute_admission(&query, None, false) {
            Ok(reply) => reply,
            Err(loki_relay_client::ClientError::Transport) => {
                return Ok(self.terminal_status(kind, true))
            }
            Err(_) => return Err("setup_admission".into()),
        };
        let notices =
            loki_relay_client::verify_terminal_notices(&self.policy()?.ceremony, &claimed, &reply)
                .map_err(|_| ERROR)?;
        if notices.terminal_kind() != kind
            || !notices
                .notifying_members()
                .contains(&self.identity.public().id)
        {
            return Ok(self.terminal_status(kind, true));
        }
        self.journal.append(&[5, kind as u8])?;
        Ok(self.terminal_status(kind, false))
    }
    pub fn abort(&mut self) -> Result<SetupStatus, String> {
        let status = self.abort_inner()?;
        self.cache_status(&status)?;
        Ok(status)
    }
    fn abort_inner(&mut self) -> Result<SetupStatus, String> {
        if self.native_saved_phase()? == Some(CeremonyPhase::Active) {
            return Err("setup_already_active".into());
        }
        match self.journal.latest().ok_or(ERROR)?.payload[0] {
            4 | 5 => self.terminal_step(),
            0 => {
                self.journal.append(&[6])?;
                self.pending_admission_abort()
            }
            6 => self.pending_admission_abort(),
            7 => self.rejection_status(),
            _ => {
                self.save_terminal(1, true)?;
                self.terminal_step()
            }
        }
    }
    fn cache_status(&self, status: &SetupStatus) -> Result<(), String> {
        journal::check_private_root(&self.root)?;
        let target = self.root.join("setup-status.json");
        if target.try_exists().map_err(|_| ERROR)? {
            journal::checked_file(&target)?;
        }
        let temporary = self
            .root
            .join(format!(".setup-status.{}.tmp", hex::encode(random())));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let result = (|| {
            let mut file = options.open(&temporary).map_err(|_| ERROR)?;
            file.write_all(&serde_json::to_vec(&status.public_json()).map_err(|_| ERROR)?)
                .map_err(|_| ERROR)?;
            file.sync_all().map_err(|_| ERROR)?;
            std::fs::rename(&temporary, &target).map_err(|_| ERROR)?;
            File::open(&self.root)
                .map_err(|_| ERROR)?
                .sync_all()
                .map_err(|_| ERROR)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }
    pub fn cached_status(root: &Path) -> Result<ValueJson, String> {
        journal::check_private_root(root)?;
        let bytes = private_file(&root.join("setup-status.json"), 4096)?;
        let value: ValueJson = serde_json::from_slice(&bytes).map_err(|_| "setup_status")?;
        let status = CachedStatus::parse(&value)?;
        status.validate()?;
        Ok(
            serde_json::json!({"phase":status.phase,"policy":status.policy,
            "own_slot":status.own_slot,"joined_slots":status.joined_slots,
            "missing_slots":status.missing_slots,"agreed_fingerprint":status.agreed_fingerprint,
            "retryable":status.retryable,"handoff":status.handoff}),
        )
    }
    pub fn step(&mut self) -> Result<SetupStatus, String> {
        let status = if matches!(self.journal.latest().ok_or(ERROR)?.payload[0], 0..=3)
            && self.transport_is_terminal()?
        {
            self.save_terminal(1, true)?;
            self.terminal_step()?
        } else {
            match self.drive_step() {
                Ok(status) => status,
                Err(error) => {
                    if !self.failure_requires_abort()? {
                        return Err(error);
                    }
                    self.save_terminal(1, true)?;
                    self.terminal_step()?
                }
            }
        };
        self.cache_status(&status)?;
        Ok(status)
    }
    fn pending_admission_abort(&mut self) -> Result<SetupStatus, String> {
        self.admission_step()?;
        match self.journal.latest().ok_or(ERROR)?.payload[0] {
            6 => Ok(self.terminal_status(1, true)),
            7 => self.rejection_status(),
            4 | 5 => self.terminal_step(),
            1 => {
                self.save_terminal(1, true)?;
                self.terminal_step()
            }
            _ => Err(ERROR.into()),
        }
    }
    fn drive_step(&mut self) -> Result<SetupStatus, String> {
        match self.journal.latest().ok_or(ERROR)?.payload[0] {
            4 | 5 => self.terminal_step(),
            6 => self.pending_admission_abort(),
            7 => self.rejection_status(),
            0 => self.admission_step(),
            _ => self.provision_step(),
        }
    }
    fn admission_step(&mut self) -> Result<SetupStatus, String> {
        let credential = if self.context.own_slot == 1 {
            Zeroizing::new(self.context.grant.to_vec())
        } else {
            let invite = verified_invite(
                &self.context.grant,
                &self.context.bundle,
                &self.context.key,
                self.context.development,
                0,
            )?;
            Zeroizing::new(invite.secret().as_bytes().to_vec())
        };
        let reply = self.execute_admission(&self.context.create, Some(&credential), true);
        match reply {
            Err(loki_relay_client::ClientError::Transport) => Ok(SetupStatus {
                agreed: None,
                waiting: None,
                own_slot: self.context.own_slot,
                phase: "admission_pending",
                threshold: self.threshold,
                count: self.context.count,
                joined: Vec::new(),
                retryable: true,
            }),
            Err(_) => Err("setup_admission".into()),
            Ok(reply) => match reply.outcome() {
                AdmissionOutcome::Accepted(Value::Integer(slot))
                    if self.context.own_slot > 1
                        && *slot == u64::from(self.context.own_slot).into() =>
                {
                    let Some(state) = self.state()? else {
                        return Ok(SetupStatus {
                            agreed: None,
                            waiting: None,
                            own_slot: self.context.own_slot,
                            phase: "admission_pending",
                            threshold: self.threshold,
                            count: self.context.count,
                            joined: Vec::new(),
                            retryable: true,
                        });
                    };
                    let AdmissionOutcome::Accepted(Value::Array(state)) = state.outcome() else {
                        return Err(ERROR.into());
                    };
                    if state.len() != 7
                        || state[0] != Value::Integer(u64::from(self.context.count).into())
                    {
                        return Err(ERROR.into());
                    }
                    self.validate_claims(&state[4])?;
                    let Value::Integer(kind) = state[3] else {
                        return Err(ERROR.into());
                    };
                    let kind = u16::try_from(kind).map_err(|_| ERROR)?;
                    if kind != 0 {
                        self.save_terminal(kind, false)?;
                        return self.terminal_step();
                    }
                    let mut next = Zeroizing::new(vec![1]);
                    for value in &state[1..3] {
                        let Value::Integer(n) = value else {
                            return Err(ERROR.into());
                        };
                        next.extend_from_slice(
                            &u64::try_from(*n).map_err(|_| ERROR)?.to_be_bytes(),
                        );
                    }
                    Self::validate_snapshot(&self.operators, &next)?;
                    self.journal.append(&next)?;
                    Ok(self.provisioning_status(false))
                }
                AdmissionOutcome::Accepted(Value::Array(fields)) if fields.len() == 2 => {
                    let mut next = Zeroizing::new(vec![1]);
                    for field in fields {
                        let Value::Integer(number) = field else {
                            return Err(ERROR.into());
                        };
                        let number = u64::try_from(*number).map_err(|_| ERROR)?;
                        next.extend_from_slice(&number.to_be_bytes());
                    }
                    Self::validate_snapshot(&self.operators, &next)?;
                    self.journal.append(&next)?;
                    Ok(SetupStatus {
                        agreed: None,
                        waiting: None,
                        own_slot: self.context.own_slot,
                        phase: "provisioning",
                        threshold: self.threshold,
                        count: self.context.count,
                        joined: vec![self.context.own_slot],
                        retryable: true,
                    })
                }
                AdmissionOutcome::Rejected(_) => self.save_rejection(&reply),
                _ => Err("setup_admission".into()),
            },
        }
    }
}

fn private_file(path: &Path, limit: usize) -> Result<Zeroizing<Vec<u8>>, String> {
    let file = journal::checked_file(path).map_err(|_| "setup_file")?;
    if file.metadata().map_err(|_| "setup_file")?.len() > limit as u64 {
        return Err("setup_file".into());
    }
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "setup_file")?;
    if bytes.len() > limit {
        return Err("setup_file".into());
    }
    Ok(bytes)
}
fn private_passphrase(path: &str) -> Result<Zeroizing<String>, String> {
    let path = Path::new(path.strip_prefix('@').unwrap_or(path));
    let raw = private_file(path, 4098)?;
    let text = std::str::from_utf8(&raw)
        .map_err(|_| "setup_file")?
        .trim_end_matches(['\r', '\n']);
    if text.is_empty() || text.len() > 4096 {
        return Err("setup_file".into());
    }
    Ok(Zeroizing::new(text.to_owned()))
}
pub enum BackupCommandOutput {
    Words(Zeroizing<String>),
    Public(ValueJson),
}
pub fn backup_command(command: &str, args: &[String]) -> Result<BackupCommandOutput, String> {
    let count = match command {
        "setup-backup-create" => 3,
        "setup-backup-verify" => 4,
        "setup-backup-finalize" => 5,
        _ => return Err("setup_arguments".into()),
    };
    if args.len() != count {
        return Err("setup_arguments".into());
    }
    let absolute = |path: &str| -> Result<PathBuf, String> {
        let path = Path::new(path);
        if path.is_absolute() {
            Ok(path.to_owned())
        } else {
            Ok(std::env::current_dir()
                .map_err(|_| "setup_file")?
                .join(path))
        }
    };
    let root = absolute(&args[0])?;
    let passphrase = private_passphrase(&args[1])?;
    let setup = HostedSetup::open(&root, &passphrase)?;
    let card = absolute(&args[2])?;
    if command == "setup-backup-create" {
        return Ok(BackupCommandOutput::Words(setup.backup_create(&card)?));
    }
    let words = if command == "setup-backup-finalize" && args[4] == "-" {
        let path = root.join("secrets/backup-words.sealed");
        let file = journal::checked_file(&path)?;
        if file.metadata().map_err(|_| "setup_backup")?.len() > 1024 {
            return Err("setup_backup".into());
        }
        let raw = Zeroizing::new(
            MemberDir::open(&root, "secrets")
                .read_sealed("backup-words.sealed", &passphrase)
                .map_err(|_| "setup_backup")?,
        );
        Zeroizing::new(
            std::str::from_utf8(&raw)
                .map_err(|_| "setup_backup")?
                .to_owned(),
        )
    } else {
        private_passphrase(&args[count - 1])?
    };
    if command == "setup-backup-verify" {
        setup.backup_verify(&card, &words)?;
        Ok(BackupCommandOutput::Public(
            serde_json::json!({"backup":"checked"}),
        ))
    } else {
        let destination = absolute(&args[3])?;
        Ok(BackupCommandOutput::Public(setup.backup_finalize(
            &card,
            &destination,
            &words,
        )?))
    }
}
pub fn command(command: &str, args: &[String]) -> Result<serde_json::Value, String> {
    let root = args.first().ok_or("setup_arguments")?;
    let root = Path::new(root);
    let root = if root.is_absolute() {
        root.to_owned()
    } else {
        std::env::current_dir().map_err(|_| ERROR)?.join(root)
    };
    match command {
        "setup-config-check" => {
            if args.len() != 3 || args[1] != "--operator-key" || args[2].len() != 64 {
                return Err("setup_arguments".into());
            }
            let key: [u8; 32] = hex::decode(&args[2])
                .map_err(|_| ERROR)?
                .try_into()
                .map_err(|_| ERROR)?;
            let bundle = private_file(&root, LIMIT)?;
            let operators = OperatorSet::verify(&bundle, &key).map_err(|_| "setup_config")?;
            Ok(
                serde_json::json!({"configuration_sha256":hex::encode(operators.digest()),"relays":operators.relay_routes().iter().map(|route|serde_json::json!({"endpoint":route.endpoint,"receipt_key":hex::encode(route.pin.key),"run_id":hex::encode(route.pin.run)})).collect::<Vec<_>>(),"development":false}),
            )
        }
        "setup-status" => {
            if args.len() != 1 {
                return Err("setup_arguments".into());
            }
            HostedSetup::cached_status(&root)
        }
        "setup-evidence" => {
            if args.len() != 2 {
                return Err("setup_arguments".into());
            }
            let passphrase = private_passphrase(&args[1])?;
            let setup = HostedSetup::open(&root, &passphrase)?;
            setup.with_accepted_ceremony(|engine, authority, store, transport, routes, accepted| {
                if engine.phase() != CeremonyPhase::Active { return Err("setup_payment_pending".into()); }
                let handoff = setup.payment_handoff_step(engine, authority, store, transport, routes, accepted, false)?;
                if !handoff.is_ready() { return Err("setup_payment_pending".into()); }
                let (roster, fingerprint, _) = setup.saved_approval()?.ok_or("setup_approval")?;
                Ok(serde_json::json!({"policy":format!("{}-of-{}",setup.threshold,setup.context.count),"vault":hex::encode(roster.vault),"own_slot":setup.context.own_slot,"fingerprint":hex::encode(fingerprint),"address":engine.certified_address()?,"group_ak":hex::encode(engine.certified_group_key()?),"handoff":"ready","development":setup.context.development,"configuration_digest":hex::encode(setup.operators.digest()),"native_checkpoint":hex::encode(engine.checkpoint().digest),"relays":setup.operators.relay_routes().iter().map(|route|serde_json::json!({"endpoint":route.endpoint,"receipt_key":hex::encode(route.pin.key),"run_id":hex::encode(route.pin.run)})).collect::<Vec<_>>()}))
            })
        }
        "setup-info" => {
            if args.len() != 2 {
                return Err("setup_arguments".into());
            }
            let passphrase = private_passphrase(&args[1])?;
            let setup = HostedSetup::open(&root, &passphrase)?;
            let policy = setup.policy()?;
            let approved = setup.saved_approval()?;
            let proposal = if approved.is_none() {
                setup.current_proposal().ok()
            } else {
                None
            };
            let roster = approved
                .as_ref()
                .map(|(roster, _, _)| roster)
                .or_else(|| proposal.as_ref().map(|proposal| &proposal.roster));
            let fingerprint = approved
                .as_ref()
                .map(|(_, fingerprint, _)| *fingerprint)
                .or_else(|| proposal.as_ref().map(|proposal| proposal.fingerprint));
            Ok(
                serde_json::json!({"vault":hex::encode(policy.ceremony),"own_slot":setup.context.own_slot,"member_count":policy.member_count,
                "network":policy.network,"threshold":policy.threshold,"birth_height":(policy.network == "testnet").then_some(TESTNET_NU7_BIRTH),"fingerprint":fingerprint.map(hex::encode),"members":roster.map(|roster|roster.members.iter().map(|peer|serde_json::json!({"id":peer.id,"signing":hex::encode(peer.signing),"encryption":hex::encode(peer.encryption)})).collect::<Vec<_>>()).unwrap_or_default()}),
            )
        }
        "setup-create" => {
            if args.len() < 7 || args[5] != "--operator-key" || args[6].len() != 64 {
                return Err("setup_arguments".into());
            }
            let (network, development) = match &args[7..] {
                [] => ("regtest", false),
                [flag] if flag == "--development-http" => ("regtest", true),
                [flag, network] if flag == "--network" => (network.as_str(), false),
                [flag, network, development]
                    if flag == "--network" && development == "--development-http" =>
                {
                    (network.as_str(), true)
                }
                _ => return Err("setup_arguments".into()),
            };
            let (threshold, count) = match args[4].as_str() {
                "2-of-3" => (2, 3),
                "2-of-4" => (2, 4),
                "3-of-4" => (3, 4),
                _ => return Err("setup_policy".into()),
            };
            let key: [u8; 32] = hex::decode(&args[6])
                .map_err(|_| "setup_config")?
                .try_into()
                .map_err(|_| "setup_config")?;
            let passphrase = private_passphrase(&args[1])?;
            let bundle = private_file(Path::new(&args[2]), LIMIT)?;
            let grant = private_file(Path::new(&args[3]), 4096)?;
            let mut setup = HostedSetup::create_with_policy(
                &root,
                &passphrase,
                &bundle,
                &key,
                &grant,
                threshold,
                count,
                network,
                development,
            )?;
            Ok(setup.step()?.public_json())
        }
        "setup-join" => {
            if args.len() < 6 || args[4] != "--operator-key" || args[5].len() != 64 {
                return Err("setup_arguments".into());
            }
            let (network, development) = match &args[6..] {
                [] => ("regtest", false),
                [flag] if flag == "--development-http" => ("regtest", true),
                [flag, network] if flag == "--network" => (network.as_str(), false),
                [flag, network, development]
                    if flag == "--network" && development == "--development-http" =>
                {
                    (network.as_str(), true)
                }
                _ => return Err("setup_arguments".into()),
            };
            let key: [u8; 32] = hex::decode(&args[5])
                .map_err(|_| "setup_config")?
                .try_into()
                .map_err(|_| "setup_config")?;
            let passphrase = private_passphrase(&args[1])?;
            let invitation = private_file(Path::new(&args[2]), 4096)?;
            let bundle = private_file(Path::new(&args[3]), LIMIT)?;
            let mut setup = HostedSetup::join(
                &root,
                &passphrase,
                &invitation,
                &bundle,
                &key,
                network,
                development,
            )?;
            Ok(setup.step()?.public_json())
        }
        "setup-invite" => {
            if args.len() != 4 {
                return Err("setup_arguments".into());
            }
            let slot = args[2].parse::<u16>().map_err(|_| "setup_arguments")?;
            let passphrase = private_passphrase(&args[1])?;
            let setup = HostedSetup::open(&root, &passphrase)?;
            let output = Path::new(&args[3]);
            let output = if output.is_absolute() {
                output.to_owned()
            } else {
                std::env::current_dir()
                    .map_err(|_| "setup_file")?
                    .join(output)
            };
            setup.export_invitation(slot, &output)?;
            Ok(serde_json::json!({"exported":true,"slot":slot}))
        }
        "setup-fingerprint" | "setup-agree" => {
            if args.len() != if command == "setup-agree" { 3 } else { 2 } {
                return Err("setup_arguments".into());
            }
            let passphrase = private_passphrase(&args[1])?;
            let mut setup = HostedSetup::open(&root, &passphrase)?;
            if command == "setup-fingerprint" {
                Ok(serde_json::json!({"fingerprint":hex::encode(setup.proposed_fingerprint()?)}))
            } else {
                if args[2].len() != 64 {
                    return Err("setup_fingerprint".into());
                }
                let expected = hex::decode(&args[2])
                    .map_err(|_| "setup_fingerprint")?
                    .try_into()
                    .map_err(|_| "setup_fingerprint")?;
                Ok(setup.agree(expected)?.public_json())
            }
        }
        "setup-step" | "setup-abort" => {
            if args.len() != 2 {
                return Err("setup_arguments".into());
            }
            let passphrase = private_passphrase(&args[1])?;
            let mut setup = HostedSetup::open(&root, &passphrase)?;
            Ok(if command == "setup-abort" {
                setup.abort()?
            } else {
                setup.step()?
            }
            .public_json())
        }
        _ => Err("setup_arguments".into()),
    }
}

#[cfg(test)]
#[path = "setup_relay_tests.rs"]
mod tests;
