use crate::{ClientError, ClientResult, CommIdentity, OperatorSet, Secret32};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use loki_relay_protocol::{
    canonical::{self, Value},
    setup::{self, SetupCapabilities, SetupKey, SetupPhase, SetupRecord},
    types::{self, Id32, MemberPublic, Roster},
    WireError,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use zeroize::{Zeroize, Zeroizing};

const INVITE_DOMAIN: &[u8] = b"Loki_Setup_Invite_v1\0";
const INVITE_LIMIT: usize = 16384;

pub(crate) struct PrivateValue(pub(crate) Value);
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

struct RecordGuard(Option<SetupRecord>);
impl std::ops::Deref for RecordGuard {
    type Target = SetupRecord;
    fn deref(&self) -> &SetupRecord {
        self.0.as_ref().expect("live record guard")
    }
}
impl RecordGuard {
    fn take(mut self) -> SetupRecord {
        self.0.take().expect("live record guard")
    }
}
impl Drop for RecordGuard {
    fn drop(&mut self) {
        if let Some(record) = &mut self.0 {
            record.payload.zeroize();
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetupPolicy {
    pub ceremony: Id32,
    pub network: String,
    pub threshold: u16,
    pub member_count: u16,
    pub config_digest: Id32,
}
impl SetupPolicy {
    fn validate(&self) -> ClientResult<()> {
        setup::encode_record(&SetupRecord {
            version: 1,
            key: SetupKey {
                ceremony: self.ceremony,
                phase: SetupPhase::Join,
                author: 1,
                recipient: 1,
                revision: 1,
            },
            network: self.network.clone(),
            threshold: self.threshold,
            member_count: self.member_count,
            roster_digest: None,
            prerequisites: vec![],
            payload: vec![],
        })?;
        Ok(())
    }
}

/// Bootstrap context carries no certified payment authority.
///
/// ```compile_fail
/// use loki_relay_client::{BootstrapContext, sign_message, CommIdentity};
/// use loki_relay_protocol::types::MessageBody;
/// fn payment(id: &CommIdentity, ctx: &BootstrapContext, body: &MessageBody) {
///     sign_message(id, ctx, body).unwrap();
/// }
/// ```
pub struct BootstrapContext {
    policy: SetupPolicy,
    creator: MemberPublic,
}
impl BootstrapContext {
    pub fn creator(
        policy: SetupPolicy,
        creator: MemberPublic,
        operators: &OperatorSet,
    ) -> ClientResult<Self> {
        policy.validate()?;
        if creator.id != 1
            || policy.config_digest != *operators.digest()
            || !operators.setup_versions().contains(&1)
        {
            return Err(ClientError::Config);
        }
        VerifyingKey::from_bytes(&creator.signing)?;
        Ok(Self { policy, creator })
    }
    fn check_bootstrap(
        &self,
        body: &SetupRecord,
        peer: &MemberPublic,
        recipient: u16,
    ) -> ClientResult<()> {
        self.check(body, recipient)?;
        if body.key.author != peer.id
            || (peer.id == 1 && peer != &self.creator)
            || !matches!(
                body.key.phase,
                SetupPhase::Join
                    | SetupPhase::RosterProposal
                    | SetupPhase::RosterAccept
                    | SetupPhase::Abort
            )
            || (body.key.phase == SetupPhase::RosterProposal && peer != &self.creator)
        {
            return Err(ClientError::Identity);
        }
        if body.key.phase == SetupPhase::RosterAccept {
            let encoded = Zeroizing::new(verify_package(
                &body.payload,
                setup::MAX_PACKAGE,
                setup::RECORD_DOMAIN,
                peer,
            )?);
            let inner = setup::decode_record(&encoded)?;
            self.check(&inner, 1)?;
            if inner.key.author != peer.id
                || inner.key.phase != SetupPhase::RosterAccept
                || inner.key.revision != 1
                || body.key.revision != 1
                || !inner.prerequisites.is_empty()
                || inner.roster_digest != body.roster_digest
            {
                return Err(ClientError::Identity);
            }
            let value = canonical::decode(&inner.payload, 4096)?;
            let f = fields(&value, 3)?;
            let roster = types::decode_roster(binary(&f[0])?)?;
            if roster.vault != self.policy.ceremony
                || roster.members.len() != self.policy.member_count as usize
                || roster.members.first() != Some(&self.creator)
                || !roster.members.contains(peer)
                || inner.roster_digest != Some(types::roster_digest(&roster)?)
            {
                return Err(ClientError::Identity);
            }
            fn list(v: &Value) -> ClientResult<Vec<u16>> {
                let Value::Array(a) = v else {
                    return Err(ClientError::Config);
                };
                a.iter().map(small).collect()
            }
            let capabilities = SetupCapabilities {
                versions: list(&f[1])?,
                member_counts: list(&f[2])?,
            };
            if acceptance_payload(&roster, &capabilities)? != inner.payload {
                return Err(ClientError::Identity);
            }
        }
        Ok(())
    }
    pub fn sign_bootstrap(
        &self,
        identity: &CommIdentity,
        body: &SetupRecord,
    ) -> ClientResult<Vec<u8>> {
        self.check_bootstrap(body, &identity.public(), body.key.recipient)?;
        signed(identity, setup::RECORD_DOMAIN, setup::encode_record(body)?)
    }
    /// The caller obtains the peer identity from its authenticated admission claim.
    pub fn authenticate_bootstrap(
        &self,
        peer: &MemberPublic,
        recipient: u16,
        package: &[u8],
    ) -> ClientResult<AuthenticatedSetupRecord> {
        let encoded = Zeroizing::new(verify_package(
            package,
            setup::MAX_PACKAGE,
            setup::RECORD_DOMAIN,
            peer,
        )?);
        let body = RecordGuard(Some(setup::decode_record(&encoded)?));
        if !matches!(
            body.key.phase,
            SetupPhase::Join
                | SetupPhase::RosterProposal
                | SetupPhase::RosterAccept
                | SetupPhase::Abort
        ) {
            self.check(&body, recipient)?;
            if body.key.author != peer.id || (peer.id == 1 && peer != &self.creator) {
                return Err(ClientError::Identity);
            }
            return Err(ClientError::SetupAgreementPending);
        }
        self.check_bootstrap(&body, peer, recipient)?;
        Ok(AuthenticatedSetupRecord {
            body: body.take(),
            digest: Sha256::digest(&*encoded).into(),
            canonical_body: encoded.to_vec(),
        })
    }
    pub fn policy(&self) -> &SetupPolicy {
        &self.policy
    }
    pub fn creator_identity(&self) -> &MemberPublic {
        &self.creator
    }
    fn check(&self, body: &SetupRecord, recipient: u16) -> ClientResult<()> {
        let p = &self.policy;
        if body.key.ceremony != p.ceremony
            || body.network != p.network
            || body.threshold != p.threshold
            || body.member_count != p.member_count
            || body.key.recipient != recipient
        {
            return Err(ClientError::Identity);
        }
        Zeroizing::new(setup::encode_record(body)?);
        Ok(())
    }
}

/// A verified invitation retains its bearer secret without a formatting implementation.
///
/// ```compile_fail
/// fn debug<T: std::fmt::Debug>() {}
/// debug::<loki_relay_client::SetupInvite>();
/// ```
pub struct SetupInvite {
    context: BootstrapContext,
    slot: u16,
    expires: u64,
    secret: Secret32,
    bootstrap: Option<SetupInboxDescriptor>,
}
fn input(domain: &[u8], body: &[u8]) -> ClientResult<Vec<u8>> {
    let len = u32::try_from(body.len()).map_err(|_| WireError::Bounds)?;
    let mut out = Vec::with_capacity(domain.len() + 4 + body.len());
    out.extend_from_slice(domain);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}
fn uint(n: impl Into<u64>) -> Value {
    Value::Integer(n.into().into())
}
fn bytes(id: &Id32) -> Value {
    Value::Bytes(id.to_vec())
}
fn member_value(member: &MemberPublic) -> Value {
    Value::Array(vec![
        uint(member.id),
        bytes(&member.signing),
        bytes(&member.encryption),
    ])
}
fn fields(value: &Value, n: usize) -> ClientResult<&[Value]> {
    match value {
        Value::Array(v) if v.len() == n => Ok(v),
        _ => Err(WireError::Schema.into()),
    }
}
fn number(value: &Value) -> ClientResult<u64> {
    match value {
        Value::Integer(n) => u64::try_from(*n).map_err(|_| WireError::Schema.into()),
        _ => Err(WireError::Schema.into()),
    }
}
fn small(value: &Value) -> ClientResult<u16> {
    u16::try_from(number(value)?).map_err(|_| WireError::Schema.into())
}
fn id(value: &Value) -> ClientResult<Id32> {
    match value {
        Value::Bytes(b) => b
            .as_slice()
            .try_into()
            .map_err(|_| WireError::Schema.into()),
        _ => Err(WireError::Schema.into()),
    }
}
fn binary(value: &Value) -> ClientResult<&[u8]> {
    match value {
        Value::Bytes(b) => Ok(b),
        _ => Err(WireError::Schema.into()),
    }
}
pub(crate) fn signed(
    identity: &CommIdentity,
    domain: &[u8],
    body: Vec<u8>,
) -> ClientResult<Vec<u8>> {
    let signature = identity
        .signing
        .sign(&Zeroizing::new(input(domain, &body)?));
    let package = PrivateValue(Value::Array(vec![
        Value::Bytes(body),
        Value::Bytes(signature.to_bytes().to_vec()),
    ]));
    Ok(canonical::encode(&package.0)?)
}
pub(crate) fn verify_package(
    package: &[u8],
    limit: usize,
    domain: &[u8],
    author: &MemberPublic,
) -> ClientResult<Vec<u8>> {
    let value = PrivateValue(canonical::decode(package, limit)?);
    let f = fields(&value.0, 2)?;
    let body = binary(&f[0])?;
    let sig = binary(&f[1])?;
    if sig.len() != 64 {
        return Err(WireError::Schema.into());
    }
    VerifyingKey::from_bytes(&author.signing)?.verify_strict(
        &Zeroizing::new(input(domain, body)?),
        &Signature::from_slice(sig)?,
    )?;
    Ok(body.to_vec())
}
impl SetupInvite {
    pub fn create(
        identity: &CommIdentity,
        policy: &SetupPolicy,
        slot: u16,
        expires: u64,
        secret: Id32,
        operators: &OperatorSet,
    ) -> ClientResult<Zeroizing<Vec<u8>>> {
        let ctx = BootstrapContext::creator(policy.clone(), identity.public(), operators)?;
        if !(2..=policy.member_count).contains(&slot)
            || expires == 0
            || expires > i64::MAX as u64
            || secret == [0; 32]
        {
            return Err(WireError::Schema.into());
        }
        let secret = Zeroizing::new(secret);
        let body = canonical::encode(&Value::Array(vec![
            uint(1u16),
            bytes(&policy.ceremony),
            Value::Text(policy.network.clone()),
            uint(policy.threshold),
            uint(policy.member_count),
            uint(slot),
            uint(expires),
            member_value(&ctx.creator),
            bytes(&policy.config_digest),
            Value::Bytes(Sha256::digest(&*secret).to_vec()),
        ]))?;
        let package = signed(identity, INVITE_DOMAIN, body)?;
        let private = PrivateValue(Value::Array(vec![Value::Bytes(package), bytes(&secret)]));
        Ok(Zeroizing::new(canonical::encode(&private.0)?))
    }
    pub fn verify(
        private: &[u8],
        trusted_creator: &MemberPublic,
        bundle: &[u8],
        trusted_config_key: &Id32,
        now: u64,
    ) -> ClientResult<Self> {
        Self::verify_mode(
            private,
            trusted_creator,
            bundle,
            trusted_config_key,
            now,
            false,
        )
    }
    pub fn verify_development(
        private: &[u8],
        trusted_creator: &MemberPublic,
        bundle: &[u8],
        trusted_config_key: &Id32,
        now: u64,
    ) -> ClientResult<Self> {
        Self::verify_mode(
            private,
            trusted_creator,
            bundle,
            trusted_config_key,
            now,
            true,
        )
    }
    fn verify_mode(
        private: &[u8],
        trusted_creator: &MemberPublic,
        bundle: &[u8],
        trusted_config_key: &Id32,
        now: u64,
        development: bool,
    ) -> ClientResult<Self> {
        let operators = if development {
            OperatorSet::verify_development(bundle, trusted_config_key)
        } else {
            OperatorSet::verify(bundle, trusted_config_key)
        }?;
        let value = PrivateValue(canonical::decode(private, INVITE_LIMIT)?);
        let outer = match &value.0 {
            Value::Array(a) if matches!(a.len(), 2 | 3) => a.as_slice(),
            _ => return Err(WireError::Schema.into()),
        };
        let secret = Secret32::from_bytes(id(&outer[1])?);
        let encoded = verify_package(
            binary(&outer[0])?,
            INVITE_LIMIT,
            INVITE_DOMAIN,
            trusted_creator,
        )?;
        let body = canonical::decode(&encoded, INVITE_LIMIT)?;
        let f = fields(&body, 10)?;
        if number(&f[0])? != 1 {
            return Err(WireError::Version.into());
        }
        let Value::Text(network) = &f[2] else {
            return Err(WireError::Schema.into());
        };
        let creator_fields = fields(&f[7], 3)?;
        let creator = MemberPublic {
            id: small(&creator_fields[0])?,
            signing: id(&creator_fields[1])?,
            encryption: id(&creator_fields[2])?,
        };
        if creator != *trusted_creator
            || id(&f[9])? != <Id32>::from(Sha256::digest(secret.as_bytes()))
            || *secret.as_bytes() == [0; 32]
        {
            return Err(ClientError::Identity);
        }
        let policy = SetupPolicy {
            ceremony: id(&f[1])?,
            network: network.clone(),
            threshold: small(&f[3])?,
            member_count: small(&f[4])?,
            config_digest: id(&f[8])?,
        };
        let slot = small(&f[5])?;
        let expires = number(&f[6])?;
        if !(2..=policy.member_count).contains(&slot) || expires <= now || expires > i64::MAX as u64
        {
            return Err(ClientError::Config);
        }
        let context = BootstrapContext::creator(policy, creator, &operators)?;
        let bootstrap = if outer.len() == 3 {
            let ephemeral = invite_identity(secret.as_bytes(), context.policy(), slot)?;
            let seal = crate::SealContext {
                vault: context.policy().ceremony,
                roster: context.policy().config_digest,
                recipient: ephemeral.public(),
                domain: crate::SealDomain::Setup,
            };
            let raw = Zeroizing::new(crate::open_record(&seal, &ephemeral, binary(&outer[2])?)?);
            Some(SetupInboxDescriptor::verify(
                &raw,
                context.policy(),
                &operators,
                context.creator_identity(),
            )?)
        } else {
            None
        };
        Ok(Self {
            context,
            slot,
            expires,
            secret,
            bootstrap,
        })
    }
    pub fn context(&self) -> &BootstrapContext {
        &self.context
    }
    pub fn slot(&self) -> u16 {
        self.slot
    }
    pub fn expires(&self) -> u64 {
        self.expires
    }
    pub fn secret(&self) -> &Secret32 {
        &self.secret
    }
    pub fn to_fragment(private: &[u8]) -> ClientResult<Zeroizing<String>> {
        PrivateValue(canonical::decode(private, INVITE_LIMIT)?);
        let mut out = Zeroizing::new(String::with_capacity(1 + private.len() * 2));
        out.push('#');
        const HEX: &[u8] = b"0123456789abcdef";
        for b in private {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 15) as usize] as char);
        }
        Ok(out)
    }
    pub fn from_fragment(fragment: &str) -> ClientResult<Zeroizing<Vec<u8>>> {
        let hex = fragment.strip_prefix('#').ok_or(ClientError::Config)?;
        if hex.len() > INVITE_LIMIT * 2 || hex.len() % 2 != 0 || !hex.is_ascii() {
            return Err(WireError::Bounds.into());
        }
        fn digit(b: u8) -> ClientResult<u8> {
            match b {
                b'0'..=b'9' => Ok(b - b'0'),
                b'a'..=b'f' => Ok(b - b'a' + 10),
                _ => Err(ClientError::Config),
            }
        }
        let mut out = Zeroizing::new(Vec::with_capacity(hex.len() / 2));
        for pair in hex.as_bytes().chunks_exact(2) {
            out.push(digit(pair[0])? * 16 + digit(pair[1])?);
        }
        PrivateValue(canonical::decode(&out, INVITE_LIMIT)?);
        Ok(out)
    }
}

fn acceptance_payload(roster: &Roster, capabilities: &SetupCapabilities) -> ClientResult<Vec<u8>> {
    capabilities.require(1, roster.members.len() as u16)?;
    if capabilities.versions.len() > 8
        || capabilities.member_counts.len() > 4
        || capabilities.versions.windows(2).any(|w| w[0] >= w[1])
        || capabilities.member_counts.windows(2).any(|w| w[0] >= w[1])
    {
        return Err(WireError::Schema.into());
    }
    Ok(canonical::encode(&Value::Array(vec![
        Value::Bytes(types::encode_roster(roster)?),
        Value::Array(capabilities.versions.iter().map(|n| uint(*n)).collect()),
        Value::Array(
            capabilities
                .member_counts
                .iter()
                .map(|n| uint(*n))
                .collect(),
        ),
    ]))?)
}
pub fn sign_roster_acceptance(
    identity: &CommIdentity,
    ctx: &BootstrapContext,
    roster: &Roster,
    capabilities: &SetupCapabilities,
) -> ClientResult<Vec<u8>> {
    ctx.policy.validate()?;
    if roster.vault != ctx.policy.ceremony
        || roster.members.len() != ctx.policy.member_count as usize
        || roster.members.first() != Some(&ctx.creator)
        || !roster.members.contains(&identity.public())
    {
        return Err(ClientError::Identity);
    }
    let body = SetupRecord {
        version: 1,
        key: SetupKey {
            ceremony: ctx.policy.ceremony,
            phase: SetupPhase::RosterAccept,
            author: identity.public().id,
            recipient: 1,
            revision: 1,
        },
        network: ctx.policy.network.clone(),
        threshold: ctx.policy.threshold,
        member_count: ctx.policy.member_count,
        roster_digest: Some(types::roster_digest(roster)?),
        prerequisites: vec![],
        payload: acceptance_payload(roster, capabilities)?,
    };
    signed(identity, setup::RECORD_DOMAIN, setup::encode_record(&body)?)
}

/// Every slot has authenticated the same roster and policy; DKG may now begin.
/// This is still not a certified payment roster.
///
/// ```compile_fail
/// use loki_relay_client::{AcceptedSetupRoster, CommIdentity, sign_message};
/// use loki_relay_protocol::types::MessageBody;
/// fn payment(id:&CommIdentity, roster:&AcceptedSetupRoster, body:&MessageBody) {
///     sign_message(id, roster, body).unwrap();
/// }
/// ```
///
/// ```compile_fail
/// use loki_relay_client::AcceptedSetupRoster;
/// fn forge() -> AcceptedSetupRoster { AcceptedSetupRoster { } }
/// ```
pub struct AcceptedSetupRoster {
    context: BootstrapContext,
    roster: Roster,
    digest: Id32,
}
impl AcceptedSetupRoster {
    pub fn verify(
        ctx: &BootstrapContext,
        roster: Roster,
        acceptances: &[Vec<u8>],
    ) -> ClientResult<Self> {
        let digest = types::roster_digest(&roster)?;
        if roster.vault != ctx.policy.ceremony
            || roster.members.len() != ctx.policy.member_count as usize
            || roster.members.first() != Some(&ctx.creator)
            || acceptances.len() != roster.members.len()
        {
            return Err(ClientError::Identity);
        }
        for (author, package) in roster.members.iter().zip(acceptances) {
            let encoded =
                verify_package(package, setup::MAX_PACKAGE, setup::RECORD_DOMAIN, author)?;
            let record = setup::decode_record(&encoded)?;
            ctx.check(&record, 1)?;
            if record.key.author != author.id
                || record.key.phase != SetupPhase::RosterAccept
                || record.key.revision != 1
                || record.roster_digest != Some(digest)
                || !record.prerequisites.is_empty()
            {
                return Err(ClientError::Identity);
            }
            let payload = canonical::decode(&record.payload, 4096)?;
            let f = fields(&payload, 3)?;
            if binary(&f[0])? != types::encode_roster(&roster)? {
                return Err(ClientError::Identity);
            }
            fn list(v: &Value) -> ClientResult<Vec<u16>> {
                let Value::Array(items) = v else {
                    return Err(WireError::Schema.into());
                };
                items.iter().map(small).collect()
            }
            let capabilities = SetupCapabilities {
                versions: list(&f[1])?,
                member_counts: list(&f[2])?,
            };
            if acceptance_payload(&roster, &capabilities)? != record.payload {
                return Err(WireError::Canonical.into());
            }
        }
        Ok(Self {
            context: BootstrapContext {
                policy: ctx.policy.clone(),
                creator: ctx.creator.clone(),
            },
            roster,
            digest,
        })
    }
    pub fn roster(&self) -> &Roster {
        &self.roster
    }
    pub fn context(&self) -> &BootstrapContext {
        &self.context
    }
    pub fn digest(&self) -> &Id32 {
        &self.digest
    }
    fn check(&self, body: &SetupRecord, recipient: u16) -> ClientResult<&MemberPublic> {
        self.context.check(body, recipient)?;
        if matches!(
            body.key.phase,
            SetupPhase::Join | SetupPhase::RosterProposal | SetupPhase::RosterAccept
        ) || body.roster_digest != Some(self.digest)
        {
            return Err(ClientError::Identity);
        }
        self.roster
            .members
            .iter()
            .find(|m| m.id == body.key.author)
            .ok_or(ClientError::Identity)
    }
    pub fn sign(&self, identity: &CommIdentity, body: &SetupRecord) -> ClientResult<Vec<u8>> {
        if self.check(body, body.key.recipient)? != &identity.public() {
            return Err(ClientError::Identity);
        }
        signed(identity, setup::RECORD_DOMAIN, setup::encode_record(body)?)
    }
    pub fn authenticate(
        &self,
        recipient: u16,
        package: &[u8],
    ) -> ClientResult<AuthenticatedSetupRecord> {
        let value = PrivateValue(canonical::decode(package, setup::MAX_PACKAGE)?);
        let f = fields(&value.0, 2)?;
        let body = RecordGuard(Some(setup::decode_record(binary(&f[0])?)?));
        let author = self
            .roster
            .members
            .iter()
            .find(|m| m.id == body.key.author)
            .ok_or(ClientError::Identity)?;
        let encoded = Zeroizing::new(verify_package(
            package,
            setup::MAX_PACKAGE,
            setup::RECORD_DOMAIN,
            author,
        )?);
        self.context.check(&body, recipient)?;
        if body.roster_digest != Some(self.digest) {
            return Err(ClientError::Conflict);
        }
        self.check(&body, recipient)?;
        Ok(AuthenticatedSetupRecord {
            body: body.take(),
            digest: Sha256::digest(&*encoded).into(),
            canonical_body: encoded.to_vec(),
        })
    }
}
pub struct AuthenticatedSetupRecord {
    body: SetupRecord,
    digest: Id32,
    canonical_body: Vec<u8>,
}
impl AuthenticatedSetupRecord {
    pub fn body(&self) -> &SetupRecord {
        &self.body
    }
    pub fn digest(&self) -> &Id32 {
        &self.digest
    }
    pub fn canonical_body(&self) -> &[u8] {
        &self.canonical_body
    }
}

/// Volatile duplicate guard; transport must persist the same key/digest rule before effects.
#[derive(Default)]
pub struct SetupRecordIndex {
    records: BTreeMap<SetupKey, Id32>,
    terminal: bool,
}
impl SetupRecordIndex {
    pub fn observe(&mut self, record: &AuthenticatedSetupRecord) -> ClientResult<bool> {
        if self.terminal {
            return Err(ClientError::Conflict);
        }
        match self.records.get(&record.body.key) {
            Some(digest) if digest == &record.digest => Ok(false),
            Some(_) => {
                self.terminal = true;
                Err(ClientError::Conflict)
            }
            None => {
                self.records.insert(record.body.key.clone(), record.digest);
                Ok(true)
            }
        }
    }
}

pub fn sign_admission_request(
    identity: &CommIdentity,
    request: &loki_relay_protocol::admission::AdmissionRequest,
) -> ClientResult<Vec<u8>> {
    if request.device != identity.public() {
        return Err(ClientError::Identity);
    }
    signed(
        identity,
        loki_relay_protocol::admission::REQUEST_DOMAIN,
        loki_relay_protocol::admission::encode_request(request)?,
    )
}

#[derive(Clone)]
pub enum AdmissionOutcome {
    Accepted(Value),
    Rejected(&'static str),
}
#[derive(Clone)]
pub struct VerifiedAdmissionReply {
    outcome: AdmissionOutcome,
    package: Vec<u8>,
}
impl VerifiedAdmissionReply {
    pub fn outcome(&self) -> &AdmissionOutcome {
        &self.outcome
    }
    pub fn package(&self) -> &[u8] {
        &self.package
    }
}
fn admission_request(
    package: &[u8],
) -> ClientResult<loki_relay_protocol::admission::AdmissionRequest> {
    use loki_relay_protocol::admission;
    let value = canonical::decode(package, admission::MAX_REQUEST)?;
    let f = fields(&value, 2)?;
    let request = admission::decode_request(binary(&f[0])?)?;
    verify_package(
        package,
        admission::MAX_REQUEST,
        admission::REQUEST_DOMAIN,
        &request.device,
    )?;
    Ok(request)
}
pub fn verify_admission_reply(
    operators: &OperatorSet,
    request_package: &[u8],
    package: &[u8],
) -> ClientResult<VerifiedAdmissionReply> {
    verify_admission_reply_key(
        operators.admission_key(),
        operators.digest(),
        request_package,
        package,
    )
}
fn verify_admission_reply_key(
    key: &Id32,
    config: &Id32,
    request_package: &[u8],
    package: &[u8],
) -> ClientResult<VerifiedAdmissionReply> {
    use loki_relay_protocol::admission::{self, AdmissionCommand};
    let request = admission_request(request_package)?;
    if let AdmissionCommand::Create { config_digest, .. } = &request.command {
        if config_digest != config {
            return Err(ClientError::Config);
        }
    }
    let value = canonical::decode(package, admission::MAX_RESPONSE)?;
    let f = fields(&value, 2)?;
    let encoded = binary(&f[0])?;
    let signature = binary(&f[1])?;
    if signature.len() != 64 {
        return Err(WireError::Schema.into());
    }
    VerifyingKey::from_bytes(key)?.verify_strict(
        &input(admission::RESPONSE_DOMAIN, encoded)?,
        &Signature::from_slice(signature)?,
    )?;
    let value = canonical::decode(encoded, admission::MAX_RESPONSE - 128)?;
    let f = fields(&value, 4)?;
    if number(&f[0])? != 1 {
        return Err(WireError::Version.into());
    }
    if id(&f[1])? != request.operation
        || id(&f[2])? != <Id32>::from(Sha256::digest(request_package))
    {
        return Err(ClientError::Identity);
    }
    decode_admission_outcome(&f[3], package.to_vec())
}
pub struct VerifiedTerminalNotices {
    terminal: u16,
    members: Vec<u16>,
}
impl VerifiedTerminalNotices {
    pub fn terminal_kind(&self) -> u16 {
        self.terminal
    }
    pub fn notifying_members(&self) -> &[u16] {
        &self.members
    }
}
pub fn verify_terminal_notices(
    ceremony: &Id32,
    claimed: &[MemberPublic],
    reply: &VerifiedAdmissionReply,
) -> ClientResult<VerifiedTerminalNotices> {
    use loki_relay_protocol::admission::AdmissionCommand;
    if claimed.is_empty() || claimed.len() > 4 || *ceremony == [0; 32] {
        return Err(ClientError::Config);
    }
    let mut peers = BTreeMap::new();
    for peer in claimed {
        if !(1..=4).contains(&peer.id) || peers.insert(peer.id, peer).is_some() {
            return Err(ClientError::Config);
        }
    }
    let AdmissionOutcome::Accepted(value) = reply.outcome() else {
        return Err(ClientError::Identity);
    };
    let f = fields(value, 2)?;
    let terminal = u16::try_from(number(&f[0])?).map_err(|_| WireError::Schema)?;
    if terminal > 4 {
        return Err(WireError::Schema.into());
    }
    let Value::Array(notices) = &f[1] else {
        return Err(WireError::Schema.into());
    };
    if notices.len() > claimed.len() || (terminal == 0 && !notices.is_empty()) {
        return Err(WireError::Schema.into());
    }
    let mut members = Vec::new();
    for value in notices {
        let package = binary(value)?;
        if package.len() > 1024 {
            return Err(WireError::Bounds.into());
        }
        let request = admission_request(package)?;
        let kind = match request.command {
            AdmissionCommand::Terminal { ceremony: id, kind }
            | AdmissionCommand::TerminalNotice { ceremony: id, kind }
                if id == *ceremony && kind == terminal && kind != 0 =>
            {
                kind
            }
            _ => return Err(ClientError::Identity),
        };
        if kind == 0
            || peers.get(&request.device.id).copied() != Some(&request.device)
            || members
                .last()
                .map(|id| *id >= request.device.id)
                .unwrap_or(false)
        {
            return Err(ClientError::Identity);
        }
        members.push(request.device.id);
    }
    Ok(VerifiedTerminalNotices { terminal, members })
}
pub struct AdmissionHttp {
    client: reqwest::Client,
    origin: String,
    key: Id32,
    config: Id32,
    deadline: std::time::Duration,
}
impl AdmissionHttp {
    pub fn new(operators: &OperatorSet) -> ClientResult<Self> {
        Self::build(operators, false)
    }
    pub fn development(operators: &OperatorSet) -> ClientResult<Self> {
        Self::build(operators, true)
    }
    fn build(operators: &OperatorSet, development: bool) -> ClientResult<Self> {
        crate::validate_endpoint(operators.admission_origin(), development)?;
        Ok(Self {
            client: crate::RelayHttp::client_builder()
                .timeout(std::time::Duration::from_secs(
                    operators.limits().request_seconds,
                ))
                .build()?,
            origin: operators.admission_origin().trim_end_matches('/').into(),
            key: *operators.admission_key(),
            config: *operators.digest(),
            deadline: std::time::Duration::from_secs(operators.limits().request_seconds),
        })
    }
    pub async fn execute_authenticated(
        &self,
        identity: &CommIdentity,
        package: &[u8],
        credential: Option<&[u8]>,
    ) -> ClientResult<VerifiedAdmissionReply> {
        use loki_relay_protocol::admission::{AdmissionCommand, AdmissionRequest};
        let request = admission_request(package)?;
        if request.device != identity.public() {
            return Err(ClientError::Identity);
        }
        tokio::time::timeout(self.deadline, async {
            if credential.is_some() {
                let mut operation = [0; 32];
                getrandom::fill(&mut operation).map_err(|_| ClientError::Crypto)?;
                let probe = sign_admission_request(
                    identity,
                    &AdmissionRequest {
                        operation,
                        device: identity.public(),
                        command: AdmissionCommand::State {
                            ceremony: *request.command.ceremony(),
                            slot: identity.public().id,
                        },
                    },
                )?;
                self.execute_wire(&probe, None).await?;
            }
            self.execute_wire(package, credential).await
        })
        .await
        .map_err(|_| ClientError::Transport)?
    }
    pub async fn execute(
        &self,
        package: &[u8],
        credential: Option<&[u8]>,
    ) -> ClientResult<VerifiedAdmissionReply> {
        if credential.is_some() {
            return Err(ClientError::Config);
        }
        self.execute_wire(package, None).await
    }
    async fn execute_wire(
        &self,
        package: &[u8],
        credential: Option<&[u8]>,
    ) -> ClientResult<VerifiedAdmissionReply> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use loki_relay_protocol::admission::{self, AdmissionCommand};
        use reqwest::header::{HeaderValue, AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE};
        let request = admission_request(package)?;
        match &request.command {
            AdmissionCommand::Create {
                config_digest,
                grant_digest,
                ..
            } => {
                if *config_digest != self.config
                    || credential
                        .map(|c| <Id32>::from(Sha256::digest(c)) != *grant_digest)
                        .unwrap_or(false)
                {
                    return Err(ClientError::Config);
                }
            }
            AdmissionCommand::Claim { invite_hash, .. } => {
                if credential
                    .map(|c| c.len() != 32 || <Id32>::from(Sha256::digest(c)) != *invite_hash)
                    .unwrap_or(false)
                {
                    return Err(ClientError::Config);
                }
            }
            _ => {
                if credential.is_some() {
                    return Err(ClientError::Config);
                }
            }
        }
        let (method, path) = admission::request_target(&request.command);
        let method =
            reqwest::Method::from_bytes(method.as_bytes()).map_err(|_| ClientError::Config)?;
        let mut outgoing = self
            .client
            .request(method, format!("{}{path}", self.origin))
            .header(CONTENT_TYPE, "application/cbor")
            .body(package.to_vec());
        if let Some(credential) = credential {
            if credential.len() > 4096 {
                return Err(WireError::Bounds.into());
            }
            let encoded = Zeroizing::new(URL_SAFE_NO_PAD.encode(credential));
            let bearer = Zeroizing::new(format!("Bearer {}", &*encoded));
            let mut header = HeaderValue::from_str(&bearer).map_err(|_| ClientError::Config)?;
            header.set_sensitive(true);
            outgoing = outgoing.header(AUTHORIZATION, header);
        }
        let mut response = outgoing.send().await?;
        if response.status() != 200
            || response
                .headers()
                .get(CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                != Some("application/cbor")
            || response.headers().contains_key(CONTENT_ENCODING)
            || response
                .content_length()
                .map(|n| n > admission::MAX_RESPONSE as u64)
                .unwrap_or(false)
        {
            return Err(ClientError::Transport);
        }
        let mut raw = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if raw
                .len()
                .checked_add(chunk.len())
                .filter(|n| *n <= admission::MAX_RESPONSE)
                .is_none()
            {
                return Err(WireError::Bounds.into());
            }
            raw.extend_from_slice(&chunk);
        }
        verify_admission_reply_key(&self.key, &self.config, package, &raw)
    }
}
fn decode_admission_outcome(
    value: &Value,
    package: Vec<u8>,
) -> ClientResult<VerifiedAdmissionReply> {
    let result = fields(value, 2)?;
    let outcome = match number(&result[0])? {
        1 => AdmissionOutcome::Accepted(result[1].clone()),
        0 => {
            let Value::Text(code) = &result[1] else {
                return Err(WireError::Schema.into());
            };
            let code = match code.as_str() {
                "enrollment" => "enrollment",
                "identity" => "identity",
                "conflict" => "conflict",
                "expired" => "expired",
                "terminal" => "terminal",
                "quota" => "quota",
                "malformed" => "malformed",
                "storage" => "storage",
                "unavailable" => "unavailable",
                _ => return Err(WireError::Schema.into()),
            };
            AdmissionOutcome::Rejected(code)
        }
        _ => return Err(WireError::Schema.into()),
    };
    Ok(VerifiedAdmissionReply { outcome, package })
}

impl Drop for AuthenticatedSetupRecord {
    fn drop(&mut self) {
        self.body.payload.zeroize();
        self.canonical_body.zeroize();
    }
}
const INBOX_DOMAIN: &[u8] = b"Loki_Setup_Inbox_v1\0";
pub struct SetupInboxDescriptor {
    package: Zeroizing<Vec<u8>>,
    policy: SetupPolicy,
    owner: MemberPublic,
    relays: Vec<crate::DescriptorRelay>,
}
pub(crate) fn policy_bytes(p: &SetupPolicy) -> ClientResult<Vec<u8>> {
    p.validate()?;
    Ok(canonical::encode(&Value::Array(vec![
        bytes(&p.ceremony),
        Value::Text(p.network.clone()),
        uint(p.threshold),
        uint(p.member_count),
        bytes(&p.config_digest),
    ]))?)
}
impl SetupInboxDescriptor {
    pub fn to_package(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.package.to_vec())
    }
    pub fn owner(&self) -> u16 {
        self.owner.id
    }
    pub fn owner_identity(&self) -> &MemberPublic {
        &self.owner
    }
    pub fn relays(&self) -> &[crate::DescriptorRelay] {
        &self.relays
    }
    pub fn policy(&self) -> &SetupPolicy {
        &self.policy
    }
    pub fn sign(
        identity: &CommIdentity,
        policy: &SetupPolicy,
        operators: &OperatorSet,
        relays: Vec<crate::DescriptorRelay>,
    ) -> ClientResult<Zeroizing<Vec<u8>>> {
        Self::check_routes(policy, operators, identity.public().id, &relays)?;
        let value = PrivateValue(Value::Array(vec![
            uint(1u16),
            Value::Bytes(policy_bytes(policy)?),
            member_value(&identity.public()),
            Value::Array(
                relays
                    .iter()
                    .map(|r| {
                        Value::Array(vec![
                            bytes(&r.route.pin.key),
                            bytes(&r.route.pin.run),
                            Value::Bytes(r.route.endpoint.as_bytes().to_vec()),
                            bytes(&r.route.mailbox),
                            uint(r.route.append_revision),
                            bytes(r.append.as_bytes()),
                        ])
                    })
                    .collect(),
            ),
        ]));
        Ok(Zeroizing::new(signed(
            identity,
            INBOX_DOMAIN,
            canonical::encode(&value.0)?,
        )?))
    }
    fn check_routes(
        policy: &SetupPolicy,
        operators: &OperatorSet,
        owner: u16,
        relays: &[crate::DescriptorRelay],
    ) -> ClientResult<()> {
        if policy.config_digest != *operators.digest()
            || !(1..=policy.member_count).contains(&owner)
            || relays.len() != 3
        {
            return Err(ClientError::Identity);
        }
        let mut mailboxes = std::collections::BTreeSet::new();
        for (r, pin) in relays.iter().zip(operators.relay_routes()) {
            if r.route.pin != pin.pin
                || r.route.endpoint != pin.endpoint
                || r.route.append_revision != 1
                || r.route.mailbox == [0; 32]
                || *r.append.as_bytes() == [0; 32]
                || !mailboxes.insert(r.route.mailbox)
            {
                return Err(ClientError::Config);
            }
        }
        Ok(())
    }
    pub fn verify(
        package: &[u8],
        policy: &SetupPolicy,
        operators: &OperatorSet,
        claimed_owner: &MemberPublic,
    ) -> ClientResult<Self> {
        let raw = Zeroizing::new(verify_package(package, 16384, INBOX_DOMAIN, claimed_owner)?);
        let value = PrivateValue(canonical::decode(&raw, 16384)?);
        let f = fields(&value.0, 4)?;
        if number(&f[0])? != 1 || binary(&f[1])? != policy_bytes(policy)? {
            return Err(ClientError::Identity);
        }
        let m = fields(&f[2], 3)?;
        let owner = MemberPublic {
            id: small(&m[0])?,
            signing: id(&m[1])?,
            encryption: id(&m[2])?,
        };
        if owner != *claimed_owner {
            return Err(ClientError::Identity);
        }
        let Value::Array(routes) = &f[3] else {
            return Err(ClientError::Config);
        };
        let mut relays = Vec::new();
        for route in routes {
            let r = fields(route, 6)?;
            relays.push(crate::DescriptorRelay {
                route: loki_relay_protocol::types::RelayRoute {
                    pin: loki_relay_protocol::types::RelayPin {
                        key: id(&r[0])?,
                        run: id(&r[1])?,
                    },
                    endpoint: std::str::from_utf8(binary(&r[2])?)
                        .map_err(|_| ClientError::Config)?
                        .to_owned(),
                    mailbox: id(&r[3])?,
                    append_revision: number(&r[4])?,
                },
                append: Secret32::from_bytes(id(&r[5])?),
            });
        }
        Self::check_routes(policy, operators, owner.id, &relays)?;
        Ok(Self {
            package: Zeroizing::new(package.to_vec()),
            policy: policy.clone(),
            owner,
            relays,
        })
    }
}
fn invite_identity(secret: &Id32, policy: &SetupPolicy, slot: u16) -> ClientResult<CommIdentity> {
    let mut raw = Zeroizing::new([0u8; 66]);
    raw[..2].copy_from_slice(&slot.to_be_bytes());
    for (domain, offset) in [
        (b"Loki_Setup_Invite_Signing_v1\0".as_slice(), 2),
        (b"Loki_Setup_Invite_Encryption_v1\0".as_slice(), 34),
    ] {
        let mut hash = Sha256::new();
        hash.update(domain);
        hash.update(secret);
        hash.update(policy.ceremony);
        hash.update(policy.config_digest);
        hash.update(slot.to_be_bytes());
        raw[offset..offset + 32].copy_from_slice(&hash.finalize());
    }
    CommIdentity::from_serialized(&raw)
}
impl SetupInvite {
    pub fn create_with_bootstrap(
        identity: &CommIdentity,
        policy: &SetupPolicy,
        slot: u16,
        expires: u64,
        secret: Id32,
        operators: &OperatorSet,
        descriptor: &[u8],
    ) -> ClientResult<Zeroizing<Vec<u8>>> {
        SetupInboxDescriptor::verify(descriptor, policy, operators, &identity.public())?;
        let secret = Zeroizing::new(secret);
        let base = Self::create(identity, policy, slot, expires, *secret, operators)?;
        let ephemeral = invite_identity(&secret, policy, slot)?;
        let ctx = crate::SealContext {
            vault: policy.ceremony,
            roster: policy.config_digest,
            recipient: ephemeral.public(),
            domain: crate::SealDomain::Setup,
        };
        let encrypted = crate::seal_record(&ctx, descriptor)?;
        let mut private = PrivateValue(canonical::decode(&base, INVITE_LIMIT)?);
        let Value::Array(a) = &mut private.0 else {
            return Err(ClientError::Config);
        };
        a.push(Value::Bytes(encrypted.wire));
        Ok(Zeroizing::new(canonical::encode(&private.0)?))
    }
    pub fn bootstrap_descriptor(&self) -> Option<&SetupInboxDescriptor> {
        self.bootstrap.as_ref()
    }
}
