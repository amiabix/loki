use crate::{
    open_record, seal_record, AcceptedSetupRoster, AuthenticatedSetupRecord, BootstrapContext,
    ClientError, ClientResult, CommIdentity, OperatorSet, SealContext, SealDomain,
};
use loki_relay_protocol::{
    canonical::{self, Value},
    setup::{self, SetupKey, SetupPhase, SetupRecord},
    types::{Id32, MemberPublic, Object},
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use zeroize::{Zeroize, Zeroizing};

const SEGMENT: usize = 60_000;
const MAX_CHUNKS: usize = 18;

pub enum SetupAuthority<'a> {
    Bootstrap(&'a BootstrapContext, &'a [MemberPublic]),
    Accepted(&'a AcceptedSetupRoster),
}
pub struct SetupTransport<'a> {
    pub(crate) identity: &'a CommIdentity,
    pub(crate) operators: &'a OperatorSet,
    authority: SetupAuthority<'a>,
    pub(crate) development: bool,
}
pub struct PreparedSetup {
    pub(crate) ceremony: Id32,
    pub(crate) config: Id32,
    pub(crate) author: MemberPublic,
    pub(crate) copies: Vec<SetupCopy>,
}
pub(crate) struct SetupCopy {
    pub key: SetupKey,
    pub digest: Id32,
    pub prerequisites: Vec<Id32>,
    pub root: Id32,
    pub objects: Vec<Object>,
}
struct Temporary(Value);
impl Drop for Temporary {
    fn drop(&mut self) {
        fn wipe(v: &mut Value) {
            match v {
                Value::Bytes(b) => b.zeroize(),
                Value::Text(t) => t.zeroize(),
                Value::Array(a) => a.iter_mut().for_each(wipe),
                _ => {}
            }
        }
        wipe(&mut self.0);
    }
}
fn uint(n: usize) -> Value {
    Value::Integer((n as u64).into())
}
fn bytes(b: &[u8]) -> Value {
    Value::Bytes(b.to_vec())
}
fn fields(v: &Value, n: usize) -> ClientResult<&[Value]> {
    match v {
        Value::Array(a) if a.len() == n => Ok(a),
        _ => Err(ClientError::Config),
    }
}
fn binary(v: &Value) -> ClientResult<&[u8]> {
    match v {
        Value::Bytes(b) => Ok(b),
        _ => Err(ClientError::Config),
    }
}
fn number(v: &Value) -> ClientResult<usize> {
    match v {
        Value::Integer(n) => usize::try_from(*n).map_err(|_| ClientError::Config),
        _ => Err(ClientError::Config),
    }
}
fn id(v: &Value) -> ClientResult<Id32> {
    binary(v)?.try_into().map_err(|_| ClientError::Config)
}
impl<'a> SetupTransport<'a> {
    pub(crate) fn has_accepted_roster(&self) -> bool {
        matches!(self.authority, SetupAuthority::Accepted(_))
    }
    pub fn new(
        identity: &'a CommIdentity,
        operators: &'a OperatorSet,
        authority: SetupAuthority<'a>,
        development: bool,
    ) -> ClientResult<Self> {
        let t = Self {
            identity,
            operators,
            authority,
            development,
        };
        let p = t.context().policy();
        if p.config_digest != *operators.digest() {
            return Err(ClientError::Config);
        }
        let peers = t.peers();
        let mut ids = BTreeSet::new();
        let mut signing = BTreeSet::new();
        let mut encryption = BTreeSet::new();
        if peers.is_empty() || peers.len() > p.member_count as usize {
            return Err(ClientError::Identity);
        }
        for m in peers {
            if !(1..=p.member_count).contains(&m.id)
                || !ids.insert(m.id)
                || !signing.insert(m.signing)
                || !encryption.insert(m.encryption)
            {
                return Err(ClientError::Identity);
            }
            ed25519_dalek::VerifyingKey::from_bytes(&m.signing)?;
        }
        if t.peer(1)? != t.context().creator_identity()
            || t.peer(identity.public().id)? != &identity.public()
        {
            return Err(ClientError::Identity);
        }
        Ok(t)
    }
    pub fn context(&self) -> &BootstrapContext {
        match &self.authority {
            SetupAuthority::Bootstrap(c, _) => c,
            SetupAuthority::Accepted(r) => r.context(),
        }
    }
    pub(crate) fn peers(&self) -> &[MemberPublic] {
        match &self.authority {
            SetupAuthority::Bootstrap(_, p) => p,
            SetupAuthority::Accepted(r) => &r.roster().members,
        }
    }
    pub(crate) fn peer(&self, id: u16) -> ClientResult<&MemberPublic> {
        self.peers()
            .iter()
            .find(|m| m.id == id)
            .ok_or(ClientError::Identity)
    }
    pub(crate) fn seal_context(&self, recipient: u16) -> ClientResult<SealContext> {
        Ok(SealContext {
            vault: self.context().policy().ceremony,
            roster: self.context().policy().config_digest,
            recipient: self.peer(recipient)?.clone(),
            domain: SealDomain::Setup,
        })
    }
    fn sign(&self, record: &SetupRecord) -> ClientResult<Vec<u8>> {
        match &self.authority {
            SetupAuthority::Bootstrap(c, _) => c.sign_bootstrap(self.identity, record),
            SetupAuthority::Accepted(r) => r.sign(self.identity, record),
        }
    }
    pub(crate) fn authenticate(&self, package: &[u8]) -> ClientResult<AuthenticatedSetupRecord> {
        let record = match &self.authority {
            SetupAuthority::Bootstrap(c, _) => {
                let v = Temporary(canonical::decode(package, setup::MAX_PACKAGE)?);
                let f = fields(&v.0, 2)?;
                let mut record = setup::decode_record(binary(&f[0])?)?;
                let author = record.key.author;
                record.payload.zeroize();
                c.authenticate_bootstrap(self.peer(author)?, self.identity.public().id, package)
            }
            SetupAuthority::Accepted(r) => {
                let v = Temporary(canonical::decode(package, setup::MAX_PACKAGE)?);
                let f = fields(&v.0, 2)?;
                let mut record = setup::decode_record(binary(&f[0])?)?;
                let phase = record.key.phase;
                let author = record.key.author;
                let roster = record.roster_digest;
                record.payload.zeroize();
                if matches!(
                    phase,
                    SetupPhase::Join
                        | SetupPhase::RosterProposal
                        | SetupPhase::RosterAccept
                        | SetupPhase::Abort
                ) {
                    let authenticated = r.context().authenticate_bootstrap(
                        self.peer(author)?,
                        self.identity.public().id,
                        package,
                    )?;
                    if phase != SetupPhase::Join
                        && !(phase == SetupPhase::Abort && roster.is_none())
                        && roster != Some(*r.digest())
                    {
                        return Err(ClientError::Conflict);
                    }
                    Ok(authenticated)
                } else {
                    r.authenticate(self.identity.public().id, package)
                }
            }
        }?;
        if record.body().payload.len() as u64 > self.operators.limits().payload_bytes {
            return Err(ClientError::Capacity);
        }
        Ok(record)
    }
    pub fn prepare(&self, records: &[SetupRecord]) -> ClientResult<PreparedSetup> {
        if records
            .iter()
            .any(|r| r.payload.len() as u64 > self.operators.limits().payload_bytes)
        {
            return Err(ClientError::Capacity);
        }
        let first = records.first().ok_or(ClientError::Config)?;
        let author = self.identity.public();
        let required: BTreeSet<u16> = if first.key.phase == SetupPhase::Join {
            [1, author.id].into_iter().collect()
        } else {
            (1..=self.context().policy().member_count).collect()
        };
        if records.len() != required.len() {
            return Err(ClientError::Identity);
        }
        let mut seen = BTreeSet::new();
        let mut copies = Vec::new();
        for record in records {
            if record.key.author != author.id
                || record.key.phase != first.key.phase
                || record.key.revision != first.key.revision
                || record.key.ceremony != first.key.ceremony
                || !required.contains(&record.key.recipient)
                || !seen.insert(record.key.recipient)
                || record.roster_digest != first.roster_digest
                || (!matches!(
                    record.key.phase,
                    SetupPhase::Round2 | SetupPhase::PaymentDescriptor
                ) && record.payload != first.payload)
            {
                return Err(ClientError::Identity);
            }
            let package = Zeroizing::new(self.sign(record)?);
            let ctx = self.seal_context(record.key.recipient)?;
            let mut objects = Vec::new();
            let root = if package.len() <= SEGMENT {
                let v = Temporary(Value::Array(vec![uint(1), bytes(&package)]));
                seal_record(&ctx, &Zeroizing::new(canonical::encode(&v.0)?))?
            } else {
                let package_hash: Id32 = Sha256::digest(&*package).into();
                let mut entries = Vec::new();
                for (index, segment) in package.chunks(SEGMENT).enumerate() {
                    let v = Temporary(Value::Array(vec![
                        uint(3),
                        bytes(&package_hash),
                        uint(index),
                        bytes(segment),
                    ]));
                    let object = seal_record(&ctx, &Zeroizing::new(canonical::encode(&v.0)?))?;
                    entries.push(Value::Array(vec![bytes(&object.hash), uint(segment.len())]));
                    objects.push(object);
                }
                if objects.len() > MAX_CHUNKS {
                    return Err(ClientError::Capacity);
                }
                let manifest = Temporary(Value::Array(vec![
                    uint(2),
                    uint(package.len()),
                    bytes(&package_hash),
                    Value::Array(entries),
                ]));
                seal_record(&ctx, &Zeroizing::new(canonical::encode(&manifest.0)?))?
            };
            let root_hash = root.hash;
            objects.push(root);
            copies.push(SetupCopy {
                key: record.key.clone(),
                digest: Sha256::digest(&*Zeroizing::new(setup::encode_record(record)?)).into(),
                prerequisites: record.prerequisites.clone(),
                root: root_hash,
                objects,
            });
        }
        let wire_bytes: u64 = copies
            .iter()
            .flat_map(|c| &c.objects)
            .map(|o| o.wire.len() as u64)
            .sum();
        if wire_bytes > self.operators.limits().storage_bytes_per_relay {
            return Err(ClientError::Capacity);
        }
        Ok(PreparedSetup {
            ceremony: self.context().policy().ceremony,
            config: *self.operators.digest(),
            author,
            copies,
        })
    }
    pub(crate) fn inspect(&self, root: &Object) -> ClientResult<Vec<(Id32, usize)>> {
        if <Id32>::from(Sha256::digest(&root.wire)) != root.hash {
            return Err(ClientError::Identity);
        }
        let raw = Zeroizing::new(open_record(
            &self.seal_context(self.identity.public().id)?,
            self.identity,
            &root.wire,
        )?);
        let v = Temporary(canonical::decode(&raw, 65536)?);
        let Value::Array(a) = &v.0 else {
            return Err(ClientError::Config);
        };
        match number(a.first().ok_or(ClientError::Config)?)? {
            1 => {
                fields(&v.0, 2)?;
                Ok(vec![])
            }
            3 => {
                fields(&v.0, 4)?;
                Err(ClientError::MissingObjects(vec![]))
            }
            2 => {
                let f = fields(&v.0, 4)?;
                let total = number(&f[1])?;
                id(&f[2])?;
                let Value::Array(entries) = &f[3] else {
                    return Err(ClientError::Config);
                };
                if total <= SEGMENT
                    || total
                        > self.operators.limits().payload_bytes as usize
                            + (setup::MAX_PACKAGE - setup::MAX_PAYLOAD)
                    || entries.len() != total.div_ceil(SEGMENT)
                    || entries.len() > MAX_CHUNKS
                {
                    return Err(ClientError::Config);
                }
                let mut out = Vec::new();
                let mut seen = BTreeSet::new();
                for (i, e) in entries.iter().enumerate() {
                    let e = fields(e, 2)?;
                    let h = id(&e[0])?;
                    let len = number(&e[1])?;
                    if h == root.hash
                        || !seen.insert(h)
                        || len != std::cmp::min(SEGMENT, total - i * SEGMENT)
                    {
                        return Err(ClientError::Config);
                    }
                    out.push((h, len));
                }
                Ok(out)
            }
            _ => Err(ClientError::Config),
        }
    }
    pub(crate) fn assemble(
        &self,
        root: &Object,
        objects: &BTreeMap<Id32, Object>,
    ) -> ClientResult<AuthenticatedSetupRecord> {
        let entries = self.inspect(root)?;
        let ctx = self.seal_context(self.identity.public().id)?;
        let raw = Zeroizing::new(open_record(&ctx, self.identity, &root.wire)?);
        let v = Temporary(canonical::decode(&raw, 65536)?);
        let Value::Array(f) = &v.0 else {
            return Err(ClientError::Config);
        };
        if entries.is_empty() {
            return self.authenticate(binary(&f[1])?);
        }
        let package_hash = id(&f[2])?;
        let mut package = Zeroizing::new(Vec::with_capacity(number(&f[1])?));
        let missing: Vec<_> = entries
            .iter()
            .filter(|(h, _)| !objects.contains_key(h))
            .map(|(h, _)| *h)
            .collect();
        if !missing.is_empty() {
            return Err(ClientError::MissingObjects(missing));
        }
        for (i, (h, len)) in entries.iter().enumerate() {
            let object = &objects[h];
            if object.hash != *h || <Id32>::from(Sha256::digest(&object.wire)) != *h {
                return Err(ClientError::Identity);
            }
            let raw = Zeroizing::new(open_record(&ctx, self.identity, &object.wire)?);
            let chunk = Temporary(canonical::decode(&raw, 65536)?);
            let c = fields(&chunk.0, 4)?;
            if number(&c[0])? != 3
                || id(&c[1])? != package_hash
                || number(&c[2])? != i
                || binary(&c[3])?.len() != *len
            {
                return Err(ClientError::Identity);
            }
            package.extend_from_slice(binary(&c[3])?);
        }
        if <Id32>::from(Sha256::digest(&*package)) != package_hash {
            return Err(ClientError::Identity);
        }
        self.authenticate(&package)
    }
}

impl PreparedSetup {
    pub fn recipient_digest(&self, recipient: u16) -> ClientResult<Id32> {
        self.copies
            .iter()
            .find(|copy| copy.key.recipient == recipient)
            .map(|copy| copy.digest)
            .ok_or(ClientError::Identity)
    }
    pub fn recipient_objects(
        &self,
        recipient: u16,
    ) -> ClientResult<(Object, BTreeMap<Id32, Object>)> {
        let c = self
            .copies
            .iter()
            .find(|c| c.key.recipient == recipient)
            .ok_or(ClientError::Identity)?;
        let objects: BTreeMap<_, _> = c.objects.iter().map(|o| (o.hash, o.clone())).collect();
        Ok((
            objects.get(&c.root).ok_or(ClientError::Storage)?.clone(),
            objects,
        ))
    }
}
impl SetupTransport<'_> {
    pub fn authenticate_objects(
        &self,
        root: &Object,
        objects: &BTreeMap<Id32, Object>,
    ) -> ClientResult<AuthenticatedSetupRecord> {
        self.assemble(root, objects)
    }
}

const PREPARED_DOMAIN: &[u8] = b"Loki_Setup_Prepared_v1\0";
const PREPARED_LIMIT: usize = 8 * 1024 * 1024;
fn prepared_message(body: &[u8]) -> ClientResult<Vec<u8>> {
    if body.len() > PREPARED_LIMIT - 128 {
        return Err(ClientError::Capacity);
    }
    let mut out = PREPARED_DOMAIN.to_vec();
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}
impl SetupTransport<'_> {
    fn validate_prepared(&self, prepared: &PreparedSetup) -> ClientResult<()> {
        if prepared.ceremony != self.context().policy().ceremony
            || prepared.config != *self.operators.digest()
            || prepared.author != self.identity.public()
        {
            return Err(ClientError::Identity);
        }
        let first = prepared.copies.first().ok_or(ClientError::Identity)?;
        let required: BTreeSet<u16> = if first.key.phase == SetupPhase::Join {
            [1, prepared.author.id].into_iter().collect()
        } else {
            (1..=self.context().policy().member_count).collect()
        };
        if prepared.copies.len() != required.len() {
            return Err(ClientError::Identity);
        }
        let mut seen = BTreeSet::new();
        let mut total = 0u64;
        for copy in &prepared.copies {
            if copy.key.ceremony != prepared.ceremony
                || copy.key.author != prepared.author.id
                || copy.key.phase != first.key.phase
                || copy.key.revision != first.key.revision
                || copy.key.revision == 0
                || !required.contains(&copy.key.recipient)
                || !seen.insert(copy.key.recipient)
                || copy.digest == [0; 32]
                || copy.prerequisites.len() > 64
                || copy.prerequisites.iter().any(|p| *p == [0; 32])
                || !copy.prerequisites.windows(2).all(|p| p[0] < p[1])
                || copy.objects.is_empty()
                || copy.objects.len() > MAX_CHUNKS + 1
                || copy.objects.last().map(|o| o.hash) != Some(copy.root)
            {
                return Err(ClientError::Identity);
            }
            let mut hashes = BTreeSet::new();
            for object in &copy.objects {
                loki_relay_protocol::envelope::validate_wire(&object.wire)?;
                if !hashes.insert(object.hash)
                    || <Id32>::from(Sha256::digest(&object.wire)) != object.hash
                {
                    return Err(ClientError::Identity);
                }
                total = total
                    .checked_add(object.wire.len() as u64)
                    .ok_or(ClientError::Capacity)?;
            }
        }
        if total > self.operators.limits().storage_bytes_per_relay
            || total > PREPARED_LIMIT as u64 - 16 * 1024
        {
            return Err(ClientError::Capacity);
        }
        let own = prepared
            .copies
            .iter()
            .find(|c| c.key.recipient == prepared.author.id)
            .ok_or(ClientError::Identity)?;
        let root = own.objects.last().ok_or(ClientError::Identity)?;
        let objects = own.objects.iter().map(|o| (o.hash, o.clone())).collect();
        let record = self.assemble(root, &objects)?;
        if record.body().key != own.key
            || record.digest() != &own.digest
            || record.body().prerequisites != own.prerequisites
        {
            return Err(ClientError::Identity);
        }
        Ok(())
    }
    /// Save this signed ciphertext bundle inside an authenticated sealed generation before publication.
    pub fn checkpoint_prepared(&self, prepared: &PreparedSetup) -> ClientResult<Vec<u8>> {
        use ed25519_dalek::Signer;
        self.validate_prepared(prepared)?;
        let body = canonical::encode(&Value::Array(vec![
            uint(1),
            bytes(&prepared.ceremony),
            bytes(&prepared.config),
            Value::Array(vec![
                uint(prepared.author.id as usize),
                bytes(&prepared.author.signing),
                bytes(&prepared.author.encryption),
            ]),
            Value::Array(
                prepared
                    .copies
                    .iter()
                    .map(|copy| {
                        Value::Array(vec![
                            Value::Array(vec![
                                uint(copy.key.phase as usize),
                                uint(copy.key.author as usize),
                                uint(copy.key.recipient as usize),
                                Value::Integer(copy.key.revision.into()),
                            ]),
                            bytes(&copy.digest),
                            Value::Array(copy.prerequisites.iter().map(|p| bytes(p)).collect()),
                            bytes(&copy.root),
                            Value::Array(
                                copy.objects
                                    .iter()
                                    .map(|o| Value::Array(vec![bytes(&o.hash), bytes(&o.wire)]))
                                    .collect(),
                            ),
                        ])
                    })
                    .collect(),
            ),
        ]))?;
        let signature = self.identity.signing.sign(&prepared_message(&body)?);
        let raw = canonical::encode(&Value::Array(vec![
            bytes(&body),
            bytes(&signature.to_bytes()),
        ]))?;
        if raw.len() > PREPARED_LIMIT {
            return Err(ClientError::Capacity);
        }
        Ok(raw)
    }
    /// Restore exact saved objects; this never draws fresh encryption randomness.
    pub fn restore_prepared(&self, raw: &[u8]) -> ClientResult<PreparedSetup> {
        let wrapper = Temporary(canonical::decode(raw, PREPARED_LIMIT)?);
        let wrapper = fields(&wrapper.0, 2)?;
        let body = binary(&wrapper[0])?;
        let signature: [u8; 64] = binary(&wrapper[1])?
            .try_into()
            .map_err(|_| ClientError::Identity)?;
        self.identity.signing.verifying_key().verify_strict(
            &prepared_message(body)?,
            &ed25519_dalek::Signature::from_bytes(&signature),
        )?;
        let value = Temporary(canonical::decode(body, PREPARED_LIMIT)?);
        let value = fields(&value.0, 5)?;
        if number(&value[0])? != 1 {
            return Err(ClientError::Config);
        }
        let ceremony = id(&value[1])?;
        let config = id(&value[2])?;
        let author = fields(&value[3], 3)?;
        let author = MemberPublic {
            id: u16::try_from(number(&author[0])?).map_err(|_| ClientError::Identity)?,
            signing: id(&author[1])?,
            encryption: id(&author[2])?,
        };
        let Value::Array(encoded) = &value[4] else {
            return Err(ClientError::Config);
        };
        if encoded.len() > usize::from(loki_relay_protocol::types::MAX_MEMBERS) {
            return Err(ClientError::Capacity);
        }
        let mut copies = Vec::new();
        for encoded in encoded {
            let encoded = fields(encoded, 5)?;
            let key = fields(&encoded[0], 4)?;
            let key = SetupKey {
                ceremony,
                phase: SetupPhase::try_from(number(&key[0])? as u64)?,
                author: u16::try_from(number(&key[1])?).map_err(|_| ClientError::Identity)?,
                recipient: u16::try_from(number(&key[2])?).map_err(|_| ClientError::Identity)?,
                revision: u64::try_from(number(&key[3])?).map_err(|_| ClientError::Identity)?,
            };
            let Value::Array(prerequisites) = &encoded[2] else {
                return Err(ClientError::Config);
            };
            if prerequisites.len() > 64 {
                return Err(ClientError::Capacity);
            }
            let prerequisites = prerequisites
                .iter()
                .map(id)
                .collect::<ClientResult<Vec<_>>>()?;
            let Value::Array(objects) = &encoded[4] else {
                return Err(ClientError::Config);
            };
            if objects.len() > MAX_CHUNKS + 1 {
                return Err(ClientError::Capacity);
            }
            let objects = objects
                .iter()
                .map(|o| {
                    let o = fields(o, 2)?;
                    Ok(Object {
                        hash: id(&o[0])?,
                        wire: binary(&o[1])?.to_vec(),
                    })
                })
                .collect::<ClientResult<Vec<_>>>()?;
            copies.push(SetupCopy {
                key,
                digest: id(&encoded[1])?,
                prerequisites,
                root: id(&encoded[3])?,
                objects,
            });
        }
        let prepared = PreparedSetup {
            ceremony,
            config,
            author,
            copies,
        };
        self.validate_prepared(&prepared)?;
        Ok(prepared)
    }
}
