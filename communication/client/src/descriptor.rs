use crate::{
    open_record, seal_record, ClientError, ClientResult, CommIdentity, SealContext, SealDomain,
};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use loki_relay_protocol::{
    canonical::{self, Value},
    types::{roster_digest, Id32, MemberId, MemberPublic, Object, RelayPin, RelayRoute, Roster},
    WireError,
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const MAX_BODY: usize = 16 * 1024 * 1024;
const MAX_PACKAGE: usize = MAX_BODY + 128;
const MAX_REVISION: u64 = i64::MAX as u64;
const SIGNATURE_DOMAIN: &[u8] = b"Loki_Relay_Config_v1\0";

pub struct Secret32(Zeroizing<Id32>);

impl Secret32 {
    pub fn from_bytes(bytes: Id32) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &Id32 {
        &self.0
    }
}

pub struct DescriptorRelay {
    pub route: RelayRoute,
    pub append: Secret32,
}

pub struct Descriptor {
    pub vault: Id32,
    pub roster: Id32,
    pub owner: MemberId,
    pub revision: u64,
    pub relays: Vec<DescriptorRelay>,
}

impl Descriptor {
    pub fn new(
        vault: Id32,
        roster: Id32,
        owner: MemberId,
        revision: u64,
        relays: Vec<DescriptorRelay>,
    ) -> Self {
        Self {
            vault,
            roster,
            owner,
            revision,
            relays,
        }
    }
}

pub struct AuthenticatedDescriptor {
    body: Descriptor,
    canonical_body: Zeroizing<Vec<u8>>,
    digest: Id32,
}

impl AuthenticatedDescriptor {
    pub fn body(&self) -> &Descriptor {
        &self.body
    }

    pub fn canonical_body(&self) -> &[u8] {
        &self.canonical_body
    }

    pub fn digest(&self) -> &Id32 {
        &self.digest
    }
}

pub struct OwnerInbox {
    pub route: RelayRoute,
    pub read: Secret32,
    pub append: Secret32,
    pub admin: Secret32,
}

pub struct ClientConfig {
    pub own: Vec<OwnerInbox>,
    pub peers: Vec<AuthenticatedDescriptor>,
}

struct SecretValue(Value);

impl Drop for SecretValue {
    fn drop(&mut self) {
        fn wipe(value: &mut Value) {
            match value {
                Value::Bytes(bytes) => bytes.zeroize(),
                Value::Array(values) => values.iter_mut().for_each(wipe),
                _ => {}
            }
        }
        wipe(&mut self.0);
    }
}

fn array(value: &Value) -> ClientResult<&[Value]> {
    match value {
        Value::Array(fields) => Ok(fields),
        _ => Err(WireError::Schema.into()),
    }
}

fn bytes(value: &Value) -> ClientResult<&[u8]> {
    match value {
        Value::Bytes(bytes) => Ok(bytes),
        _ => Err(WireError::Schema.into()),
    }
}

fn id(value: &Value) -> ClientResult<Id32> {
    bytes(value)?
        .try_into()
        .map_err(|_| WireError::Schema.into())
}

fn number(value: &Value) -> ClientResult<u64> {
    match value {
        Value::Integer(n) => u64::try_from(*n).map_err(|_| WireError::Schema.into()),
        _ => Err(WireError::Schema.into()),
    }
}

fn revision(value: u64) -> ClientResult<()> {
    if value == 0 || value > MAX_REVISION {
        return Err(WireError::Bounds.into());
    }
    Ok(())
}

pub(crate) fn endpoint(endpoint: &str) -> ClientResult<()> {
    crate::validate_endpoint(endpoint, true)
}

fn validate(descriptor: &Descriptor) -> ClientResult<()> {
    if !(1..=loki_relay_protocol::types::MAX_MEMBERS).contains(&descriptor.owner)
        || descriptor.relays.len() != 3
    {
        return Err(WireError::Schema.into());
    }
    revision(descriptor.revision)?;
    for relay in &descriptor.relays {
        revision(relay.route.append_revision)?;
        endpoint(&relay.route.endpoint)?;
    }
    if descriptor
        .relays
        .windows(2)
        .any(|pair| pair[0].route.pin.key >= pair[1].route.pin.key)
    {
        return Err(WireError::Schema.into());
    }
    for (index, relay) in descriptor.relays.iter().enumerate() {
        if descriptor.relays[..index]
            .iter()
            .any(|prior| prior.append.as_bytes() == relay.append.as_bytes())
        {
            return Err(ClientError::Config);
        }
    }
    Ok(())
}

fn encode_body(descriptor: &Descriptor) -> ClientResult<Zeroizing<Vec<u8>>> {
    validate(descriptor)?;
    let value = SecretValue(Value::Array(vec![
        Value::Integer(1.into()),
        Value::Bytes(descriptor.vault.to_vec()),
        Value::Bytes(descriptor.roster.to_vec()),
        Value::Integer(descriptor.owner.into()),
        Value::Integer(descriptor.revision.into()),
        Value::Array(
            descriptor
                .relays
                .iter()
                .map(|relay| {
                    Value::Array(vec![
                        Value::Bytes(relay.route.pin.key.to_vec()),
                        Value::Bytes(relay.route.endpoint.as_bytes().to_vec()),
                        Value::Bytes(relay.route.pin.run.to_vec()),
                        Value::Bytes(relay.route.mailbox.to_vec()),
                        Value::Integer(relay.route.append_revision.into()),
                        Value::Bytes(relay.append.as_bytes().to_vec()),
                    ])
                })
                .collect(),
        ),
    ]));
    let encoded = Zeroizing::new(canonical::encode(&value.0)?);
    if encoded.len() > MAX_BODY {
        return Err(WireError::Bounds.into());
    }
    Ok(encoded)
}

fn decode_body(encoded: &[u8]) -> ClientResult<Descriptor> {
    let value = SecretValue(canonical::decode(encoded, MAX_BODY)?);
    let fields = array(&value.0)?;
    if fields.len() != 6 {
        return Err(WireError::Schema.into());
    }
    if number(&fields[0])? != 1 {
        return Err(WireError::Version.into());
    }
    let relays = array(&fields[5])?;
    if relays.len() != 3 {
        return Err(WireError::Schema.into());
    }
    let relays = relays
        .iter()
        .map(|value| {
            let entry = array(value)?;
            if entry.len() != 6 {
                return Err(WireError::Schema.into());
            }
            let url = bytes(&entry[1])?;
            if url.len() > 2048 {
                return Err(WireError::Bounds.into());
            }
            Ok(DescriptorRelay {
                route: RelayRoute {
                    pin: RelayPin {
                        key: id(&entry[0])?,
                        run: id(&entry[2])?,
                    },
                    endpoint: std::str::from_utf8(url)
                        .map_err(|_| WireError::Schema)?
                        .to_owned(),
                    mailbox: id(&entry[3])?,
                    append_revision: number(&entry[4])?,
                },
                append: Secret32::from_bytes(id(&entry[5])?),
            })
        })
        .collect::<ClientResult<Vec<_>>>()?;
    let descriptor = Descriptor::new(
        id(&fields[1])?,
        id(&fields[2])?,
        u16::try_from(number(&fields[3])?).map_err(|_| WireError::Schema)?,
        number(&fields[4])?,
        relays,
    );
    if encode_body(&descriptor)?.as_slice() != encoded {
        return Err(WireError::Canonical.into());
    }
    Ok(descriptor)
}

fn signature_input(body: &[u8]) -> ClientResult<Zeroizing<Vec<u8>>> {
    let length = u32::try_from(body.len()).map_err(|_| WireError::Bounds)?;
    let mut input = Zeroizing::new(Vec::with_capacity(SIGNATURE_DOMAIN.len() + 4 + body.len()));
    input.extend_from_slice(SIGNATURE_DOMAIN);
    input.extend_from_slice(&length.to_be_bytes());
    input.extend_from_slice(body);
    Ok(input)
}

fn certified_identity(roster: &Roster, identity: &CommIdentity) -> ClientResult<Id32> {
    let digest = roster_digest(roster)?;
    if !roster.members.contains(&identity.public()) {
        return Err(ClientError::Identity);
    }
    Ok(digest)
}

fn owner<'a>(
    roster: &'a Roster,
    digest: &Id32,
    descriptor: &Descriptor,
) -> ClientResult<&'a MemberPublic> {
    if descriptor.vault != roster.vault || &descriptor.roster != digest {
        return Err(ClientError::Identity);
    }
    roster
        .members
        .iter()
        .find(|member| member.id == descriptor.owner)
        .ok_or(ClientError::Identity)
}

pub fn seal_descriptor(
    identity: &CommIdentity,
    roster: &Roster,
    descriptor: &Descriptor,
    peer: &MemberPublic,
) -> ClientResult<Object> {
    let digest = certified_identity(roster, identity)?;
    if owner(roster, &digest, descriptor)? != &identity.public() || !roster.members.contains(peer) {
        return Err(ClientError::Identity);
    }
    let body = encode_body(descriptor)?;
    let signature = identity.signing.sign(&signature_input(&body)?);
    let package = SecretValue(Value::Array(vec![
        Value::Bytes(body.to_vec()),
        Value::Bytes(signature.to_bytes().to_vec()),
    ]));
    let package = Zeroizing::new(canonical::encode(&package.0)?);
    let record = SecretValue(Value::Array(vec![
        Value::Integer(1.into()),
        Value::Bytes(package.to_vec()),
    ]));
    let record = Zeroizing::new(canonical::encode(&record.0)?);
    seal_record(
        &SealContext {
            vault: roster.vault,
            roster: digest,
            recipient: peer.clone(),
            domain: SealDomain::Config,
        },
        &record,
    )
}

pub fn open_descriptor(
    identity: &CommIdentity,
    roster: &Roster,
    wire: &[u8],
) -> ClientResult<AuthenticatedDescriptor> {
    let digest = certified_identity(roster, identity)?;
    let record = Zeroizing::new(open_record(
        &SealContext {
            vault: roster.vault,
            roster: digest,
            recipient: identity.public(),
            domain: SealDomain::Config,
        },
        identity,
        wire,
    )?);
    let record = SecretValue(canonical::decode(&record, MAX_PACKAGE)?);
    let fields = array(&record.0)?;
    if fields.len() != 2 {
        return Err(WireError::Schema.into());
    }
    if number(&fields[0])? != 1 {
        return Err(WireError::Version.into());
    }
    let package = SecretValue(canonical::decode(bytes(&fields[1])?, MAX_PACKAGE)?);
    let fields = array(&package.0)?;
    if fields.len() != 2 {
        return Err(WireError::Schema.into());
    }
    let body = bytes(&fields[0])?;
    let signature = bytes(&fields[1])?;
    if signature.len() != 64 {
        return Err(WireError::Schema.into());
    }
    let descriptor = decode_body(body)?;
    let owner = owner(roster, &digest, &descriptor)?;
    VerifyingKey::from_bytes(&owner.signing)?
        .verify_strict(&signature_input(body)?, &Signature::from_slice(signature)?)?;
    Ok(AuthenticatedDescriptor {
        body: descriptor,
        canonical_body: Zeroizing::new(body.to_vec()),
        digest: Sha256::digest(body).into(),
    })
}

pub fn accept_descriptor(
    prior: &AuthenticatedDescriptor,
    next: &AuthenticatedDescriptor,
) -> ClientResult<()> {
    let prior_digest = prior.digest;
    let next_digest = next.digest;
    let prior = prior.body();
    let next = next.body();
    if prior.vault != next.vault || prior.roster != next.roster || prior.owner != next.owner {
        return Err(ClientError::Identity);
    }
    if next.revision < prior.revision
        || (next.revision == prior.revision && next_digest != prior_digest)
    {
        return Err(ClientError::Conflict);
    }
    Ok(())
}
