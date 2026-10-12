use crate::{
    seal_record, sign_message, ClientError, ClientResult, CommIdentity, SealContext, SealDomain,
};
use ed25519_dalek::Signer;
use loki_relay_protocol::{
    canonical::{self, Value},
    envelope,
    types::{self, Id32, LogicalKey, MemberId, MemberPublic, MessageBody, Object, Roster},
    WireError,
};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, Zeroizing};

const MAX_BODY: usize = 16 * 1024 * 1024;
const MAX_PACKAGE: usize = MAX_BODY + 128;
const SEGMENT_LEN: usize = 61440;
const MAX_CHUNKS: usize = 274;
const MANIFEST_DOMAIN: &[u8] = b"Loki_Relay_Manifest_v1\0";

/// The exact complete encrypted sets bound to the validated signed message.
/// Only preparation can construct this authority; cloning extracted ciphertext
/// does not grant authority to publish it under a different key or digest.
///
/// ```compile_fail
/// use loki_relay_client::PreparedOutbox;
/// fn change(outbox: &mut PreparedOutbox) { outbox.key().message = [0; 32]; }
/// ```
/// ```compile_fail
/// use loki_relay_client::PreparedOutbox;
/// fn change(outbox: &mut PreparedOutbox) { outbox.digest()[0] ^= 1; }
/// ```
/// ```compile_fail
/// use loki_relay_client::PreparedOutbox;
/// fn reorder(outbox: &mut PreparedOutbox) { outbox.recipients().swap(0, 1); }
/// ```
/// ```compile_fail
/// use loki_relay_client::PreparedOutbox;
/// use loki_relay_protocol::types::LogicalKey;
/// fn forge(key: LogicalKey) -> PreparedOutbox {
///     PreparedOutbox { key, digest: [0; 32], recipients: vec![] }
/// }
/// ```
pub struct PreparedOutbox {
    key: LogicalKey,
    digest: Id32,
    recipients: Vec<RecipientObjects>,
}

impl PreparedOutbox {
    pub fn key(&self) -> &LogicalKey {
        &self.key
    }
    pub fn digest(&self) -> &Id32 {
        &self.digest
    }
    pub fn recipients(&self) -> &[RecipientObjects] {
        &self.recipients
    }
}

/// Saved chunks precede the root manifest; a single envelope is its own root.
///
/// ```compile_fail
/// use loki_relay_client::RecipientObjects;
/// fn corrupt(recipient: &mut RecipientObjects) { recipient.objects()[0].wire.clear(); }
/// ```
/// ```compile_fail
/// use loki_relay_client::RecipientObjects;
/// fn forge() -> RecipientObjects {
///     RecipientObjects { recipient: 1, transfer: None, objects: vec![], root_hash: [0; 32] }
/// }
/// ```
pub struct RecipientObjects {
    recipient: MemberId,
    transfer: Option<Id32>,
    objects: Vec<Object>,
    root_hash: Id32,
}

impl RecipientObjects {
    pub fn recipient(&self) -> MemberId {
        self.recipient
    }
    pub fn transfer(&self) -> Option<&Id32> {
        self.transfer.as_ref()
    }
    pub fn objects(&self) -> &[Object] {
        &self.objects
    }
    pub fn root_hash(&self) -> &Id32 {
        &self.root_hash
    }
}

fn uint(n: usize) -> Value {
    Value::Integer((n as u64).into())
}
fn bytes(data: &[u8]) -> Value {
    Value::Bytes(data.to_vec())
}

fn wipe(value: &mut Value) {
    match value {
        Value::Bytes(data) => data.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(wipe),
        _ => (),
    }
}

fn encode_temporary(mut value: Value) -> ClientResult<Zeroizing<Vec<u8>>> {
    let encoded = canonical::encode(&value);
    wipe(&mut value);
    Ok(Zeroizing::new(encoded?))
}

fn package_chunks(body_len: usize, package_len: usize) -> ClientResult<usize> {
    if body_len > MAX_BODY
        || package_len > MAX_PACKAGE
        || package_len < body_len
        || package_len - body_len > 128
    {
        return Err(WireError::Bounds.into());
    }
    let count = package_len.div_ceil(SEGMENT_LEN);
    if !(1..=MAX_CHUNKS).contains(&count) {
        return Err(WireError::Bounds.into());
    }
    Ok(count)
}

/// Prepare all three complete recipient copies without network or store effects.
pub fn prepare_outbox(
    identity: &CommIdentity,
    roster: &Roster,
    body: &MessageBody,
) -> ClientResult<PreparedOutbox> {
    let package = Zeroizing::new(sign_message(identity, roster, body)?);
    let encoded_body = Zeroizing::new(types::encode_message(body)?);
    let chunk_count = package_chunks(encoded_body.len(), package.len())?;
    let digest: Id32 = Sha256::digest(&*encoded_body).into();
    drop(encoded_body);
    let single = encode_temporary(Value::Array(vec![uint(1), bytes(&package)]))?;
    let fits_single = envelope::padded_wire_length(single.len()).is_ok();
    let package_hash: Id32 = Sha256::digest(&*package).into();
    let mut recipients = Vec::with_capacity(3);
    for member in &roster.members {
        let ctx = SealContext {
            vault: body.key.vault,
            roster: body.key.roster,
            recipient: member.clone(),
            domain: SealDomain::Message,
        };
        let (transfer, objects) = if fits_single {
            (None, vec![seal_record(&ctx, &single)?])
        } else {
            let mut transfer = [0u8; 32];
            getrandom::fill(&mut transfer).map_err(|_| ClientError::Crypto)?;
            let mut objects = Vec::with_capacity(chunk_count + 1);
            let mut entries = Vec::with_capacity(chunk_count);
            for (index, segment) in package.chunks(SEGMENT_LEN).enumerate() {
                let record = encode_temporary(Value::Array(vec![
                    uint(3),
                    bytes(&transfer),
                    uint(index),
                    bytes(segment),
                ]))?;
                let object = seal_record(&ctx, &record)?;
                entries.push(Value::Array(vec![
                    bytes(&object.hash),
                    uint(object.wire.len()),
                    uint(segment.len()),
                ]));
                objects.push(object);
            }
            let manifest = encode_temporary(Value::Array(vec![
                uint(1),
                bytes(&body.key.vault),
                bytes(&body.key.roster),
                uint(body.key.sender as usize),
                uint(member.id as usize),
                bytes(&transfer),
                bytes(&body.key.message),
                bytes(&digest),
                bytes(&package_hash),
                uint(package.len()),
                Value::Array(entries),
            ]))?;
            let mut input = Zeroizing::new(MANIFEST_DOMAIN.to_vec());
            input.extend_from_slice(&(manifest.len() as u32).to_be_bytes());
            input.extend_from_slice(&manifest);
            let signature = identity.signing.sign(&input);
            let record = encode_temporary(Value::Array(vec![
                uint(2),
                bytes(&manifest),
                bytes(&signature.to_bytes()),
            ]))?;
            objects.push(seal_record(&ctx, &record)?);
            (Some(transfer), objects)
        };
        let root_hash = objects.last().ok_or(WireError::Bounds)?.hash;
        recipients.push(RecipientObjects {
            recipient: member.id,
            transfer,
            objects,
            root_hash,
        });
    }
    Ok(PreparedOutbox {
        key: body.key.clone(),
        digest,
        recipients,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recipient_set_package_limits() {
        assert_eq!(package_chunks(16_777_216, 16_777_344).unwrap(), 274);
        assert!(package_chunks(16_777_216, 16_777_345).is_err());
        assert!(package_chunks(16_777_217, 16_777_344).is_err());
        assert!(package_chunks(100, 229).is_err());
        assert!(package_chunks(100, 99).is_err());
        assert!(package_chunks(0, 0).is_err());
    }
}

/// Complete ciphertext membership bound by successful transfer authentication.
///
/// ```compile_fail
/// use loki_relay_client::CompleteSource;
/// fn forge() -> CompleteSource {
///     CompleteSource { required_hashes: vec![], key: todo!(), digest: [0;32], recipient: 1 }
/// }
/// ```
/// ```compile_fail
/// use loki_relay_client::CompleteSource;
/// fn alter(source: &mut CompleteSource) { source.required_hashes()[0] = [0;32]; }
/// ```
/// ```compile_fail
/// use loki_relay_client::CompleteSource;
/// fn alter(source: &mut CompleteSource) { source.key().message = [0;32]; }
/// ```
/// ```compile_fail
/// use loki_relay_client::CompleteSource;
/// fn alter(source: &mut CompleteSource) { source.digest()[0] ^= 1; }
/// ```
pub struct CompleteSource {
    required_hashes: Vec<Id32>,
    key: LogicalKey,
    digest: Id32,
    recipient: MemberId,
}
impl CompleteSource {
    pub(crate) fn committed(
        required_hashes: Vec<Id32>,
        key: LogicalKey,
        digest: Id32,
        recipient: MemberId,
    ) -> Self {
        Self {
            required_hashes,
            key,
            digest,
            recipient,
        }
    }

    pub fn required_hashes(&self) -> &[Id32] {
        &self.required_hashes
    }
    pub fn key(&self) -> &LogicalKey {
        &self.key
    }
    pub fn digest(&self) -> &Id32 {
        &self.digest
    }
    pub fn recipient(&self) -> MemberId {
        self.recipient
    }
}

/// The authenticated message and its validated complete encrypted source.
///
/// ```compile_fail
/// use loki_relay_client::{AuthenticatedTransfer, AuthenticatedMessage, CompleteSource};
/// fn forge(message: AuthenticatedMessage, source: CompleteSource) -> AuthenticatedTransfer {
///     AuthenticatedTransfer { message, source }
/// }
/// ```
pub struct AuthenticatedTransfer {
    message: crate::AuthenticatedMessage,
    source: CompleteSource,
}
impl AuthenticatedTransfer {
    pub fn message(&self) -> &crate::AuthenticatedMessage {
        &self.message
    }
    pub fn source(&self) -> &CompleteSource {
        &self.source
    }
    pub fn into_parts(self) -> (crate::AuthenticatedMessage, CompleteSource) {
        (self.message, self.source)
    }
}

impl std::fmt::Debug for AuthenticatedTransfer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedTransfer")
            .field("message", &self.message)
            .field("recipient", &self.source.recipient)
            .field("objects", &self.source.required_hashes.len())
            .finish()
    }
}

struct TemporaryValue(Value);
impl Drop for TemporaryValue {
    fn drop(&mut self) {
        wipe(&mut self.0);
    }
}
fn decode_temporary(data: &[u8], max: usize) -> ClientResult<TemporaryValue> {
    Ok(TemporaryValue(canonical::decode(data, max)?))
}
fn fields(value: &Value, count: usize) -> ClientResult<&[Value]> {
    match value {
        Value::Array(items) if items.len() == count => Ok(items),
        _ => Err(WireError::Schema.into()),
    }
}
fn data(value: &Value) -> ClientResult<&[u8]> {
    match value {
        Value::Bytes(bytes) => Ok(bytes),
        _ => Err(WireError::Schema.into()),
    }
}
fn id(value: &Value) -> ClientResult<Id32> {
    data(value)?
        .try_into()
        .map_err(|_| WireError::Schema.into())
}
fn integer(value: &Value) -> ClientResult<usize> {
    match value {
        Value::Integer(n) => usize::try_from(*n).map_err(|_| WireError::Schema.into()),
        _ => Err(WireError::Schema.into()),
    }
}
fn verify_object(object: &Object, expected: &Id32) -> ClientResult<()> {
    envelope::validate_wire(&object.wire)?;
    if &object.hash != expected || <Id32>::from(Sha256::digest(&object.wire)) != *expected {
        return Err(WireError::Schema.into());
    }
    Ok(())
}

fn transfer_limits(count: usize, total: usize) -> ClientResult<()> {
    if !(1..=MAX_CHUNKS).contains(&count) || total == 0 || total > MAX_PACKAGE {
        return Err(WireError::Bounds.into());
    }
    Ok(())
}

fn manifest_entries(
    entries: &[Value],
    root_hash: Id32,
    total: usize,
) -> ClientResult<Vec<(Id32, usize, usize)>> {
    transfer_limits(entries.len(), total)?;
    let mut seen = std::collections::BTreeSet::from([root_hash]);
    let mut parsed = Vec::with_capacity(entries.len());
    let mut summed = 0usize;
    for (index, entry) in entries.iter().enumerate() {
        let e = fields(entry, 3)?;
        let hash = id(&e[0])?;
        let wire_len = integer(&e[1])?;
        let segment_len = integer(&e[2])?;
        if !seen.insert(hash)
            || !(1024..=65536).contains(&wire_len)
            || wire_len % 1024 != 0
            || !(1..=SEGMENT_LEN).contains(&segment_len)
            || (index + 1 < entries.len() && segment_len != SEGMENT_LEN)
        {
            return Err(WireError::Schema.into());
        }
        summed = summed.checked_add(segment_len).ok_or(WireError::Bounds)?;
        parsed.push((hash, wire_len, segment_len));
    }
    if summed != total {
        return Err(WireError::Bounds.into());
    }
    Ok(parsed)
}

fn chunk_segment<'a>(
    chunk: &'a Value,
    transfer: &Id32,
    index: usize,
    segment_len: usize,
) -> ClientResult<&'a [u8]> {
    let c = fields(chunk, 4)?;
    if integer(&c[0])? != 3
        || id(&c[1])? != *transfer
        || integer(&c[2])? != index
        || data(&c[3])?.len() != segment_len
    {
        return Err(WireError::Schema.into());
    }
    data(&c[3])
}

fn message_context<'a>(
    roster: &'a Roster,
    identity: &CommIdentity,
) -> ClientResult<(&'a MemberPublic, Id32, SealContext)> {
    let roster_digest = types::roster_digest(roster)?;
    let public = identity.public();
    let recipient = roster
        .members
        .iter()
        .find(|member| **member == public)
        .ok_or(ClientError::Identity)?;
    let ctx = SealContext {
        vault: roster.vault,
        roster: roster_digest,
        recipient: recipient.clone(),
        domain: SealDomain::Message,
    };
    Ok((recipient, roster_digest, ctx))
}

struct ParsedManifest {
    transfer: Id32,
    key: LogicalKey,
    digest: Id32,
    package_hash: Id32,
    total: usize,
    entries: Vec<(Id32, usize, usize)>,
}

fn parsed_manifest(
    roster: &Roster,
    roster_digest: Id32,
    recipient: MemberId,
    root_hash: Id32,
    manifest_bytes: &[u8],
    signature: &[u8],
) -> ClientResult<ParsedManifest> {
    let manifest = decode_temporary(manifest_bytes, 65536)?;
    let m = fields(&manifest.0, 11)?;
    let sender_id = integer(&m[3])?;
    let sender = roster
        .members
        .iter()
        .find(|member| usize::from(member.id) == sender_id)
        .ok_or(ClientError::Identity)?;
    let mut input = Zeroizing::new(MANIFEST_DOMAIN.to_vec());
    input.extend_from_slice(
        &u32::try_from(manifest_bytes.len())
            .map_err(|_| WireError::Bounds)?
            .to_be_bytes(),
    );
    input.extend_from_slice(manifest_bytes);
    ed25519_dalek::VerifyingKey::from_bytes(&sender.signing)?.verify_strict(
        &input,
        &ed25519_dalek::Signature::from_slice(signature)?,
    )?;
    if integer(&m[0])? != 1
        || id(&m[1])? != roster.vault
        || id(&m[2])? != roster_digest
        || integer(&m[4])? != usize::from(recipient)
    {
        return Err(ClientError::Identity);
    }
    let transfer = id(&m[5])?;
    let key = LogicalKey {
        vault: id(&m[1])?,
        roster: id(&m[2])?,
        sender: sender.id,
        message: id(&m[6])?,
    };
    let digest = id(&m[7])?;
    let package_hash = id(&m[8])?;
    let total = integer(&m[9])?;
    let Value::Array(entries) = &m[10] else {
        return Err(WireError::Schema.into());
    };
    Ok(ParsedManifest {
        transfer,
        key,
        digest,
        package_hash,
        total,
        entries: manifest_entries(entries, root_hash, total)?,
    })
}

fn rejection_reason(error: &ClientError) -> &'static str {
    match error {
        ClientError::Identity => "identity",
        ClientError::Crypto => "signature",
        ClientError::Wire(WireError::Bounds) => "bounds",
        ClientError::Wire(WireError::Schema) => "schema",
        ClientError::Wire(_) => "framing",
        _ => "manifest",
    }
}

/// One ordered object named by a verified signed manifest.
///
/// The hash and wire length are staging metadata. They do not authenticate the package.
pub struct ManifestRequirement {
    hash: Id32,
    wire_length: usize,
}

impl ManifestRequirement {
    pub fn hash(&self) -> &Id32 {
        &self.hash
    }

    pub fn wire_length(&self) -> usize {
        self.wire_length
    }
}

/// Context-bound signed manifest. Staging may use this value.
///
/// It is not an authenticated message, a `CompleteSource`, or a Received proof.
/// Full body authentication stays in `TransferAssembler::open`.
pub struct SignedManifest {
    root: Id32,
    transfer: Id32,
    key: LogicalKey,
    digest: Id32,
    recipient: MemberId,
    requirements: Vec<ManifestRequirement>,
}

impl SignedManifest {
    pub fn root(&self) -> &Id32 {
        &self.root
    }

    pub fn transfer(&self) -> &Id32 {
        &self.transfer
    }

    pub fn key(&self) -> &LogicalKey {
        &self.key
    }

    pub fn digest(&self) -> &Id32 {
        &self.digest
    }

    pub fn recipient(&self) -> MemberId {
        self.recipient
    }

    pub fn requirements(&self) -> &[ManifestRequirement] {
        &self.requirements
    }
}

/// Group id for one verified binding. The same binding reuses a slot; a reused transfer id does not.
pub(crate) fn source_group_id(
    key: &LogicalKey,
    digest: &Id32,
    recipient: MemberId,
    transfer: Option<&Id32>,
) -> ClientResult<Id32> {
    let transfer = match transfer {
        Some(id) => bytes(id),
        None => Value::Null,
    };
    let encoded = canonical::encode(&Value::Array(vec![
        uint(1),
        bytes(&key.vault),
        bytes(&key.roster),
        uint(usize::from(key.sender)),
        bytes(&key.message),
        bytes(digest),
        uint(usize::from(recipient)),
        transfer,
    ]))?;
    Ok(Sha256::digest(encoded).into())
}

fn chunk_shape(value: &Value) -> Result<(), &'static str> {
    let c = fields(value, 4).map_err(|_| "schema")?;
    if integer(&c[0]).ok() != Some(3) || id(&c[1]).is_err() {
        return Err("schema");
    }
    let index = integer(&c[2]).map_err(|_| "schema")?;
    if index >= MAX_CHUNKS {
        return Err("bounds");
    }
    match data(&c[3]) {
        Ok(segment) if (1..=SEGMENT_LEN).contains(&segment.len()) => Ok(()),
        Ok(_) => Err("bounds"),
        Err(_) => Err("schema"),
    }
}

fn open_failure(error: &ClientError) -> &'static str {
    match error {
        ClientError::Identity => "identity",
        ClientError::Crypto => "decryption",
        ClientError::Wire(WireError::Bounds) => "bounds",
        ClientError::Wire(WireError::Schema) => "schema",
        ClientError::Wire(_) => "framing",
        _ => "schema",
    }
}

fn signed_manifest(root: Id32, recipient: MemberId, parsed: ParsedManifest) -> SignedManifest {
    SignedManifest {
        root,
        transfer: parsed.transfer,
        key: parsed.key,
        digest: parsed.digest,
        recipient,
        requirements: parsed
            .entries
            .into_iter()
            .map(|(hash, wire_length, _segment)| ManifestRequirement { hash, wire_length })
            .collect(),
    }
}

/// What a cached ciphertext is allowed to mean before complete authentication.
///
/// `Chunk` is a structurally valid tag-3 record. Its clear transfer id is not group authority
/// and the ciphertext is not rejected. `Invalid` is a durable per-object failure.
pub enum RootInspection {
    Chunk,
    Single,
    Manifest(SignedManifest),
    Invalid(&'static str),
}

pub struct TransferAssembler;
impl TransferAssembler {
    /// Classify a cached object without assembling its package.
    ///
    /// A signed manifest yields readonly requirements. A chunk stays opaque.
    /// Only `open` authenticates the complete body.
    pub fn inspect(
        roster: &Roster,
        identity: &CommIdentity,
        root: &Object,
    ) -> ClientResult<RootInspection> {
        let (recipient, roster_digest, ctx) = message_context(roster, identity)?;
        if envelope::validate_wire(&root.wire).is_err() {
            return Ok(RootInspection::Invalid("framing"));
        }
        if verify_object(root, &root.hash).is_err() {
            return Ok(RootInspection::Invalid("hash"));
        }
        let raw = match crate::open_record(&ctx, identity, &root.wire) {
            Ok(raw) => Zeroizing::new(raw),
            Err(error) => return Ok(RootInspection::Invalid(open_failure(&error))),
        };
        let inner = match decode_temporary(&raw, 65536) {
            Ok(inner) => inner,
            Err(error) => return Ok(RootInspection::Invalid(open_failure(&error))),
        };
        let Value::Array(record) = &inner.0 else {
            return Ok(RootInspection::Invalid("schema"));
        };
        let tag = match record.first().map(integer).transpose() {
            Ok(Some(tag)) => tag,
            _ => return Ok(RootInspection::Invalid("schema")),
        };
        // A valid chunk stays available for its manifest. The unsigned transfer id is ignored.
        if tag == 3 {
            return Ok(match chunk_shape(&inner.0) {
                Ok(()) => RootInspection::Chunk,
                Err(reason) => RootInspection::Invalid(reason),
            });
        }
        if tag == 1 {
            return Ok(if fields(&inner.0, 2).is_ok() {
                RootInspection::Single
            } else {
                RootInspection::Invalid("schema")
            });
        }
        if tag != 2 {
            return Ok(RootInspection::Invalid("schema"));
        }
        let record = match fields(&inner.0, 3) {
            Ok(record) => record,
            Err(_) => return Ok(RootInspection::Invalid("schema")),
        };
        let (manifest_bytes, signature) = match (data(&record[1]), data(&record[2])) {
            (Ok(manifest_bytes), Ok(signature)) => (manifest_bytes, signature),
            _ => return Ok(RootInspection::Invalid("schema")),
        };
        match parsed_manifest(
            roster,
            roster_digest,
            recipient.id,
            root.hash,
            manifest_bytes,
            signature,
        ) {
            Ok(parsed) => Ok(RootInspection::Manifest(signed_manifest(
                root.hash,
                recipient.id,
                parsed,
            ))),
            Err(error) => Ok(RootInspection::Invalid(rejection_reason(&error))),
        }
    }

    /// Authenticate only a fully assembled transfer for the certified recipient.
    pub fn open(
        roster: &Roster,
        identity: &CommIdentity,
        root: &Object,
        objects: &std::collections::BTreeMap<Id32, Object>,
    ) -> ClientResult<AuthenticatedTransfer> {
        let (recipient, roster_digest, ctx) = message_context(roster, identity)?;
        verify_object(root, &root.hash)?;
        let raw = Zeroizing::new(crate::open_record(&ctx, identity, &root.wire)?);
        let inner = decode_temporary(&raw, 65536)?;
        let Value::Array(record) = &inner.0 else {
            return Err(WireError::Schema.into());
        };
        let tag = integer(record.first().ok_or(WireError::Schema)?)?;
        for (hash, object) in objects {
            verify_object(object, hash)?;
        }
        let mut required_hashes = vec![root.hash];
        let message = match tag {
            1 => {
                let record = fields(&inner.0, 2)?;
                crate::authenticate(roster, data(&record[1])?)?
            }
            2 => {
                let record = fields(&inner.0, 3)?;
                let parsed = parsed_manifest(
                    roster,
                    roster_digest,
                    recipient.id,
                    root.hash,
                    data(&record[1])?,
                    data(&record[2])?,
                )?;
                let mut missing = Vec::new();
                for (hash, wire_len, _) in &parsed.entries {
                    if let Some(object) = objects.get(hash) {
                        verify_object(object, hash)?;
                        if object.wire.len() != *wire_len {
                            return Err(WireError::Bounds.into());
                        }
                    } else {
                        missing.push(*hash);
                    }
                }
                if !missing.is_empty() {
                    return Err(ClientError::MissingObjects(missing));
                }
                let mut package = Zeroizing::new(Vec::with_capacity(parsed.total));
                for (index, (hash, _, segment_len)) in parsed.entries.iter().enumerate() {
                    let object = objects.get(hash).ok_or(WireError::Schema)?;
                    let raw = Zeroizing::new(crate::open_record(&ctx, identity, &object.wire)?);
                    let chunk = decode_temporary(&raw, 65536)?;
                    package.extend_from_slice(chunk_segment(
                        &chunk.0,
                        &parsed.transfer,
                        index,
                        *segment_len,
                    )?);
                    required_hashes.push(*hash);
                }
                if package.len() != parsed.total
                    || <Id32>::from(Sha256::digest(&*package)) != parsed.package_hash
                {
                    return Err(WireError::Schema.into());
                }
                let message = crate::authenticate(roster, &package)?;
                if message.body().key != parsed.key || message.digest() != &parsed.digest {
                    return Err(ClientError::Identity);
                }
                message
            }
            _ => return Err(WireError::Schema.into()),
        };
        let source = CompleteSource {
            required_hashes,
            key: message.body().key.clone(),
            digest: *message.digest(),
            recipient: recipient.id,
        };
        Ok(AuthenticatedTransfer { message, source })
    }
}

#[cfg(test)]
mod assembly_tests {
    use super::*;
    #[test]
    fn transfer_complete_current_root_reference() {
        let root = [8; 32];
        let entry = Value::Array(vec![bytes(&root), uint(1024), uint(1)]);
        assert!(manifest_entries(&[entry], root, 1).is_err());
    }
}

#[cfg(test)]
mod guard_regressions {
    use super::*;

    fn entry(hash: u8, wire: usize, segment: usize) -> Value {
        Value::Array(vec![bytes(&[hash; 32]), uint(wire), uint(segment)])
    }

    #[test]
    fn transfer_complete_guard_duplicate() {
        let entries = [entry(1, 62464, SEGMENT_LEN), entry(1, 62464, 1)];
        assert!(manifest_entries(&entries, [9; 32], SEGMENT_LEN + 1).is_err());
    }

    #[test]
    fn transfer_complete_guard_segmentation() {
        let entries = [entry(1, 62464, SEGMENT_LEN - 1), entry(2, 1024, 1)];
        assert!(manifest_entries(&entries, [9; 32], SEGMENT_LEN).is_err());
    }

    #[test]
    fn transfer_complete_guard_final_segment_bound() {
        let entries = [entry(1, 62464, SEGMENT_LEN), entry(2, 1024, 0)];
        assert!(manifest_entries(&entries, [9; 32], SEGMENT_LEN).is_err());
    }

    #[test]
    fn transfer_complete_guard_wire_bound() {
        assert!(manifest_entries(&[entry(1, 66560, 1)], [9; 32], 1).is_err());
    }

    #[test]
    fn transfer_complete_guard_wire_alignment() {
        assert!(manifest_entries(&[entry(1, 1025, 1)], [9; 32], 1).is_err());
    }

    #[test]
    fn transfer_complete_guard_total() {
        assert!(manifest_entries(&[entry(1, 1024, 1)], [9; 32], 2).is_err());
    }

    #[test]
    fn transfer_complete_guard_total_bound() {
        let mut entries: Vec<_> = (0..273)
            .map(|n| {
                let mut hash = [0; 32];
                hash[..8].copy_from_slice(&(n as u64).to_be_bytes());
                Value::Array(vec![bytes(&hash), uint(62464), uint(SEGMENT_LEN)])
            })
            .collect();
        entries.push(entry(8, 6144, MAX_PACKAGE + 1 - 273 * SEGMENT_LEN));
        assert!(manifest_entries(&entries, [9; 32], MAX_PACKAGE + 1).is_err());
    }
    #[test]
    fn transfer_complete_guard_empty_entries() {
        assert!(transfer_limits(0, 1).is_err());
    }
    #[test]
    fn transfer_complete_guard_chunk_bound() {
        assert!(transfer_limits(275, 1).is_err());
    }
    #[test]
    fn transfer_complete_guard_zero_total() {
        assert!(transfer_limits(1, 0).is_err());
    }
    #[test]
    fn transfer_complete_guard_manifest_schema() {
        assert!(fields(&Value::Array(vec![uint(1); 10]), 11).is_err());
    }
    #[test]
    fn transfer_complete_guard_segment() {
        let transfer = [1; 32];
        let chunk = Value::Array(vec![uint(3), bytes(&transfer), uint(0), bytes(&[8])]);
        assert!(chunk_segment(&chunk, &transfer, 0, 2).is_err());
    }
    #[test]
    fn transfer_complete_guard_chunk_tag() {
        let transfer = [1; 32];
        let chunk = Value::Array(vec![uint(2), bytes(&transfer), uint(0), bytes(&[8])]);
        assert!(chunk_segment(&chunk, &transfer, 0, 1).is_err());
    }
}
#[cfg(test)]
mod outbox_consumer_tests {
    use super::*;
    use crate::{outbox_intent_digest, ClientStore};
    use std::sync::atomic::{AtomicU64, Ordering};
    use types::{MessageBody, Payload};

    fn identity(id: u16) -> CommIdentity {
        let mut seed = [0; 66];
        seed[..2].copy_from_slice(&id.to_be_bytes());
        seed[2..34].fill(id as u8);
        seed[34..].fill(id as u8 + 10);
        CommIdentity::from_serialized(&seed).unwrap()
    }
    fn fixture(
        size: usize,
    ) -> (
        Roster,
        CommIdentity,
        MessageBody,
        PreparedOutbox,
        std::path::PathBuf,
        ClientStore,
    ) {
        let identity = identity(1);
        let roster = Roster {
            vault: [70; 32],
            members: (1..=3).map(|id| self::identity(id).public()).collect(),
        };
        let body = MessageBody {
            key: LogicalKey {
                vault: roster.vault,
                roster: types::roster_digest(&roster).unwrap(),
                sender: 1,
                message: [91; 32],
            },
            audience: vec![1, 2, 3],
            session: None,
            prerequisites: vec![],
            payload: Payload::Test(vec![19; size]),
        };
        let prepared = prepare_outbox(&identity, &roster, &body).unwrap();
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let parent = std::path::PathBuf::from("/private/tmp/relay-6.2-evidence").join(format!(
            "consumer-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&parent).unwrap();
        let root = parent.join("client");
        let store = ClientStore::open(&root, &roster, 1).unwrap();
        (roster, identity, body, prepared, root, store)
    }
    fn refuses(size: usize, corrupt: impl FnOnce(&mut PreparedOutbox)) {
        let (roster, identity, body, mut prepared, root, mut store) = fixture(size);
        corrupt(&mut prepared);
        let result = store.commit_outbox(&roster, &identity, &[121; 32], &prepared);
        assert!(result.is_err(), "corrupted consumer must refuse");
        assert!(store.recover_logical(0, 100).unwrap().is_empty());
        assert!(store
            .lookup_outbox_request(&[121; 32], &outbox_intent_digest(&body).unwrap())
            .unwrap()
            .is_none());
        assert!(store.recover_uploads(0, 100).unwrap().is_empty());
        let sql = rusqlite::Connection::open(root.join("client.sqlite3")).unwrap();
        for table in [
            "ciphertext_objects",
            "logical_records",
            "outgoing_recipients",
            "required_objects",
            "caller_requests",
            "upload_work",
        ] {
            assert_eq!(
                sql.query_row::<i64, _, _>(&format!("SELECT count(*) FROM {table}"), [], |r| r
                    .get(0))
                    .unwrap(),
                0
            );
        }
    }
    #[test]
    fn outbox_atomic_missing_author() {
        refuses(10, |p| {
            p.recipients.remove(0);
        });
    }
    #[test]
    fn outbox_atomic_missing_peer() {
        refuses(10, |p| {
            p.recipients.remove(1);
        });
    }
    #[test]
    fn outbox_atomic_missing_author_chunk() {
        refuses(80000, |p| {
            p.recipients[0].objects.remove(0);
        });
    }
    #[test]
    fn outbox_atomic_missing_peer_chunk() {
        refuses(80000, |p| {
            p.recipients[1].objects.remove(0);
        });
    }
    #[test]
    fn outbox_atomic_empty_set() {
        refuses(10, |p| p.recipients[1].objects.clear());
    }
    #[test]
    fn outbox_atomic_root_last() {
        refuses(80000, |p| p.recipients[1].objects.swap(0, 2));
    }
    #[test]
    fn outbox_atomic_root_mismatch() {
        refuses(10, |p| p.recipients[1].root_hash = [0; 32]);
    }
    #[test]
    fn outbox_atomic_transfer_shape() {
        refuses(10, |p| p.recipients[1].transfer = Some([1; 32]));
    }
    #[test]
    fn outbox_atomic_duplicate_recipient() {
        refuses(10, |p| p.recipients[1].recipient = 1);
    }
    #[test]
    fn outbox_atomic_corrupt_hash() {
        refuses(10, |p| p.recipients[1].objects[0].wire[100] ^= 1);
    }
    #[test]
    fn outbox_atomic_corrupt_domain() {
        refuses(10, |p| {
            let r = &mut p.recipients[1];
            r.objects[0].wire[..8].copy_from_slice(envelope::CONFIG_MAGIC);
            r.objects[0].hash = Sha256::digest(&r.objects[0].wire).into();
            r.root_hash = r.objects[0].hash;
        });
    }
    #[test]
    fn outbox_atomic_corrupt_version() {
        refuses(10, |p| {
            let r = &mut p.recipients[1];
            r.objects[0].wire[8] = 2;
            r.objects[0].hash = Sha256::digest(&r.objects[0].wire).into();
            r.root_hash = r.objects[0].hash;
        });
    }
    #[test]
    fn outbox_atomic_corrupt_wire_bound() {
        refuses(10, |p| {
            let r = &mut p.recipients[1];
            r.objects[0].wire.resize(66560, 0);
            r.objects[0].hash = Sha256::digest(&r.objects[0].wire).into();
            r.root_hash = r.objects[0].hash;
        });
    }
    #[test]
    fn outbox_atomic_private_key_binding() {
        refuses(10, |p| p.key.message = [0; 32]);
    }
    #[test]
    fn outbox_atomic_private_digest_binding() {
        refuses(10, |p| p.digest = [0; 32]);
    }
    #[test]
    fn outbox_atomic_peer_reuse() {
        refuses(10, |p| {
            p.recipients[1].objects = p.recipients[0].objects.clone();
            p.recipients[1].root_hash = p.recipients[0].root_hash;
        });
    }
    #[test]
    fn outbox_atomic_different_valid_author_source() {
        let (roster, identity, mut body, mut first, root, mut store) = fixture(80000);
        body.key.message = [122; 32];
        let mut second = prepare_outbox(&identity, &roster, &body).unwrap();
        std::mem::swap(&mut first.recipients[0], &mut second.recipients[0]);
        assert_eq!(
            store.commit_outbox(&roster, &identity, &[123; 32], &first),
            Err(ClientError::Identity)
        );
        assert!(store.recover_logical(0, 100).unwrap().is_empty());
        let sql = rusqlite::Connection::open(root.join("client.sqlite3")).unwrap();
        assert_eq!(
            sql.query_row::<i64, _, _>("SELECT count(*) FROM ciphertext_objects", [], |r| r.get(0))
                .unwrap(),
            0
        );
    }

    #[test]
    fn outbox_atomic_author_extra_object() {
        refuses(80000, |p| {
            let key = p.key.clone();
            for recipient in &mut p.recipients {
                let ctx = SealContext {
                    vault: key.vault,
                    roster: key.roster,
                    recipient: identity(recipient.recipient).public(),
                    domain: SealDomain::Message,
                };
                let record = canonical::encode(&Value::Array(vec![
                    uint(3),
                    bytes(recipient.transfer.as_ref().unwrap()),
                    uint(999),
                    bytes(&[42]),
                ]))
                .unwrap();
                let extra = seal_record(&ctx, &record).unwrap();
                recipient.objects.insert(recipient.objects.len() - 1, extra);
            }
        });
    }

    #[test]
    fn outbox_atomic_duplicate_required_object() {
        refuses(150000, |p| {
            p.recipients[1].objects[1] = p.recipients[1].objects[0].clone();
        });
    }
    #[test]
    fn outbox_atomic_chunk_count_bound() {
        refuses(80000, |p| {
            let key = p.key.clone();
            let recipient = &mut p.recipients[1];
            let ctx = SealContext {
                vault: key.vault,
                roster: key.roster,
                recipient: identity(recipient.recipient).public(),
                domain: SealDomain::Message,
            };
            for index in 0..273 {
                let record = canonical::encode(&Value::Array(vec![
                    uint(3),
                    bytes(recipient.transfer.as_ref().unwrap()),
                    uint(index + 1000),
                    bytes(&[42]),
                ]))
                .unwrap();
                let extra = seal_record(&ctx, &record).unwrap();
                recipient.objects.insert(recipient.objects.len() - 1, extra);
            }
        });
    }
    #[test]
    fn outbox_atomic_private_vault_binding() {
        refuses(10, |p| p.key.vault = [0; 32]);
    }
    #[test]
    fn outbox_atomic_private_roster_binding() {
        refuses(10, |p| p.key.roster = [0; 32]);
    }
    #[test]
    fn outbox_atomic_private_sender_binding() {
        refuses(10, |p| p.key.sender = 2);
    }
}
