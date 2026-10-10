use crate::{ClientError, ClientResult, CommIdentity};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use loki_relay_protocol::{
    canonical::{self, Value},
    types::{self, Id32, MemberPublic, MessageBody, Roster},
    WireError,
};
use sha2::{Digest, Sha256};

const MAX_PACKAGE: usize = 16 * 1024 * 1024 + 128;
const SIGNATURE_DOMAIN: &[u8] = b"Loki_Relay_Message_v1\0";

/// A canonical body authenticated against its certified roster sender.
/// Only authentication can construct this binding; accessors cannot alter it.
///
/// ```compile_fail
/// use loki_relay_client::AuthenticatedMessage;
/// fn overwrite(message: &mut AuthenticatedMessage) {
///     message.body().key.message = [0; 32];
/// }
/// ```
///
/// ```compile_fail
/// use loki_relay_client::AuthenticatedMessage;
/// use loki_relay_protocol::types::MessageBody;
/// fn forge(body: MessageBody) -> AuthenticatedMessage {
///     AuthenticatedMessage { body, canonical_body: vec![], digest: [0; 32] }
/// }
/// ```
pub struct AuthenticatedMessage {
    body: MessageBody,
    canonical_body: Vec<u8>,
    digest: Id32,
}

impl AuthenticatedMessage {
    pub fn body(&self) -> &MessageBody {
        &self.body
    }

    pub fn canonical_body(&self) -> &[u8] {
        &self.canonical_body
    }

    pub fn digest(&self) -> &Id32 {
        &self.digest
    }
}

fn roster_sender<'a>(roster: &'a Roster, body: &MessageBody) -> ClientResult<&'a MemberPublic> {
    let digest = types::roster_digest(roster)?;
    if body.key.vault != roster.vault || body.key.roster != digest {
        return Err(ClientError::Identity);
    }
    if !body
        .audience
        .iter()
        .copied()
        .eq(roster.members.iter().map(|m| m.id))
    {
        return Err(WireError::Schema.into());
    }
    roster
        .members
        .iter()
        .find(|member| member.id == body.key.sender)
        .ok_or(ClientError::Identity)
}

fn signature_input(body: &[u8]) -> ClientResult<Vec<u8>> {
    let length = u32::try_from(body.len()).map_err(|_| WireError::Bounds)?;
    let mut input = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 4 + body.len());
    input.extend_from_slice(SIGNATURE_DOMAIN);
    input.extend_from_slice(&length.to_be_bytes());
    input.extend_from_slice(body);
    Ok(input)
}

/// Sign one common package after validating the body and certified sender context.
/// The roster must come from the caller's certified identity setup.
pub fn sign_message(
    identity: &CommIdentity,
    roster: &Roster,
    body: &MessageBody,
) -> ClientResult<Vec<u8>> {
    let sender = roster_sender(roster, body)?;
    if sender != &identity.public() {
        return Err(ClientError::Identity);
    }
    let encoded = types::encode_message(body)?;
    let signature = identity.signing.sign(&signature_input(&encoded)?);
    Ok(canonical::encode(&Value::Array(vec![
        Value::Bytes(encoded),
        Value::Bytes(signature.to_bytes().to_vec()),
    ]))?)
}

/// Verify a bounded canonical package against the certified roster sender.
/// Original Received type/session association is checked when the original is known.
pub fn authenticate(roster: &Roster, package: &[u8]) -> ClientResult<AuthenticatedMessage> {
    let value = canonical::decode(package, MAX_PACKAGE)?;
    let Value::Array(fields) = value else {
        return Err(WireError::Schema.into());
    };
    let [Value::Bytes(encoded), Value::Bytes(signature)] = fields.as_slice() else {
        return Err(WireError::Schema.into());
    };
    if signature.len() != 64 {
        return Err(WireError::Schema.into());
    }
    let body = types::decode_message(encoded)?;
    let sender = roster_sender(roster, &body)?;
    let key = VerifyingKey::from_bytes(&sender.signing)?;
    key.verify_strict(
        &signature_input(encoded)?,
        &Signature::from_slice(signature)?,
    )?;
    Ok(AuthenticatedMessage {
        body,
        digest: Sha256::digest(encoded).into(),
        canonical_body: encoded.clone(),
    })
}
