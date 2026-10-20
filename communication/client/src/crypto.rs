use crate::{ClientError, ClientResult, CommIdentity};
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, setup_receiver, setup_sender,
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
};
use loki_relay_protocol::{
    canonical::{self, Value},
    envelope::{self, HEADER_LEN, LENGTH_PREFIX_LEN, MAX_WIRE_LEN, TAG_LEN, VERSION},
    types::{Id32, MemberPublic, Object},
    WireError,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

type Kem = X25519HkdfSha256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SealDomain {
    Message,
    Config,
    Setup,
}

impl SealDomain {
    pub const fn magic(self) -> &'static [u8; 8] {
        match self {
            Self::Message => envelope::MESSAGE_MAGIC,
            Self::Config => envelope::CONFIG_MAGIC,
            Self::Setup => envelope::SETUP_MAGIC,
        }
    }

    pub const fn aad_domain(self) -> &'static [u8] {
        match self {
            Self::Message => b"Loki_Relay_Envelope_v1\0",
            Self::Config => b"Loki_Relay_Config_Envelope_v1\0",
            Self::Setup => b"Loki_Setup_Envelope_v1\0",
        }
    }

    fn info_domain(self) -> &'static [u8] {
        match self {
            Self::Message => b"Loki_Relay_Seal_v1",
            Self::Config => b"Loki_Relay_Config_Seal_v1",
            Self::Setup => b"Loki_Setup_Seal_v1",
        }
    }
}

#[derive(Clone, Debug)]
pub struct SealContext {
    pub vault: Id32,
    pub roster: Id32,
    pub recipient: MemberPublic,
    pub domain: SealDomain,
}

fn encode_seal_info(ctx: &SealContext) -> ClientResult<Vec<u8>> {
    if !(1..=loki_relay_protocol::types::MAX_MEMBERS).contains(&ctx.recipient.id) {
        return Err(ClientError::Identity);
    }
    Ok(canonical::encode(&Value::Array(vec![
        Value::Bytes(ctx.domain.info_domain().to_vec()),
        Value::Integer(1.into()),
        Value::Bytes(ctx.vault.to_vec()),
        Value::Bytes(ctx.roster.to_vec()),
        Value::Integer(ctx.recipient.id.into()),
        Value::Bytes(ctx.recipient.encryption.to_vec()),
    ]))?)
}

fn aad(domain: SealDomain, header: &[u8]) -> Vec<u8> {
    let mut aad = domain.aad_domain().to_vec();
    aad.extend_from_slice(header);
    aad
}

fn length_prefix_and_zero_pad(
    record: &[u8],
    header_len: usize,
    tag_len: usize,
) -> ClientResult<Zeroizing<Vec<u8>>> {
    if header_len != HEADER_LEN || tag_len != TAG_LEN {
        return Err(WireError::Bounds.into());
    }
    let wire_len = envelope::padded_wire_length(record.len())?;
    let mut padded = Zeroizing::new(Vec::with_capacity(wire_len - header_len - tag_len));
    padded.extend_from_slice(&(record.len() as u32).to_be_bytes());
    padded.extend_from_slice(record);
    padded.resize(wire_len - header_len - tag_len, 0);
    Ok(padded)
}

pub fn seal_record(ctx: &SealContext, record: &[u8]) -> ClientResult<Object> {
    envelope::padded_wire_length(record.len())?;
    let decode = if ctx.domain == SealDomain::Setup {
        canonical::decode
    } else {
        canonical::decode_without_text
    };
    crate::setup::PrivateValue(decode(
        record,
        MAX_WIRE_LEN - HEADER_LEN - TAG_LEN - LENGTH_PREFIX_LEN,
    )?);
    let pk = <Kem as KemTrait>::PublicKey::from_bytes(&ctx.recipient.encryption)?;
    let info = encode_seal_info(ctx)?;
    let (enc, mut sender) =
        setup_sender::<ChaCha20Poly1305, HkdfSha256, Kem>(&OpModeS::Base, &pk, &info)?;
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(ctx.domain.magic());
    header.push(VERSION);
    header.extend_from_slice(&enc.to_bytes());
    let aad = aad(ctx.domain, &header);
    let padded = length_prefix_and_zero_pad(record, header.len(), TAG_LEN)?;
    let ciphertext = sender.seal(&padded, &aad)?;
    drop(sender);
    header.extend_from_slice(&ciphertext);
    Ok(Object {
        hash: Sha256::digest(&header).into(),
        wire: header,
    })
}

pub fn open_record(
    ctx: &SealContext,
    identity: &CommIdentity,
    wire: &[u8],
) -> ClientResult<Vec<u8>> {
    envelope::validate_wire(wire)?;
    if &wire[..8] != ctx.domain.magic() {
        return Err(WireError::Schema.into());
    }
    if ctx.recipient != identity.public() {
        return Err(ClientError::Identity);
    }
    let info = encode_seal_info(ctx)?;
    let enc = <Kem as KemTrait>::EncappedKey::from_bytes(&wire[9..HEADER_LEN])?;
    let mut receiver = setup_receiver::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &OpModeR::Base,
        &identity.encryption,
        &enc,
        &info,
    )?;
    let padded =
        Zeroizing::new(receiver.open(&wire[HEADER_LEN..], &aad(ctx.domain, &wire[..HEADER_LEN]))?);
    drop(receiver);
    let prefix = padded.get(..LENGTH_PREFIX_LEN).ok_or(WireError::Bounds)?;
    let length = u32::from_be_bytes(prefix.try_into().map_err(|_| WireError::Bounds)?) as usize;
    let end = LENGTH_PREFIX_LEN
        .checked_add(length)
        .ok_or(WireError::Bounds)?;
    if length == 0 || end > padded.len() {
        return Err(WireError::Bounds.into());
    }
    if padded[end..].iter().any(|byte| *byte != 0) {
        return Err(WireError::Canonical.into());
    }
    let record = &padded[LENGTH_PREFIX_LEN..end];
    let decode = if ctx.domain == SealDomain::Setup {
        canonical::decode
    } else {
        canonical::decode_without_text
    };
    crate::setup::PrivateValue(decode(
        record,
        MAX_WIRE_LEN - HEADER_LEN - TAG_LEN - LENGTH_PREFIX_LEN,
    )?);
    Ok(record.to_vec())
}
