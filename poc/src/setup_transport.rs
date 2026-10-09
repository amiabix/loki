//! Signed, recipient-only transport for one DKG round-two share.
//! A public identity must be checked against the group's out-of-band roster first.

use blake2b_simd::Params;
use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand_core::{OsRng, RngCore};
use x25519_dalek::{PublicKey, StaticSecret};

const MAGIC: &[u8; 8] = b"LOKIDKG1";
const ROUND1_MAGIC: &[u8; 8] = b"LOKIR1V1";
const CERT_MAGIC: &[u8; 8] = b"LOKICRV1";
const BACKUP_MAGIC: &[u8; 8] = b"LOKIBKV1";
const HEADER: usize = 8 + 32 + 2 + 2 + 24 + 4;
const PUBLIC_HEADER: usize = 8 + 32 + 2 + 4;
const SIGNATURE: usize = 64;

pub struct Identity {
    id: u16,
    signing: SigningKey,
    encryption: StaticSecret,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicIdentity {
    pub id: u16,
    pub signing: [u8; 32],
    pub encryption: [u8; 32],
}

impl Identity {
    pub fn new(id: u16) -> Self {
        Self {
            id,
            signing: SigningKey::generate(&mut OsRng),
            encryption: StaticSecret::random_from_rng(OsRng),
        }
    }

    /// These bytes must only be written through the sealed member store.
    pub fn to_secret_bytes(&self) -> [u8; 66] {
        let mut bytes = [0u8; 66];
        bytes[..2].copy_from_slice(&self.id.to_be_bytes());
        bytes[2..34].copy_from_slice(&self.signing.to_bytes());
        bytes[34..].copy_from_slice(&self.encryption.to_bytes());
        bytes
    }

    pub fn from_secret_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 66 {
            return Err("invalid DKG identity length".into());
        }
        let id = u16::from_be_bytes(bytes[..2].try_into().unwrap());
        if !(1..=3).contains(&id) {
            return Err("invalid DKG member id".into());
        }
        Ok(Self {
            id,
            signing: SigningKey::from_bytes(bytes[2..34].try_into().unwrap()),
            encryption: StaticSecret::from(<[u8; 32]>::try_from(&bytes[34..]).unwrap()),
        })
    }

    pub fn public(&self) -> PublicIdentity {
        PublicIdentity {
            id: self.id,
            signing: self.signing.verifying_key().to_bytes(),
            encryption: PublicKey::from(&self.encryption).to_bytes(),
        }
    }

    pub fn sign_round1(&self, vault: &[u8; 32], payload: &[u8]) -> Result<Vec<u8>, String> {
        self.sign_public(ROUND1_MAGIC, vault, payload)
    }

    pub fn sign_certificate(&self, vault: &[u8; 32], payload: &[u8]) -> Result<Vec<u8>, String> {
        self.sign_public(CERT_MAGIC, vault, payload)
    }

    pub fn sign_backup(&self, vault: &[u8; 32], payload: &[u8]) -> Result<Vec<u8>, String> {
        self.sign_public(BACKUP_MAGIC, vault, payload)
    }

    fn sign_public(
        &self,
        magic: &[u8; 8],
        vault: &[u8; 32],
        payload: &[u8],
    ) -> Result<Vec<u8>, String> {
        if payload.len() > 64 * 1024 {
            return Err("oversized DKG public package".into());
        }
        let mut wire = Vec::with_capacity(PUBLIC_HEADER + payload.len() + SIGNATURE);
        wire.extend_from_slice(magic);
        wire.extend_from_slice(vault);
        wire.extend_from_slice(&self.id.to_be_bytes());
        wire.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        wire.extend_from_slice(payload);
        wire.extend_from_slice(&self.signing.sign(&wire).to_bytes());
        Ok(wire)
    }

    pub fn verify_round1(
        &self,
        sender: &PublicIdentity,
        vault: &[u8; 32],
        wire: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.verify_public(ROUND1_MAGIC, sender, vault, wire)
    }

    pub fn verify_certificate(
        &self,
        sender: &PublicIdentity,
        vault: &[u8; 32],
        wire: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.verify_public(CERT_MAGIC, sender, vault, wire)
    }

    pub fn verify_backup(
        &self,
        sender: &PublicIdentity,
        vault: &[u8; 32],
        wire: &[u8],
    ) -> Result<Vec<u8>, String> {
        self.verify_public(BACKUP_MAGIC, sender, vault, wire)
    }

    fn verify_public(
        &self,
        magic: &[u8; 8],
        sender: &PublicIdentity,
        vault: &[u8; 32],
        wire: &[u8],
    ) -> Result<Vec<u8>, String> {
        if wire.len() < PUBLIC_HEADER + SIGNATURE
            || &wire[..8] != magic
            || &wire[8..40] != vault
            || u16::from_be_bytes(wire[40..42].try_into().unwrap()) != sender.id
        {
            return Err("wrong DKG round-one envelope".into());
        }
        let size = u32::from_be_bytes(wire[42..46].try_into().unwrap()) as usize;
        if size > 64 * 1024 || wire.len() != PUBLIC_HEADER + size + SIGNATURE {
            return Err("invalid DKG round-one length".into());
        }
        let verify = VerifyingKey::from_bytes(&sender.signing).map_err(|_| "invalid sender key")?;
        let signature = ed25519_dalek::Signature::from_bytes(
            wire[PUBLIC_HEADER + size..]
                .try_into()
                .map_err(|_| "invalid DKG signature length")?,
        );
        verify
            .verify_strict(&wire[..PUBLIC_HEADER + size], &signature)
            .map_err(|_| "DKG round-one signature failed")?;
        Ok(wire[PUBLIC_HEADER..PUBLIC_HEADER + size].to_vec())
    }

    pub fn seal_round2(
        &self,
        recipient: &PublicIdentity,
        vault: &[u8; 32],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, String> {
        if recipient.id == self.id || plaintext.len() > 64 * 1024 {
            return Err("invalid DKG recipient or oversized share".into());
        }
        let key = self.box_key(recipient, vault)?;
        let cipher = XChaCha20Poly1305::new(&key.into());
        let mut header = Vec::with_capacity(HEADER);
        header.extend_from_slice(MAGIC);
        header.extend_from_slice(vault);
        header.extend_from_slice(&self.id.to_be_bytes());
        header.extend_from_slice(&recipient.id.to_be_bytes());
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        header.extend_from_slice(&nonce);
        header.extend_from_slice(&((plaintext.len() + 16) as u32).to_be_bytes());
        let nonce = XNonce::from_slice(&nonce);
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: plaintext,
                    aad: &header,
                },
            )
            .map_err(|_| "DKG encryption failed")?;
        header.extend_from_slice(&ciphertext);
        let signature = self.signing.sign(&header);
        header.extend_from_slice(&signature.to_bytes());
        Ok(header)
    }

    pub fn open_round2(
        &self,
        sender: &PublicIdentity,
        vault: &[u8; 32],
        wire: &[u8],
    ) -> Result<Vec<u8>, String> {
        if wire.len() < HEADER + 16 + SIGNATURE || &wire[..8] != MAGIC {
            return Err("invalid DKG envelope".into());
        }
        if &wire[8..40] != vault
            || u16::from_be_bytes(wire[40..42].try_into().unwrap()) != sender.id
            || u16::from_be_bytes(wire[42..44].try_into().unwrap()) != self.id
        {
            return Err("DKG envelope belongs to another vault or member".into());
        }
        let size = u32::from_be_bytes(wire[68..72].try_into().unwrap()) as usize;
        if size > 64 * 1024 + 16 || wire.len() != HEADER + size + SIGNATURE {
            return Err("invalid DKG envelope length".into());
        }
        let verify = VerifyingKey::from_bytes(&sender.signing).map_err(|_| "invalid sender key")?;
        let signature = ed25519_dalek::Signature::from_bytes(
            wire[HEADER + size..]
                .try_into()
                .map_err(|_| "invalid DKG signature length")?,
        );
        verify
            .verify_strict(&wire[..HEADER + size], &signature)
            .map_err(|_| "DKG sender signature failed")?;
        let key = self.box_key(sender, vault)?;
        let nonce = XNonce::from_slice(&wire[44..68]);
        XChaCha20Poly1305::new(&key.into())
            .decrypt(
                nonce,
                Payload {
                    msg: &wire[HEADER..HEADER + size],
                    aad: &wire[..HEADER],
                },
            )
            .map_err(|_| "DKG decryption failed".into())
    }

    fn box_key(&self, peer: &PublicIdentity, vault: &[u8; 32]) -> Result<[u8; 32], String> {
        let shared = self
            .encryption
            .diffie_hellman(&PublicKey::from(peer.encryption));
        if !shared.was_contributory() {
            return Err("invalid DKG encryption public key".into());
        }
        let (low, high) = if self.id < peer.id {
            (self.id, peer.id)
        } else {
            (peer.id, self.id)
        };
        let hash = Params::new()
            .hash_length(32)
            .personal(b"Loki_Dkg_Box_v1")
            .to_state()
            .update(vault)
            .update(&low.to_be_bytes())
            .update(&high.to_be_bytes())
            .update(shared.as_bytes())
            .finalize();
        Ok(hash
            .as_bytes()
            .try_into()
            .expect("BLAKE2b output is 32 bytes"))
    }
}
