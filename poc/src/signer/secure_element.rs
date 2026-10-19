//! At-rest key hierarchy (ws1-signer §5).
//!
//! ```text
//! KEK  (SecureElement: Enclave/StrongBox/TPM, non-exportable)
//!   │ unwraps
//! DEK  (random, per sealed share)
//!   │ AEAD-decrypts
//! share bytes
//! ```
//!
//! The share on disk is ONLY ever ciphertext: a random DEK seals the share with
//! XChaCha20-Poly1305, and the DEK itself is wrapped by a KEK that lives behind the
//! [`SecureElement`] trait. The software fallback here wraps the DEK with its own
//! XChaCha20-Poly1305 key held in memory; Secure Enclave (iOS/macOS) and Android
//! StrongBox implement the SAME trait later, moving the KEK into non-exportable
//! hardware with biometric release. Nothing above the trait changes when they do.

use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use rand_core::{OsRng, RngCore};
use zeroize::{Zeroize, Zeroizing};

/// A DEK wrapped by the secure element's KEK. Opaque bytes; only a [`SecureElement`]
/// that holds the matching KEK can unwrap it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedDek(pub Vec<u8>);

/// Platform secure element: holds a non-exportable KEK and wraps/unwraps data keys.
///
/// Real implementations (Secure Enclave, StrongBox, TPM) gate `unwrap_dek` behind a
/// biometric/passphrase unlock; the trait is identical so the share store is swappable
/// behind it (ws1-signer §4 "Hardware path"). A KEK never leaves the element — only
/// wrapped DEKs cross this boundary.
pub trait SecureElement {
    /// Wrap a freshly generated 32-byte DEK under the element's KEK.
    fn wrap_dek(&self, dek: &[u8; 32]) -> Result<WrappedDek, String>;
    /// Release the DEK after unlock. The caller must zeroize the result.
    fn unwrap_dek(&self, wrapped: &WrappedDek) -> Result<Zeroizing<[u8; 32]>, String>;
}

/// Software fallback KEK (desktop without a TPM, ws1-signer §4 reduced-guarantee row).
/// The KEK sits in process memory; a real element keeps it non-exportable. The wrap
/// format is XChaCha20-Poly1305(KEK) over the DEK, so the on-disk DEK is ciphertext.
pub struct SoftwareSecureElement {
    kek: Zeroizing<[u8; 32]>,
}

impl SoftwareSecureElement {
    /// A random KEK. In production this handle is the element itself, not raw bytes.
    pub fn generate() -> Self {
        let mut kek = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *kek);
        Self { kek }
    }

    /// Reconstruct from a persisted KEK (software fallback only; real elements never
    /// expose this). Used so a restarted process can unwrap DEKs it sealed before.
    pub fn from_kek(kek: [u8; 32]) -> Self {
        Self {
            kek: Zeroizing::new(kek),
        }
    }

    fn cipher(&self) -> XChaCha20Poly1305 {
        XChaCha20Poly1305::new_from_slice(&*self.kek).expect("32-byte KEK")
    }
}

const WRAP_AAD: &[u8] = b"Loki_signer_dek_wrap_v1";

impl SecureElement for SoftwareSecureElement {
    fn wrap_dek(&self, dek: &[u8; 32]) -> Result<WrappedDek, String> {
        let mut nonce = XNonce::default();
        OsRng.fill_bytes(nonce.as_mut_slice());
        let ct = self
            .cipher()
            .encrypt(
                &nonce,
                Payload {
                    msg: dek,
                    aad: WRAP_AAD,
                },
            )
            .map_err(|_| "DEK wrap failed".to_string())?;
        let mut out = Vec::with_capacity(24 + ct.len());
        out.extend_from_slice(nonce.as_slice());
        out.extend_from_slice(&ct);
        Ok(WrappedDek(out))
    }

    fn unwrap_dek(&self, wrapped: &WrappedDek) -> Result<Zeroizing<[u8; 32]>, String> {
        if wrapped.0.len() < 24 {
            return Err("truncated wrapped DEK".into());
        }
        let (nonce, ct) = wrapped.0.split_at(24);
        let mut plain = self
            .cipher()
            .decrypt(
                XNonce::from_slice(nonce),
                Payload { msg: ct, aad: WRAP_AAD },
            )
            .map_err(|_| "DEK unwrap failed (wrong KEK or tampered)".to_string())?;
        let dek: [u8; 32] = plain
            .as_slice()
            .try_into()
            .map_err(|_| "unwrapped DEK is not 32 bytes")?;
        plain.zeroize();
        Ok(Zeroizing::new(dek))
    }
}

const SHARE_MAGIC: &[u8; 8] = b"LOKISHR1";
const SHARE_AAD: &[u8] = b"Loki_signer_share_seal_v1";

/// A FROST share at rest: ciphertext under a DEK, DEK wrapped by the secure element.
/// The blob written to disk is `magic || backup_epoch || wrapped_dek || nonce || ct`.
/// There is no path that returns the plaintext share except [`SealedShare::open`],
/// which needs the matching [`SecureElement`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedShare {
    /// Rolls forward on restore-from-backup so a rolled-back store is detectable
    /// (ws1-signer §5, ties to nonce epoch in §8).
    pub backup_epoch: u64,
    wrapped_dek: WrappedDek,
    nonce: [u8; 24],
    ciphertext: Vec<u8>,
}

impl SealedShare {
    /// Seal `share` with a fresh random DEK wrapped by `se`. Plaintext never persists.
    pub fn seal(
        se: &impl SecureElement,
        backup_epoch: u64,
        share: &[u8],
    ) -> Result<Self, String> {
        let mut dek = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *dek);
        let wrapped_dek = se.wrap_dek(&dek)?;
        let mut nonce = [0u8; 24];
        OsRng.fill_bytes(&mut nonce);
        let cipher = XChaCha20Poly1305::new_from_slice(&*dek).expect("32-byte DEK");
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: share,
                    aad: SHARE_AAD,
                },
            )
            .map_err(|_| "share seal failed".to_string())?;
        Ok(Self {
            backup_epoch,
            wrapped_dek,
            nonce,
            ciphertext,
        })
    }

    /// Unwrap the DEK via `se`, then AEAD-decrypt the share. Caller zeroizes the result.
    pub fn open(&self, se: &impl SecureElement) -> Result<Zeroizing<Vec<u8>>, String> {
        let dek = se.unwrap_dek(&self.wrapped_dek)?;
        let cipher = XChaCha20Poly1305::new_from_slice(&*dek).expect("32-byte DEK");
        let plain = cipher
            .decrypt(
                XNonce::from_slice(&self.nonce),
                Payload {
                    msg: &self.ciphertext,
                    aad: SHARE_AAD,
                },
            )
            .map_err(|_| "share open failed (wrong element or tampered blob)".to_string())?;
        Ok(Zeroizing::new(plain))
    }

    /// The exact ciphertext blob to write to disk. Never contains the share plaintext.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(SHARE_MAGIC);
        out.extend_from_slice(&self.backup_epoch.to_be_bytes());
        out.extend_from_slice(&(self.wrapped_dek.0.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.wrapped_dek.0);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ciphertext);
        out
    }

    pub fn from_bytes(raw: &[u8]) -> Result<Self, String> {
        if raw.len() < 8 + 8 + 4 || &raw[..8] != SHARE_MAGIC {
            return Err("not a sealed share blob".into());
        }
        let backup_epoch = u64::from_be_bytes(raw[8..16].try_into().unwrap());
        let dek_len = u32::from_be_bytes(raw[16..20].try_into().unwrap()) as usize;
        let mut at = 20;
        if at + dek_len + 24 > raw.len() {
            return Err("truncated sealed share blob".into());
        }
        let wrapped_dek = WrappedDek(raw[at..at + dek_len].to_vec());
        at += dek_len;
        let nonce: [u8; 24] = raw[at..at + 24].try_into().unwrap();
        at += 24;
        Ok(Self {
            backup_epoch,
            wrapped_dek,
            nonce,
            ciphertext: raw[at..].to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disk_blob_is_ciphertext_and_roundtrips() {
        let se = SoftwareSecureElement::generate();
        let share = b"a FROST signing share worth forging";
        let sealed = SealedShare::seal(&se, 1, share).unwrap();
        let blob = sealed.to_bytes();
        // The plaintext share never appears in the on-disk bytes.
        assert!(!blob.windows(share.len()).any(|w| w == share));
        let reopened = SealedShare::from_bytes(&blob).unwrap();
        assert_eq!(reopened, sealed);
        assert_eq!(&**reopened.open(&se).unwrap(), share);
        assert_eq!(reopened.backup_epoch, 1);
    }

    #[test]
    fn wrong_element_cannot_open() {
        let se = SoftwareSecureElement::generate();
        let other = SoftwareSecureElement::generate();
        let sealed = SealedShare::seal(&se, 0, b"share").unwrap();
        assert!(sealed.open(&other).is_err());
    }

    #[test]
    fn tampered_ciphertext_is_rejected() {
        let se = SoftwareSecureElement::generate();
        let sealed = SealedShare::seal(&se, 0, b"share").unwrap();
        let mut blob = sealed.to_bytes();
        *blob.last_mut().unwrap() ^= 0xff;
        let tampered = SealedShare::from_bytes(&blob).unwrap();
        assert!(tampered.open(&se).is_err());
    }
}
