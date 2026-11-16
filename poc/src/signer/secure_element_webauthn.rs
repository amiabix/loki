//! WebAuthn PRF backend of [`SecureElement`] (in-browser signer, ws1-signer §4
//! "Hardware path" — the no-install tier).
//!
//! Like the Apple Enclave and the software fallback, this backend does NOT hold the FROST
//! share: it only sources the KEK that wraps the per-share DEK. Here the KEK is derived from
//! a **WebAuthn PRF secret** — a 32-byte secret bound to a passkey that the browser releases
//! only after a user gesture. The same passkey (and therefore the same PRF secret, and the
//! same KEK) can be fronted by:
//!   1. a platform authenticator (Touch/Face ID, Windows Hello), or
//!   2. a roaming/security key or cross-device phone passkey (hybrid/caBLE).
//! Both tiers land in this one impl; only the WebAuthn ceremony differs, and that is JS in the
//! browser (`poc/web/webauthn_prf.js`). The Rust side takes the already-released PRF secret.
//!
//! Machines/browsers with no WebAuthn PRF use tier 3, the existing
//! [`super::secure_element::SoftwareSecureElement::persistent`] (Argon2id-wrapped KEK +
//! recovery words) — unchanged, just selected instead of this.
//!
//! The KEK is HKDF-SHA256(PRF secret) with a fixed domain-separation `info`, then the DEK
//! wrap/unwrap is the proven [`SoftwareSecureElement`] format (XChaCha20-Poly1305). Nothing in
//! [`super::secure_element::SealedShare`] changes; only the KEK source does.

use super::secure_element::{SecureElement, SoftwareSecureElement, WrappedDek};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Domain separation for the WebAuthn-PRF-derived KEK. Distinct from any other use of the
/// same passkey's PRF so the KEK can't collide with a differently-scoped secret.
const KEK_INFO: &[u8] = b"Loki_signer_webauthn_prf_kek_v1";

/// A KEK sourced from a WebAuthn PRF secret. Wraps/unwraps DEKs in the identical format as
/// [`SoftwareSecureElement`]; the share seal path is untouched.
pub struct WebAuthnSecureElement {
    inner: SoftwareSecureElement,
}

impl WebAuthnSecureElement {
    /// Derive the KEK from a 32-byte WebAuthn PRF secret (the `prf.results.first` the browser
    /// releases after the Touch/Face ID / security-key / phone gesture). The same passkey +
    /// same salt always yields the same secret, so a reloaded signer re-derives the same KEK
    /// and opens its sealed share.
    pub fn from_prf_secret(prf_secret: &[u8; 32]) -> Self {
        // PRF output is already uniform HMAC material, so extract with no salt; expand pins the
        // domain. A 32-byte OKM is always a valid HKDF-SHA256 length.
        let hk = Hkdf::<Sha256>::new(None, prf_secret);
        let mut kek = Zeroizing::new([0u8; 32]);
        hk.expand(KEK_INFO, &mut *kek)
            .expect("32 bytes is a valid HKDF-SHA256 output length");
        Self {
            inner: SoftwareSecureElement::from_kek(*kek),
        }
    }
}

impl SecureElement for WebAuthnSecureElement {
    fn wrap_dek(&self, dek: &[u8; 32]) -> Result<WrappedDek, String> {
        self.inner.wrap_dek(dek)
    }

    fn unwrap_dek(&self, wrapped: &WrappedDek) -> Result<Zeroizing<[u8; 32]>, String> {
        self.inner.unwrap_dek(wrapped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::secure_element::SealedShare;

    #[test]
    fn prf_secret_seals_and_reopens_byte_identical() {
        let prf = [9u8; 32];
        let share = b"a FROST signing share worth forging";

        let se = WebAuthnSecureElement::from_prf_secret(&prf);
        let sealed = SealedShare::seal(&se, 3, share).unwrap();

        // A signer that re-derives from the SAME PRF secret reopens the share unchanged.
        let se_again = WebAuthnSecureElement::from_prf_secret(&prf);
        let reopened = SealedShare::from_bytes(&sealed.to_bytes()).unwrap();
        assert_eq!(&**reopened.open(&se_again).unwrap(), share);
        assert_eq!(reopened.backup_epoch, 3);
    }

    #[test]
    fn wrong_prf_secret_cannot_open() {
        let se = WebAuthnSecureElement::from_prf_secret(&[1u8; 32]);
        let wrong = WebAuthnSecureElement::from_prf_secret(&[2u8; 32]);
        let sealed = SealedShare::seal(&se, 0, b"share").unwrap();
        assert!(sealed.open(&wrong).is_err());
    }

    #[test]
    fn passphrase_fallback_path_seals_and_opens() {
        let dir = std::env::temp_dir().join(format!(
            "loki-webauthn-fallback-{}-{}",
            std::process::id(),
            rand_core::RngCore::next_u64(&mut rand_core::OsRng)
        ));
        let _ = std::fs::remove_dir_all(&dir);

        // Tier 3: the existing software fallback, reused as-is.
        let se = SoftwareSecureElement::persistent(&dir, "correct horse battery staple").unwrap();
        let sealed = SealedShare::seal(&se, 0, b"share").unwrap();

        // Reopen after a "restart": reconstruct the KEK from the same passphrase.
        let se_again =
            SoftwareSecureElement::persistent(&dir, "correct horse battery staple").unwrap();
        assert_eq!(&**sealed.open(&se_again).unwrap(), b"share");
        // Wrong passphrase can't even reconstruct the element.
        assert!(SoftwareSecureElement::persistent(&dir, "wrong").is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
