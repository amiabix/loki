//! KEK for the in-browser signer, derived from a WebAuthn PRF secret: a 32-byte secret bound
//! to a passkey that the browser releases only after a user gesture. The KEK is
//! HKDF-SHA256(PRF secret) with a fixed domain-separation `info`; it is used with
//! [`super::secure_element::SoftwareSecureElement::from_kek`], so the sealed format does not
//! change. The passkey ceremony itself is JS (`core/web/webauthn_prf.js`).

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

const KEK_INFO: &[u8] = b"Loki_signer_webauthn_prf_kek_v1";

pub fn prf_kek(prf_secret: &[u8; 32]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, prf_secret);
    let mut kek = Zeroizing::new([0u8; 32]);
    hk.expand(KEK_INFO, &mut *kek)
        .expect("32 bytes is a valid HKDF-SHA256 output length");
    *kek
}

#[cfg(test)]
mod tests {
    use crate::signer::secure_element::{SealedShare, SoftwareSecureElement};

    #[test]
    fn passphrase_fallback_path_seals_and_opens() {
        let dir = std::env::temp_dir().join(format!(
            "loki-webauthn-fallback-{}-{}",
            std::process::id(),
            rand_core::RngCore::next_u64(&mut rand_core::OsRng)
        ));
        let _ = std::fs::remove_dir_all(&dir);

        let se = SoftwareSecureElement::persistent(&dir, "correct horse battery staple").unwrap();
        let sealed = SealedShare::seal(&se, 0, b"share").unwrap();

        let se_again =
            SoftwareSecureElement::persistent(&dir, "correct horse battery staple").unwrap();
        assert_eq!(&**sealed.open(&se_again).unwrap(), b"share");
        assert!(SoftwareSecureElement::persistent(&dir, "wrong").is_err());

        let _ = std::fs::remove_dir_all(&dir);
    }
}
