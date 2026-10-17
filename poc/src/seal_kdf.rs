//! The one Argon2id derivation behind every passphrase-sealed file.
//!
//! `LOKISEAL\x01` files and `LOKIJRN1` journal generations each carry their own salt,
//! and every one of them derives its key here with `Argon2::default()` (Argon2id,
//! 19 MiB, t=2, p=1). Keeping the call in one place keeps the parameters identical
//! across formats and lets the `kdf-stats` feature count derivations per process.

use argon2::Argon2;
use zeroize::Zeroizing;

#[derive(Debug)]
pub struct KdfError;

/// Derive the 32-byte file key for `secret` over `salt`. Fails only for a salt shorter
/// than Argon2's minimum, which means a corrupt header.
pub(crate) fn derive(secret: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, KdfError> {
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(secret.as_bytes(), salt, &mut *key)
        .map_err(|_| KdfError)?;
    #[cfg(feature = "kdf-stats")]
    stats::DERIVATIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    Ok(key)
}

/// Number of Argon2id derivations this process ran (always 0 without `kdf-stats`).
pub fn derivations() -> u64 {
    #[cfg(feature = "kdf-stats")]
    return stats::DERIVATIONS.load(std::sync::atomic::Ordering::Relaxed);
    #[cfg(not(feature = "kdf-stats"))]
    0
}

/// With `kdf-stats`, print `kdf_derivations=N` to stderr; binaries call this at exit.
pub fn report() {
    #[cfg(feature = "kdf-stats")]
    eprintln!("kdf_derivations={}", derivations());
}

#[cfg(feature = "kdf-stats")]
mod stats {
    pub(super) static DERIVATIONS: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(0);
}
