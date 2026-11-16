//! The one Argon2id derivation behind every passphrase-sealed file.
//!
//! `LOKISEAL\x01` files and `LOKIJRN1` journal generations each carry their own salt,
//! and every one of them derives its key here with `Argon2::default()` (Argon2id,
//! 19 MiB, t=2, p=1). Keeping the call in one place keeps the parameters identical
//! across formats and lets the `kdf-stats` feature count derivations per process.
//!
//! A process that already holds the member's passphrase may enable a session cache:
//! per-file keys derived from exactly that passphrase are kept in memory, so reopening
//! the same sealed file costs no second derivation. Nothing is written anywhere; the
//! formats, parameters and per-file salts are unchanged. Lookups are keyed by a keyed
//! hash of the secret and salt under a per-process random key, so a different
//! secret (a wrong passphrase, recovery words, a card secret) never matches an entry
//! and is never stored. `clear_session_cache` zeroizes every entry.

use argon2::Argon2;
use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;
use zeroize::{Zeroize, Zeroizing};

/// Entries kept at most; the oldest is dropped first.
const CACHE_LIMIT: usize = 1024;

struct Cache {
    hasher: [u8; 32],
    session: Option<[u8; 32]>,
    keys: BTreeMap<[u8; 32], Zeroizing<[u8; 32]>>,
    order: VecDeque<[u8; 32]>,
}

impl Drop for Cache {
    fn drop(&mut self) {
        self.hasher.zeroize();
        self.session.zeroize();
    }
}

static CACHE: Mutex<Option<Cache>> = Mutex::new(None);

fn cache() -> std::sync::MutexGuard<'static, Option<Cache>> {
    CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn identify(hasher: &[u8; 32], secret: &str, salt: Option<&[u8]>) -> [u8; 32] {
    let mut hash = blake3::Hasher::new_keyed(hasher);
    hash.update(b"loki-kdf-v1");
    hash.update(&(secret.len() as u64).to_be_bytes());
    hash.update(secret.as_bytes());
    if let Some(salt) = salt {
        hash.update(&(salt.len() as u64).to_be_bytes());
        hash.update(salt);
    }
    *hash.finalize().as_bytes()
}

#[cfg(any(test, feature = "test-support"))]
thread_local! {
    /// Unit tests run in parallel in one process; only a test that opts in on its
    /// own thread turns the process-wide cache on.
    pub static TEST_OPT_IN: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}
/// Serializes the unit tests that opt in to the cache.
#[cfg(any(test, feature = "test-support"))]
pub static TEST_LOCK: Mutex<()> = Mutex::new(());

/// Remember derivations for `passphrase` (and only it) in this process's memory.
pub fn enable_session_cache(passphrase: &str) {
    #[cfg(any(test, feature = "test-support"))]
    if !TEST_OPT_IN.with(|opt_in| opt_in.get()) {
        return;
    }
    let mut guard = cache();
    if let Some(existing) = guard.as_mut() {
        let session = identify(&existing.hasher, passphrase, None);
        if existing.session != Some(session) {
            existing.keys.clear();
            existing.order.clear();
            existing.session = Some(session);
        }
        return;
    }
    let mut hasher = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut hasher);
    let session = identify(&hasher, passphrase, None);
    *guard = Some(Cache {
        hasher,
        session: Some(session),
        keys: BTreeMap::new(),
        order: VecDeque::new(),
    });
}

/// Forget the session passphrase and zeroize every cached key.
pub fn clear_session_cache() {
    *cache() = None;
}

/// Number of cached keys (for tests and the service's lock check).
pub fn cache_len() -> usize {
    cache().as_ref().map_or(0, |cache| cache.keys.len())
}

#[derive(Debug)]
pub struct KdfError;

/// Derive the 32-byte file key for `secret` over `salt`. Fails only for a salt shorter
/// than Argon2's minimum, which means a corrupt header.
pub fn derive(secret: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, KdfError> {
    let lookup = {
        let guard = cache();
        match guard.as_ref() {
            Some(cache) if cache.session.is_some() => {
                let session = identify(&cache.hasher, secret, None);
                // Constant-time comparison of the keyed hashes.
                let same = session
                    .iter()
                    .zip(cache.session.as_ref().unwrap())
                    .fold(0u8, |acc, (a, b)| acc | (a ^ b))
                    == 0;
                if same {
                    let id = identify(&cache.hasher, secret, Some(salt));
                    if let Some(key) = cache.keys.get(&id) {
                        return Ok(Zeroizing::new(**key));
                    }
                    Some(id)
                } else {
                    None
                }
            }
            _ => None,
        }
    };
    let key = derive_uncached(secret, salt)?;
    if let Some(id) = lookup {
        let mut guard = cache();
        if let Some(cache) = guard.as_mut() {
            if !cache.keys.contains_key(&id) {
                if cache.order.len() >= CACHE_LIMIT {
                    if let Some(oldest) = cache.order.pop_front() {
                        cache.keys.remove(&oldest);
                    }
                }
                cache.order.push_back(id);
                cache.keys.insert(id, Zeroizing::new(*key));
            }
        }
    }
    Ok(key)
}

fn derive_uncached(secret: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>, KdfError> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::MemberDir;

    // The cache is process-wide; these cases run in one test so they never interleave.
    #[test]
    fn session_cache_serves_only_the_session_passphrase() {
        let _serial = TEST_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        TEST_OPT_IN.with(|opt_in| opt_in.set(true));
        clear_session_cache();
        let salt = [7u8; 16];
        let fresh = derive_uncached("session pass", &salt).unwrap();
        enable_session_cache("session pass");
        assert_eq!(*derive("session pass", &salt).unwrap(), *fresh);
        assert_eq!(cache_len(), 1);
        assert_eq!(*derive("session pass", &salt).unwrap(), *fresh);
        assert_eq!(cache_len(), 1, "a second open reuses the derived key");
        // A different secret with the same salt is neither served nor stored.
        let other = derive("wrong pass", &salt).unwrap();
        assert_ne!(*other, *fresh);
        assert_eq!(*other, *derive_uncached("wrong pass", &salt).unwrap());
        let words = "abandon ".repeat(23) + "art";
        derive(&words, &salt).unwrap();
        assert_eq!(cache_len(), 1, "non-session secrets are never cached");
        // Cached keys equal fresh derivations.
        for index in 0..100u8 {
            let salt = [index; 16];
            assert_eq!(
                *derive("session pass", &salt).unwrap(),
                *derive_uncached("session pass", &salt).unwrap()
            );
        }
        assert_eq!(cache_len(), 100);
        // A sealed file still refuses the wrong passphrase with the cache warm.
        let root = std::env::temp_dir().join(format!("loki-kdf-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        let dir = MemberDir::create(&root, "sealed").unwrap();
        dir.write_sealed("secret.sealed", b"payload", "session pass")
            .unwrap();
        assert_eq!(
            dir.read_sealed("secret.sealed", "session pass").unwrap(),
            b"payload"
        );
        assert!(dir.read_sealed("secret.sealed", "wrong pass").is_err());
        assert_eq!(
            dir.read_sealed("secret.sealed", "session pass").unwrap(),
            b"payload"
        );
        std::fs::remove_dir_all(&root).unwrap();
        // Switching sessions drops the old keys; clearing empties the cache.
        enable_session_cache("next pass");
        assert_eq!(cache_len(), 0);
        derive("next pass", &salt).unwrap();
        assert_eq!(cache_len(), 1);
        clear_session_cache();
        assert_eq!(cache_len(), 0);
        derive("next pass", &salt).unwrap();
        assert_eq!(cache_len(), 0, "a cleared cache stores nothing");
    }
}
