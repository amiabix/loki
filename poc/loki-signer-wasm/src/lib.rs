//! wasm-bindgen bindings for the in-browser FROST signer.
//!
//! Phase 3 slice: the trust-critical, persistence-free custody primitive, proven to run
//! in the browser — seal/open a FROST share under a WebAuthn-PRF-derived KEK (W2's
//! [`WebAuthnSecureElement`]). This is the piece the onboarding UX needs first: the share
//! is wrapped under the passkey's PRF secret (released by Touch/Face ID / security key /
//! phone) and persisted sealed; a reload re-derives the same KEK and reopens it.
//!
//! The full stateful `SignerModule` (web/wallet/src/lib/signer.ts) — `createSigner` →
//! sealed share in OPFS, DKG/signing over the frostd transport, `request(path, body)` —
//! builds on top of this once the synchronous OPFS store seam replaces `store.rs`'s
//! `std::fs` (the core stays synchronous; the signer runs in a Web Worker where OPFS
//! `createSyncAccessHandle` gives synchronous file I/O). See the Phase 3 report.

use loki_signer_core::setup_transport::Identity;
use loki_signer_core::signer::secure_element::{
    fresh_kek_salt, SealedShare, SecureElement, SoftwareSecureElement, WrappedDek,
};
use loki_signer_core::signer::secure_element_webauthn::WebAuthnSecureElement;
use loki_signer_core::signer::{opfs_exists, opfs_get, opfs_put};
use wasm_bindgen::prelude::*;

// secp256k1 is pulled into this crate transitively (bip32 <- zakura-transparent, and pczt's
// `signer` feature forces `transparent`), but the Orchard FROST signer never calls it. Its
// C preallocated-context functions are left as `env` module imports by the wasm build (no
// WASI C toolchain compiles the C here), and a browser can't resolve a bare `env` specifier.
// Define the three dead symbols so the linker satisfies them in-module instead — no `env`
// import, no WASI toolchain, no fork of the vendored crypto. They are never called; if that
// ever changes, a null context makes the first real use fail loudly rather than silently.
#[cfg(target_arch = "wasm32")]
mod secp256k1_link_stub {
    use core::ffi::{c_uint, c_void};
    #[no_mangle]
    pub extern "C" fn rustsecp256k1_v0_10_0_context_preallocated_size(_flags: c_uint) -> usize {
        0
    }
    #[no_mangle]
    pub extern "C" fn rustsecp256k1_v0_10_0_context_preallocated_create(
        _prealloc: *mut c_void,
        _flags: c_uint,
    ) -> *mut c_void {
        core::ptr::null_mut()
    }
    #[no_mangle]
    pub extern "C" fn rustsecp256k1_v0_10_0_context_preallocated_destroy(_ctx: *mut c_void) {}
}

fn prf32(prf_secret: &[u8]) -> Result<[u8; 32], String> {
    prf_secret
        .try_into()
        .map_err(|_| "WebAuthn PRF secret must be exactly 32 bytes".to_string())
}

// Inner impls return String so the native `wasm-bindgen-test` can assert on them; the
// exported wrappers map the error to a JS exception.
fn seal_impl(prf_secret: &[u8], epoch: u64, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let se = WebAuthnSecureElement::from_prf_secret(&prf32(prf_secret)?);
    Ok(SealedShare::seal(&se, epoch, plaintext)?.to_bytes())
}

fn open_impl(prf_secret: &[u8], sealed: &[u8]) -> Result<Vec<u8>, String> {
    let se = WebAuthnSecureElement::from_prf_secret(&prf32(prf_secret)?);
    Ok(SealedShare::from_bytes(sealed)?.open(&se)?.to_vec())
}

/// Seal a FROST share under a passkey: KEK = HKDF(PRF secret), then the proven
/// XChaCha20-Poly1305 share seal. Returns the sealed bytes the browser persists.
/// `epoch` is the share's backup epoch.
#[wasm_bindgen(js_name = sealShareUnderPasskey)]
pub fn seal_share_under_passkey(
    prf_secret: &[u8],
    epoch: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, JsError> {
    seal_impl(prf_secret, epoch, plaintext).map_err(|e| JsError::new(&e))
}

/// Reopen a share sealed by [`seal_share_under_passkey`] with the same passkey's PRF
/// secret. Fails if the secret is wrong, the bytes are corrupt, or they were sealed under
/// a different element.
#[wasm_bindgen(js_name = openShareWithPasskey)]
pub fn open_share_with_passkey(prf_secret: &[u8], sealed: &[u8]) -> Result<Vec<u8>, JsError> {
    open_impl(prf_secret, sealed).map_err(|e| JsError::new(&e))
}

/// Browser OPFS-store seam self-test: write bytes at `path` and read them back through
/// the signer's synchronous `durable` backend (OPFS sync handles in this Worker). The
/// Worker must `opfsPreopenWrite(path)` first. Proves wasm↔OPFS before the full store.
#[wasm_bindgen(js_name = opfsSelftest)]
pub fn opfs_selftest(path: &str, bytes: &[u8]) -> Result<Vec<u8>, JsError> {
    loki_signer_core::signer::opfs_selftest(path, bytes).map_err(|e| JsError::new(&e))
}

// ─── Phase A: the stateful profile-lifecycle signer ──────────────────────────
//
// `Signer` is a stateful wasm-bindgen object: it holds the unlocked device `Identity` in
// memory between `unlock` and `lock`, and persists ONLY its sealed form to OPFS. The
// device identity is `Identity::new(1)` — slot 1 as a placeholder; it is re-stamped to the
// real vault slot later when the signer joins a vault (DKG, Phase B). The at-rest files are
// a fixed, deterministic set under `loki/device/`, so the Worker can pre-open exactly the
// paths each op touches before the synchronous call (OPFS sync handles are acquired async):
//
//   createSigner  writes: identity.sealed, profile.json, (passphrase) kek.salt
//   hasSigner     reads:  identity.sealed
//   unlock        reads:  identity.sealed, profile.json, (passphrase) kek.salt
//   lock          no I/O
//
// `request()` (DKG/payment) is NOT here — it stays `SignerPending` in the TS layer (Phase B/C).

/// Sealed device identity: `SealedShare(identity.to_secret_bytes())` under the selected SE.
pub const IDENTITY_PATH: &str = "loki/device/identity.sealed";
/// Public profile metadata (the display name). Non-secret, plaintext JSON.
pub const PROFILE_PATH: &str = "loki/device/profile.json";
/// Argon2id salt for the passphrase KEK (passphrase custody only).
pub const SALT_PATH: &str = "loki/device/kek.salt";

/// The device file set the Worker pre-opens, as a JSON array, so the pre-open protocol has a
/// single source of truth shared with `signer-worker.js` instead of drifting constants.
#[wasm_bindgen(js_name = devicePaths)]
pub fn device_paths() -> String {
    serde_json::json!({
        "identity": IDENTITY_PATH,
        "profile": PROFILE_PATH,
        "salt": SALT_PATH,
    })
    .to_string()
}

/// One of the custody secure elements, so the seal/open calls stay monomorphic over a single
/// type. Both delegate to the proven `SecureElement` impls; no new crypto here.
enum Element {
    Passphrase(SoftwareSecureElement),
    Passkey(WebAuthnSecureElement),
}

impl SecureElement for Element {
    fn wrap_dek(&self, dek: &[u8; 32]) -> Result<WrappedDek, String> {
        match self {
            Element::Passphrase(e) => e.wrap_dek(dek),
            Element::Passkey(e) => e.wrap_dek(dek),
        }
    }
    fn unwrap_dek(&self, wrapped: &WrappedDek) -> Result<zeroize::Zeroizing<[u8; 32]>, String> {
        match self {
            Element::Passphrase(e) => e.unwrap_dek(wrapped),
            Element::Passkey(e) => e.unwrap_dek(wrapped),
        }
    }
}

/// Re-derive the custody element. `create` draws and persists a fresh passphrase salt (first
/// create); otherwise the salt is read back. Passkey tiers take the JS-released PRF secret.
fn element(
    method: &str,
    passphrase: Option<String>,
    prf_secret: Option<Vec<u8>>,
    create: bool,
) -> Result<Element, String> {
    match method {
        "passphrase" => {
            let pass = passphrase.ok_or("passphrase required for passphrase custody")?;
            let salt = if create {
                let s = fresh_kek_salt();
                opfs_put(SALT_PATH, &s, false)?; // fresh salt on every create
                s.to_vec()
            } else {
                opfs_get(SALT_PATH)?.ok_or("no KEK salt — this signer is not passphrase-backed")?
            };
            Ok(Element::Passphrase(SoftwareSecureElement::from_passphrase(
                &pass, &salt,
            )?))
        }
        "platform" | "roaming" => {
            let prf = prf_secret.ok_or("WebAuthn PRF secret required for passkey custody")?;
            Ok(Element::Passkey(WebAuthnSecureElement::from_prf_secret(
                &prf32(&prf)?,
            )))
        }
        other => Err(format!("unknown custody method: {other}")),
    }
}

fn profile_json(identity: &Identity, name: &str) -> String {
    serde_json::json!({
        "id": hex::encode(identity.public().signing),
        "name": name,
    })
    .to_string()
}

/// Stateful in-browser signer. Holds the unlocked device identity only while unlocked.
#[wasm_bindgen]
pub struct Signer {
    identity: Option<Identity>,
}

impl Default for Signer {
    fn default() -> Self {
        Self { identity: None }
    }
}

#[wasm_bindgen]
impl Signer {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Signer {
        Signer::default()
    }

    /// True once a device identity is sealed in this browser → Unlock, not Create.
    /// The Worker must `opfsPreopenRead(IDENTITY_PATH)` first.
    #[wasm_bindgen(js_name = hasSigner)]
    pub fn has_signer(&self) -> bool {
        opfs_exists(IDENTITY_PATH)
    }

    /// Generate `Identity::new(1)`, seal it under the chosen custody element, and persist the
    /// sealed identity + profile (+ salt for passphrase) to OPFS. Returns the profile JSON
    /// `{id,name}`. The Worker must pre-open identity.sealed, profile.json (+ kek.salt) for
    /// write first. Refuses if a signer already exists here.
    #[wasm_bindgen(js_name = createSigner)]
    pub fn create_signer(
        &mut self,
        method: &str,
        name: &str,
        passphrase: Option<String>,
        prf_secret: Option<Vec<u8>>,
    ) -> Result<String, JsError> {
        self.create_impl(method, name, passphrase, prf_secret)
            .map_err(|e| JsError::new(&e))
    }

    /// Re-derive the custody element, open the sealed identity, and hold it in the session.
    /// Returns the profile JSON `{id,name}`. The Worker must pre-open the same paths for read.
    #[wasm_bindgen(js_name = unlock)]
    pub fn unlock(
        &mut self,
        method: &str,
        passphrase: Option<String>,
        prf_secret: Option<Vec<u8>>,
    ) -> Result<String, JsError> {
        self.unlock_impl(method, passphrase, prf_secret)
            .map_err(|e| JsError::new(&e))
    }

    /// Drop the in-memory identity; the session ends. The sealed files stay on disk.
    #[wasm_bindgen(js_name = lock)]
    pub fn lock(&mut self) {
        self.identity = None;
    }

    /// Whether an identity is currently held unlocked in memory.
    #[wasm_bindgen(js_name = isUnlocked)]
    pub fn is_unlocked(&self) -> bool {
        self.identity.is_some()
    }
}

impl Signer {
    fn create_impl(
        &mut self,
        method: &str,
        name: &str,
        passphrase: Option<String>,
        prf_secret: Option<Vec<u8>>,
    ) -> Result<String, String> {
        if opfs_exists(IDENTITY_PATH) {
            return Err("a signer already exists in this browser".into());
        }
        let se = element(method, passphrase, prf_secret, true)?;
        let identity = Identity::new(1);
        let secret = identity.to_secret_bytes();
        let sealed = SealedShare::seal(&se, 0, &secret)?;
        opfs_put(IDENTITY_PATH, &sealed.to_bytes(), true)?; // write-once
        opfs_put(PROFILE_PATH, profile_json(&identity, name).as_bytes(), false)?;
        let out = profile_json(&identity, name);
        self.identity = Some(identity);
        Ok(out)
    }

    fn unlock_impl(
        &mut self,
        method: &str,
        passphrase: Option<String>,
        prf_secret: Option<Vec<u8>>,
    ) -> Result<String, String> {
        let se = element(method, passphrase, prf_secret, false)?;
        let raw = opfs_get(IDENTITY_PATH)?.ok_or("no signer in this browser — create one first")?;
        let secret = SealedShare::from_bytes(&raw)?.open(&se)?;
        let identity = Identity::from_secret_bytes(&secret)?;
        let name = opfs_get(PROFILE_PATH)?
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|v| v.get("name").and_then(|n| n.as_str()).map(|s| s.to_string()))
            .unwrap_or_else(|| "You".to_string());
        let out = profile_json(&identity, &name);
        self.identity = Some(identity);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn prf_seal_open_round_trips_and_rejects_wrong_secret() {
        let prf = [7u8; 32];
        let share = b"a FROST signing share worth forging";

        let sealed = seal_impl(&prf, 2, share).unwrap();
        // Same passkey re-derives the KEK and reopens byte-identical.
        assert_eq!(open_impl(&prf, &sealed).unwrap(), share);
        // A different PRF secret cannot open it.
        assert!(open_impl(&[8u8; 32], &sealed).is_err());
        // A short secret is rejected before any crypto.
        assert!(seal_impl(&[0u8; 16], 0, share).is_err());
    }
}
