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

use loki_signer_core::signer::secure_element::SealedShare;
use loki_signer_core::signer::secure_element_webauthn::WebAuthnSecureElement;
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
