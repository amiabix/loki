//! Apple Secure Enclave backend of [`SecureElement`] (ws1-signer §4 "Hardware path").
//!
//! The Enclave is P-256 only, so — exactly like the software fallback — it does not hold
//! the FROST share: it holds the KEK and wraps/unwraps the per-share DEK via ECIES
//! (`eciesEncryptionCofactorX963SHA256AESGCM`). The share seals under that DEK in
//! [`super::secure_element::SealedShare`]; nothing above the trait changes versus
//! [`super::secure_element::SoftwareSecureElement`].
//!
//! Key lifetimes (both expose the identical wrap/unwrap surface):
//! - [`AppleSecureElement::ephemeral`] — process-lifetime key, no keychain, no signing
//!   identity. Works unsigned and offline; this is what the FFI verifier exercises today.
//! - [`AppleSecureElement::persistent`] — `kSecAttrIsPermanent` + `kSecAttrApplicationTag`
//!   with biometric access control (`.biometryCurrentSet | .privateKeyUsage`), so
//!   `unwrap_dek` is gated behind Face/Touch ID and the key dies if enrolled biometrics
//!   change. **Requires the binary signed with an Apple Team ID** (a free personal team is
//!   enough); unsigned, key creation fails with `errSecMissingEntitlement` (-34018).
//!
//! The Swift side lives in `poc/enclave-spike/se_backend.swift` (built to a dylib). Wiring
//! this module into the main crate build is the remaining non-crypto gate — see
//! `poc/enclave-spike/BACKEND.md`.
//!
//! ponytail: this module compiles only on macOS behind `#[cfg(target_os = "macos")]` and
//! links `libse_backend`; the crate must declare that link (build.rs or `#[link]`) before
//! it is reachable from the main build. Until then it is verified standalone by
//! `poc/enclave-spike/apple_ffi_verify.rs`.

use super::secure_element::{OpenError, SecureElement, WrappedDek};
use zeroize::Zeroizing;

// C-ABI surface implemented in se_backend.swift. Lengths are `isize`-shaped `Int` on the
// Swift side; we pass `isize`. Negative returns are error codes (see se_backend.swift).
extern "C" {
    fn se_open_ephemeral(out_handle: *mut u64) -> isize;
    fn se_open_persistent(tag: *const u8, tag_len: isize, out_handle: *mut u64) -> isize;
    fn se_wrap(handle: u64, dek: *const u8, dek_len: isize, out: *mut u8, out_cap: isize) -> isize;
    fn se_unwrap(handle: u64, ct: *const u8, ct_len: isize, out: *mut u8, out_cap: isize) -> isize;
    fn se_sign(handle: u64, msg: *const u8, msg_len: isize, out: *mut u8, out_cap: isize) -> isize;
    fn se_public_key(handle: u64, out: *mut u8, out_cap: isize) -> isize;
    fn se_close(handle: u64);
}

/// A live Secure Enclave KEK handle. Wraps/unwraps DEKs through the Enclave; the KEK never
/// crosses this boundary (`SecKeyCopyExternalRepresentation` refuses, proven in the spike).
pub struct AppleSecureElement {
    handle: u64,
}

impl AppleSecureElement {
    /// Open a fresh process-lifetime Enclave key. No signing identity required.
    pub fn ephemeral() -> Result<Self, String> {
        let mut handle = 0u64;
        let rc = unsafe { se_open_ephemeral(&mut handle) };
        if rc != 0 {
            return Err(format!("se_open_ephemeral failed (code {rc})"));
        }
        Ok(Self { handle })
    }

    /// Open (or create on first use) the persistent, biometric-gated Enclave key named by
    /// `tag`. Fails with an `errSecMissingEntitlement`-rooted error unless the binary is
    /// signed with an Apple Team ID.
    pub fn persistent(tag: &[u8]) -> Result<Self, String> {
        let mut handle = 0u64;
        let rc = unsafe { se_open_persistent(tag.as_ptr(), tag.len() as isize, &mut handle) };
        if rc != 0 {
            return Err(format!(
                "se_open_persistent failed (code {rc}); code -5 unsigned = errSecMissingEntitlement, \
                 needs an Apple Team ID signature"
            ));
        }
        Ok(Self { handle })
    }
}

impl AppleSecureElement {
    /// Sign `msg` with the Enclave key (ECDSA/SHA-256, DER) — the device login-challenge
    /// signature. On a persistent biometric key this prompts Face/Touch ID; the private op
    /// stays inside the Enclave. Verified by [`crate::signer::device_auth::DeviceRegistry`].
    pub fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, String> {
        // A P-256 ECDSA DER signature is <= 72 bytes; 128 is a comfortable ceiling.
        let mut out = vec![0u8; 128];
        let n = unsafe {
            se_sign(self.handle, msg.as_ptr(), msg.len() as isize, out.as_mut_ptr(), out.len() as isize)
        };
        if n <= 0 {
            return Err(format!("se_sign failed (code {n})"));
        }
        out.truncate(n as usize);
        Ok(out)
    }

    /// The Enclave key's PUBLIC point, X9.63 uncompressed (`04 || X || Y`, 65 bytes for P-256).
    /// This is what Loki enrolls as the device key; the private key never leaves the Enclave.
    pub fn public_key_sec1(&self) -> Result<Vec<u8>, String> {
        let mut out = vec![0u8; 128];
        let n = unsafe { se_public_key(self.handle, out.as_mut_ptr(), out.len() as isize) };
        if n <= 0 {
            return Err(format!("se_public_key failed (code {n})"));
        }
        out.truncate(n as usize);
        Ok(out)
    }
}

impl Drop for AppleSecureElement {
    fn drop(&mut self) {
        unsafe { se_close(self.handle) };
    }
}

// ECIES(P-256, X9.63-SHA256, AES-GCM) ciphertext of a 32-byte DEK is 113 bytes (measured
// in the spike); 256 is a comfortable ceiling. The unwrap output is exactly the 32-byte DEK.
const WRAP_OUT_CAP: usize = 256;

impl SecureElement for AppleSecureElement {
    fn wrap_dek(&self, dek: &[u8; 32]) -> Result<WrappedDek, String> {
        let mut out = vec![0u8; WRAP_OUT_CAP];
        let n = unsafe {
            se_wrap(self.handle, dek.as_ptr(), 32, out.as_mut_ptr(), out.len() as isize)
        };
        if n <= 0 {
            return Err(format!("se_wrap failed (code {n})"));
        }
        out.truncate(n as usize);
        Ok(WrappedDek(out))
    }

    fn unwrap_dek(&self, wrapped: &WrappedDek) -> Result<Zeroizing<[u8; 32]>, OpenError> {
        let mut out = Zeroizing::new([0u8; 64]);
        let n = unsafe {
            se_unwrap(
                self.handle,
                wrapped.0.as_ptr(),
                wrapped.0.len() as isize,
                out.as_mut_ptr(),
                out.len() as isize,
            )
        };
        if n != 32 {
            return Err(match n {
                -11 => OpenError::Element("Touch ID was cancelled or authentication failed".into()),
                // Security didn't expose a recognizable authentication error. This does not prove a wrong binding.
                -4 => OpenError::Element("Secure Enclave could not unlock the file key (code -4); Touch ID may not have completed".into()),
                _ => OpenError::Element(format!("se_unwrap failed or wrong length (code/len {n})")),
            });
        }
        let mut dek = Zeroizing::new([0u8; 32]);
        dek.copy_from_slice(&out[..32]);
        Ok(dek)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Exercises the REAL Secure Enclave through the FFI (ephemeral key — no signing
    // identity / keychain needed, so it runs in a bare test binary). Persistence +
    // biometrics need the provisioned app context (see poc/signer-app/).
    #[test]
    fn apple_enclave_wraps_and_unwraps_a_dek() {
        let se = AppleSecureElement::ephemeral().expect("open ephemeral Secure Enclave");
        let dek = [7u8; 32];
        let wrapped = se.wrap_dek(&dek).expect("wrap_dek via the Enclave");
        assert!(wrapped.0.len() > 32, "ECIES ciphertext is larger than the DEK");
        let back = se.unwrap_dek(&wrapped).expect("unwrap_dek via the Enclave");
        assert_eq!(&*back, &dek, "DEK round-trips through the Secure Enclave");
    }
}
