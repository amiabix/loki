//! Ephemeral Rust -> Swift -> Secure Enclave FFI demo.
//! Mirrors loki's `SecureElement::{wrap_dek,unwrap_dek}` with an Apple Enclave backend.
//! std-only, built with `rustc` directly so it compiles offline (no cargo/crates.io).

use std::fs::File;
use std::io::Read;

extern "C" {
    fn se_wrap(dek: *const u8, dek_len: isize, out: *mut u8, out_cap: isize) -> isize;
    fn se_unwrap(ct: *const u8, ct_len: isize, out: *mut u8, out_cap: isize) -> isize;
}

/// The Apple Enclave backend of loki's `SecureElement` trait (ephemeral key for this demo).
/// Drops into core/src/signer/secure_element.rs as `AppleSecureElement` behind the same trait.
struct AppleSecureElement;

impl AppleSecureElement {
    fn wrap_dek(&self, dek: &[u8; 32]) -> Vec<u8> {
        let mut out = vec![0u8; 256];
        let n = unsafe { se_wrap(dek.as_ptr(), 32, out.as_mut_ptr(), out.len() as isize) };
        assert!(n > 0, "se_wrap failed: {n}");
        out.truncate(n as usize);
        out
    }
    fn unwrap_dek(&self, ct: &[u8]) -> [u8; 32] {
        let mut out = vec![0u8; 64];
        let n = unsafe { se_unwrap(ct.as_ptr(), ct.len() as isize, out.as_mut_ptr(), out.len() as isize) };
        assert!(n == 32, "se_unwrap failed/returned {n}");
        let mut dek = [0u8; 32];
        dek.copy_from_slice(&out[..32]);
        dek
    }
}

fn main() {
    // A DEK, exactly as loki's signer generates it to seal a FROST share at wallet init.
    let mut dek = [0u8; 32];
    File::open("/dev/urandom").unwrap().read_exact(&mut dek).unwrap();

    let se = AppleSecureElement;
    println!("[rust] signer DEK generated (32B) — the key that seals the FROST share");
    let wrapped = se.wrap_dek(&dek);
    println!("[rust] wrap_dek via the Secure Enclave -> {} bytes", wrapped.len());
    let back = se.unwrap_dek(&wrapped);
    assert_eq!(dek, back, "SECURITY: DEK round-trip mismatch");
    println!("[rust] unwrap_dek via the Secure Enclave -> DEK recovered byte-for-byte");
    println!("EPHEMERAL FFI DEMO PASS: Rust -> Swift -> real Secure Enclave wrap/unwrap of a signer DEK");
}
