//! End-to-end verifier for the real `AppleSecureElement` backend, built with `rustc`
//! directly (std-only, offline — the main crate can't resolve crates.io on this Mac).
//!
//! It includes the SHIPPED module `poc/src/signer/secure_element_apple.rs` as a submodule,
//! so the code exercised here is byte-for-byte the code that goes into the crate. The only
//! dependencies it stubs are the crate-side `SecureElement`/`WrappedDek` (declared in the
//! crate-root `secure_element` module below, which the backend reaches via `super::`) and
//! the `zeroize` crate (supplied as an rlib via `--extern`, see `zeroize_shim.rs`).

use std::fs::File;
use std::io::Read;

// The backend's `use super::secure_element::{SecureElement, WrappedDek}` resolves here:
// pasted into `mod backend`, `super` is the crate root, so this crate-root module is it.
mod secure_element {
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct WrappedDek(pub Vec<u8>);

    pub trait SecureElement {
        fn wrap_dek(&self, dek: &[u8; 32]) -> Result<WrappedDek, String>;
        fn unwrap_dek(&self, wrapped: &WrappedDek)
            -> Result<zeroize::Zeroizing<[u8; 32]>, String>;
    }
}

use secure_element::SecureElement;

#[path = "../src/signer/secure_element_apple.rs"]
mod backend;

use backend::AppleSecureElement;

fn main() {
    // A DEK exactly as the signer generates it to seal a FROST share at wallet init.
    let mut dek = [0u8; 32];
    File::open("/dev/urandom").unwrap().read_exact(&mut dek).unwrap();

    // Ephemeral path: no signing identity, runs unsigned/offline on this Mac.
    let se = AppleSecureElement::ephemeral().expect("open ephemeral Secure Enclave key");
    println!("[rust] ephemeral AppleSecureElement opened via FFI");

    let wrapped = se.wrap_dek(&dek).expect("wrap_dek");
    println!("[rust] wrap_dek -> {} bytes (ECIES to the Enclave key)", wrapped.0.len());

    let back = se.unwrap_dek(&wrapped).expect("unwrap_dek");
    assert_eq!(&dek, &*back, "SECURITY: DEK round-trip mismatch");
    println!("[rust] unwrap_dek -> DEK recovered byte-for-byte");

    // Wrong ciphertext must be rejected (the Enclave decrypt fails, not silent garbage).
    let mut bad = wrapped.clone();
    *bad.0.last_mut().unwrap() ^= 0xff;
    assert!(se.unwrap_dek(&bad).is_err(), "SECURITY: tampered ciphertext was accepted");
    println!("[rust] tampered ciphertext correctly rejected");

    // Persistent path is present and callable; unsigned it must fail cleanly (not panic,
    // not succeed) — this is the documented cert gate, asserted so it can't silently pass.
    match AppleSecureElement::persistent(b"cash.loki.signer.kek.verify") {
        Err(e) => println!("[rust] persistent path gated as expected (unsigned): {e}"),
        Ok(_) => panic!("UNEXPECTED: persistent Enclave key succeeded without a signing identity"),
    }

    println!("APPLE FFI VERIFY PASS: real AppleSecureElement ephemeral wrap/unwrap round-trips a signer DEK");
}
