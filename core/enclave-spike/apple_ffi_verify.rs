use std::fs::File;
use std::io::Read;

mod secure_element {
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct WrappedDek(pub Vec<u8>);

    #[derive(Debug)]
    pub enum OpenError { Element(String) }

    pub trait SecureElement {
        fn wrap_dek(&self, dek: &[u8; 32]) -> Result<WrappedDek, String>;
        fn unwrap_dek(&self, wrapped: &WrappedDek)
            -> Result<zeroize::Zeroizing<[u8; 32]>, OpenError>;
    }
}

use secure_element::SecureElement;

#[path = "../loki-signer-core/src/signer/secure_element_apple.rs"]
mod backend;

use backend::AppleSecureElement;

fn main() {
    let mut dek = [0u8; 32];
    File::open("/dev/urandom").unwrap().read_exact(&mut dek).unwrap();

    let se = AppleSecureElement::ephemeral().expect("open ephemeral Secure Enclave key");
    println!("[rust] ephemeral AppleSecureElement opened via FFI");

    let wrapped = se.wrap_dek(&dek).expect("wrap_dek");
    println!("[rust] wrap_dek -> {} bytes (ECIES to the Enclave key)", wrapped.0.len());

    let back = se.unwrap_dek(&wrapped).expect("unwrap_dek");
    assert_eq!(&dek, &*back, "SECURITY: DEK round-trip mismatch");
    println!("[rust] unwrap_dek -> DEK recovered byte-for-byte");

    let mut bad = wrapped.clone();
    *bad.0.last_mut().unwrap() ^= 0xff;
    assert!(se.unwrap_dek(&bad).is_err(), "SECURITY: tampered ciphertext was accepted");
    println!("[rust] tampered ciphertext correctly rejected");

    match AppleSecureElement::create_persistent(b"cash.loki.signer.kek.verify", None) {
        Err(e) => println!("[rust] persistent path gated as expected (unsigned): {e}"),
        Ok(_) => panic!("UNEXPECTED: persistent Enclave key succeeded without a signing identity"),
    }

    println!("APPLE FFI VERIFY PASS: real AppleSecureElement ephemeral wrap/unwrap round-trips a signer DEK");
}
