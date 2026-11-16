//! wasm32 compile spike for the Loki signer core's real dependency subtree.
//! Not shipped; exercises one non-trivial op per heavy dep so the linker must
//! emit the full monomorphized tree for wasm.

use reddsa_frost::frost::redpallas as frost;

/// FROST round-1 commit — the core signing primitive. Forces frost-core,
/// reddsa, pasta_curves and getrandom(js) codegen. Returns the serialized
/// hiding commitment length (non-zero on success).
pub fn frost_commit_len() -> usize {
    let (shares, _pubkeys) = frost::keys::generate_with_dealer(
        2,
        2,
        frost::keys::IdentifierList::Default,
        &mut rand_core::OsRng,
    )
    .expect("trusted-dealer keygen");
    let (_id, share) = shares.into_iter().next().expect("one share");
    let key_package = frost::keys::KeyPackage::try_from(share).expect("key package");
    let (_nonces, commitments) =
        frost::round1::commit(key_package.signing_share(), &mut rand_core::OsRng);
    commitments.serialize().expect("serialize commitment").len()
}

/// argon2 + XChaCha20-Poly1305 seal, mirroring secure_element.rs sealing.
/// Forces argon2, chacha20poly1305 and getrandom codegen.
pub fn seal_roundtrip() -> bool {
    use argon2::Argon2;
    use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};
    use rand_core::RngCore;

    let mut kek = [0u8; 32];
    Argon2::default()
        .hash_password_into(b"passphrase", b"salt-16-bytes-ok", &mut kek)
        .expect("argon2");
    let cipher = XChaCha20Poly1305::new((&kek).into());
    let mut nonce = [0u8; 24];
    rand_core::OsRng.fill_bytes(&mut nonce);
    let ct = cipher
        .encrypt(XNonce::from_slice(&nonce), b"share".as_ref())
        .expect("encrypt");
    let pt = cipher
        .decrypt(XNonce::from_slice(&nonce), ct.as_ref())
        .expect("decrypt");
    pt == b"share"
}

/// C-ABI entry so the linker keeps the above in a cdylib wasm build.
#[no_mangle]
pub extern "C" fn spike_run() -> u32 {
    (frost_commit_len() as u32) + (seal_roundtrip() as u32)
}
