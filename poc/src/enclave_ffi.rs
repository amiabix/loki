//! C-ABI entry points for the native signer app (`poc/signer-app/`, LokiSigner.app).
//!
//! The app is provisioned (Apple Team ID + profile), so — unlike a bare CLI — it is
//! allowed to create a PERSISTENT, biometric-capable Secure Enclave key. This selftest
//! runs the real signer sealing path through that key: it seals a stand-in FROST share
//! under a persistent Enclave KEK, drops everything, reopens the SAME Enclave key by tag,
//! and unseals — proving the share is held in the Enclave across "launches".

use crate::signer::secure_element::SealedShare;
use crate::signer::secure_element_apple::AppleSecureElement;

/// Returns 0 on success; small nonzero codes mark which step failed.
#[no_mangle]
pub extern "C" fn loki_signer_enclave_selftest() -> i32 {
    let tag = b"cash.loki.signer.share.v1";

    // Wallet init: open the persistent Enclave KEK and seal the member's share under it.
    let se = match AppleSecureElement::persistent(tag) {
        Ok(s) => s,
        Err(_) => return 1,
    };
    let share = [0x9u8; 64];
    let sealed = match SealedShare::seal(&se, 0, &share) {
        Ok(s) => s,
        Err(_) => return 2,
    };
    let blob = sealed.to_bytes();
    drop(sealed);
    drop(se);

    // Next launch: reopen the SAME Enclave key by tag and unseal the share.
    let se2 = match AppleSecureElement::persistent(tag) {
        Ok(s) => s,
        Err(_) => return 3,
    };
    let parsed = match SealedShare::from_bytes(&blob) {
        Ok(s) => s,
        Err(_) => return 4,
    };
    let opened = match parsed.open(&se2) {
        Ok(o) => o,
        Err(_) => return 5,
    };
    if opened.as_slice() == &share[..] {
        0
    } else {
        6
    }
}
