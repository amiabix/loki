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

/// Full native-member lifecycle: a 2-of-3 vault created by REAL v2 DKG where every share is
/// generated and sealed under its own PERSISTENT, biometric-capable Secure Enclave key, then a
/// quorum signs a payment the prover accepts. This is the ephemeral `cargo test`
/// (`real_enclave_member_runs_dkg_and_signs`) with persistent keys — the share survives restart
/// and `unwrap` is Face-ID-gated. Returns 0 on success.
#[no_mangle]
pub extern "C" fn loki_signer_enclave_dkg_member_selftest() -> i32 {
    let tags: [&[u8]; 3] = [
        b"cash.loki.signer.dkg.m1.v1",
        b"cash.loki.signer.dkg.m2.v1",
        b"cash.loki.signer.dkg.m3.v1",
    ];
    let r = std::panic::catch_unwind(|| {
        crate::signer::native_member::prove_dkg_member(2, 3, |id| {
            AppleSecureElement::persistent(tags[(id - 1) as usize])
                .expect("open persistent Secure Enclave key")
        })
    });
    match r {
        Ok(Ok(())) => 0,
        Ok(Err(e)) => {
            eprintln!("dkg-member selftest failed: {e}");
            1
        }
        Err(_) => {
            eprintln!("dkg-member selftest panicked (persistent Secure Enclave key open?)");
            2
        }
    }
}

/// Run the LIVE member-app signer (the axum coordinator + frostd DKG/payment loop) inside the
/// provisioned app, with the member's FROST share held in the Secure Enclave. This is the real
/// native signer: `LokiSigner serve --data <dir> --port <n> --frostd-url <url> --advertise-url
/// <url> --peer <slot=url>...`. Reads the member args from this process's own argv (skipping the
/// binary name and the `serve` verb), forces the Apple Enclave backend, and serves. Blocks.
#[cfg(feature = "relay-communication")]
#[no_mangle]
pub extern "C" fn loki_member_app_serve() -> i32 {
    let args: Vec<String> = std::env::args().skip(2).collect();
    let mut config = match crate::host::config_from_args(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("serve config: {e}");
            return 2;
        }
    };
    // The whole point of the native signer: the share lives in the Secure Enclave.
    config.secure_element = "apple".into();
    if let Err(e) = config.validate_secure_element().and_then(|_| crate::host::run(config)) {
        eprintln!("serve: {e}");
        return 1;
    }
    0
}

/// The native app's payment dialog: receives the signer-derived summary JSON and returns 1
/// only when the member approved. Anything else (refuse, cancel, timeout) refuses.
pub type NativeApprove = extern "C" fn(*const std::ffi::c_char) -> i32;

fn native_approval(approve: NativeApprove) -> crate::host::LocalApproval {
    std::sync::Arc::new(move |summary| {
        std::ffi::CString::new(summary).is_ok_and(|summary| approve(summary.as_ptr()) == 1)
    })
}

/// Native payment-approval selftest: a 2-of-3 vault created by real v2 DKG signs one payment,
/// and each quorum member's `sign_approve` asks the app's dialog through `approve`, exactly as
/// the live member does. Shares use the software element, so it runs without enrolled
/// biometrics. Returns 0 when signed, 3 when the member refused.
#[no_mangle]
pub extern "C" fn loki_signer_approval_selftest(approve: NativeApprove) -> i32 {
    let r = std::panic::catch_unwind(|| {
        crate::signer::native_member::prove_dkg_member_with(
            2,
            3,
            |_| crate::signer::secure_element::SoftwareSecureElement::generate(),
            |slot| Some(crate::host::approval_policy(Some(native_approval(approve)), crate::signer::Network::Regtest, slot)),
        )
    });
    match r {
        Ok(Ok(())) => 0,
        Ok(Err(e)) if e.contains("member refused") => {
            eprintln!("approval selftest: the member refused; nothing was signed");
            3
        }
        Ok(Err(e)) => {
            eprintln!("approval selftest failed: {e}");
            1
        }
        Err(_) => 2,
    }
}

/// Native UI entry point. Unlock material crosses only this in-process ABI, never HTTP,
/// argv, a file or stdout. `notify` presents recovery words and the local session link;
/// `approve` asks the member to approve each payment before this device signs it.
///
/// # Safety
/// `launch` and `pass` must be live NUL-terminated UTF-8 strings for this call. `pass`
/// must be writable: its bytes are zeroed immediately after copying into Rust. `notify`
/// and `approve` must remain callable until the member stops and must copy strings before
/// returning.
#[cfg(feature = "relay-communication")]
#[no_mangle]
pub unsafe extern "C" fn loki_member_app_pair(
    launch: *const std::ffi::c_char,
    pass: *mut std::ffi::c_char,
    notify: extern "C" fn(*const std::ffi::c_char, *const std::ffi::c_char),
    approve: NativeApprove,
) -> i32 {
    let notice: crate::host::LocalNotice = std::sync::Arc::new(move |kind, message| {
        if let (Ok(kind), Ok(message)) = (std::ffi::CString::new(kind), std::ffi::CString::new(message)) {
            notify(kind.as_ptr(), message.as_ptr());
        }
    });
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| -> Result<(), String> {
        if launch.is_null() || pass.is_null() { return Err("missing native launch or unlock".into()); }
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Launch { args: Vec<String>, pairing_url: Option<String> }
        let launch: Launch = serde_json::from_str(std::ffi::CStr::from_ptr(launch).to_str().map_err(|e| e.to_string())?).map_err(|e| e.to_string())?;
        let raw = std::ffi::CStr::from_ptr(pass).to_bytes();
        let secret = std::str::from_utf8(raw).map(|s| zeroize::Zeroizing::new(s.to_owned()));
        zeroize::Zeroize::zeroize(std::slice::from_raw_parts_mut(pass, raw.len()));
        let pass = secret.map_err(|e| e.to_string())?;
        let mut config = crate::host::config_from_args(&launch.args)?;
        if config.registration.is_some() { return Err("native pairing accepts registration only through its pairing link".into()); }
        config.secure_element = "apple".into();
        config.validate_secure_element()?;
        config.registration = Some(match launch.pairing_url {
            Some(link) => crate::host::RegistrationConfig::pairing(&link, config.development_http)?,
            None => crate::host::RegistrationConfig::resume(&config.data, config.development_http)?,
        });
        crate::host::run_local(config, Some(pass), Some(notice.clone()), Some(native_approval(approve)))
    }));
    match result {
        Ok(Ok(())) => 0,
        Ok(Err(e)) => { notice("error", &e); 1 }
        Err(_) => { notice("error", "native member stopped unexpectedly"); 2 }
    }
}

#[cfg(all(test, feature = "relay-communication"))]
mod native_pairing_tests {
    #[test]
    fn native_unlock_buffer_is_wiped_before_startup() {
        extern "C" fn notice(kind: *const std::ffi::c_char, _: *const std::ffi::c_char) {
            assert_eq!(unsafe { std::ffi::CStr::from_ptr(kind) }.to_str().unwrap(), "error");
        }
        let launch = std::ffi::CString::new(r#"{"args":[]}"#).unwrap();
        extern "C" fn refuse(_: *const std::ffi::c_char) -> i32 { 0 }
        let mut pass = b"native passphrase\0".to_vec();
        let code = unsafe { super::loki_member_app_pair(launch.as_ptr(), pass.as_mut_ptr().cast(), notice, refuse) };
        assert_eq!(code, 1); // Invalid config fails before any Enclave operation.
        assert!(pass.iter().all(|b| *b == 0));
    }
}
