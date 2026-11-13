//! Member-local wiring for device authentication (the daily-login half of the recovery flow).
//!
//! A device holds a P-256 login key (the Secure Enclave key in the native signer). Loki
//! recognises it by challenge/response: `GET /api/device-challenge` issues a random nonce, the
//! device signs it, `POST /api/device-login` verifies the signature against the device's
//! enrolled public key — Loki never sees a private key. A device is enrolled only once the
//! recovery identity (the 24 words) has authorized it (`POST /api/device-enroll`), which is how
//! a new phone registers; `POST /api/device-revoke` drops a compromised device.
//!
//! The [`DeviceRegistry`](crate::signer::device_auth::DeviceRegistry) is the audited protocol
//! core; this module only persists enrolled devices (so they survive a restart) and exposes
//! the registry over HTTP. Enrollments are re-verified against the recovery key on reload, so
//! a tampered `devices.json` cannot inject a device the recovery words never signed.

use std::fs;
use std::path::{Path, PathBuf};

use axum::{extract::State, Json};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::routes::{err, ok, Reply};
use super::state::Shared;
use axum::http::StatusCode;

/// One persisted enrolled device: its SEC1 P-256 public key, the recovery authorization that
/// admitted it (re-verified on load), and whether it is still active.
#[derive(Serialize, Deserialize)]
struct StoredDevice {
    device_pub: String,
    authorization: String,
    active: bool,
}

fn devices_file(data: &Path) -> PathBuf {
    data.join("devices.json")
}

fn load_stored(data: &Path) -> Vec<StoredDevice> {
    fs::read(devices_file(data))
        .ok()
        .and_then(|raw| serde_json::from_slice(&raw).ok())
        .unwrap_or_default()
}

fn save_stored(data: &Path, devices: &[StoredDevice]) -> Result<(), String> {
    let raw = serde_json::to_vec_pretty(devices).map_err(|e| e.to_string())?;
    fs::write(devices_file(data), raw).map_err(|e| e.to_string())
}

/// Rebuild the registry from disk: bind it to the recovery device-authorization key and
/// re-enroll each persisted device (which re-verifies its authorization), then re-apply
/// revocations. Errors if no recovery identity has been established yet.
fn build_registry(data: &Path) -> Result<crate::signer::device_auth::DeviceRegistry, String> {
    let authz = super::recovery::read_authz_pubkey(data)
        .ok_or("no recovery identity yet — run recovery setup first")?;
    let mut registry = crate::signer::device_auth::DeviceRegistry::new(authz);
    for d in load_stored(data) {
        let device_pub = hex::decode(&d.device_pub).map_err(|e| e.to_string())?;
        let authorization: [u8; 64] = hex::decode(&d.authorization)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "stored authorization is not 64 bytes")?;
        registry.enroll(&device_pub, &authorization)?;
        if !d.active {
            registry.revoke(&device_pub);
        }
    }
    Ok(registry)
}

fn hex_field(body: &Value, name: &str) -> Result<Vec<u8>, Reply> {
    body.get(name)
        .and_then(Value::as_str)
        .and_then(|s| hex::decode(s).ok())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, format!("missing or invalid hex {name}")))
}

/// Run `f` against the in-process registry, lazily building it from disk on first use. The
/// guard is held only for the synchronous closure (no `.await` inside), so it never blocks a
/// worker across a yield point.
fn with_registry<F>(st: &Shared, f: F) -> Reply
where
    F: FnOnce(&mut crate::signer::device_auth::DeviceRegistry) -> Reply,
{
    let mut guard = st.device_auth.lock().unwrap();
    if guard.is_none() {
        match build_registry(&st.config.data) {
            Ok(r) => *guard = Some(r),
            Err(e) => return err(StatusCode::CONFLICT, e),
        }
    }
    f(guard.as_mut().unwrap())
}

/// POST /api/device-enroll { device_pub, authorization } — enroll a recovery-authorized device.
pub(super) async fn enroll(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    let device_pub = match hex_field(&body, "device_pub") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let authorization: [u8; 64] = match hex_field(&body, "authorization").map(TryInto::try_into) {
        Ok(Ok(a)) => a,
        Ok(Err(_)) => return err(StatusCode::BAD_REQUEST, "authorization must be 64 bytes"),
        Err(e) => return e,
    };
    let reply = with_registry(&st, |registry| match registry.enroll(&device_pub, &authorization) {
        Ok(()) => ok(json!({ "enrolled": true })),
        Err(e) => err(StatusCode::BAD_REQUEST, e),
    });
    if reply.0 != StatusCode::OK {
        return reply;
    }
    // Persist for restart (dedupe on device_pub; mark active).
    let mut stored = load_stored(&st.config.data);
    let hexpub = hex::encode(&device_pub);
    stored.retain(|d| d.device_pub != hexpub);
    stored.push(StoredDevice {
        device_pub: hexpub,
        authorization: hex::encode(authorization),
        active: true,
    });
    if let Err(e) = save_stored(&st.config.data, &stored) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, e);
    }
    reply
}

/// GET /api/device-challenge — issue a one-time random login challenge.
pub(super) async fn challenge(State(st): State<Shared>) -> Reply {
    with_registry(&st, |registry| {
        ok(json!({ "challenge": hex::encode(registry.issue_challenge()) }))
    })
}

/// POST /api/device-login { device_pub, challenge, signature } — verify a device's response.
pub(super) async fn login(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    let (device_pub, challenge, signature) = match (
        hex_field(&body, "device_pub"),
        hex_field(&body, "challenge"),
        hex_field(&body, "signature"),
    ) {
        (Ok(d), Ok(c), Ok(s)) => (d, c, s),
        (Err(e), _, _) | (_, Err(e), _) | (_, _, Err(e)) => return e,
    };
    let challenge: [u8; 32] = match challenge.try_into() {
        Ok(c) => c,
        Err(_) => return err(StatusCode::BAD_REQUEST, "challenge must be 32 bytes"),
    };
    with_registry(&st, |registry| {
        match registry.verify_login(&device_pub, &challenge, &signature) {
            Ok(()) => ok(json!({ "logged_in": true })),
            Err(e) => err(StatusCode::UNAUTHORIZED, e),
        }
    })
}

/// POST /api/device-revoke { device_pub } — revoke a compromised device's login.
pub(super) async fn revoke(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    let device_pub = match hex_field(&body, "device_pub") {
        Ok(v) => v,
        Err(e) => return e,
    };
    let reply = with_registry(&st, |registry| {
        registry.revoke(&device_pub);
        ok(json!({ "revoked": true }))
    });
    if reply.0 != StatusCode::OK {
        return reply;
    }
    // Persist the revocation so it survives a restart.
    let mut stored = load_stored(&st.config.data);
    let hexpub = hex::encode(&device_pub);
    for d in stored.iter_mut().filter(|d| d.device_pub == hexpub) {
        d.active = false;
    }
    if let Err(e) = save_stored(&st.config.data, &stored) {
        return err(StatusCode::INTERNAL_SERVER_ERROR, e);
    }
    reply
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::recovery::RecoveryKey;
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};

    fn tempdir() -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "loki-device-{}-{}",
            std::process::id(),
            rand_core::RngCore::next_u64(&mut rand_core::OsRng)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    // Write a recovery identity's public keys where build_registry expects them.
    fn write_recovery_pub(data: &Path, key: &RecoveryKey) {
        let mut pubkeys = Vec::new();
        pubkeys.extend_from_slice(&key.public_bytes());
        pubkeys.extend_from_slice(&key.signing_public());
        fs::write(data.join("recovery.pub"), pubkeys).unwrap();
    }

    #[test]
    fn enrolled_device_survives_a_rebuild_and_revocation_sticks() {
        let data = tempdir();
        let (_words, recovery) = RecoveryKey::generate().unwrap();
        write_recovery_pub(&data, &recovery);

        // Enroll a device: persist its recovery authorization.
        let sk = SigningKey::random(&mut rand_core::OsRng);
        let device_pub = sk.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        let authorization = recovery.authorize_device(&device_pub);
        save_stored(
            &data,
            &[StoredDevice {
                device_pub: hex::encode(&device_pub),
                authorization: hex::encode(authorization),
                active: true,
            }],
        )
        .unwrap();

        // Rebuild from disk (restart): the device logs in.
        let mut registry = build_registry(&data).unwrap();
        let challenge = registry.issue_challenge();
        let sig: Signature = sk.sign(&challenge);
        registry
            .verify_login(&device_pub, &challenge, &sig.to_der().as_bytes().to_vec())
            .expect("reloaded device logs in");

        // A tampered devices.json whose authorization is for a DIFFERENT recovery key is
        // refused on rebuild (re-verification), so it cannot inject an unauthorized device.
        let (_w2, other) = RecoveryKey::generate().unwrap();
        save_stored(
            &data,
            &[StoredDevice {
                device_pub: hex::encode(&device_pub),
                authorization: hex::encode(other.authorize_device(&device_pub)),
                active: true,
            }],
        )
        .unwrap();
        assert!(build_registry(&data).is_err(), "forged authorization is rejected on reload");

        // A revoked device stays revoked across a rebuild.
        save_stored(
            &data,
            &[StoredDevice {
                device_pub: hex::encode(&device_pub),
                authorization: hex::encode(authorization),
                active: false,
            }],
        )
        .unwrap();
        let mut registry = build_registry(&data).unwrap();
        let challenge = registry.issue_challenge();
        let sig: Signature = sk.sign(&challenge);
        assert!(
            registry
                .verify_login(&device_pub, &challenge, &sig.to_der().as_bytes().to_vec())
                .is_err(),
            "a revoked device must not log in after reload"
        );
    }
}
