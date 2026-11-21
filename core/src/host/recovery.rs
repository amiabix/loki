//! Member host wiring for the native-signer recovery flow.
//!
//! Establishes the member's recovery identity (24 words shown ONCE; only the PUBLIC keys are
//! persisted) and serves the independent recovery backup blob. Each per-vault backup is HPKE
//! ciphertext to the member's words (see [`crate::signer::recovery`]). The member host stores
//! it locally; an account login cannot open it. The share is sealed into the backup during the ceremony
//! ([`crate::signer::local::BackupDevice::save_recovery`]); this module only persists the
//! public key the signer seals to, and hands the stored blob back for a restore.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use axum::{
    extract::{Query, State},
    http::StatusCode,
    Json,
};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

use super::routes::{err, ok, Reply};
use super::state::Shared;
use crate::signer::backup::{self, BackupArtifact};
use crate::signer::recovery::RecoveryKey;
use crate::state::MemberDir;

/// `data/recovery.pub` — 64 bytes: X25519 backup-encryption key (32) then Ed25519 device-
/// authorization key (32). Public keys only; the 24 words are never written to disk.
fn pubkey_file(data: &Path) -> PathBuf {
    data.join("recovery.pub")
}

/// The member's recovery backup-encryption public key, if a recovery identity is established.
#[cfg(test)]
pub(super) fn read_encryption_pubkey(data: &Path) -> Option<[u8; 32]> {
    let keys = <[u8; 64]>::try_from(fs::read(pubkey_file(data)).ok()?).ok()?;
    keys[..32].try_into().ok()
}

/// The member's recovery device-authorization public key (the Ed25519 key that authorizes
/// replacement devices). Second half of `data/recovery.pub`.
pub(super) fn read_authz_pubkey(data: &Path) -> Option<[u8; 32]> {
    let keys = <[u8; 64]>::try_from(fs::read(pubkey_file(data)).ok()?).ok()?;
    keys[32..].try_into().ok()
}

/// The opaque recovery backup for a vault lives beside its sealed share.
pub(super) fn backup_file(signer_dir: &Path) -> PathBuf {
    signer_dir.join("recovery.backup")
}

/// Seal this vault's recovery backup: re-seal the share held in the passphrase-sealed
/// `backup.sealed` to the member's recovery words (HPKE to its recovery public key), so a
/// replacement device can restore from the words and an exported copy of this file.
/// Called at vault activation. A no-op when no recovery identity is established or when
/// `backup.sealed` is absent. An existing target alone is not proof of a usable backup.
///
/// Delete `backup.sealed` only after publication to confirmed words. Legacy profiles keep
/// their passphrase copy until the member supplies their original words.
pub(super) fn seal_vault_backup(
    data: &Path,
    signer_dir: &Path,
    vault_id: &[u8; 32],
    pass: &str,
) -> Result<(), String> {
    let keys = match fs::read(pubkey_file(data)) {
        Ok(keys) if keys.len() == 64 => keys,
        Ok(_) => return Err("recovery.pub is incomplete; keep your passphrase backup".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.to_string()),
    };
    let target = backup_file(signer_dir);
    let confirmed = match MemberDir::open(data, "").read_sealed("recovery.confirmed", pass) {
        Ok(record) if record == keys => true,
        Ok(_) => return Err("recovery.pub differs from the confirmed recipient; keep your existing backups".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(e.to_string()),
    };
    if !confirmed && target.try_exists().map_err(|e| e.to_string())? {
        // Legacy setup may never have delivered the words. Don't discard either copy.
        return Ok(());
    }
    let sealed = match MemberDir::open(signer_dir, "").read_sealed("backup.sealed", pass) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.to_string()),
    };
    let material = backup::verify(&BackupArtifact(sealed), pass, vault_id)?;
    let artifact = backup::create_to_recovery(&material, keys[..32].try_into().unwrap())?;
    publish(&target, &artifact.0, confirmed).map_err(|e| e.to_string())?;
    if confirmed {
        match fs::remove_file(signer_dir.join("backup.sealed")) {
            Err(e) if e.kind() != std::io::ErrorKind::NotFound => return Err(format!("remove backup.sealed: {e}")),
            _ => (),
        }
    }
    Ok(())
}

/// Publish verified bytes in place, never exposing a partial export.
pub(super) fn install_backup(signer_dir: &Path, blob: &[u8]) -> Result<(), String> {
    publish(&backup_file(signer_dir), blob, true).map_err(|e| e.to_string())
}

fn publish(path: &Path, bytes: &[u8], replace: bool) -> std::io::Result<()> {
    let parent = path.parent().unwrap();
    let temp = parent.join(format!(".recovery.{}.tmp", uuid::Uuid::new_v4()));
    let mut file = fs::File::create_new(&temp)?;
    let result = (|| {
        file.write_all(bytes)?;
        file.sync_all()?;
        if replace { fs::rename(&temp, path)?; }
        else { fs::hard_link(&temp, path)?; }
        fs::File::open(parent)?.sync_all()
    })();
    let _ = fs::remove_file(&temp);
    result
}

/// Seal the missing recovery backup of every active vault. Vaults that became active before
/// the recovery identity existed have none; this runs at unlock and after recovery setup.
/// Each vault is attempted; the errors are returned together.
pub(super) fn seal_missing_backups(data: &Path, pass: &str) -> Result<(), String> {
    if !pubkey_file(data).try_exists().map_err(|e| e.to_string())? {
        return Ok(());
    }
    let entries = match fs::read_dir(data.join("vaults")) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.to_string()),
    };
    let mut errors = Vec::new();
    for entry in entries.flatten() {
        let Some(vault) = entry.file_name().to_str().map(str::to_owned) else { continue };
        let Ok(vault_id) = <[u8; 32]>::try_from(hex::decode(&vault).unwrap_or_default()) else { continue };
        if !entry.path().join("vault.sealed").exists() {
            continue;
        }
        let sealed = super::ceremony::signer_dir(data, &vault)
            .and_then(|dir| seal_vault_backup(data, &dir, &vault_id, pass));
        if let Err(e) = sealed {
            errors.push(format!("vault {vault}: {e}"));
        }
    }
    if errors.is_empty() { Ok(()) } else { Err(errors.join("; ")) }
}

/// [`seal_missing_backups`] for callers that must not fail on it (unlock, recovery setup):
/// the error goes to the local log and the next unlock tries again.
pub(super) fn seal_missing_backups_logged(data: &Path, pass: &str) {
    if let Err(e) = seal_missing_backups(data, pass) {
        eprintln!("recovery backup not sealed (retried at the next unlock): {e}");
    }
}

/// The `recovery.pub` layout for these words.
fn public_keys(key: &RecoveryKey) -> Vec<u8> {
    let mut pubkeys = Vec::with_capacity(64);
    pubkeys.extend_from_slice(&key.public_bytes());
    pubkeys.extend_from_slice(&key.signing_public());
    pubkeys
}

/// Restore brings the recovery identity with it: these words must be this profile's recovery
/// identity. Returns true when `recovery.pub` is absent and must be written with
/// [`adopt_recovery`]; refuses when the profile already has different words.
pub(super) fn check_recovery(data: &Path, key: &RecoveryKey) -> Result<bool, String> {
    match fs::read(pubkey_file(data)) {
        Ok(existing) if existing == public_keys(key) => Ok(false),
        Ok(_) => Err("this profile already has different recovery words; restore into a profile \
            created without --coordinator-url that holds no other vaults".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e.to_string()),
    }
}

/// Make these words the profile's recovery identity (public keys only).
pub(super) fn adopt_recovery(data: &Path, key: &RecoveryKey, pass: &str) -> Result<(), String> {
    let keys = public_keys(key);
    match publish(&pubkey_file(data), &keys, false) {
        Ok(()) => (),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => { check_recovery(data, key)?; }
        Err(e) => return Err(e.to_string()),
    }
    let root = MemberDir::open(data, "");
    match root.write_sealed("recovery.confirmed", &keys, pass) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists
            && root.read_sealed("recovery.confirmed", pass).is_ok_and(|saved| saved == keys) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

/// Whether this profile has a recovery identity.
pub(super) fn exists(data: &Path) -> bool {
    pubkey_file(data).exists()
}

/// Interactive startup must not adopt words the member never confirmed saving.
pub(super) fn confirm_recovery(data: &Path, pass: &str, notice: &super::LocalNotice) -> Result<(), String> {
    if pubkey_file(data).try_exists().map_err(|e| e.to_string())? { return Ok(()); }
    let (words, key) = RecoveryKey::generate()?;
    if !notice("recovery", words.as_str()) { return Err("recovery-not-confirmed".into()); }
    adopt_recovery(data, &key, pass)
}

pub(super) async fn in_app_only() -> Reply {
    err(StatusCode::FORBIDDEN, "Manage recovery words and restore vaults in LokiSigner.")
}

/// Headless only: `{}` begins setup; `{ "words": ... }` confirms the words saved by the member.
/// Keep only pending public keys in memory, so a lost response or restart cannot activate them.
pub(super) async fn setup(State(st): State<Shared>, Json(mut body): Json<Value>) -> Reply {
    let (data, pass) = {
        let session = st.session.read().await;
        let Some(session) = session.as_ref() else {
            return err(StatusCode::UNAUTHORIZED, "unlock before setting up recovery");
        };
        let Ok(mut pending) = st.pending_recovery.lock() else {
            return err(StatusCode::INTERNAL_SERVER_ERROR, "recovery setup unavailable");
        };
        if body.as_object().is_some_and(|fields| fields.is_empty()) {
            match pubkey_file(&session.data).try_exists() {
                Ok(false) => (),
                Ok(true) => return err(StatusCode::CONFLICT, "a recovery identity is already established"),
                Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            }
            return match RecoveryKey::generate() {
                Ok((words, key)) => {
                    *pending = Some(public_keys(&key));
                    ok(json!({ "words": words.as_str() }))
                }
                Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e),
            };
        }
        let Some(Value::String(words)) = body.as_object_mut().and_then(|fields| fields.remove("words")) else {
            return err(StatusCode::BAD_REQUEST, "provide the saved recovery words to confirm setup");
        };
        let key = match RecoveryKey::from_words(&Zeroizing::new(words)) {
            Ok(key) => key,
            Err(e) => return err(StatusCode::BAD_REQUEST, e),
        };
        match check_recovery(&session.data, &key) {
            Ok(true) if pending.as_ref() != Some(&public_keys(&key)) => {
                return err(StatusCode::CONFLICT, "these words are not pending; begin recovery setup again");
            }
            Ok(_) => (),
            Err(e) => return err(StatusCode::CONFLICT, e),
        }
        if let Err(e) = adopt_recovery(&session.data, &key, &session.passphrase) {
            return err(StatusCode::INTERNAL_SERVER_ERROR, e);
        }
        *pending = None;
        (session.data.clone(), session.passphrase.clone())
    };
    let _ = tokio::task::spawn_blocking(move || seal_missing_backups_logged(&data, &pass)).await;
    ok(json!({ "confirmed": true }))
}

/// GET /api/recovery-status — whether a recovery identity exists and whether this vault has a
/// stored recovery backup. No session required (safe, non-secret presence flags).
pub(super) async fn status(
    State(st): State<Shared>,
    Query(query): Query<BTreeMap<String, String>>,
) -> Reply {
    let data = &st.config.data;
    let has_identity = pubkey_file(data).exists();
    let has_backup = match query.get("vault") {
        Some(vault) => match super::ceremony::signer_dir(data, vault) {
            Ok(dir) => backup_file(&dir).exists(),
            Err(e) => return err(StatusCode::BAD_REQUEST, e),
        },
        None => false,
    };
    let mut reply = json!({ "recovery_identity": has_identity, "recovery_backup": has_backup });
    if st.config.native { reply["recovery_in_app"] = json!(true); }
    ok(reply)
}

/// GET /api/recovery-backup?vault=<id> — return the opaque recovery backup blob (hex) for a
/// restore. No session required: the blob is HPKE ciphertext that only the member's 24 words
/// can open, so serving it to the token-bearing proxy leaks nothing.
pub(super) async fn fetch(
    State(st): State<Shared>,
    Query(query): Query<BTreeMap<String, String>>,
) -> Reply {
    let Some(vault) = query.get("vault") else {
        return err(StatusCode::BAD_REQUEST, "missing vault");
    };
    let dir = match super::ceremony::signer_dir(&st.config.data, vault) {
        Ok(d) => d,
        Err(e) => return err(StatusCode::BAD_REQUEST, e),
    };
    match fs::read(backup_file(&dir)) {
        Ok(blob) if st.config.native => ok(json!({ "vault": vault.to_ascii_lowercase(), "backup": hex::encode(blob) })),
        Ok(blob) => {
            let artifact = BackupArtifact(blob);
            ok(json!({ "vault": vault.to_ascii_lowercase(), "backup": hex::encode(&artifact.0), "fingerprint": artifact.fingerprint() }))
        }
        Err(_) => err(StatusCode::NOT_FOUND, "no recovery backup for this vault"),
    }
}

/// Headless only: POST /api/recovery-restore { vault, words, backup? } — rebuild this member's vault from a
/// recovery backup using the 24 words. `backup` is the hex blob exported with
/// `GET /api/recovery-backup`, needed on a new device; without it the stored blob is used.
/// Requires an unlocked session (the restored vault is sealed under the profile passphrase).
pub(super) async fn restore(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    let (data, pass) = {
        let session = st.session.read().await;
        match session.as_ref() {
            Some(s) => (s.data.clone(), s.passphrase.clone()),
            None => return err(StatusCode::UNAUTHORIZED, "unlock before restoring"),
        }
    };
    let (Some(vault), Some(words)) = (
        body.get("vault").and_then(Value::as_str),
        body.get("words").and_then(Value::as_str),
    ) else {
        return err(StatusCode::BAD_REQUEST, "missing vault or words");
    };
    let backup = match body.get("backup").and_then(Value::as_str).map(|b| hex::decode(b.trim())) {
        None => None,
        Some(Ok(blob)) => Some(blob),
        Some(Err(_)) => return err(StatusCode::BAD_REQUEST, "backup must be hex"),
    };
    let (st, vault, words) = (st.clone(), vault.to_owned(), Zeroizing::new(words.to_owned()));
    let fingerprint = body.get("fingerprint").and_then(Value::as_str).map(str::to_owned);
    super::routes::blocking(move || {
        let _restore = st.ceremony.lock().map_err(|e| e.to_string())?;
        super::ceremony::restore_vault_from_backup(
            &data, &vault, &words, backup.as_deref(), fingerprint.as_deref(), &pass, &st.config,
        )?;
        Ok(json!({ "restored": true }))
    }).await
}
