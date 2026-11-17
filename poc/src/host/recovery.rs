//! Coordinator wiring for the native-signer recovery flow.
//!
//! Establishes the member's recovery identity (24 words shown ONCE; only the PUBLIC keys are
//! persisted) and serves the independent recovery backup blob. Each per-vault backup is HPKE
//! ciphertext to the member's words (see [`crate::signer::recovery`]): this coordinator stores
//! it but cannot open it, and neither can an account login — so the login key is never the
//! vault backup. The share itself is sealed into the backup by the signer during the ceremony
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
pub(super) fn read_encryption_pubkey(data: &Path) -> Option<[u8; 32]> {
    fs::read(pubkey_file(data)).ok()?.get(..32)?.try_into().ok()
}

/// The member's recovery device-authorization public key (the Ed25519 key that authorizes
/// replacement devices). Second half of `data/recovery.pub`.
pub(super) fn read_authz_pubkey(data: &Path) -> Option<[u8; 32]> {
    fs::read(pubkey_file(data)).ok()?.get(32..64)?.try_into().ok()
}

/// The opaque recovery backup for a vault lives beside its sealed share.
pub(super) fn backup_file(signer_dir: &Path) -> PathBuf {
    signer_dir.join("recovery.backup")
}

/// Seal this vault's recovery backup: re-seal the share held in the passphrase-sealed
/// `backup.sealed` to the member's recovery words (HPKE to its recovery public key), so a
/// lost device can restore from the words alone ([`restore`] → [`crate::host::ceremony::
/// restore_vault_from_backup`]). Called at vault activation. A no-op (not an error) when no
/// recovery identity is established, when `backup.sealed` is absent, or when the recovery
/// backup already exists — so it is safe to call idempotently.
pub(super) fn seal_vault_backup(
    data: &Path,
    signer_dir: &Path,
    vault_id: &[u8; 32],
    pass: &str,
) -> Result<(), String> {
    let Some(recovery_pub) = read_encryption_pubkey(data) else {
        return Ok(());
    };
    let target = backup_file(signer_dir);
    if target.exists() {
        return Ok(());
    }
    let sealed = match MemberDir::open(signer_dir, "").read_sealed("backup.sealed", pass) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.to_string()),
    };
    let material = backup::verify(&BackupArtifact(sealed), pass, vault_id)?;
    let artifact = backup::create_to_recovery(&material, &recovery_pub)?;
    fs::write(&target, &artifact.0).map_err(|e| e.to_string())
}

/// Seal the missing recovery backup of every active vault. Vaults that became active before
/// the recovery identity existed have none; this runs at unlock and after recovery setup.
/// Each vault is attempted; the errors are returned together.
pub(super) fn seal_missing_backups(data: &Path, pass: &str) -> Result<(), String> {
    if read_encryption_pubkey(data).is_none() {
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

/// Write `recovery.pub` only if it does not exist. Returns false when it already exists.
fn create_public_keys(data: &Path, pubkeys: &[u8]) -> Result<bool, String> {
    let path = pubkey_file(data);
    // Never replace an identity created by a concurrent request.
    let mut file = match fs::OpenOptions::new().write(true).create_new(true).open(&path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Ok(false),
        Err(e) => return Err(e.to_string()),
    };
    if let Err(e) = file.write_all(pubkeys) {
        let _ = fs::remove_file(&path);
        return Err(e.to_string());
    }
    Ok(true)
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
pub(super) fn adopt_recovery(data: &Path, key: &RecoveryKey) -> Result<(), String> {
    if !create_public_keys(data, &public_keys(key))? {
        check_recovery(data, key)?;
    }
    Ok(())
}

/// Whether this profile has a recovery identity.
pub(super) fn exists(data: &Path) -> bool {
    pubkey_file(data).exists()
}

/// Establish the recovery identity once. Only public keys are persisted; existing identities
/// are left untouched and their words can never be reshown.
pub async fn establish_recovery(data: &Path) -> Result<Option<Zeroizing<String>>, String> {
    if pubkey_file(data).try_exists().map_err(|e| e.to_string())? {
        return Ok(None);
    }
    let (words, key) = RecoveryKey::generate()?;
    Ok(create_public_keys(data, &public_keys(&key))?.then_some(words))
}

/// POST /api/recovery-setup — establish the recovery identity once and return the 24 words for
/// the member to write down. Persists only the public keys; refuses if one already exists (the
/// words can never be reshown). Requires an unlocked session (a deliberate member action).
pub(super) async fn setup(State(st): State<Shared>) -> Reply {
    let (data, pass) = {
        let session = st.session.read().await;
        match session.as_ref() {
            Some(s) => (s.data.clone(), s.passphrase.clone()),
            None => return err(StatusCode::UNAUTHORIZED, "unlock before setting up recovery"),
        }
    };
    // Returned once, never stored. The member writes these down; they are the only way to open
    // recovery backups and to authorize a replacement device.
    match establish_recovery(&data).await {
        Ok(Some(words)) => {
            // Vaults that are already active get their backup now; the words are returned
            // even if sealing fails, and the next unlock retries it.
            let _ = tokio::task::spawn_blocking(move || seal_missing_backups_logged(&data, &pass)).await;
            ok(json!({ "words": words.as_str() }))
        }
        Ok(None) => err(StatusCode::CONFLICT, "a recovery identity is already established"),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
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
    ok(json!({ "recovery_identity": has_identity, "recovery_backup": has_backup }))
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
        Ok(blob) => ok(json!({ "vault": vault, "backup": hex::encode(blob) })),
        Err(_) => err(StatusCode::NOT_FOUND, "no recovery backup for this vault"),
    }
}

/// POST /api/recovery-restore { vault, words, backup? } — rebuild this member's vault from a
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
    match super::ceremony::restore_vault_from_backup(&data, vault, words.trim(), backup.as_deref(), &pass, &st.config) {
        Ok(()) => ok(json!({ "restored": true })),
        Err(e) => err(StatusCode::BAD_REQUEST, e),
    }
}
