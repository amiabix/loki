//! Member host wiring for local recovery and wallet-safe backup export.
//!
//! Establishes the member's recovery identity (24 words shown ONCE; only the PUBLIC keys are
//! persisted) and serves the independent recovery backup blob. Each per-vault backup is HPKE
//! ciphertext to the member's words (see [`crate::signer::recovery`]). The member host stores
//! it locally; an account login cannot open it. The share is sealed into the backup during the ceremony
//! ([`crate::signer::local::BackupDevice::save_recovery`]); this module only persists the
//! public key the signer seals to, and hands the stored blob back for a restore.

use std::fs;
use std::io::{self, IsTerminal, Write};
use std::path::{Path, PathBuf};

use axum::{extract::{Query, State}, http::StatusCode};
use serde_json::json;
use std::collections::BTreeMap;
use zeroize::Zeroizing;

use super::routes::{err, ok, Reply};
use super::state::Shared;
use crate::signer::backup::{self, BackupArtifact};
use crate::signer::recovery::RecoveryKey;
use crate::state::MemberDir;

fn pubkey_file(data: &Path) -> PathBuf {
    data.join("recovery.pub")
}

#[cfg(test)]
pub(super) fn read_encryption_pubkey(data: &Path) -> Option<[u8; 32]> {
    let keys = <[u8; 64]>::try_from(fs::read(pubkey_file(data)).ok()?).ok()?;
    keys[..32].try_into().ok()
}

pub(super) fn read_authz_pubkey(data: &Path) -> Option<[u8; 32]> {
    let keys = <[u8; 64]>::try_from(fs::read(pubkey_file(data)).ok()?).ok()?;
    keys[32..].try_into().ok()
}

pub(super) fn backup_file(signer_dir: &Path) -> PathBuf {
    signer_dir.join("recovery.backup")
}

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

pub(super) fn seal_missing_backups_logged(data: &Path, pass: &str) {
    if let Err(e) = seal_missing_backups(data, pass) {
        eprintln!("recovery backup not sealed (retried at the next unlock): {e}");
    }
}

fn public_keys(key: &RecoveryKey) -> Vec<u8> {
    let mut pubkeys = Vec::with_capacity(64);
    pubkeys.extend_from_slice(&key.public_bytes());
    pubkeys.extend_from_slice(&key.signing_public());
    pubkeys
}

pub(super) fn check_recovery(data: &Path, key: &RecoveryKey) -> Result<bool, String> {
    match fs::read(pubkey_file(data)) {
        Ok(existing) if existing == public_keys(key) => Ok(false),
        Ok(_) => Err("this profile already has different recovery words; restore into a profile \
            created without --coordinator-url that holds no other vaults".into()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(e) => Err(e.to_string()),
    }
}

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

pub(super) fn exists(data: &Path) -> bool {
    pubkey_file(data).exists()
}

pub(super) fn confirm_recovery(data: &Path, pass: &str, notice: &super::LocalNotice) -> Result<(), String> {
    if pubkey_file(data).try_exists().map_err(|e| e.to_string())? { return Ok(()); }
    let (words, key) = RecoveryKey::generate()?;
    if !notice("recovery", words.as_str()) { return Err("recovery-not-confirmed".into()); }
    adopt_recovery(data, &key, pass)
}

pub(super) async fn local_only(State(st): State<Shared>) -> Reply {
    let message = if st.config.native {
        "Manage recovery words and restore vaults in LokiSigner."
    } else {
        "Stop the member app and run loki_member_app recovery-setup or recovery-restore in its terminal."
    };
    err(StatusCode::FORBIDDEN, message)
}

pub(super) fn terminal_notice() -> super::LocalNotice {
    std::sync::Arc::new(|_, words| {
        println!("Save these 24 recovery words privately (shown once):\n{words}\nType YES and press Enter after saving them.");
        let mut answer = Zeroizing::new(String::new());
        io::stdin().read_line(&mut answer).is_ok() && answer.trim() == "YES"
    })
}

pub(super) fn lock_headless_data(data: &Path) -> Result<fs::File, String> {
    if !data.try_exists().map_err(|e| e.to_string())? {
        MemberDir::create(data, "").map_err(|e| e.to_string())?;
    }
    let file = fs::OpenOptions::new().read(true).write(true).create(true).truncate(false)
        .open(data.join("member-app.lock")).map_err(|e| e.to_string())?;
    file.try_lock().map_err(|e| format!("could not lock member data; stop the running member app first: {e}"))?;
    Ok(file)
}

pub fn run_recovery_command(args: &[String]) -> Result<(), String> {
    let (command, flags) = args.split_first().ok_or("missing recovery command")?;
    let mut config_args = flags.to_vec();
    config_args.extend(["--port".into(), "0".into()]);
    let config = super::config_from_args(&config_args)?;
    config.validate_secure_element()?;
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err("run recovery in a private interactive terminal, without pipes or logs".into());
    }
    let data = &config.data;
    if !crate::profile::exists(data) {
        return Err("create a member profile before running recovery".into());
    }
    let _lock = lock_headless_data(data)?;
    let prompt = |label| rpassword::prompt_password(label).map(Zeroizing::new).map_err(|e| e.to_string());
    let pass = prompt("Profile passphrase: ")?;
    crate::profile::open(data, &pass)?;
    match command.as_str() {
        "recovery-setup" => {
            if exists(data) && !data.join("recovery.confirmed").try_exists().map_err(|e| e.to_string())? {
                let words = prompt("Original 24 recovery words (hidden): ")?;
                let key = RecoveryKey::from_words(&words)?;
                adopt_recovery(data, &key, &pass)?;
            } else {
                confirm_recovery(data, &pass, &terminal_notice())?;
            }
            seal_missing_backups(data, &pass)?;
            println!("Recovery is configured.");
        }
        "recovery-restore" => {
            #[derive(serde::Deserialize)]
            struct Export { vault: String, backup: String }
            let option = |name| flags.iter().position(|arg| arg == name).and_then(|i| flags.get(i + 1));
            let file = option("--backup").ok_or("--backup <export.json> is required")?;
            let fingerprint = option("--fingerprint").ok_or("--fingerprint <sha256> from the original signer is required")?;
            let export: Export = serde_json::from_reader(fs::File::open(file).map_err(|e| e.to_string())?)
                .map_err(|_| "invalid recovery backup file")?;
            let backup = hex::decode(export.backup.trim()).map_err(|_| "backup must be hex")?;
            let words = prompt("24 recovery words (hidden): ")?;
            super::ceremony::restore_vault_from_backup(data, &export.vault, &words, Some(&backup), Some(fingerprint), &pass, &config)?;
            println!("Vault restored.");
        }
        _ => return Err("unknown recovery command".into()),
    }
    Ok(())
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
