//! Local-only restore. Neither the words nor backup bytes are submitted to the coordinator.

use std::{fs, io::Read, path::{Path, PathBuf}};

use serde::Deserialize;
use zeroize::Zeroizing;

use super::{ceremony::{self, RecoveryBackup}, recovery, registration::{self, PublicMember, RESTORE_PENDING}, state::Shared, Config, FetchedConfig, RegistrationConfig};
use crate::{setup_transport::{Identity, PublicIdentity}, signer::{recovery::RecoveryKey, Network}, state::MemberDir};

pub(crate) const REFUSED: &str = "LokiSigner could not restore this vault. Check the recovery words and backup, then try again.";
pub(super) const LOCKED: &str = "Unlock LokiSigner before restoring a vault.";
const BAD_FILE: &str = "Choose a valid LokiSigner recovery backup file (at most 256 KiB).";
const WRONG_PROFILE: &str = "This backup or these recovery words do not match the unlocked LokiSigner profile.";
const ALREADY_PRESENT: &str = "This vault already has data in the profile. LokiSigner did not replace it.";
const NOT_FRESH: &str = "First-run recovery needs a new LokiSigner profile directory.";
const ROSTER_UNAVAILABLE: &str = "LokiSigner could not read the coordinator roster. Check the coordinator and try again.";
const ROSTER_MISMATCH: &str = "The coordinator roster does not identify exactly one slot for this backup.";

fn open_backup(file: &Path, words: Zeroizing<Vec<u8>>) -> Result<RecoveryBackup, &'static str> {
    const LIMIT: u64 = 256 * 1024;
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Export { vault: String, backup: String }

    if !fs::metadata(file).is_ok_and(|m| m.is_file() && m.len() <= LIMIT) { return Err(BAD_FILE); }
    let file = fs::File::open(file).map_err(|_| BAD_FILE)?;
    if !file.metadata().is_ok_and(|m| m.is_file()) { return Err(BAD_FILE); }
    let mut bytes = Vec::new();
    file.take(LIMIT + 1).read_to_end(&mut bytes).map_err(|_| BAD_FILE)?;
    if bytes.len() as u64 > LIMIT { return Err(BAD_FILE); }
    let export: Export = serde_json::from_slice(&bytes).map_err(|_| BAD_FILE)?;
    let is_hex = |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
    if export.vault.len() != 64 || !export.vault.bytes().all(is_hex) || !export.backup.bytes().all(is_hex) {
        return Err(BAD_FILE);
    }
    let blob = hex::decode(export.backup).map_err(|_| BAD_FILE)?;
    let key = RecoveryKey::from_words(std::str::from_utf8(&words).map_err(|_| REFUSED)?).map_err(|_| REFUSED)?;
    drop(words);
    RecoveryBackup::open(&export.vault, key, blob).map_err(|_| REFUSED)
}

/// Stage beside the destination so a same-filesystem rename is the only publication step.
/// A failed or interrupted restore cannot leave an active half-written vault/profile.
struct Stage(PathBuf);

impl Stage {
    fn new(parent: &Path) -> Result<Self, &'static str> {
        let path = parent.join(format!(".loki-restore-{}", uuid::Uuid::new_v4()));
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)] {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&path).map_err(|_| REFUSED)?;
        Ok(Self(path))
    }

    fn publish(&self, dest: &Path) -> Result<(), &'static str> {
        fn sync_tree(dir: &Path) -> std::io::Result<()> {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                if entry.file_type()?.is_dir() { sync_tree(&entry.path())?; }
                else { fs::File::open(entry.path())?.sync_all()?; }
            }
            fs::File::open(dir)?.sync_all()
        }
        sync_tree(&self.0).map_err(|_| REFUSED)?;
        fs::rename(&self.0, dest).map_err(|_| REFUSED)?;
        // Once published, don't ask the member to retry by reporting a failed flush.
        let _ = fs::File::open(dest.parent().expect("restore destination has a parent")).and_then(|f| f.sync_all());
        Ok(())
    }
}

impl Drop for Stage {
    fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); }
}

fn absent(path: &Path) -> Result<bool, &'static str> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Err(_) => Err(REFUSED),
    }
}

fn read_roster(origin: &str) -> Result<Vec<PublicMember>, &'static str> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Roster { slots: Vec<PublicMember> }

    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build().map_err(|_| ROSTER_UNAVAILABLE)?;
    runtime.block_on(async {
        let error = |_| ROSTER_UNAVAILABLE;
        let client = reqwest::Client::builder().redirect(reqwest::redirect::Policy::none())
            .timeout(std::time::Duration::from_secs(15)).build().map_err(error)?;
        // A plain GET: never send words, backup data, recovered keys, or a candidate slot here.
        let mut response = client.get(format!("{origin}/api/members")).send().await
            .and_then(|r| r.error_for_status()).map_err(error)?;
        if !response.status().is_success() { return Err(ROSTER_UNAVAILABLE); }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(error)? {
            if body.len() + chunk.len() > 1024 * 1024 { return Err(ROSTER_UNAVAILABLE); }
            body.extend_from_slice(&chunk);
        }
        serde_json::from_slice::<Roster>(&body).map(|r| r.slots).map_err(|_| ROSTER_UNAVAILABLE)
    })
}

fn restored_slot(identity: &PublicIdentity, members: &[PublicMember]) -> Result<u32, &'static str> {
    let (signing, relay) = (hex::encode(identity.signing), hex::encode(identity.encryption));
    let mut matches = members.iter().filter(|m| m.signing_pubkey == signing && m.relay_pubkey == relay);
    match (matches.next(), matches.next()) {
        (Some(m), None) if m.slot > 0 => Ok(m.slot),
        _ => Err(ROSTER_MISMATCH),
    }
}

pub(crate) fn restore_new(
    config: &mut Config, pass: &str, words: Zeroizing<Vec<u8>>, file: &Path, origin: &str, fetched: Option<&FetchedConfig>,
) -> Result<(), &'static str> {
    let backup = open_backup(file, words)?;
    if pass.is_empty() || config.registration.is_some() { return Err(REFUSED); }
    if !absent(&config.data)? { return Err(NOT_FRESH); }
    let origin = registration::plain_origin(origin, config.development_http).map_err(|_| ROSTER_UNAVAILABLE)?;
    let network = match backup.material.network { Network::Regtest => "regtest", Network::Testnet => "testnet" };
    if network != config.network { return Err(REFUSED); }
    let identity = Identity::from_secret_bytes(&backup.material.identity).map_err(|_| REFUSED)?.public();
    let slot = restored_slot(&identity, &read_roster(&origin)?)?;

    let name = "Member";
    let parent = config.data.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    fs::create_dir_all(parent).map_err(|_| REFUSED)?;
    let parent = parent.canonicalize().map_err(|_| REFUSED)?;
    let dest = parent.join(config.data.file_name().ok_or(NOT_FRESH)?);
    let staged = Stage::new(&parent)?;
    let vault = hex::encode(backup.material.vault_id);
    let vault_dir = MemberDir::open(&staged.0.join("vaults"), &vault);
    let final_key_dir = dest.join("vaults").join(&vault).join("signer");
    crate::profile::create(&staged.0, pass, name).map_err(|_| REFUSED)?;
    ceremony::restore_opened_backup(backup, &staged.0, &vault_dir, pass, config, Some(&final_key_dir)).map_err(|_| REFUSED)?;
    registration::save_coordinator(&staged.0, &origin, slot).map_err(|_| REFUSED)?;
    if let Some(fetched) = fetched { fetched.save_unlocked(&staged.0).map_err(|_| REFUSED)?; }
    fs::write(staged.0.join(RESTORE_PENDING), []).map_err(|_| REFUSED)?;
    if !absent(&dest)? { return Err(NOT_FRESH); }
    staged.publish(&dest)?;
    config.registration = Some(RegistrationConfig {
        coordinator: origin, slot: Some(slot), passphrase_file: None, name: name.into(), pairing_challenge: None,
    });
    Ok(())
}

pub(super) fn restore_running(st: &Shared, words: Zeroizing<Vec<u8>>, file: &Path) -> Result<(), &'static str> {
    let backup = open_backup(file, words)?;
    let session = st.session.blocking_read();
    let session = session.as_ref().ok_or(LOCKED)?;
    let (data, pass) = (&session.data, &session.passphrase);
    let _guard = st.ceremony.lock().map_err(|_| REFUSED)?;
    if !matches!(recovery::check_recovery(data, &backup.key), Ok(false)) { return Err(WRONG_PROFILE); }
    let existing = Zeroizing::new(MemberDir::open(data, "").read_sealed("identity.sealed", pass).map_err(|_| WRONG_PROFILE)?);
    if existing.len() != 66 || existing.get(2..) != backup.material.identity.get(2..) { return Err(WRONG_PROFILE); }

    let vault = hex::encode(backup.material.vault_id);
    let parent = data.join("vaults");
    fs::create_dir_all(&parent).map_err(|_| REFUSED)?;
    let parent = parent.canonicalize().map_err(|_| REFUSED)?;
    let dest = parent.join(&vault);
    if !absent(&dest)? { return Err(ALREADY_PRESENT); }
    let staged = Stage::new(&parent)?;
    let vault_dir = MemberDir::open(&staged.0, "");
    ceremony::restore_opened_backup(backup, data, &vault_dir, pass, &st.config, Some(&dest.join("signer"))).map_err(|_| REFUSED)?;
    staged.publish(&dest)
}
