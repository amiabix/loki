//! The account profile: a passphrase-sealed `{version, id, name}` under `<data>/profile/`.
//! One profile namespaces a member's vaults. Lifted from the `loki_setup_member` bin so
//! both the CLI and the `loki_member_app` coordinator share one implementation.

use std::path::Path;

use rand_core::{OsRng, RngCore};
use serde_json::Value;

use crate::state::MemberDir;

fn valid_name(name: &str) -> bool {
    !name.is_empty() && name.len() <= 80
}

/// Create (and seal) a new profile. Errors if one already exists at `root`.
pub fn create(root: &Path, passphrase: &str, name: &str) -> Result<Value, String> {
    let label = name.trim();
    if !valid_name(label) {
        return Err("profile name must be 1 to 80 bytes".into());
    }
    let mut id = [0u8; 32];
    OsRng.fill_bytes(&mut id);
    let dir = MemberDir::create(root, "profile").map_err(|e| e.to_string())?;
    let profile = serde_json::json!({"version": 1, "id": hex::encode(id), "name": label});
    dir.write_sealed(
        "profile.sealed",
        &serde_json::to_vec(&profile).map_err(|e| e.to_string())?,
        passphrase,
    )
    .map_err(|e| e.to_string())?;
    Ok(profile)
}

/// Open and validate an existing sealed profile. Also the passphrase check for unlock.
pub fn open(root: &Path, passphrase: &str) -> Result<Value, String> {
    let dir = MemberDir::open(root, "profile");
    let raw = dir
        .read_sealed("profile.sealed", passphrase)
        .map_err(|e| e.to_string())?;
    let profile: Value = serde_json::from_slice(&raw).map_err(|e| e.to_string())?;
    let ok = profile["version"] == 1
        && profile["name"].as_str().is_some_and(valid_name)
        && profile["id"]
            .as_str()
            .and_then(|s| hex::decode(s).ok())
            .is_some_and(|b| b.len() == 32);
    if !ok {
        return Err("invalid sealed profile".into());
    }
    Ok(profile)
}

/// Whether a sealed profile exists at `root` (without the passphrase).
pub fn exists(root: &Path) -> bool {
    root.join("profile").join("profile.sealed").is_file()
}
