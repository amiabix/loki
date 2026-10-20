//! The new signer's data directory (A5).
//!
//! ```text
//! <dir>/
//!   kek.sealed      software KEK, sealed once under the member passphrase
//!   signer.meta     public: network, vault id, member number
//!   identity.sealed setup identity (Ed25519 signing + X25519 encryption keys)
//!   roster.sealed   the roster the member confirmed on-device
//!   setup.sealed    DKG checkpoint: core state (fresh key until the certificate state),
//!                   exact outgoing messages, accepted incoming messages, backup receipts
//!   share.sealed    key package, group public package and the vault secret `vs`
//!   nonces/         crash-safe signing nonces
//! ```
//!
//! Every `.sealed` file except the KEK is a [`SealedShare`] under the secure element,
//! bound by its associated data to the file type, the vault and the member, so a file
//! moved between types, vaults or members fails to open. Writes are atomic (temporary
//! file, fsync, rename, directory fsync). With the software KEK a removed file is only
//! unlinked, not securely erased; real erasure depends on a hardware KEK.

use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::signer::durable::{remove_durable, replace_durable, write_durable};
use crate::signer::secure_element::{file_binding, SealedShare, SecureElement};
use crate::signer::Network;

const META: &str = "signer.meta";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FileKind {
    Identity,
    Roster,
    Setup,
    Share,
}

impl FileKind {
    fn name(self) -> &'static str {
        match self {
            Self::Identity => "identity",
            Self::Roster => "roster",
            Self::Setup => "setup",
            Self::Share => "share",
        }
    }
    fn file(self) -> String {
        format!("{}.sealed", self.name())
    }
}

pub(crate) struct SignerStore {
    dir: PathBuf,
    network: Network,
    vault: [u8; 32],
    member: u16,
}

fn network_label(network: Network) -> &'static str {
    match network {
        Network::Regtest => "regtest",
        Network::Testnet => "testnet",
    }
}

impl SignerStore {
    /// Create the data directory (owner-only) and its public metadata, once.
    pub(crate) fn create(
        dir: &Path,
        network: Network,
        vault: [u8; 32],
        member: u16,
    ) -> Result<Self, String> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(|e| format!("signer directory: {e}"))?;
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| format!("signer directory: {e}"))?;
        }
        #[cfg(not(unix))]
        std::fs::create_dir_all(dir).map_err(|e| format!("signer directory: {e}"))?;
        if dir.join(META).exists() {
            return Err("signer directory already holds a signer".into());
        }
        let meta = serde_json::json!({
            "version": 1,
            "network": network_label(network),
            "vault": hex::encode(vault),
            "member": member,
        });
        write_durable(dir, META, meta.to_string().as_bytes())
            .map_err(|e| format!("signer metadata: {e}"))?;
        Ok(Self {
            dir: dir.to_path_buf(),
            network,
            vault,
            member,
        })
    }

    /// Reopen an existing data directory from its public metadata.
    pub(crate) fn open(dir: &Path) -> Result<Self, String> {
        let meta: serde_json::Value = serde_json::from_slice(
            &std::fs::read(dir.join(META)).map_err(|e| format!("signer metadata: {e}"))?,
        )
        .map_err(|_| "signer metadata is not JSON")?;
        let network = match meta["network"].as_str() {
            Some("regtest") => Network::Regtest,
            Some("testnet") => Network::Testnet,
            _ => return Err("signer metadata: network".into()),
        };
        let vault: [u8; 32] = hex::decode(meta["vault"].as_str().unwrap_or(""))
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or("signer metadata: vault")?;
        let member = meta["member"]
            .as_u64()
            .and_then(|m| u16::try_from(m).ok())
            .ok_or("signer metadata: member")?;
        if meta["version"] != 1 {
            return Err("signer metadata: version".into());
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            network,
            vault,
            member,
        })
    }

    pub(crate) fn network(&self) -> Network {
        self.network
    }

    pub(crate) fn vault(&self) -> [u8; 32] {
        self.vault
    }

    pub(crate) fn member(&self) -> u16 {
        self.member
    }

    pub(crate) fn nonce_dir(&self) -> PathBuf {
        self.dir.join("nonces")
    }

    fn binding(&self, kind: FileKind) -> Vec<u8> {
        file_binding(kind.name(), &self.vault, self.member)
    }

    /// Seal and atomically replace one file.
    pub(crate) fn write(
        &self,
        se: &impl SecureElement,
        kind: FileKind,
        epoch: u64,
        plaintext: &[u8],
    ) -> Result<(), String> {
        let sealed = SealedShare::seal_bound(se, epoch, plaintext, &self.binding(kind))?;
        replace_durable(&self.dir, &kind.file(), &sealed.to_bytes())
            .map_err(|e| format!("signer {} file: {e}", kind.name()))
    }

    /// Open one file, or `None` if it does not exist. A file sealed for another type,
    /// vault or member, or under another element, is an error.
    pub(crate) fn read(
        &self,
        se: &impl SecureElement,
        kind: FileKind,
    ) -> Result<Option<(u64, Zeroizing<Vec<u8>>)>, String> {
        let raw = match std::fs::read(self.dir.join(kind.file())) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("signer {} file: {e}", kind.name())),
        };
        let sealed = SealedShare::from_bytes(&raw)?;
        let plain = sealed
            .open_bound(se, &self.binding(kind))
            .map_err(|_| format!("signer {} file does not belong to this signer", kind.name()))?;
        Ok(Some((sealed.backup_epoch, plain)))
    }

    pub(crate) fn remove(&self, kind: FileKind) -> Result<(), String> {
        remove_durable(&self.dir, &kind.file())
            .map_err(|e| format!("signer {} file: {e}", kind.name()))
    }
}
