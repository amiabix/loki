use crate::{RelayError, RelayResult};
use ed25519_dalek::{Signer, SigningKey};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

pub(crate) struct Root {
    pub path: PathBuf,
    _lock: File,
    pub run_id: [u8; 32],
    pub public_key: [u8; 32],
    signing_key: SigningKey,
}

pub(crate) fn publish(path: &Path, bytes: &[u8]) -> RelayResult<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(path.parent().ok_or(RelayError::StorageUnavailable)?)?.sync_all()?;
    Ok(())
}

impl Root {
    pub(crate) fn sign_receipt(&self, body: &[u8]) -> RelayResult<[u8; 64]> {
        let length = u32::try_from(body.len()).map_err(|_| RelayError::StorageUnavailable)?;
        let mut signed = b"Loki_Relay_Stored_v1\0".to_vec();
        signed.extend_from_slice(&length.to_be_bytes());
        signed.extend_from_slice(body);
        Ok(self.signing_key.sign(&signed).to_bytes())
    }

    pub fn open(path: &Path) -> RelayResult<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let root = fs::symlink_metadata(path)?;
            if !root.is_dir() || root.permissions().mode() & 0o777 != 0o700 {
                return Err(RelayError::StorageUnavailable);
            }
            for name in ["receipt.seed", "provision.secret"] {
                let secret = fs::symlink_metadata(path.join(name))?;
                if !secret.is_file()
                    || secret.uid() != root.uid()
                    || secret.permissions().mode() & 0o777 != 0o600
                {
                    return Err(RelayError::StorageUnavailable);
                }
            }
        }
        let lock = File::open(path)?;
        lock.try_lock()
            .map_err(|_| RelayError::StorageUnavailable)?;
        let provision = Zeroizing::new(fs::read(path.join("provision.secret"))?);
        if provision.len() != 32 {
            return Err(RelayError::StorageUnavailable);
        }
        let seed = Zeroizing::new(fs::read(path.join("receipt.seed"))?);
        if seed.len() != 32 {
            return Err(RelayError::StorageUnavailable);
        }
        let manifest = fs::read_to_string(path.join("manifest"))?;
        let lines: Vec<_> = manifest.lines().collect();
        if lines.len() != 3 {
            return Err(RelayError::StorageUnavailable);
        }
        let decode = |value: &str| -> RelayResult<[u8; 32]> {
            hex::decode(value)
                .map_err(|_| RelayError::StorageUnavailable)?
                .try_into()
                .map_err(|_| RelayError::StorageUnavailable)
        };
        let public_key = decode(lines[2])?;
        let seed_array = Zeroizing::new(
            <[u8; 32]>::try_from(seed.as_slice()).map_err(|_| RelayError::StorageUnavailable)?,
        );
        let signing_key = SigningKey::from_bytes(&seed_array);
        if signing_key.verifying_key().to_bytes() != public_key {
            return Err(RelayError::StorageUnavailable);
        }
        Ok(Self {
            path: path.to_owned(),
            _lock: lock,
            run_id: decode(lines[1])?,
            public_key,
            signing_key,
        })
    }

    pub fn init(
        path: &Path,
        run_id: [u8; 32],
        url: &str,
        provision: &[u8; 32],
    ) -> RelayResult<Self> {
        if url.is_empty() || url.contains(['\n', '\r']) {
            return Err(RelayError::MalformedRequest);
        }
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(path)?;
        let lock = File::open(path)?;
        lock.try_lock()
            .map_err(|_| RelayError::StorageUnavailable)?;
        File::open(path.parent().ok_or(RelayError::StorageUnavailable)?)?.sync_all()?;
        let mut seed = Zeroizing::new([0; 32]);
        getrandom::fill(seed.as_mut()).map_err(|_| RelayError::StorageUnavailable)?;
        let signing_key = SigningKey::from_bytes(&seed);
        let public_key = signing_key.verifying_key().to_bytes();
        publish(&path.join("receipt.seed"), seed.as_ref())?;
        publish(&path.join("provision.secret"), provision)?;
        publish(
            &path.join("manifest"),
            format!(
                "{}\n{}\n{}\n",
                url,
                hex::encode(run_id),
                hex::encode(public_key)
            )
            .as_bytes(),
        )?;
        Ok(Self {
            path: path.to_owned(),
            _lock: lock,
            run_id,
            public_key,
            signing_key,
        })
    }
}

impl Drop for Root {
    fn drop(&mut self) {
        // Release explicitly when a spawned child temporarily inherits the descriptor.
        let _ = self._lock.unlock();
    }
}
