//! Crash-safe file writes for signer storage, shared by the nonce store and the signer's
//! sealed files. Every write goes to a temporary file that is fsync'd before it is linked
//! or renamed into place, and the directory is fsync'd afterwards.

use std::{
    fs,
    io::{self, Write},
    path::Path,
};

fn write_temp(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<std::path::PathBuf> {
    let temp = dir.join(format!(".{name}.tmp"));
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(temp)
}

/// Create `name` once: fsync a temporary file, then hard-link it into place. An existing
/// `name` is kept, so a write-once record is never replaced.
pub(crate) fn write_durable(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    let final_path = dir.join(name);
    let temp = write_temp(dir, name, bytes)?;
    match fs::hard_link(&temp, &final_path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(e),
    }
    fs::remove_file(&temp)?;
    fs::File::open(dir)?.sync_all()
}

/// Replace `name` atomically: fsync a temporary file, then rename it over `name`. A crash
/// leaves either the old or the new contents, never a mix.
pub(crate) fn replace_durable(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
    let temp = write_temp(dir, name, bytes)?;
    fs::rename(&temp, dir.join(name))?;
    fs::File::open(dir)?.sync_all()
}

/// Remove `name` if present, then fsync the directory. Removing a missing file succeeds.
pub(crate) fn remove_durable(dir: &Path, name: &str) -> io::Result<()> {
    match fs::remove_file(dir.join(name)) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    fs::File::open(dir)?.sync_all()
}
