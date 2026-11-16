//! Crash-safe synchronous file layer for signer storage, shared by the nonce store and
//! the signer's sealed files.
//!
//! Two backends behind one `pub(crate)` API, chosen by target:
//! - **native** (`cfg(not(wasm32))`): `std::fs`. Every write goes to a temporary file that
//!   is fsync'd before it is linked or renamed into place, and the directory is fsync'd
//!   afterwards. This is the audited path and is byte-for-byte unchanged from before the
//!   wasm split.
//! - **wasm** (`cfg(wasm32)`): OPFS `FileSystemSyncAccessHandle`s via the `js/opfs_fs.js`
//!   worker glue. Reads/writes/flush are synchronous (the signer runs in a Web Worker), so
//!   the signing/DKG core stays synchronous and the nonce invariant "persist+flush BEFORE
//!   the commitment is emitted" (`nonce.rs`) holds exactly as on native: `opfsWrite` does
//!   `write` then `flush()` before it returns.
//!
//! The call sites in `store.rs`/`nonce.rs` are identical across targets; only this module
//! differs by `cfg`.

#[cfg(not(target_arch = "wasm32"))]
mod backend {
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

    /// Read `name`; `ErrorKind::NotFound` when it is absent (callers map that to `None`).
    pub(crate) fn read_file(dir: &Path, name: &str) -> io::Result<Vec<u8>> {
        fs::read(dir.join(name))
    }

    /// Whether `name` exists under `dir`.
    pub(crate) fn file_exists(dir: &Path, name: &str) -> bool {
        dir.join(name).exists()
    }

    /// Remove `name` without a directory fsync (the caller fsyncs when it needs to). A
    /// missing file is not an error.
    pub(crate) fn remove_file(dir: &Path, name: &str) -> io::Result<()> {
        match fs::remove_file(dir.join(name)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Create the signer data directory owner-only (0700), idempotently.
    pub(crate) fn create_dir_private(dir: &Path) -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
            fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
        #[cfg(not(unix))]
        fs::create_dir_all(dir)?;
        Ok(())
    }

    /// Create `dir` and any missing parents.
    pub(crate) fn create_dir_all(dir: &Path) -> io::Result<()> {
        fs::create_dir_all(dir)
    }

    /// fsync the directory so prior renames/removes are durable.
    pub(crate) fn sync_dir(dir: &Path) -> io::Result<()> {
        fs::File::open(dir)?.sync_all()
    }
}

#[cfg(target_arch = "wasm32")]
mod backend {
    //! OPFS-backed implementation. Each `(dir, name)` is a path key under the OPFS root the
    //! worker set up; `js/opfs_fs.js` resolves it to a `FileSystemSyncAccessHandle`. The
    //! handle for a path must be pre-opened by the worker (async `opfsPreopen`) before the
    //! synchronous core touches it — see that file for the contract. Durability is `flush()`
    //! inside `opfsWrite`; OPFS has no atomic rename, so `replace_durable` overwrites in
    //! place after flush.
    //!
    //! ponytail: in-place overwrite, no atomic rename (OPFS has none). The nonce invariant
    //! only needs flush-before-emit, which holds; a torn `replace_durable` is bounded to the
    //! sealed `.sealed` files, which are re-derivable, not the write-once nonce/burn records.
    use std::{io, path::Path};
    use wasm_bindgen::prelude::*;

    #[wasm_bindgen(module = "/js/opfs_fs.js")]
    extern "C" {
        #[wasm_bindgen(js_name = opfsRead, catch)]
        fn js_read(path: &str) -> Result<Option<Vec<u8>>, JsValue>;
        #[wasm_bindgen(js_name = opfsWrite, catch)]
        fn js_write(path: &str, bytes: &[u8], create_new: bool) -> Result<(), JsValue>;
        #[wasm_bindgen(js_name = opfsRemove, catch)]
        fn js_remove(path: &str) -> Result<(), JsValue>;
        #[wasm_bindgen(js_name = opfsExists, catch)]
        fn js_exists(path: &str) -> Result<bool, JsValue>;
        #[wasm_bindgen(js_name = opfsMkdir, catch)]
        fn js_mkdir(path: &str) -> Result<(), JsValue>;
    }

    fn err(j: JsValue) -> io::Error {
        io::Error::new(io::ErrorKind::Other, format!("opfs: {j:?}"))
    }
    fn key(dir: &Path, name: &str) -> String {
        dir.join(name).to_string_lossy().into_owned()
    }

    pub(crate) fn write_durable(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
        js_write(&key(dir, name), bytes, true).map_err(err)
    }
    pub(crate) fn replace_durable(dir: &Path, name: &str, bytes: &[u8]) -> io::Result<()> {
        js_write(&key(dir, name), bytes, false).map_err(err)
    }
    pub(crate) fn remove_durable(dir: &Path, name: &str) -> io::Result<()> {
        js_remove(&key(dir, name)).map_err(err)
    }
    pub(crate) fn read_file(dir: &Path, name: &str) -> io::Result<Vec<u8>> {
        match js_read(&key(dir, name)).map_err(err)? {
            Some(b) => Ok(b),
            None => Err(io::Error::from(io::ErrorKind::NotFound)),
        }
    }
    pub(crate) fn file_exists(dir: &Path, name: &str) -> bool {
        js_exists(&key(dir, name)).unwrap_or(false)
    }
    pub(crate) fn remove_file(dir: &Path, name: &str) -> io::Result<()> {
        js_remove(&key(dir, name)).map_err(err)
    }
    pub(crate) fn create_dir_private(dir: &Path) -> io::Result<()> {
        js_mkdir(&dir.to_string_lossy()).map_err(err)
    }
    pub(crate) fn create_dir_all(dir: &Path) -> io::Result<()> {
        js_mkdir(&dir.to_string_lossy()).map_err(err)
    }
    pub(crate) fn sync_dir(_dir: &Path) -> io::Result<()> {
        // OPFS flushes per file inside `opfsWrite`; there is no directory handle to fsync.
        Ok(())
    }
}

pub(crate) use backend::*;
