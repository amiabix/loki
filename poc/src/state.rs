//! Test-only on-disk state for the three member processes.
//!
//! Plain files under a per-member directory. The brief permits this and is explicit
//! about what it does **not** establish: there is no crash or rollback guarantee here,
//! and nothing in this module is evidence for G3.

use std::{fs, io, path::{Path, PathBuf}};

/// One member's private directory. Never committed; see `.gitignore`.
pub struct MemberDir(PathBuf);

impl MemberDir {
    pub fn create(root: &Path, name: &str) -> io::Result<Self> {
        let dir = root.join(name);
        fs::create_dir_all(&dir)?;
        Ok(MemberDir(dir))
    }

    pub fn open(root: &Path, name: &str) -> Self {
        MemberDir(root.join(name))
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn write_hex(&self, file: &str, bytes: &[u8]) -> io::Result<()> {
        fs::write(self.0.join(file), hex::encode(bytes))
    }

    pub fn read_hex(&self, file: &str) -> io::Result<Vec<u8>> {
        let text = fs::read_to_string(self.0.join(file))?;
        hex::decode(text.trim())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    pub fn write_text(&self, file: &str, text: &str) -> io::Result<()> {
        fs::write(self.0.join(file), text)
    }

    pub fn read_text(&self, file: &str) -> io::Result<String> {
        Ok(fs::read_to_string(self.0.join(file))?.trim().to_string())
    }

    pub fn exists(&self, file: &str) -> bool {
        self.0.join(file).exists()
    }
}
