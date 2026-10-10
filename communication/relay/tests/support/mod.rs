use std::{
    fs,
    path::{Path, PathBuf},
};

pub struct Scratch(pub PathBuf);
impl Scratch {
    pub fn new() -> Self {
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).unwrap();
        Self(std::env::temp_dir().join(format!("relay-root-{}", hex::encode(nonce))))
    }
    pub fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
