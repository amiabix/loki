use std::{
    fs, io,
    io::Write,
    path::{Path, PathBuf},
};

pub struct MemberDir(PathBuf);

impl MemberDir {
    pub fn create(root: &Path, name: &str) -> io::Result<Self> {
        let dir = root.join(name);
        #[cfg(unix)]
        {
            use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true).mode(0o700).create(&dir)?;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        }
        #[cfg(not(unix))]
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
        hex::decode(text.trim()).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
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

use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use rand_core::{OsRng, RngCore};

const SEAL_MAGIC: &[u8; 9] = b"LOKISEAL\x01";
const SEAL_SALT: usize = 16;
const SEAL_NONCE: usize = 24;
const SEAL_HEADER: usize = SEAL_MAGIC.len() + SEAL_SALT + SEAL_NONCE;

fn seal_cipher(passphrase: &str, salt: &[u8]) -> io::Result<XChaCha20Poly1305> {
    let key = crate::seal_kdf::derive(passphrase, salt)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid sealing salt"))?;
    XChaCha20Poly1305::new_from_slice(&*key).map_err(|_| io::Error::other("invalid sealing key"))
}

impl MemberDir {
    pub fn write_sealed(&self, file: &str, bytes: &[u8], passphrase: &str) -> io::Result<()> {
        let mut header = [0u8; SEAL_HEADER];
        header[..SEAL_MAGIC.len()].copy_from_slice(SEAL_MAGIC);
        OsRng.fill_bytes(&mut header[SEAL_MAGIC.len()..]);

        let cipher = seal_cipher(
            passphrase,
            &header[SEAL_MAGIC.len()..SEAL_MAGIC.len() + SEAL_SALT],
        )?;
        let nonce = XNonce::from_slice(&header[SEAL_MAGIC.len() + SEAL_SALT..]);
        let sealed = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: bytes,
                    aad: &header,
                },
            )
            .map_err(|e| io::Error::other(e.to_string()))?;

        let mut out = header.to_vec();
        out.extend_from_slice(&sealed);
        let path = self.0.join(file);
        let temp = self
            .0
            .join(format!(".{file}.{}.tmp", hex::encode(&header[9..25])));
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut handle = options.open(&temp)?;
        let result = (|| {
            handle.write_all(&out)?;
            handle.sync_all()?;
            fs::hard_link(&temp, &path)?;
            fs::remove_file(&temp)?;
            #[cfg(unix)]
            fs::File::open(&self.0)?.sync_all()?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }

    pub fn read_sealed(&self, file: &str, passphrase: &str) -> io::Result<Vec<u8>> {
        let raw = fs::read(self.0.join(file))?;
        if raw.len() < SEAL_HEADER || &raw[..SEAL_MAGIC.len()] != SEAL_MAGIC {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a sealed file, or an unknown format version",
            ));
        }
        let (header, sealed) = raw.split_at(SEAL_HEADER);

        let cipher = seal_cipher(
            passphrase,
            &header[SEAL_MAGIC.len()..SEAL_MAGIC.len() + SEAL_SALT],
        )?;
        let nonce = XNonce::from_slice(&header[SEAL_MAGIC.len() + SEAL_SALT..]);
        cipher
            .decrypt(
                nonce,
                Payload {
                    msg: sealed,
                    aad: header,
                },
            )
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "sealed file failed authentication: wrong passphrase or tampered file",
                )
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> MemberDir {
        let mut suffix = [0u8; 8];
        OsRng.fill_bytes(&mut suffix);
        let root = std::env::temp_dir().join(format!("loki-seal-{tag}-{}", hex::encode(suffix)));
        MemberDir::create(&root, "member").expect("a scratch directory under the temp dir")
    }

    #[test]
    fn sealed_secret_round_trips() {
        let dir = scratch("roundtrip");
        let secret = b"a FROST signing share's worth of bytes, give or take";
        dir.write_sealed("key_package.hex", secret, "correct horse")
            .unwrap();

        assert_eq!(
            dir.read_sealed("key_package.hex", "correct horse").unwrap(),
            secret,
            "opening with the right passphrase returns the exact original bytes"
        );
    }

    #[test]
    fn sealed_secret_cannot_be_replaced() {
        let dir = scratch("no-replace");
        dir.write_sealed("vault.sealed", b"first vault", "pass")
            .unwrap();
        assert!(dir
            .write_sealed("vault.sealed", b"second vault", "pass")
            .is_err());
        assert_eq!(
            dir.read_sealed("vault.sealed", "pass").unwrap(),
            b"first vault"
        );
    }

    #[cfg(unix)]
    #[test]
    fn member_secret_store_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch("permissions");
        dir.write_sealed("identity.sealed", b"secret", "passphrase")
            .unwrap();
        assert_eq!(
            fs::metadata(dir.path()).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(dir.path().join("identity.sealed"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn wrong_passphrase_is_an_error_not_garbage() {
        let dir = scratch("wrongpass");
        dir.write_sealed("key_package.hex", b"share", "correct horse")
            .unwrap();

        let opened = dir.read_sealed("key_package.hex", "incorrect horse");
        assert!(
            opened.is_err(),
            "a wrong passphrase must fail, never return plaintext"
        );
        assert_eq!(opened.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn a_single_flipped_ciphertext_bit_is_detected() {
        let dir = scratch("tamper");
        dir.write_sealed("key_package.hex", b"a share worth forging", "correct horse")
            .unwrap();

        let path = dir.path().join("key_package.hex");
        let mut raw = fs::read(&path).unwrap();
        raw[SEAL_HEADER] ^= 0x01;
        fs::write(&path, &raw).unwrap();

        assert!(
            dir.read_sealed("key_package.hex", "correct horse").is_err(),
            "the Poly1305 tag must reject a one-bit edit of the ciphertext"
        );
    }

    #[test]
    fn the_sealed_file_does_not_contain_the_plaintext() {
        let dir = scratch("opaque");
        let secret = b"ZEBRAFISH-MARKER-DO-NOT-LEAK";
        dir.write_sealed("key_package.hex", secret, "correct horse")
            .unwrap();

        let raw = fs::read(dir.path().join("key_package.hex")).unwrap();
        assert!(
            !raw.windows(secret.len()).any(|w| w == secret),
            "the plaintext must not appear anywhere in the sealed file"
        );
        assert_eq!(
            raw.len(),
            SEAL_HEADER + secret.len() + 16,
            "header + ciphertext + tag"
        );
    }

    #[test]
    fn a_flipped_salt_bit_is_detected() {
        let md = scratch("salt");
        md.write_sealed("k.sealed", b"the signing share", "pass")
            .unwrap();

        let path = md.path().join("k.sealed");
        let mut raw = fs::read(&path).unwrap();
        raw[SEAL_MAGIC.len()] ^= 1;
        fs::write(&path, &raw).unwrap();

        assert!(
            md.read_sealed("k.sealed", "pass").is_err(),
            "a damaged salt must not open",
        );
    }

    #[test]
    fn two_seals_of_the_same_secret_differ() {
        let dir = scratch("freshness");
        dir.write_sealed("a", b"same secret", "same passphrase")
            .unwrap();
        dir.write_sealed("b", b"same secret", "same passphrase")
            .unwrap();

        assert_ne!(
            fs::read(dir.path().join("a")).unwrap(),
            fs::read(dir.path().join("b")).unwrap(),
            "fresh salt and nonce per write"
        );
    }
}
