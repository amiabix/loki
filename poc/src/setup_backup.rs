use crate::{
    setup_ceremony::journal::{self, MemberLock},
    state::MemberDir,
};
use bip39::{Language, Mnemonic};
use rand_core::{OsRng, RngCore};
use std::{fs::File, path::Path};
use zeroize::Zeroizing;
const ERROR: &str = "setup_backup";
const LIMIT: u64 = 1024 * 1024;
fn normalized(words: &str) -> Result<Zeroizing<String>, String> {
    let mnemonic = Mnemonic::parse_in(Language::English, words).map_err(|_| ERROR)?;
    if mnemonic.word_count() != 24 {
        return Err(ERROR.into());
    }
    Ok(Zeroizing::new(mnemonic.to_string()))
}
fn sealed(dir: &MemberDir, name: &str, passphrase: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let file = journal::checked_file(&dir.path().join(name))?;
    if file.metadata().map_err(|_| ERROR)?.len() > LIMIT {
        return Err(ERROR.into());
    }
    Ok(Zeroizing::new(
        dir.read_sealed(name, passphrase).map_err(|_| ERROR)?,
    ))
}
fn card(path: &Path, create: bool) -> Result<MemberDir, String> {
    let parent = path.parent().ok_or(ERROR)?;
    journal::check_private_root(parent)?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(ERROR)?;
    if !path.try_exists().map_err(|_| ERROR)? {
        if !create {
            return Err(ERROR.into());
        }
        MemberDir::create(parent, name).map_err(|_| ERROR)?;
        File::open(parent)
            .map_err(|_| ERROR)?
            .sync_all()
            .map_err(|_| ERROR)?;
    }
    journal::check_private_root(path)?;
    Ok(MemberDir::open(parent, name))
}
pub(crate) fn create(
    root: &Path,
    passphrase: &str,
    path: &Path,
    state: &[u8],
    lock: &MemberLock,
) -> Result<Zeroizing<String>, String> {
    let _held = lock.share_for(&root.join("secrets/.setup.lock"))?;
    if state.is_empty() || state.len() as u64 > LIMIT - 65 {
        return Err(ERROR.into());
    }
    let secrets = MemberDir::open(root, "secrets");
    journal::check_private_root(secrets.path())?;
    let destination = card(path, true)?;
    let words = if secrets.exists("backup-words.sealed") {
        let raw = sealed(&secrets, "backup-words.sealed", passphrase)?;
        normalized(std::str::from_utf8(&raw).map_err(|_| ERROR)?)?
    } else {
        if path.join("vault.card").try_exists().map_err(|_| ERROR)? {
            return Err(ERROR.into());
        }
        let mut entropy = Zeroizing::new([0u8; 32]);
        OsRng.fill_bytes(&mut *entropy);
        let words = Zeroizing::new(
            Mnemonic::from_entropy(&*entropy)
                .map_err(|_| ERROR)?
                .to_string(),
        );
        secrets
            .write_sealed("backup-words.sealed", words.as_bytes(), passphrase)
            .map_err(|_| ERROR)?;
        words
    };
    let card = destination;
    if card.exists("vault.card") {
        if sealed(&card, "vault.card", &words)?.as_slice() != state {
            return Err(ERROR.into());
        }
    } else {
        card.write_sealed("vault.card", state, &words)
            .map_err(|_| ERROR)?;
    }
    if sealed(&card, "vault.card", &words)?.as_slice() != state {
        return Err(ERROR.into());
    }
    Ok(words)
}
pub(crate) fn recover(path: &Path, words: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    let words = normalized(words)?;
    sealed(&card(path, false)?, "vault.card", &words)
}
pub(crate) struct PrivateJson(pub serde_json::Value);
impl Drop for PrivateJson {
    fn drop(&mut self) {
        fn wipe(value: &mut serde_json::Value) {
            match value {
                serde_json::Value::String(value) => zeroize::Zeroize::zeroize(value),
                serde_json::Value::Array(values) => values.iter_mut().for_each(wipe),
                serde_json::Value::Object(values) => values.values_mut().for_each(wipe),
                _ => {}
            }
        }
        wipe(&mut self.0);
    }
}
pub(crate) fn finish(
    root: &Path,
    passphrase: &str,
    provisional: &Path,
    destination: &Path,
    entered: &str,
    state: &[u8],
    evidence: &[u8],
    lock: &MemberLock,
) -> Result<(), String> {
    let _held = lock.share_for(&root.join("secrets/.setup.lock"))?;
    if evidence.is_empty() || evidence.len() as u64 > LIMIT - 65 {
        return Err(ERROR.into());
    }
    let words = normalized(entered)?;
    if recover(provisional, &words)?.as_slice() != state {
        return Err(ERROR.into());
    }
    let secrets = MemberDir::open(root, "secrets");
    journal::check_private_root(secrets.path())?;
    if secrets.exists("backup-words.sealed") {
        let saved = sealed(&secrets, "backup-words.sealed", passphrase)?;
        if normalized(std::str::from_utf8(&saved).map_err(|_| ERROR)?)?.as_str() != words.as_str() {
            return Err(ERROR.into());
        }
    }
    let card = card(destination, true)?;
    if !card.exists("vault.card") {
        card.write_sealed("vault.card", evidence, &words)
            .map_err(|_| ERROR)?;
    }
    if sealed(&card, "vault.card", &words)?.as_slice() != evidence {
        return Err(ERROR.into());
    }
    let pending = secrets.path().join("backup-words.sealed");
    if pending.try_exists().map_err(|_| ERROR)? {
        journal::checked_file(&pending)?;
        std::fs::remove_file(&pending).map_err(|_| ERROR)?;
        File::open(secrets.path())
            .map_err(|_| ERROR)?
            .sync_all()
            .map_err(|_| ERROR)?;
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn provisional_card_preserves_words_and_ciphertext_and_checks_private_files() {
        fn wipes_on_drop<T: zeroize::ZeroizeOnDrop>() {}
        wipes_on_drop::<Mnemonic>();
        let root = std::env::temp_dir().canonicalize().unwrap().join(format!(
            "loki-hosted-card-{}",
            hex::encode(rand_core_bytes())
        ));
        let member = MemberDir::create(&root, "member").unwrap();
        MemberDir::create(member.path(), "secrets").unwrap();
        let lock = journal::lock_file(&member.path().join("secrets/.setup.lock")).unwrap();
        let path = member.path().join("card");
        let state = br#"{"version":2,"private":"owned fixture"}"#;
        let words = create(member.path(), "pass", &path, state, &lock).unwrap();
        let first = std::fs::read(path.join("vault.card")).unwrap();
        let same = create(member.path(), "pass", &path, state, &lock).unwrap();
        assert!(words.as_str() == same.as_str());
        assert!(std::fs::read(path.join("vault.card")).unwrap() == first);
        assert!(recover(&path, &words).unwrap().as_slice() == state);
        assert!(create(member.path(), "pass", &path, b"different state", &lock).is_err());
        let wrong = Zeroizing::new(Mnemonic::from_entropy(&[1; 32]).unwrap().to_string());
        assert!(recover(&path, &wrong).is_err());
        let final_card = member.path().join("final-card");
        let evidence = br#"{"recovery_version":2,"state":{"version":2,"private":"owned fixture"},"roster":{},"receipts":{}}"#;
        assert!(finish(
            member.path(),
            "pass",
            &path,
            &final_card,
            &wrong,
            state,
            evidence,
            &lock
        )
        .is_err());
        assert!(member.path().join("secrets/backup-words.sealed").exists());
        finish(
            member.path(),
            "pass",
            &path,
            &final_card,
            &words,
            state,
            evidence,
            &lock,
        )
        .unwrap();
        assert!(!member.path().join("secrets/backup-words.sealed").exists());
        let final_cipher = std::fs::read(final_card.join("vault.card")).unwrap();
        finish(
            member.path(),
            "pass",
            &path,
            &final_card,
            &words,
            state,
            evidence,
            &lock,
        )
        .unwrap();
        assert!(std::fs::read(final_card.join("vault.card")).unwrap() == final_cipher);
        assert!(recover(&final_card, &words).unwrap().as_slice() == evidence);
        let foreign = MemberDir::create(&root, "foreign").unwrap();
        MemberDir::create(foreign.path(), "secrets").unwrap();
        assert!(create(
            foreign.path(),
            "pass",
            &foreign.path().join("card"),
            state,
            &lock
        )
        .is_err());
        assert!(!foreign.path().join("secrets/backup-words.sealed").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(
                path.join("vault.card"),
                std::fs::Permissions::from_mode(0o644),
            )
            .unwrap();
            assert!(recover(&path, &words).is_err());
        }
        drop(lock);
        std::fs::remove_dir_all(root).unwrap();
    }
    fn rand_core_bytes() -> [u8; 32] {
        let mut bytes = [0; 32];
        OsRng.fill_bytes(&mut bytes);
        bytes
    }
}
