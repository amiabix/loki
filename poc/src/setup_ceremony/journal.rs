use chacha20poly1305::{
    aead::{Aead, Payload},
    KeyInit, XChaCha20Poly1305, XNonce,
};
use rand_core::{OsRng, RngCore};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Component, Path, PathBuf},
    sync::Arc,
};
use zeroize::Zeroizing;

const ERROR: &str = "setup_journal";
const MAGIC: &[u8; 8] = b"LOKIJRN1";
const HEADER: usize = 8 + 32 + 2 + 8 + 16 + 24;
const MAX_PAYLOAD: usize = 16 * 1024 * 1024;
const MAX_GENERATIONS: u64 = 64;
const MAX_DISK: u64 = 128 * 1024 * 1024;

pub(crate) struct Generation {
    pub number: u64,
    pub predecessor: [u8; 32],
    pub digest: [u8; 32],
    pub operation: [u8; 32],
    pub payload: Zeroizing<Vec<u8>>,
}
pub(crate) struct Journal {
    root: PathBuf,
    passphrase: Zeroizing<String>,
    context: [u8; 32],
    member: u16,
    tail: Option<Generation>,
    disk_bytes: u64,
    poisoned: bool,
    _lock: HeldLock,
}
fn random32() -> [u8; 32] {
    let mut value = [0; 32];
    OsRng.fill_bytes(&mut value);
    value
}
fn filename(number: u64) -> String {
    format!("generation-{number:08}.sealed")
}
fn checked(metadata: &fs::Metadata, directory: bool) -> Result<(), String> {
    checked_links(metadata, directory, 1)
}
fn checked_links(metadata: &fs::Metadata, directory: bool, links: u64) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        unsafe extern "C" {
            fn geteuid() -> u32;
        }
        // The effective user ID identifies the owner of this process's private files.
        let uid = unsafe { geteuid() };
        let mode = if directory { 0o700 } else { 0o600 };
        if metadata.uid() == uid
            && metadata.permissions().mode() & 0o7777 == mode
            && if directory {
                metadata.is_dir()
            } else {
                metadata.is_file() && metadata.nlink() == links
            }
        {
            return Ok(());
        }
    }
    Err(ERROR.into())
}
fn nofollow(options: &mut OpenOptions) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        #[cfg(target_os = "macos")]
        const NOFOLLOW: i32 = 0x100;
        #[cfg(not(target_os = "macos"))]
        const NOFOLLOW: i32 = 0x20000;
        options.mode(0o600).custom_flags(NOFOLLOW);
    }
}
pub(crate) fn checked_file(path: &Path) -> Result<File, String> {
    checked(&fs::symlink_metadata(path).map_err(|_| ERROR)?, false)?;
    let mut options = OpenOptions::new();
    options.read(true);
    nofollow(&mut options);
    let file = options.open(path).map_err(|_| ERROR)?;
    checked(&file.metadata().map_err(|_| ERROR)?, false)?;
    Ok(file)
}
pub(crate) fn check_private_root(path: &Path) -> Result<(), String> {
    let mut prefix = PathBuf::new();
    if !path.is_absolute() {
        return Err(ERROR.into());
    }
    for component in path.components() {
        if matches!(component, Component::ParentDir) {
            return Err(ERROR.into());
        }
        prefix.push(component);
        if !fs::symlink_metadata(&prefix).map_err(|_| ERROR)?.is_dir() {
            return Err(ERROR.into());
        }
    }
    checked(&fs::symlink_metadata(path).map_err(|_| ERROR)?, true)
}
struct HeldLock(File);
impl std::ops::Deref for HeldLock {
    type Target = File;
    fn deref(&self) -> &File {
        &self.0
    }
}
impl Drop for HeldLock {
    fn drop(&mut self) {
        let _ = self.0.unlock();
    }
}
pub(crate) struct MemberLock {
    file: Arc<HeldLock>,
    path: PathBuf,
}
impl MemberLock {
    pub(crate) fn share_for(&self, path: &Path) -> Result<Self, String> {
        if self.path != path {
            return Err("setup_worker_locked".into());
        }
        let current = checked_file(path)?;
        let expected = self.file.metadata().map_err(|_| ERROR)?;
        checked(&expected, false)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let actual = current.metadata().map_err(|_| ERROR)?;
            if actual.dev() != expected.dev() || actual.ino() != expected.ino() {
                return Err("setup_worker_locked".into());
            }
        }
        #[cfg(not(unix))]
        return Err(ERROR.into());
        Ok(Self {
            file: Arc::clone(&self.file),
            path: self.path.clone(),
        })
    }
}
pub(crate) fn lock_file(path: &Path) -> Result<MemberLock, String> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    nofollow(&mut options);
    let lock = options.open(path).map_err(|_| ERROR)?;
    checked(&lock.metadata().map_err(|_| ERROR)?, false)?;
    lock.try_lock().map_err(|_| "setup_worker_locked")?;
    Ok(MemberLock {
        file: Arc::new(HeldLock(lock)),
        path: path.to_owned(),
    })
}
fn cipher(passphrase: &str, salt: &[u8]) -> Result<XChaCha20Poly1305, String> {
    let key = crate::seal_kdf::derive(passphrase, salt).map_err(|_| ERROR)?;
    Ok(XChaCha20Poly1305::new_from_slice(&*key).map_err(|_| ERROR)?)
}
fn temporary_final(name: &str) -> Option<String> {
    let body = name.strip_prefix('.')?.strip_suffix(".tmp")?;
    let (base, random) = body.rsplit_once('.')?;
    let number = base
        .strip_prefix("generation-")?
        .strip_suffix(".sealed")?
        .parse::<u64>()
        .ok()?;
    if !(1..=MAX_GENERATIONS).contains(&number)
        || filename(number) != base
        || random.len() != 64
        || !random
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    Some(base.to_owned())
}
fn recover_linked_temporary(root: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mut count = 0;
        for entry in fs::read_dir(root).map_err(|_| ERROR)? {
            count += 1;
            if count > 129 {
                return Err(ERROR.into());
            }
            let entry = entry.map_err(|_| ERROR)?;
            let name = entry.file_name().into_string().map_err(|_| ERROR)?;
            if let Some(final_name) = temporary_final(&name) {
                let temp = fs::symlink_metadata(entry.path()).map_err(|_| ERROR)?;
                if temp.nlink() == 2 {
                    checked_links(&temp, false, 2)?;
                    let final_meta =
                        fs::symlink_metadata(root.join(final_name)).map_err(|_| ERROR)?;
                    checked_links(&final_meta, false, 2)?;
                    if temp.dev() != final_meta.dev() || temp.ino() != final_meta.ino() {
                        return Err(ERROR.into());
                    }
                    fs::remove_file(entry.path()).map_err(|_| ERROR)?;
                    File::open(root)
                        .map_err(|_| ERROR)?
                        .sync_all()
                        .map_err(|_| ERROR)?;
                }
            }
        }
    }
    Ok(())
}
impl Journal {
    pub fn open(
        root: &Path,
        passphrase: &str,
        context: [u8; 32],
        member: u16,
    ) -> Result<Self, String> {
        if passphrase.is_empty()
            || passphrase.len() > 4096
            || context == [0; 32]
            || !(1..=crate::member_state::MAX_MEMBERS).contains(&member)
        {
            return Err(ERROR.into());
        }
        let root = if root.is_absolute() {
            root.to_owned()
        } else {
            std::env::current_dir().map_err(|_| ERROR)?.join(root)
        };
        let mut prefix = PathBuf::new();
        for component in root.components() {
            if matches!(component, Component::ParentDir) {
                return Err(ERROR.into());
            }
            prefix.push(component);
            if prefix != root && !fs::symlink_metadata(&prefix).map_err(|_| ERROR)?.is_dir() {
                return Err(ERROR.into());
            }
        }
        match fs::symlink_metadata(&root) {
            Ok(meta) => checked(&meta, true)?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::DirBuilderExt;
                    fs::DirBuilder::new()
                        .mode(0o700)
                        .create(&root)
                        .map_err(|_| ERROR)?;
                }
                #[cfg(not(unix))]
                {
                    return Err(ERROR.into());
                }
                checked(&fs::symlink_metadata(&root).map_err(|_| ERROR)?, true)?;
                File::open(root.parent().ok_or(ERROR)?)
                    .map_err(|_| ERROR)?
                    .sync_all()
                    .map_err(|_| ERROR)?;
            }
            Err(_) => return Err(ERROR.into()),
        }
        let lock_path = root.join(".journal.lock");
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        nofollow(&mut options);
        let lock = options.open(&lock_path).map_err(|_| ERROR)?;
        checked(&lock.metadata().map_err(|_| ERROR)?, false)?;
        lock.try_lock().map_err(|_| "setup_worker_locked")?;
        let lock = HeldLock(lock);
        File::open(&root)
            .map_err(|_| ERROR)?
            .sync_all()
            .map_err(|_| ERROR)?;
        recover_linked_temporary(&root)?;
        let mut names = std::collections::BTreeMap::new();
        let mut disk_bytes = 0u64;
        let mut temps = 0;
        for entry in fs::read_dir(&root).map_err(|_| ERROR)? {
            let entry = entry.map_err(|_| ERROR)?;
            let name = entry.file_name().into_string().map_err(|_| ERROR)?;
            checked(
                &fs::symlink_metadata(entry.path()).map_err(|_| ERROR)?,
                false,
            )?;
            if name == ".journal.lock" {
                continue;
            }
            let size = entry.metadata().map_err(|_| ERROR)?.len();
            disk_bytes = disk_bytes
                .checked_add(size)
                .filter(|n| *n <= MAX_DISK)
                .ok_or(ERROR)?;
            if name.starts_with(".generation-") && name.ends_with(".tmp") {
                temps += 1;
                if temps > 64 || temporary_final(&name).is_none() {
                    return Err(ERROR.into());
                }
                continue;
            }
            let number = name
                .strip_prefix("generation-")
                .and_then(|n| n.strip_suffix(".sealed"))
                .and_then(|n| n.parse::<u64>().ok())
                .ok_or(ERROR)?;
            if !(1..=MAX_GENERATIONS).contains(&number)
                || filename(number) != name
                || names.insert(number, entry.path()).is_some()
            {
                return Err(ERROR.into());
            }
        }
        let mut journal = Self {
            root,
            passphrase: Zeroizing::new(passphrase.to_owned()),
            context,
            member,
            tail: None,
            disk_bytes,
            poisoned: false,
            _lock: lock,
        };
        for (number, path) in names {
            let expected = journal.tail.as_ref().map_or(1, |g| g.number + 1);
            if number != expected {
                return Err(ERROR.into());
            }
            let generation = journal.read(&path, number)?;
            if generation.predecessor != journal.tail.as_ref().map_or([0; 32], |g| g.digest) {
                return Err(ERROR.into());
            }
            journal.tail = Some(generation);
        }
        Ok(journal)
    }
    pub fn latest(&self) -> Option<&Generation> {
        self.tail.as_ref()
    }
    fn read(&self, path: &Path, number: u64) -> Result<Generation, String> {
        let file = checked_file(path)?;
        let size = file.metadata().map_err(|_| ERROR)?.len();
        if size < (HEADER + 16 + 68) as u64 || size > (HEADER + 16 + 68 + MAX_PAYLOAD) as u64 {
            return Err(ERROR.into());
        }
        let mut raw = Vec::with_capacity(size as usize);
        file.take(size + 1)
            .read_to_end(&mut raw)
            .map_err(|_| ERROR)?;
        if raw.len() != size as usize
            || &raw[..8] != MAGIC
            || raw[8..40] != self.context
            || raw[40..42] != self.member.to_be_bytes()
            || raw[42..50] != number.to_be_bytes()
        {
            return Err(ERROR.into());
        }
        let digest = *blake3::hash(&raw).as_bytes();
        let header = &raw[..HEADER];
        let plain = Zeroizing::new(
            cipher(&self.passphrase, &header[50..66])?
                .decrypt(
                    XNonce::from_slice(&header[66..90]),
                    Payload {
                        msg: &raw[HEADER..],
                        aad: header,
                    },
                )
                .map_err(|_| ERROR)?,
        );
        if plain.len() < 68 {
            return Err(ERROR.into());
        }
        let predecessor = plain[..32].try_into().map_err(|_| ERROR)?;
        let operation = plain[32..64].try_into().map_err(|_| ERROR)?;
        let len = u32::from_be_bytes(plain[64..68].try_into().map_err(|_| ERROR)?) as usize;
        if operation == [0; 32] || len > MAX_PAYLOAD || plain.len() != 68 + len {
            return Err(ERROR.into());
        }
        Ok(Generation {
            number,
            predecessor,
            digest,
            operation,
            payload: Zeroizing::new(plain[68..].to_vec()),
        })
    }
    pub fn append(&mut self, payload: &[u8]) -> Result<&Generation, String> {
        if self.poisoned {
            return Err(ERROR.into());
        }
        let number = self.tail.as_ref().map_or(1, |g| g.number + 1);
        let size = (HEADER + 16 + 68 + payload.len()) as u64;
        if payload.len() > MAX_PAYLOAD
            || number > MAX_GENERATIONS
            || self
                .disk_bytes
                .checked_add(size)
                .filter(|n| *n <= MAX_DISK)
                .is_none()
        {
            return Err(ERROR.into());
        }
        let predecessor = self.tail.as_ref().map_or([0; 32], |g| g.digest);
        let operation = random32();
        let mut header = MAGIC.to_vec();
        header.extend_from_slice(&self.context);
        header.extend_from_slice(&self.member.to_be_bytes());
        header.extend_from_slice(&number.to_be_bytes());
        let mut salt_nonce = [0; 40];
        OsRng.fill_bytes(&mut salt_nonce);
        header.extend_from_slice(&salt_nonce);
        let mut plain = Zeroizing::new(Vec::with_capacity(68 + payload.len()));
        plain.extend_from_slice(&predecessor);
        plain.extend_from_slice(&operation);
        plain.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        plain.extend_from_slice(payload);
        let encrypted = cipher(&self.passphrase, &header[50..66])?
            .encrypt(
                XNonce::from_slice(&header[66..90]),
                Payload {
                    msg: &plain,
                    aad: &header,
                },
            )
            .map_err(|_| ERROR)?;
        let mut raw = header;
        raw.extend_from_slice(&encrypted);
        let digest = *blake3::hash(&raw).as_bytes();
        let name = filename(number);
        let temporary = self
            .root
            .join(format!(".{name}.{}.tmp", hex::encode(random32())));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        nofollow(&mut options);
        let mut file = options.open(&temporary).map_err(|_| ERROR)?;
        let result = (|| -> Result<(), String> {
            file.write_all(&raw).map_err(|_| ERROR)?;
            file.sync_all().map_err(|_| ERROR)?;
            fs::hard_link(&temporary, self.root.join(&name)).map_err(|_| ERROR)?;
            fs::remove_file(&temporary).map_err(|_| ERROR)?;
            File::open(&self.root)
                .map_err(|_| ERROR)?
                .sync_all()
                .map_err(|_| ERROR)?;
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
            let _ = fs::remove_file(&temporary);
            return Err(ERROR.into());
        }
        self.disk_bytes += size;
        self.tail = Some(Generation {
            number,
            predecessor,
            digest,
            operation,
            payload: Zeroizing::new(payload.to_vec()),
        });
        #[cfg(feature = "setup-fault-injection")]
        pause_owned_checkpoint(
            &self.root,
            self.tail.as_ref().expect("committed generation"),
        )?;
        Ok(self.tail.as_ref().expect("committed generation"))
    }
}

#[cfg(all(feature = "setup-fault-injection", not(debug_assertions)))]
compile_error!("setup fault injection is restricted to debug acceptance builds");

#[cfg(feature = "setup-fault-injection")]
fn pause_owned_checkpoint(root: &Path, generation: &Generation) -> Result<(), String> {
    let Some(selected) = std::env::var_os("LOKI_SETUP_TEST_PAUSE_ROOT") else {
        return Ok(());
    };
    let selected_phase = std::env::var("LOKI_SETUP_TEST_PAUSE_PHASE").unwrap_or_default();
    let phase = generation.payload.get(8).copied().unwrap_or(255);
    let all = selected_phase == "all";
    if Path::new(&selected) != root
        || !generation.payload.starts_with(b"LOKIENG1")
        || (all && (phase == 1 || phase > 8))
        || (!all && selected_phase.parse::<u8>().ok() != Some(phase))
    {
        return Ok(());
    }
    let marker_root = root.parent().ok_or(ERROR)?;
    let marker = marker_root.join(if all {
        format!("checkpoint-paused-{phase}.json")
    } else {
        "checkpoint-paused.json".into()
    });
    if marker.exists() {
        return Ok(());
    }
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(marker)
        .map_err(|_| ERROR)?;
    output.write_all(serde_json::to_string(&serde_json::json!({"generation":generation.number,"digest":hex::encode(generation.digest),"phase":phase})).map_err(|_| ERROR)?.as_bytes()).map_err(|_| ERROR)?;
    output.sync_all().map_err(|_| ERROR)?;
    File::open(marker_root)
        .map_err(|_| ERROR)?
        .sync_all()
        .map_err(|_| ERROR)?;
    loop {
        std::thread::park();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn root(tag: &str) -> PathBuf {
        let root = std::env::temp_dir()
            .canonicalize()
            .unwrap()
            .join(format!("loki-journal-{tag}-{}", hex::encode(random32())));
        fs::create_dir(&root).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        }
        root
    }
    #[test]
    fn released_owner_unlocks_even_with_an_inherited_descriptor() {
        let root = root("inherited-lock");
        let path = root.join(".member.lock");
        let owner = lock_file(&path).unwrap();
        let shared = owner.share_for(&path).unwrap();
        let inherited = owner.file.try_clone().unwrap();
        drop(owner);
        assert!(lock_file(&path).is_err());
        drop(shared);
        let released = lock_file(&path).unwrap();
        drop(released);
        drop(inherited);
        let journal = Journal::open(&root.join("journal"), "pass", [3; 32], 1).unwrap();
        let inherited = journal._lock.try_clone().unwrap();
        drop(journal);
        let released = Journal::open(&root.join("journal"), "pass", [3; 32], 1).unwrap();
        drop(released);
        drop(inherited);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn sealed_chain_reopens_exact_bytes_and_rejects_corruption_or_rollback() {
        let root = root("chain");
        let mut journal = Journal::open(&root, "pass", [3; 32], 4).unwrap();
        let first = journal
            .append(b"private contribution and saved ciphertext")
            .unwrap();
        let first = (first.digest, first.operation);
        let second = journal.append(b"next exact package").unwrap();
        let second = (second.predecessor, second.digest, second.operation);
        assert_eq!(second.0, first.0);
        assert_ne!(second.2, first.1);
        assert!(Journal::open(&root, "pass", [3; 32], 4).is_err());
        drop(journal);
        assert!(Journal::open(&root, "wrong", [3; 32], 4).is_err());
        assert!(Journal::open(&root, "pass", [4; 32], 4).is_err());
        assert!(Journal::open(&root, "pass", [3; 32], 3).is_err());
        let journal = Journal::open(&root, "pass", [3; 32], 4).unwrap();
        let saved = journal.latest().unwrap();
        assert_eq!(saved.digest, second.1);
        assert_eq!(saved.operation, second.2);
        assert_eq!(&*saved.payload, b"next exact package");
        for entry in fs::read_dir(&root).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|s| s.to_str()) == Some("sealed") {
                let raw = fs::read(&path).unwrap();
                assert!(!raw.windows(20).any(|w| w == b"private contribution"));
            }
        }
        drop(journal);
        fs::remove_file(root.join(filename(1))).unwrap();
        assert!(Journal::open(&root, "pass", [3; 32], 4).is_err());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn committed_generation_recovers_an_interrupted_temporary_unlink() {
        let root = root("linked-temp");
        let mut journal = Journal::open(&root, "pass", [3; 32], 1).unwrap();
        let saved = journal.append(b"complete generation").unwrap().digest;
        drop(journal);
        let temporary = root.join(format!(".{}.{}.tmp", filename(1), hex::encode([4; 32])));
        fs::hard_link(root.join(filename(1)), &temporary).unwrap();
        let journal = Journal::open(&root, "pass", [3; 32], 1).unwrap();
        assert_eq!(journal.latest().unwrap().digest, saved);
        assert!(!temporary.exists());
        drop(journal);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn rejects_insecure_files_symlinks_and_damaged_latest_without_fallback() {
        let root = root("damage");
        let mut journal = Journal::open(&root, "pass", [3; 32], 1).unwrap();
        journal.append(b"first").unwrap();
        journal.append(b"second").unwrap();
        drop(journal);
        let path = root.join(filename(2));
        let mut raw = fs::read(&path).unwrap();
        *raw.last_mut().unwrap() ^= 1;
        fs::write(&path, raw).unwrap();
        assert!(Journal::open(&root, "pass", [3; 32], 1).is_err());
        #[cfg(unix)]
        {
            use std::os::unix::fs::{symlink, PermissionsExt};
            fs::set_permissions(root.join(filename(1)), fs::Permissions::from_mode(0o644)).unwrap();
            assert!(Journal::open(&root, "pass", [3; 32], 1).is_err());
            fs::remove_file(root.join(filename(1))).unwrap();
            symlink(".journal.lock", root.join(filename(1))).unwrap();
            assert!(Journal::open(&root, "pass", [3; 32], 1).is_err());
        }
        fs::remove_dir_all(root).unwrap();
    }
}
