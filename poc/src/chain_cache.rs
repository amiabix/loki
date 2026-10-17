//! An incremental chain scan, saved sealed between runs.
//!
//! [`scan`] keeps a [`ScanState`] in `<member>/chain/scan.sealed`, so a later scan reads
//! only the blocks mined since the last one instead of the whole chain. The file is
//! sealed with XChaCha20-Poly1305 under a key derived from the vault's full viewing key
//! and vault id: whoever can open it can already rebuild its contents from that key and
//! the chain, so it adds no exposure and costs no Argon2id. A file that fails
//! authentication or parsing is discarded and the chain is scanned again; an old but
//! valid file only means more blocks to read, because the saved tip hash is checked
//! against the node (the reorg rules in [`crate::scan::scan_blocks`]). The node stays the
//! source of truth: `finish` still checks the rebuilt tree root against the node anchor.
//!
//! Writers are serialized by `chain/.lock`. A scan that cannot take the lock within
//! [`LOCK_WAIT`] reads the chain without saving.

use std::fs;
use std::io::{Read, Write};
use std::path::Path;
use std::time::{Duration, Instant};

use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use orchard::keys::FullViewingKey;
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::scan::{scan_blocks, Chain};
use crate::scanstate::ScanState;

const MAGIC: &[u8; 8] = b"LOKISCN\x01";
const LIMIT: u64 = 64 * 1024 * 1024;
pub const LOCK_WAIT: Duration = Duration::from_secs(5);

/// The cache key: BLAKE2b-256 over the viewing key and vault id.
fn key(fvk: &FullViewingKey, vault: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut state = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"Loki_ScanCache1")
        .to_state();
    state.update(&fvk.to_bytes());
    state.update(vault);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(state.finalize().as_bytes());
    out
}

fn seal(fvk: &FullViewingKey, vault: &[u8; 32], state: &ScanState) -> Result<Vec<u8>, String> {
    let cipher = XChaCha20Poly1305::new((&*key(fvk, vault)).into());
    let mut nonce = [0u8; 24];
    OsRng.fill_bytes(&mut nonce);
    let plain = Zeroizing::new(state.encode().into_bytes());
    let sealed = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &plain,
                aad: MAGIC,
            },
        )
        .map_err(|_| "chain cache could not be sealed")?;
    let mut out = MAGIC.to_vec();
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// The saved state, or `None` for a missing, foreign, tampered or unreadable file.
fn open(fvk: &FullViewingKey, vault: &[u8; 32], raw: &[u8]) -> Option<ScanState> {
    if raw.len() < MAGIC.len() + 24 || &raw[..MAGIC.len()] != MAGIC {
        return None;
    }
    let (nonce, sealed) = raw[MAGIC.len()..].split_at(24);
    let plain = Zeroizing::new(
        XChaCha20Poly1305::new((&*key(fvk, vault)).into())
            .decrypt(
                XNonce::from_slice(nonce),
                Payload {
                    msg: sealed,
                    aad: MAGIC,
                },
            )
            .ok()?,
    );
    let mut state = ScanState::decode(std::str::from_utf8(&plain).ok()?).ok()?;
    state.rebuild_own(fvk);
    Some(state)
}

fn private_dir(path: &Path) -> Result<(), String> {
    let mut builder = fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    match builder.create(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            if fs::symlink_metadata(path).map_err(|e| e.to_string())?.is_dir() {
                Ok(())
            } else {
                Err(format!("{} is not a directory", path.display()))
            }
        }
        Err(error) => Err(format!("{}: {error}", path.display())),
    }
}

/// Take `chain/.lock`, waiting up to [`LOCK_WAIT`]. `None` when another scan holds it.
fn lock(directory: &Path) -> Result<Option<fs::File>, String> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(directory.join(".lock"))
        .map_err(|e| format!("chain lock: {e}"))?;
    let end = Instant::now() + LOCK_WAIT;
    loop {
        match file.try_lock() {
            Ok(()) => return Ok(Some(file)),
            Err(fs::TryLockError::WouldBlock) if Instant::now() < end => {
                std::thread::sleep(Duration::from_millis(50))
            }
            Err(fs::TryLockError::WouldBlock) => return Ok(None),
            Err(fs::TryLockError::Error(error)) => return Err(format!("chain lock: {error}")),
        }
    }
}

fn read_saved(path: &Path) -> Option<Vec<u8>> {
    let file = fs::File::open(path).ok()?;
    if file.metadata().ok()?.len() > LIMIT {
        return None;
    }
    let mut raw = Vec::new();
    file.take(LIMIT + 1).read_to_end(&mut raw).ok()?;
    Some(raw)
}

fn write_saved(directory: &Path, raw: &[u8]) -> Result<(), String> {
    let io = |e: std::io::Error| format!("chain cache: {e}");
    let mut random = [0u8; 8];
    OsRng.fill_bytes(&mut random);
    let temp = directory.join(format!(".scan.{}.tmp", hex::encode(random)));
    let result = (|| {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp).map_err(io)?;
        file.write_all(raw).map_err(io)?;
        file.sync_all().map_err(io)?;
        fs::rename(&temp, directory.join("scan.sealed")).map_err(io)?;
        fs::File::open(directory).and_then(|d| d.sync_all()).map_err(io)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

/// Scan state brought up to `tip`, starting from the saved state under `member`.
///
/// `get_block` is the only thing this needs from the node, which lets tests count
/// requests over a canned chain.
pub fn scan_state_with<F>(
    member: &Path,
    fvk: &FullViewingKey,
    vault: &[u8; 32],
    tip: u64,
    get_block: F,
) -> Result<ScanState, String>
where
    F: Fn(u64) -> Result<serde_json::Value, String>,
{
    let directory = member.join("chain");
    private_dir(&directory)?;
    let held = lock(&directory)?;
    let saved = if held.is_some() {
        read_saved(&directory.join("scan.sealed")).and_then(|raw| open(fvk, vault, &raw))
    } else {
        None
    };
    let mut state = saved.unwrap_or_default();
    scan_blocks(fvk, &mut state, tip, get_block)?;
    if held.is_some() {
        write_saved(&directory, &seal(fvk, vault, &state)?)?;
    }
    Ok(state)
}

/// [`crate::scan::scan_chain`] with the sealed incremental cache under `member`.
pub fn scan(
    rpc: &crate::rpc::Rpc,
    member: &Path,
    fvk: &FullViewingKey,
    vault: &[u8; 32],
) -> Result<Chain, String> {
    let state = scan_state(rpc, member, fvk, vault)?;
    state.into_chain(fvk)
}

/// The saved scan state brought up to the node's tip.
pub fn scan_state(
    rpc: &crate::rpc::Rpc,
    member: &Path,
    fvk: &FullViewingKey,
    vault: &[u8; 32],
) -> Result<ScanState, String> {
    let tip = rpc
        .json("getblockcount", "[]")?
        .as_u64()
        .ok_or("getblockcount did not return a number")?;
    scan_state_with(member, fvk, vault, tip, |height| {
        rpc.json("getblock", &format!("[\"{height}\", 2]"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanstate::tests::{a_fvk, action_json, canned_chain, rebranch, tx};
    use std::cell::Cell;

    fn member(name: &str) -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("loki-chain-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    type Summary = (u64, Vec<[u8; 32]>, Vec<(u64, u64)>, Vec<([u8; 32], (u32, String))>);

    fn summary(state: &ScanState, fvk: &FullViewingKey) -> Summary {
        let notes = state.notes(fvk).unwrap();
        (
            state.tip,
            state.cmxs.clone(),
            notes.iter().map(|n| (n.position, n.value_zat)).collect(),
            state.spent.clone().into_iter().collect(),
        )
    }

    /// `chain[h - 1]` is block `h`.
    fn block(chain: &[serde_json::Value], h: u64) -> Result<serde_json::Value, String> {
        chain.get(h as usize - 1).cloned().ok_or_else(|| format!("no block {h}"))
    }

    fn full(fvk: &FullViewingKey, chain: &[serde_json::Value], to: u64) -> ScanState {
        let mut state = ScanState::default();
        scan_blocks(fvk, &mut state, to, |h| block(chain, h)).unwrap();
        state
    }

    /// The canned chain plus a block 7 whose transaction `spend` spends the vault's
    /// first note.
    fn chain_with_spend(vault: &FullViewingKey, decoy: &FullViewingKey) -> (Vec<serde_json::Value>, [u8; 32]) {
        let mut chain = canned_chain(vault, decoy);
        let spent = full(vault, &chain, 6).notes(vault).unwrap()[0].nullifier;
        let mut action = action_json(decoy, 1, 20);
        action["nullifier"] = serde_json::json!(hex::encode(spent));
        chain.push(serde_json::json!({
            "hash": format!("{:064x}", 7),
            "previousblockhash": format!("{:064x}", 6),
            "tx": [tx("spend", vec![action])],
        }));
        (chain, spent)
    }

    #[test]
    fn sealed_cache_reads_only_new_blocks_and_matches_a_full_scan() {
        let (vault_fvk, decoy) = (a_fvk(3), a_fvk(9));
        let (chain, spent) = chain_with_spend(&vault_fvk, &decoy);
        let vault = [9u8; 32];
        let root = member("incremental");
        let calls = Cell::new(0);
        let get = |h: u64| {
            calls.set(calls.get() + 1);
            block(&chain, h)
        };
        let first = scan_state_with(&root, &vault_fvk, &vault, 5, get).unwrap();
        assert_eq!(summary(&first, &vault_fvk), summary(&full(&vault_fvk, &chain, 5), &vault_fvk));
        calls.set(0);
        // Same tip: the saved tip's hash and the end-of-scan check, nothing rescanned.
        scan_state_with(&root, &vault_fvk, &vault, 5, get).unwrap();
        assert_eq!(calls.get(), 2);
        calls.set(0);
        let grown = scan_state_with(&root, &vault_fvk, &vault, 7, get).unwrap();
        assert_eq!(calls.get(), 1 + 2 + 1, "saved tip, two new blocks, end check");
        assert_eq!(summary(&grown, &vault_fvk), summary(&full(&vault_fvk, &chain, 7), &vault_fvk));
        // The spent index names the spending transaction, as a per-block search would.
        assert_eq!(grown.spent.get(&spent), Some(&(7, "spend".to_string())));
        assert_eq!(grown.spent.len(), 1);
        assert_eq!(grown.notes(&vault_fvk).unwrap().len(), 2);
        // The file is sealed: no plaintext commitment or txid in it.
        let raw = fs::read(root.join("chain/scan.sealed")).unwrap();
        assert_eq!(&raw[..8], MAGIC);
        let text = String::from_utf8_lossy(&raw);
        assert!(!text.contains(&hex::encode(grown.cmxs[0])) && !text.contains("spend"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(root.join("chain")).unwrap().permissions().mode() & 0o777, 0o700);
            assert_eq!(fs::metadata(root.join("chain/scan.sealed")).unwrap().permissions().mode() & 0o777, 0o600);
        }
        // A reorg 3 blocks deep resets and matches a full scan of the new branch,
        // which no longer contains the spend.
        let mut branch = chain.clone();
        rebranch(&mut branch, 4);
        branch[6]["tx"] = serde_json::json!([]);
        let reorged = scan_state_with(&root, &vault_fvk, &vault, 7, |h| block(&branch, h)).unwrap();
        assert_eq!(summary(&reorged, &vault_fvk), summary(&full(&vault_fvk, &branch, 7), &vault_fvk));
        assert!(reorged.spent.is_empty());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn foreign_tampered_or_truncated_cache_is_rescanned() {
        let (vault_fvk, decoy) = (a_fvk(3), a_fvk(9));
        let (chain, _) = chain_with_spend(&vault_fvk, &decoy);
        let root = member("tamper");
        scan_state_with(&root, &vault_fvk, &[9; 32], 7, |h| block(&chain, h)).unwrap();
        let path = root.join("chain/scan.sealed");
        let raw = fs::read(&path).unwrap();
        // Only this viewing key and vault open it.
        assert!(open(&decoy, &[9; 32], &raw).is_none());
        assert!(open(&vault_fvk, &[8; 32], &raw).is_none());
        assert!(open(&vault_fvk, &[9; 32], &raw).is_some());
        let expected = summary(&full(&vault_fvk, &chain, 7), &vault_fvk);
        let mut flipped = raw.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 1;
        for broken in [flipped, raw[..raw.len() / 2].to_vec(), b"tip 1\n".to_vec()] {
            fs::write(&path, &broken).unwrap();
            let calls = Cell::new(0);
            let state = scan_state_with(&root, &vault_fvk, &[9; 32], 7, |h| {
                calls.set(calls.get() + 1);
                block(&chain, h)
            })
            .unwrap();
            assert_eq!(calls.get(), 7 + 1, "a bad cache is a full rescan");
            assert_eq!(summary(&state, &vault_fvk), expected);
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn a_held_lock_scans_without_saving() {
        let (vault_fvk, decoy) = (a_fvk(3), a_fvk(9));
        let chain = canned_chain(&vault_fvk, &decoy);
        let root = member("lock");
        fs::create_dir_all(root.join("chain")).unwrap();
        let other = lock(&root.join("chain")).unwrap().unwrap();
        let started = Instant::now();
        let state = scan_state_with(&root, &vault_fvk, &[9; 32], 2, |h| block(&chain, h)).unwrap();
        assert!(started.elapsed() >= LOCK_WAIT);
        assert_eq!(state.tip, 2);
        assert!(!root.join("chain/scan.sealed").exists());
        drop(other);
        fs::remove_dir_all(root).unwrap();
    }
}
