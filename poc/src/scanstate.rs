//! What a scan remembers between runs.
//!
//! A scan that starts at genesis every time is fine on a 70-block regtest chain and
//! impossible at mainnet height. This is the smallest state that lets the next scan skip
//! the blocks the last one already read: how far it got, every Ironwood commitment it
//! saw, and the vault's own actions.
//!
//! The commitment stream is kept in full because that is what [`crate::witness`] needs to
//! rebuild the tree and check its root against the node's anchor. It is bounded by the
//! number of Ironwood actions on the chain, not by the number of blocks, and it is the
//! part that would have to become a frontier plus tracked witnesses before this is a real
//! wallet.

use std::io::Write as _;
use std::path::Path;

use orchard::keys::{FullViewingKey, PreparedIncomingViewingKey};
use rand_core::{OsRng, RngCore};

use crate::scan::{vault_ivks, vault_note_at, Chain, RawAction, VaultNote};

/// One Ironwood action the vault owns, kept exactly as the node reported it.
///
/// The decrypted note is deliberately not stored: orchard's `Note` has no byte encoding,
/// and re-deriving it costs one trial decryption per vault note, which is nothing next to
/// reading the chain again.
pub struct Found {
    pub height: u32,
    pub txid: String,
    pub position: u64,
    pub action: RawAction,
}

/// Everything a scan carries forward to the next one.
#[derive(Default)]
pub struct ScanState {
    /// Hash of the viewing key that selected `found`; absent in older cache files.
    pub viewing_key_id: Option<[u8; 32]>,
    /// The last block height whose actions are already recorded here. `0` means nothing
    /// has been scanned, which is also what the first run sees.
    pub tip: u64,
    /// The canonical hash of `tip`; absent in legacy cache files.
    pub tip_hash: Option<[u8; 32]>,
    /// Every Ironwood commitment up to `tip`, in append order.
    pub cmxs: Vec<[u8; 32]>,
    /// Every nullifier revealed up to `tip`, in the same order as `cmxs`. A vault note
    /// whose nullifier appears here has already been spent, by this vault or by anyone
    /// else holding the key, and must not be offered as an input again.
    pub nfs: Vec<[u8; 32]>,
    /// The vault's own actions, in the same order.
    pub found: Vec<Found>,
}

impl ScanState {
    /// Record one transaction's Ironwood actions, keeping the vault's own.
    pub fn push(
        &mut self,
        fvk: &FullViewingKey,
        ivks: &[PreparedIncomingViewingKey],
        height: u32,
        txid: &str,
        actions: &[RawAction],
    ) {
        for raw in actions {
            // A commitment's position is the number of commitments appended before it,
            // which is exactly what the note commitment tree does.
            let position = self.cmxs.len() as u64;
            self.cmxs.push(raw.cmx);
            self.nfs.push(raw.nullifier);
            if vault_note_at(fvk, ivks, height, txid, position, raw).is_some() {
                self.found.push(Found {
                    height,
                    txid: txid.to_string(),
                    position,
                    action: raw.clone(),
                });
            }
        }
    }

    /// The vault's **unspent** notes, rebuilt from the stored actions.
    ///
    /// Built by the same code as a live scan ([`vault_note_at`]), so a note recovered
    /// from disk cannot drift from one found on the wire.
    ///
    /// A note whose nullifier has already appeared on the chain is dropped: it is gone,
    /// and a proposer handed it would build a candidate the network rejects as a double
    /// spend.
    pub fn notes(&self, fvk: &FullViewingKey) -> Result<Vec<VaultNote>, String> {
        let ivks = vault_ivks(fvk);
        let spent: std::collections::HashSet<_> = self.nfs.iter().collect();
        self.found
            .iter()
            .map(|f| {
                vault_note_at(fvk, &ivks, f.height, &f.txid, f.position, &f.action).ok_or_else(
                    || {
                        format!(
                            "stored action at position {} no longer decrypts to a vault note",
                            f.position
                        )
                    },
                )
            })
            .filter(|n| match n {
                Ok(n) => !spent.contains(&n.nullifier),
                Err(_) => true,
            })
            .collect()
    }

    /// The same value a full chain scan returns, without having read the chain again.
    pub fn into_chain(self, fvk: &FullViewingKey) -> Result<Chain, String> {
        let notes = self.notes(fvk)?;
        Ok(Chain {
            notes,
            cmxs: self.cmxs,
            tip: self.tip,
        })
    }

    /// Read state left by an earlier scan. A missing file is the first scan, not an error.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };

        let mut state = Self::default();
        for (i, line) in text.lines().enumerate() {
            let bad = || format!("{}:{}: malformed scan state", path.display(), i + 1);
            let mut f = line.split_whitespace();
            match f.next() {
                None => continue,
                Some("viewing_key_id") => {
                    state.viewing_key_id = Some(field(&mut f).ok_or_else(bad)?);
                }
                Some("tip") => {
                    state.tip = f.next().and_then(|v| v.parse().ok()).ok_or_else(bad)?;
                    state.tip_hash = match f.next() {
                        Some(hash) => Some(
                            hex::decode(hash)
                                .ok()
                                .and_then(|v| v.try_into().ok())
                                .ok_or_else(bad)?,
                        ),
                        None => None,
                    };
                }
                Some("c") => {
                    state.cmxs.push(field(&mut f).ok_or_else(bad)?);
                    state.nfs.push(field(&mut f).ok_or_else(bad)?);
                }
                Some("n") => {
                    let height = f.next().and_then(|v| v.parse().ok()).ok_or_else(bad)?;
                    let position = f.next().and_then(|v| v.parse().ok()).ok_or_else(bad)?;
                    let txid = f.next().ok_or_else(bad)?.to_string();
                    let action = RawAction {
                        cv: field(&mut f).ok_or_else(bad)?,
                        nullifier: field(&mut f).ok_or_else(bad)?,
                        rk: field(&mut f).ok_or_else(bad)?,
                        cmx: field(&mut f).ok_or_else(bad)?,
                        ephemeral_key: field(&mut f).ok_or_else(bad)?,
                        enc_ciphertext: f
                            .next()
                            .and_then(|s| hex::decode(s).ok())
                            .ok_or_else(bad)?,
                        out_ciphertext: field(&mut f).ok_or_else(bad)?,
                    };
                    state.found.push(Found {
                        height,
                        txid,
                        position,
                        action,
                    });
                }
                Some(_) => return Err(bad()),
            }
        }
        Ok(state)
    }

    /// Write the state for the next scan to pick up.
    ///
    /// One record per line, hex throughout: the file is big enough to want to look at
    /// with `grep` when a scan disagrees with the node.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let io = |e: std::io::Error| format!("{}: {e}", path.display());
        let mut random = [0u8; 8];
        OsRng.fill_bytes(&mut random);
        let temp = path.with_extension(format!("{}.tmp", hex::encode(random)));
        let result = (|| {
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let f = options.open(&temp).map_err(io)?;
            let mut out = std::io::BufWriter::new(f);

            if let Some(key) = self.viewing_key_id {
                writeln!(out, "viewing_key_id {}", hex::encode(key)).map_err(io)?;
            }
            if let Some(hash) = self.tip_hash {
                writeln!(out, "tip {} {}", self.tip, hex::encode(hash)).map_err(io)?;
            } else {
                writeln!(out, "tip {}", self.tip).map_err(io)?;
            }
            for (c, nf) in self.cmxs.iter().zip(self.nfs.iter()) {
                writeln!(out, "c {} {}", hex::encode(c), hex::encode(nf)).map_err(io)?;
            }
            for n in &self.found {
                let a = &n.action;
                writeln!(
                    out,
                    "n {} {} {} {} {} {} {} {} {} {}",
                    n.height,
                    n.position,
                    n.txid,
                    hex::encode(a.cv),
                    hex::encode(a.nullifier),
                    hex::encode(a.rk),
                    hex::encode(a.cmx),
                    hex::encode(a.ephemeral_key),
                    hex::encode(&a.enc_ciphertext),
                    hex::encode(a.out_ciphertext),
                )
                .map_err(io)?;
            }
            out.flush().map_err(io)?;
            out.get_ref().sync_all().map_err(io)?;
            std::fs::rename(&temp, path).map_err(io)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temp);
        }
        result
    }
}

/// The next whitespace-separated field, as exactly `N` bytes of hex.
fn field<'a, const N: usize>(f: &mut impl Iterator<Item = &'a str>) -> Option<[u8; N]> {
    hex::decode(f.next()?).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::scan_blocks;
    use orchard::{
        keys::{Scope, SpendingKey},
        note::{ExtractedNoteCommitment, RandomSeed, Rho},
        note_encryption::{IronwoodDomain, IronwoodNoteEncryption},
        value::NoteValue,
        Note, NoteVersion,
    };
    use zcash_note_encryption::Domain;

    fn a_fvk(seed: u8) -> FullViewingKey {
        FullViewingKey::from(&SpendingKey::from_bytes([seed; 32]).unwrap())
    }

    /// One Ironwood action as the node's JSON reports it, carrying a note for `fvk`.
    ///
    /// `cv` and `rk` only have to be structurally valid points for the action to be
    /// rebuilt; `ak` is one, so it stands in for both.
    fn action_json(fvk: &FullViewingKey, value: u64, seed: u8) -> serde_json::Value {
        // The action's rho IS its nullifier field, so the note has to be built from the
        // same bytes or the domain the scanner derives would not decrypt it.
        let nf = [seed; 32];
        let rho = Rho::from_bytes(&nf).unwrap();
        let rseed = RandomSeed::from_bytes([seed.wrapping_add(1); 32], &rho).unwrap();
        let note = Note::from_parts(
            fvk.address_at(0u64, Scope::External),
            NoteValue::from_raw(value),
            rho,
            rseed,
            NoteVersion::V3,
        )
        .unwrap();

        let enc = IronwoodNoteEncryption::new(None, note, [0u8; 512]);
        let point = hex::encode(&fvk.to_bytes()[0..32]);
        serde_json::json!({
            "cv": point,
            "nullifier": hex::encode(nf),
            "rk": point,
            "cmx": hex::encode(ExtractedNoteCommitment::from(note.commitment()).to_bytes()),
            "ephemeralKey": hex::encode(IronwoodDomain::epk_bytes(enc.epk()).0),
            "encCiphertext": hex::encode(enc.encrypt_note_plaintext()),
            "outCiphertext": hex::encode([0u8; 80]),
        })
    }

    fn tx(txid: &str, actions: Vec<serde_json::Value>) -> serde_json::Value {
        serde_json::json!({ "txid": txid, "ironwood": { "actions": actions } })
    }

    /// Six blocks, `blocks[h - 1]` being block `h` as `getblock` would return it.
    ///
    /// Vault notes sit behind decoys, in more than one block and more than one
    /// transaction, so a wrong position would not survive by luck.
    fn canned_chain(vault: &FullViewingKey, decoy: &FullViewingKey) -> Vec<serde_json::Value> {
        let mut height = 0u8;
        let mut block = |txs: Vec<serde_json::Value>| {
            height += 1;
            serde_json::json!({
                "hash": format!("{:064x}", height),
                "previousblockhash": format!("{:064x}", height - 1),
                "tx": txs,
            })
        };
        vec![
            block(vec![serde_json::json!({ "txid": "coinbase" })]),
            block(vec![tx(
                "aa",
                vec![action_json(decoy, 1, 11), action_json(vault, 100, 12)],
            )]),
            block(vec![]),
            block(vec![tx("bb", vec![action_json(decoy, 2, 13)])]),
            block(vec![
                tx("cc", vec![action_json(vault, 200, 14)]),
                tx(
                    "dd",
                    vec![action_json(decoy, 3, 15), action_json(vault, 300, 16)],
                ),
            ]),
            block(vec![]),
        ]
    }

    fn rebranch(chain: &mut [serde_json::Value], from: usize) {
        for i in from..chain.len() {
            chain[i]["hash"] = serde_json::json!(format!("{:064x}", i + 101));
            chain[i]["previousblockhash"] =
                serde_json::json!(format!("{:064x}", if i == from { i } else { i + 100 }));
        }
    }

    #[test]
    fn same_height_reorg_recomputes_spentness_even_with_unchanged_commitments() {
        let vault = a_fvk(3);
        let decoy = a_fvk(9);
        let mut chain = canned_chain(&vault, &decoy);
        let mut state = ScanState::default();
        scan_blocks(&vault, &mut state, 6, |h| Ok(chain[h as usize - 1].clone())).unwrap();
        let spent = state.notes(&vault).unwrap()[0].nullifier;
        let old_cmxs = state.cmxs.clone();
        let path = std::env::temp_dir().join(format!("loki-reorg-{}.txt", std::process::id()));
        state.save(&path).unwrap();
        let mut state = ScanState::load(&path).unwrap();

        // The replacement action spends a vault note but appends the same commitment.
        chain[4]["tx"][1]["ironwood"]["actions"][0]["nullifier"] =
            serde_json::json!(hex::encode(spent));
        rebranch(&mut chain, 4);
        scan_blocks(&vault, &mut state, 6, |h| Ok(chain[h as usize - 1].clone())).unwrap();
        std::fs::remove_file(&path).unwrap();

        assert_eq!(state.cmxs, old_cmxs);
        let notes = state.notes(&vault).unwrap();
        assert_eq!(notes.len(), 2);
        assert!(notes.iter().all(|note| note.nullifier != spent));
    }

    #[test]
    fn earlier_reorg_followed_by_growth_replaces_old_notes() {
        let vault = a_fvk(3);
        let decoy = a_fvk(9);
        let mut chain = canned_chain(&vault, &decoy);
        let mut state = ScanState::default();
        scan_blocks(&vault, &mut state, 6, |h| Ok(chain[h as usize - 1].clone())).unwrap();
        chain[1]["tx"][0]["ironwood"]["actions"][1] = action_json(&vault, 150, 12);
        rebranch(&mut chain, 1);
        chain.push(serde_json::json!({
            "hash": format!("{:064x}", 107),
            "previousblockhash": format!("{:064x}", 106),
            "tx": [],
        }));

        scan_blocks(&vault, &mut state, 7, |h| Ok(chain[h as usize - 1].clone())).unwrap();
        let notes = state.notes(&vault).unwrap();
        assert_eq!(notes.len(), 3);
        assert_eq!(notes[0].value_zat, 150);
    }

    #[test]
    fn legacy_cache_without_tip_hash_is_rescanned() {
        let vault = a_fvk(3);
        let decoy = a_fvk(9);
        let chain = canned_chain(&vault, &decoy);
        let path = std::env::temp_dir().join(format!("loki-legacy-{}.txt", std::process::id()));
        std::fs::write(&path, "tip 6\n").unwrap();
        let mut state = ScanState::load(&path).unwrap();
        scan_blocks(&vault, &mut state, 6, |h| Ok(chain[h as usize - 1].clone())).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(state.notes(&vault).unwrap().len(), 3);
    }

    #[test]
    fn disconnected_or_malformed_block_is_rejected() {
        let vault = a_fvk(3);
        let decoy = a_fvk(9);
        let mut chain = canned_chain(&vault, &decoy);
        chain[3]["previousblockhash"] = serde_json::json!("ff".repeat(32));
        let mut state = ScanState::default();
        assert!(scan_blocks(&vault, &mut state, 6, |h| Ok(chain[h as usize - 1].clone())).is_err());

        let mut chain = canned_chain(&vault, &decoy);
        chain[1]["hash"] = serde_json::json!("bad hash");
        let mut state = ScanState::default();
        assert!(scan_blocks(&vault, &mut state, 6, |h| Ok(chain[h as usize - 1].clone())).is_err());
    }

    #[test]
    fn changed_tip_during_scan_is_rejected_without_touching_saved_cache() {
        let vault = a_fvk(3);
        let decoy = a_fvk(9);
        let chain = canned_chain(&vault, &decoy);
        let path = std::env::temp_dir().join(format!("loki-race-{}.txt", std::process::id()));
        let mut saved = ScanState::default();
        scan_blocks(&vault, &mut saved, 3, |h| Ok(chain[h as usize - 1].clone())).unwrap();
        saved.save(&path).unwrap();
        let original = std::fs::read(&path).unwrap();
        let mut resumed = ScanState::load(&path).unwrap();
        let reads_of_tip = std::cell::Cell::new(0);
        let result = scan_blocks(&vault, &mut resumed, 6, |h| {
            let mut block = chain[h as usize - 1].clone();
            if h == 6 {
                reads_of_tip.set(reads_of_tip.get() + 1);
                if reads_of_tip.get() > 1 {
                    block["hash"] = serde_json::json!("ff".repeat(32));
                }
            }
            Ok(block)
        });
        assert!(result.is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn saving_replaces_cache_without_truncating_its_previous_inode() {
        let path = std::env::temp_dir().join(format!("loki-atomic-{}.txt", std::process::id()));
        let linked = path.with_extension("linked");
        let state = ScanState::default();
        state.save(&path).unwrap();
        std::fs::hard_link(&path, &linked).unwrap();
        let prior = std::fs::read(&linked).unwrap();
        let mut newer = ScanState::default();
        newer.tip = 1;
        newer.save(&path).unwrap();
        assert_eq!(std::fs::read(&linked).unwrap(), prior);
        assert_ne!(std::fs::read(&path).unwrap(), prior);
        std::fs::remove_file(&path).unwrap();
        std::fs::remove_file(&linked).unwrap();
    }

    /// The whole point: stopping, saving, and resuming must land on exactly the chain a
    /// single uninterrupted scan produces.
    #[test]
    fn an_incremental_scan_matches_a_full_one() {
        let vault = a_fvk(3);
        let decoy = a_fvk(9);
        let chain = canned_chain(&vault, &decoy);
        let fetched = std::cell::Cell::new(0u64);
        let get = |h: u64| {
            fetched.set(fetched.get() + 1);
            chain
                .get(h as usize - 1)
                .cloned()
                .ok_or_else(|| format!("no block {h}"))
        };

        let mut full = ScanState::default();
        scan_blocks(&vault, &mut full, 6, get).unwrap();
        assert_eq!(fetched.get(), 7, "a full scan rechecks its tip");

        // Two runs with the state written and read back between them, which is what two
        // separate processes would do.
        let mut part = ScanState::default();
        scan_blocks(&vault, &mut part, 3, get).unwrap();
        let path = std::env::temp_dir().join(format!("loki-scanstate-{}.txt", std::process::id()));
        part.save(&path).unwrap();
        let mut part = ScanState::load(&path).unwrap();
        assert_eq!(
            part.tip, 3,
            "the state file remembers where the scan stopped"
        );
        fetched.set(0);
        scan_blocks(&vault, &mut part, 6, get).unwrap();
        std::fs::remove_file(&path).ok();
        assert_eq!(
            fetched.get(),
            5,
            "the resumed scan checks the old tip, new blocks, and final tip"
        );

        assert_eq!(part.tip, full.tip);
        assert_eq!(
            part.cmxs, full.cmxs,
            "the commitment streams must be identical"
        );

        let full = full.into_chain(&vault).unwrap();
        let part = part.into_chain(&vault).unwrap();
        assert_eq!(
            full.notes.len(),
            3,
            "the fixture funds the vault three times"
        );
        assert_eq!(part.notes.len(), full.notes.len());
        for (a, b) in full.notes.iter().zip(&part.notes) {
            assert_eq!(a.position, b.position);
            assert_eq!(a.height, b.height);
            assert_eq!(a.txid, b.txid);
            assert_eq!(a.value_zat, b.value_zat);
            assert_eq!(a.cmx, b.cmx);
            assert_eq!(a.nullifier, b.nullifier);
        }
        // And the positions are the ones the tree would assign: the decoys count too.
        assert_eq!(
            full.notes.iter().map(|n| n.position).collect::<Vec<_>>(),
            vec![1, 3, 5]
        );
    }

    #[test]
    fn a_cache_from_another_vault_cannot_skip_earlier_notes() {
        let vault = a_fvk(3);
        let decoy = a_fvk(9);
        let unrelated = a_fvk(20);
        let chain = canned_chain(&vault, &decoy);
        let get = |h: u64| Ok(chain[h as usize - 1].clone());
        let path =
            std::env::temp_dir().join(format!("loki-cross-vault-{}.txt", std::process::id()));
        let mut state = ScanState::default();
        scan_blocks(&unrelated, &mut state, 6, get).unwrap();
        assert!(state.notes(&unrelated).unwrap().is_empty());
        state.save(&path).unwrap();

        let mut reused = ScanState::load(&path).unwrap();
        scan_blocks(&vault, &mut reused, 6, get).unwrap();
        std::fs::remove_file(path).unwrap();
        assert_eq!(reused.notes(&vault).unwrap().len(), 3);
    }

    /// A chain shorter than the stored one is a different chain, so the state must be
    /// thrown away rather than appended to.
    #[test]
    fn a_shorter_chain_forces_a_rescan() {
        let vault = a_fvk(3);
        let decoy = a_fvk(9);
        let chain = canned_chain(&vault, &decoy);
        let get = |h: u64| {
            chain
                .get(h as usize - 1)
                .cloned()
                .ok_or_else(|| format!("no block {h}"))
        };

        let mut state = ScanState::default();
        scan_blocks(&vault, &mut state, 6, get).unwrap();
        scan_blocks(&vault, &mut state, 3, get).unwrap();

        let mut fresh = ScanState::default();
        scan_blocks(&vault, &mut fresh, 3, get).unwrap();
        assert_eq!(state.tip, 3);
        assert_eq!(
            state.cmxs, fresh.cmxs,
            "the rolled-back state is a fresh scan"
        );
        assert_eq!(state.found.len(), fresh.found.len());
    }

    #[test]
    fn a_spent_note_is_not_offered_after_resuming_the_scan() {
        let vault = a_fvk(3);
        let decoy = a_fvk(9);
        let mut chain = canned_chain(&vault, &decoy);
        let mut state = ScanState::default();
        scan_blocks(&vault, &mut state, 6, |h| {
            chain
                .get(h as usize - 1)
                .cloned()
                .ok_or_else(|| format!("no block {h}"))
        })
        .unwrap();
        let spent = state.notes(&vault).unwrap()[0].nullifier;
        let path = std::env::temp_dir().join(format!("loki-spent-{}.txt", std::process::id()));
        state.save(&path).unwrap();
        let mut state = ScanState::load(&path).unwrap();
        std::fs::remove_file(&path).unwrap();

        // The next action spends that note and sends its output to another account.
        let mut action = action_json(&decoy, 1, 20);
        action["nullifier"] = serde_json::json!(hex::encode(spent));
        chain.push(serde_json::json!({
            "hash": format!("{:064x}", 7),
            "previousblockhash": format!("{:064x}", 6),
            "tx": [tx("spend", vec![action])],
        }));
        scan_blocks(&vault, &mut state, 7, |h| {
            chain
                .get(h as usize - 1)
                .cloned()
                .ok_or_else(|| format!("no block {h}"))
        })
        .unwrap();

        let notes = state.notes(&vault).unwrap();
        assert_eq!(notes.len(), 2);
        assert!(notes.iter().all(|note| note.nullifier != spent));
    }
}
