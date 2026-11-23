use std::io::Write as _;
use std::path::Path;

use orchard::keys::{FullViewingKey, PreparedIncomingViewingKey};
use rand_core::{OsRng, RngCore};

use crate::scan::{vault_ivks, vault_note_at, Chain, RawAction, VaultNote};
use crate::witness::BirthWitnesses;

pub struct Found {
    pub height: u32,
    pub txid: String,
    pub position: u64,
    pub action: RawAction,
}

#[derive(Default)]
pub struct ScanState {
    pub tip: u64,
    pub tip_hash: Option<[u8; 32]>,
    pub birth_height: Option<u64>,
    pub checkpoint_hash: Option<[u8; 32]>,
    pub checkpoint_tree: Option<Vec<u8>>,
    position_offset: u64,
    pub cmxs: Vec<[u8; 32]>,
    pub nfs: Vec<[u8; 32]>,
    pub found: Vec<Found>,
}

impl ScanState {
    pub fn from_birth(
        birth_height: u64,
        checkpoint_hash: [u8; 32],
        checkpoint_tree: Vec<u8>,
    ) -> Result<Self, String> {
        if birth_height == 0 {
            return Err("invalid vault birth height".into());
        }
        let position_offset = BirthWitnesses::from_state(&checkpoint_tree)?.size();
        Ok(Self {
            tip: birth_height - 1,
            tip_hash: Some(checkpoint_hash),
            birth_height: Some(birth_height),
            checkpoint_hash: Some(checkpoint_hash),
            checkpoint_tree: Some(checkpoint_tree),
            position_offset,
            ..Self::default()
        })
    }

    pub fn birth_witnesses(&self) -> Result<BirthWitnesses, String> {
        let mut witnesses = BirthWitnesses::from_state(
            self.checkpoint_tree
                .as_deref()
                .ok_or("scan has no birth checkpoint")?,
        )?;
        let mut found = self.found.iter().map(|note| note.position).peekable();
        for cmx in &self.cmxs {
            let position = witnesses.append(*cmx)?;
            if found.peek().copied() == Some(position) {
                witnesses.track_latest()?;
                found.next();
            }
        }
        if found.next().is_some() {
            return Err("vault note position is outside the scanned tree".into());
        }
        Ok(witnesses)
    }

    pub fn push(
        &mut self,
        fvk: &FullViewingKey,
        ivks: &[PreparedIncomingViewingKey],
        height: u32,
        txid: &str,
        actions: &[RawAction],
    ) {
        for raw in actions {
            let position = self.position_offset + self.cmxs.len() as u64;
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

    pub fn into_chain(self, fvk: &FullViewingKey) -> Result<Chain, String> {
        if self.birth_height.is_some() {
            return Err("birth scan has no genesis commitment stream".into());
        }
        let notes = self.notes(fvk)?;
        Ok(Chain {
            notes,
            cmxs: self.cmxs,
            tip: self.tip,
        })
    }

    pub fn load(path: &Path) -> Result<Self, String> {
        let text = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(format!("{}: {e}", path.display())),
        };
        Self::decode(&text)
            .map_err(|line| format!("{}:{line}: malformed scan state", path.display()))
    }

    pub fn decode(text: &str) -> Result<Self, usize> {
        let mut state = Self::default();
        for (i, line) in text.lines().enumerate() {
            let bad = || i + 1;
            let mut f = line.split_whitespace();
            match f.next() {
                None => continue,
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
                Some("b") => {
                    if state.birth_height.is_some() {
                        return Err(bad());
                    }
                    let height = f.next().and_then(|v| v.parse().ok()).ok_or_else(bad)?;
                    let hash = field(&mut f).ok_or_else(bad)?;
                    let tree = f.next().and_then(|s| hex::decode(s).ok()).ok_or_else(bad)?;
                    let birth = Self::from_birth(height, hash, tree).map_err(|_| bad())?;
                    state.birth_height = birth.birth_height;
                    state.checkpoint_hash = birth.checkpoint_hash;
                    state.checkpoint_tree = birth.checkpoint_tree;
                    state.position_offset = birth.position_offset;
                }
                Some("c") => {
                    state.cmxs.push(field(&mut f).ok_or_else(bad)?);
                    state.nfs.push(field(&mut f).ok_or_else(bad)?);
                }
                Some("s") => {}
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

    pub fn encode(&self) -> String {
        use std::fmt::Write as _;
        let mut out = String::new();
        if let Some(hash) = self.tip_hash {
            let _ = writeln!(out, "tip {} {}", self.tip, hex::encode(hash));
        } else {
            let _ = writeln!(out, "tip {}", self.tip);
        }
        if let (Some(height), Some(hash), Some(tree)) = (
            self.birth_height,
            self.checkpoint_hash,
            self.checkpoint_tree.as_ref(),
        ) {
            let _ = writeln!(
                out,
                "b {height} {} {}",
                hex::encode(hash),
                hex::encode(tree)
            );
        }
        for (c, nf) in self.cmxs.iter().zip(self.nfs.iter()) {
            let _ = writeln!(out, "c {} {}", hex::encode(c), hex::encode(nf));
        }
        for n in &self.found {
            let a = &n.action;
            let _ = writeln!(
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
            );
        }
        out
    }

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
            out.write_all(self.encode().as_bytes()).map_err(io)?;
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

fn field<'a, const N: usize>(f: &mut impl Iterator<Item = &'a str>) -> Option<[u8; N]> {
    hex::decode(f.next()?).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::{scan_birth_blocks, scan_blocks};
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

    fn action_json(fvk: &FullViewingKey, value: u64, seed: u8) -> serde_json::Value {
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

    fn canned_chain(
        vault: &FullViewingKey,
        decoy: &FullViewingKey,
    ) -> Vec<serde_json::Value> {
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
    fn birth_checkpoint_matches_genesis_positions_root_and_witnesses() {
        use incrementalmerkletree::frontier::CommitmentTree;
        use orchard::tree::MerkleHashOrchard;
        use zcash_primitives::merkle_tree::write_commitment_tree;

        let vault = a_fvk(3);
        let decoy = a_fvk(9);
        let mut chain = canned_chain(&vault, &decoy);
        let mut checkpoint = CommitmentTree::<MerkleHashOrchard, 32>::empty();
        let pre_birth = chain[1]["tx"][0]["ironwood"]["actions"]
            .as_array()
            .unwrap()
            .iter()
            .chain(chain[3]["tx"][0]["ironwood"]["actions"].as_array().unwrap());
        for action in pre_birth {
            let cmx = crate::scan::hex32(action, "cmx").unwrap();
            let note = ExtractedNoteCommitment::from_bytes(&cmx)
                .into_option()
                .unwrap();
            checkpoint
                .append(MerkleHashOrchard::from_cmx(&note))
                .unwrap();
        }
        let mut encoded = Vec::new();
        write_commitment_tree(&checkpoint, &mut encoded).unwrap();
        let checkpoint_hash = crate::scan::hex32(&chain[3], "hash").unwrap();
        let mut full = ScanState::default();
        scan_blocks(&vault, &mut full, 6, |height| {
            Ok(chain[height as usize - 1].clone())
        })
        .unwrap();
        let full_tree = crate::witness::CommitmentTree::build(&full.cmxs).unwrap();
        let full_root = full_tree.root().to_bytes();
        let scanned = scan_birth_blocks(&vault, &encoded, checkpoint_hash, 5, 6, |height| {
            Ok(chain[height as usize - 1].clone())
        })
        .unwrap();
        assert_eq!(
            scanned.notes.iter().map(|n| n.position).collect::<Vec<_>>(),
            vec![3, 5]
        );
        assert_eq!(scanned.witnesses.root(), full_root);
        let mut cached = ScanState::from_birth(5, checkpoint_hash, encoded).unwrap();
        scan_blocks(&vault, &mut cached, 5, |height| {
            assert!(
                height >= 4,
                "birth scan may only recheck its checkpoint block"
            );
            Ok(chain[height as usize - 1].clone())
        })
        .unwrap();
        cached = ScanState::decode(&cached.encode()).unwrap();
        scan_blocks(&vault, &mut cached, 6, |height| {
            assert!(
                height >= 4,
                "birth scan must not read pre-checkpoint blocks"
            );
            Ok(chain[height as usize - 1].clone())
        })
        .unwrap();
        let cached_witnesses = cached.birth_witnesses().unwrap();
        assert_eq!(cached_witnesses.root(), full_root);
        assert!(ScanState::decode(&cached.encode())
            .unwrap()
            .into_chain(&vault)
            .is_err());
        let cached_notes = cached.notes(&vault).unwrap();
        assert_eq!(
            cached_notes.iter().map(|n| n.position).collect::<Vec<_>>(),
            vec![3, 5]
        );
        for note in &scanned.notes {
            let full_path = full_tree.path(note.position).unwrap();
            let birth_path = scanned.witnesses.path(note.position).unwrap();
            let cached_path = cached_witnesses.path(note.position).unwrap();
            assert_eq!(birth_path.position(), full_path.position());
            assert_eq!(birth_path.auth_path(), full_path.auth_path());
            assert_eq!(cached_path.auth_path(), full_path.auth_path());
            assert_eq!(
                birth_path
                    .root(
                        ExtractedNoteCommitment::from_bytes(&note.cmx)
                            .into_option()
                            .unwrap()
                    )
                    .to_bytes(),
                scanned.witnesses.root()
            );
        }
        chain[4]["tx"][0]["ironwood"]["actions"][0] = action_json(&vault, 250, 18);
        rebranch(&mut chain, 4);
        scan_blocks(&vault, &mut cached, 6, |height| {
            assert!(height >= 4, "a reorg must restart at the birth checkpoint");
            Ok(chain[height as usize - 1].clone())
        })
        .unwrap();
        let mut reorg_full = ScanState::default();
        scan_blocks(&vault, &mut reorg_full, 6, |height| {
            Ok(chain[height as usize - 1].clone())
        })
        .unwrap();
        assert_eq!(
            cached.birth_witnesses().unwrap().root(),
            crate::witness::CommitmentTree::build(&reorg_full.cmxs)
                .unwrap()
                .root()
                .to_bytes()
        );
        assert_eq!(cached.notes(&vault).unwrap()[0].value_zat, 250);
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
    fn reorg_that_drops_a_note_below_the_saved_tip_forgets_it() {
        let vault = a_fvk(3);
        let decoy = a_fvk(9);
        let mut chain = canned_chain(&vault, &decoy);
        let mut state = ScanState::default();
        scan_blocks(&vault, &mut state, 6, |h| Ok(chain[h as usize - 1].clone())).unwrap();
        let path = std::env::temp_dir().join(format!("loki-reorg-drop-{}.txt", std::process::id()));
        state.save(&path).unwrap();
        let mut state = ScanState::load(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert!(state.notes(&vault).unwrap().iter().any(|note| note.value_zat == 100));

        chain[1]["tx"] = serde_json::json!([]);
        rebranch(&mut chain, 1);
        scan_blocks(&vault, &mut state, 6, |h| Ok(chain[h as usize - 1].clone())).unwrap();
        let notes = state.notes(&vault).unwrap();
        assert_eq!(notes.iter().map(|note| note.value_zat).collect::<Vec<_>>(), [200, 300]);
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
        assert_eq!(
            full.notes.iter().map(|n| n.position).collect::<Vec<_>>(),
            vec![1, 3, 5]
        );
    }

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
