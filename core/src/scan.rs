use orchard::{
    keys::{FullViewingKey, IncomingViewingKey, PreparedIncomingViewingKey, Scope},
    note::{ExtractedNoteCommitment, Note, Nullifier, TransmittedNoteCiphertext},
    note_encryption::IronwoodDomain,
    primitives::redpallas::{self, SpendAuth},
    value::ValueCommitment,
    Action,
};
use zcash_note_encryption::try_note_decryption;

use crate::scanstate::ScanState;
use crate::witness::BirthWitnesses;

#[derive(Clone, Debug)]
pub struct RawAction {
    pub cv: [u8; 32],
    pub nullifier: [u8; 32],
    pub rk: [u8; 32],
    pub cmx: [u8; 32],
    pub ephemeral_key: [u8; 32],
    pub enc_ciphertext: Vec<u8>,
    pub out_ciphertext: [u8; 80],
}

#[derive(Clone, Debug)]
pub struct VaultNote {
    pub height: u32,
    pub txid: String,
    pub position: u64,
    pub value_zat: u64,
    pub note: Note,
    pub cmx: [u8; 32],
    pub nullifier: [u8; 32],
}

fn rebuild(raw: &RawAction) -> Option<Action<()>> {
    let enc: [u8; 580] = raw.enc_ciphertext.as_slice().try_into().ok()?;

    Action::from_parts(
        Nullifier::from_bytes(&raw.nullifier).into_option()?,
        redpallas::VerificationKey::<SpendAuth>::try_from(raw.rk).ok()?,
        ExtractedNoteCommitment::from_bytes(&raw.cmx).into_option()?,
        TransmittedNoteCiphertext {
            epk_bytes: raw.ephemeral_key,
            enc_ciphertext: enc,
            out_ciphertext: raw.out_ciphertext,
        },
        ValueCommitment::from_bytes(&raw.cv).into_option()?,
        (),
    )
    .ok()
}

pub fn try_decrypt(ivk: &PreparedIncomingViewingKey, raw: &RawAction) -> Option<Note> {
    let action = rebuild(raw)?;
    let domain = IronwoodDomain::for_action(&action);
    try_note_decryption::<IronwoodDomain, Action<()>>(&domain, ivk, &action)
        .map(|(note, _, _)| note)
}

pub fn vault_ivk(fvk: &FullViewingKey) -> PreparedIncomingViewingKey {
    let ivk: IncomingViewingKey = fvk.to_ivk(Scope::External);
    PreparedIncomingViewingKey::new(&ivk)
}

pub fn vault_ivks(fvk: &FullViewingKey) -> [PreparedIncomingViewingKey; 2] {
    [
        PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External)),
        PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::Internal)),
    ]
}

pub fn scan_block(
    fvk: &FullViewingKey,
    ivks: &[PreparedIncomingViewingKey],
    height: u32,
    txid: &str,
    actions: &[RawAction],
    start_position: u64,
) -> (Vec<VaultNote>, u64) {
    let mut found = Vec::new();
    let mut position = start_position;

    for raw in actions {
        if let Some(note) = vault_note_at(fvk, ivks, height, txid, position, raw) {
            found.push(note);
        }
        position += 1;
    }

    (found, position)
}

pub(crate) fn vault_note_at(
    fvk: &FullViewingKey,
    ivks: &[PreparedIncomingViewingKey],
    height: u32,
    txid: &str,
    position: u64,
    raw: &RawAction,
) -> Option<VaultNote> {
    let note = ivks.iter().find_map(|ivk| try_decrypt(ivk, raw))?;
    Some(VaultNote {
        height,
        txid: txid.to_string(),
        position,
        value_zat: note.value().inner(),
        cmx: raw.cmx,
        nullifier: note.nullifier(fvk).to_bytes(),
        note,
    })
}

pub fn hex32(v: &serde_json::Value, key: &str) -> Option<[u8; 32]> {
    hex::decode(v[key].as_str()?).ok()?.try_into().ok()
}

pub struct Chain {
    pub notes: Vec<VaultNote>,
    pub cmxs: Vec<[u8; 32]>,
    pub tip: u64,
}

pub struct BirthChain {
    pub notes: Vec<VaultNote>,
    pub witnesses: BirthWitnesses,
    pub tip: u64,
}

pub fn scan_birth_blocks<F>(
    fvk: &FullViewingKey,
    checkpoint_tree: &[u8],
    checkpoint_hash: [u8; 32],
    birth_height: u64,
    tip: u64,
    get_block: F,
) -> Result<BirthChain, String>
where
    F: Fn(u64) -> Result<serde_json::Value, String>,
{
    if birth_height == 0 || tip < birth_height - 1 {
        return Err("invalid vault birth height".into());
    }
    let mut witnesses = BirthWitnesses::from_state(checkpoint_tree)?;
    let ivks = vault_ivks(fvk);
    let mut notes = Vec::new();
    let mut spent = std::collections::HashSet::new();
    let mut previous = checkpoint_hash;
    for height in birth_height..=tip {
        let block = get_block(height)?;
        if hex32(&block, "previousblockhash") != Some(previous) {
            return Err(format!(
                "block {height} does not extend the birth checkpoint"
            ));
        }
        previous = block_hash(&block, height)?;
        for tx in block["tx"].as_array().ok_or("block has no tx array")? {
            let txid = tx["txid"].as_str().ok_or("transaction has no txid")?;
            if let Some(actions) = tx["ironwood"]["actions"].as_array() {
                for raw in parse_actions(actions, txid)? {
                    let position = witnesses.append(raw.cmx)?;
                    if let Some(note) = vault_note_at(
                        fvk,
                        &ivks,
                        u32::try_from(height).map_err(|_| "block height overflow")?,
                        txid,
                        position,
                        &raw,
                    ) {
                        witnesses.track_latest()?;
                        notes.push(note);
                    }
                    spent.insert(raw.nullifier);
                }
            }
        }
    }
    if tip >= birth_height && block_hash(&get_block(tip)?, tip)? != previous {
        return Err(format!("block {tip} changed during the scan"));
    }
    notes.retain(|note| !spent.contains(&note.nullifier));
    Ok(BirthChain {
        notes,
        witnesses,
        tip,
    })
}

pub fn scan_chain_from_birth(
    rpc: &crate::rpc::Rpc,
    fvk: &FullViewingKey,
    birth_height: u64,
) -> Result<BirthChain, String> {
    let (hash, encoded, expected) = birth_checkpoint(rpc, birth_height)?;
    if BirthWitnesses::from_state(&encoded)?.root() != expected {
        return Err("birth checkpoint tree disagrees with its root".into());
    }
    let tip = rpc
        .json("getblockcount", "[]")?
        .as_u64()
        .ok_or("getblockcount did not return a number")?;
    let chain = scan_birth_blocks(fvk, &encoded, hash, birth_height, tip, |height| {
        rpc.json("getblock", &format!("[\"{height}\", 2]"))
    })?;
    if rpc
        .json("getblockhash", &format!("[{}]", birth_height - 1))?
        .as_str()
        != Some(hex::encode(hash).as_str())
    {
        return Err("birth checkpoint changed during the scan".into());
    }
    if chain.witnesses.root() != chain_anchor(rpc, chain.tip)? {
        return Err("scanned Ironwood tree disagrees with the node's anchor".into());
    }
    Ok(chain)
}

fn birth_checkpoint(
    rpc: &crate::rpc::Rpc,
    birth_height: u64,
) -> Result<([u8; 32], Vec<u8>, [u8; 32]), String> {
    let height = birth_height
        .checked_sub(1)
        .ok_or("invalid vault birth height")?;
    let state = rpc.json("z_gettreestate", &format!("[\"{height}\"]"))?;
    if state["height"].as_u64() != Some(height) {
        return Err("birth checkpoint height differs from the node response".into());
    }
    let hash = hex32(&state, "hash").ok_or("birth checkpoint has no block hash")?;
    let tree = hex::decode(
        state["ironwood"]["commitments"]["finalState"]
            .as_str()
            .ok_or("birth checkpoint has no Ironwood tree state")?,
    )
    .map_err(|e| format!("birth checkpoint tree: {e}"))?;
    let root = anchor_from_treestate(&state)?;
    Ok((hash, tree, root))
}

pub fn scan_chain(rpc: &crate::rpc::Rpc, fvk: &FullViewingKey) -> Result<Chain, String> {
    let mut state = ScanState::default();
    scan_to_tip(rpc, fvk, &mut state)?;
    state.into_chain(fvk)
}

pub fn scan_chain_cached(
    rpc: &crate::rpc::Rpc,
    fvk: &FullViewingKey,
    path: &std::path::Path,
) -> Result<Chain, String> {
    let mut state = ScanState::load(path)?;
    if state.birth_height.is_some() {
        state = ScanState::default();
    }
    scan_to_tip(rpc, fvk, &mut state)?;
    let notes = state.notes(fvk)?;
    state.save(path)?;
    Ok(Chain {
        notes,
        cmxs: state.cmxs,
        tip: state.tip,
    })
}

pub fn scan_chain_cached_from_birth(
    rpc: &crate::rpc::Rpc,
    fvk: &FullViewingKey,
    path: &std::path::Path,
    birth_height: u64,
) -> Result<BirthChain, String> {
    let (hash, tree, root) = birth_checkpoint(rpc, birth_height)?;
    let mut state = ScanState::load(path)?;
    if state.birth_height != Some(birth_height) || state.checkpoint_hash != Some(hash) {
        state = ScanState::from_birth(birth_height, hash, tree)?;
    }
    if BirthWitnesses::from_state(
        state
            .checkpoint_tree
            .as_deref()
            .ok_or("scan has no birth checkpoint")?,
    )?
    .root()
        != root
    {
        return Err("birth checkpoint tree disagrees with the node's root".into());
    }
    scan_to_tip(rpc, fvk, &mut state)?;
    if rpc
        .json("getblockhash", &format!("[{}]", birth_height - 1))?
        .as_str()
        != Some(hex::encode(hash).as_str())
    {
        return Err("birth checkpoint changed during the scan".into());
    }
    let notes = state.notes(fvk)?;
    let witnesses = state.birth_witnesses()?;
    let anchor = chain_anchor(rpc, state.tip)?;
    if rpc
        .json("getblockhash", &format!("[{}]", state.tip))?
        .as_str()
        != state.tip_hash.map(hex::encode).as_deref()
    {
        return Err("scanned tip changed while checking the Ironwood anchor".into());
    }
    if witnesses.root() != anchor {
        return Err("scanned Ironwood tree disagrees with the node's anchor".into());
    }
    for note in &notes {
        let cmx = ExtractedNoteCommitment::from_bytes(&note.cmx)
            .into_option()
            .ok_or("vault note has invalid Ironwood commitment")?;
        if witnesses.path(note.position)?.root(cmx).to_bytes() != anchor {
            return Err(format!(
                "witness at position {} disagrees with the node's anchor",
                note.position
            ));
        }
    }
    state.save(path)?;
    Ok(BirthChain {
        notes,
        witnesses,
        tip: state.tip,
    })
}

fn scan_to_tip(
    rpc: &crate::rpc::Rpc,
    fvk: &FullViewingKey,
    state: &mut ScanState,
) -> Result<(), String> {
    let tip = rpc
        .json("getblockcount", "[]")?
        .as_u64()
        .ok_or("getblockcount did not return a number")?;

    scan_blocks(fvk, state, tip, |height| {
        rpc.json("getblock", &format!("[\"{height}\", 2]"))
    })
}

pub fn scan_blocks<F>(
    fvk: &FullViewingKey,
    state: &mut ScanState,
    to: u64,
    get_block: F,
) -> Result<(), String>
where
    F: Fn(u64) -> Result<serde_json::Value, String>,
{
    if to < state.tip
        || (state.tip > 0
            && (state.tip_hash.is_none()
                || Some(block_hash(&get_block(state.tip)?, state.tip)?) != state.tip_hash))
    {
        *state = match (
            state.birth_height,
            state.checkpoint_hash,
            state.checkpoint_tree.clone(),
        ) {
            (Some(height), Some(hash), Some(tree)) => ScanState::from_birth(height, hash, tree)?,
            _ => ScanState::default(),
        };
    }

    let ivks = vault_ivks(fvk);
    for height in state.tip + 1..=to {
        let block = get_block(height)?;
        let hash = block_hash(&block, height)?;
        if let Some(parent) = state.tip_hash {
            if hex32(&block, "previousblockhash") != Some(parent) {
                return Err(format!("block {height} does not extend the scanned chain"));
            }
        }
        for tx in block["tx"].as_array().ok_or("block has no tx array")? {
            let txid = tx["txid"].as_str().unwrap_or("?").to_string();
            let actions = match tx["ironwood"]["actions"].as_array() {
                Some(a) if !a.is_empty() => a,
                _ => continue,
            };

            let raws = parse_actions(actions, &txid)?;
            state.push(fvk, &ivks, height as u32, &txid, &raws);
        }
        state.tip = height;
        state.tip_hash = Some(hash);
    }
    if to > 0 && Some(block_hash(&get_block(to)?, to)?) != state.tip_hash {
        return Err(format!("block {to} changed during the scan"));
    }

    Ok(())
}

fn block_hash(block: &serde_json::Value, height: u64) -> Result<[u8; 32], String> {
    hex32(block, "hash").ok_or_else(|| format!("block {height} has no valid hash"))
}

pub fn parse_actions(actions: &[serde_json::Value], txid: &str) -> Result<Vec<RawAction>, String> {
    let raws: Vec<RawAction> = actions
        .iter()
        .filter_map(|a| {
            Some(RawAction {
                cv: hex32(a, "cv")?,
                nullifier: hex32(a, "nullifier")?,
                rk: hex32(a, "rk")?,
                cmx: hex32(a, "cmx")?,
                ephemeral_key: hex32(a, "ephemeralKey")?,
                enc_ciphertext: hex::decode(a["encCiphertext"].as_str()?).ok()?,
                out_ciphertext: hex::decode(a["outCiphertext"].as_str()?)
                    .ok()?
                    .try_into()
                    .ok()?,
            })
        })
        .collect();

    if raws.len() != actions.len() {
        return Err(format!("tx {txid}: an Ironwood action failed to parse"));
    }
    Ok(raws)
}

pub fn chain_anchor(rpc: &crate::rpc::Rpc, height: u64) -> Result<[u8; 32], String> {
    let state = rpc.json("z_gettreestate", &format!("[\"{height}\"]"))?;
    anchor_from_treestate(&state)
}

fn anchor_from_treestate(state: &serde_json::Value) -> Result<[u8; 32], String> {
    let commitments = &state["ironwood"]["commitments"];
    let root = commitments["finalRoot"]
        .as_str()
        .map(|s| {
            hex::decode(s)
                .map_err(|e| format!("anchor hex: {e}"))?
                .try_into()
                .map_err(|_| "anchor is not 32 bytes".to_string())
        })
        .transpose()?;
    let state_root = commitments["finalState"]
        .as_str()
        .map(|s| {
            BirthWitnesses::from_state(&hex::decode(s).map_err(|e| e.to_string())?)
                .map(|tree| tree.root())
        })
        .transpose()?;
    match (root, state_root) {
        (Some(a), Some(b)) if a != b => Err("Ironwood finalRoot differs from finalState".into()),
        (Some(root), _) | (_, Some(root)) => Ok(root),
        _ => Err("z_gettreestate has no Ironwood root or state".into()),
    }
}

#[cfg(test)]
mod birth_tests {
    use super::*;
    use incrementalmerkletree::frontier::CommitmentTree;
    use orchard::tree::MerkleHashOrchard;
    use zcash_primitives::merkle_tree::write_commitment_tree;

    #[test]
    fn treestate_accepts_zebra_state_and_rejects_conflicting_root() {
        let mut bytes = Vec::new();
        write_commitment_tree(
            &CommitmentTree::<MerkleHashOrchard, 32>::empty(),
            &mut bytes,
        )
        .unwrap();
        let root = BirthWitnesses::from_state(&bytes).unwrap().root();
        let mut response = serde_json::json!({"ironwood": {"commitments": {
            "finalState": hex::encode(bytes), "finalRoot": hex::encode(root)
        }}});
        assert_eq!(anchor_from_treestate(&response).unwrap(), root);
        response["ironwood"]["commitments"]["finalRoot"] = serde_json::json!(hex::encode([7; 32]));
        assert!(anchor_from_treestate(&response).is_err());
    }
}

pub fn try_decrypt_with_memo(
    ivk: &PreparedIncomingViewingKey,
    raw: &RawAction,
) -> Option<(Note, [u8; 512])> {
    let action = rebuild(raw)?;
    let domain = IronwoodDomain::for_action(&action);
    try_note_decryption::<IronwoodDomain, Action<()>>(&domain, ivk, &action)
        .map(|(note, _, memo)| (note, memo))
}
