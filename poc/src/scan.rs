//! Narrow Ironwood note scanning for the CLI wallet path.
//!
//! It trial-decrypts verbose block actions, keeping vault notes and witnesses.
//! Testnet starts at the vault's certified birth checkpoint; regtest retains its
//! short-chain scan. This is still a CLI research scanner, not a durable wallet store.

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

/// One Ironwood action as the node reports it.
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

/// A note the vault owns, with everything checkpoint 3 needs to spend it.
#[derive(Clone, Debug)]
pub struct VaultNote {
    pub height: u32,
    pub txid: String,
    /// Position of this action's commitment in the Ironwood note commitment tree,
    /// counting every Ironwood action in every block in order.
    pub position: u64,
    pub value_zat: u64,
    pub note: Note,
    pub cmx: [u8; 32],
    /// The nullifier this note will have when the vault spends it. Derived from the
    /// vault's own viewing key, not copied from the action that created it.
    pub nullifier: [u8; 32],
}

/// Rebuild an [`Action`] from the node's JSON so it can be trial-decrypted.
///
/// Returns `None` if any field is structurally invalid, which for our own regtest chain
/// would mean the node and these crates disagree about the wire format.
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

/// Trial-decrypt one action with the vault's incoming viewing key.
pub fn try_decrypt(ivk: &PreparedIncomingViewingKey, raw: &RawAction) -> Option<Note> {
    let action = rebuild(raw)?;
    // The domain is derived from the action's own rho, so each action decrypts under
    // the domain it was encrypted with.
    let domain = IronwoodDomain::for_action(&action);
    try_note_decryption::<IronwoodDomain, Action<()>>(&domain, ivk, &action)
        .map(|(note, _, _)| note)
}

/// The vault's external incoming viewing key, prepared for repeated trial decryption.
///
/// External only. Coinbase funding arrives at the external address, which is all the
/// funding scan needs. Change goes to the INTERNAL address, so anything that has to see
/// change must use [`vault_ivks`] instead; getting this wrong is why the first run of the
/// effects check could not decrypt the change output.
pub fn vault_ivk(fvk: &FullViewingKey) -> PreparedIncomingViewingKey {
    let ivk: IncomingViewingKey = fvk.to_ivk(Scope::External);
    PreparedIncomingViewingKey::new(&ivk)
}

/// Both scopes, external first. A full view of the vault's own outputs needs both:
/// payments land on a diversified external address, change lands on the internal one.
pub fn vault_ivks(fvk: &FullViewingKey) -> [PreparedIncomingViewingKey; 2] {
    [
        PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::External)),
        PreparedIncomingViewingKey::new(&fvk.to_ivk(Scope::Internal)),
    ]
}

/// Scan a block's Ironwood actions, keeping those the vault owns.
///
/// `start_position` is the number of Ironwood actions seen in all earlier blocks, so
/// positions are assigned in the same order the note commitment tree appends them.
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

/// What the vault learns from one action, or `None` if the action is not addressed to it.
///
/// Shared by the live scan and by [`crate::scanstate::ScanState`] rebuilding a note it
/// stored earlier, so a note recovered from disk cannot drift from one found on the wire.
pub(crate) fn vault_note_at(
    fvk: &FullViewingKey,
    ivks: &[PreparedIncomingViewingKey],
    height: u32,
    txid: &str,
    position: u64,
    raw: &RawAction,
) -> Option<VaultNote> {
    // Every scope in turn. External finds coinbase funding and payments to a
    // diversified address; internal finds change. A scan that only tried external
    // would silently miss every change note the vault owns.
    let note = ivks.iter().find_map(|ivk| try_decrypt(ivk, raw))?;
    Some(VaultNote {
        height,
        txid: txid.to_string(),
        position,
        value_zat: note.value().inner(),
        cmx: raw.cmx,
        // The spend nullifier is a function of the note and the vault's key.
        nullifier: note.nullifier(fvk).to_bytes(),
        note,
    })
}

/// One Ironwood action's `cmx`, as the node's JSON reports it.
pub fn hex32(v: &serde_json::Value, key: &str) -> Option<[u8; 32]> {
    hex::decode(v[key].as_str()?).ok()?.try_into().ok()
}

/// Everything a full-chain scan produces.
pub struct Chain {
    /// Notes the vault owns, in tree-append order.
    pub notes: Vec<VaultNote>,
    /// Every Ironwood commitment on the chain, in append order.
    pub cmxs: Vec<[u8; 32]>,
    pub tip: u64,
}

/// A fresh vault's notes and witnesses, scanned from its certified birth block.
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

/// Scan a newly created vault from the block after its saved tree checkpoint.
/// shortcut: rescans from birth on each command; persist witnesses once Testnet
/// vaults routinely span more than a few days of blocks.
pub fn scan_chain_from_birth(
    rpc: &crate::rpc::Rpc,
    fvk: &FullViewingKey,
    birth_height: u64,
) -> Result<BirthChain, String> {
    let checkpoint_height = birth_height
        .checked_sub(1)
        .ok_or("invalid vault birth height")?;
    let checkpoint = rpc.json("z_gettreestate", &format!("[\"{checkpoint_height}\"]"))?;
    if checkpoint["height"].as_u64() != Some(checkpoint_height) {
        return Err("birth checkpoint height differs from the node response".into());
    }
    let hash = hex32(&checkpoint, "hash").ok_or("birth checkpoint has no block hash")?;
    let encoded = hex::decode(
        checkpoint["ironwood"]["commitments"]["finalState"]
            .as_str()
            .ok_or("birth checkpoint has no Ironwood tree state")?,
    )
    .map_err(|e| format!("birth checkpoint tree: {e}"))?;
    let expected = anchor_from_treestate(&checkpoint)?;
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
        .json("getblockhash", &format!("[{checkpoint_height}]"))?
        .as_str()
        != checkpoint["hash"].as_str()
    {
        return Err("birth checkpoint changed during the scan".into());
    }
    if chain.witnesses.root() != chain_anchor(rpc, chain.tip)? {
        return Err("scanned Ironwood tree disagrees with the node's anchor".into());
    }
    Ok(chain)
}

/// Scan every block for the vault's Ironwood notes and collect the commitment stream.
///
/// This is what makes a second device independent: a finisher that runs this derives the
/// note position and the witness from the chain itself, rather than from a file an
/// approver wrote. It is the same narrow fixture as before, just callable.
pub fn scan_chain(rpc: &crate::rpc::Rpc, fvk: &FullViewingKey) -> Result<Chain, String> {
    let mut state = ScanState::default();
    scan_to_tip(rpc, fvk, &mut state)?;
    state.into_chain(fvk)
}

/// [`scan_chain`], but only over the blocks that are new since the last run.
///
/// `path` is a file this owns: it holds how far the last scan got, the commitment stream
/// it collected and the vault's own actions, so a second run checks its saved-tip block
/// and reads blocks mined since the first. The result is the same `Chain` a full scan
/// returns — including the whole commitment stream, which is what
/// [`crate::witness::witness_for`] needs to rebuild
/// the tree and check its root against the node's anchor.
///
/// A shorter chain, a changed saved-tip block, or a legacy cache without a block hash
/// is rescanned from scratch. A disconnected chain or a tip that changes during the
/// scan is refused without replacing the saved state.
pub fn scan_chain_cached(
    rpc: &crate::rpc::Rpc,
    fvk: &FullViewingKey,
    path: &std::path::Path,
) -> Result<Chain, String> {
    let mut state = ScanState::load(path)?;
    scan_to_tip(rpc, fvk, &mut state)?;
    let notes = state.notes(fvk)?;
    state.save(path)?;
    Ok(Chain {
        notes,
        cmxs: state.cmxs,
        tip: state.tip,
    })
}

/// Bring `state` up to the node's current tip.
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

/// Scan the blocks `state` has not seen yet, up to and including `to`.
///
/// `get_block` is the only thing this needs from the node, which is what lets a test run
/// the real scan over a canned chain.
/// Discard `state` on error; an interrupted block may have added some actions.
pub fn scan_blocks<F>(
    fvk: &FullViewingKey,
    state: &mut ScanState,
    to: u64,
    get_block: F,
) -> Result<(), String>
where
    F: Fn(u64) -> Result<serde_json::Value, String>,
{
    // A saved height alone cannot identify a chain after a reorg.
    if to < state.tip
        || (state.tip > 0
            && (state.tip_hash.is_none()
                || Some(block_hash(&get_block(state.tip)?, state.tip)?) != state.tip_hash))
    {
        *state = ScanState::default();
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

/// One transaction's Ironwood actions, as the node's JSON reports them.
///
/// A single unparsable action is fatal: on our own regtest chain it would mean the node
/// and these crates disagree about the wire format, and a scan that silently skipped it
/// would assign every later note the wrong tree position.
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

/// The node's own Ironwood anchor at `height`.
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

/// Trial-decrypt one action, keeping the memo as well as the note.
///
/// The effects check needs the memo: an output with the right value to the right address
/// but a different memo is not the payment that was approved.
pub fn try_decrypt_with_memo(
    ivk: &PreparedIncomingViewingKey,
    raw: &RawAction,
) -> Option<(Note, [u8; 512])> {
    let action = rebuild(raw)?;
    let domain = IronwoodDomain::for_action(&action);
    try_note_decryption::<IronwoodDomain, Action<()>>(&domain, ivk, &action)
        .map(|(note, _, memo)| (note, memo))
}
