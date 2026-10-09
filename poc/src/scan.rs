//! A narrow regtest fixture: find the vault's Ironwood notes.
//!
//! This is deliberately not a wallet. It trial-decrypts the Ironwood actions that the
//! node already hands us as JSON, keeps the ones addressed to the vault, and records
//! what checkpoint 3 needs: value, nullifier, commitment and tree position.
//!
//! The brief allows exactly this ("a narrow test fixture is fine; implementing a general
//! scanner is outside G1").

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
/// it collected and the vault's own actions, so a second run reads only the blocks mined
/// since the first. The result is the same `Chain` a full scan returns — including the
/// whole commitment stream, which is what [`crate::witness::witness_for`] needs to rebuild
/// the tree and check its root against the node's anchor.
///
/// A chain that has got shorter is treated as a different chain and rescanned from
/// scratch. A reorg that keeps the same height is not detected here; it surfaces as the
/// anchor mismatch in `witness_for`, which refuses rather than signs.
pub fn scan_chain_cached(
    rpc: &crate::rpc::Rpc,
    fvk: &FullViewingKey,
    path: &std::path::Path,
) -> Result<Chain, String> {
    let mut state = ScanState::load(path)?;
    scan_to_tip(rpc, fvk, &mut state)?;
    state.save(path)?;
    state.into_chain(fvk)
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
pub fn scan_blocks<F>(
    fvk: &FullViewingKey,
    state: &mut ScanState,
    to: u64,
    get_block: F,
) -> Result<(), String>
where
    F: Fn(u64) -> Result<serde_json::Value, String>,
{
    // A chain shorter than the one we remember is not the chain we scanned, and nothing
    // in the stored state can be trusted to still be on it.
    if to < state.tip {
        *state = ScanState::default();
    }

    let ivks = vault_ivks(fvk);
    for height in state.tip + 1..=to {
        let block = get_block(height)?;
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
    }

    Ok(())
}

/// One transaction's Ironwood actions, as the node's JSON reports them.
///
/// A single unparsable action is fatal: on our own regtest chain it would mean the node
/// and these crates disagree about the wire format, and a scan that silently skipped it
/// would assign every later note the wrong tree position.
fn parse_actions(actions: &[serde_json::Value], txid: &str) -> Result<Vec<RawAction>, String> {
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
    hex::decode(
        state["ironwood"]["commitments"]["finalRoot"]
            .as_str()
            .ok_or("z_gettreestate has no ironwood finalRoot")?,
    )
    .map_err(|e| format!("anchor hex: {e}"))?
    .try_into()
    .map_err(|_| "anchor is not 32 bytes".to_string())
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
