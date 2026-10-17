//! A reusable Ironwood indexer for the local chain.
//!
//! Other applications run this to learn the vault's state without re-implementing the
//! scan: it emits a single JSON document on stdout — the tip, every unspent vault note
//! with its tree position and nullifier, the total, and the node's own anchor at the tip.
//!
//! It is a thin wrapper over the persistent, incremental, reorg-safe scan already proven
//! in `scan::scan_chain_cached`. A cache file next to the vault state makes repeated runs
//! read only blocks mined since the last call.
//!
//! ponytail: scans from genesis, like every other path here. A birth-height start that
//! skips early blocks is NOT a flag — the note commitment position counts every Ironwood
//! action from genesis (see `scanstate.rs` and `witness.rs`), so it needs the tree
//! frontier seeded from `z_gettreestate` at the birth height. Add that when a chain is
//! long enough that genesis rescan hurts; on the local/regtest chain it does not.

use std::{env, path::PathBuf, process};

use loki_poc::{rpc, scan, state::MemberDir, vault};

fn main() {
    if let Err(e) = run() {
        eprintln!("loki_indexer: {e}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut args = env::args().skip(1);
    let root = PathBuf::from(
        args.next()
            .ok_or("usage: loki_indexer <state-dir> [cache-file]")?,
    );
    // Default the cache beside the vault state so repeated runs are incremental.
    let cache = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("indexer-cache.txt"));

    let ak: [u8; 32] = MemberDir::open(&root, "public")
        .read_hex("group_ak.hex")
        .map_err(|e| format!("run setup first: {e}"))?
        .try_into()
        .map_err(|_| "group_ak.hex is not 32 bytes")?;
    let fvk = vault::test_only_fvk(&ak).map_err(|e| format!("{e:?}"))?;

    let rpc = rpc::Rpc::regtest();
    let chain = scan::scan_chain_cached(&rpc, &fvk, &cache)?;
    let anchor = scan::chain_anchor(&rpc, chain.tip)?;

    let total: u64 = chain.notes.iter().map(|n| n.value_zat).sum();
    let notes: Vec<serde_json::Value> = chain
        .notes
        .iter()
        .map(|n| {
            serde_json::json!({
                "height": n.height,
                "position": n.position,
                "value_zat": n.value_zat,
                "nullifier": hex::encode(n.nullifier),
                "txid": n.txid,
                "cmx": hex::encode(n.cmx),
            })
        })
        .collect();

    let out = serde_json::json!({
        "tip": chain.tip,
        "actions": chain.cmxs.len(),
        "unspent_notes": notes.len(),
        "total_zat": total,
        "anchor": hex::encode(anchor),
        "notes": notes,
    });
    println!(
        "{}",
        serde_json::to_string_pretty(&out).map_err(|e| e.to_string())?
    );
    Ok(())
}
