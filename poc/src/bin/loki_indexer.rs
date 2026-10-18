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
//! `--from-height` seeds the cache with the node's Ironwood frontier at the preceding
//! block, so positions and witnesses still count actions before the birth block.

use std::{env, path::PathBuf, process};

use loki_poc::{rpc, scan, state::MemberDir, vault};

fn main() {
    if let Err(e) = run() {
        eprintln!("loki_indexer: {e}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let (root, cache, birth_height) = parse_args(env::args().skip(1))?;

    let ak: [u8; 32] = MemberDir::open(&root, "public")
        .read_hex("group_ak.hex")
        .map_err(|e| format!("run setup first: {e}"))?
        .try_into()
        .map_err(|_| "group_ak.hex is not 32 bytes")?;
    let fvk = vault::test_only_fvk(&ak).map_err(|e| format!("{e:?}"))?;

    let rpc = rpc::Rpc::regtest();
    let (notes, tip, actions, anchor) = if let Some(height) = birth_height {
        let chain = scan::scan_chain_cached_from_birth(&rpc, &fvk, &cache, height)?;
        (
            chain.notes,
            chain.tip,
            chain.witnesses.size(),
            chain.witnesses.root(),
        )
    } else {
        let chain = scan::scan_chain_cached(&rpc, &fvk, &cache)?;
        let anchor = scan::chain_anchor(&rpc, chain.tip)?;
        (chain.notes, chain.tip, chain.cmxs.len() as u64, anchor)
    };

    let total: u64 = notes.iter().map(|n| n.value_zat).sum();
    let notes: Vec<serde_json::Value> = notes
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
        "tip": tip,
        "actions": actions,
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

fn parse_args(
    mut args: impl Iterator<Item = String>,
) -> Result<(PathBuf, PathBuf, Option<u64>), String> {
    let usage = "usage: loki_indexer <state-dir> [cache-file] [--from-height N]";
    let root = PathBuf::from(args.next().ok_or(usage)?);
    let mut rest: Vec<_> = args.collect();
    let birth_height = if let Some(index) = rest.iter().position(|arg| arg == "--from-height") {
        if index + 2 != rest.len() {
            return Err(usage.into());
        }
        let height = rest[index + 1]
            .parse::<u64>()
            .map_err(|_| "--from-height requires a positive block height")?;
        if height == 0 {
            return Err("--from-height requires a positive block height".into());
        }
        rest.truncate(index);
        Some(height)
    } else {
        None
    };
    let cache = match rest.as_slice() {
        [] => root.join("indexer-cache.txt"),
        [path] => PathBuf::from(path),
        _ => return Err(usage.into()),
    };
    Ok((root, cache, birth_height))
}

#[cfg(test)]
mod tests {
    use super::parse_args;

    #[test]
    fn birth_height_flag_keeps_default_cache_and_rejects_invalid_heights() {
        let (_, cache, height) = parse_args(
            ["vault", "--from-height", "42"]
                .map(str::to_string)
                .into_iter(),
        )
        .unwrap();
        assert_eq!(cache.to_str(), Some("vault/indexer-cache.txt"));
        assert_eq!(height, Some(42));
        let (_, cache, height) = parse_args(
            ["vault", "other-cache", "--from-height", "42"]
                .map(str::to_string)
                .into_iter(),
        )
        .unwrap();
        assert_eq!(cache.to_str(), Some("other-cache"));
        assert_eq!(height, Some(42));
        assert_eq!(parse_args(["vault".into()].into_iter()).unwrap().2, None);
        assert!(parse_args(
            ["vault", "--from-height", "0"]
                .map(str::to_string)
                .into_iter()
        )
        .is_err());
    }
}
