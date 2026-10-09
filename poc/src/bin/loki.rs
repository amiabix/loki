//! The G1-TX CLI: `setup`, `propose`, `review-sign`, `finish`.
//!
//! Each stage is a separate process invocation with its own state directory, because the
//! point of the exercise is that a signer reviews and signs with only its own material.

use std::{collections::BTreeMap, env, path::PathBuf, process};

use loki_poc::{state::MemberDir, vault};
use reddsa_frost::frost::redpallas as frost;

const MEMBERS: [(&str, u16); 3] = [("alice", 1), ("bob", 2), ("carol", 3)];

/// Which shared directory this invocation uses.
///
/// Two payments run against one vault in the second-device test, and each needs its own
/// proposal, candidates, commitments and shares. `LOKI_ROUND=p2` puts them in `public_p2`
/// so the second payment cannot overwrite the first. Default is the original `public`.
fn shared_name() -> String {
    match std::env::var("LOKI_ROUND") {
        Ok(r) if !r.is_empty() => format!("public_{r}"),
        _ => "public".to_string(),
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let stage = args.get(1).map(String::as_str).unwrap_or("");

    let result = match stage {
        "setup" => setup(&args[2..]),
        "address" => address(&args[2..]),
        "scan" => scan(&args[2..]),
        "commit" => commit(&args[2..]),
        "propose" => propose(&args[2..]),
        "review-sign" => review_sign(&args[2..]),
        "finish" => finish(&args[2..]),
        "post-final" => post_final(&args[2..]),
        "replicate" => replicate(&args[2..]),
        "finish-second" => finish_second(&args[2..]),
        "verify-effects" => verify_effects(&args[2..]),
        "tamper" => tamper(&args[2..]),
        _ => {
            eprintln!(
                "loki <stage> [args]\n\
                 \n\
                 stages:\n\
                   setup   <state-dir>   run 2-of-3 DKG into three member directories\n\
                   address <state-dir>   print the vault's regtest unified address\n\
                   scan    <state-dir>   find the vault's Ironwood notes on regtest\n\
                   commit  <state-dir> <member> [--spends N]   round 1: preprocess nonces\n\
                   propose <state-dir> [note-file]\n\
                             [--to <unified-address>] [--amount <zat>] [--memo <text>]\n\
                             build the three unproved candidates\n\
                   review-sign <state-dir> <member>   review all, then sign\n\
                   finish  <state-dir>   aggregate AC, prove, broadcast\n\
                   post-final <state-dir>   aggregate and prove AC, post it, do NOT broadcast\n\
                   replicate <state-dir> <replica-dir> [--with-final]   confidential seed handoff\n\
                   finish-second <replica-dir> <work-dir>   finish from a replica + own scan\n\
                   verify-effects <replica-dir> <txid>   check the mined effects\n\
                   tamper  <state-dir> <case>   TEST-ONLY: corrupt candidate AC\n"
            );
            process::exit(2);
        }
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        process::exit(1);
    }
}

/// Checkpoint 2, first half: a real three-member 2-of-3 DKG.
///
/// Each member ends up with its own key package and the common public package. The
/// vault's spend key is never materialized: `part3` returns a share, never the secret.
fn setup(args: &[String]) -> Result<(), String> {
    let root = PathBuf::from(args.first().ok_or("usage: setup <state-dir>")?);
    let rng = rand_core::OsRng;

    let ids: Vec<frost::Identifier> = MEMBERS
        .iter()
        .map(|(_, i)| (*i).try_into().expect("nonzero identifier"))
        .collect();

    // Round 1: each member commits to its own polynomial.
    let mut r1_secret = BTreeMap::new();
    let mut r1_public = BTreeMap::new();
    for id in &ids {
        let (secret, public) =
            frost::keys::dkg::part1(*id, 3, 2, rng).map_err(|e| format!("dkg part1: {e}"))?;
        r1_secret.insert(*id, secret);
        r1_public.insert(*id, public);
    }

    // Round 2: per-peer packages.
    let mut r2_secret = BTreeMap::new();
    let mut r2_inbox: BTreeMap<frost::Identifier, BTreeMap<frost::Identifier, _>> = BTreeMap::new();
    for id in &ids {
        let others = peers(&r1_public, id);
        let (secret, outgoing) = frost::keys::dkg::part2(r1_secret.remove(id).unwrap(), &others)
            .map_err(|e| format!("dkg part2: {e}"))?;
        r2_secret.insert(*id, secret);
        for (to, pkg) in outgoing {
            r2_inbox.entry(to).or_default().insert(*id, pkg);
        }
    }

    // Round 3: each member derives its share and the common public package.
    let mut group_key: Option<[u8; 32]> = None;
    for (slot, (name, _)) in MEMBERS.iter().enumerate() {
        let id = ids[slot];
        let others = peers(&r1_public, &id);
        let (key_package, public_package) =
            frost::keys::dkg::part3(&r2_secret[&id], &others, &r2_inbox[&id])
                .map_err(|e| format!("dkg part3: {e}"))?;

        let ak: [u8; 32] = public_package
            .verifying_key()
            .serialize()
            .map_err(|e| format!("serialize group key: {e}"))?
            .try_into()
            .map_err(|_| "group key is not 32 bytes")?;

        match group_key {
            None => group_key = Some(ak),
            Some(seen) if seen != ak => return Err("members disagree on the group key".into()),
            _ => {}
        }

        let dir = MemberDir::create(&root, name).map_err(|e| format!("{name}: {e}"))?;
        dir.write_hex(
            "key_package.hex",
            &key_package.serialize().map_err(|e| format!("{e}"))?,
        )
        .map_err(|e| format!("{name}: {e}"))?;
        dir.write_hex(
            "public_package.hex",
            &public_package.serialize().map_err(|e| format!("{e}"))?,
        )
        .map_err(|e| format!("{name}: {e}"))?;
        dir.write_hex("identifier.hex", &id.serialize())
            .map_err(|e| format!("{name}: {e}"))?;

        println!("{name:<6} share written to {}", dir.path().display());
    }

    let ak = group_key.ok_or("no group key")?;
    let fvk = vault::test_only_fvk(&ak).map_err(|e| format!("vault key: {e:?}"))?;
    let ua = vault::regtest_unified_address(&fvk);

    // Public material only: every member process can recompute these.
    let shared = MemberDir::create(&root, "public").map_err(|e| e.to_string())?;
    shared
        .write_hex("group_ak.hex", &ak)
        .map_err(|e| e.to_string())?;
    shared
        .write_text("vault_address.txt", &ua)
        .map_err(|e| e.to_string())?;

    println!();
    println!("group ak      {}", hex::encode(ak));
    println!("vault address {ua}");
    println!();
    println!("The vault address is TEST-ONLY: nk and rivk come from a fixed fixture,");
    println!("not from the ZIP 2005 derivation. See DEPENDENCIES.md finding B1.");
    Ok(())
}

/// Print the vault address from already-written public state.
fn address(args: &[String]) -> Result<(), String> {
    let root = PathBuf::from(args.first().ok_or("usage: address <state-dir>")?);
    let shared = MemberDir::open(&root, "public");
    let ak: [u8; 32] = shared
        .read_hex("group_ak.hex")
        .map_err(|e| format!("run setup first: {e}"))?
        .try_into()
        .map_err(|_| "group_ak.hex is not 32 bytes")?;
    let fvk = vault::test_only_fvk(&ak).map_err(|e| format!("{e:?}"))?;
    println!("{}", vault::regtest_unified_address(&fvk));
    Ok(())
}

fn peers<T: Clone>(
    all: &BTreeMap<frost::Identifier, T>,
    me: &frost::Identifier,
) -> BTreeMap<frost::Identifier, T> {
    all.iter()
        .filter(|(id, _)| *id != me)
        .map(|(id, v)| (*id, v.clone()))
        .collect()
}

/// Checkpoint 2, second half: find the vault's funded Ironwood notes.
///
/// A narrow regtest fixture, not a wallet. Walks every block, rebuilds each Ironwood
/// action from the node's JSON, and trial-decrypts it with the vault's incoming viewing
/// key. Tree positions count every Ironwood action in order, which is the order the note
/// commitment tree appends them.
fn scan(args: &[String]) -> Result<(), String> {
    let root = PathBuf::from(args.first().ok_or("usage: scan <state-dir>")?);
    let shared = MemberDir::open(&root, "public");

    let ak: [u8; 32] = shared
        .read_hex("group_ak.hex")
        .map_err(|e| format!("run setup first: {e}"))?
        .try_into()
        .map_err(|_| "group_ak.hex is not 32 bytes")?;
    let fvk = vault::test_only_fvk(&ak).map_err(|e| format!("{e:?}"))?;
    let rpc = loki_poc::rpc::Rpc::regtest();
    let chain = loki_poc::scan::scan_chain(&rpc, &fvk)?;
    let tip = chain.tip;
    let cmxs = chain.cmxs;
    let notes = chain.notes;
    let position = cmxs.len();

    println!("scanned {tip} blocks, {position} Ironwood actions");
    println!("unspent vault notes: {}", notes.len());
    println!();

    let mut total = 0u64;
    for n in &notes {
        total += n.value_zat;
        println!(
            "  h{:<4} pos {:<4} {:>14} zat  nf {}  tx {}",
            n.height,
            n.position,
            n.value_zat,
            &hex::encode(n.nullifier)[..16],
            &n.txid[..16]
        );
    }
    println!();
    println!("total {total} zat ({:.8} ZEC)", total as f64 / 1e8);

    if notes.is_empty() {
        return Err("no vault notes found".into());
    }

    // The note we will spend: the largest, which on a coinbase-only chain is any of
    // them. Deepest wins so maturity is never in question.
    let best = notes
        .iter()
        .max_by_key(|n| (n.value_zat, std::cmp::Reverse(n.height)))
        .unwrap();

    // Rebuild the commitment tree and check it against the node's own anchor before
    // trusting any witness from it.
    let tree_state = rpc.json("z_gettreestate", &format!("[\"{tip}\"]"))?;
    let anchor_hex = tree_state["ironwood"]["commitments"]["finalRoot"]
        .as_str()
        .ok_or("z_gettreestate has no ironwood finalRoot")?;
    let anchor: [u8; 32] = hex::decode(anchor_hex)
        .map_err(|e| format!("anchor hex: {e}"))?
        .try_into()
        .map_err(|_| "anchor is not 32 bytes")?;

    let path = loki_poc::witness::witness_for(&cmxs, best.position, &anchor)?;
    println!();
    println!("anchor   {anchor_hex}");
    println!(
        "witness  position {} verified against the node's anchor",
        path.position()
    );

    shared
        .write_text(
            "anchor.txt",
            &format!("height={tip}\nironwood_final_root={anchor_hex}\n"),
        )
        .map_err(|e| e.to_string())?;
    shared
        .write_hex(
            "cmxs.hex",
            &cmxs
                .iter()
                .flat_map(|c| c.iter().copied())
                .collect::<Vec<u8>>(),
        )
        .map_err(|e| e.to_string())?;
    // Persist everything needed to reconstruct the Note itself, not just describe it.
    shared
        .write_text(
            "funded_note.txt",
            &format!(
                "height={}\ntxid={}\nposition={}\nvalue_zat={}\ncmx={}\nnullifier={}\n\
                 recipient={}\nrho={}\nrseed={}\n",
                best.height,
                best.txid,
                best.position,
                best.value_zat,
                hex::encode(best.cmx),
                hex::encode(best.nullifier),
                hex::encode(best.note.recipient().to_raw_address_bytes()),
                hex::encode(best.note.rho().to_bytes()),
                hex::encode(best.note.rseed().as_bytes()),
            ),
        )
        .map_err(|e| e.to_string())?;
    // A second note, for the adversarial input case: genuinely owned by the vault and
    // genuinely spendable, but not the one the intent names.
    if let Some(alt) = notes.iter().find(|n| n.position != best.position) {
        shared
            .write_text(
                "funded_note_alt.txt",
                &format!(
                    "height={}\ntxid={}\nposition={}\nvalue_zat={}\ncmx={}\nnullifier={}\n\
                     recipient={}\nrho={}\nrseed={}\n",
                    alt.height,
                    alt.txid,
                    alt.position,
                    alt.value_zat,
                    hex::encode(alt.cmx),
                    hex::encode(alt.nullifier),
                    hex::encode(alt.note.recipient().to_raw_address_bytes()),
                    hex::encode(alt.note.rho().to_bytes()),
                    hex::encode(alt.note.rseed().as_bytes()),
                ),
            )
            .map_err(|e| e.to_string())?;
    }

    // Every note the vault owns, so the proposer can choose a set that covers a payment
    // rather than being limited to whatever single note this scan happened to rank first.
    // The two single-note files above stay for the scripts and the tamper harness, which
    // name them directly.
    let mut all = String::new();
    for n in &notes {
        all.push_str(&format!(
            "height={} txid={} position={} value_zat={} cmx={} nullifier={} \
             recipient={} rho={} rseed={}\n",
            n.height,
            n.txid,
            n.position,
            n.value_zat,
            hex::encode(n.cmx),
            hex::encode(n.nullifier),
            hex::encode(n.note.recipient().to_raw_address_bytes()),
            hex::encode(n.note.rho().to_bytes()),
            hex::encode(n.note.rseed().as_bytes()),
        ));
    }
    shared
        .write_text("funded_notes.txt", &all)
        .map_err(|e| e.to_string())?;

    println!();
    println!(
        "funding fixture written: {}/public/funded_note.txt",
        root.display()
    );
    println!(
        "all {} vault notes written to public/funded_notes.txt",
        notes.len()
    );
    Ok(())
}

fn hex32(v: &serde_json::Value, key: &str) -> Option<[u8; 32]> {
    hex::decode(v[key].as_str()?).ok()?.try_into().ok()
}

/// The three candidate pairs, by member slot.
const PAIRS: [(&str, usize, usize); 3] = [("AB", 0, 1), ("AC", 0, 2), ("BC", 1, 2)];

/// Checkpoint 3, round 1: each member preprocesses one nonce pair per candidate it is in.
///
/// Nonces stay in the member's own directory and never leave it. Only commitments are
/// published. Each candidate gets its own nonce pair, which is what keeps one signer's
/// two candidates independent.
fn commit(args: &[String]) -> Result<(), String> {
    let root = PathBuf::from(args.first().ok_or("usage: commit <state-dir> <member>")?);
    let who = args
        .get(1)
        .ok_or("usage: commit <state-dir> <member>")?
        .as_str();

    let slot = MEMBERS
        .iter()
        .position(|(n, _)| *n == who)
        .ok_or_else(|| format!("unknown member {who}"))?;

    let me = MemberDir::open(&root, who);
    let key_package = frost::keys::KeyPackage::deserialize(
        &me.read_hex("key_package.hex")
            .map_err(|e| format!("run setup first: {e}"))?,
    )
    .map_err(|e| format!("key package: {e}"))?;

    // Commitments belong to the round, not to the vault: a second payment needs its own.
    let shared = MemberDir::create(&root, &shared_name()).map_err(|e| format!("{e}"))?;
    let mut rng = rand_core::OsRng;

    // One nonce pair per candidate PER SPEND. A transaction that spends several notes has
    // one Orchard action per note, each with its own `rk`, so each needs its own FROST
    // signature and therefore its own single-use nonce. Sharing one across two actions
    // would be nonce reuse, which hands over the signing share.
    //
    // The count is fixed here rather than discovered later because commitments must exist
    // before the proposer can derive a randomiser from them.
    let spends: usize = match flag(args, "--spends") {
        Some(v) => v
            .parse()
            .map_err(|e| format!("--spends must be a whole number: {e}"))?,
        None => 1,
    };
    if spends == 0 {
        return Err("--spends must be at least 1".into());
    }

    for (name, x, y) in PAIRS {
        if slot != x && slot != y {
            continue;
        }

        for i in 0..spends {
            let (nonces, commitment) = frost::round1::commit(key_package.signing_share(), &mut rng);

            // Secret: stays here.
            me.write_hex(
                &nonce_file(name, i),
                &nonces.serialize().map_err(|e| format!("{e}"))?,
            )
            .map_err(|e| e.to_string())?;

            // Public: goes to the proposer.
            shared
                .write_hex(
                    &commitment_file(name, who, i),
                    &commitment.serialize().map_err(|e| format!("{e}"))?,
                )
                .map_err(|e| e.to_string())?;
        }

        println!("{who:<6} {name}  {spends} nonce pair(s) stored, commitment(s) published");
    }

    Ok(())
}

/// Read `key=value` lines into a map.
fn kv(text: &str) -> std::collections::HashMap<String, String> {
    text.lines()
        .filter_map(|l| l.split_once('='))
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .collect()
}

fn hexn<const N: usize>(
    m: &std::collections::HashMap<String, String>,
    k: &str,
) -> Result<[u8; N], String> {
    hex::decode(m.get(k).ok_or_else(|| format!("missing {k}"))?)
        .map_err(|e| format!("{k}: {e}"))?
        .try_into()
        .map_err(|_| format!("{k} is not {N} bytes"))
}

/// Checkpoint 3: build the three unproved candidates from one intent.
///
/// Every candidate spends the same note, pays the same recipient the same amount with the
/// same memo, fee, change and expiry. Only the signing pair differs, so only `alpha` and
/// therefore `rk` differ. All three are built with the anchor and witness ABSENT.
/// Read `--name value` from the stage's own arguments.
///
/// Deliberately minimal: the CLI takes a handful of flags and a dependency for that would
/// be heavier than the thing it parses.
fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

/// The nullifiers this proposal spends, in the order the proposer chose.
///
/// Order is load-bearing: spend `i` uses commitment `i`, nonce `i` and randomiser `i`, so
/// a stage that read them in a different order would check one spend's `rk` against
/// another spend's alpha. Written comma-separated on one line so the fixture stays a flat
/// key=value file.
fn intent_nullifiers(
    m: &std::collections::HashMap<String, String>,
) -> Result<Vec<[u8; 32]>, String> {
    let raw = m
        .get("input_nullifier")
        .ok_or("intent has no input_nullifier")?;
    let nullifiers: Vec<[u8; 32]> = raw
        .split(',')
        .filter(|f| !f.trim().is_empty())
        .map(|f| {
            hex::decode(f.trim())
                .map_err(|e| format!("input_nullifier: {e}"))?
                .try_into()
                .map_err(|_| "input_nullifier is not 32 bytes".to_string())
        })
        .collect::<Result<_, _>>()?;
    if nullifiers.is_empty()
        || nullifiers
            .iter()
            .enumerate()
            .any(|(i, nf)| nullifiers[..i].contains(nf))
    {
        return Err("intent has no inputs or repeats an input nullifier".into());
    }
    Ok(nullifiers)
}

/// Where a member keeps its signature share for spend `i` of candidate `pair`. Same
/// index-0-keeps-the-old-name rule as the nonce and commitment files.
fn share_file(pair: &str, who: &str, i: usize) -> String {
    if i == 0 {
        format!("share_{pair}_{who}.hex")
    } else {
        format!("share_{pair}_{who}_{i}.hex")
    }
}

/// Split one space-separated `key=value` record into a map.
///
/// `kv` reads one pair per LINE, so it cannot parse a record written on a single line:
/// the first key swallows the rest. `funded_notes.txt` keeps one note per line so the
/// file stays greppable, which means it needs this.
fn kv_record(line: &str) -> std::collections::HashMap<String, String> {
    line.split_whitespace()
        .filter_map(|f| f.split_once('='))
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

/// Rebuild a note from the fields `scan` recorded, and check it is the note it claims.
///
/// The nullifier check is the point: it is derived from the note and the vault key, so a
/// note whose recorded nullifier does not match was not reconstructed correctly and must
/// not be spent.
type SpendNote = (orchard::Note, [u8; 32], u64);

fn note_from_kv(
    m: &std::collections::HashMap<String, String>,
    fvk: &orchard::keys::FullViewingKey,
) -> Result<SpendNote, String> {
    use orchard::{
        note::{RandomSeed, Rho},
        value::NoteValue,
        Note, NoteVersion,
    };

    let rho = Rho::from_bytes(&hexn::<32>(m, "rho")?)
        .into_option()
        .ok_or("note has an invalid rho")?;
    let rseed = RandomSeed::from_bytes(hexn::<32>(m, "rseed")?, &rho)
        .into_option()
        .ok_or("note has an invalid rseed")?;
    let value: u64 = m["value_zat"].parse().map_err(|e| format!("value: {e}"))?;
    let note = Note::from_parts(
        orchard::Address::from_raw_address_bytes(&hexn::<43>(m, "recipient")?)
            .into_option()
            .ok_or("note has an invalid recipient")?,
        NoteValue::from_raw(value),
        rho,
        rseed,
        NoteVersion::V3,
    )
    .into_option()
    .ok_or("note does not reconstruct")?;

    let expect: [u8; 32] = hexn(m, "nullifier")?;
    if note.nullifier(fvk).to_bytes() != expect {
        return Err("reconstructed note has a different nullifier than the scan recorded".into());
    }
    let position: u64 = m["position"]
        .parse()
        .map_err(|e| format!("position: {e}"))?;
    Ok((note, expect, position))
}

/// Choose notes that cover `amount` plus the fee those notes imply.
///
/// Largest first, which keeps the action count down, and the action count is what ZIP 317
/// charges for. The fee is re-quoted after each addition because adding a note adds an
/// action and therefore raises the fee: selecting against a fixed fee quote would
/// occasionally come up one note short.
fn select_notes(
    available: &[SpendNote],
    fvk: &orchard::keys::FullViewingKey,
    recipient: orchard::Address,
    amount: zcash_protocol::value::Zatoshis,
    memo: &zcash_protocol::memo::MemoBytes,
    target_height: u32,
    expiry_height: u32,
) -> Result<(Vec<SpendNote>, zcash_protocol::value::Zatoshis), String> {
    use loki_poc::candidate::{quote_fee, CandidateInputs, Regtest};
    use zcash_protocol::value::Zatoshis;

    let mut by_value = available.to_vec();
    by_value.sort_by_key(|(n, _, _)| std::cmp::Reverse(n.value().inner()));

    let mut chosen: Vec<SpendNote> = Vec::new();
    for candidate_note in by_value {
        chosen.push(candidate_note);

        let inputs = CandidateInputs {
            vault_fvk: fvk,
            notes: chosen.iter().map(|(n, _, _)| *n).collect(),
            recipient,
            amount,
            memo: memo.clone(),
            change: Zatoshis::ZERO,
            target_height,
            expiry_height,
        };
        let fee = quote_fee(&Regtest, &inputs)?;
        let total: u64 = chosen.iter().map(|(n, _, _)| n.value().inner()).sum();
        let needed = u64::from(amount)
            .checked_add(u64::from(fee))
            .ok_or("amount plus fee overflows")?;
        if total >= needed {
            return Ok((chosen, fee));
        }
    }

    let total: u64 = available.iter().map(|(n, _, _)| n.value().inner()).sum();
    Err(format!(
        "insufficient funds: the account holds {total} zat across {} note(s), which does \
         not cover {} zat plus the fee those notes would imply",
        available.len(),
        u64::from(amount),
    ))
}

/// Where a member keeps the nonce pair for spend `i` of candidate `pair`.
///
/// Spend 0 keeps the original unindexed name. That is not tidiness: the demo runner, the
/// tamper harness and the shell scripts all name these files directly, and renaming the
/// common case would break them for no benefit.
fn nonce_file(pair: &str, i: usize) -> String {
    if i == 0 {
        format!("nonces_{pair}.hex")
    } else {
        format!("nonces_{pair}_{i}.hex")
    }
}

/// The published counterpart of [`nonce_file`]. Same compatibility rule.
fn commitment_file(pair: &str, who: &str, i: usize) -> String {
    if i == 0 {
        format!("commitment_{pair}_{who}.hex")
    } else {
        format!("commitment_{pair}_{who}_{i}.hex")
    }
}

fn seed_file(pair: &str, i: usize) -> String {
    if i == 0 {
        format!("randomizer_seed_{pair}.hex")
    } else {
        format!("randomizer_seed_{pair}_{i}.hex")
    }
}

fn write_seed_record(
    shared: &MemberDir,
    pair: &str,
    i: usize,
    record: &loki_poc::randomizer::SeedRecord,
) -> Result<(), String> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(shared.path().join(seed_file(pair, i)))
        .map_err(|e| e.to_string())?;
    file.write_all(record.encode()?.as_bytes())
        .map_err(|e| e.to_string())
}

fn check_seed_record_count(shared: &MemberDir, pair: &str, spends: usize) -> Result<(), String> {
    let expected: Vec<_> = (0..spends).map(|i| seed_file(pair, i)).collect();
    for entry in std::fs::read_dir(shared.path()).map_err(|e| e.to_string())? {
        let name = entry
            .map_err(|e| e.to_string())?
            .file_name()
            .to_string_lossy()
            .into_owned();
        if (name == seed_file(pair, 0) || name.starts_with(&format!("randomizer_seed_{pair}_")))
            && !expected.contains(&name)
        {
            return Err(format!(
                "REFUSED: unexpected randomizer seed record count for {pair}: {name}"
            ));
        }
    }
    // Missing expected records retain the descriptive missing-record refusal when loaded.
    Ok(())
}

fn load_seed_record(
    shared: &MemberDir,
    pair: &str,
    i: usize,
) -> Result<loki_poc::randomizer::SeedRecord, String> {
    let file = seed_file(pair, i);
    let text = shared
        .read_text(&file)
        .map_err(|e| format!("REFUSED: missing randomizer seed record {file}: {e}"))?;
    loki_poc::randomizer::SeedRecord::decode(&text).map_err(|e| format!("REFUSED: {file}: {e}"))
}

fn checked_proposal_id(m: &std::collections::HashMap<String, String>) -> Result<[u8; 32], String> {
    use loki_poc::intent::{ChangePolicy, Intent};
    let number = |k: &str| -> Result<u64, String> {
        m.get(k)
            .ok_or(format!("missing {k}"))?
            .parse()
            .map_err(|e| format!("{k}: {e}"))
    };
    if m.get("change_policy").map(String::as_str) != Some("vault_internal") {
        return Err("REFUSED: unknown change policy".into());
    }
    let intent = Intent {
        proposer: hex::decode(m.get("proposer").ok_or("missing proposer")?)
            .map_err(|e| e.to_string())?,
        created_height: number("created_height")?
            .try_into()
            .map_err(|_| "created_height overflow")?,
        input_nullifiers: intent_nullifiers(m)?,
        recipient: hex::decode(m.get("recipient").ok_or("missing recipient")?)
            .map_err(|e| e.to_string())?,
        amount_zat: number("amount_zat")?,
        memo: hex::decode(m.get("memo").ok_or("missing memo")?).map_err(|e| e.to_string())?,
        change_policy: ChangePolicy::VaultInternal,
        fee_zat: number("fee_zat")?,
        change_zat: number("change_zat")?,
        expiry_height: number("expiry_height")?
            .try_into()
            .map_err(|_| "expiry_height overflow")?,
    };
    let recorded = hexn(m, "proposal_id")?;
    if intent.proposal_id() != recorded {
        return Err("REFUSED: proposal ID differs from canonical intent".into());
    }
    Ok(recorded)
}

fn check_randomized_spend(
    candidate: &pczt::Pczt,
    nf: &[u8; 32],
    params: &frost_rerandomized::RandomizedParams<frost::PallasBlake2b512>,
    ak: &[u8; 32],
) -> Result<usize, String> {
    use pczt::roles::low_level_signer::Signer;
    let alpha: [u8; 32] = params
        .randomizer()
        .serialize()
        .try_into()
        .map_err(|_| "alpha length")?;
    let scalar =
        loki_poc::candidate::alpha_from_canonical_bytes(&alpha).ok_or("noncanonical alpha")?;
    let fvk = vault::test_only_fvk(ak).map_err(|e| format!("{e:?}"))?;
    let expected: orchard::primitives::redpallas::VerificationKey<
        orchard::primitives::redpallas::SpendAuth,
    > = orchard::keys::SpendValidatingKey::from(fvk).randomize(&scalar);
    let expected_rk = <[u8; 32]>::from(&expected);
    if params
        .randomized_verifying_key()
        .serialize()
        .map_err(|e| e.to_string())?
        != expected_rk
    {
        return Err("REFUSED: public package differs from known vault key".into());
    }
    let mut found = None;
    Signer::new(candidate.clone())
        .sign_ironwood_with::<pczt::roles::low_level_signer::OrchardParseError, _>(
            |_, bundle, _| {
                for (index, action) in bundle.actions().iter().enumerate() {
                    if action.spend().nullifier().to_bytes() == *nf {
                        found = Some((
                            index,
                            *action.spend().alpha(),
                            <[u8; 32]>::from(action.spend().rk()),
                        ));
                    }
                }
                Ok(())
            },
        )
        .map_err(|e| format!("parse spend: {e:?}"))?;
    let (index, actual_alpha, actual_rk) =
        found.ok_or("REFUSED: candidate missing intended nullifier")?;
    if actual_alpha != Some(scalar) || actual_rk != expected_rk {
        return Err("REFUSED: rk does not match recomputed alpha".into());
    }
    Ok(index)
}

fn propose(args: &[String]) -> Result<(), String> {
    use loki_poc::{candidate::*, intent::*};
    use orchard::keys::Scope;
    use zcash_protocol::consensus::Parameters as _;
    use zcash_protocol::{memo::MemoBytes, value::Zatoshis};

    let root = PathBuf::from(
        args.first()
            .ok_or("usage: propose <state-dir> [note-file]")?,
    );
    // Vault-level state (the group key, the scan output) lives in `public` whatever round
    // this is; the proposal and its candidates belong to the round.
    let vault_dir = MemberDir::open(&root, "public");
    let shared = MemberDir::create(&root, &shared_name()).map_err(|e| format!("{e}"))?;
    if std::fs::read_dir(shared.path())
        .map_err(|e| e.to_string())?
        .any(|entry| {
            entry
                .ok()
                .and_then(|e| e.file_name().into_string().ok())
                .is_some_and(|f| {
                    f == "intent.txt"
                        || f.starts_with("candidate_")
                        || f.starts_with("randomizer_seed_")
                        || f.starts_with("alpha_")
                        || f.starts_with("share_")
                })
        })
    {
        return Err("REFUSED: saved signing session exists; keep its candidate and seeds unchanged, or use a fresh round with fresh commitments".into());
    }
    // The note file is positional and optional, so it must not swallow a flag: without
    // this guard `propose <dir> --amount N` read "--amount" as the filename.
    let note_file = args
        .get(1)
        .map(String::as_str)
        .filter(|a| !a.starts_with("--"))
        .unwrap_or("funded_note.txt");

    // ── the vault and its funded note ───────────────────────────────────────
    let ak: [u8; 32] = vault_dir
        .read_hex("group_ak.hex")
        .map_err(|e| format!("run setup first: {e}"))?
        .try_into()
        .map_err(|_| "group_ak.hex is not 32 bytes")?;
    let public_package = frost::keys::PublicKeyPackage::deserialize(
        &MemberDir::open(&root, "alice")
            .read_hex("public_package.hex")
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if public_package
        .verifying_key()
        .serialize()
        .map_err(|e| e.to_string())?
        != ak
    {
        return Err("REFUSED: public package differs from known vault key".into());
    }
    let fvk = vault::test_only_fvk(&ak).map_err(|e| format!("{e:?}"))?;

    // Which notes are available to spend. A named note file pins the choice to exactly
    // that one, which is what the tamper harness and the second-device script rely on;
    // otherwise every scanned note is a candidate and the selector picks a covering set.
    let named_note = args
        .get(1)
        .map(String::as_str)
        .filter(|a| !a.starts_with("--"))
        .is_some();
    let available: Vec<SpendNote> = if named_note {
        let m = kv(&vault_dir
            .read_text(note_file)
            .map_err(|e| format!("run scan first: {e}"))?);
        vec![note_from_kv(&m, &fvk)?]
    } else if vault_dir.exists("funded_notes.txt") {
        vault_dir
            .read_text("funded_notes.txt")
            .map_err(|e| format!("{e}"))?
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| note_from_kv(&kv_record(l), &fvk))
            .collect::<Result<_, String>>()?
    } else {
        let m = kv(&vault_dir
            .read_text(note_file)
            .map_err(|e| format!("run scan first: {e}"))?);
        vec![note_from_kv(&m, &fvk)?]
    };
    if available.is_empty() {
        return Err("the account holds no notes; run scan after the chain has funded it".into());
    }

    // ── the intent ──────────────────────────────────────────────────────────
    let rpc = loki_poc::rpc::Rpc::regtest();
    let tip = rpc
        .json("getblockcount", "[]")?
        .as_u64()
        .ok_or("getblockcount")? as u32;

    // One week at 75s blocks, rounded up to a 1,152-block boundary.
    const WEEK_BLOCKS: u32 = 7 * 24 * 60 * 60 / 75;
    let expiry = {
        let want = tip + WEEK_BLOCKS;
        want.div_ceil(1_152) * 1_152
    };

    // The payment, from the caller. Defaults reproduce what this stage did when the
    // values were hard-coded, so the existing scripts are unaffected.
    const DEFAULT_AMOUNT: u64 = 40_000_000;
    const DEFAULT_MEMO: &str = "loki g1-tx";

    let recipient = match flag(args, "--to") {
        Some(a) => vault::orchard_receiver_from_ua(&a, Regtest.network_type())?,
        None => fvk.address_at(7u64, Scope::External),
    };
    let amount_zat: u64 = match flag(args, "--amount") {
        Some(v) => v
            .parse()
            .map_err(|e| format!("--amount must be a whole number of zatoshis: {e}"))?,
        None => DEFAULT_AMOUNT,
    };
    if amount_zat == 0 {
        return Err("--amount must be greater than zero".into());
    }
    let amount = Zatoshis::from_u64(amount_zat)
        .map_err(|e| format!("--amount is not a valid amount: {e:?}"))?;

    let memo_text = flag(args, "--memo").unwrap_or_else(|| DEFAULT_MEMO.to_string());
    let memo = MemoBytes::from_bytes(memo_text.as_bytes())
        .map_err(|e| format!("--memo: {e:?} (at most 512 bytes)"))?;

    // Pick a covering set. The fee is quoted inside the selector because each added note
    // is another action and ZIP 317 charges by action count, so a fee quoted once up
    // front would occasionally leave the selection one note short.
    let (chosen, fee) = select_notes(&available, &fvk, recipient, amount, &memo, tip, expiry)?;
    let selected_total: u64 = chosen.iter().map(|(n, _, _)| n.value().inner()).sum();
    let needed = amount_zat
        .checked_add(u64::from(fee))
        .ok_or("amount plus fee overflows")?;
    let change = Zatoshis::from_u64(selected_total - needed)
        .map_err(|e| format!("change is not a valid amount: {e:?}"))?;

    let inputs = CandidateInputs {
        vault_fvk: &fvk,
        notes: chosen.iter().map(|(n, _, _)| *n).collect(),
        recipient,
        amount,
        memo: memo.clone(),
        change,
        target_height: tip,
        expiry_height: expiry,
    };
    let spend_nullifiers: Vec<[u8; 32]> = chosen.iter().map(|(_, nf, _)| *nf).collect();

    let intent = Intent {
        proposer: MemberDir::open(&root, "alice")
            .read_hex("identifier.hex")
            .map_err(|e| format!("{e}"))?,
        created_height: tip,
        input_nullifiers: spend_nullifiers.clone(),
        recipient: recipient.to_raw_address_bytes().to_vec(),
        amount_zat: u64::from(amount),
        memo: memo_text.as_bytes().to_vec(),
        change_policy: ChangePolicy::VaultInternal,
        fee_zat: u64::from(fee),
        change_zat: u64::from(change),
        expiry_height: expiry,
    };
    let proposal_id = intent.proposal_id();

    // The machine-readable fixture the signers check against. Not an annotation on the
    // proposal: the signers read this, and recompute the proposal id from it.
    shared
        .write_text(
            "intent.txt",
            &format!(
                "proposal_id={}\nproposer={}\ncreated_height={}\ninput_nullifier={}\n\
                 recipient={}\namount_zat={}\nmemo={}\nchange_policy=vault_internal\n\
                 fee_zat={}\nchange_zat={}\nexpiry_height={}\ntarget_height={}\n",
                hex::encode(proposal_id),
                hex::encode(&intent.proposer),
                intent.created_height,
                spend_nullifiers
                    .iter()
                    .map(hex::encode)
                    .collect::<Vec<_>>()
                    .join(","),
                hex::encode(&intent.recipient),
                intent.amount_zat,
                hex::encode(&intent.memo),
                intent.fee_zat,
                intent.change_zat,
                intent.expiry_height,
                tip,
            ),
        )
        .map_err(|e| e.to_string())?;

    // The round dir has to stand alone for `replicate`, so the group ak travels with it.
    shared
        .write_hex("group_ak.hex", &ak)
        .map_err(|e| e.to_string())?;

    println!("proposal   {}", hex::encode(proposal_id));
    println!(
        "spend      {} zat across {} note(s) at position(s) {}",
        selected_total,
        chosen.len(),
        chosen
            .iter()
            .map(|(_, _, p)| p.to_string())
            .collect::<Vec<_>>()
            .join(", "),
    );
    println!(
        "pay        {} zat  fee {}  change {}",
        u64::from(amount),
        u64::from(fee),
        u64::from(change)
    );
    println!("expiry     {expiry}  (tip {tip})");
    println!();

    // ── three candidates ────────────────────────────────────────────────────
    let mut seen_rk: Vec<[u8; 32]> = Vec::new();

    for (name, x, y) in PAIRS {
        let ids: Vec<frost::Identifier> = [x, y]
            .iter()
            .map(|k| {
                let raw = MemberDir::open(&root, MEMBERS[*k].0)
                    .read_hex("identifier.hex")
                    .map_err(|e| format!("{e}"))?;
                frost::Identifier::deserialize(&raw).map_err(|e| format!("identifier: {e}"))
            })
            .collect::<Result<_, String>>()?;

        // One randomiser per spend, each from that spend's own commitment set. Every spend
        // is a separate Orchard action with its own `rk` and its own FROST signature, so
        // reusing one randomiser across two of them would mean signing twice under the
        // same key.
        let mut alphas = Vec::with_capacity(spend_nullifiers.len());
        let mut alpha_bytes: Vec<[u8; 32]> = Vec::with_capacity(spend_nullifiers.len());
        for i in 0..spend_nullifiers.len() {
            let mut commitments = BTreeMap::new();
            for (slot, id) in [x, y].iter().zip(ids.iter()) {
                let raw = shared
                    .read_hex(&commitment_file(name, MEMBERS[*slot].0, i))
                    .map_err(|e| {
                        format!(
                            "this payment spends {} note(s), so each member needs that \
                             many commitments; run: commit <state-dir> <member> \
                             --spends {} ({e})",
                            spend_nullifiers.len(),
                            spend_nullifiers.len(),
                        )
                    })?;
                commitments.insert(
                    *id,
                    frost::round1::SigningCommitments::deserialize(&raw)
                        .map_err(|e| format!("commitment: {e}"))?,
                );
            }

            let (params, seed) = frost_rerandomized::RandomizedParams::new_from_commitments(
                public_package.verifying_key(),
                &commitments,
                rand_core::OsRng,
            )
            .map_err(|e| format!("randomizer: {e}"))?;
            let record = loki_poc::randomizer::SeedRecord::new(
                proposal_id,
                name,
                i,
                spend_nullifiers[i],
                &commitments,
                &seed,
            )?;
            write_seed_record(&shared, name, i, &record)?;
            let alpha_arr: [u8; 32] = params
                .randomizer()
                .serialize()
                .as_slice()
                .try_into()
                .map_err(|_| "alpha is not 32 bytes")?;
            alphas.push(
                alpha_from_canonical_bytes(&alpha_arr)
                    .ok_or("derived alpha is not a canonical Pallas scalar")?,
            );
            alpha_bytes.push(alpha_arr);
        }

        let built = build_candidate(
            &Regtest,
            &inputs,
            &alphas,
            rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng),
        )?;

        let bundle = built
            .pczt_parts
            .ironwood
            .as_ref()
            .ok_or("no ironwood bundle")?;

        if !*bundle.anchor_deferred() {
            return Err(format!("{name}: anchor is not deferred"));
        }
        if bundle.zkproof().is_some() {
            return Err(format!("{name}: proof is present before proving"));
        }

        let real: Vec<_> = bundle
            .actions()
            .iter()
            .filter(|a| spend_nullifiers.contains(&a.spend().nullifier().to_bytes()))
            .collect();
        if real.len() != spend_nullifiers.len() {
            return Err(format!(
                "{name}: expected {} real spend(s), found {}",
                spend_nullifiers.len(),
                real.len(),
            ));
        }
        // Every spend, not just the first: checking only `real[0]` would have let a
        // second action keep a witness or repeat an `rk` without anyone noticing.
        for a in &real {
            if a.spend().witness().is_some() {
                return Err(format!("{name}: a real spend already has a witness"));
            }
            let rk = <[u8; 32]>::from(a.spend().rk());
            if seen_rk.contains(&rk) {
                return Err(format!(
                    "{name}: rk {} collides with another spend or candidate",
                    &hex::encode(rk)[..16],
                ));
            }
            seen_rk.push(rk);
        }
        let spend_count = real.len();
        let first_rk = <[u8; 32]>::from(real[0].spend().rk());

        // Serialize the PCZT: this is the handoff artifact the signers receive.
        let pczt = pczt::roles::creator::Creator::build_from_parts(built.pczt_parts)
            .ok_or_else(|| format!("{name}: build_from_parts"))?;

        // IO Finalizer: no more inputs or outputs may be added after this, and it derives
        // the binding signature signing key. It must run BEFORE anyone computes a
        // sighash, or the signers would sign a transaction whose IO was still open.
        let pczt = pczt::roles::io_finalizer::IoFinalizer::new(pczt)
            .finalize_io(rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng))
            .map_err(|e| format!("{name}: io finalizer: {e:?}"))?;

        let bytes = pczt
            .serialize()
            .map_err(|e| format!("{name}: serialize: {e:?}"))?;

        shared
            .write_hex(&format!("candidate_{name}.pczt.hex"), &bytes)
            .map_err(|e| e.to_string())?;
        // One alpha file per spend, matching the commitment and nonce naming so a reader
        // can line all three up by index.
        for (i, a) in alpha_bytes.iter().enumerate() {
            let file = if i == 0 {
                format!("alpha_{name}.hex")
            } else {
                format!("alpha_{name}_{i}.hex")
            };
            shared.write_hex(&file, a).map_err(|e| e.to_string())?;
        }

        println!(
            "{name}  {} spend(s)  rk {}  alpha {}  {} bytes, anchor deferred, no witness, no proof",
            spend_count,
            &hex::encode(first_rk)[..16],
            &hex::encode(alpha_bytes[0])[..16],
            bytes.len()
        );
    }

    println!();
    println!("three candidates written to {}/public/", root.display());
    Ok(())
}

/// Checkpoint 4: review every candidate this member is in, then sign them all.
///
/// The signer receives only its own key package and nonces, the public vault material,
/// the machine-readable intent, and the serialized candidates. It parses the PCZT bytes
/// itself and computes its own sighash; no coordinator-supplied sighash is accepted, and
/// the FROST signing package is built here rather than received.
///
/// Nothing is emitted until every candidate containing this member has passed.
fn review_sign(args: &[String]) -> Result<(), String> {
    use loki_poc::verify::{Expectations, Refusal};
    use pczt::roles::{
        low_level_signer::Signer as LowLevelSigner,
        signer::Signer,
        verifier::{OrchardError, Verifier},
    };

    let root = PathBuf::from(
        args.first()
            .ok_or("usage: review-sign <state-dir> <member>")?,
    );
    let who = args
        .get(1)
        .ok_or("usage: review-sign <state-dir> <member>")?
        .as_str();
    let slot = MEMBERS
        .iter()
        .position(|(n, _)| *n == who)
        .ok_or_else(|| format!("unknown member {who}"))?;

    let me = MemberDir::open(&root, who);
    let shared = MemberDir::open(&root, &shared_name());

    let key_package = frost::keys::KeyPackage::deserialize(
        &me.read_hex("key_package.hex").map_err(|e| format!("{e}"))?,
    )
    .map_err(|e| format!("key package: {e}"))?;

    // The intent fixture: machine-readable, and the signer recomputes the proposal id
    // from it rather than trusting the one it was handed.
    let intent_kv = kv(&shared.read_text("intent.txt").map_err(|e| format!("{e}"))?);
    let want_nfs = intent_nullifiers(&intent_kv)?;
    let want_recipient: [u8; 43] = hexn(&intent_kv, "recipient")?;
    let want_amount: u64 = intent_kv["amount_zat"]
        .parse()
        .map_err(|e| format!("{e}"))?;
    let want_change: u64 = intent_kv["change_zat"]
        .parse()
        .map_err(|e| format!("{e}"))?;
    let want_memo = hex::decode(&intent_kv["memo"]).map_err(|e| format!("{e}"))?;
    let want_expiry: u32 = intent_kv["expiry_height"]
        .parse()
        .map_err(|e| format!("{e}"))?;
    let want_fee: u64 = intent_kv["fee_zat"].parse().map_err(|e| format!("{e}"))?;
    let proposal_id = checked_proposal_id(&intent_kv)?;

    // The vault key: the signer derives the change address from this itself rather than
    // taking one from the intent, so a swapped change address cannot be smuggled in.
    let ak: [u8; 32] = shared
        .read_hex("group_ak.hex")
        .map_err(|e| format!("{e}"))?
        .try_into()
        .map_err(|_| "group_ak.hex is not 32 bytes")?;
    let public_package = frost::keys::PublicKeyPackage::deserialize(
        &me.read_hex("public_package.hex")
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if public_package
        .verifying_key()
        .serialize()
        .map_err(|e| e.to_string())?
        != ak
    {
        return Err("REFUSED: public package differs from known vault key".into());
    }
    let known_ak = MemberDir::open(&root, "public")
        .read_hex("group_ak.hex")
        .map_err(|e| e.to_string())?;
    if known_ak != ak
        || key_package
            .verifying_key()
            .serialize()
            .map_err(|e| e.to_string())?
            != ak
    {
        return Err("REFUSED: public package differs from known vault key".into());
    }
    let vault_fvk = vault::test_only_fvk(&ak).map_err(|e| format!("{e:?}"))?;

    let want = Expectations {
        input_nullifiers: want_nfs.clone(),
        recipient: want_recipient,
        amount_zat: want_amount,
        memo: want_memo.clone(),
        change_zat: want_change,
        fee_zat: want_fee,
        expiry_height: want_expiry,
    };

    // ── review every candidate this member is in, emitting nothing yet ──────
    let mut reviewed = Vec::new();

    for (name, x, y) in PAIRS {
        if slot != x && slot != y {
            continue;
        }
        check_seed_record_count(&shared, name, want_nfs.len())?;

        let bytes = shared
            .read_hex(&format!("candidate_{name}.pczt.hex"))
            .map_err(|e| format!("{name}: {e}"))?;
        let pczt = pczt::Pczt::parse(&bytes).map_err(|e| format!("{name}: parse: {e:?}"))?;

        // Full Verifier checks over these exact bytes, which low_level_signer requires
        // before its preverified signing parse may be trusted. Every effect the intent
        // names is proven against the PCZT's cryptographic openings here.
        let checked = Verifier::new(pczt.clone())
            .with_ironwood::<Refusal, _>(|bundle| {
                loki_poc::verify::check_candidate(bundle, &vault_fvk, &want)
                    .map_err(OrchardError::Custom)
            })
            .map_err(|e| format!("{name}: REFUSED: {e:?}"))?
            .finish();

        // G1-TX is an Ironwood-only transaction. Every other pool must be empty, or value
        // could enter or leave by a route the Ironwood checks above never inspect.
        if !checked.orchard().actions().is_empty() {
            return Err(format!(
                "{name}: REFUSED: {}",
                Refusal::ExtraOutputOrPool("the Orchard pool is in use".into())
            ));
        }
        if !checked.transparent().inputs().is_empty() || !checked.transparent().outputs().is_empty()
        {
            return Err(format!(
                "{name}: REFUSED: {}",
                Refusal::ExtraOutputOrPool(format!(
                    "the transparent pool is in use: {} input(s), {} output(s)",
                    checked.transparent().inputs().len(),
                    checked.transparent().outputs().len()
                ))
            ));
        }
        if !checked.sapling().spends().is_empty() || !checked.sapling().outputs().is_empty() {
            return Err(format!(
                "{name}: REFUSED: {}",
                Refusal::ExtraOutputOrPool(format!(
                    "the Sapling pool is in use: {} spend(s), {} output(s)",
                    checked.sapling().spends().len(),
                    checked.sapling().outputs().len()
                ))
            ));
        }

        // Expiry and version, from the PCZT's own global fields.
        if *checked.global().expiry_height() != want_expiry {
            return Err(format!(
                "{name}: REFUSED: {}",
                Refusal::ExpiryDiffers {
                    expected: want.expiry_height,
                    found: *checked.global().expiry_height(),
                }
            ));
        }
        if *checked.global().tx_version() != 6 {
            return Err(format!(
                "{name}: REFUSED: {}",
                Refusal::WrongNetworkOrVersion(format!(
                    "tx version {}",
                    checked.global().tx_version()
                ))
            ));
        }

        // The signer computes its own sighash. Nothing supplied it.
        let sighash = Signer::new(checked.clone())
            .map_err(|e| format!("{name}: signer: {e:?}"))?
            .shielded_sighash();

        // Read each spend's alpha and rk out of the PCZT, indexed by the nullifier the
        // intent names, so a reordered action bundle cannot pair spend i's rk with
        // spend j's randomiser.
        let mut found: BTreeMap<[u8; 32], (pasta_curves::pallas::Scalar, [u8; 32])> =
            BTreeMap::new();
        LowLevelSigner::new(checked.clone())
            .sign_ironwood_with::<pczt::roles::low_level_signer::OrchardParseError, _>(
                |_pczt, bundle, _| {
                    for action in bundle.actions() {
                        let nf = action.spend().nullifier().to_bytes();
                        if let Some(alpha) = *action.spend().alpha() {
                            found.insert(nf, (alpha, <[u8; 32]>::from(action.spend().rk())));
                        }
                    }
                    Ok(())
                },
            )
            .map_err(|e| format!("{name}: low level signer: {e:?}"))?;

        // Rebuild the pair's commitments and recompute alpha independently.
        let ids: Vec<frost::Identifier> = [x, y]
            .iter()
            .map(|k| {
                let raw = MemberDir::open(&root, MEMBERS[*k].0)
                    .read_hex("identifier.hex")
                    .map_err(|e| format!("{e}"))?;
                frost::Identifier::deserialize(&raw).map_err(|e| format!("{e}"))
            })
            .collect::<Result<_, String>>()?;

        // One pass per spend. Each has its own commitment round, its own randomiser and
        // its own rk, so the check below is repeated rather than hoisted: a spend whose
        // rk matched some *other* spend's alpha would otherwise go unnoticed.
        let mut per_spend = Vec::new();
        for (i, want_nf) in want_nfs.iter().enumerate() {
            let mut commitments = BTreeMap::new();
            for (k, id) in [x, y].iter().zip(ids.iter()) {
                let raw = shared
                    .read_hex(&commitment_file(name, MEMBERS[*k].0, i))
                    .map_err(|e| format!("{e}"))?;
                commitments.insert(
                    *id,
                    frost::round1::SigningCommitments::deserialize(&raw)
                        .map_err(|e| format!("{e}"))?,
                );
            }

            let record = load_seed_record(&shared, name, i)?;
            let seed = record
                .validate(&proposal_id, name, i, want_nf, &commitments)
                .map_err(|e| format!("{name}: REFUSED: {e}"))?;
            let params =
                frost_rerandomized::RandomizedParams::regenerate_from_seed_and_commitments(
                    key_package.verifying_key(),
                    &seed,
                    &commitments,
                )
                .map_err(|e| format!("{name}: REFUSED: randomizer: {e}"))?;
            let recomputed_bytes: [u8; 32] = params
                .randomizer()
                .serialize()
                .as_slice()
                .try_into()
                .map_err(|_| "alpha is not 32 bytes")?;

            let (in_pczt_alpha, in_pczt_rk) = *found
                .get(want_nf)
                .ok_or(format!("{name}: spend {i} carries no alpha"))?;

            // rk must equal ak randomized by the alpha WE recomputed, not the one supplied.
            let scalar = loki_poc::candidate::alpha_from_canonical_bytes(&recomputed_bytes)
                .ok_or(format!("{name}: recomputed alpha is noncanonical"))?;
            if in_pczt_alpha != scalar {
                return Err(format!(
                    "{name}: REFUSED: {}",
                    Refusal::RkDoesNotMatchAlpha {
                        expected: hex::encode(recomputed_bytes),
                        found: format!("a different alpha on spend {i}"),
                    }
                ));
            }

            let expect_rk: orchard::primitives::redpallas::VerificationKey<
                orchard::primitives::redpallas::SpendAuth,
            > = orchard::keys::SpendValidatingKey::from(vault_fvk.clone()).randomize(&scalar);
            if <[u8; 32]>::from(&expect_rk) != in_pczt_rk {
                return Err(format!(
                    "{name}: REFUSED: {}",
                    Refusal::RkDoesNotMatchAlpha {
                        expected: hex::encode(<[u8; 32]>::from(&expect_rk)),
                        found: hex::encode(in_pczt_rk),
                    }
                ));
            }

            // Build the FROST package HERE, from the local sighash and the sorted
            // commitments. A package that named a different sighash could not be used.
            // Every spend signs the same sighash; only the commitments differ.
            let package = frost::SigningPackage::new(commitments, &sighash);
            if package.message() != &sighash[..] {
                return Err(format!(
                    "{name}: REFUSED: {}",
                    Refusal::PackageSighashMismatch
                ));
            }

            let nonces = frost::round1::SigningNonces::deserialize(
                &me.read_hex(&nonce_file(name, i))
                    .map_err(|e| format!("REFUSED: {name}: spend {i}: run commit first: {e}"))?,
            )
            .map_err(|e| format!("REFUSED: nonces: {e}"))?;
            per_spend.push((package, seed, nonces));
        }

        let spends = per_spend.len();
        reviewed.push((name, per_spend, sighash));
        println!(
            "{who:<6} {name}  reviewed: effects match, rk matches recomputed alpha on all \
             {spends} spend(s)"
        );
    }

    if reviewed.is_empty() {
        return Err(format!("{who} is not a member of any candidate"));
    }

    // Compute the entire batch before writing shares or consuming any nonce.
    let mut batch = Vec::new();
    for (name, per_spend, sighash) in reviewed {
        let mut shares = Vec::new();
        for (i, (package, seed, nonces)) in per_spend.into_iter().enumerate() {
            let share = frost_rerandomized::sign_with_randomizer_seed(
                &package,
                &nonces,
                &key_package,
                &seed,
            )
            .map_err(|e| format!("{name}: REFUSED: spend {i}: sign: {e}"))?;
            shares.push(share);
        }
        batch.push((name, shares, sighash));
    }
    for (name, shares, sighash) in batch {
        let spends = shares.len();
        for (i, share) in shares.into_iter().enumerate() {
            shared
                .write_hex(&share_file(name, who, i), &share.serialize())
                .map_err(|e| e.to_string())?;
            std::fs::remove_file(me.path().join(nonce_file(name, i)))
                .map_err(|e| format!("{name}: spend {i}: removing spent nonce: {e}"))?;
        }
        println!(
            "{who:<6} {name}  {spends} share(s) emitted, nonce(s) consumed  (sighash {})",
            &hex::encode(sighash)[..16]
        );
    }

    Ok(())
}

/// Collect every Ironwood commitment on the chain, in append order, plus the tip anchor.
/// The commitment stream, the node's anchor, and the tip height.
type ChainView = (Vec<[u8; 32]>, [u8; 32], u64);

fn chain_commitments(rpc: &loki_poc::rpc::Rpc) -> Result<ChainView, String> {
    let tip = rpc
        .json("getblockcount", "[]")?
        .as_u64()
        .ok_or("getblockcount")?;
    let mut cmxs = Vec::new();

    for height in 1..=tip {
        let block = rpc.json("getblock", &format!("[\"{height}\", 2]"))?;
        for tx in block["tx"].as_array().ok_or("no tx array")? {
            if let Some(actions) = tx["ironwood"]["actions"].as_array() {
                for a in actions {
                    cmxs.push(hex32(a, "cmx").ok_or("bad cmx")?);
                }
            }
        }
    }

    let state = rpc.json("z_gettreestate", &format!("[\"{tip}\"]"))?;
    let anchor: [u8; 32] = hex::decode(
        state["ironwood"]["commitments"]["finalRoot"]
            .as_str()
            .ok_or("no ironwood finalRoot")?,
    )
    .map_err(|e| format!("anchor: {e}"))?
    .try_into()
    .map_err(|_| "anchor is not 32 bytes")?;

    Ok((cmxs, anchor, tip))
}

/// Checkpoint 5: finish AC and mine it.
///
/// This process holds **no** signature share of its own and never reads Bob's directory.
/// It verifies Alice's and Carol's shares, aggregates them, applies the signature, and
/// only THEN installs the anchor and witness, proves, extracts and broadcasts.
fn finish(args: &[String]) -> Result<(), String> {
    use pczt::roles::{
        prover::Prover, signer::Signer, spend_finalizer::SpendFinalizer,
        tx_extractor::TransactionExtractor, updater::Updater,
    };

    let root = PathBuf::from(args.first().ok_or("usage: finish <state-dir>")?);
    let shared = MemberDir::open(&root, &shared_name());
    let vault_dir = MemberDir::open(&root, "public");

    let intent_kv = kv(&shared.read_text("intent.txt").map_err(|e| e.to_string())?);
    let want_nfs = intent_nullifiers(&intent_kv)?;
    let inputs = approver_inputs(&root, &shared)?;
    let (signed, sighash, spend_indices) = aggregate_and_apply(&inputs)?;
    let name = "AC";
    println!("AC  two shares per spend aggregated, verified, applied before anchor/witness/proof");

    // ── everything below happens AFTER signing ──────────────────────────────
    let rpc = loki_poc::rpc::Rpc::regtest();
    let (cmxs, anchor, tip) = chain_commitments(&rpc)?;

    // A witness per spend, each against the same anchor. The position comes from the
    // scan output, matched on nullifier, so spend i gets note i's merkle path.
    let scanned = vault_dir
        .read_text("funded_notes.txt")
        .map_err(|e| format!("{e}"))?;
    let mut witnesses = Vec::new();
    for (want_nf, index) in want_nfs.iter().zip(spend_indices.iter()) {
        let line = scanned
            .lines()
            .map(kv_record)
            .find(|m| m.get("nullifier").map(String::as_str) == Some(&hex::encode(want_nf)))
            .ok_or("the scan output has no note matching a spent nullifier")?;
        let position: u64 = line["position"].parse().map_err(|e| format!("{e}"))?;
        witnesses.push((
            *index,
            loki_poc::witness::witness_for(&cmxs, position, &anchor)?,
        ));
    }
    println!(
        "{name}  anchor {} at height {tip}",
        &hex::encode(anchor)[..16]
    );

    let updated = Updater::new(signed)
        .set_ironwood_anchor(
            orchard::Anchor::from_bytes(anchor)
                .into_option()
                .ok_or("the node's anchor is not a valid Anchor")?,
        )
        .map_err(|e| format!("set anchor: {e:?}"))?
        .set_ironwood_spend_witnesses(witnesses)
        .map_err(|e| format!("set witness: {e:?}"))?
        .finish();
    println!("{name}  anchor and witness installed after signing");

    // The sighash must be unchanged by installing them: that is the whole claim.
    let after = Signer::new(updated.clone())
        .map_err(|e| format!("signer: {e:?}"))?
        .shielded_sighash();
    if after != sighash {
        return Err(format!(
            "installing the anchor changed the effects sighash: {} -> {}",
            hex::encode(sighash),
            hex::encode(after)
        ));
    }
    println!("{name}  effects sighash unchanged by anchor/witness installation");

    // Prove. Orchard uses Halo 2, so the proving key is built locally.
    println!("{name}  building the proving key...");
    let pk =
        orchard::circuit::ProvingKey::build(orchard::circuit::OrchardCircuitVersion::PostNu6_3);
    let proved = Prover::new(updated)
        .create_ironwood_proof(rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng), &pk)
        .map_err(|e| format!("prove: {e:?}"))?
        .finish();
    println!("{name}  proof created");

    let finalized = SpendFinalizer::new(proved)
        .finalize_spends()
        .map_err(|e| format!("finalize: {e:?}"))?;

    let vk =
        orchard::circuit::VerifyingKey::build(orchard::circuit::OrchardCircuitVersion::PostNu6_3);
    let tx = TransactionExtractor::new(finalized)
        .with_orchard(&vk)
        .extract(rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng))
        .map_err(|e| format!("extract: {e:?}"))?;

    let mut raw = Vec::new();
    tx.write(&mut raw)
        .map_err(|e| format!("serialize tx: {e}"))?;
    let txid = tx.txid().to_string();
    println!(
        "{name}  extracted v6 transaction {txid} ({} bytes)",
        raw.len()
    );

    let sent = rpc.json(
        "sendrawtransaction",
        &format!("[\"{}\"]", hex::encode(&raw)),
    )?;
    println!("{name}  broadcast: {sent}");

    shared
        .write_text(
            "mined.txt",
            &format!(
                "txid={txid}\nbroadcast_at_height={tip}\nanchor={}\n",
                hex::encode(anchor)
            ),
        )
        .map_err(|e| e.to_string())?;

    Ok(())
}

/// TEST-ONLY: rebuild candidate AC differing from the intent in exactly one field.
///
/// This attacks the candidate, not the intent: it simulates a hostile proposer handing
/// signers a PCZT that is structurally valid and correctly built, but not the payment
/// they agreed to. The honest `intent.txt` is left untouched.
fn tamper(args: &[String]) -> Result<(), String> {
    use loki_poc::candidate::*;
    use orchard::{
        keys::Scope,
        note::{RandomSeed, Rho},
        value::NoteValue,
        Note, NoteVersion,
    };
    use zcash_protocol::{memo::MemoBytes, value::Zatoshis};

    let root = PathBuf::from(args.first().ok_or("usage: tamper <state-dir> <case>")?);
    let case = args
        .get(1)
        .ok_or("usage: tamper <state-dir> <case>")?
        .as_str();
    let shared = MemberDir::open(&root, &shared_name());

    if case == "rebuild-session" {
        // Deliberately adversarial rollback experiment; ordinary propose cannot do this.
        for entry in std::fs::read_dir(shared.path()).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let file = entry.file_name().to_string_lossy().into_owned();
            if file == "intent.txt"
                || file.starts_with("candidate_")
                || file.starts_with("randomizer_seed_")
                || file.starts_with("alpha_")
                || file.starts_with("share_")
            {
                std::fs::remove_file(entry.path()).map_err(|e| e.to_string())?;
            }
        }
        return propose(&[root.to_string_lossy().into_owned()]);
    }

    // This case does not touch the candidate at all, so it branches before the rebuild.
    if case == "cosigner-recommit" {
        return tamper_cosigner_recommit(&root, &shared);
    }

    let ak: [u8; 32] = shared
        .read_hex("group_ak.hex")
        .map_err(|e| format!("{e}"))?
        .try_into()
        .map_err(|_| "group_ak")?;
    let fvk = vault::test_only_fvk(&ak).map_err(|e| format!("{e:?}"))?;

    let note_kv = kv(&shared
        .read_text("funded_note.txt")
        .map_err(|e| format!("{e}"))?);
    let intent_kv = kv(&shared.read_text("intent.txt").map_err(|e| format!("{e}"))?);

    let rho = Rho::from_bytes(&hexn::<32>(&note_kv, "rho")?)
        .into_option()
        .ok_or("rho")?;
    let rseed = RandomSeed::from_bytes(hexn::<32>(&note_kv, "rseed")?, &rho)
        .into_option()
        .ok_or("rseed")?;
    let value: u64 = note_kv["value_zat"].parse().map_err(|e| format!("{e}"))?;
    let honest_note = Note::from_parts(
        orchard::Address::from_raw_address_bytes(&hexn::<43>(&note_kv, "recipient")?)
            .into_option()
            .ok_or("recipient")?,
        NoteValue::from_raw(value),
        rho,
        rseed,
        NoteVersion::V3,
    )
    .into_option()
    .ok_or("note")?;

    let honest_recipient =
        orchard::Address::from_raw_address_bytes(&hexn::<43>(&intent_kv, "recipient")?)
            .into_option()
            .ok_or("intent recipient")?;
    let amount: u64 = intent_kv["amount_zat"]
        .parse()
        .map_err(|e| format!("{e}"))?;
    let change: u64 = intent_kv["change_zat"]
        .parse()
        .map_err(|e| format!("{e}"))?;
    let expiry: u32 = intent_kv["expiry_height"]
        .parse()
        .map_err(|e| format!("{e}"))?;
    let target: u32 = intent_kv["target_height"]
        .parse()
        .map_err(|e| format!("{e}"))?;
    let proposal_id = checked_proposal_id(&intent_kv)?;

    // One field differs, everything else is the honest value.
    let mut note = honest_note;
    let mut recipient = honest_recipient;
    let mut memo_bytes = hex::decode(&intent_kv["memo"]).map_err(|e| format!("{e}"))?;
    let mut amount_z = Zatoshis::const_from_u64(amount);
    let mut change_z = Zatoshis::const_from_u64(change);
    let mut expiry_h = expiry;
    let mut change_to_vault = true;
    let mut splice_transparent = false;
    let mut splice_sapling = false;

    match case {
        "memo" => memo_bytes = b"loki g1-TX".to_vec(),
        "recipient" => recipient = fvk.address_at(9u64, Scope::External),
        "amount" => {
            // Pay one zatoshi more, taken from change so the bundle still balances.
            amount_z = Zatoshis::const_from_u64(amount + 1);
            change_z = Zatoshis::const_from_u64(change - 1);
        }
        "change-amount" => {
            // Shift a zatoshi the other way.
            amount_z = Zatoshis::const_from_u64(amount - 1);
            change_z = Zatoshis::const_from_u64(change + 1);
        }
        "change-address" => change_to_vault = false,
        "input" => {
            // A second note the vault genuinely owns and could genuinely spend, but not
            // the one the intent names. Fabricating a note here would fail at the
            // builder for the wrong reason.
            let alt = kv(&shared
                .read_text("funded_note_alt.txt")
                .map_err(|e| format!("no alternate note recorded by scan: {e}"))?);
            let alt_rho = Rho::from_bytes(&hexn::<32>(&alt, "rho")?)
                .into_option()
                .ok_or("alt rho")?;
            let alt_rseed = RandomSeed::from_bytes(hexn::<32>(&alt, "rseed")?, &alt_rho)
                .into_option()
                .ok_or("alt rseed")?;
            let alt_value: u64 = alt["value_zat"].parse().map_err(|e| format!("{e}"))?;
            if alt_value != value {
                return Err(format!(
                    "the alternate note is {alt_value} zat, not {value}; the tampered \
                     candidate would not balance for an unrelated reason"
                ));
            }
            note = Note::from_parts(
                orchard::Address::from_raw_address_bytes(&hexn::<43>(&alt, "recipient")?)
                    .into_option()
                    .ok_or("alt recipient")?,
                NoteValue::from_raw(alt_value),
                alt_rho,
                alt_rseed,
                NoteVersion::V3,
            )
            .into_option()
            .ok_or("alt note")?;
        }
        "expiry" => expiry_h = expiry + 1_152,
        // The fee is in - out, so pinning the inputs and both outputs pins it. The only
        // way to make the implied fee wrong is to make one of those wrong, which is why
        // this case is really "the fee is off because the change is". See RESULTS.md.
        "fee" => change_z = Zatoshis::const_from_u64(change - 1_000),
        "transparent" => splice_transparent = true,
        "sapling" => splice_sapling = true,
        other => return Err(format!("unknown tamper case {other}")),
    }

    let inputs = CandidateInputs {
        vault_fvk: &fvk,
        notes: vec![note],
        recipient,
        amount: amount_z,
        memo: MemoBytes::from_bytes(&memo_bytes).map_err(|e| format!("memo: {e:?}"))?,
        change: change_z,
        target_height: target,
        expiry_height: expiry_h,
    };

    // AC's alpha, derived honestly: the tamper is in the effects, not the randomizer.
    let ids: Vec<frost::Identifier> = [0usize, 2]
        .iter()
        .map(|k| {
            let raw = MemberDir::open(&root, MEMBERS[*k].0)
                .read_hex("identifier.hex")
                .map_err(|e| format!("{e}"))?;
            frost::Identifier::deserialize(&raw).map_err(|e| format!("{e}"))
        })
        .collect::<Result<_, String>>()?;
    let mut commitments = BTreeMap::new();
    for (k, id) in [0usize, 2].iter().zip(ids.iter()) {
        let raw = shared
            .read_hex(&format!("commitment_AC_{}.hex", MEMBERS[*k].0))
            .map_err(|e| format!("{e}"))?;
        commitments.insert(
            *id,
            frost::round1::SigningCommitments::deserialize(&raw).map_err(|e| format!("{e}"))?,
        );
    }
    let record = load_seed_record(&shared, "AC", 0)?;
    let seed = record.validate(
        &proposal_id,
        "AC",
        0,
        &intent_nullifiers(&intent_kv)?[0],
        &commitments,
    )?;
    let group_key = frost::VerifyingKey::deserialize(&ak).map_err(|e| e.to_string())?;
    let params = frost_rerandomized::RandomizedParams::regenerate_from_seed_and_commitments(
        &group_key,
        &seed,
        &commitments,
    )
    .map_err(|e| e.to_string())?;
    let alpha_bytes: [u8; 32] = params
        .randomizer()
        .serialize()
        .try_into()
        .map_err(|_| "alpha")?;
    let alpha = alpha_from_canonical_bytes(&alpha_bytes).ok_or("alpha noncanonical")?;

    let built = build_tampered(
        &Regtest,
        &inputs,
        alpha,
        change_to_vault,
        rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng),
    )?;

    // Graft on a forbidden pool component, if that is the case under test. `PcztParts`
    // exposes these fields publicly, which is the only route: the deferred builder has
    // no transparent or Sapling methods.
    let mut parts = built.pczt_parts;
    if splice_transparent {
        parts.transparent = Some(forbidden_transparent_bundle()?);
    }
    if splice_sapling {
        parts.sapling = Some(forbidden_sapling_bundle()?);
    }

    let pczt = pczt::roles::creator::Creator::build_from_parts(parts).ok_or("build_from_parts")?;
    let pczt = pczt::roles::io_finalizer::IoFinalizer::new(pczt)
        .finalize_io(rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng))
        .map_err(|e| format!("io finalizer: {e:?}"))?;
    let bytes = pczt.serialize().map_err(|e| format!("serialize: {e:?}"))?;

    shared
        .write_hex("candidate_AC.pczt.hex", &bytes)
        .map_err(|e| e.to_string())?;

    println!("candidate_AC.pczt.hex replaced with a candidate tampered in: {case}");
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Second-device finishing.
//
// The question these stages answer: once the approvers have approved and closed, can a
// device that holds NONE of their local files finish the payment? Two ways in, and both
// are tested:
//
//   path A   a final transaction was already produced and posted. The finisher only has
//            to check it and broadcast it.
//   path B   no final transaction exists. The finisher has to aggregate the shares, find
//            the note and anchor by its OWN chain scan, install them after the signature,
//            prove, extract and broadcast.
//
// The finisher receives a confidential local handoff, including saved randomizer seeds.
// Approver key packages, nonce secrets, scan output and witnesses are withheld.
// `replicate` is explicit about both halves, and writes a manifest naming what it withheld.
//
// None of this is G4. It is one regtest flow on the documented test-only FVK, and it
// claims nothing about recovery, custody, or a real second device.
// ─────────────────────────────────────────────────────────────────────────────

/// Everything needed to aggregate AC and apply the signature, as bytes.
///
/// A struct rather than a directory so the same code serves both an approver's state
/// layout and a flat replica. The finisher cannot accidentally reach for a file that is
/// not in here.
struct AggregateInputs {
    pair: String,
    group_ak: [u8; 32],
    seeds: Vec<loki_poc::randomizer::SeedRecord>,
    candidate: Vec<u8>,
    public_package: Vec<u8>,
    ids: [Vec<u8>; 2],
    commitments: Vec<[Vec<u8>; 2]>,
    shares: Vec<[Vec<u8>; 2]>,
    proposal_id: [u8; 32],
    want_nfs: Vec<[u8; 32]>,
}

/// Compute the v6 shielded sighash of finalized bytes for comparison with the PCZT.
/// The transaction crate requires a transparent signing context even when the bundle is
/// absent, so map only that empty slot to its effects-only authorization type.
fn finalized_sighash(tx: &zcash_primitives::transaction::Transaction) -> Result<[u8; 32], String> {
    use zcash_primitives::transaction::{Authorization, TransactionData};
    struct ShieldedOnly;
    impl Authorization for ShieldedOnly {
        type TransparentAuth = zcash_transparent::bundle::EffectsOnly;
        type SaplingAuth = sapling_crypto::bundle::Authorized;
        type OrchardAuth = orchard::bundle::Authorized;
    }
    if tx.transparent_bundle().is_some()
        || tx.sapling_bundle().is_some()
        || tx.orchard_bundle().is_some()
    {
        return Err("the finalized transaction has an unexpected pool".into());
    }
    let data: TransactionData<ShieldedOnly> = tx.clone().into_data().try_map_bundles(
        |_| Ok::<_, String>(None),
        |_| Ok::<_, String>(None),
        Ok::<_, String>,
    )?;
    let digest = zcash_primitives::transaction::sighash::signature_hash(
        &data,
        &zcash_primitives::transaction::sighash::SignableInput::Shielded,
        &data.digest(zcash_primitives::transaction::txid::TxIdDigester),
    );
    Ok(*digest.as_ref())
}

/// Verify the two shares, aggregate, check the group signature under `ak + [alpha]G`, and
/// apply it for every spend. Returns the signed PCZT, its effects sighash, and action indices.
fn aggregate_and_apply(i: &AggregateInputs) -> Result<(pczt::Pczt, [u8; 32], Vec<usize>), String> {
    use pczt::roles::signer::Signer;

    let public_package = frost::keys::PublicKeyPackage::deserialize(&i.public_package)
        .map_err(|e| format!("public package: {e}"))?;
    if public_package
        .verifying_key()
        .serialize()
        .map_err(|e| e.to_string())?
        != i.group_ak
    {
        return Err("REFUSED: public package differs from known vault key".into());
    }
    let pczt = pczt::Pczt::parse(&i.candidate).map_err(|e| format!("parse: {e:?}"))?;

    // The finisher computes the sighash from the candidate bytes itself, exactly as the
    // signers did. It is never told what to sign.
    let sighash = Signer::new(pczt.clone())
        .map_err(|e| format!("signer: {e:?}"))?
        .shielded_sighash();

    let ids: Vec<frost::Identifier> = i
        .ids
        .iter()
        .map(|raw| frost::Identifier::deserialize(raw).map_err(|e| format!("{e}")))
        .collect::<Result<_, String>>()?;

    let mut signer = Signer::new(pczt.clone()).map_err(|e| format!("signer: {e:?}"))?;
    if i.want_nfs.is_empty()
        || i.commitments.len() != i.want_nfs.len()
        || i.shares.len() != i.want_nfs.len()
        || i.seeds.len() != i.want_nfs.len()
    {
        return Err("the replica has an incomplete spend batch".into());
    }
    let mut indices = Vec::with_capacity(i.want_nfs.len());
    for (spend, want_nf) in i.want_nfs.iter().enumerate() {
        let mut commitments = BTreeMap::new();
        for (id, raw) in ids.iter().zip(i.commitments[spend].iter()) {
            commitments.insert(
                *id,
                frost::round1::SigningCommitments::deserialize(raw)
                    .map_err(|e| format!("spend {spend}: {e}"))?,
            );
        }
        let seed = i.seeds[spend]
            .validate(&i.proposal_id, &i.pair, spend, want_nf, &commitments)
            .map_err(|e| format!("REFUSED: {e}"))?;
        let params = frost_rerandomized::RandomizedParams::regenerate_from_seed_and_commitments(
            public_package.verifying_key(),
            &seed,
            &commitments,
        )
        .map_err(|e| format!("REFUSED: randomizer: {e}"))?;
        check_randomized_spend(&pczt, want_nf, &params, &i.group_ak)?;
        let package = frost::SigningPackage::new(commitments, &sighash);
        let mut shares = BTreeMap::new();
        for (id, raw) in ids.iter().zip(i.shares[spend].iter()) {
            shares.insert(
                *id,
                frost::round2::SignatureShare::deserialize(raw)
                    .map_err(|e| format!("spend {spend}: {e}"))?,
            );
        }
        let group_sig = frost_rerandomized::aggregate(&package, &shares, &public_package, &params)
            .map_err(|e| format!("spend {spend}: aggregate: {e}"))?;
        params
            .randomized_verifying_key()
            .verify(&sighash, &group_sig)
            .map_err(|e| format!("spend {spend}: the aggregated signature does not verify: {e}"))?;
        let sig_bytes: [u8; 64] = group_sig
            .serialize()
            .map_err(|e| format!("{e}"))?
            .as_slice()
            .try_into()
            .map_err(|_| "signature is not 64 bytes")?;
        let orchard_sig = orchard::primitives::redpallas::Signature::<
            orchard::primitives::redpallas::SpendAuth,
        >::from(sig_bytes);
        let index = pczt
            .ironwood()
            .actions()
            .iter()
            .position(|a| a.spend().nullifier() == want_nf)
            .ok_or(format!(
                "the candidate does not spend note {spend} named by the intent"
            ))?;
        if indices.contains(&index) {
            return Err("the intent names the same input twice".into());
        }
        signer
            .apply_ironwood_signature(index, orchard_sig)
            .map_err(|e| format!("spend {spend}: apply signature: {e:?}"))?;
        indices.push(index);
    }
    Ok((signer.finish(), sighash, indices))
}

/// Install the anchor and witness AFTER signing, prove, extract.
///
/// `positions` and `anchor` come from whoever called this; in path B they come from the
/// finisher's own scan. The sighash is re-checked after installation and must be
/// byte-identical, which is the claim the whole v6 path rests on.
fn prove_and_extract(
    signed: pczt::Pczt,
    sighash: &[u8],
    positions: &[(usize, u64)],
    cmxs: &[[u8; 32]],
    anchor: [u8; 32],
    label: &str,
) -> Result<(Vec<u8>, String), String> {
    use pczt::roles::{
        prover::Prover, signer::Signer, spend_finalizer::SpendFinalizer,
        tx_extractor::TransactionExtractor, updater::Updater,
    };

    let witnesses = positions
        .iter()
        .map(|(index, position)| {
            Ok((
                *index,
                loki_poc::witness::witness_for(cmxs, *position, &anchor)?,
            ))
        })
        .collect::<Result<Vec<_>, String>>()?;

    let updated = Updater::new(signed)
        .set_ironwood_anchor(
            orchard::Anchor::from_bytes(anchor)
                .into_option()
                .ok_or("the node's anchor is not a valid Anchor")?,
        )
        .map_err(|e| format!("set anchor: {e:?}"))?
        .set_ironwood_spend_witnesses(witnesses)
        .map_err(|e| format!("set witness: {e:?}"))?
        .finish();
    println!("{label}  anchor and witness installed after signing");

    let after = Signer::new(updated.clone())
        .map_err(|e| format!("signer: {e:?}"))?
        .shielded_sighash();
    if after != sighash {
        return Err(format!(
            "installing the anchor changed the effects sighash: {} -> {}",
            hex::encode(sighash),
            hex::encode(after)
        ));
    }
    println!("{label}  effects sighash unchanged by anchor/witness installation");

    println!("{label}  building the proving key...");
    let pk =
        orchard::circuit::ProvingKey::build(orchard::circuit::OrchardCircuitVersion::PostNu6_3);
    let proved = Prover::new(updated)
        .create_ironwood_proof(rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng), &pk)
        .map_err(|e| format!("prove: {e:?}"))?
        .finish();
    println!("{label}  proof created");

    let finalized = SpendFinalizer::new(proved)
        .finalize_spends()
        .map_err(|e| format!("finalize: {e:?}"))?;
    let vk =
        orchard::circuit::VerifyingKey::build(orchard::circuit::OrchardCircuitVersion::PostNu6_3);
    let tx = TransactionExtractor::new(finalized)
        .with_orchard(&vk)
        .extract(rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng))
        .map_err(|e| format!("extract: {e:?}"))?;

    let mut raw = Vec::new();
    tx.write(&mut raw)
        .map_err(|e| format!("serialize tx: {e}"))?;
    let txid = tx.txid().to_string();
    println!(
        "{label}  extracted v6 transaction {txid} ({} bytes)",
        raw.len()
    );
    Ok((raw, txid))
}

/// Read the AC aggregate inputs out of a flat replica directory.
fn replica_inputs(r: &MemberDir) -> Result<AggregateInputs, String> {
    let intent_kv = kv(&r.read_text("intent.txt").map_err(|e| format!("{e}"))?);
    let rd = |f: &str| r.read_hex(f).map_err(|e| format!("{f}: {e}"));
    let want_nfs = intent_nullifiers(&intent_kv)?;
    check_seed_record_count(r, "AC", want_nfs.len())?;
    let mut commitments = Vec::new();
    let mut shares = Vec::new();
    for spend in 0..want_nfs.len() {
        commitments.push([
            rd(&commitment_file("AC", "alice", spend))?,
            rd(&commitment_file("AC", "carol", spend))?,
        ]);
        shares.push([
            rd(&share_file("AC", "alice", spend))?,
            rd(&share_file("AC", "carol", spend))?,
        ]);
    }
    Ok(AggregateInputs {
        pair: "AC".into(),
        group_ak: rd("group_ak.hex")?
            .try_into()
            .map_err(|_| "group_ak length")?,
        seeds: (0..want_nfs.len())
            .map(|spend| load_seed_record(r, "AC", spend))
            .collect::<Result<_, _>>()?,
        candidate: rd("candidate_AC.pczt.hex")?,
        public_package: rd("public_package.hex")?,
        ids: [rd("identifier_alice.hex")?, rd("identifier_carol.hex")?],
        commitments,
        shares,
        proposal_id: checked_proposal_id(&intent_kv)?,
        want_nfs,
    })
}

/// Approver-side: produce the final transaction and POST it, without broadcasting.
///
/// This is how path A's input comes to exist: Alice proved the transaction but never got
/// it to a node. Everything after this point is the second device's job.
fn approver_inputs(root: &std::path::Path, shared: &MemberDir) -> Result<AggregateInputs, String> {
    let intent_kv = kv(&shared.read_text("intent.txt").map_err(|e| format!("{e}"))?);
    let want_nfs = intent_nullifiers(&intent_kv)?;
    check_seed_record_count(shared, "AC", want_nfs.len())?;
    let rd = |f: &str| shared.read_hex(f).map_err(|e| format!("{f}: {e}"));
    Ok(AggregateInputs {
        pair: "AC".into(),
        group_ak: MemberDir::open(root, "public")
            .read_hex("group_ak.hex")
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "group_ak length")?,
        seeds: (0..want_nfs.len())
            .map(|spend| load_seed_record(shared, "AC", spend))
            .collect::<Result<_, _>>()?,
        candidate: rd("candidate_AC.pczt.hex")?,
        public_package: MemberDir::open(root, "alice")
            .read_hex("public_package.hex")
            .map_err(|e| format!("{e}"))?,
        ids: [
            MemberDir::open(root, "alice")
                .read_hex("identifier.hex")
                .map_err(|e| format!("{e}"))?,
            MemberDir::open(root, "carol")
                .read_hex("identifier.hex")
                .map_err(|e| format!("{e}"))?,
        ],
        commitments: (0..want_nfs.len())
            .map(|spend| {
                Ok([
                    rd(&commitment_file("AC", "alice", spend))?,
                    rd(&commitment_file("AC", "carol", spend))?,
                ])
            })
            .collect::<Result<_, String>>()?,
        shares: (0..want_nfs.len())
            .map(|spend| {
                Ok([
                    rd(&share_file("AC", "alice", spend))?,
                    rd(&share_file("AC", "carol", spend))?,
                ])
            })
            .collect::<Result<_, String>>()?,
        proposal_id: checked_proposal_id(&intent_kv)?,
        want_nfs,
    })
}

fn post_final(args: &[String]) -> Result<(), String> {
    let root = PathBuf::from(args.first().ok_or("usage: post-final <state-dir>")?);
    let shared = MemberDir::open(&root, &shared_name());

    let inputs = approver_inputs(&root, &shared)?;

    let (signed, sighash, indices) = aggregate_and_apply(&inputs)?;
    println!("AC  aggregated two shares per spend; verifies under ak+alpha");

    let rpc = loki_poc::rpc::Rpc::regtest();
    let ak: [u8; 32] = shared
        .read_hex("group_ak.hex")
        .map_err(|e| format!("{e}"))?
        .try_into()
        .map_err(|_| "group_ak")?;
    let fvk = vault::test_only_fvk(&ak).map_err(|e| format!("{e:?}"))?;
    let chain = loki_poc::scan::scan_chain(&rpc, &fvk)?;
    let anchor = loki_poc::scan::chain_anchor(&rpc, chain.tip)?;
    let positions = inputs
        .want_nfs
        .iter()
        .zip(indices)
        .map(|(nf, index)| {
            let note = chain
                .notes
                .iter()
                .find(|n| &n.nullifier == nf)
                .ok_or("an intent input note is not on this chain")?;
            Ok((index, note.position))
        })
        .collect::<Result<Vec<_>, String>>()?;

    let (raw, txid) = prove_and_extract(signed, &sighash, &positions, &chain.cmxs, anchor, "AC")?;

    shared
        .write_hex("final_tx.hex", &raw)
        .map_err(|e| e.to_string())?;
    shared
        .write_text(
            "final_tx.txt",
            &format!(
                "txid={txid}\nbytes={}\nanchor={}\nbuilt_at_height={}\nbroadcast=no\n",
                raw.len(),
                hex::encode(anchor),
                chain.tip
            ),
        )
        .map_err(|e| e.to_string())?;
    println!("AC  final transaction POSTED, not broadcast: {txid}");
    Ok(())
}

/// Build the replica a second device is given, and nothing else.
///
/// The withheld list is as much the point as the copied list: if a finisher can work from
/// what is here, it did not need an approver's device.
fn replicate(args: &[String]) -> Result<(), String> {
    let root = PathBuf::from(
        args.first()
            .ok_or("usage: replicate <state-dir> <replica-dir> [--with-final]")?,
    );
    let out = PathBuf::from(
        args.get(1)
            .ok_or("usage: replicate <state-dir> <replica-dir> [--with-final]")?,
    );
    let with_final = args.iter().any(|a| a == "--with-final");
    if out.exists()
        && std::fs::read_dir(&out)
            .map_err(|e| e.to_string())?
            .next()
            .is_some()
    {
        return Err("REFUSED: replica destination is not empty".into());
    }
    let shared = MemberDir::open(&root, &shared_name());
    let intent_kv = kv(&shared.read_text("intent.txt").map_err(|e| format!("{e}"))?);
    let spend_count = intent_nullifiers(&intent_kv)?.len();
    check_seed_record_count(&shared, "AC", spend_count)?;

    let replica = MemberDir::create(
        out.parent().unwrap_or(&out),
        out.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("replica"),
    )
    .map_err(|e| e.to_string())?;

    // Public group data and the proposal. All of this is designed to be replicated.
    for f in ["intent.txt", "candidate_AC.pczt.hex", "group_ak.hex"] {
        let bytes = std::fs::read(shared.path().join(f))
            .map_err(|e| format!("{f}: {e} (run propose and review-sign first)"))?;
        std::fs::write(replica.path().join(f), bytes).map_err(|e| format!("{f}: {e}"))?;
    }
    for spend in 0..spend_count {
        let record = load_seed_record(&shared, "AC", spend)?;
        write_seed_record(&replica, "AC", spend, &record)?;
        for member in ["alice", "carol"] {
            for file in [
                commitment_file("AC", member, spend),
                share_file("AC", member, spend),
            ] {
                let bytes = std::fs::read(shared.path().join(&file))
                    .map_err(|e| format!("{file}: {e} (run review-sign first)"))?;
                std::fs::write(replica.path().join(&file), bytes)
                    .map_err(|e| format!("{file}: {e}"))?;
            }
        }
    }

    // The group's public key package and the two approvers' public identifiers. These are
    // public by construction: the package holds verifying shares, never a key package.
    std::fs::write(
        replica.path().join("public_package.hex"),
        std::fs::read(
            MemberDir::open(&root, "alice")
                .path()
                .join("public_package.hex"),
        )
        .map_err(|e| format!("public_package: {e}"))?,
    )
    .map_err(|e| format!("{e}"))?;
    for m in ["alice", "carol"] {
        std::fs::write(
            replica.path().join(format!("identifier_{m}.hex")),
            std::fs::read(MemberDir::open(&root, m).path().join("identifier.hex"))
                .map_err(|e| format!("identifier {m}: {e}"))?,
        )
        .map_err(|e| format!("{e}"))?;
    }

    let mut manifest = String::from(
        "# Replica handed to the second device.\n\
         #\n\
         # confidential local handoff: seeds require confidential transport; no encrypted relay is implemented.\n\
         # copied:\n\
         intent.txt\ncandidate_AC.pczt.hex\ngroup_ak.hex\npublic_package.hex\n\
         identifier_alice.hex\nidentifier_carol.hex\n",
    );
    for spend in 0..spend_count {
        manifest.push_str(&format!("{}\n", seed_file("AC", spend)));
        for member in ["alice", "carol"] {
            manifest.push_str(&format!(
                "{}\n{}\n",
                commitment_file("AC", member, spend),
                share_file("AC", member, spend)
            ));
        }
    }

    if with_final {
        std::fs::write(
            replica.path().join("final_tx.hex"),
            std::fs::read(shared.path().join("final_tx.hex"))
                .map_err(|e| format!("final_tx.hex: {e} (run post-final first)"))?,
        )
        .map_err(|e| format!("{e}"))?;
        manifest.push_str("final_tx.hex\n");
    }

    manifest.push_str(
        "#\n\
         # WITHHELD. None of this is in the replica, and the finisher never reads it:\n\
         #   alice/key_package.hex      alice's secret share\n\
         #   carol/key_package.hex      carol's secret share\n\
         #   bob/key_package.hex        the finisher's own share is not used either\n\
         #   */nonces_*.hex             every member's nonce secrets\n\
         #   funded_note.txt            an approver's scan output: note, rho, rseed, position\n\
         #   funded_note_alt.txt        the same for the second note\n\
         #   funded_notes.txt           the proposer's multi-note scan output\n\
         #   cmxs.hex                   an approver's commitment stream\n\
         #   anchor.txt                 an approver's anchor\n\
         # The finisher derives the note, its position, the commitment stream and the\n\
         # anchor from its OWN chain scan. That is what makes it a second device rather\n\
         # than a copy of Alice's.\n",
    );
    if !with_final {
        manifest.push_str("#   final_tx.hex               deliberately absent: this is path B\n");
    }
    replica
        .write_text("MANIFEST.txt", &manifest)
        .map_err(|e| e.to_string())?;

    println!("replica written to {}", out.display());
    println!(
        "  final transaction included: {}",
        if with_final {
            "yes (path A)"
        } else {
            "no (path B)"
        }
    );
    println!("  withheld: every key package, every nonce, every approver scan artifact");
    Ok(())
}

/// The second device. Holds no approver file; scans the chain itself.
fn finish_second(args: &[String]) -> Result<(), String> {
    let rdir = PathBuf::from(
        args.first()
            .ok_or("usage: finish-second <replica-dir> <work-dir>")?,
    );
    let work = PathBuf::from(
        args.get(1)
            .ok_or("usage: finish-second <replica-dir> <work-dir>")?,
    );
    std::fs::create_dir_all(&work).map_err(|e| format!("{e}"))?;

    let replica = MemberDir::open(
        rdir.parent().unwrap_or(&rdir),
        rdir.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("replica"),
    );
    let mine = MemberDir::create(&work, "self").map_err(|e| format!("{e}"))?;

    // Refuse to run against a directory that still contains approver state. A second
    // device test that silently read alice/ would prove nothing.
    for forbidden in ["alice", "bob", "carol"] {
        if work.join(forbidden).exists() || rdir.join(forbidden).exists() {
            return Err(format!(
                "{forbidden}/ exists under the replica or work directory; this stage must \
                 run with no approver state in reach"
            ));
        }
    }
    for forbidden in [
        "funded_note.txt",
        "funded_notes.txt",
        "cmxs.hex",
        "anchor.txt",
    ] {
        if replica.exists(forbidden) {
            return Err(format!(
                "the replica contains {forbidden}, which is an approver's scan output; \
                 the second device must derive it from the chain"
            ));
        }
    }

    let intent_kv = kv(&replica
        .read_text("intent.txt")
        .map_err(|e| format!("{e}"))?);
    let want_nfs = intent_nullifiers(&intent_kv)?;

    // THE TEST-ONLY KEY CONSTRUCTION, stated at the point of use. The vault FVK is a
    // documented splice of the DKG group key into `ak || nk || rivk`, NOT the ZIP 2005
    // `qsk -> qk -> rivk_ext` derivation, which is implemented nowhere. See
    // DEPENDENCIES.md finding B1. Full G1 is BLOCKED on that and nothing here changes it.
    let ak: [u8; 32] = replica
        .read_hex("group_ak.hex")
        .map_err(|e| format!("{e}"))?
        .try_into()
        .map_err(|_| "group_ak")?;
    let fvk = vault::test_only_fvk(&ak).map_err(|e| format!("{e:?}"))?;
    println!("second device: vault FVK rebuilt from the replicated group ak");
    println!("               TEST-ONLY construction (ak || nk || rivk), not ZIP 2005");

    let inputs = replica_inputs(&replica)?;
    let (signed_candidate, candidate_sighash, candidate_indices) = aggregate_and_apply(&inputs)?;

    // Check posted bytes before the chain scan. A substituted transaction must be
    // refused for its effects even if the original input has since been mined away.
    let posted = if replica.exists("final_tx.hex") {
        let raw = replica
            .read_hex("final_tx.hex")
            .map_err(|e| format!("{e}"))?;
        let tx = zcash_primitives::transaction::Transaction::read(
            &raw[..],
            zcash_protocol::consensus::BranchId::Nu6_3,
        )
        .map_err(|e| format!("the posted final transaction does not parse: {e}"))?;
        let candidate = pczt::Pczt::parse(
            &replica
                .read_hex("candidate_AC.pczt.hex")
                .map_err(|e| format!("candidate: {e}"))?,
        )
        .map_err(|e| format!("parse candidate: {e:?}"))?;
        let approved_sighash = pczt::roles::signer::Signer::new(candidate.clone())
            .map_err(|e| format!("candidate sighash: {e:?}"))?
            .shielded_sighash();
        if finalized_sighash(&tx)? != approved_sighash {
            return Err("the posted transaction's effects differ from the signed candidate".into());
        }
        let bundle = tx
            .ironwood_bundle()
            .ok_or("the posted transaction has no Ironwood bundle")?;
        let expected = candidate
            .ironwood()
            .actions()
            .iter()
            .map(|a| *a.spend().nullifier())
            .collect::<Vec<_>>();
        let actual = bundle
            .actions()
            .iter()
            .map(|a| a.nullifier().to_bytes())
            .collect::<Vec<_>>();
        if actual != expected || want_nfs.iter().any(|nf| !actual.contains(nf)) {
            return Err("the posted transaction's inputs differ from the signed candidate".into());
        }
        let txid = tx.txid().to_string();
        println!("path A         posted final transaction parsed: {txid}");
        println!("path A         every input and effect matches the signed candidate");
        Some((raw, txid))
    } else {
        None
    };

    // ── its own chain scan ──────────────────────────────────────────────────
    let rpc = loki_poc::rpc::Rpc::regtest();
    let chain = loki_poc::scan::scan_chain(&rpc, &fvk)?;
    let anchor = loki_poc::scan::chain_anchor(&rpc, chain.tip)?;
    let positions = want_nfs
        .iter()
        .map(|nf| {
            chain
                .notes
                .iter()
                .find(|n| &n.nullifier == nf)
                .map(|n| (n.position, n.value_zat))
                .ok_or("an intent input note was not found by this device's own scan")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let input_total: u64 = positions.iter().try_fold(0u64, |sum, (_, value)| {
        sum.checked_add(*value).ok_or("input values overflow")
    })?;
    println!(
        "               own scan: {} blocks, {} vault notes, {} input note(s)",
        chain.tip,
        chain.notes.len(),
        positions.len()
    );
    mine.write_text(
        "own_scan.txt",
        &format!(
            "tip={}\nactions={}\nvault_notes={}\ninput_positions={}\ninput_value_zat={}\nanchor={}\n",
            chain.tip, chain.cmxs.len(), chain.notes.len(),
            positions.iter().map(|(position, _)| position.to_string()).collect::<Vec<_>>().join(","), input_total,
            hex::encode(anchor),
        ),
    )
    .map_err(|e| e.to_string())?;

    // ── path A or path B ────────────────────────────────────────────────────
    let (raw, txid, path_name) = if let Some((raw, txid)) = posted {
        (raw, txid, "A")
    } else {
        println!("path B         no final transaction posted; re-proving the signed candidate");
        let (signed, sighash, indices) = (signed_candidate, candidate_sighash, candidate_indices);
        println!("path B         aggregated two shares per spend; verifies under ak+alpha");
        let witnesses = indices
            .into_iter()
            .zip(positions.iter())
            .map(|(index, (position, _))| (index, *position))
            .collect::<Vec<_>>();
        let (raw, txid) = prove_and_extract(
            signed,
            &sighash,
            &witnesses,
            &chain.cmxs,
            anchor,
            "path B       ",
        )?;
        (raw, txid, "B")
    };

    let sent = rpc.json(
        "sendrawtransaction",
        &format!("[\"{}\"]", hex::encode(&raw)),
    )?;
    println!("path {path_name}         broadcast: {sent}");

    mine.write_text(
        "finished.txt",
        &format!(
            "path={path_name}\ntxid={txid}\nbroadcast_at_height={}\n",
            chain.tip
        ),
    )
    .map_err(|e| e.to_string())?;
    println!("{txid}");
    Ok(())
}

/// Check that what was mined is exactly what was approved.
///
/// Read from the chain, not from any local artifact: the transaction is fetched by txid,
/// its Ironwood actions are trial-decrypted with the vault's own viewing key, and every
/// field the intent names is compared against what the chain actually carries. A mined
/// transaction is not evidence on its own; this is what makes it evidence.
fn verify_effects(args: &[String]) -> Result<(), String> {
    use orchard::keys::Scope;

    let rdir = PathBuf::from(
        args.first()
            .ok_or("usage: verify-effects <replica-dir> <txid>")?,
    );
    let txid = args
        .get(1)
        .ok_or("usage: verify-effects <replica-dir> <txid>")?;
    let replica = MemberDir::open(
        rdir.parent().unwrap_or(&rdir),
        rdir.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("replica"),
    );

    let intent_kv = kv(&replica
        .read_text("intent.txt")
        .map_err(|e| format!("{e}"))?);
    let want_nfs = intent_nullifiers(&intent_kv)?;
    let want_recipient: [u8; 43] = hexn(&intent_kv, "recipient")?;
    let want_amount: u64 = intent_kv["amount_zat"]
        .parse()
        .map_err(|e| format!("{e}"))?;
    let want_change: u64 = intent_kv["change_zat"]
        .parse()
        .map_err(|e| format!("{e}"))?;
    let want_fee: u64 = intent_kv["fee_zat"].parse().map_err(|e| format!("{e}"))?;
    let want_memo = hex::decode(&intent_kv["memo"]).map_err(|e| format!("{e}"))?;

    // TEST-ONLY FVK again: spliced from the DKG group ak, not ZIP 2005 derived.
    let ak: [u8; 32] = replica
        .read_hex("group_ak.hex")
        .map_err(|e| format!("{e}"))?
        .try_into()
        .map_err(|_| "group_ak")?;
    let fvk = vault::test_only_fvk(&ak).map_err(|e| format!("{e:?}"))?;
    // Both scopes: the payment is on a diversified external address, the change is on the
    // internal one, and the effects check has to see both.
    let ivks = loki_poc::scan::vault_ivks(&fvk);
    let change_addr = fvk.address_at(0u64, Scope::Internal).to_raw_address_bytes();

    let rpc = loki_poc::rpc::Rpc::regtest();
    let tx = rpc.json("getrawtransaction", &format!("[\"{txid}\", 1]"))?;
    let conf = tx["confirmations"].as_u64().unwrap_or(0);
    let height = tx["height"].as_i64().unwrap_or(-1);
    if conf < 1 {
        return Err(format!("{txid} has {conf} confirmations; it is not mined"));
    }

    // The consensus transaction carries the signed value balance. Reading it from the
    // mined bytes avoids treating a proposed input value as evidence of the paid fee.
    let raw_hex = rpc.json("getrawtransaction", &format!("[\"{txid}\", 0]"))?;
    let raw = hex::decode(
        raw_hex
            .as_str()
            .ok_or("getrawtransaction did not return hex")?,
    )
    .map_err(|e| format!("mined transaction hex: {e}"))?;
    let mined = zcash_primitives::transaction::Transaction::read(
        &raw[..],
        zcash_protocol::consensus::BranchId::Nu6_3,
    )
    .map_err(|e| format!("mined transaction does not parse: {e}"))?;
    if mined.txid().to_string() != *txid
        || mined.transparent_bundle().is_some()
        || mined.sapling_bundle().is_some()
        || mined.orchard_bundle().is_some()
    {
        return Err("mined transaction has a different txid or an unexpected pool".into());
    }
    let bundle = mined
        .ironwood_bundle()
        .ok_or("mined transaction has no Ironwood bundle")?;
    let candidate = pczt::Pczt::parse(
        &replica
            .read_hex("candidate_AC.pczt.hex")
            .map_err(|e| format!("candidate: {e}"))?,
    )
    .map_err(|e| format!("parse candidate: {e:?}"))?;
    let approved_sighash = pczt::roles::signer::Signer::new(candidate.clone())
        .map_err(|e| format!("candidate sighash: {e:?}"))?
        .shielded_sighash();
    if finalized_sighash(&mined)? != approved_sighash {
        return Err("mined transaction effects differ from the signed candidate".into());
    }
    let expected = candidate
        .ironwood()
        .actions()
        .iter()
        .map(|a| *a.spend().nullifier())
        .collect::<Vec<_>>();
    let actual = bundle
        .actions()
        .iter()
        .map(|a| a.nullifier().to_bytes())
        .collect::<Vec<_>>();
    if actual != expected || want_nfs.iter().any(|nf| !actual.contains(nf)) {
        return Err("mined transaction inputs differ from the signed candidate".into());
    }
    let implied_fee: u64 = (*bundle.value_balance())
        .try_into()
        .map_err(|_| "mined Ironwood value balance is not a valid fee")?;
    if implied_fee != want_fee {
        return Err(format!(
            "mined fee {implied_fee} zat, intent says {want_fee}"
        ));
    }

    let actions = tx["ironwood"]["actions"]
        .as_array()
        .ok_or("the mined transaction has no Ironwood actions")?;

    let mut paid: Option<u64> = None;
    let mut changed: Option<u64> = None;

    for a in actions {
        let raw = loki_poc::scan::RawAction {
            cv: loki_poc::scan::hex32(a, "cv").ok_or("cv")?,
            nullifier: loki_poc::scan::hex32(a, "nullifier").ok_or("nullifier")?,
            rk: loki_poc::scan::hex32(a, "rk").ok_or("rk")?,
            cmx: loki_poc::scan::hex32(a, "cmx").ok_or("cmx")?,
            ephemeral_key: loki_poc::scan::hex32(a, "ephemeralKey").ok_or("epk")?,
            enc_ciphertext: hex::decode(a["encCiphertext"].as_str().ok_or("enc")?)
                .map_err(|e| format!("{e}"))?,
            out_ciphertext: hex::decode(a["outCiphertext"].as_str().ok_or("out")?)
                .map_err(|e| format!("{e}"))?
                .try_into()
                .map_err(|_| "out_ciphertext is not 80 bytes")?,
        };
        let Some((note, memo)) = ivks
            .iter()
            .find_map(|ivk| loki_poc::scan::try_decrypt_with_memo(ivk, &raw))
        else {
            continue;
        };
        let value = note.value().inner();
        let to = note.recipient().to_raw_address_bytes();
        if to == want_recipient {
            // The memo is padded to 512 bytes; compare the prefix the intent named and
            // require the rest to be zero, so a trailing payload cannot hide there.
            if want_memo.len() > memo.len()
                || memo[..want_memo.len()] != want_memo[..]
                || memo[want_memo.len()..].iter().any(|b| *b != 0)
            {
                return Err(format!(
                    "the payment output's memo is not the approved memo: chain has {}",
                    hex::encode(&memo[..want_memo.len().min(32)])
                ));
            }
            if paid.replace(value).is_some() {
                return Err("multiple outputs pay the approved recipient".into());
            }
        } else if to == change_addr {
            if changed.replace(value).is_some() {
                return Err("multiple change outputs".into());
            }
        } else {
            return Err(format!(
                "the mined transaction pays {value} zat to an address the intent does not name"
            ));
        }
    }

    let paid = paid.ok_or("no output to the approved recipient could be decrypted")?;
    let changed = changed.ok_or("no change output to the vault could be decrypted")?;
    if paid != want_amount {
        return Err(format!("paid {paid} zat, intent says {want_amount}"));
    }
    if changed != want_change {
        return Err(format!("change {changed} zat, intent says {want_change}"));
    }

    println!("effects verified against the chain, not against a local file:");
    println!("  txid            {txid}");
    println!("  mined at height {height}, {conf} confirmation(s)");
    println!(
        "  input notes     {} (all match the signed candidate)",
        want_nfs.len()
    );
    println!(
        "  paid            {paid} zat to {}",
        &hex::encode(want_recipient)[..16]
    );
    println!(
        "  memo            {:?}",
        String::from_utf8_lossy(&want_memo)
    );
    println!("  change          {changed} zat to the vault internal address");
    println!("  fee             {implied_fee} zat");
    Ok(())
}

/// TEST-ONLY: the A.5 attack, against the real signing path.
///
/// `src/nonce_binding.rs` showed that in bare FROST a co-signer who simply commits a
/// second time moves the binding factor while a bound nonce stays fixed, which is the
/// precondition for recovering a signing share. Loki is not bare FROST: it derives the
/// per-pair randomiser from the proposal AND the published commitment set, and every
/// signer recomputes it rather than accepting one.
///
/// So the prediction is that this attack cannot reach the signing step here, because
/// moving carol's commitment moves alpha, and alpha no longer matches the `rk` baked into
/// the candidate. That prediction had never been run. This case runs it.
///
/// Carol re-commits for the AC pair. The candidate is left exactly as it was.
fn tamper_cosigner_recommit(root: &std::path::Path, shared: &MemberDir) -> Result<(), String> {
    let carol = MemberDir::open(root, "carol");
    let key_package = frost::keys::KeyPackage::deserialize(
        &carol
            .read_hex("key_package.hex")
            .map_err(|e| format!("{e}"))?,
    )
    .map_err(|e| format!("key package: {e}"))?;

    let before = shared
        .read_hex("commitment_AC_carol.hex")
        .map_err(|e| format!("run commit and propose first: {e}"))?;

    let mut rng = rand_core::OsRng;
    let (nonces, commitment) = frost::round1::commit(key_package.signing_share(), &mut rng);

    carol
        .write_hex(
            "nonces_AC.hex",
            &nonces.serialize().map_err(|e| format!("{e}"))?,
        )
        .map_err(|e| e.to_string())?;
    let after = commitment.serialize().map_err(|e| format!("{e}"))?;
    shared
        .write_hex("commitment_AC_carol.hex", &after)
        .map_err(|e| e.to_string())?;

    if before == after {
        return Err("the new commitment is identical to the old one; nothing was tampered".into());
    }

    println!("carol re-committed for pair AC. The candidate is untouched.");
    println!("  commitment was {}...", &hex::encode(&before)[..16]);
    println!("  commitment now {}...", &hex::encode(&after)[..16]);
    println!("alice should now refuse: the commitment set feeds alpha, and alpha fixes rk.");
    Ok(())
}

#[cfg(test)]
mod selection_tests {
    use super::*;
    use loki_poc::{
        candidate::{build_candidate, quote_fee, CandidateInputs, Regtest},
        randomizer::SeedRecord,
    };
    use orchard::{
        keys::Scope,
        note::{RandomSeed, Rho},
        value::NoteValue,
        Note, NoteVersion,
    };
    use zcash_protocol::{memo::MemoBytes, value::Zatoshis};

    #[test]
    fn payment_needing_two_notes_selects_both_and_quotes_their_fee() {
        let (_, public) = frost::keys::generate_with_dealer(
            3,
            2,
            frost::keys::IdentifierList::Default,
            rand_core::OsRng,
        )
        .unwrap();
        let ak: [u8; 32] = public
            .verifying_key()
            .serialize()
            .unwrap()
            .try_into()
            .unwrap();
        let fvk = vault::test_only_fvk(&ak).unwrap();

        let note = |value, seed: u8, position| {
            let rho = Rho::from_bytes(&[seed + 1; 32]).unwrap();
            let rseed = RandomSeed::from_bytes([seed + 2; 32], &rho).unwrap();
            let note = Note::from_parts(
                fvk.address_at(0u64, Scope::External),
                NoteValue::from_raw(value),
                rho,
                rseed,
                NoteVersion::V3,
            )
            .unwrap();
            let nullifier = note.nullifier(&fvk).to_bytes();
            (note, nullifier, position)
        };
        let notes = [note(30_000_000, 1, 0), note(35_000_000, 2, 1)];
        let memo = MemoBytes::from_bytes(b"two notes").unwrap();
        let pay = Zatoshis::from_u64(50_000_000).unwrap();
        let recipient = fvk.address_at(7u64, Scope::External);

        assert!(select_notes(&notes[..1], &fvk, recipient, pay, &memo, 20, 9_216).is_err());
        let (selected, fee) = select_notes(&notes, &fvk, recipient, pay, &memo, 20, 9_216).unwrap();
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[0].0.value().inner(), 35_000_000);
        assert!(65_000_000 >= 50_000_000 + u64::from(fee));
    }

    #[test]
    fn second_device_aggregates_each_input_with_its_own_shares() {
        let (shares, public) = frost::keys::generate_with_dealer(
            3,
            2,
            frost::keys::IdentifierList::Default,
            rand_core::OsRng,
        )
        .unwrap();
        let packages: BTreeMap<_, _> = shares
            .into_iter()
            .map(|(id, share)| (id, frost::keys::KeyPackage::try_from(share).unwrap()))
            .collect();
        let ids = [
            *packages.keys().next().unwrap(),
            *packages.keys().nth(2).unwrap(),
        ];
        let ak: [u8; 32] = public
            .verifying_key()
            .serialize()
            .unwrap()
            .try_into()
            .unwrap();
        let fvk = vault::test_only_fvk(&ak).unwrap();
        let notes = [1u8, 2].map(|seed| {
            let rho = Rho::from_bytes(&[seed + 1; 32]).unwrap();
            let rseed = RandomSeed::from_bytes([seed + 2; 32], &rho).unwrap();
            Note::from_parts(
                fvk.address_at(0u64, Scope::External),
                NoteValue::from_raw(30_000_000),
                rho,
                rseed,
                NoteVersion::V3,
            )
            .unwrap()
        });
        let proposal_id = [9u8; 32];
        let mut nonces = Vec::new();
        let mut commitments = Vec::new();
        let mut alphas = Vec::new();
        let mut seeds = Vec::new();
        let mut records = Vec::new();
        for (spend, note) in notes.iter().enumerate() {
            let mut n = BTreeMap::new();
            let mut c = BTreeMap::new();
            for id in ids {
                let (nonce, commitment) =
                    frost::round1::commit(packages[&id].signing_share(), &mut rand_core::OsRng);
                n.insert(id, nonce);
                c.insert(id, commitment);
            }
            let (params, seed) = frost_rerandomized::RandomizedParams::new_from_commitments(
                public.verifying_key(),
                &c,
                rand_core::OsRng,
            )
            .unwrap();
            let alpha = *params.randomizer();
            records.push(
                SeedRecord::new(
                    proposal_id,
                    "AC",
                    spend,
                    note.nullifier(&fvk).to_bytes(),
                    &c,
                    &seed,
                )
                .unwrap(),
            );
            seeds.push(seed);
            nonces.push(n);
            commitments.push(c);
            alphas.push(alpha);
        }
        let mut inputs = CandidateInputs {
            vault_fvk: &fvk,
            notes: notes.to_vec(),
            recipient: fvk.address_at(7u64, Scope::External),
            amount: Zatoshis::const_from_u64(50_000_000),
            memo: MemoBytes::empty(),
            change: Zatoshis::ZERO,
            target_height: 20,
            expiry_height: 9_216,
        };
        let fee = quote_fee(&Regtest, &inputs).unwrap();
        inputs.change = Zatoshis::const_from_u64(10_000_000 - u64::from(fee));
        let builder_alphas = alphas
            .iter()
            .map(|a| {
                let bytes: [u8; 32] = a.serialize().try_into().unwrap();
                loki_poc::candidate::alpha_from_canonical_bytes(&bytes).unwrap()
            })
            .collect::<Vec<_>>();
        let built = build_candidate(
            &Regtest,
            &inputs,
            &builder_alphas,
            rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng),
        )
        .unwrap();
        let candidate = pczt::roles::creator::Creator::build_from_parts(built.pczt_parts).unwrap();
        let candidate = pczt::roles::io_finalizer::IoFinalizer::new(candidate)
            .finalize_io(rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng))
            .unwrap();
        let sighash = pczt::roles::signer::Signer::new(candidate.clone())
            .unwrap()
            .shielded_sighash();
        let mut signed_shares = Vec::new();
        for spend in 0..2 {
            let package = frost::SigningPackage::new(commitments[spend].clone(), &sighash);
            let pair = ids.map(|id| {
                let share = frost_rerandomized::sign_with_randomizer_seed(
                    &package,
                    &nonces[spend][&id],
                    &packages[&id],
                    &seeds[spend],
                )
                .unwrap();
                share.serialize()
            });
            signed_shares.push(pair);
        }
        let aggregate_inputs = AggregateInputs {
            pair: "AC".into(),
            group_ak: ak,
            seeds: records,
            candidate: candidate.serialize().unwrap(),
            public_package: public.serialize().unwrap(),
            ids: ids.map(|id| id.serialize()),
            commitments: commitments
                .iter()
                .map(|c| ids.map(|id| c[&id].serialize().unwrap()))
                .collect(),
            shares: signed_shares,
            proposal_id,
            want_nfs: notes
                .iter()
                .map(|note| note.nullifier(&fvk).to_bytes())
                .collect(),
        };
        let (signed, actual_sighash, indices) = aggregate_and_apply(&aggregate_inputs).unwrap();
        assert_eq!(actual_sighash, sighash);
        assert_eq!(indices.len(), 2);
        assert_ne!(indices[0], indices[1]);

        let mut wrong = aggregate_inputs;
        wrong.shares[1][0] = wrong.shares[0][0].clone();
        assert!(
            aggregate_and_apply(&wrong).is_err(),
            "a share for input 0 cannot authorize input 1"
        );

        let cmxs = notes
            .map(|note| orchard::note::ExtractedNoteCommitment::from(note.commitment()).to_bytes());
        let anchor = loki_poc::witness::CommitmentTree::build(&cmxs)
            .unwrap()
            .root()
            .to_bytes();
        let positions = indices
            .into_iter()
            .enumerate()
            .map(|(position, index)| (index, position as u64))
            .collect::<Vec<_>>();
        let (raw, txid) = prove_and_extract(
            signed,
            &sighash,
            &positions,
            &cmxs,
            anchor,
            "offline two-note",
        )
        .unwrap();
        let tx = zcash_primitives::transaction::Transaction::read(
            &raw[..],
            zcash_protocol::consensus::BranchId::Nu6_3,
        )
        .unwrap();
        assert_eq!(tx.txid().to_string(), txid);
        assert_eq!(finalized_sighash(&tx).unwrap(), sighash);
        assert_eq!(
            u64::try_from(*tx.ironwood_bundle().unwrap().value_balance()).unwrap(),
            u64::from(fee)
        );
    }
}

#[cfg(test)]
mod saved_session_tests {
    use super::*;
    #[test]
    fn randomizer_reproposal_refuses_before_mutating_saved_session() {
        let root = std::env::temp_dir().join(format!("loki-reproposal-{}", std::process::id()));
        let shared = MemberDir::create(&root, "public").unwrap();
        shared
            .write_text("intent.txt", "saved session marker")
            .unwrap();
        let error = propose(&[root.to_str().unwrap().to_string()]).unwrap_err();
        assert!(error.contains("saved signing session exists"), "{error}");
        assert_eq!(
            shared.read_text("intent.txt").unwrap(),
            "saved session marker"
        );
        std::fs::remove_dir_all(root).unwrap();
    }
}

#[cfg(test)]
#[path = "loki/randomizer_tests.rs"]
mod randomizer_tests;
