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
                   replicate <state-dir> <replica-dir> [--with-final]   public artifacts only\n\
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
        let (secret, public) = frost::keys::dkg::part1(*id, 3, 2, rng)
            .map_err(|e| format!("dkg part1: {e}"))?;
        r1_secret.insert(*id, secret);
        r1_public.insert(*id, public);
    }

    // Round 2: per-peer packages.
    let mut r2_secret = BTreeMap::new();
    let mut r2_inbox: BTreeMap<frost::Identifier, BTreeMap<frost::Identifier, _>> =
        BTreeMap::new();
    for id in &ids {
        let others = peers(&r1_public, id);
        let (secret, outgoing) =
            frost::keys::dkg::part2(r1_secret.remove(id).unwrap(), &others)
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
            Some(seen) if seen != ak => {
                return Err("members disagree on the group key".into())
            }
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
    shared.write_hex("group_ak.hex", &ak).map_err(|e| e.to_string())?;
    shared.write_text("vault_address.txt", &ua).map_err(|e| e.to_string())?;

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
    let ivks = loki_poc::scan::vault_ivks(&fvk);

    let rpc = loki_poc::rpc::Rpc::regtest();
    let tip = rpc
        .json("getblockcount", "[]")?
        .as_u64()
        .ok_or("getblockcount did not return a number")?;

    let mut position = 0u64;
    let mut notes = Vec::new();
    let mut cmxs: Vec<[u8; 32]> = Vec::new();

    for height in 1..=tip {
        let block = rpc.json("getblock", &format!("[\"{height}\", 2]"))?;
        let txs = block["tx"].as_array().ok_or("block has no tx array")?;

        for tx in txs {
            let txid = tx["txid"].as_str().unwrap_or("?").to_string();
            let actions = match tx["ironwood"]["actions"].as_array() {
                Some(a) if !a.is_empty() => a,
                _ => continue,
            };

            let raws: Vec<_> = actions
                .iter()
                .filter_map(|a| {
                    Some(loki_poc::scan::RawAction {
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

            cmxs.extend(raws.iter().map(|r| r.cmx));

            let (found, next) = loki_poc::scan::scan_block(
                &fvk,
                &ivks,
                height as u32,
                &txid,
                &raws,
                position,
            );
            position = next;
            notes.extend(found);
        }
    }

    println!("scanned {tip} blocks, {position} Ironwood actions");
    println!("vault notes: {}", notes.len());
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
    let best = notes.iter().max_by_key(|n| (n.value_zat, std::cmp::Reverse(n.height))).unwrap();

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
    println!("witness  position {} verified against the node's anchor", path.position());

    shared
        .write_text(
            "anchor.txt",
            &format!("height={tip}\nironwood_final_root={anchor_hex}\n"),
        )
        .map_err(|e| e.to_string())?;
    shared
        .write_hex(
            "cmxs.hex",
            &cmxs.iter().flat_map(|c| c.iter().copied()).collect::<Vec<u8>>(),
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

    println!();
    println!("funding fixture written: {}/public/funded_note.txt", root.display());
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
    let who = args.get(1).ok_or("usage: commit <state-dir> <member>")?.as_str();

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
        Some(v) => v.parse().map_err(|e| format!("--spends must be a whole number: {e}"))?,
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
            let (nonces, commitment) =
                frost::round1::commit(key_package.signing_share(), &mut rng);

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

fn hexn<const N: usize>(m: &std::collections::HashMap<String, String>, k: &str) -> Result<[u8; N], String> {
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
    args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned()
}

/// Where a member keeps the nonce pair for spend `i` of candidate `pair`.
///
/// Spend 0 keeps the original unindexed name. That is not tidiness: the demo runner, the
/// tamper harness and the shell scripts all name these files directly, and renaming the
/// common case would break them for no benefit.
fn nonce_file(pair: &str, i: usize) -> String {
    if i == 0 { format!("nonces_{pair}.hex") } else { format!("nonces_{pair}_{i}.hex") }
}

/// The published counterpart of [`nonce_file`]. Same compatibility rule.
fn commitment_file(pair: &str, who: &str, i: usize) -> String {
    if i == 0 {
        format!("commitment_{pair}_{who}.hex")
    } else {
        format!("commitment_{pair}_{who}_{i}.hex")
    }
}

fn propose(args: &[String]) -> Result<(), String> {
    use zcash_protocol::consensus::Parameters as _;
    use loki_poc::{candidate::*, intent::*};
    use orchard::{
        keys::Scope,
        note::{RandomSeed, Rho},
        value::NoteValue,
        Note, NoteVersion,
    };
    use zcash_protocol::{memo::MemoBytes, value::Zatoshis};

    let root = PathBuf::from(args.first().ok_or("usage: propose <state-dir> [note-file]")?);
    // Vault-level state (the group key, the scan output) lives in `public` whatever round
    // this is; the proposal and its candidates belong to the round.
    let vault_dir = MemberDir::open(&root, "public");
    let shared = MemberDir::create(&root, &shared_name()).map_err(|e| format!("{e}"))?;
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
    let fvk = vault::test_only_fvk(&ak).map_err(|e| format!("{e:?}"))?;

    let note_kv = kv(&vault_dir
        .read_text(note_file)
        .map_err(|e| format!("run scan first: {e}"))?);

    let recipient_bytes: [u8; 43] = hexn(&note_kv, "recipient")?;
    let rho = Rho::from_bytes(&hexn::<32>(&note_kv, "rho")?)
        .into_option()
        .ok_or("funded note has an invalid rho")?;
    let rseed = RandomSeed::from_bytes(hexn::<32>(&note_kv, "rseed")?, &rho)
        .into_option()
        .ok_or("funded note has an invalid rseed")?;
    let value: u64 = note_kv["value_zat"].parse().map_err(|e| format!("value: {e}"))?;

    let note = Note::from_parts(
        orchard::Address::from_raw_address_bytes(&recipient_bytes)
            .into_option()
            .ok_or("funded note has an invalid recipient")?,
        NoteValue::from_raw(value),
        rho,
        rseed,
        NoteVersion::V3,
    )
    .into_option()
    .ok_or("funded note does not reconstruct")?;

    // The reconstructed note must be the one we scanned.
    let expect_nf: [u8; 32] = hexn(&note_kv, "nullifier")?;
    if note.nullifier(&fvk).to_bytes() != expect_nf {
        return Err("reconstructed note has a different nullifier than the scan recorded".into());
    }

    // ── the intent ──────────────────────────────────────────────────────────
    let rpc = loki_poc::rpc::Rpc::regtest();
    let tip = rpc.json("getblockcount", "[]")?.as_u64().ok_or("getblockcount")? as u32;

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
        Some(v) => v.parse().map_err(|e| format!("--amount must be a whole number of zatoshis: {e}"))?,
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

    let mut inputs = CandidateInputs {
        vault_fvk: &fvk,
        notes: vec![note],
        recipient,
        amount,
        memo: memo.clone(),
        change: Zatoshis::ZERO,
        target_height: tip,
        expiry_height: expiry,
    };
    let fee = quote_fee(&Regtest, &inputs)?;

    // The note has to cover the payment and the fee. Without this the subtraction below
    // underflows: it panics in a debug build and silently wraps to an enormous change
    // value in a release one, so there was no "insufficient funds" path at all.
    let needed = amount_zat
        .checked_add(u64::from(fee))
        .ok_or("amount plus fee overflows")?;
    if value < needed {
        return Err(format!(
            "insufficient funds: this note holds {value} zat, and the payment needs \
             {needed} zat ({amount_zat} to pay plus {} fee). Spending several notes in \
             one payment is not implemented yet, so a single note must cover it.",
            u64::from(fee),
        ));
    }
    let change = Zatoshis::from_u64(value - needed)
        .map_err(|e| format!("change is not a valid amount: {e:?}"))?;
    inputs.change = change;

    let intent = Intent {
        proposer: MemberDir::open(&root, "alice")
            .read_hex("identifier.hex")
            .map_err(|e| format!("{e}"))?,
        created_height: tip,
        input_nullifiers: vec![expect_nf],
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
                hex::encode(expect_nf),
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
    shared.write_hex("group_ak.hex", &ak).map_err(|e| e.to_string())?;

    println!("proposal   {}", hex::encode(proposal_id));
    println!("spend      {} zat from position {}", value, note_kv["position"]);
    println!("pay        {} zat  fee {}  change {}", u64::from(amount), u64::from(fee), u64::from(change));
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

        // That pair's published commitments.
        let mut commitments = BTreeMap::new();
        for (slot, id) in [x, y].iter().zip(ids.iter()) {
            let raw = shared
                .read_hex(&format!("commitment_{name}_{}.hex", MEMBERS[*slot].0))
                .map_err(|e| format!("run commit first: {e}"))?;
            commitments.insert(
                *id,
                frost::round1::SigningCommitments::deserialize(&raw)
                    .map_err(|e| format!("commitment: {e}"))?,
            );
        }

        // alpha, derived from the proposal and this pair's commitments.
        let seed = alpha_seed(&proposal_id, (&ids[0], &ids[1]), 0);
        let alpha_bytes = alpha_for_candidate(&seed, &commitments)
            .map_err(|e| format!("alpha: {e}"))?
            .serialize();
        let alpha_arr: [u8; 32] = alpha_bytes
            .as_slice()
            .try_into()
            .map_err(|_| "alpha is not 32 bytes")?;
        let alpha = alpha_from_canonical_bytes(&alpha_arr)
            .ok_or("derived alpha is not a canonical Pallas scalar")?;

        let built = build_candidate(
            &Regtest,
            &inputs,
            &[alpha],
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
            .filter(|a| a.spend().nullifier().to_bytes() == expect_nf)
            .collect();
        if real.len() != 1 {
            return Err(format!("{name}: expected exactly one real spend"));
        }
        if real[0].spend().witness().is_some() {
            return Err(format!("{name}: real spend already has a witness"));
        }
        let rk = <[u8; 32]>::from(real[0].spend().rk());
        if seen_rk.contains(&rk) {
            return Err(format!("{name}: rk collides with another candidate"));
        }
        seen_rk.push(rk);

        // Serialize the PCZT: this is the handoff artifact the signers receive.
        let pczt = pczt::roles::creator::Creator::build_from_parts(built.pczt_parts)
            .ok_or_else(|| format!("{name}: build_from_parts"))?;

        // IO Finalizer: no more inputs or outputs may be added after this, and it derives
        // the binding signature signing key. It must run BEFORE anyone computes a
        // sighash, or the signers would sign a transaction whose IO was still open.
        let pczt = pczt::roles::io_finalizer::IoFinalizer::new(pczt)
            .finalize_io(rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng))
            .map_err(|e| format!("{name}: io finalizer: {e:?}"))?;

        let bytes = pczt.serialize().map_err(|e| format!("{name}: serialize: {e:?}"))?;

        shared
            .write_hex(&format!("candidate_{name}.pczt.hex"), &bytes)
            .map_err(|e| e.to_string())?;
        shared
            .write_hex(&format!("alpha_{name}.hex"), &alpha_arr)
            .map_err(|e| e.to_string())?;

        println!(
            "{name}  rk {}  alpha {}  {} bytes, anchor deferred, no witness, no proof",
            &hex::encode(rk)[..16],
            &hex::encode(alpha_arr)[..16],
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
    use loki_poc::intent::alpha_seed;
    use loki_poc::verify::{Expectations, Refusal};
    use pczt::roles::{
        low_level_signer::Signer as LowLevelSigner, signer::Signer,
        verifier::{OrchardError, Verifier},
    };

    let root = PathBuf::from(args.first().ok_or("usage: review-sign <state-dir> <member>")?);
    let who = args.get(1).ok_or("usage: review-sign <state-dir> <member>")?.as_str();
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
    let want_nf: [u8; 32] = hexn(&intent_kv, "input_nullifier")?;
    let want_recipient: [u8; 43] = hexn(&intent_kv, "recipient")?;
    let want_amount: u64 = intent_kv["amount_zat"].parse().map_err(|e| format!("{e}"))?;
    let want_change: u64 = intent_kv["change_zat"].parse().map_err(|e| format!("{e}"))?;
    let want_memo = hex::decode(&intent_kv["memo"]).map_err(|e| format!("{e}"))?;
    let want_expiry: u32 = intent_kv["expiry_height"].parse().map_err(|e| format!("{e}"))?;
    let want_fee: u64 = intent_kv["fee_zat"].parse().map_err(|e| format!("{e}"))?;
    let proposal_id: [u8; 32] = hexn(&intent_kv, "proposal_id")?;

    // The vault key: the signer derives the change address from this itself rather than
    // taking one from the intent, so a swapped change address cannot be smuggled in.
    let ak: [u8; 32] = shared
        .read_hex("group_ak.hex")
        .map_err(|e| format!("{e}"))?
        .try_into()
        .map_err(|_| "group_ak.hex is not 32 bytes")?;
    let vault_fvk = vault::test_only_fvk(&ak).map_err(|e| format!("{e:?}"))?;

    let want = Expectations {
        input_nullifiers: vec![want_nf],
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

        // Read this candidate's alpha out of the PCZT, and recompute what it should be.
        let mut found_alpha = None;
        let mut found_rk = None;
        LowLevelSigner::new(checked.clone())
            .sign_ironwood_with::<pczt::roles::low_level_signer::OrchardParseError, _>(
                |_pczt, bundle, _| {
                for action in bundle.actions() {
                    if action.spend().nullifier().to_bytes() == want_nf {
                        found_alpha = *action.spend().alpha();
                        found_rk = Some(<[u8; 32]>::from(action.spend().rk()));
                    }
                }
                    Ok(())
                },
            )
            .map_err(|e| format!("{name}: low level signer: {e:?}"))?;

        let in_pczt_alpha = found_alpha.ok_or(format!("{name}: the spend carries no alpha"))?;
        let in_pczt_rk = found_rk.ok_or(format!("{name}: the spend carries no rk"))?;

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

        let mut commitments = BTreeMap::new();
        for (k, id) in [x, y].iter().zip(ids.iter()) {
            let raw = shared
                .read_hex(&format!("commitment_{name}_{}.hex", MEMBERS[*k].0))
                .map_err(|e| format!("{e}"))?;
            commitments.insert(
                *id,
                frost::round1::SigningCommitments::deserialize(&raw)
                    .map_err(|e| format!("{e}"))?,
            );
        }

        let seed = alpha_seed(&proposal_id, (&ids[0], &ids[1]), 0);
        let recomputed = loki_poc::intent::alpha_for_candidate(&seed, &commitments)
            .map_err(|e| format!("{name}: alpha: {e}"))?;
        let recomputed_bytes: [u8; 32] = recomputed
            .serialize()
            .as_slice()
            .try_into()
            .map_err(|_| "alpha is not 32 bytes")?;

        // rk must equal ak randomized by the alpha WE recomputed, not the one supplied.
        let scalar = loki_poc::candidate::alpha_from_canonical_bytes(&recomputed_bytes)
            .ok_or(format!("{name}: recomputed alpha is noncanonical"))?;
        if in_pczt_alpha != scalar {
            return Err(format!(
                "{name}: REFUSED: {}",
                Refusal::RkDoesNotMatchAlpha {
                    expected: hex::encode(recomputed_bytes),
                    found: "a different alpha in the PCZT".into(),
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
        let package = frost::SigningPackage::new(commitments.clone(), &sighash);
        if package.message() != &sighash[..] {
            return Err(format!("{name}: REFUSED: {}", Refusal::PackageSighashMismatch));
        }

        reviewed.push((name, package, recomputed, sighash));
        println!("{who:<6} {name}  reviewed: effects match, rk matches recomputed alpha");
    }

    if reviewed.is_empty() {
        return Err(format!("{who} is not a member of any candidate"));
    }

    // ── only now, emit the share batch ──────────────────────────────────────
    for (name, package, alpha, sighash) in reviewed {
        let nonces = frost::round1::SigningNonces::deserialize(
            &me.read_hex(&format!("nonces_{name}.hex"))
                .map_err(|e| format!("{name}: run commit first: {e}"))?,
        )
        .map_err(|e| format!("{name}: nonces: {e}"))?;

        #[allow(deprecated)] // alpha is fixed by the transaction; the seed path cannot be used
        let share = frost_rerandomized::sign(&package, &nonces, &key_package, alpha)
            .map_err(|e| format!("{name}: sign: {e}"))?;

        shared
            .write_hex(
                &format!("share_{name}_{who}.hex"),
                &share.serialize(),
            )
            .map_err(|e| e.to_string())?;

        // The nonce is spent. Remove it so it cannot be used a second time.
        std::fs::remove_file(me.path().join(format!("nonces_{name}.hex")))
            .map_err(|e| format!("{name}: removing spent nonce: {e}"))?;

        println!(
            "{who:<6} {name}  share emitted, nonce consumed  (sighash {})",
            &hex::encode(sighash)[..16]
        );
    }

    Ok(())
}

/// Collect every Ironwood commitment on the chain, in append order, plus the tip anchor.
/// The commitment stream, the node's anchor, and the tip height.
type ChainView = (Vec<[u8; 32]>, [u8; 32], u64);

fn chain_commitments(rpc: &loki_poc::rpc::Rpc) -> Result<ChainView, String> {
    let tip = rpc.json("getblockcount", "[]")?.as_u64().ok_or("getblockcount")?;
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
    use loki_poc::intent::alpha_seed;
    use pczt::roles::{
        prover::Prover, signer::Signer, spend_finalizer::SpendFinalizer,
        tx_extractor::TransactionExtractor, updater::Updater,
    };

    let root = PathBuf::from(args.first().ok_or("usage: finish <state-dir>")?);
    let shared = MemberDir::open(&root, &shared_name());
    let vault_dir = MemberDir::open(&root, "public");

    // Alice and Carol only. Bob's directory is never opened.
    const PAIR: (&str, usize, usize) = ("AC", 0, 2);
    let (name, x, y) = PAIR;

    let intent_kv = kv(&shared.read_text("intent.txt").map_err(|e| format!("{e}"))?);
    let want_nf: [u8; 32] = hexn(&intent_kv, "input_nullifier")?;
    let proposal_id: [u8; 32] = hexn(&intent_kv, "proposal_id")?;

    let ak: [u8; 32] = shared.read_hex("group_ak.hex").map_err(|e| format!("{e}"))?
        .try_into().map_err(|_| "group_ak")?;
    let _fvk = vault::test_only_fvk(&ak).map_err(|e| format!("{e:?}"))?;

    let public_package = frost::keys::PublicKeyPackage::deserialize(
        &MemberDir::open(&root, "alice")
            .read_hex("public_package.hex")
            .map_err(|e| format!("{e}"))?,
    )
    .map_err(|e| format!("public package: {e}"))?;

    let bytes = shared
        .read_hex(&format!("candidate_{name}.pczt.hex"))
        .map_err(|e| format!("{e}"))?;
    let pczt = pczt::Pczt::parse(&bytes).map_err(|e| format!("parse: {e:?}"))?;

    // The coordinator computes the sighash from the same bytes the signers did.
    let sighash = Signer::new(pczt.clone())
        .map_err(|e| format!("signer: {e:?}"))?
        .shielded_sighash();

    // Rebuild the pair's commitments and alpha.
    let ids: Vec<frost::Identifier> = [x, y]
        .iter()
        .map(|k| {
            let raw = MemberDir::open(&root, MEMBERS[*k].0)
                .read_hex("identifier.hex")
                .map_err(|e| format!("{e}"))?;
            frost::Identifier::deserialize(&raw).map_err(|e| format!("{e}"))
        })
        .collect::<Result<_, String>>()?;

    let mut commitments = BTreeMap::new();
    for (k, id) in [x, y].iter().zip(ids.iter()) {
        let raw = shared
            .read_hex(&format!("commitment_{name}_{}.hex", MEMBERS[*k].0))
            .map_err(|e| format!("{e}"))?;
        commitments.insert(
            *id,
            frost::round1::SigningCommitments::deserialize(&raw).map_err(|e| format!("{e}"))?,
        );
    }

    let seed = alpha_seed(&proposal_id, (&ids[0], &ids[1]), 0);
    let alpha = loki_poc::intent::alpha_for_candidate(&seed, &commitments)
        .map_err(|e| format!("alpha: {e}"))?;

    // Verify and aggregate the two shares. `aggregate` checks each share and names any
    // culprit, so a bad share is identified rather than silently producing garbage.
    let package = frost::SigningPackage::new(commitments, &sighash);
    let mut shares = BTreeMap::new();
    for (k, id) in [x, y].iter().zip(ids.iter()) {
        let raw = shared
            .read_hex(&format!("share_{name}_{}.hex", MEMBERS[*k].0))
            .map_err(|e| format!("run review-sign first: {e}"))?;
        shares.insert(
            *id,
            frost::round2::SignatureShare::deserialize(&raw).map_err(|e| format!("{e}"))?,
        );
    }

    let params = frost_rerandomized::RandomizedParams::from_randomizer(
        public_package.verifying_key(),
        alpha,
    );
    let group_sig = frost_rerandomized::aggregate(&package, &shares, &public_package, &params)
        .map_err(|e| format!("aggregate: {e}"))?;

    // The signature verifies under ak+alpha before it ever reaches the node.
    params
        .randomized_verifying_key()
        .verify(&sighash, &group_sig)
        .map_err(|e| format!("the aggregated signature does not verify: {e}"))?;
    println!("{name}  aggregated two shares; verifies under ak+alpha");

    // Cross the version boundary as 64 canonical bytes.
    let sig_bytes: [u8; 64] = group_sig
        .serialize()
        .map_err(|e| format!("{e}"))?
        .as_slice()
        .try_into()
        .map_err(|_| "signature is not 64 bytes")?;
    let orchard_sig =
        orchard::primitives::redpallas::Signature::<
            orchard::primitives::redpallas::SpendAuth,
        >::from(sig_bytes);

    // Which action spends our note?
    let index = pczt
        .ironwood()
        .actions()
        .iter()
        .position(|a| a.spend().nullifier() == &want_nf)
        .ok_or("the candidate does not spend the funded note")?;

    let mut signer = Signer::new(pczt).map_err(|e| format!("signer: {e:?}"))?;
    signer
        .apply_ironwood_signature(index, orchard_sig)
        .map_err(|e| format!("apply signature: {e:?}"))?;
    let signed = signer.finish();
    println!("{name}  signature applied to action {index}");

    // ── everything below happens AFTER signing ──────────────────────────────
    let rpc = loki_poc::rpc::Rpc::regtest();
    let (cmxs, anchor, tip) = chain_commitments(&rpc)?;

    let note_kv = kv(&vault_dir.read_text("funded_note.txt").map_err(|e| format!("{e}"))?);
    let position: u64 = note_kv["position"].parse().map_err(|e| format!("{e}"))?;
    let path = loki_poc::witness::witness_for(&cmxs, position, &anchor)?;
    println!("{name}  anchor {} at height {tip}", &hex::encode(anchor)[..16]);

    let updated = Updater::new(signed)
        .set_ironwood_anchor(
            orchard::Anchor::from_bytes(anchor)
                .into_option()
                .ok_or("the node's anchor is not a valid Anchor")?,
        )
        .map_err(|e| format!("set anchor: {e:?}"))?
        .set_ironwood_spend_witnesses(vec![(index, path)])
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
    let pk = orchard::circuit::ProvingKey::build(
        orchard::circuit::OrchardCircuitVersion::PostNu6_3,
    );
    let proved = Prover::new(updated)
        .create_ironwood_proof(
            rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng),
            &pk,
        )
        .map_err(|e| format!("prove: {e:?}"))?
        .finish();
    println!("{name}  proof created");

    let finalized = SpendFinalizer::new(proved)
        .finalize_spends()
        .map_err(|e| format!("finalize: {e:?}"))?;

    let vk = orchard::circuit::VerifyingKey::build(
        orchard::circuit::OrchardCircuitVersion::PostNu6_3,
    );
    let tx = TransactionExtractor::new(finalized)
        .with_orchard(&vk)
        .extract(rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng))
        .map_err(|e| format!("extract: {e:?}"))?;

    let mut raw = Vec::new();
    tx.write(&mut raw).map_err(|e| format!("serialize tx: {e}"))?;
    let txid = tx.txid().to_string();
    println!("{name}  extracted v6 transaction {txid} ({} bytes)", raw.len());

    let sent = rpc.json("sendrawtransaction", &format!("[\"{}\"]", hex::encode(&raw)))?;
    println!("{name}  broadcast: {sent}");

    shared
        .write_text(
            "mined.txt",
            &format!("txid={txid}\nbroadcast_at_height={tip}\nanchor={}\n", hex::encode(anchor)),
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
    use loki_poc::{candidate::*, intent::*};
    use orchard::{
        keys::Scope,
        note::{RandomSeed, Rho},
        value::NoteValue,
        Note, NoteVersion,
    };
    use zcash_protocol::{memo::MemoBytes, value::Zatoshis};

    let root = PathBuf::from(args.first().ok_or("usage: tamper <state-dir> <case>")?);
    let case = args.get(1).ok_or("usage: tamper <state-dir> <case>")?.as_str();
    let shared = MemberDir::open(&root, &shared_name());

    // This case does not touch the candidate at all, so it branches before the rebuild.
    if case == "cosigner-recommit" {
        return tamper_cosigner_recommit(&root, &shared);
    }

    let ak: [u8; 32] = shared.read_hex("group_ak.hex").map_err(|e| format!("{e}"))?
        .try_into().map_err(|_| "group_ak")?;
    let fvk = vault::test_only_fvk(&ak).map_err(|e| format!("{e:?}"))?;

    let note_kv = kv(&shared.read_text("funded_note.txt").map_err(|e| format!("{e}"))?);
    let intent_kv = kv(&shared.read_text("intent.txt").map_err(|e| format!("{e}"))?);

    let rho = Rho::from_bytes(&hexn::<32>(&note_kv, "rho")?).into_option().ok_or("rho")?;
    let rseed = RandomSeed::from_bytes(hexn::<32>(&note_kv, "rseed")?, &rho)
        .into_option().ok_or("rseed")?;
    let value: u64 = note_kv["value_zat"].parse().map_err(|e| format!("{e}"))?;
    let honest_note = Note::from_parts(
        orchard::Address::from_raw_address_bytes(&hexn::<43>(&note_kv, "recipient")?)
            .into_option().ok_or("recipient")?,
        NoteValue::from_raw(value),
        rho,
        rseed,
        NoteVersion::V3,
    ).into_option().ok_or("note")?;

    let honest_recipient = orchard::Address::from_raw_address_bytes(
        &hexn::<43>(&intent_kv, "recipient")?,
    ).into_option().ok_or("intent recipient")?;
    let amount: u64 = intent_kv["amount_zat"].parse().map_err(|e| format!("{e}"))?;
    let change: u64 = intent_kv["change_zat"].parse().map_err(|e| format!("{e}"))?;
    let expiry: u32 = intent_kv["expiry_height"].parse().map_err(|e| format!("{e}"))?;
    let target: u32 = intent_kv["target_height"].parse().map_err(|e| format!("{e}"))?;
    let proposal_id: [u8; 32] = hexn(&intent_kv, "proposal_id")?;

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
                .into_option().ok_or("alt rho")?;
            let alt_rseed = RandomSeed::from_bytes(hexn::<32>(&alt, "rseed")?, &alt_rho)
                .into_option().ok_or("alt rseed")?;
            let alt_value: u64 = alt["value_zat"].parse().map_err(|e| format!("{e}"))?;
            if alt_value != value {
                return Err(format!(
                    "the alternate note is {alt_value} zat, not {value}; the tampered \
                     candidate would not balance for an unrelated reason"
                ));
            }
            note = Note::from_parts(
                orchard::Address::from_raw_address_bytes(&hexn::<43>(&alt, "recipient")?)
                    .into_option().ok_or("alt recipient")?,
                NoteValue::from_raw(alt_value),
                alt_rho,
                alt_rseed,
                NoteVersion::V3,
            ).into_option().ok_or("alt note")?;
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
                .read_hex("identifier.hex").map_err(|e| format!("{e}"))?;
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
    let seed = alpha_seed(&proposal_id, (&ids[0], &ids[1]), 0);
    let alpha_bytes: [u8; 32] = alpha_for_candidate(&seed, &commitments)
        .map_err(|e| format!("{e}"))?
        .serialize().as_slice().try_into().map_err(|_| "alpha")?;
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

    let pczt = pczt::roles::creator::Creator::build_from_parts(parts)
        .ok_or("build_from_parts")?;
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
// What the finisher is given is a replica of public artifacts, the kind a relay would
// carry. What it is NOT given: any approver's key package, nonces, scan output or witness.
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
    candidate: Vec<u8>,
    public_package: Vec<u8>,
    ids: [Vec<u8>; 2],
    commitments: [Vec<u8>; 2],
    shares: [Vec<u8>; 2],
    proposal_id: [u8; 32],
    want_nf: [u8; 32],
}

/// Verify the two shares, aggregate, check the group signature under `ak + [alpha]G`, and
/// apply it. Returns the signed PCZT, its effects sighash, and the action index.
fn aggregate_and_apply(i: &AggregateInputs) -> Result<(pczt::Pczt, [u8; 32], usize), String> {
    use loki_poc::intent::alpha_seed;
    use pczt::roles::signer::Signer;

    let public_package = frost::keys::PublicKeyPackage::deserialize(&i.public_package)
        .map_err(|e| format!("public package: {e}"))?;
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

    let mut commitments = BTreeMap::new();
    for (id, raw) in ids.iter().zip(i.commitments.iter()) {
        commitments.insert(
            *id,
            frost::round1::SigningCommitments::deserialize(raw).map_err(|e| format!("{e}"))?,
        );
    }

    // alpha is recomputed from the proposal and the published commitments, not accepted.
    let seed = alpha_seed(&i.proposal_id, (&ids[0], &ids[1]), 0);
    let alpha = loki_poc::intent::alpha_for_candidate(&seed, &commitments)
        .map_err(|e| format!("alpha: {e}"))?;

    let package = frost::SigningPackage::new(commitments, &sighash);
    let mut shares = BTreeMap::new();
    for (id, raw) in ids.iter().zip(i.shares.iter()) {
        shares.insert(
            *id,
            frost::round2::SignatureShare::deserialize(raw).map_err(|e| format!("{e}"))?,
        );
    }

    let params = frost_rerandomized::RandomizedParams::from_randomizer(
        public_package.verifying_key(),
        alpha,
    );
    let group_sig = frost_rerandomized::aggregate(&package, &shares, &public_package, &params)
        .map_err(|e| format!("aggregate: {e}"))?;
    params
        .randomized_verifying_key()
        .verify(&sighash, &group_sig)
        .map_err(|e| format!("the aggregated signature does not verify: {e}"))?;

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
        .position(|a| a.spend().nullifier() == &i.want_nf)
        .ok_or("the candidate does not spend the note the intent names")?;

    let mut signer = Signer::new(pczt).map_err(|e| format!("signer: {e:?}"))?;
    signer
        .apply_ironwood_signature(index, orchard_sig)
        .map_err(|e| format!("apply signature: {e:?}"))?;
    Ok((signer.finish(), sighash, index))
}

/// Install the anchor and witness AFTER signing, prove, extract.
///
/// `position` and `anchor` come from whoever called this; in path B they come from the
/// finisher's own scan. The sighash is re-checked after installation and must be
/// byte-identical, which is the claim the whole v6 path rests on.
fn prove_and_extract(
    signed: pczt::Pczt,
    sighash: &[u8],
    index: usize,
    position: u64,
    cmxs: &[[u8; 32]],
    anchor: [u8; 32],
    label: &str,
) -> Result<(Vec<u8>, String), String> {
    use pczt::roles::{
        prover::Prover, signer::Signer, spend_finalizer::SpendFinalizer,
        tx_extractor::TransactionExtractor, updater::Updater,
    };

    let path = loki_poc::witness::witness_for(cmxs, position, &anchor)?;

    let updated = Updater::new(signed)
        .set_ironwood_anchor(
            orchard::Anchor::from_bytes(anchor)
                .into_option()
                .ok_or("the node's anchor is not a valid Anchor")?,
        )
        .map_err(|e| format!("set anchor: {e:?}"))?
        .set_ironwood_spend_witnesses(vec![(index, path)])
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
    let pk = orchard::circuit::ProvingKey::build(
        orchard::circuit::OrchardCircuitVersion::PostNu6_3,
    );
    let proved = Prover::new(updated)
        .create_ironwood_proof(
            rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng),
            &pk,
        )
        .map_err(|e| format!("prove: {e:?}"))?
        .finish();
    println!("{label}  proof created");

    let finalized = SpendFinalizer::new(proved)
        .finalize_spends()
        .map_err(|e| format!("finalize: {e:?}"))?;
    let vk = orchard::circuit::VerifyingKey::build(
        orchard::circuit::OrchardCircuitVersion::PostNu6_3,
    );
    let tx = TransactionExtractor::new(finalized)
        .with_orchard(&vk)
        .extract(rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng))
        .map_err(|e| format!("extract: {e:?}"))?;

    let mut raw = Vec::new();
    tx.write(&mut raw).map_err(|e| format!("serialize tx: {e}"))?;
    let txid = tx.txid().to_string();
    println!("{label}  extracted v6 transaction {txid} ({} bytes)", raw.len());
    Ok((raw, txid))
}

/// Read the AC aggregate inputs out of a flat replica directory.
fn replica_inputs(r: &MemberDir) -> Result<AggregateInputs, String> {
    let intent_kv = kv(&r.read_text("intent.txt").map_err(|e| format!("{e}"))?);
    let rd = |f: &str| r.read_hex(f).map_err(|e| format!("{f}: {e}"));
    Ok(AggregateInputs {
        candidate: rd("candidate_AC.pczt.hex")?,
        public_package: rd("public_package.hex")?,
        ids: [rd("identifier_alice.hex")?, rd("identifier_carol.hex")?],
        commitments: [rd("commitment_AC_alice.hex")?, rd("commitment_AC_carol.hex")?],
        shares: [rd("share_AC_alice.hex")?, rd("share_AC_carol.hex")?],
        proposal_id: hexn(&intent_kv, "proposal_id")?,
        want_nf: hexn(&intent_kv, "input_nullifier")?,
    })
}

/// Approver-side: produce the final transaction and POST it, without broadcasting.
///
/// This is how path A's input comes to exist: Alice proved the transaction but never got
/// it to a node. Everything after this point is the second device's job.
fn post_final(args: &[String]) -> Result<(), String> {
    let root = PathBuf::from(args.first().ok_or("usage: post-final <state-dir>")?);
    let shared = MemberDir::open(&root, &shared_name());

    let intent_kv = kv(&shared.read_text("intent.txt").map_err(|e| format!("{e}"))?);
    let inputs = AggregateInputs {
        candidate: shared.read_hex("candidate_AC.pczt.hex").map_err(|e| format!("{e}"))?,
        public_package: MemberDir::open(&root, "alice")
            .read_hex("public_package.hex").map_err(|e| format!("{e}"))?,
        ids: [
            MemberDir::open(&root, "alice").read_hex("identifier.hex").map_err(|e| format!("{e}"))?,
            MemberDir::open(&root, "carol").read_hex("identifier.hex").map_err(|e| format!("{e}"))?,
        ],
        commitments: [
            shared.read_hex("commitment_AC_alice.hex").map_err(|e| format!("{e}"))?,
            shared.read_hex("commitment_AC_carol.hex").map_err(|e| format!("{e}"))?,
        ],
        shares: [
            shared.read_hex("share_AC_alice.hex").map_err(|e| format!("{e}"))?,
            shared.read_hex("share_AC_carol.hex").map_err(|e| format!("{e}"))?,
        ],
        proposal_id: hexn(&intent_kv, "proposal_id")?,
        want_nf: hexn(&intent_kv, "input_nullifier")?,
    };

    let (signed, sighash, index) = aggregate_and_apply(&inputs)?;
    println!("AC  aggregated two shares; verifies under ak+alpha");

    let rpc = loki_poc::rpc::Rpc::regtest();
    let ak: [u8; 32] = shared.read_hex("group_ak.hex").map_err(|e| format!("{e}"))?
        .try_into().map_err(|_| "group_ak")?;
    let fvk = vault::test_only_fvk(&ak).map_err(|e| format!("{e:?}"))?;
    let chain = loki_poc::scan::scan_chain(&rpc, &fvk)?;
    let anchor = loki_poc::scan::chain_anchor(&rpc, chain.tip)?;
    let note = chain
        .notes
        .iter()
        .find(|n| n.nullifier == inputs.want_nf)
        .ok_or("the intent's input note is not on this chain")?;

    let (raw, txid) =
        prove_and_extract(signed, &sighash, index, note.position, &chain.cmxs, anchor, "AC")?;

    shared.write_hex("final_tx.hex", &raw).map_err(|e| e.to_string())?;
    shared
        .write_text(
            "final_tx.txt",
            &format!("txid={txid}\nbytes={}\nanchor={}\nbuilt_at_height={}\nbroadcast=no\n",
                raw.len(), hex::encode(anchor), chain.tip),
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
    let root = PathBuf::from(args.first().ok_or("usage: replicate <state-dir> <replica-dir> [--with-final]")?);
    let out = PathBuf::from(args.get(1).ok_or("usage: replicate <state-dir> <replica-dir> [--with-final]")?);
    let with_final = args.iter().any(|a| a == "--with-final");
    let shared = MemberDir::open(&root, &shared_name());

    std::fs::create_dir_all(&out).map_err(|e| format!("{e}"))?;
    let replica = MemberDir::open(out.parent().unwrap_or(&out), out.file_name()
        .and_then(|s| s.to_str()).unwrap_or("replica"));

    // Public group data and the proposal. All of this is designed to be replicated.
    for f in [
        "intent.txt",
        "candidate_AC.pczt.hex",
        "group_ak.hex",
        "commitment_AC_alice.hex",
        "commitment_AC_carol.hex",
        "share_AC_alice.hex",
        "share_AC_carol.hex",
    ] {
        let bytes = std::fs::read(shared.path().join(f))
            .map_err(|e| format!("{f}: {e} (run propose and review-sign first)"))?;
        std::fs::write(replica.path().join(f), bytes).map_err(|e| format!("{f}: {e}"))?;
    }

    // The group's public key package and the two approvers' public identifiers. These are
    // public by construction: the package holds verifying shares, never a key package.
    std::fs::write(
        replica.path().join("public_package.hex"),
        std::fs::read(MemberDir::open(&root, "alice").path().join("public_package.hex"))
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
         # copied (all public, all relay-carried):\n\
         intent.txt\ncandidate_AC.pczt.hex\ngroup_ak.hex\npublic_package.hex\n\
         identifier_alice.hex\nidentifier_carol.hex\n\
         commitment_AC_alice.hex\ncommitment_AC_carol.hex\n\
         share_AC_alice.hex\nshare_AC_carol.hex\n",
    );

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
         #   cmxs.hex                   an approver's commitment stream\n\
         #   anchor.txt                 an approver's anchor\n\
         # The finisher derives the note, its position, the commitment stream and the\n\
         # anchor from its OWN chain scan. That is what makes it a second device rather\n\
         # than a copy of Alice's.\n",
    );
    if !with_final {
        manifest.push_str("#   final_tx.hex               deliberately absent: this is path B\n");
    }
    replica.write_text("MANIFEST.txt", &manifest).map_err(|e| e.to_string())?;

    println!("replica written to {}", out.display());
    println!("  final transaction included: {}", if with_final { "yes (path A)" } else { "no (path B)" });
    println!("  withheld: every key package, every nonce, every approver scan artifact");
    Ok(())
}

/// The second device. Holds no approver file; scans the chain itself.
fn finish_second(args: &[String]) -> Result<(), String> {
    let rdir = PathBuf::from(args.first().ok_or("usage: finish-second <replica-dir> <work-dir>")?);
    let work = PathBuf::from(args.get(1).ok_or("usage: finish-second <replica-dir> <work-dir>")?);
    std::fs::create_dir_all(&work).map_err(|e| format!("{e}"))?;

    let replica = MemberDir::open(
        rdir.parent().unwrap_or(&rdir),
        rdir.file_name().and_then(|s| s.to_str()).unwrap_or("replica"),
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
    for forbidden in ["funded_note.txt", "cmxs.hex", "anchor.txt"] {
        if replica.exists(forbidden) {
            return Err(format!(
                "the replica contains {forbidden}, which is an approver's scan output; \
                 the second device must derive it from the chain"
            ));
        }
    }

    let intent_kv = kv(&replica.read_text("intent.txt").map_err(|e| format!("{e}"))?);
    let want_nf: [u8; 32] = hexn(&intent_kv, "input_nullifier")?;

    // THE TEST-ONLY KEY CONSTRUCTION, stated at the point of use. The vault FVK is a
    // documented splice of the DKG group key into `ak || nk || rivk`, NOT the ZIP 2005
    // `qsk -> qk -> rivk_ext` derivation, which is implemented nowhere. See
    // DEPENDENCIES.md finding B1. Full G1 is BLOCKED on that and nothing here changes it.
    let ak: [u8; 32] = replica.read_hex("group_ak.hex").map_err(|e| format!("{e}"))?
        .try_into().map_err(|_| "group_ak")?;
    let fvk = vault::test_only_fvk(&ak).map_err(|e| format!("{e:?}"))?;
    println!("second device: vault FVK rebuilt from the replicated group ak");
    println!("               TEST-ONLY construction (ak || nk || rivk), not ZIP 2005");

    // ── its own chain scan ──────────────────────────────────────────────────
    let rpc = loki_poc::rpc::Rpc::regtest();
    let chain = loki_poc::scan::scan_chain(&rpc, &fvk)?;
    let anchor = loki_poc::scan::chain_anchor(&rpc, chain.tip)?;
    let note = chain
        .notes
        .iter()
        .find(|n| n.nullifier == want_nf)
        .ok_or("the intent's input note was not found by this device's own scan")?;
    println!(
        "               own scan: {} blocks, {} vault notes, input note at position {}",
        chain.tip,
        chain.notes.len(),
        note.position
    );
    mine.write_text(
        "own_scan.txt",
        &format!(
            "tip={}\nactions={}\nvault_notes={}\ninput_position={}\ninput_value_zat={}\nanchor={}\n",
            chain.tip, chain.cmxs.len(), chain.notes.len(), note.position, note.value_zat,
            hex::encode(anchor),
        ),
    )
    .map_err(|e| e.to_string())?;

    // ── path A or path B ────────────────────────────────────────────────────
    let (raw, txid, path_name) = if replica.exists("final_tx.hex") {
        let raw = replica.read_hex("final_tx.hex").map_err(|e| format!("{e}"))?;

        // A posted transaction is still checked before it is broadcast. The finisher
        // parses it and confirms it spends the note the intent names.
        let tx = zcash_primitives::transaction::Transaction::read(
            &raw[..],
            zcash_protocol::consensus::BranchId::Nu6_3,
        )
        .map_err(|e| format!("the posted final transaction does not parse: {e}"))?;
        let txid = tx.txid().to_string();
        let bundle = tx
            .ironwood_bundle()
            .ok_or("the posted transaction has no Ironwood bundle")?;
        if !bundle.actions().iter().any(|a| a.nullifier().to_bytes() == want_nf) {
            return Err("the posted transaction does not spend the note the intent names".into());
        }
        println!("path A         posted final transaction parsed: {txid}");
        println!("path A         it spends the nullifier the intent names");
        (raw, txid, "A")
    } else {
        println!("path B         no final transaction posted; re-proving the signed candidate");
        let inputs = replica_inputs(&replica)?;
        let (signed, sighash, index) = aggregate_and_apply(&inputs)?;
        println!("path B         aggregated two shares; verifies under ak+alpha");
        let (raw, txid) = prove_and_extract(
            signed, &sighash, index, note.position, &chain.cmxs, anchor, "path B       ",
        )?;
        (raw, txid, "B")
    };

    let sent = rpc.json("sendrawtransaction", &format!("[\"{}\"]", hex::encode(&raw)))?;
    println!("path {path_name}         broadcast: {sent}");

    mine.write_text(
        "finished.txt",
        &format!("path={path_name}\ntxid={txid}\nbroadcast_at_height={}\n", chain.tip),
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

    let rdir = PathBuf::from(args.first().ok_or("usage: verify-effects <replica-dir> <txid>")?);
    let txid = args.get(1).ok_or("usage: verify-effects <replica-dir> <txid>")?;
    let replica = MemberDir::open(
        rdir.parent().unwrap_or(&rdir),
        rdir.file_name().and_then(|s| s.to_str()).unwrap_or("replica"),
    );

    let intent_kv = kv(&replica.read_text("intent.txt").map_err(|e| format!("{e}"))?);
    let want_nf: [u8; 32] = hexn(&intent_kv, "input_nullifier")?;
    let want_recipient: [u8; 43] = hexn(&intent_kv, "recipient")?;
    let want_amount: u64 = intent_kv["amount_zat"].parse().map_err(|e| format!("{e}"))?;
    let want_change: u64 = intent_kv["change_zat"].parse().map_err(|e| format!("{e}"))?;
    let want_fee: u64 = intent_kv["fee_zat"].parse().map_err(|e| format!("{e}"))?;
    let want_memo = hex::decode(&intent_kv["memo"]).map_err(|e| format!("{e}"))?;

    // TEST-ONLY FVK again: spliced from the DKG group ak, not ZIP 2005 derived.
    let ak: [u8; 32] = replica.read_hex("group_ak.hex").map_err(|e| format!("{e}"))?
        .try_into().map_err(|_| "group_ak")?;
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

    let actions = tx["ironwood"]["actions"]
        .as_array()
        .ok_or("the mined transaction has no Ironwood actions")?;

    let mut spent = false;
    let mut paid: Option<u64> = None;
    let mut changed: Option<u64> = None;
    let mut total_out = 0u64;

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
        if raw.nullifier == want_nf {
            spent = true;
        }
        let Some((note, memo)) = ivks
            .iter()
            .find_map(|ivk| loki_poc::scan::try_decrypt_with_memo(ivk, &raw))
        else {
            continue;
        };
        let value = note.value().inner();
        total_out += value;
        let to = note.recipient().to_raw_address_bytes();
        if to == want_recipient {
            // The memo is padded to 512 bytes; compare the prefix the intent named and
            // require the rest to be zero, so a trailing payload cannot hide there.
            if memo[..want_memo.len()] != want_memo[..] || memo[want_memo.len()..].iter().any(|b| *b != 0) {
                return Err(format!(
                    "the payment output's memo is not the approved memo: chain has {}",
                    hex::encode(&memo[..want_memo.len().min(32)])
                ));
            }
            paid = Some(value);
        } else if to == change_addr {
            changed = Some(value);
        } else {
            return Err(format!(
                "the mined transaction pays {value} zat to an address the intent does not name"
            ));
        }
    }

    if !spent {
        return Err(format!("{txid} does not spend the nullifier the intent names"));
    }
    let paid = paid.ok_or("no output to the approved recipient could be decrypted")?;
    let changed = changed.ok_or("no change output to the vault could be decrypted")?;
    if paid != want_amount {
        return Err(format!("paid {paid} zat, intent says {want_amount}"));
    }
    if changed != want_change {
        return Err(format!("change {changed} zat, intent says {want_change}"));
    }

    let note_value: u64 = intent_kv
        .get("input_value_zat")
        .and_then(|v| v.parse().ok())
        .unwrap_or(paid + changed + want_fee);
    let implied_fee = note_value.saturating_sub(total_out);
    if implied_fee != want_fee {
        return Err(format!("implied fee {implied_fee} zat, intent says {want_fee}"));
    }

    println!("effects verified against the chain, not against a local file:");
    println!("  txid            {txid}");
    println!("  mined at height {height}, {conf} confirmation(s)");
    println!("  nullifier spent {}", &hex::encode(want_nf)[..16]);
    println!("  paid            {paid} zat to {}", &hex::encode(want_recipient)[..16]);
    println!("  memo            {:?}", String::from_utf8_lossy(&want_memo));
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
        &carol.read_hex("key_package.hex").map_err(|e| format!("{e}"))?,
    )
    .map_err(|e| format!("key package: {e}"))?;

    let before = shared
        .read_hex("commitment_AC_carol.hex")
        .map_err(|e| format!("run commit and propose first: {e}"))?;

    let mut rng = rand_core::OsRng;
    let (nonces, commitment) = frost::round1::commit(key_package.signing_share(), &mut rng);

    carol
        .write_hex("nonces_AC.hex", &nonces.serialize().map_err(|e| format!("{e}"))?)
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
