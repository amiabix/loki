use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use loki_poc::candidate::{alpha_from_canonical_bytes, build_candidate, quote_fee, CandidateInputs};
use loki_poc::member_state::{self, MemberState};
use loki_poc::signer::local::LocalSigner;
use loki_poc::signer::secure_element::SoftwareSecureElement;
use loki_poc::signer::wysiwys;
use loki_poc::signer::{
    CandidateRef, Network as SignerNetwork, PublicPaymentParams, Session, Signer,
};
use loki_poc::wallet_store::{sync_member_wallet, Lightwalletd};

use orchard::keys::Scope;
use reddsa_frost::frost::redpallas as frost;
use zcash_client_backend::proto::service::{BlockId, Empty, RawTransaction};
use zcash_protocol::consensus::BlockHeight;
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;

const URL: &str = "https://testnet.zec.rocks:443";
const AMOUNT: u64 = 2_000_000;

use loki_poc::tx_finalize::prove;

fn signer_for(
    m: &MemberState,
    nonce_dir: PathBuf,
) -> Result<LocalSigner<SoftwareSecureElement>, String> {
    LocalSigner::with_sealed_share(
        m.identity.public().id,
        m.roster.threshold,
        m.roster.members.len() as u16,
        m.vault,
        "split-payment vault".into(),
        SignerNetwork::Testnet,
        SoftwareSecureElement::generate(),
        &m.key.serialize().map_err(|e| format!("key serialize: {e}"))?,
        m.public.serialize().map_err(|e| format!("public serialize: {e}"))?,
        m.fvk.clone(),
        nonce_dir,
        Box::new(|_view| true),
    )
    .map_err(|e| format!("build signer: {e}"))
}

fn main() {
    if let Err(e) = run() {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let root = std::env::args()
        .nth(1)
        .unwrap_or_else(|| format!("{}/tn-ceremony-state", std::env::var("HOME").unwrap()));
    let root = Path::new(&root);
    let dir1 = root.join("member-1");
    let dir2 = root.join("member-2");
    let pass1 = dir1.join("passphrase");
    let pass2 = dir2.join("passphrase");

    let m1 = member_state::open(&dir1, &pass1, &root.join("roster-1.json"))?;
    let m2 = member_state::open(&dir2, &pass2, &root.join("roster-2.json"))?;
    let pass1s = std::fs::read_to_string(&pass1).map_err(|e| e.to_string())?;
    let pass1s = pass1s.trim_end_matches(['\r', '\n']);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| e.to_string())?;

    let (mut wallet, mut client): (_, Lightwalletd) =
        rt.block_on(sync_member_wallet(&m1, &dir1, pass1s, URL))?;
    let height = wallet
        .scanned_height()?
        .ok_or("wallet has not scanned any blocks")?;
    eprintln!("synced member-1 wallet to height {height}");

    let info = rt
        .block_on(client.get_lightd_info(Empty {}))
        .map_err(|e| format!("lightwalletd info: {e}"))?
        .into_inner();
    if info.block_height != u64::from(height) {
        return Err(format!(
            "wallet scan at {height} is behind lightwalletd tip {}; rerun",
            info.block_height
        ));
    }
    let tree_state = rt
        .block_on(client.get_tree_state(BlockId { height: u64::from(height), hash: vec![] }))
        .map_err(|e| format!("tree state: {e}"))?
        .into_inner();
    if tree_state.network != info.chain_name
        || tree_state.height != u64::from(height)
        || tree_state.hash != wallet.scanned_hash(BlockHeight::from_u32(height))?
    {
        return Err("wallet scan is on a different chain than lightwalletd; rerun".into());
    }
    let tree = tree_state
        .ironwood_tree()
        .map_err(|e| format!("Ironwood tree state: {e}"))?;
    let frontier = tree
        .to_frontier()
        .value()
        .cloned()
        .ok_or("scanned Ironwood tree is empty")?;
    let anchor = tree.root().to_bytes();

    let recipient = m1.fvk.address_at(0u64, Scope::External);
    let memo = MemoBytes::from_bytes(b"loki seam self-send").map_err(|e| format!("memo: {e:?}"))?;
    let amount = Zatoshis::from_u64(AMOUNT).map_err(|e| format!("amount: {e:?}"))?;
    let funding = wallet.propose(recipient, Some(amount), memo.clone())?;
    let notes = funding.notes.clone();
    let nulls: Vec<[u8; 32]> = notes.iter().map(|n| n.nullifier(&m1.fvk).to_bytes()).collect();
    let change = Zatoshis::from_u64(funding.change_zat).map_err(|e| format!("change: {e:?}"))?;
    let params = PublicPaymentParams {
        recipient,
        amount,
        memo: memo.clone(),
        target_height: height,
        expiry_height: height + 40,
    };
    let inputs = CandidateInputs {
        vault_fvk: &m1.fvk,
        notes: notes.clone(),
        recipient,
        amount,
        memo: memo.clone(),
        change,
        target_height: height,
        expiry_height: height + 40,
    };
    if u64::from(quote_fee(&m1.network, &inputs)?) != funding.fee_zat {
        return Err("ZIP-317 fee quote differs from the proposal".into());
    }
    eprintln!(
        "selected {} notes, amount={AMOUNT} fee={} change={}",
        notes.len(), funding.fee_zat, funding.change_zat
    );

    let witnesses_by_null: Vec<([u8; 32], orchard::tree::MerklePath)> = nulls
        .iter()
        .copied()
        .zip(
            wallet
                .ironwood_inputs_at(BlockHeight::from_u32(height), frontier, &nulls)?
                .into_iter()
                .map(|(_, path)| path),
        )
        .collect();

    let nonce_root = std::env::temp_dir().join(format!("loki-split-nonce-{}", std::process::id()));
    let mut s1 = signer_for(&m1, nonce_root.join("m1"))?;
    let mut s2 = signer_for(&m2, nonce_root.join("m2"))?;
    let sess1: Session = s1
        .connect("loki://split", SignerNetwork::Testnet, b"split-payment")
        .map_err(|e| format!("connect m1: {e}"))?
        .session;
    let sess2: Session = s2
        .connect("loki://split", SignerNetwork::Testnet, b"split-payment")
        .map_err(|e| format!("connect m2: {e}"))?
        .session;

    let id1 = *m1.key.identifier();
    let id2 = *m2.key.identifier();
    let payment_id = rand_bytes();

    let cands: Vec<CandidateRef> = (0..notes.len())
        .map(|_| CandidateRef { vault_id: m1.vault, payment_id, attempt_id: rand_bytes() })
        .collect();
    let mut sets: Vec<BTreeMap<frost::Identifier, frost::round1::SigningCommitments>> = Vec::new();
    let mut seeds: Vec<[u8; 32]> = Vec::new();
    let mut alphas = Vec::new();
    for cand in &cands {
        let c1 = s1.sign_commit(&sess1, cand).map_err(|e| format!("sign_commit m1: {e}"))?;
        let c2 = s2.sign_commit(&sess2, cand).map_err(|e| format!("sign_commit m2: {e}"))?;
        let mut set = BTreeMap::new();
        set.insert(id1, c1);
        set.insert(id2, c2);
        let (params, seed) = frost_rerandomized::RandomizedParams::new_from_commitments(
            m1.public.verifying_key(),
            &set,
            rand_core::OsRng,
        )
        .map_err(|e| format!("randomizer: {e}"))?;
        let alpha_bytes: [u8; 32] = params
            .randomizer()
            .serialize()
            .as_slice()
            .try_into()
            .map_err(|_| "alpha length")?;
        alphas.push(alpha_from_canonical_bytes(&alpha_bytes).ok_or("noncanonical alpha")?);
        seeds.push(seed.as_slice().try_into().map_err(|_| "seed length")?);
        sets.push(set);
    }

    let built = build_candidate(
        &m1.network,
        &inputs,
        &alphas,
        rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng),
    )?;
    let pczt = pczt::roles::creator::Creator::build_from_parts(built.pczt_parts)
        .ok_or("create PCZT")?;
    let pczt = pczt::roles::io_finalizer::IoFinalizer::new(pczt)
        .finalize_io()
        .map_err(|e| format!("IO finalizer: {e:?}"))?;
    let pczt_bytes = pczt.serialize().map_err(|e| format!("serialize: {e:?}"))?;
    let sighash = wysiwys::sighash_of_pczt(&pczt_bytes, &m1.fvk)?;

    let parsed = pczt::Pczt::parse(&pczt_bytes).map_err(|e| format!("parse: {e:?}"))?;
    let mut signer_role =
        pczt::roles::signer::Signer::new(parsed.clone()).map_err(|e| format!("signer role: {e:?}"))?;
    for (i, cand) in cands.iter().enumerate() {
        let pkg = frost::SigningPackage::new(sets[i].clone(), &sighash);
        let share1 = s1
            .sign_approve(&sess1, cand, &params, &pczt_bytes, &pkg, &seeds[i])
            .map_err(|e| format!("sign_approve m1 spend {i}: {e}"))?;
        let share2 = s2
            .sign_approve(&sess2, cand, &params, &pczt_bytes, &pkg, &seeds[i])
            .map_err(|e| format!("sign_approve m2 spend {i}: {e}"))?;
        let mut shares = BTreeMap::new();
        shares.insert(id1, share1);
        shares.insert(id2, share2);
        let agg_params =
            frost_rerandomized::RandomizedParams::regenerate_from_seed_and_commitments(
                m1.public.verifying_key(),
                &seeds[i],
                &sets[i],
            )
            .map_err(|e| format!("regenerate randomizer spend {i}: {e}"))?;
        let sig = frost_rerandomized::aggregate(&pkg, &shares, &m1.public, &agg_params)
            .map_err(|e| format!("aggregate spend {i}: {e}"))?;
        agg_params
            .randomized_verifying_key()
            .verify(&sighash, &sig)
            .map_err(|e| format!("aggregate verify spend {i}: {e}"))?;
        let sig_bytes: [u8; 64] = sig
            .serialize()
            .map_err(|e| e.to_string())?
            .as_slice()
            .try_into()
            .map_err(|_| "signature is not 64 bytes")?;
        let orchard_sig = orchard::primitives::redpallas::Signature::<
            orchard::primitives::redpallas::SpendAuth,
        >::from(sig_bytes);
        let index = parsed
            .ironwood()
            .actions()
            .iter()
            .position(|a| a.spend().nullifier() == &nulls[i])
            .ok_or("signed input missing from candidate")?;
        signer_role
            .apply_ironwood_signature(index, orchard_sig)
            .map_err(|e| format!("apply signature spend {i}: {e:?}"))?;
    }
    let signed = signer_role.finish();

    let signed_sighash = pczt::roles::signer::Signer::new(signed.clone())
        .map_err(|e| format!("signed sighash: {e:?}"))?
        .shielded_sighash();
    if signed_sighash != sighash {
        return Err("signed PCZT sighash differs from the approved sighash".into());
    }

    let witnesses = witnesses_by_null
        .into_iter()
        .map(|(nf, path)| {
            let index = parsed
                .ironwood()
                .actions()
                .iter()
                .position(|a| a.spend().nullifier() == &nf)
                .ok_or("witness input missing from candidate")?;
            Ok((index, path))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let (raw, txid) = prove(signed, sighash, witnesses, anchor)?;
    eprintln!("proved txid={txid}");

    let sent = rt
        .block_on(client.send_transaction(RawTransaction { data: raw.clone(), height: 0 }))
        .map_err(|e| format!("send_transaction: {e}"))?
        .into_inner();
    let broadcast_ok = sent.error_code == 0;
    if !broadcast_ok {
        return Err(format!(
            "lightwalletd rejected ({}): {}",
            sent.error_code, sent.error_message
        ));
    }
    eprintln!("broadcast accepted: {}", sent.error_message);

    let mut confirmations: u32 = 0;
    for attempt in 0..8 {
        std::thread::sleep(Duration::from_secs(20));
        let info = rt
            .block_on(client.get_lightd_info(Empty {}))
            .map_err(|e| format!("lightd info: {e}"))?
            .into_inner();
        eprintln!("poll {attempt}: chain tip {}", info.block_height);
        let (w2, _c2): (_, Lightwalletd) =
            rt.block_on(sync_member_wallet(&m1, &dir1, pass1s, URL))?;
        if let Some(h) = w2.mined_height(txid)? {
            let tip = w2.scanned_height()?.unwrap_or(u32::from(h));
            confirmations = tip.saturating_sub(u32::from(h)) + 1;
            eprintln!("mined at height {}, confirmations={confirmations}", u32::from(h));
            if confirmations >= 1 {
                break;
            }
        }
    }

    println!("TXID {txid}");
    println!("CONFIRMATIONS {confirmations}");
    println!("BROADCAST_REAL true");
    if confirmations == 0 {
        return Err("broadcast accepted but not mined within the poll window".into());
    }
    Ok(())
}

fn rand_bytes() -> [u8; 32] {
    let mut b = [0u8; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut b);
    b
}
