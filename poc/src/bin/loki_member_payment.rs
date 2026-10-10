//! Regtest bridge from separately created vaults to the volatile FROST signing session.
//! The shared directory is a local test courier; it is not a wallet relay or durable inbox.

use std::{
    collections::BTreeMap,
    env, fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process, thread,
    time::{Duration, Instant},
};

use loki_poc::{
    candidate::{alpha_from_canonical_bytes, build_candidate, quote_fee, CandidateInputs, Regtest},
    intent::{ChangePolicy, Intent},
    member_state::{self, MemberState},
    rpc::Rpc,
    scan,
    signing_session::{
        aggregate_and_apply, commitments_from_message, AttemptId, Mailbox, MessageKind,
        OpenedMessage, PackagePayload, SessionContext, SigningSession,
    },
    vault,
};
use orchard::{keys::Scope, Address};
use reddsa_frost::frost::redpallas as frost;
use serde_json::{json, Value};
use zcash_protocol::{consensus::Parameters, memo::MemoBytes, value::Zatoshis};
use zeroize::{Zeroize, Zeroizing};

fn hex<const N: usize>(value: &Value, field: &str) -> Result<[u8; N], String> {
    hex::decode(
        value[field]
            .as_str()
            .ok_or_else(|| format!("missing {field}"))?,
    )
    .map_err(|e| format!("{field}: {e}"))?
    .try_into()
    .map_err(|_| format!("{field} must be {N} bytes"))
}

fn bytes(value: &Value, field: &str) -> Result<Vec<u8>, String> {
    hex::decode(
        value[field]
            .as_str()
            .ok_or_else(|| format!("missing {field}"))?,
    )
    .map_err(|e| format!("{field}: {e}"))
}

fn number(value: &Value, field: &str) -> Result<u64, String> {
    value[field]
        .as_u64()
        .ok_or_else(|| format!("missing or invalid {field}"))
}

fn private_work(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let mut builder = fs::DirBuilder::new();
        builder
            .recursive(true)
            .mode(0o700)
            .create(path)
            .map_err(|e| e.to_string())?;
        if fs::metadata(path)
            .map_err(|e| e.to_string())?
            .permissions()
            .mode()
            & 0o077
            != 0
        {
            return Err("payment work directory must be owner-only (mode 0700)".into());
        }
    }
    #[cfg(not(unix))]
    fs::create_dir_all(path).map_err(|e| e.to_string())?;
    Ok(())
}

fn manifest(path: &Path) -> Result<(SessionContext, Intent), String> {
    let value: Value = serde_json::from_slice(&fs::read(path).map_err(|e| e.to_string())?)
        .map_err(|e| format!("manifest: {e}"))?;
    if value["version"] != 1 || value["network"] != "regtest" {
        return Err("unsupported payment manifest".into());
    }
    let notes = value["input_nullifiers"]
        .as_array()
        .ok_or("missing input nullifiers")?
        .iter()
        .map(|entry| hex::<32>(&json!({"nf": entry}), "nf"))
        .collect::<Result<Vec<_>, _>>()?;
    if notes.is_empty() || notes.len() > 8 {
        return Err("payment needs 1 to 8 input notes".into());
    }
    let intent = Intent {
        proposer: bytes(&value, "proposer")?,
        created_height: number(&value, "created_height")?
            .try_into()
            .map_err(|_| "created height overflow")?,
        input_nullifiers: notes,
        recipient: bytes(&value, "recipient")?,
        amount_zat: number(&value, "amount_zat")?,
        memo: bytes(&value, "memo")?,
        change_policy: ChangePolicy::VaultInternal,
        fee_zat: number(&value, "fee_zat")?,
        change_zat: number(&value, "change_zat")?,
        expiry_height: number(&value, "expiry_height")?
            .try_into()
            .map_err(|_| "expiry height overflow")?,
    };
    if value["change_policy"] != "vault_internal"
        || intent.recipient.len() != 43
        || intent.amount_zat == 0
        || intent.memo.is_empty()
        || intent.memo.len() > 512
        || intent.expiry_height <= intent.created_height
    {
        return Err("unsupported payment intent".into());
    }
    let context = SessionContext {
        vault: hex(&value, "vault")?,
        payment: hex(&value, "payment")?,
        attempt: AttemptId(hex(&value, "attempt")?),
        pair: [1, 2],
    };
    context.validate()?;
    if context.payment != intent.proposal_id()
        || intent.proposer != frost::Identifier::try_from(1u16).unwrap().serialize()
    {
        return Err("manifest payment ID or proposer differs from intent".into());
    }
    Ok((context, intent))
}

fn state(args: &[String]) -> Result<(MemberState, PathBuf, Zeroizing<String>), String> {
    if args.len() < 4 {
        return Err("expected <member-dir> <passphrase-file> <roster.json> <work-dir>".into());
    }
    let owner = PathBuf::from(&args[0]);
    let loaded = member_state::open(&owner, Path::new(&args[1]), Path::new(&args[2]))?;
    let mut pass = fs::read_to_string(&args[1]).map_err(|e| e.to_string())?;
    let trimmed = Zeroizing::new(pass.trim_end_matches(['\r', '\n']).to_string());
    pass.zeroize();
    Ok((loaded, owner, trimmed))
}

fn prepare(args: &[String]) -> Result<(), String> {
    if args.len() != 7 {
        return Err("prepare <member-dir> <passphrase-file> <roster.json> <work-dir> <recipient-UA> <amount-zat> <memo>".into());
    }
    let (member, _, _) = state(args)?;
    if member.identity.public().id != 1 {
        return Err("member 1 must prepare this two-signer regtest payment".into());
    }
    let work = Path::new(&args[3]);
    private_work(work)?;
    let rpc = Rpc::regtest();
    let chain = scan::scan_chain(&rpc, &member.fvk)?;
    let tip: u32 = chain.tip.try_into().map_err(|_| "height overflow")?;
    let recipient = vault::orchard_receiver_from_ua(&args[4], Regtest.network_type())?;
    let amount_zat: u64 = args[5].parse().map_err(|_| "invalid amount")?;
    if amount_zat == 0 {
        return Err("amount must exceed zero".into());
    }
    let amount = Zatoshis::from_u64(amount_zat).map_err(|e| format!("amount: {e:?}"))?;
    let memo = MemoBytes::from_bytes(args[6].as_bytes()).map_err(|e| format!("memo: {e:?}"))?;
    if args[6].is_empty() {
        return Err("memo must be nonempty".into());
    }
    let expiry = tip
        .checked_add(8_064)
        .ok_or("expiry overflow")?
        .div_ceil(1_152)
        .checked_mul(1_152)
        .ok_or("expiry overflow")?;
    // shortcut: this bridge selects one fresh covering note; a wallet needs spentness and coin selection.
    let (note, fee_zat, change_zat) = chain
        .notes
        .iter()
        .rev()
        .find_map(|note| {
            let inputs = CandidateInputs {
                vault_fvk: &member.fvk,
                notes: vec![note.note],
                recipient,
                amount,
                memo: memo.clone(),
                change: Zatoshis::ZERO,
                target_height: tip,
                expiry_height: expiry,
            };
            let fee = u64::from(quote_fee(&Regtest, &inputs).ok()?);
            let change = note.value_zat.checked_sub(amount_zat.checked_add(fee)?)?;
            Some((note, fee, change))
        })
        .ok_or("no single vault note covers the amount and fee")?;
    let intent = Intent {
        proposer: member.key.identifier().serialize(),
        created_height: tip,
        input_nullifiers: vec![note.nullifier],
        recipient: recipient.to_raw_address_bytes().to_vec(),
        amount_zat,
        memo: args[6].as_bytes().to_vec(),
        change_policy: ChangePolicy::VaultInternal,
        fee_zat,
        change_zat,
        expiry_height: expiry,
    };
    let payment = intent.proposal_id();
    let attempt = AttemptId::random();
    let value = json!({
        "version": 1, "network": "regtest", "vault": hex::encode(member.vault),
        "payment": hex::encode(payment), "attempt": hex::encode(attempt.0),
        "proposer": hex::encode(&intent.proposer), "created_height": tip,
        "input_nullifiers": intent.input_nullifiers.iter().map(hex::encode).collect::<Vec<_>>(),
        "recipient": hex::encode(&intent.recipient), "amount_zat": amount_zat,
        "memo": hex::encode(&intent.memo), "change_policy": "vault_internal",
        "fee_zat": fee_zat, "change_zat": change_zat, "expiry_height": expiry
    });
    let target = work.join("payment.json");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&target)
        .map_err(|e| format!("{}: {e}", target.display()))?;
    file.write_all(serde_json::to_string_pretty(&value).unwrap().as_bytes())
        .map_err(|e| e.to_string())?;
    file.sync_all().map_err(|e| e.to_string())?;
    println!(
        "payment={} attempt={} amount={} fee={} change={}",
        hex::encode(payment),
        hex::encode(attempt.0),
        amount_zat,
        fee_zat,
        change_zat
    );
    Ok(())
}

fn wait_message(
    mailbox: &Mailbox,
    member: &MemberState,
    context: &SessionContext,
    kind: MessageKind,
    sender: u16,
) -> Result<OpenedMessage, String> {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        if let Some(message) = mailbox
            .read_for(&member.identity, &member.roster.members, context)?
            .into_iter()
            .find(|message| message.kind() == kind && message.sender() == sender)
        {
            return Ok(message);
        }
        if Instant::now() >= deadline {
            return Err(format!("timed out waiting for member {sender} {kind:?}"));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn candidate(
    member: &MemberState,
    intent: &Intent,
    session: &SigningSession,
    peer: Vec<frost::round1::SigningCommitments>,
) -> Result<PackagePayload, String> {
    let rpc = Rpc::regtest();
    let chain = scan::scan_chain(&rpc, &member.fvk)?;
    let notes = intent
        .input_nullifiers
        .iter()
        .map(|nf| {
            chain
                .notes
                .iter()
                .find(|note| note.nullifier == *nf)
                .map(|note| note.note)
                .ok_or_else(|| {
                    format!(
                        "input {} is absent from this member's chain scan",
                        hex::encode(nf)
                    )
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let recipient = Address::from_raw_address_bytes(&intent.recipient.clone().try_into().unwrap())
        .into_option()
        .ok_or("invalid recipient")?;
    let inputs = CandidateInputs {
        vault_fvk: &member.fvk,
        notes,
        recipient,
        amount: Zatoshis::from_u64(intent.amount_zat).map_err(|e| format!("amount: {e:?}"))?,
        memo: MemoBytes::from_bytes(&intent.memo).map_err(|e| format!("memo: {e:?}"))?,
        change: Zatoshis::from_u64(intent.change_zat).map_err(|e| format!("change: {e:?}"))?,
        target_height: intent.created_height,
        expiry_height: intent.expiry_height,
    };
    if u64::from(quote_fee(&Regtest, &inputs)?) != intent.fee_zat {
        return Err("ZIP 317 fee differs from approved intent".into());
    }
    let mut sets = Vec::new();
    let mut seeds = Vec::new();
    let mut alphas = Vec::new();
    for (own, other) in session.commitments().iter().zip(peer) {
        let set = BTreeMap::from([
            (frost::Identifier::try_from(1u16).unwrap(), own.clone()),
            (frost::Identifier::try_from(2u16).unwrap(), other),
        ]);
        let (params, seed) = frost_rerandomized::RandomizedParams::new_from_commitments(
            member.public.verifying_key(),
            &set,
            rand_core::OsRng,
        )
        .map_err(|e| format!("randomizer: {e}"))?;
        let bytes: [u8; 32] = params
            .randomizer()
            .serialize()
            .try_into()
            .map_err(|_| "alpha length")?;
        alphas.push(alpha_from_canonical_bytes(&bytes).ok_or("noncanonical alpha")?);
        seeds.push(seed.try_into().map_err(|_| "seed length")?);
        sets.push(set);
    }
    let built = build_candidate(
        &Regtest,
        &inputs,
        &alphas,
        rand_zp::rand_core::UnwrapErr(rand_zp::rngs::SysRng),
    )?;
    let pczt =
        pczt::roles::creator::Creator::build_from_parts(built.pczt_parts).ok_or("create PCZT")?;
    let pczt = pczt::roles::io_finalizer::IoFinalizer::new(pczt)
        .finalize_io()
        .map_err(|e| format!("IO finalizer: {e:?}"))?;
    Ok(PackagePayload {
        candidate: pczt.serialize().map_err(|e| format!("serialize: {e:?}"))?,
        commitments: sets,
        seeds,
    })
}

fn confirm(
    intent: &Intent,
    summary: &loki_poc::signing_session::ReviewSummary,
) -> Result<(), String> {
    if summary.payment != intent.proposal_id()
        || summary.input_nullifiers != intent.input_nullifiers
    {
        return Err("review summary differs from local intent".into());
    }
    println!("Vault: {}", hex::encode(summary.vault));
    println!(
        "Recipient: {}",
        vault::regtest_unified_receiver(summary.recipient)
    );
    let memo = std::str::from_utf8(&summary.memo).map_err(|_| "memo is not UTF-8")?;
    println!("Amount: {} zat; memo: {memo:?}", summary.amount_zat);
    println!(
        "Fee: {} zat; change to vault: {} zat; expiry height: {}",
        summary.fee_zat, summary.change_zat, summary.expiry_height
    );
    println!(
        "Inputs: {}; candidate: {}",
        summary.input_nullifiers.len(),
        hex::encode(summary.candidate_hash)
    );
    println!("Type APPROVE {} to sign:", hex::encode(summary.payment));
    io::stdout().flush().map_err(|e| e.to_string())?;
    let mut line = String::new();
    io::stdin()
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    if line.trim() != format!("APPROVE {}", hex::encode(summary.payment)) {
        return Err("approval declined or did not match payment ID".into());
    }
    Ok(())
}

fn sign(args: &[String]) -> Result<(), String> {
    if args.len() != 4 {
        return Err("sign <member-dir> <passphrase-file> <roster.json> <work-dir>".into());
    }
    let (member, owner, pass) = state(args)?;
    let own = member.identity.public().id;
    if own != 1 && own != 2 {
        return Err("this attempt selects only members 1 and 2".into());
    }
    let peer_id = if own == 1 { 2 } else { 1 };
    let peer = member.roster.members[&peer_id].clone();
    let finisher = member.roster.members[&3].clone();
    let (context, intent) = manifest(&Path::new(&args[3]).join("payment.json"))?;
    private_work(Path::new(&args[3]))?;
    if context.vault != member.vault {
        return Err("manifest names another vault".into());
    }
    let mailbox = Mailbox::new(&Path::new(&args[3]).join("mailbox")).map_err(|e| e.to_string())?;
    let session_identity =
        loki_poc::setup_transport::Identity::from_secret_bytes(&member.identity.to_secret_bytes())?;
    let mut session = SigningSession::begin(
        &owner.join("signing"),
        context.clone(),
        &member.vault,
        intent.clone(),
        session_identity,
        member.key.clone(),
        member.public.clone(),
        member.fvk.clone(),
        intent.input_nullifiers.len(),
    )?;
    session.publish_commitments(&peer, &mailbox)?;
    let commitment = wait_message(
        &mailbox,
        &member,
        &context,
        MessageKind::Commitment,
        peer_id,
    )?;
    let peer_commitments =
        commitments_from_message(&context, &commitment, intent.input_nullifiers.len())?;
    let package_message = if own == 1 {
        let payload = candidate(&member, &intent, &session, peer_commitments)?;
        session.publish_package_to_roster(&member.roster.members, &payload, &mailbox, &pass)?;
        let wires =
            SigningSession::saved_package_wires(&owner.join("signing"), &context, own, &pass)?;
        member
            .identity
            .open_sent_session(&peer, &context, &wires[0])?
    } else {
        wait_message(&mailbox, &member, &context, MessageKind::Package, 1)?
    };
    let reviewed = session.review_package(&package_message, &peer)?;
    confirm(&intent, reviewed.summary())?;
    session.publish_approved(reviewed, &peer, &finisher, &mailbox, &pass)?;
    println!(
        "approved payment {} as member {}",
        hex::encode(context.payment),
        own
    );
    Ok(())
}

fn resend(args: &[String]) -> Result<(), String> {
    if args.len() != 4 {
        return Err("resend <member-dir> <passphrase-file> <roster.json> <work-dir>".into());
    }
    let (member, owner, pass) = state(args)?;
    let own = member.identity.public().id;
    if own != 1 && own != 2 {
        return Err("only a selected signer can resend".into());
    }
    let work = Path::new(&args[3]);
    private_work(work)?;
    let (context, _) = manifest(&work.join("payment.json"))?;
    if context.vault != member.vault {
        return Err("manifest names another vault".into());
    }
    let mailbox = Mailbox::new(&work.join("mailbox")).map_err(|e| e.to_string())?;
    let root = owner.join("signing");
    if own == 1 {
        for wire in SigningSession::saved_package_wires(&root, &context, own, &pass)? {
            mailbox.append(&wire).map_err(|e| e.to_string())?;
        }
    }
    SigningSession::recover_share(&root, &context, own, &pass, &mailbox)?;
    println!(
        "resent exact saved approval for payment {}",
        hex::encode(context.payment)
    );
    Ok(())
}

fn prove(
    signed: pczt::Pczt,
    sighash: [u8; 32],
    positions: &[(usize, u64)],
    cmxs: &[[u8; 32]],
    anchor: [u8; 32],
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
                .ok_or("invalid chain anchor")?,
        )
        .map_err(|e| format!("anchor: {e:?}"))?
        .set_ironwood_spend_witnesses(witnesses)
        .map_err(|e| format!("witness: {e:?}"))?
        .finish();
    if Signer::new(updated.clone())
        .map_err(|e| format!("sighash: {e:?}"))?
        .shielded_sighash()
        != sighash
    {
        return Err("anchor or witnesses changed the approved transaction effects".into());
    }
    let pk =
        orchard::circuit::ProvingKey::build(orchard::circuit::OrchardCircuitVersion::PostNu6_3);
    let proved = Prover::new(updated)
        .create_ironwood_proof(&pk)
        .map_err(|e| format!("proof: {e:?}"))?
        .finish();
    let finalized = SpendFinalizer::new(proved)
        .finalize_spends()
        .map_err(|e| format!("spend finalizer: {e:?}"))?;
    let vk =
        orchard::circuit::VerifyingKey::build(orchard::circuit::OrchardCircuitVersion::PostNu6_3);
    let tx = TransactionExtractor::new(finalized)
        .with_orchard(&vk)
        .extract()
        .map_err(|e| format!("extract transaction: {e:?}"))?;
    let mut raw = Vec::new();
    tx.write(&mut raw)
        .map_err(|e| format!("serialize transaction: {e}"))?;
    Ok((raw, tx.txid().to_string()))
}

fn finish(args: &[String]) -> Result<(), String> {
    if args.len() != 4 {
        return Err("finish <member-dir> <passphrase-file> <roster.json> <work-dir>".into());
    }
    let (member, _, _) = state(args)?;
    if member.identity.public().id != 3 {
        return Err("this attempt requires member 3 as the independent finisher".into());
    }
    let work = Path::new(&args[3]);
    private_work(work)?;
    let (context, intent) = manifest(&work.join("payment.json"))?;
    if context.vault != member.vault {
        return Err("manifest names another vault".into());
    }
    let mailbox = Mailbox::new(&work.join("mailbox")).map_err(|e| e.to_string())?;
    let package = wait_message(&mailbox, &member, &context, MessageKind::Package, 1)?;
    let payload = PackagePayload::decode(&context, package.body())?;
    let alice_share = wait_message(&mailbox, &member, &context, MessageKind::Share, 1)?;
    let bob_share = wait_message(&mailbox, &member, &context, MessageKind::Share, 2)?;
    let (signed, sighash, indices) = aggregate_and_apply(
        &context,
        &intent,
        &member.vault,
        &member.public,
        &member.fvk,
        &payload,
        &[alice_share, bob_share],
    )?;
    let rpc = Rpc::regtest();
    let chain = scan::scan_chain(&rpc, &member.fvk)?;
    let positions = indices
        .into_iter()
        .zip(&intent.input_nullifiers)
        .map(|(index, nf)| {
            let note = chain
                .notes
                .iter()
                .find(|note| note.nullifier == *nf)
                .ok_or_else(|| format!("finisher cannot find input {}", hex::encode(nf)))?;
            Ok((index, note.position))
        })
        .collect::<Result<Vec<_>, String>>()?;
    let anchor = scan::chain_anchor(&rpc, chain.tip)?;
    let (raw, txid) = prove(signed, sighash, &positions, &chain.cmxs, anchor)?;
    let sent = rpc.json(
        "sendrawtransaction",
        &format!("[\"{}\"]", hex::encode(&raw)),
    )?;
    if sent.as_str() != Some(&txid) {
        return Err(format!("node returned a different txid: {sent}"));
    }
    fs::write(work.join("final.hex"), hex::encode(&raw)).map_err(|e| e.to_string())?;
    println!(
        "broadcast txid={txid} payment={}",
        hex::encode(context.payment)
    );
    Ok(())
}

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
        return Err("mined transaction uses an unexpected pool".into());
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

fn verify(args: &[String]) -> Result<(), String> {
    if args.len() != 5 {
        return Err("verify <member-dir> <passphrase-file> <roster.json> <work-dir> <txid>".into());
    }
    let (member, _, _) = state(args)?;
    let work = Path::new(&args[3]);
    private_work(work)?;
    let txid = &args[4];
    if txid.len() != 64 || !txid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("txid must be 32 hexadecimal bytes".into());
    }
    let (context, intent) = manifest(&work.join("payment.json"))?;
    if context.vault != member.vault {
        return Err("manifest names another vault".into());
    }
    let rpc = Rpc::regtest();
    let tx_json = rpc.json("getrawtransaction", &format!("[\"{txid}\",1]"))?;
    let confirmations = tx_json["confirmations"].as_u64().unwrap_or(0);
    if confirmations < 1 {
        return Err("transaction is not mined".into());
    }
    let raw_hex = rpc.json("getrawtransaction", &format!("[\"{txid}\",0]"))?;
    let raw = hex::decode(
        raw_hex
            .as_str()
            .ok_or("node returned no transaction bytes")?,
    )
    .map_err(|e| e.to_string())?;
    let tx = zcash_primitives::transaction::Transaction::read(
        &raw[..],
        zcash_protocol::consensus::BranchId::Nu6_3,
    )
    .map_err(|e| format!("mined transaction parse: {e}"))?;
    if tx.txid().to_string() != *txid {
        return Err("mined transaction ID mismatch".into());
    }
    let mailbox = Mailbox::new(&work.join("mailbox")).map_err(|e| e.to_string())?;
    let package_message = wait_message(&mailbox, &member, &context, MessageKind::Package, 1)?;
    let payload = PackagePayload::decode(&context, package_message.body())?;
    let pczt =
        pczt::Pczt::parse(&payload.candidate).map_err(|e| format!("candidate parse: {e:?}"))?;
    let expected = loki_poc::verify::Expectations {
        input_nullifiers: intent.input_nullifiers.clone(),
        recipient: intent.recipient.clone().try_into().unwrap(),
        amount_zat: intent.amount_zat,
        memo: intent.memo.clone(),
        change_zat: intent.change_zat,
        fee_zat: intent.fee_zat,
        expiry_height: intent.expiry_height,
    };
    let checked = pczt::roles::verifier::Verifier::new(pczt)
        .with_ironwood::<loki_poc::verify::Refusal, _>(|bundle| {
            loki_poc::verify::check_candidate(bundle, &member.fvk, &expected)
                .map_err(pczt::roles::verifier::OrchardError::Custom)
        })
        .map_err(|e| format!("candidate verification: {e:?}"))?
        .finish();
    let approved_sighash = pczt::roles::signer::Signer::new(checked)
        .map_err(|e| format!("candidate sighash: {e:?}"))?
        .shielded_sighash();
    if finalized_sighash(&tx)? != approved_sighash {
        return Err("mined transaction effects differ from approved candidate".into());
    }
    let bundle = tx
        .ironwood_bundle()
        .ok_or("mined transaction has no Ironwood bundle")?;
    let actual_nfs = bundle
        .actions()
        .iter()
        .map(|a| a.nullifier().to_bytes())
        .collect::<Vec<_>>();
    if intent
        .input_nullifiers
        .iter()
        .any(|nf| !actual_nfs.contains(nf))
    {
        return Err("mined inputs differ from approved intent".into());
    }
    let fee: u64 = (*bundle.value_balance())
        .try_into()
        .map_err(|_| "invalid mined fee")?;
    if fee != intent.fee_zat {
        return Err("mined fee differs from approved intent".into());
    }
    let change_addr = member
        .fvk
        .address_at(0u64, Scope::Internal)
        .to_raw_address_bytes();
    let mut paid = None;
    let mut changed = None;
    let ivks = scan::vault_ivks(&member.fvk);
    let actions = tx_json["ironwood"]["actions"]
        .as_array()
        .ok_or("no mined Ironwood actions")?;
    for raw in scan::parse_actions(actions, txid)? {
        let Some((note, memo)) = ivks
            .iter()
            .find_map(|ivk| scan::try_decrypt_with_memo(ivk, &raw))
        else {
            continue;
        };
        let value = note.value().inner();
        let to = note.recipient().to_raw_address_bytes();
        if to == intent.recipient.as_slice() {
            if memo[..intent.memo.len()] != intent.memo
                || memo[intent.memo.len()..].iter().any(|byte| *byte != 0)
            {
                return Err("mined memo differs from approved intent".into());
            }
            if paid.replace(value).is_some() {
                return Err("duplicate payment output".into());
            }
        } else if to == change_addr {
            if changed.replace(value).is_some() {
                return Err("duplicate change output".into());
            }
        } else {
            return Err("mined transaction has an unexpected output".into());
        }
    }
    let self_payment = intent.recipient
        == member
            .fvk
            .address_at(0u64, Scope::External)
            .to_raw_address_bytes();
    if changed != Some(intent.change_zat)
        || paid.is_some_and(|value| value != intent.amount_zat)
        || (self_payment && paid != Some(intent.amount_zat))
    {
        return Err("mined amount or change differs from approved intent".into());
    }
    println!(
        "verified mined txid={txid} confirmations={confirmations} amount={} fee={} change={} recipient_evidence={}",
        intent.amount_zat, fee, intent.change_zat,
        if paid.is_some() { "decrypted" } else { "candidate-opening-and-mined-sighash" }
    );
    Ok(())
}

fn receive(args: &[String]) -> Result<(), String> {
    if args.len() != 5 {
        return Err("receive <recipient-member-dir> <passphrase-file> <roster.json> <payment-work-dir> <txid>".into());
    }
    let (recipient, _, _) = state(args)?;
    let (_, intent) = manifest(&Path::new(&args[3]).join("payment.json"))?;
    let txid = &args[4];
    if txid.len() != 64 || !txid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("txid must be 32 hexadecimal bytes".into());
    }
    if recipient
        .fvk
        .address_at(0u64, Scope::External)
        .to_raw_address_bytes()
        .as_slice()
        != intent.recipient.as_slice()
    {
        return Err("this member does not control the payment recipient".into());
    }
    let rpc = Rpc::regtest();
    let tx = rpc.json("getrawtransaction", &format!("[\"{txid}\",1]"))?;
    let confirmations = tx["confirmations"].as_u64().unwrap_or(0);
    if confirmations < 1 {
        return Err("recipient payment is not mined".into());
    }
    let ivks = scan::vault_ivks(&recipient.fvk);
    let mut found = 0;
    let actions = tx["ironwood"]["actions"]
        .as_array()
        .ok_or("no mined Ironwood actions")?;
    for raw in scan::parse_actions(actions, txid)? {
        for ivk in &ivks {
            if let Some((note, memo)) = scan::try_decrypt_with_memo(ivk, &raw) {
                if note.recipient().to_raw_address_bytes().as_slice() == intent.recipient.as_slice()
                    && note.value().inner() == intent.amount_zat
                    && memo[..intent.memo.len()] == intent.memo
                    && memo[intent.memo.len()..].iter().all(|byte| *byte == 0)
                {
                    found += 1;
                }
            }
        }
    }
    if found != 1 {
        return Err(format!(
            "recipient decrypted {found} matching outputs, expected one"
        ));
    }
    println!(
        "recipient independently decrypted txid={txid} amount={} confirmations={confirmations}",
        intent.amount_zat
    );
    Ok(())
}

fn main() {
    let args = env::args().collect::<Vec<_>>();
    let result = match args.get(1).map(String::as_str) {
        Some("prepare") => prepare(&args[2..]),
        Some("sign") => sign(&args[2..]),
        Some("resend") => resend(&args[2..]),
        Some("finish") => finish(&args[2..]),
        Some("verify") => verify(&args[2..]),
        Some("receive") => receive(&args[2..]),
        _ => Err(
            "loki_member_payment <prepare|sign|resend|finish|verify|receive> ... (regtest only)"
                .into(),
        ),
    };
    if let Err(error) = result {
        eprintln!("error: {error}");
        process::exit(1);
    }
}
