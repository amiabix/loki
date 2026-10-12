//! Regtest bridge from separately created vaults to the volatile FROST signing session.
//! File mode uses a local test mailbox; relay mode stores sealed signing carriers.

use std::{
    collections::BTreeMap,
    env, fs,
    io::{self, Write},
    path::{Path, PathBuf},
    process,
    sync::mpsc,
    thread,
    time::{Duration, Instant},
};

#[cfg(feature = "relay-communication")]
use loki_poc::signing_session::NonceWitness;
use loki_poc::{
    candidate::{alpha_from_canonical_bytes, build_candidate, quote_fee, CandidateInputs, Regtest},
    intent::{ChangePolicy, Intent},
    member_state::{self, MemberState, Roster},
    rpc::Rpc,
    scan,
    signing_session::{
        aggregate_and_apply, commitments_from_message, AttemptId, EnvelopeRoute, FileCourier,
        Mailbox, MessageKind, OpenedMessage, PackagePayload, SessionContext, SessionCourier,
        SigningSession,
    },
    vault,
};
#[cfg(feature = "relay-communication")]
use loki_relay_client::{ClientStore, OwnerInbox, RelayHttp, RelayRuntime};
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

#[derive(Clone, Copy)]
enum TransportMode {
    File,
    Relay,
}

struct ExportFds {
    observe: i32,
    control: i32,
    response: i32,
}

fn split_transport(
    args: &[String],
) -> Result<(Vec<String>, TransportMode, Option<ExportFds>), String> {
    let mut positional = Vec::new();
    let mut mode = TransportMode::File;
    let mut seen = false;
    let mut observe = None;
    let mut control = None;
    let mut response = None;
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        if arg == "--transport" {
            if seen {
                return Err("transport selected more than once".into());
            }
            seen = true;
            let value = args.next().ok_or("missing transport value")?;
            mode = match value.as_str() {
                "file" => TransportMode::File,
                "relay" => TransportMode::Relay,
                _ => return Err("transport must be file or relay".into()),
            };
        } else if matches!(
            arg.as_str(),
            "--observe-fd" | "--control-fd" | "--response-fd"
        ) {
            let value = args.next().ok_or("missing export descriptor")?;
            let fd: i32 = value
                .parse()
                .map_err(|_| "export descriptor must be an integer")?;
            if fd < 0 {
                return Err("export descriptor must be an integer".into());
            }
            let slot = match arg.as_str() {
                "--observe-fd" => &mut observe,
                "--control-fd" => &mut control,
                _ => &mut response,
            };
            if slot.is_some() {
                return Err("export descriptor selected more than once".into());
            }
            *slot = Some(fd);
        } else if arg.starts_with("--") {
            return Err(format!("unknown option {arg}"));
        } else {
            positional.push(arg.clone());
        }
    }
    let export = match (observe, control, response) {
        (None, None, None) => None,
        (Some(observe), Some(control), Some(response)) => Some(ExportFds {
            observe,
            control,
            response,
        }),
        _ => return Err("export descriptors must include observe, control, and response".into()),
    };
    Ok((positional, mode, export))
}

fn wait_limit(mode: TransportMode) -> Duration {
    match mode {
        TransportMode::File => Duration::from_secs(120),
        TransportMode::Relay => Duration::from_secs(300),
    }
}

enum OwnedCourier {
    File(Mailbox),
    #[cfg(feature = "relay-communication")]
    Relay(loki_poc::relay_courier::RelayCourier),
}

impl SessionCourier for OwnedCourier {
    fn publish(&mut self, route: &EnvelopeRoute<'_>, wire: &[u8]) -> Result<[u8; 32], String> {
        match self {
            Self::File(mailbox) => FileCourier(mailbox).publish(route, wire),
            #[cfg(feature = "relay-communication")]
            Self::Relay(courier) => courier.publish(route, wire),
        }
    }

    fn receive(
        &mut self,
        own: &loki_poc::setup_transport::Identity,
        roster: &BTreeMap<u16, loki_poc::setup_transport::PublicIdentity>,
        context: &SessionContext,
        kind: MessageKind,
        sender: u16,
    ) -> Result<Option<OpenedMessage>, String> {
        match self {
            Self::File(mailbox) => FileCourier(mailbox).receive(own, roster, context, kind, sender),
            #[cfg(feature = "relay-communication")]
            Self::Relay(courier) => courier.receive(own, roster, context, kind, sender),
        }
    }

    fn drive_once(&mut self) -> Result<(), String> {
        match self {
            Self::File(mailbox) => FileCourier(mailbox).drive_once(),
            #[cfg(feature = "relay-communication")]
            Self::Relay(courier) => courier.drive_once(),
        }
    }
}

impl OwnedCourier {
    /// Read a carrier that signing already accepted. File mode has no accepted set.
    /// Relay mode reopens the saved envelope and does not treat it as a new delivery.
    fn reopen_accepted(
        &mut self,
        own: &loki_poc::setup_transport::Identity,
        roster: &BTreeMap<u16, loki_poc::setup_transport::PublicIdentity>,
        context: &SessionContext,
        kind: MessageKind,
        sender: u16,
    ) -> Result<Option<OpenedMessage>, String> {
        match self {
            Self::File(mailbox) => FileCourier(mailbox).receive(own, roster, context, kind, sender),
            #[cfg(feature = "relay-communication")]
            Self::Relay(courier) => courier.reopen_accepted(own, roster, context, kind, sender),
        }
    }

    fn note_application(&mut self, accepted: bool, message: &OpenedMessage) {
        #[cfg(feature = "relay-communication")]
        if let Self::Relay(courier) = self {
            courier.note_application(accepted, message);
            return;
        }
        let _ = (accepted, message);
    }

    fn note_approved(&mut self, context: &SessionContext, member: u16, envelope_hash: [u8; 32]) {
        #[cfg(feature = "relay-communication")]
        if let Self::Relay(courier) = self {
            courier.note_approved(context, member, envelope_hash);
            return;
        }
        let _ = (context, member, envelope_hash);
    }
}

fn open_courier(
    mode: TransportMode,
    member: &Path,
    pass_file: &Path,
    roster: &Path,
    work: &Path,
    export: Option<ExportFds>,
) -> Result<OwnedCourier, String> {
    match mode {
        TransportMode::File => {
            let _ = export;
            Ok(OwnedCourier::File(
                Mailbox::new(&work.join("mailbox")).map_err(|error| error.to_string())?,
            ))
        }
        TransportMode::Relay => {
            if work.join("mailbox").exists() {
                return Err("relay mode refuses an existing file mailbox".into());
            }
            #[cfg(feature = "relay-communication")]
            {
                loki_poc::relay_courier::reserve_attempt(
                    8 * 1024 * 1024 + 53,
                    loki_poc::relay_courier::demo_quotas(),
                )?;
                let mut courier =
                    loki_poc::relay_courier::RelayCourier::open(member, pass_file, roster)?;
                if let Some(export) = export {
                    courier.attach_inherited(export.observe, export.control, export.response)?;
                }
                return Ok(OwnedCourier::Relay(courier));
            }
            #[cfg(not(feature = "relay-communication"))]
            {
                let _ = (member, pass_file, roster, export);
                Err("relay transport requires the relay-communication feature".into())
            }
        }
    }
}

fn settle_delivery(courier: &mut OwnedCourier, work: &Path) -> Result<(), String> {
    #[cfg(not(feature = "relay-communication"))]
    {
        let _ = (courier, work);
        return Ok(());
    }
    #[cfg(feature = "relay-communication")]
    {
        let OwnedCourier::Relay(relay) = courier else {
            return Ok(());
        };
        match relay.settle_until_stored(work, Instant::now() + Duration::from_secs(300)) {
            Ok(()) => {
                println!("stored");
                Ok(())
            }
            Err(error) => {
                if error == "delivery_pending" {
                    println!("delivery_pending");
                }
                Err(error)
            }
        }
    }
}

fn pair_from_name(name: &str) -> Result<[u16; 2], String> {
    match name {
        "AB" => Ok([1, 2]),
        "AC" => Ok([1, 3]),
        "AD" => Ok([1, 4]),
        "BC" => Ok([2, 3]),
        "BD" => Ok([2, 4]),
        "CD" => Ok([3, 4]),
        _ => Err("pair must be AB, AC, AD, BC, BD, or CD".into()),
    }
}

fn manifest_pair(value: &Value) -> Result<[u16; 2], String> {
    let Some(pair) = value.get("pair") else {
        return Ok([1, 2]); // Existing regtest manifests predate pair selection.
    };
    let ids = pair
        .as_array()
        .ok_or("payment pair must contain two member IDs")?;
    if ids.len() != 2 {
        return Err("payment pair must contain two member IDs".into());
    }
    let first = ids[0].as_u64().ok_or("invalid payment pair")?;
    let second = ids[1].as_u64().ok_or("invalid payment pair")?;
    let pair = [
        u16::try_from(first).map_err(|_| "invalid payment pair")?,
        u16::try_from(second).map_err(|_| "invalid payment pair")?,
    ];
    if pair[0] < 1 || pair[1] > 4 || pair[0] >= pair[1] {
        return Err("payment pair must be a supported sorted pair".into());
    }
    Ok(pair)
}

fn peer_in_pair(pair: [u16; 2], own: u16) -> Option<u16> {
    if own == pair[0] {
        Some(pair[1])
    } else if own == pair[1] {
        Some(pair[0])
    } else {
        None
    }
}

fn proposer_id(bytes: &[u8]) -> Result<u16, String> {
    (1u16..=4)
        .find(|id| frost::Identifier::try_from(*id).is_ok_and(|member| member.serialize() == bytes))
        .ok_or_else(|| "payment proposer is not a vault member".into())
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
        pair: manifest_pair(&value)?,
    };
    context.validate()?;
    if context.payment != intent.proposal_id() {
        return Err("manifest payment ID differs from intent".into());
    }
    proposer_id(&intent.proposer)?;
    Ok((context, intent))
}

fn check_manifest_roster(
    roster: &Roster,
    context: &SessionContext,
    intent: &Intent,
) -> Result<(), String> {
    if context.vault != roster.vault {
        return Err("manifest names another vault".into());
    }
    if context
        .pair
        .iter()
        .any(|id| !roster.members.contains_key(id))
    {
        return Err("payment pair includes a member outside this vault".into());
    }
    if !roster.members.contains_key(&proposer_id(&intent.proposer)?) {
        return Err("payment proposer is not a vault member".into());
    }
    Ok(())
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

fn balance(args: &[String]) -> Result<(), String> {
    if args.len() != 3 {
        return Err("balance <member-dir> <passphrase-file> <roster.json>".into());
    }
    let member = member_state::open(
        Path::new(&args[0]),
        Path::new(&args[1]),
        Path::new(&args[2]),
    )?;
    let chain = scan::scan_chain(&Rpc::regtest(), &member.fvk)?;
    let balance_zat = chain
        .notes
        .iter()
        .try_fold(0u64, |sum, note| sum.checked_add(note.value_zat))
        .ok_or("vault balance exceeds u64")?;
    println!(
        "{}",
        json!({"vault": hex::encode(member.vault), "height": chain.tip,
               "balance_zat": balance_zat, "unspent_notes": chain.notes.len()})
    );
    Ok(())
}

fn prepare(args: &[String]) -> Result<(), String> {
    if args.len() != 7 && args.len() != 8 {
        return Err("prepare <member-dir> <passphrase-file> <roster.json> <work-dir> <recipient-UA> <amount-zat> <memo> [AB|AC|AD|BC|BD|CD]".into());
    }
    let pair = pair_from_name(args.get(7).map(String::as_str).unwrap_or("AB"))?;
    let (member, _, _) = state(args)?;
    if pair
        .iter()
        .any(|id| !member.roster.members.contains_key(id))
    {
        return Err("payment pair includes a member outside this vault".into());
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
        "payment": hex::encode(payment), "attempt": hex::encode(attempt.0), "pair": pair,
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
    courier: &mut dyn SessionCourier,
    member: &MemberState,
    context: &SessionContext,
    kind: MessageKind,
    sender: u16,
    work: &Path,
    timeout: Duration,
) -> Result<OpenedMessage, String> {
    let deadline = Instant::now() + timeout;
    loop {
        if work.join("cancel").is_file() {
            return Err("cancelled".into());
        }
        courier.drive_once()?;
        if let Some(message) = courier.receive(
            &member.identity,
            &member.roster.members,
            context,
            kind,
            sender,
        )? {
            return Ok(message);
        }
        if Instant::now() >= deadline {
            return Err(format!("timed out waiting for member {sender} {kind:?}"));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn wait_reopened(
    courier: &mut OwnedCourier,
    member: &MemberState,
    context: &SessionContext,
    kind: MessageKind,
    sender: u16,
    work: &Path,
    timeout: Duration,
) -> Result<OpenedMessage, String> {
    let deadline = Instant::now() + timeout;
    loop {
        if work.join("cancel").is_file() {
            return Err("cancelled".into());
        }
        if let Some(message) = courier.reopen_accepted(
            &member.identity,
            &member.roster.members,
            context,
            kind,
            sender,
        )? {
            return Ok(message);
        }
        courier.drive_once()?;
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
    pair: [u16; 2],
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
            (frost::Identifier::try_from(pair[0]).unwrap(), own.clone()),
            (frost::Identifier::try_from(pair[1]).unwrap(), other),
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
    courier: &mut dyn SessionCourier,
    work: &Path,
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
    let expected = format!("APPROVE {}", hex::encode(summary.payment));
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut line = String::new();
        let _ = io::stdin().read_line(&mut line);
        let _ = sender.send(line);
    });
    let line = loop {
        if work.join("cancel").is_file() {
            return Err("cancelled".into());
        }
        match receiver.try_recv() {
            Ok(line) => break line,
            Err(mpsc::TryRecvError::Empty) => {
                courier.drive_once()?;
                thread::sleep(Duration::from_millis(50));
            }
            Err(mpsc::TryRecvError::Disconnected) => {
                return Err("approval input closed".into());
            }
        }
    };
    if line.trim() != expected {
        return Err("approval declined or did not match payment ID".into());
    }
    Ok(())
}

fn sign(args: &[String]) -> Result<(), String> {
    let (args, mode, export) = split_transport(args)?;
    if args.len() != 4 {
        return Err(
            "sign <member-dir> <passphrase-file> <roster.json> <work-dir> [--transport file|relay]"
                .into(),
        );
    }
    let (member, owner, pass) = state(&args)?;
    let own = member.identity.public().id;
    let work = PathBuf::from(&args[3]);
    let (context, intent) = manifest(&work.join("payment.json"))?;
    check_manifest_roster(&member.roster, &context, &intent)?;
    let peer_id =
        peer_in_pair(context.pair, own).ok_or("member is not in the selected payment pair")?;
    let peer = member
        .roster
        .members
        .get(&peer_id)
        .ok_or("payment pair outside vault")?
        .clone();
    let finishers = member
        .roster
        .members
        .values()
        .filter(|person| !context.pair.contains(&person.id))
        .cloned()
        .collect::<Vec<_>>();
    if !matches!(finishers.len(), 1 | 2) {
        return Err("payment roster has no supported finisher set".into());
    }
    private_work(&work)?;
    let mut courier = open_courier(
        mode,
        &owner,
        Path::new(&args[1]),
        Path::new(&args[2]),
        &work,
        export,
    )?;
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
    session.publish_commitments_with_courier(&peer, &mut courier, &pass)?;
    let commitment = wait_message(
        &mut courier,
        &member,
        &context,
        MessageKind::Commitment,
        peer_id,
        &work,
        wait_limit(mode),
    )?;
    let peer_commitments =
        match commitments_from_message(&context, &commitment, intent.input_nullifiers.len()) {
            Ok(parsed) => {
                courier.note_application(true, &commitment);
                parsed
            }
            Err(error) => {
                courier.note_application(false, &commitment);
                return Err(error);
            }
        };
    let package_message = if own == context.pair[0] {
        let payload = candidate(&member, &intent, &session, context.pair, peer_commitments)?;
        session.publish_package_to_roster_with_courier(
            &member.roster.members,
            &payload,
            &mut courier,
            &pass,
        )?;
        let wires =
            SigningSession::saved_package_wires(&owner.join("signing"), &context, own, &pass)?;
        member
            .identity
            .open_sent_session(&peer, &context, &wires[0])?
    } else {
        wait_message(
            &mut courier,
            &member,
            &context,
            MessageKind::Package,
            context.pair[0],
            &work,
            wait_limit(mode),
        )?
    };
    let reviewed = match session.review_package(&package_message, &peer) {
        Ok(reviewed) => {
            courier.note_application(true, &package_message);
            reviewed
        }
        Err(error) => {
            courier.note_application(false, &package_message);
            return Err(error);
        }
    };
    confirm(&intent, reviewed.summary(), &mut courier, &work)?;
    let released =
        session.publish_approved_with_courier(reviewed, &peer, &finishers, &mut courier, &pass)?;
    courier.note_approved(&context, own, released);
    println!(
        "approved payment {} as member {}",
        hex::encode(context.payment),
        own
    );
    settle_delivery(&mut courier, &work)?;
    Ok(())
}

#[cfg(feature = "relay-communication")]
fn signing_inputs(
    args: &[String],
) -> Result<
    (
        MemberState,
        PathBuf,
        Zeroizing<String>,
        SessionContext,
        Intent,
        Mailbox,
    ),
    String,
> {
    if args.len() != 4 {
        return Err("<member-dir> <passphrase-file> <roster.json> <work-dir>".into());
    }
    let (member, owner, pass) = state(args)?;
    if member.roster.members.len() != 3 {
        return Err("relay signing currently supports only 2-of-3 vaults".into());
    }
    let (context, intent) = manifest(&Path::new(&args[3]).join("payment.json"))?;
    check_manifest_roster(&member.roster, &context, &intent)?;
    if !context.pair.contains(&member.identity.public().id) {
        return Err("member is not an approver for this payment".into());
    }
    private_work(Path::new(&args[3]))?;
    let mailbox = Mailbox::new(&Path::new(&args[3]).join("mailbox")).map_err(|e| e.to_string())?;
    Ok((member, owner, pass, context, intent, mailbox))
}

#[cfg(feature = "relay-communication")]
fn commit(args: &[String]) -> Result<(), String> {
    let (member, owner, pass, context, intent, mailbox) = signing_inputs(args)?;
    let own = member.identity.public().id;
    let peer = member.roster.members[&peer_in_pair(context.pair, own).unwrap()].clone();
    let identity =
        loki_poc::setup_transport::Identity::from_secret_bytes(&member.identity.to_secret_bytes())?;
    let relays = two_relays(args)?;
    let session = SigningSession::begin_sealed(
        &owner.join("signing"),
        context.clone(),
        &member.vault,
        intent.clone(),
        identity,
        member.key.clone(),
        member.public.clone(),
        member.fvk.clone(),
        intent.input_nullifiers.len(),
        &pass,
        relays.pins(),
    )?;
    session.publish_commitments(&peer, &mailbox)?;
    println!(
        "commitments published for payment {}; approval pending",
        hex::encode(context.payment)
    );
    Ok(())
}

#[cfg(feature = "relay-communication")]
fn reopen_signer(
    args: &[String],
) -> Result<
    (
        MemberState,
        PathBuf,
        Zeroizing<String>,
        SessionContext,
        Intent,
        Mailbox,
        SigningSession,
    ),
    String,
> {
    let (member, owner, pass, context, intent, mailbox) = signing_inputs(args)?;
    let identity =
        loki_poc::setup_transport::Identity::from_secret_bytes(&member.identity.to_secret_bytes())?;
    let session = SigningSession::reopen_sealed(
        &owner.join("signing"),
        context.clone(),
        &member.vault,
        intent.clone(),
        identity,
        member.key.clone(),
        member.public.clone(),
        member.fvk.clone(),
        &pass,
    )?;
    Ok((member, owner, pass, context, intent, mailbox, session))
}

#[cfg(feature = "relay-communication")]
fn next_message(
    mailbox: &Mailbox,
    member: &MemberState,
    context: &SessionContext,
    kind: MessageKind,
    sender: u16,
) -> Result<OpenedMessage, String> {
    mailbox
        .read_for(&member.identity, &member.roster.members, context)?
        .into_iter()
        .find(|message| message.kind() == kind && message.sender() == sender)
        .ok_or_else(|| format!("waiting for member {sender} {kind:?}; sync relay inbox and retry"))
}

#[cfg(feature = "relay-communication")]
fn package(args: &[String]) -> Result<(), String> {
    let (member, _owner, pass, context, intent, mailbox, session) = reopen_signer(args)?;
    let own = member.identity.public().id;
    if own != context.pair[0] {
        return Err("only the selected proposer builds this package".into());
    }
    let peer_id = context.pair[1];
    let commitment = next_message(
        &mailbox,
        &member,
        &context,
        MessageKind::Commitment,
        peer_id,
    )?;
    let peer = commitments_from_message(&context, &commitment, intent.input_nullifiers.len())?;
    let payload = candidate(&member, &intent, &session, context.pair, peer)?;
    session.publish_package_to_roster(&member.roster.members, &payload, &mailbox, &pass)?;
    println!("payment package published; members may review");
    Ok(())
}

#[cfg(feature = "relay-communication")]
struct TwoRelays {
    own: Vec<OwnerInbox>,
    http: RelayHttp,
    runtime: RelayRuntime,
}

#[cfg(feature = "relay-communication")]
impl NonceWitness for TwoRelays {
    fn pins(&self) -> loki_poc::signing_session::WitnessPins {
        [
            (&self.own[0].route.pin.key, &self.own[0].route.pin.run),
            (&self.own[1].route.pin.key, &self.own[1].route.pin.run),
        ]
        .map(|(key, run)| (*key, *run))
    }
    fn claim(&mut self, cid: [u8; 32], wire: &[u8]) -> Result<(), String> {
        for inbox in &self.own[..2] {
            let created = self
                .runtime
                .block_on(self.http.claim_nonce(&inbox.route, &inbox.read, cid, wire))
                .map_err(|e| format!("nonce relay claim: {e}"))?;
            if !created {
                return Err("nonce already claimed; start a new signing attempt".into());
            }
        }
        Ok(())
    }
}

#[cfg(feature = "relay-communication")]
fn two_relays(args: &[String]) -> Result<TwoRelays, String> {
    let root = Path::new(&args[0]);
    let loaded = loki_poc::relay_member::load(root, Path::new(&args[1]), Path::new(&args[2]))
        .map_err(|e| e.to_string())?;
    let config_store = loki_poc::relay_member::ConfigStore::open(root, Path::new(&args[1]))
        .map_err(|e| e.to_string())?;
    let db = ClientStore::open(
        &root.join("transport"),
        &loaded.roster,
        loaded.identity.public().id,
    )
    .map_err(|e| e.to_string())?;
    let mut own = config_store
        .routing(&db, &loaded)
        .map_err(|e| e.to_string())?
        .own;
    if own.len() < 2
        || own[0].route.pin.key == own[1].route.pin.key
        || own[0].route.pin.run == own[1].route.pin.run
    {
        return Err("two distinct configured relays required for nonce safety".into());
    }
    own.truncate(2);
    Ok(TwoRelays {
        own,
        http: RelayHttp::new().map_err(|e| e.to_string())?,
        runtime: RelayRuntime::new().map_err(|e| e.to_string())?,
    })
}

#[cfg(feature = "relay-communication")]
fn approve(args: &[String]) -> Result<(), String> {
    let (member, owner, pass, context, intent, mailbox, mut session) = reopen_signer(args)?;
    let own = member.identity.public().id;
    let peer_id = peer_in_pair(context.pair, own).unwrap();
    let peer = member.roster.members[&peer_id].clone();
    let finisher =
        member.roster.members[&(1..=3).find(|id| !context.pair.contains(id)).unwrap()].clone();
    let package_message = if own == context.pair[0] {
        let wires =
            SigningSession::saved_package_wires(&owner.join("signing"), &context, own, &pass)?;
        member
            .identity
            .open_sent_session(&peer, &context, &wires[0])?
    } else {
        next_message(&mailbox, &member, &context, MessageKind::Package, peer_id)?
    };
    let reviewed = session.review_package(&package_message, &peer)?;
    confirm(
        &intent,
        reviewed.summary(),
        &mut FileCourier(&mailbox),
        Path::new(&args[3]),
    )?;
    let mut relays = two_relays(args)?;
    session.publish_approved_secured(reviewed, &peer, &finisher, &mailbox, &pass, &mut relays)?;
    println!("signed locally; approval delivery pending relay storage");
    Ok(())
}

fn resend(args: &[String]) -> Result<(), String> {
    let (args, mode, export) = split_transport(args)?;
    if args.len() != 4 {
        return Err("resend <member-dir> <passphrase-file> <roster.json> <work-dir> [--transport file|relay]".into());
    }
    let (member, owner, pass) = state(&args)?;
    let own = member.identity.public().id;
    let work = Path::new(&args[3]);
    private_work(work)?;
    let (context, intent) = manifest(&work.join("payment.json"))?;
    check_manifest_roster(&member.roster, &context, &intent)?;
    if !context.pair.contains(&own) {
        return Err("only a selected signer can resend".into());
    }
    let mut courier = open_courier(
        mode,
        &owner,
        Path::new(&args[1]),
        Path::new(&args[2]),
        &work,
        export,
    )?;
    let root = owner.join("signing");
    if own == context.pair[0] {
        SigningSession::republish_saved_package(
            &root,
            &context,
            &member.roster.members,
            own,
            &pass,
            &mut courier,
        )?;
    }
    SigningSession::recover_share_with_courier(&root, &context, own, &pass, &mut courier)?;
    settle_delivery(&mut courier, work)?;
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
    let (args, mode, export) = split_transport(args)?;
    if args.len() != 4 {
        return Err("finish <member-dir> <passphrase-file> <roster.json> <work-dir> [--transport file|relay]".into());
    }
    let (member, owner, pass) = state(&args)?;
    let work = Path::new(&args[3]);
    private_work(work)?;
    let (context, intent) = manifest(&work.join("payment.json"))?;
    check_manifest_roster(&member.roster, &context, &intent)?;
    let mut courier = open_courier(
        mode,
        &owner,
        Path::new(&args[1]),
        Path::new(&args[2]),
        work,
        export,
    )?;
    let limit = wait_limit(mode);
    let own = member.identity.public().id;
    let peer = peer_in_pair(context.pair, own);
    let package = if own == context.pair[0] {
        let wires =
            SigningSession::saved_package_wires(&owner.join("signing"), &context, own, &pass)?;
        member.identity.open_sent_session(
            &member.roster.members[&peer.unwrap()],
            &context,
            &wires[0],
        )?
    } else {
        wait_reopened(
            &mut courier,
            &member,
            &context,
            MessageKind::Package,
            context.pair[0],
            work,
            limit,
        )?
    };
    let payload = match PackagePayload::decode(&context, package.body()) {
        Ok(payload) => payload,
        Err(error) => {
            courier.note_application(false, &package);
            return Err(error);
        }
    };
    let shares = if let Some(peer_id) = peer {
        let wires =
            SigningSession::saved_share_wires(&owner.join("signing"), &context, own, &pass)?;
        let own_share = member.identity.open_sent_session(
            &member.roster.members[&peer_id],
            &context,
            &wires[0],
        )?;
        let peer_share = wait_reopened(
            &mut courier,
            &member,
            &context,
            MessageKind::Share,
            peer_id,
            work,
            limit,
        )?;
        [own_share, peer_share]
    } else {
        [
            wait_reopened(
                &mut courier,
                &member,
                &context,
                MessageKind::Share,
                context.pair[0],
                work,
                limit,
            )?,
            wait_reopened(
                &mut courier,
                &member,
                &context,
                MessageKind::Share,
                context.pair[1],
                work,
                limit,
            )?,
        ]
    };
    let (signed, sighash, indices) = match aggregate_and_apply(
        &context,
        &intent,
        &member.vault,
        &member.public,
        &member.fvk,
        &payload,
        &shares,
    ) {
        Ok(applied) => {
            courier.note_application(true, &package);
            for share in &shares {
                courier.note_application(true, share);
            }
            applied
        }
        Err(error) => {
            courier.note_application(false, &package);
            for share in &shares {
                courier.note_application(false, share);
            }
            return Err(error);
        }
    };
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
    let (args, mode, export) = split_transport(args)?;
    if args.len() != 5 {
        return Err("verify <member-dir> <passphrase-file> <roster.json> <work-dir> <txid> [--transport file|relay]".into());
    }
    let (member, owner, pass) = state(&args)?;
    let work = Path::new(&args[3]);
    private_work(work)?;
    let txid = &args[4];
    if txid.len() != 64 || !txid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("txid must be 32 hexadecimal bytes".into());
    }
    let (context, intent) = manifest(&work.join("payment.json"))?;
    check_manifest_roster(&member.roster, &context, &intent)?;
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
    let mut courier = open_courier(
        mode,
        &owner,
        Path::new(&args[1]),
        Path::new(&args[2]),
        &work,
        export,
    )?;
    let package_message = if member.identity.public().id == context.pair[0] {
        let wires = SigningSession::saved_package_wires(
            &owner.join("signing"),
            &context,
            context.pair[0],
            &pass,
        )?;
        member.identity.open_sent_session(
            &member.roster.members[&context.pair[1]],
            &context,
            &wires[0],
        )?
    } else {
        wait_reopened(
            &mut courier,
            &member,
            &context,
            MessageKind::Package,
            context.pair[0],
            work,
            wait_limit(mode),
        )?
    };
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
    let (args, mode, export) = split_transport(args)?;
    let _ = export;
    if args.len() != 5 {
        return Err("receive <recipient-member-dir> <passphrase-file> <roster.json> <payment-work-dir> <txid> [--transport file|relay]".into());
    }
    let (recipient, _, _) = state(&args)?;
    let work = Path::new(&args[3]);
    if matches!(mode, TransportMode::Relay) && work.join("mailbox").exists() {
        return Err("relay mode refuses an existing file mailbox".into());
    }
    let (_, intent) = manifest(&work.join("payment.json"))?;
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
        Some("balance") => balance(&args[2..]),
        #[cfg(feature = "relay-communication")]
        Some("features") => {
            println!("relay-backed-signing=1");
            Ok(())
        }
        #[cfg(feature = "relay-communication")]
        Some("commit") => commit(&args[2..]),
        #[cfg(feature = "relay-communication")]
        Some("package") => package(&args[2..]),
        #[cfg(feature = "relay-communication")]
        Some("approve") => approve(&args[2..]),
        Some("sign") => sign(&args[2..]),
        Some("resend") => resend(&args[2..]),
        Some("finish") => finish(&args[2..]),
        Some("verify") => verify(&args[2..]),
        Some("receive") => receive(&args[2..]),
        _ => Err(
            "loki_member_payment <balance|prepare|sign|resend|finish|verify|receive> ... (regtest only)"
                .into(),
        ),
    };
    if let Err(error) = result {
        eprintln!("error: {error}");
        process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payment_pair_is_sorted_and_explicit() {
        assert_eq!(manifest_pair(&json!({})).unwrap(), [1, 2]);
        for (name, pair) in [
            ("AB", [1, 2]),
            ("AC", [1, 3]),
            ("AD", [1, 4]),
            ("BC", [2, 3]),
            ("BD", [2, 4]),
            ("CD", [3, 4]),
        ] {
            assert_eq!(pair_from_name(name).unwrap(), pair);
            assert_eq!(manifest_pair(&json!({ "pair": pair })).unwrap(), pair);
        }
        for pair in [
            json!([2, 1]),
            json!([1, 1]),
            json!([4, 5]),
            json!([1]),
            json!("AC"),
        ] {
            assert!(manifest_pair(&json!({ "pair": pair })).is_err());
        }
        assert_eq!(peer_in_pair([2, 3], 1), None);
        assert_eq!(peer_in_pair([2, 3], 2), Some(3));
        assert_eq!(peer_in_pair([2, 3], 3), Some(2));
    }

    #[test]
    fn any_roster_member_can_propose() {
        for id in 1..=4 {
            let bytes = frost::Identifier::try_from(id).unwrap().serialize();
            assert_eq!(proposer_id(&bytes).unwrap(), id);
        }
        assert!(proposer_id(&frost::Identifier::try_from(5u16).unwrap().serialize()).is_err());
        assert!(proposer_id(&[0u8; 32]).is_err());
    }

    #[test]
    fn manifest_pair_and_proposer_must_belong_to_certified_roster() {
        let path = std::env::temp_dir().join(format!("loki-payment-roster-{}", process::id()));
        let members: Vec<_> = (1..=3)
            .map(|id| {
                let public = loki_poc::setup_transport::Identity::new(id).public();
                json!({"id": id, "signing": hex::encode(public.signing),
                       "encryption": hex::encode(public.encryption)})
            })
            .collect();
        fs::write(
            &path,
            json!({"vault": hex::encode([7u8; 32]),
                                "threshold": 2, "members": members})
            .to_string(),
        )
        .unwrap();
        let roster = Roster::load(&path).unwrap();
        fs::remove_file(path).unwrap();
        let context = SessionContext {
            vault: roster.vault,
            payment: [0; 32],
            attempt: AttemptId([1; 32]),
            pair: [1, 3],
        };
        let mut intent = Intent {
            proposer: frost::Identifier::try_from(2u16).unwrap().serialize(),
            created_height: 1,
            input_nullifiers: vec![[0; 32]],
            recipient: vec![0; 43],
            amount_zat: 1,
            memo: vec![1],
            change_policy: ChangePolicy::VaultInternal,
            fee_zat: 1,
            change_zat: 1,
            expiry_height: 2,
        };
        assert!(check_manifest_roster(&roster, &context, &intent).is_ok());
        let mut bad_pair = context.clone();
        bad_pair.pair = [1, 4];
        assert!(check_manifest_roster(&roster, &bad_pair, &intent).is_err());
        intent.proposer = frost::Identifier::try_from(4u16).unwrap().serialize();
        assert!(check_manifest_roster(&roster, &context, &intent).is_err());
    }
}
