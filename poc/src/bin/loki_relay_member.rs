//! Communication member commands. Arguments are paths and public identifiers.
//! Secret bytes stay in sealed files and are never written to stdout or stderr.

use loki_poc::relay_member::{
    load, ConfigStore, CourierImport, LoadedMember, MemberError, ProvisionTarget,
};
use loki_relay_client::{
    committed_readiness, open_descriptor, outbox_intent_digest, poll_once, prepare_outbox,
    received_status, upload_pending, AuthenticatedDescriptor, CandidateReadiness, ClientConfig,
    ClientError, ClientStore, DiagnosticSample, DownloadRejection, PendingDownload,
    RecoveryLogical, RecoveryUpload, RelayHttp, RelayRuntime, RouteCursor, Secret32,
    SourceRejection, ThirdPass,
};
use loki_relay_protocol::types::{
    roster_digest, Id32, LogicalKey, MessageBody, Payload, RelayPin, RelayRoute,
};
use rand_core::{OsRng, RngCore};
use std::{
    env, fs, io,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};
use zeroize::Zeroize;

const PAGE: u16 = 100;
const ENTRY_LIMIT: u64 = 100;
const MAX_PAYLOAD: usize = 16 * 1024 * 1024;
const MAX_MANIFEST: usize = 8192;
const SWITCHES: &[&str] = &["--once", "--verify-relays", "--diagnostics"];
const DIAGNOSTIC_ROW_BOUND: usize = 400;

enum Exit {
    Usage,
    Member(MemberError),
    Client(ClientError),
}

struct OwnInbox {
    route: RelayRoute,
    read: Secret32,
}

fn main() {
    let code = match run() {
        Ok(()) => 0,
        Err(Exit::Usage) => {
            eprintln!("member_arguments");
            2
        }
        Err(Exit::Member(error)) => {
            eprintln!("{}", error.code());
            1
        }
        Err(Exit::Client(error)) => {
            eprintln!("{}", error.code());
            1
        }
    };
    std::process::exit(code);
}

fn run() -> Result<(), Exit> {
    let mut args = env::args_os().skip(1);
    let command = args.next().ok_or(Exit::Usage)?;
    let command = command.to_str().ok_or(Exit::Usage)?;
    let mut flags: Vec<(String, Option<std::ffi::OsString>)> = Vec::new();
    while let Some(raw) = args.next() {
        let name = raw.to_str().ok_or(Exit::Usage)?.to_owned();
        if !name.starts_with("--") || name.len() == 2 || name.contains('=') {
            return Err(Exit::Usage);
        }
        if flags.iter().any(|(seen, _)| seen == &name) {
            return Err(Exit::Usage);
        }
        if SWITCHES.contains(&name.as_str()) {
            flags.push((name, None));
        } else {
            let value = args.next().ok_or(Exit::Usage)?;
            if value.is_empty() || value.to_str().is_some_and(|text| text.starts_with("--")) {
                return Err(Exit::Usage);
            }
            flags.push((name, Some(value)));
        }
    }
    let take = |name: &str| -> Result<PathBuf, Exit> {
        flags
            .iter()
            .find(|(flag, _)| flag == name)
            .and_then(|(_, value)| value.clone())
            .map(PathBuf::from)
            .ok_or(Exit::Usage)
    };
    let switched = |name: &str| flags.iter().any(|(flag, _)| flag == name);
    let common = || -> Result<(PathBuf, PathBuf, PathBuf), Exit> {
        Ok((
            take("--member-root")?,
            take("--passphrase-file")?,
            take("--roster")?,
        ))
    };
    let expect = |allowed: &[&str]| -> Result<(), Exit> {
        if flags
            .iter()
            .any(|(flag, _)| !allowed.contains(&flag.as_str()))
        {
            Err(Exit::Usage)
        } else {
            Ok(())
        }
    };
    match command {
        "provision" => {
            expect(&[
                "--member-root",
                "--passphrase-file",
                "--roster",
                "--relay-manifest",
                "--provision-capability-files",
            ])?;
            let (root, pass, roster) = common()?;
            provision(
                &root,
                &pass,
                &roster,
                &take("--relay-manifest")?,
                &take("--provision-capability-files")?,
            )
        }
        "export-config" => {
            expect(&[
                "--member-root",
                "--passphrase-file",
                "--roster",
                "--courier-directory",
            ])?;
            let (root, pass, roster) = common()?;
            export_config(&root, &pass, &roster, &take("--courier-directory")?)
        }
        "import-config" => {
            expect(&[
                "--member-root",
                "--passphrase-file",
                "--roster",
                "--courier-file",
            ])?;
            let (root, pass, roster) = common()?;
            import_config(&root, &pass, &roster, &take("--courier-file")?)
        }
        "rotate-append" => {
            expect(&["--member-root", "--passphrase-file", "--roster"])?;
            let (root, pass, roster) = common()?;
            rotate_append(&root, &pass, &roster)
        }
        "send" => {
            expect(&[
                "--member-root",
                "--passphrase-file",
                "--roster",
                "--payload-file",
                "--request-id",
            ])?;
            let (root, pass, roster) = common()?;
            let request = flags
                .iter()
                .find(|(flag, _)| flag == "--request-id")
                .and_then(|(_, value)| value.as_ref())
                .ok_or(Exit::Usage)?;
            let request = request.to_str().ok_or(Exit::Usage)?;
            send(&root, &pass, &roster, &take("--payload-file")?, request)
        }
        "upload" => {
            expect(&["--member-root", "--passphrase-file", "--roster"])?;
            let (root, pass, roster) = common()?;
            upload(&root, &pass, &roster)
        }
        "poll" => {
            expect(&["--member-root", "--passphrase-file", "--roster", "--once"])?;
            if !switched("--once") {
                return Err(Exit::Usage);
            }
            let (root, pass, roster) = common()?;
            poll(&root, &pass, &roster)
        }
        "status" => {
            expect(&[
                "--member-root",
                "--passphrase-file",
                "--roster",
                "--verify-relays",
                "--diagnostics",
            ])?;
            let (root, pass, roster) = common()?;
            status(
                &root,
                &pass,
                &roster,
                switched("--verify-relays"),
                switched("--diagnostics"),
            )
        }
        _ => Err(Exit::Usage),
    }
}

struct Session {
    member: LoadedMember,
    configs: ConfigStore,
    db: ClientStore,
}

fn open_session(root: &Path, pass: &Path, roster: &Path) -> Result<Session, Exit> {
    let member = load(root, pass, roster).map_err(Exit::Member)?;
    let configs = ConfigStore::open(root, pass).map_err(Exit::Member)?;
    // Transport state stays a direct child of the certified member root.
    let db = ClientStore::open(
        &root.join("transport"),
        &member.roster,
        member.identity.public().id,
    )
    .map_err(Exit::Client)?;
    Ok(Session {
        member,
        configs,
        db,
    })
}

fn provision(
    root: &Path,
    pass: &Path,
    roster: &Path,
    manifest_dir: &Path,
    capability_dir: &Path,
) -> Result<(), Exit> {
    let mut session = open_session(root, pass, roster)?;
    let (targets, capabilities) = provision_inputs(manifest_dir, capability_dir)?;
    let runtime = runtime()?;
    runtime.block_on(async {
        session
            .configs
            .prepare_provision(&mut session.db, &session.member, &targets)
            .map_err(Exit::Member)?;
        session
            .configs
            .provision(
                &mut session.db,
                &session.member,
                &RelayHttp::new().map_err(Exit::Client)?,
                &capabilities,
            )
            .await
            .map_err(Exit::Member)
    })?;
    print_reference(&session)?;
    print_authenticated_inboxes(&session)?;
    Ok(())
}

fn export_config(root: &Path, pass: &Path, roster: &Path, directory: &Path) -> Result<(), Exit> {
    let session = open_session(root, pass, roster)?;
    let paths = session
        .configs
        .publish_provision(&session.db, &session.member, directory)
        .map_err(Exit::Member)?;
    print_reference(&session)?;
    for path in paths {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or(Exit::Member(MemberError::Io))?;
        println!("courier={name}");
    }
    Ok(())
}

fn import_config(root: &Path, pass: &Path, roster: &Path, file: &Path) -> Result<(), Exit> {
    let mut session = open_session(root, pass, roster)?;
    let imported = CourierImport::read(&session.member, file).map_err(Exit::Member)?;
    let owner = imported.descriptor().body().owner;
    let revision = imported.descriptor().body().revision;
    let digest = *imported.descriptor().digest();
    session
        .configs
        .accept_peer(&mut session.db, &session.member, imported.wire())
        .map_err(Exit::Member)?;
    print_reference(&session)?;
    println!(
        "imported owner={owner} revision={revision} digest={}",
        hex_id(&digest)
    );
    Ok(())
}

fn rotate_append(root: &Path, pass: &Path, roster: &Path) -> Result<(), Exit> {
    let mut session = open_session(root, pass, roster)?;
    let runtime = runtime()?;
    runtime.block_on(async {
        prepare_selected_rotation(&mut session)?;
        session
            .configs
            .rotate(
                &mut session.db,
                &session.member,
                &RelayHttp::new().map_err(Exit::Client)?,
            )
            .await
            .map_err(Exit::Member)
    })?;
    print_reference(&session)?;
    Ok(())
}

fn send(
    root: &Path,
    pass: &Path,
    roster: &Path,
    payload_file: &Path,
    request_hex: &str,
) -> Result<(), Exit> {
    let request_id = parse_id(request_hex)?;
    let mut payload = read_exact(payload_file, MAX_PAYLOAD, false)?;
    let mut session = open_session(root, pass, roster)?;
    let digest =
        roster_digest(&session.member.roster).map_err(|_| Exit::Member(MemberError::Roster))?;
    let mut body = MessageBody {
        key: LogicalKey {
            vault: session.member.roster.vault,
            roster: digest,
            sender: session.member.identity.public().id,
            message: [0; 32],
        },
        audience: session
            .member
            .roster
            .members
            .iter()
            .map(|member| member.id)
            .collect(),
        session: None,
        prerequisites: Vec::new(),
        payload: Payload::Test(payload.to_vec()),
    };
    let intent = outbox_intent_digest(&body).map_err(|error| {
        wipe_test(&mut body);
        Exit::Client(error)
    });
    let saved = intent.and_then(|intent| {
        if let Some(existing) = session
            .db
            .lookup_outbox_request(&request_id, &intent)
            .map_err(Exit::Client)?
        {
            return Ok(existing);
        }
        OsRng
            .try_fill_bytes(&mut body.key.message)
            .map_err(|_| Exit::Member(MemberError::Io))?;
        let prepared = prepare_outbox(&session.member.identity, &session.member.roster, &body)
            .map_err(Exit::Client)?;
        // The caller binding and every recipient object are durable before any upload command.
        session
            .db
            .commit_outbox(
                &session.member.roster,
                &session.member.identity,
                &request_id,
                &prepared,
            )
            .map_err(Exit::Client)
    });
    wipe_test(&mut body);
    payload.zeroize();
    let saved = saved?;
    println!("request_id={}", hex_id(&request_id));
    print_logical(&session.db, &saved)?;
    Ok(())
}

fn upload(root: &Path, pass: &Path, roster: &Path) -> Result<(), Exit> {
    let mut session = open_session(root, pass, roster)?;
    let (config, self_route) = routed(&session)?;
    let now = now_ms()?;
    let logicals = logical_page(&session.db)?;
    let runtime = runtime()?;
    let http = RelayHttp::new().map_err(Exit::Client)?;
    runtime.block_on(async {
        for logical in &logicals {
            let pass = upload_pending(
                &mut session.db,
                &http,
                logical,
                &session.member.roster,
                &session.member.identity,
                &config,
                &self_route,
                now,
                ThirdPass::StopAfterStored,
            )
            .await
            .map_err(Exit::Client)?;
            println!(
                "upload message={} digest={} needs_route={} stopped_third={}",
                hex_id(&logical.key.message),
                hex_id(&logical.digest),
                member_list(&pass.needs_route),
                u8::from(pass.stopped_third)
            );
        }
        Ok(())
    })
}

fn poll(root: &Path, pass: &Path, roster: &Path) -> Result<(), Exit> {
    let mut session = open_session(root, pass, roster)?;
    let (config, self_route) = routed(&session)?;
    let now = now_ms()?;
    let runtime = runtime()?;
    runtime
        .block_on(poll_once(
            &mut session.db,
            &RelayHttp::new().map_err(Exit::Client)?,
            &session.member.identity,
            &session.member.roster,
            &config,
            &self_route,
            now,
        ))
        .map_err(Exit::Client)?;
    println!("poll=ok");
    Ok(())
}

fn status(
    root: &Path,
    pass: &Path,
    roster: &Path,
    verify_relays: bool,
    diagnostics: bool,
) -> Result<(), Exit> {
    let mut session = open_session(root, pass, roster)?;
    println!("section=local");
    println!("receipt_digest_alg=blake3");
    println!("member={}", session.member.identity.public().id);
    print_reference(&session)?;
    print_authenticated_inboxes(&session)?;
    let logicals = logical_page(&session.db)?;
    let incoming = page_rows(
        |after| session.db.recover_incoming_originals(after, PAGE),
        usize::MAX,
    )?;
    let acks = page_rows(
        |after| session.db.recover_ack_links(after, PAGE),
        usize::MAX,
    )?;
    println!("logical_count={}", logicals.len());
    println!("incoming_count={}", incoming.len());
    println!("ack_count={}", acks.len());
    println!(
        "pending_transfers={}",
        session.db.pending_transfer_count().map_err(Exit::Client)?
    );
    let routed = routed(&session);
    for logical in &logicals {
        print_message(&mut session, logical, routed.as_ref())?;
    }
    for record in &incoming {
        print_incoming(&session, record)?;
    }
    for ack in &acks {
        println!(
            "ack sender={} id={} digest={} author={} ack_message={} request={}",
            ack.key.sender,
            hex_id(&ack.key.message),
            hex_id(&ack.digest),
            ack.ack_author,
            hex_id(&ack.ack_message),
            hex_id(&ack.request_id)
        );
    }
    if !verify_relays {
        if diagnostics {
            print_diagnostics(&session)?;
        }
        return Ok(());
    }
    let local = session
        .configs
        .load(&session.db, &session.member)
        .map_err(Exit::Member)?
        .ok_or(Exit::Member(MemberError::Sealed))?;
    if local.own.len() != 3 {
        return Err(Exit::Member(MemberError::Sealed));
    }
    let own = local
        .own
        .iter()
        .map(|inbox| OwnInbox {
            route: inbox.route.clone(),
            read: Secret32::from_bytes(*inbox.read.as_bytes()),
        })
        .collect::<Vec<_>>();
    drop(local);
    println!("section=remote");
    println!("receipt_digest_alg=blake3");
    let runtime = runtime()?;
    let http = RelayHttp::new().map_err(Exit::Client)?;
    let member_id = session.member.identity.public().id;
    // Read the owner's inboxes from cursor 0. Entries and object gets do not advance saved cursors.
    runtime.block_on(async {
        for inbox in &own {
            match verify_inbox(&http, inbox).await {
                Ok(snapshot) => println!(
                    "remote_inbox member={member_id} pin={} run={} mailbox={} entries={} failures={} result={}",
                    hex_id(&inbox.route.pin.key),
                    hex_id(&inbox.route.pin.run),
                    hex_id(&inbox.route.mailbox),
                    snapshot.entries,
                    snapshot.failures,
                    if snapshot.failures == 0 { "ok" } else { "partial" }
                ),
                Err(error) => println!(
                    "route_error pin={} run={} mailbox={} result=error code={}",
                    hex_id(&inbox.route.pin.key),
                    hex_id(&inbox.route.pin.run),
                    hex_id(&inbox.route.mailbox),
                    error.code()
                ),
            }
        }
        Ok(())
    })?;
    if diagnostics {
        print_diagnostics(&session)?;
    }
    Ok(())
}

fn print_diagnostics(session: &Session) -> Result<(), Exit> {
    // Transport counters and capture metadata. They do not authenticate a message.
    let cursors = page_rows(
        |after| session.db.recover_route_cursors(after, PAGE),
        DIAGNOSTIC_ROW_BOUND,
    )?;
    let pending = page_rows(
        |after| session.db.recover_pending_downloads(after, PAGE),
        DIAGNOSTIC_ROW_BOUND,
    )?;
    let download_rejections = page_rows(
        |after| session.db.recover_download_rejections(after, PAGE),
        DIAGNOSTIC_ROW_BOUND,
    )?;
    let source_rejections = page_rows(
        |after| session.db.recover_source_rejections(after, PAGE),
        DIAGNOSTIC_ROW_BOUND,
    )?;
    let uploads = page_rows(
        |after| session.db.recover_uploads(after, PAGE),
        DIAGNOSTIC_ROW_BOUND,
    )?;
    let samples = page_rows(
        |after| session.db.recover_diagnostic_samples(after, PAGE),
        DIAGNOSTIC_ROW_BOUND,
    )?;
    let sample_bytes = samples.iter().try_fold(0u64, |total, sample| {
        total
            .checked_add(sample.sample_len)
            .ok_or(Exit::Client(ClientError::Capacity))
    })?;
    println!("section=diagnostics");
    println!("diagnostics_authority=transport");
    println!("route_cursor_count={}", cursors.len());
    println!("pending_download_count={}", pending.len());
    println!("download_rejection_count={}", download_rejections.len());
    println!("source_rejection_count={}", source_rejections.len());
    let upload_pending_count = uploads.iter().filter(|upload| !upload.acknowledged).count();
    println!("upload_work_count={}", uploads.len());
    println!("upload_pending_count={upload_pending_count}");
    println!("sample_count={}", samples.len());
    println!("sample_bytes={sample_bytes}");
    for cursor in &cursors {
        println!(
            "route_cursor pin={} run={} mailbox={} position={}",
            hex_id(&cursor.relay_key),
            hex_id(&cursor.run),
            hex_id(&cursor.mailbox),
            cursor.position
        );
    }
    for task in &pending {
        println!(
            "pending_download pin={} run={} mailbox={} hash={} length={} attempts={} retry_at={}",
            hex_id(&task.relay_key),
            hex_id(&task.run),
            hex_id(&task.mailbox),
            hex_id(&task.source_hash),
            task.wire_length,
            task.attempts,
            task.retry_at
        );
    }
    for rejection in &download_rejections {
        println!(
            "download_rejection pin={} run={} mailbox={} hash={} {}",
            hex_id(&rejection.relay_key),
            hex_id(&rejection.run),
            hex_id(&rejection.mailbox),
            hex_id(&rejection.source_hash),
            public_reason(&rejection.reason)
        );
    }
    for rejection in &source_rejections {
        println!(
            "source_rejection root={} {}",
            hex_id(&rejection.root_hash),
            public_reason(&rejection.reason)
        );
    }
    for upload in &uploads {
        println!(
            "upload_retry message={} recipient={} hash={} pin={} run={} mailbox={} acknowledged={} attempts={} retry_at={}",
            hex_id(&upload.key.message),
            upload.recipient,
            hex_id(&upload.hash),
            hex_id(&upload.relay_key),
            hex_id(&upload.run),
            hex_id(&upload.mailbox),
            u8::from(upload.acknowledged),
            upload.attempts,
            upload.retry_at
        );
    }
    for sample in &samples {
        println!(
            "diagnostic_sample pin={} run={} mailbox={} sequence={} length={}",
            hex_id(&sample.relay_key),
            hex_id(&sample.run),
            hex_id(&sample.mailbox),
            sample.sequence,
            sample.sample_len
        );
    }
    Ok(())
}

fn public_reason(reason: &str) -> String {
    // A stored reason is metadata. Only a short token is a status field.
    let token = !reason.is_empty()
        && reason.len() <= 64
        && reason.as_bytes()[0].is_ascii_lowercase()
        && reason
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_');
    if token {
        format!("reason={reason}")
    } else {
        format!("reason=other length={}", reason.len())
    }
}

fn prepare_selected_rotation(session: &mut Session) -> Result<(), Exit> {
    let local = session
        .configs
        .load(&session.db, &session.member)
        .map_err(Exit::Member)?
        .ok_or(Exit::Member(MemberError::Sealed))?;
    // Authenticated sealed state chooses the generation. A later command must not replay the first prepare.
    local.authenticated(&session.member).map_err(Exit::Member)?;
    if local.rotated.is_some() {
        session
            .configs
            .prepare_next_rotation(&mut session.db, &session.member)
            .map_err(Exit::Member)?;
    } else {
        session
            .configs
            .prepare_rotation(&mut session.db, &session.member)
            .map_err(Exit::Member)?;
    }
    Ok(())
}

fn print_incoming(
    session: &Session,
    record: &loki_relay_client::IncomingOriginal,
) -> Result<(), Exit> {
    let readiness = committed_readiness(
        &session.db,
        &session.member.roster,
        &session.member.identity,
        &record.key,
        &record.digest,
    )
    .map_err(Exit::Client)?;
    let received = received_status(
        &session.db,
        &session.member.roster,
        &session.member.identity,
        &record.key,
        &record.digest,
    )
    .map_err(Exit::Client)?;
    println!(
        "incoming sender={} id={} digest={} kind={} session={} readiness={} received_whole={} received_author={} root={}",
        record.key.sender,
        hex_id(&record.key.message),
        hex_id(&record.digest),
        kind_name(record.kind),
        session_text(record.session.as_ref()),
        readiness_name(readiness),
        u8::from(received.whole_vault()),
        u8::from(received.author_committed()),
        hex_id(&record.source_root)
    );
    for member in &session.member.roster.members {
        println!(
            "incoming_received_member sender={} id={} digest={} member={} value={}",
            record.key.sender,
            hex_id(&record.key.message),
            hex_id(&record.digest),
            member.id,
            u8::from(received.member_received(member.id))
        );
    }
    Ok(())
}

fn print_message(
    session: &mut Session,
    logical: &RecoveryLogical,
    routed: Result<&(ClientConfig, AuthenticatedDescriptor), &Exit>,
) -> Result<(), Exit> {
    let readiness = committed_readiness(
        &session.db,
        &session.member.roster,
        &session.member.identity,
        &logical.key,
        &logical.digest,
    )
    .map_err(Exit::Client)?;
    let received = received_status(
        &session.db,
        &session.member.roster,
        &session.member.identity,
        &logical.key,
        &logical.digest,
    )
    .map_err(Exit::Client)?;
    let report = match routed {
        Ok((config, self_route)) => match session.db.delivery_report(
            &session.member.roster,
            &session.member.identity,
            logical,
            config,
            self_route,
        ) {
            Ok(report) => Some(report),
            Err(ClientError::Config) => None,
            Err(error) => return Err(Exit::Client(error)),
        },
        Err(_) => None,
    };
    let recipients = session
        .db
        .recover_recipients(&logical.key)
        .map_err(Exit::Client)?;
    let needs_route = recipients
        .iter()
        .filter(|recipient| recipient.needs_route)
        .count();
    println!(
        "message sender={} id={} digest={} kind={} session={} readiness={} stored_whole={} received_whole={} received_author={} needs_route={}",
        logical.key.sender,
        hex_id(&logical.key.message),
        hex_id(&logical.digest),
        kind_name(logical.kind),
        session_text(logical.session.as_ref()),
        readiness_name(readiness),
        report.as_ref().map(|item| u8::from(item.whole_vault()).to_string()).unwrap_or_else(|| "unavailable".to_owned()),
        u8::from(received.whole_vault()),
        u8::from(received.author_committed()),
        needs_route
    );
    for member in &session.member.roster.members {
        println!(
            "received_member id={} value={}",
            member.id,
            u8::from(received.member_received(member.id))
        );
    }
    if let Some(report) = &report {
        for member in &session.member.roster.members {
            println!(
                "stored_member id={} value={}",
                member.id,
                u8::from(report.member_stored(member.id))
            );
            for (pin, run) in report.member_pins(member.id) {
                println!(
                    "stored_pin scope=member member={} pin={} run={}",
                    member.id,
                    hex_id(pin),
                    hex_id(run)
                );
            }
        }
        for (pin, run) in report.whole_pins() {
            println!(
                "stored_pin scope=whole member=- pin={} run={}",
                hex_id(pin),
                hex_id(run)
            );
        }
    }
    for recipient in &recipients {
        println!(
            "recipient id={} root={} needs_route={}",
            recipient.recipient,
            hex_id(&recipient.root_hash),
            u8::from(recipient.needs_route)
        );
        let mut after = None;
        loop {
            let page = session
                .db
                .recover_requirements(&logical.key, recipient.recipient, after.as_ref(), PAGE)
                .map_err(Exit::Client)?;
            if page.is_empty() {
                break;
            }
            let last = page.last().map(|item| item.hash);
            if last == after {
                return Err(Exit::Client(ClientError::Storage));
            }
            let short = page.len() < usize::from(PAGE);
            for object in &page {
                println!(
                    "object recipient={} ordinal={} hash={} length={}",
                    recipient.recipient,
                    object.ordinal,
                    hex_id(&object.hash),
                    object.length
                );
            }
            if short {
                break;
            }
            after = last;
        }
    }
    for upload in uploads_for(&session.db, &logical.key)? {
        let mut saved = session.db.saved_receipt(&upload).map_err(Exit::Client)?;
        let receipt_digest = saved.as_ref().map(|bytes| digest_hex(bytes));
        if let Some(bytes) = &mut saved {
            bytes.zeroize();
        }
        println!(
            "upload recipient={} hash={} pin={} run={} acknowledged={} receipt_digest={}",
            upload.recipient,
            hex_id(&upload.hash),
            hex_id(&upload.relay_key),
            hex_id(&upload.run),
            u8::from(upload.acknowledged),
            receipt_digest.unwrap_or_else(|| "-".to_owned())
        );
    }
    Ok(())
}

fn print_authenticated_inboxes(session: &Session) -> Result<(), Exit> {
    let Some(local) = session
        .configs
        .load(&session.db, &session.member)
        .map_err(Exit::Member)?
    else {
        return Ok(());
    };
    match local.authenticated(&session.member) {
        Ok(config) => print_own_inboxes(session.member.identity.public().id, &config.own),
        Err(error) => println!("inbox_error={}", error.code()),
    }
    Ok(())
}

fn print_own_inboxes(member_id: u16, own: &[loki_relay_client::OwnerInbox]) {
    for inbox in own {
        println!(
            "inbox member={member_id} pin={} run={} mailbox={} append_revision={} endpoint={}",
            hex_id(&inbox.route.pin.key),
            hex_id(&inbox.route.pin.run),
            hex_id(&inbox.route.mailbox),
            inbox.route.append_revision,
            inbox.route.endpoint
        );
    }
}

struct RemoteSnapshot {
    entries: u64,
    failures: u64,
}

async fn verify_inbox(http: &RelayHttp, inbox: &OwnInbox) -> Result<RemoteSnapshot, ClientError> {
    let mut after = 0;
    let mut seen = Vec::new();
    let mut entries = 0u64;
    let mut failures = 0u64;
    loop {
        let page = http
            .entries(&inbox.route, &inbox.read, after, Some(ENTRY_LIMIT))
            .await?;
        for entry in page.entries() {
            entries = entries.saturating_add(1);
            let body = entry.receipt().body();
            match http.get(&inbox.route, &inbox.read, entry.hash()).await {
                Ok(mut object) => {
                    let retrieved_len = object.wire.len() as u64;
                    let retrieved_hash = object.hash;
                    object.wire.zeroize();
                    let agreed = retrieved_hash == body.hash
                        && retrieved_hash == *entry.hash()
                        && retrieved_len == body.wire_length
                        && retrieved_len == entry.wire_length();
                    if !agreed {
                        failures = failures.saturating_add(1);
                        println!(
                            "retrieval_error pin={} run={} mailbox={} sequence={} hash={} length={} receipt_digest={} retrieved_hash={} retrieved_length={} code={}",
                            hex_id(&body.pin.key),
                            hex_id(&body.pin.run),
                            hex_id(&body.mailbox),
                            body.sequence,
                            hex_id(&body.hash),
                            body.wire_length,
                            digest_hex(entry.receipt().bytes()),
                            hex_id(&retrieved_hash),
                            retrieved_len,
                            ClientError::Receipt.code()
                        );
                        continue;
                    }
                    println!(
                        "entry pin={} run={} mailbox={} sequence={} hash={} length={} receipt_digest={} retrieved_hash={} retrieved_length={}",
                        hex_id(&body.pin.key),
                        hex_id(&body.pin.run),
                        hex_id(&body.mailbox),
                        body.sequence,
                        hex_id(&body.hash),
                        body.wire_length,
                        digest_hex(entry.receipt().bytes()),
                        hex_id(&retrieved_hash),
                        retrieved_len
                    );
                }
                Err(error) => {
                    failures = failures.saturating_add(1);
                    println!(
                        "retrieval_error pin={} run={} mailbox={} sequence={} hash={} length={} receipt_digest={} code={}",
                        hex_id(&body.pin.key),
                        hex_id(&body.pin.run),
                        hex_id(&body.mailbox),
                        body.sequence,
                        hex_id(&body.hash),
                        body.wire_length,
                        digest_hex(entry.receipt().bytes()),
                        error.code()
                    );
                }
            }
        }
        if page.next() == page.high_water() {
            return Ok(RemoteSnapshot { entries, failures });
        }
        if page.next() <= after || seen.contains(&page.next()) {
            return Err(ClientError::Cursor);
        }
        seen.push(page.next());
        after = page.next();
    }
}

fn provision_inputs(
    manifest_dir: &Path,
    capability_dir: &Path,
) -> Result<(Vec<ProvisionTarget>, Vec<Secret32>), Exit> {
    let mut targets = Vec::new();
    for root in child_directories(manifest_dir)? {
        let mut lines = read_text(&root.join("manifest"), MAX_MANIFEST)?;
        if lines.len() != 3 || lines.iter().any(|line| line.is_empty()) {
            return Err(Exit::Member(MemberError::Bounds));
        }
        let endpoint = lines.remove(0);
        if endpoint.len() > 2048 || endpoint.chars().any(char::is_whitespace) {
            return Err(Exit::Member(MemberError::Bounds));
        }
        let quota_text = read_text(&root.join("mailbox-bytes"), 32)?;
        if quota_text.len() != 1 {
            return Err(Exit::Member(MemberError::Bounds));
        }
        let quota = parse_quota(&quota_text[0])?;
        targets.push(ProvisionTarget {
            pin: RelayPin {
                run: parse_id(&lines[0])?,
                key: parse_id(&lines[1])?,
            },
            endpoint,
            quota,
        });
    }
    if targets.len() != 3 {
        return Err(Exit::Member(MemberError::Bounds));
    }
    targets.sort_by(|left, right| left.pin.key.cmp(&right.pin.key));
    if targets
        .windows(2)
        .any(|pair| pair[0].pin.key == pair[1].pin.key)
    {
        return Err(Exit::Member(MemberError::Bounds));
    }
    let mut names = child_files(capability_dir)?;
    if names.len() != 3 {
        return Err(Exit::Member(MemberError::Bounds));
    }
    names.sort();
    let mut capabilities = Vec::new();
    for target in &targets {
        let expected = hex_id(&target.pin.key);
        let path = names
            .iter()
            .find(|path| path.file_name().and_then(|name| name.to_str()) == Some(expected.as_str()))
            .ok_or(Exit::Member(MemberError::Bounds))?;
        let mut bytes = read_exact(path, 32, true)?;
        if bytes.len() != 32 {
            bytes.zeroize();
            return Err(Exit::Member(MemberError::Bounds));
        }
        let mut secret = [0u8; 32];
        secret.copy_from_slice(&bytes);
        bytes.zeroize();
        capabilities.push(Secret32::from_bytes(secret));
        secret.zeroize();
    }
    Ok((targets, capabilities))
}

fn routed(session: &Session) -> Result<(ClientConfig, AuthenticatedDescriptor), Exit> {
    let config = session
        .configs
        .routing(&session.db, &session.member)
        .map_err(Exit::Member)?;
    let local = session
        .configs
        .load(&session.db, &session.member)
        .map_err(Exit::Member)?
        .ok_or(Exit::Member(MemberError::Sealed))?;
    let wire = local
        .self_wire
        .as_ref()
        .ok_or(Exit::Member(MemberError::Sealed))?;
    let self_route = open_descriptor(&session.member.identity, &session.member.roster, wire)
        .map_err(Exit::Client)?;
    Ok((config, self_route))
}

fn print_reference(session: &Session) -> Result<(), Exit> {
    match session.db.config_reference().map_err(Exit::Client)? {
        Some(reference) => {
            println!(
                "config revision={} hash={}",
                reference.revision(),
                hex_id(reference.hash())
            );
        }
        None => println!("config absent=1"),
    }
    Ok(())
}

fn print_logical(db: &ClientStore, logical: &RecoveryLogical) -> Result<(), Exit> {
    let recipients = db.recover_recipients(&logical.key).map_err(Exit::Client)?;
    let needs_route = recipients
        .iter()
        .filter(|recipient| recipient.needs_route)
        .count();
    println!(
        "request message={} digest={} needs_route={}",
        hex_id(&logical.key.message),
        hex_id(&logical.digest),
        needs_route
    );
    Ok(())
}

fn logical_page(db: &ClientStore) -> Result<Vec<RecoveryLogical>, Exit> {
    page_rows(|after| db.recover_logical(after, PAGE), usize::MAX)
}

fn uploads_for(db: &ClientStore, key: &LogicalKey) -> Result<Vec<RecoveryUpload>, Exit> {
    let rows = page_rows(|after| db.recover_uploads(after, PAGE), usize::MAX)?;
    Ok(rows
        .into_iter()
        .filter(|upload| upload.key == *key)
        .collect())
}

fn page_rows<T>(
    mut page: impl FnMut(u64) -> Result<Vec<T>, ClientError>,
    max_rows: usize,
) -> Result<Vec<T>, Exit>
where
    T: Cursor,
{
    let mut after = 0;
    let mut rows = Vec::new();
    loop {
        let batch = page(after).map_err(Exit::Client)?;
        if batch.is_empty() {
            break;
        }
        let next = batch.last().map(Cursor::cursor).unwrap_or(after);
        if next <= after {
            return Err(Exit::Client(ClientError::Storage));
        }
        if rows.len().saturating_add(batch.len()) > max_rows {
            return Err(Exit::Client(ClientError::Capacity));
        }
        let short = batch.len() < usize::from(PAGE);
        rows.extend(batch);
        if short {
            break;
        }
        after = next;
    }
    Ok(rows)
}

trait Cursor {
    fn cursor(&self) -> u64;
}

macro_rules! cursor_row {
    ($ty:ty) => {
        impl Cursor for $ty {
            fn cursor(&self) -> u64 {
                self.cursor
            }
        }
    };
}

cursor_row!(RecoveryLogical);
cursor_row!(loki_relay_client::IncomingOriginal);
cursor_row!(loki_relay_client::AckLink);
cursor_row!(RecoveryUpload);
cursor_row!(RouteCursor);
cursor_row!(PendingDownload);
cursor_row!(DownloadRejection);
cursor_row!(SourceRejection);

impl Cursor for DiagnosticSample {
    fn cursor(&self) -> u64 {
        u64::try_from(self.id).unwrap_or(0)
    }
}

fn child_directories(path: &Path) -> Result<Vec<PathBuf>, Exit> {
    let mut found = Vec::new();
    for entry in read_children(path)? {
        let metadata = fs::symlink_metadata(&entry).map_err(|_| Exit::Member(MemberError::Io))?;
        if metadata.is_dir() {
            found.push(entry);
        } else {
            return Err(Exit::Member(MemberError::Bounds));
        }
    }
    if found.len() != 3 {
        found.clear();
        return Err(Exit::Member(MemberError::Bounds));
    }
    Ok(found)
}

fn child_files(path: &Path) -> Result<Vec<PathBuf>, Exit> {
    let mut found = Vec::new();
    for entry in read_children(path)? {
        let metadata = fs::symlink_metadata(&entry).map_err(|_| Exit::Member(MemberError::Io))?;
        if !metadata.is_file() {
            return Err(Exit::Member(MemberError::Bounds));
        }
        private_file(&metadata)?;
        found.push(entry);
    }
    Ok(found)
}

fn read_children(path: &Path) -> Result<Vec<PathBuf>, Exit> {
    let metadata = fs::symlink_metadata(path).map_err(|_| Exit::Member(MemberError::Io))?;
    if !metadata.is_dir() {
        return Err(Exit::Member(MemberError::Permissions));
    }
    let entries = fs::read_dir(path).map_err(|_| Exit::Member(MemberError::Io))?;
    entries
        .map(|entry| {
            entry
                .map(|entry| entry.path())
                .map_err(|_| Exit::Member(MemberError::Io))
        })
        .collect()
}

fn read_text(path: &Path, max: usize) -> Result<Vec<String>, Exit> {
    let bytes = read_exact(path, max, false)?;
    let text = std::str::from_utf8(&bytes).map_err(|_| Exit::Member(MemberError::Bounds))?;
    if text.contains('\0') {
        return Err(Exit::Member(MemberError::Bounds));
    }
    Ok(text.lines().map(str::to_owned).collect())
}

fn read_exact(path: &Path, max: usize, private: bool) -> Result<zeroize::Zeroizing<Vec<u8>>, Exit> {
    let metadata = fs::symlink_metadata(path).map_err(|_| Exit::Member(MemberError::Io))?;
    if !metadata.is_file() || metadata.len() > max as u64 {
        return Err(Exit::Member(if metadata.is_file() {
            MemberError::Bounds
        } else {
            MemberError::Permissions
        }));
    }
    if private {
        private_file(&metadata)?;
    }
    let mut file = fs::File::open(path).map_err(|_| Exit::Member(MemberError::Io))?;
    let mut bytes = vec![0; metadata.len() as usize];
    io::Read::read_exact(&mut file, &mut bytes).map_err(|_| Exit::Member(MemberError::Io))?;
    Ok(zeroize::Zeroizing::new(bytes))
}

fn private_file(metadata: &fs::Metadata) -> Result<(), Exit> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        extern "C" {
            fn geteuid() -> u32;
        }
        let uid = unsafe { geteuid() };
        if metadata.uid() != uid || metadata.mode() & 0o077 != 0 || metadata.nlink() != 1 {
            return Err(Exit::Member(MemberError::Permissions));
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        Err(Exit::Member(MemberError::Unsupported))
    }
}

fn parse_quota(text: &str) -> Result<u64, Exit> {
    let text = text.trim_end_matches(['\r', '\n']);
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(Exit::Member(MemberError::Bounds));
    }
    let quota = text
        .parse::<u64>()
        .map_err(|_| Exit::Member(MemberError::Bounds))?;
    if quota == 0 || quota > i64::MAX as u64 {
        return Err(Exit::Member(MemberError::Bounds));
    }
    Ok(quota)
}

fn parse_id(text: &str) -> Result<Id32, Exit> {
    if text.len() != 64
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(Exit::Member(MemberError::Bounds));
    }
    let mut id = [0u8; 32];
    hex::decode_to_slice(text, &mut id).map_err(|_| Exit::Member(MemberError::Bounds))?;
    Ok(id)
}

fn hex_id(id: &Id32) -> String {
    hex::encode(id)
}

fn digest_hex(bytes: &[u8]) -> String {
    hex::encode(blake3::hash(bytes).as_bytes())
}

fn wipe_test(body: &mut MessageBody) {
    if let Payload::Test(data) = &mut body.payload {
        data.zeroize();
    }
}

fn kind_name(kind: u8) -> String {
    match kind {
        1 => "test".to_owned(),
        2 => "received".to_owned(),
        other => other.to_string(),
    }
}

fn session_text(session: Option<&Id32>) -> String {
    session.map(hex_id).unwrap_or_else(|| "-".to_owned())
}

fn readiness_name(readiness: CandidateReadiness) -> &'static str {
    match readiness {
        CandidateReadiness::Ready => "ready",
        CandidateReadiness::Pending => "pending",
    }
}

fn member_list(ids: &[u16]) -> String {
    if ids.is_empty() {
        "-".to_owned()
    } else {
        ids.iter()
            .map(|id| id.to_string())
            .collect::<Vec<_>>()
            .join(",")
    }
}

fn now_ms() -> Result<u64, Exit> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Exit::Member(MemberError::Io))?
        .as_millis();
    u64::try_from(millis).map_err(|_| Exit::Client(ClientError::Capacity))
}

fn runtime() -> Result<RelayRuntime, Exit> {
    RelayRuntime::new().map_err(|_| Exit::Member(MemberError::Io))
}

#[cfg(test)]
mod pagination_tests {
    use super::*;

    fn sample(id: i64) -> DiagnosticSample {
        DiagnosticSample {
            id,
            relay_key: [0; 32],
            run: [0; 32],
            mailbox: [0; 32],
            sequence: 1,
            sample_len: 0,
        }
    }

    #[test]
    fn diagnostic_pagination_enforces_capacity() {
        for count in [399, 400, 401] {
            let rows = page_rows(
                |after| {
                    Ok(((after + 1)..=count.min(after + u64::from(PAGE)))
                        .map(|id| sample(id as i64))
                        .collect())
                },
                DIAGNOSTIC_ROW_BOUND,
            );
            if count <= 400 {
                assert_eq!(rows.ok().unwrap().len(), count as usize);
            } else {
                assert!(matches!(rows, Err(Exit::Client(ClientError::Capacity))));
            }
        }
    }

    #[test]
    fn diagnostic_pagination_rejects_invalid_or_stalled_cursors() {
        for id in [-1, 0] {
            let rows = page_rows(|_| Ok(vec![sample(id)]), DIAGNOSTIC_ROW_BOUND);
            assert!(matches!(rows, Err(Exit::Client(ClientError::Storage))));
        }
        let rows = page_rows(
            |_| Ok((1..=i64::from(PAGE)).map(sample).collect()),
            DIAGNOSTIC_ROW_BOUND,
        );
        assert!(matches!(rows, Err(Exit::Client(ClientError::Storage))));
    }
}
