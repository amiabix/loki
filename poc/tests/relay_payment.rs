#![cfg(feature = "relay-communication")]
//! Relay payment commands stay off the file mailbox unless file transport is selected.

use loki_poc::{
    relay_courier::RelayCourier,
    setup_transport::Identity,
    signing_session::{AttemptId, EnvelopeRoute, MessageKind, SessionContext, SessionCourier},
};
use loki_relay_client::reopen_committed;
use loki_relay_protocol::types::Payload;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    net::TcpStream,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::OnceLock,
    thread,
    time::{Duration, Instant},
};

const PASS: &str = " synthetic setup pass ";
static CERTIFIED: OnceLock<PathBuf> = OnceLock::new();

#[test]
fn relay_flag_is_explicit_and_does_not_create_a_mailbox() {
    let pay = env!("CARGO_BIN_EXE_loki_member_payment");
    let root = std::env::temp_dir().join(format!("loki-relay-pay-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir(&root).unwrap();
    let work = root.join("work");
    fs::create_dir(&work).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&work, fs::Permissions::from_mode(0o700)).unwrap();
    }
    let missing = Command::new(pay)
        .args([
            "sign",
            root.join("missing").to_str().unwrap(),
            root.join("pass").to_str().unwrap(),
            root.join("roster.json").to_str().unwrap(),
            work.to_str().unwrap(),
            "--transport",
            "relay",
        ])
        .output()
        .unwrap();
    assert!(!missing.status.success());
    let error = String::from_utf8(missing.stderr).unwrap();
    assert!(error.starts_with("error:"), "{error}");
    assert!(!error.contains("mailbox"), "{error}");
    assert!(!work.join("mailbox").exists());

    let bad = Command::new(pay)
        .args(["sign", "--transport", "postal"])
        .output()
        .unwrap();
    assert!(!bad.status.success());
    let error = String::from_utf8(bad.stderr).unwrap();
    assert!(error.contains("transport must be file or relay"), "{error}");

    let positional = Command::new(pay).args(["sign"]).output().unwrap();
    let error = String::from_utf8(positional.stderr).unwrap();
    assert!(error.contains("sign <member-dir>"), "{error}");
    let missing_fd = Command::new(pay)
        .args(["sign", "--observe-fd"])
        .output()
        .unwrap();
    let error = String::from_utf8(missing_fd.stderr).unwrap();
    assert!(error.contains("missing export descriptor"), "{error}");
    let partial = Command::new(pay)
        .args(["sign", "--observe-fd", "1", "--control-fd", "2"])
        .output()
        .unwrap();
    let error = String::from_utf8(partial.stderr).unwrap();
    assert!(error.contains("export descriptors must include"), "{error}");
    let _ = fs::remove_dir_all(&root);
    let _ = PathBuf::from(pay);
}

struct RelayProcess {
    child: std::process::Child,
}

struct Loopback {
    root: PathBuf,
    members: Vec<PathBuf>,
    passes: Vec<PathBuf>,
    roster: PathBuf,
    relays: Vec<RelayProcess>,
}

impl Drop for Loopback {
    fn drop(&mut self) {
        for relay in &mut self.relays {
            let _ = relay.child.kill();
            let _ = relay.child.wait();
        }
    }
}

fn private(path: &Path, directory: bool) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(if directory { 0o700 } else { 0o600 }),
        )
        .unwrap();
    }
}

fn run_dir() -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "loki-relay-loop-{}-{}",
        std::process::id(),
        hex::encode(Identity::new(1).public().signing)
    ));
    fs::create_dir(&path).unwrap();
    private(&path, true);
    path.canonicalize().unwrap()
}

fn certified_setup() -> &'static PathBuf {
    CERTIFIED.get_or_init(|| {
        let root = run_dir();
        let exchange = root.join("exchange");
        fs::create_dir(&exchange).unwrap();
        let exe = env!("CARGO_BIN_EXE_loki_setup_member");
        let mut public = Vec::new();
        for id in 1..=3 {
            let member = root.join(format!("member-{id}"));
            fs::create_dir(&member).unwrap();
            private(&member, true);
            let pass = member.join("pass");
            fs::write(&pass, format!("{PASS}\r\n")).unwrap();
            private(&pass, false);
            let out = Command::new(exe)
                .args([
                    "identity",
                    member.to_str().unwrap(),
                    &id.to_string(),
                    pass.to_str().unwrap(),
                ])
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "identity: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            public.push(serde_json::from_slice::<Value>(&out.stdout).unwrap());
        }
        let roster = root.join("roster.json");
        fs::write(
            &roster,
            serde_json::to_vec(&serde_json::json!({"vault":hex::encode([71;32]),"members":public}))
                .unwrap(),
        )
        .unwrap();
        let out = Command::new(exe)
            .args(["fingerprint", roster.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(out.status.success(), "fingerprint failed");
        let fingerprint = String::from_utf8(out.stdout).unwrap();
        let mut children = Vec::new();
        for id in 1..=3 {
            let member = root.join(format!("member-{id}"));
            children.push(
                Command::new(exe)
                    .args([
                        "run",
                        member.to_str().unwrap(),
                        member.join("pass").to_str().unwrap(),
                        roster.to_str().unwrap(),
                        exchange.to_str().unwrap(),
                        fingerprint.trim(),
                    ])
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap(),
            );
        }
        let deadline = Instant::now() + Duration::from_secs(25);
        for mut child in children {
            while child.try_wait().unwrap().is_none() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(20));
            }
            if child.try_wait().unwrap().is_none() {
                let _ = child.kill();
            }
            let out = child.wait_with_output().unwrap();
            assert!(
                out.status.success(),
                "certificate exchange: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        root
    })
}

fn server_bin() -> PathBuf {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../communication/target/debug/loki-relay-server");
    if !path.is_file() {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("../communication/Cargo.toml");
        let status = Command::new("cargo")
            .args([
                "build",
                "--manifest-path",
                manifest.to_str().unwrap(),
                "-p",
                "loki-relay-server",
                "--locked",
                "--offline",
                "--bin",
                "loki-relay-server",
            ])
            .status()
            .unwrap();
        assert!(status.success(), "loki-relay-server build failed");
    }
    path.canonicalize().unwrap()
}

fn checked(program: &str, args: &[String]) -> String {
    let output = Command::new(program).args(args).output().unwrap();
    assert!(
        output.status.success(),
        "{} {:?}\n{}",
        program,
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

fn free_port() -> u16 {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.local_addr().unwrap().port()
}

fn wait_port(port: u16, child: &mut std::process::Child, log: &Path) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while Instant::now() < deadline {
        if child.try_wait().unwrap().is_some() {
            break;
        }
        if TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().unwrap(),
            Duration::from_millis(200),
        )
        .is_ok()
        {
            return;
        }
        thread::sleep(Duration::from_millis(30));
    }
    panic!(
        "relay {port} did not accept\n{}",
        fs::read_to_string(log).unwrap_or_default()
    );
}

fn copy_member(source: &Path, id: u16, root: &Path) -> (PathBuf, PathBuf) {
    let member = root.join(format!("member-{id}"));
    fs::create_dir_all(member.join("secrets")).unwrap();
    private(&member, true);
    private(&member.join("secrets"), true);
    for file in ["identity.sealed", "vault.sealed"] {
        let dest = member.join("secrets").join(file);
        fs::copy(source.join(format!("member-{id}/secrets/{file}")), &dest).unwrap();
        private(&dest, false);
    }
    let pass = member.join("pass");
    fs::copy(source.join(format!("member-{id}/pass")), &pass).unwrap();
    private(&pass, false);
    (member, pass)
}

fn start_loopback(mailbox_bytes: u64, total_bytes: u64) -> Loopback {
    let source = certified_setup();
    let root = run_dir();
    let roster = root.join("roster.json");
    fs::copy(source.join("roster.json"), &roster).unwrap();
    let mut members = Vec::new();
    let mut passes = Vec::new();
    for id in 1..=3 {
        let (member, pass) = copy_member(source, id, &root);
        members.push(member);
        passes.push(pass);
    }
    let server = server_bin();
    let member_bin = env!("CARGO_BIN_EXE_loki_relay_member");
    let manifests = root.join("public-manifests");
    let capabilities = root.join("capabilities");
    fs::create_dir(&manifests).unwrap();
    fs::create_dir(&capabilities).unwrap();
    private(&manifests, true);
    private(&capabilities, true);
    let mut relays = Vec::new();
    for index in 1..=3 {
        let port = free_port();
        let relay_root = root.join("relays").join(index.to_string());
        fs::create_dir_all(relay_root.parent().unwrap()).unwrap();
        let staging = root.join(format!("capability-{index}.bin"));
        let mut secret = [0u8; 32];
        secret[0] = index;
        secret[31] = 0x5a;
        fs::write(&staging, secret).unwrap();
        private(&staging, false);
        let init = Command::new(&server)
            .args([
                "init",
                "--root",
                relay_root.to_str().unwrap(),
                "--provision-capability-file",
                staging.to_str().unwrap(),
                "--total-bytes",
                &total_bytes.to_string(),
                "--mailbox-bytes",
                &mailbox_bytes.to_string(),
                "--mailbox-count",
                "3",
                "--listen",
                &format!("127.0.0.1:{port}"),
            ])
            .output()
            .unwrap();
        assert!(
            init.status.success(),
            "init {index}: {}",
            String::from_utf8_lossy(&init.stderr)
        );
        let manifest = fs::read_to_string(relay_root.join("manifest")).unwrap();
        let mut lines = manifest.lines();
        let endpoint = lines.next().unwrap().to_string();
        let _run = lines.next().unwrap();
        let receipt = lines.next().unwrap().to_string();
        assert_eq!(endpoint, format!("http://127.0.0.1:{port}"));
        let projection = manifests.join(index.to_string());
        fs::create_dir(&projection).unwrap();
        private(&projection, true);
        fs::copy(relay_root.join("manifest"), projection.join("manifest")).unwrap();
        fs::write(
            projection.join("mailbox-bytes"),
            format!("{mailbox_bytes}\n"),
        )
        .unwrap();
        let named = capabilities.join(&receipt);
        fs::write(&named, secret).unwrap();
        private(&named, false);
        fs::remove_file(&staging).unwrap();
        let log_path = root.join(format!("serve-{index}.log"));
        let log = fs::File::create(&log_path).unwrap();
        let mut child = Command::new(&server)
            .args([
                "serve",
                "--root",
                relay_root.to_str().unwrap(),
                "--listen",
                &format!("127.0.0.1:{port}"),
            ])
            .stdout(Stdio::null())
            .stderr(log)
            .spawn()
            .unwrap();
        wait_port(port, &mut child, &log_path);
        relays.push(RelayProcess { child });
    }
    let mut inboxes = BTreeMap::<String, u16>::new();
    for (member, pass) in members.iter().zip(&passes) {
        let text = checked(
            member_bin,
            &[
                "provision".into(),
                "--member-root".into(),
                member.to_string_lossy().into(),
                "--passphrase-file".into(),
                pass.to_string_lossy().into(),
                "--roster".into(),
                roster.to_string_lossy().into(),
                "--relay-manifest".into(),
                manifests.to_string_lossy().into(),
                "--provision-capability-files".into(),
                capabilities.to_string_lossy().into(),
            ],
        );
        for line in text.lines() {
            if let Some(rest) = line.strip_prefix("inbox member=") {
                let mut parts = rest.split_whitespace();
                let owner: u16 = parts.next().unwrap().parse().unwrap();
                let mailbox = parts
                    .find(|part| part.starts_with("mailbox="))
                    .unwrap()
                    .trim_start_matches("mailbox=")
                    .to_string();
                assert!(inboxes.insert(mailbox, owner).is_none(), "duplicate inbox");
            }
        }
    }
    assert_eq!(inboxes.len(), 9, "provision did not publish nine inboxes");
    let export_root = root.join("exports");
    fs::create_dir(&export_root).unwrap();
    private(&export_root, true);
    let mut couriers = Vec::new();
    for (id, (member, pass)) in members.iter().zip(&passes).enumerate() {
        let directory = export_root.join((id + 1).to_string());
        fs::create_dir(&directory).unwrap();
        private(&directory, true);
        let text = checked(
            member_bin,
            &[
                "export-config".into(),
                "--member-root".into(),
                member.to_string_lossy().into(),
                "--passphrase-file".into(),
                pass.to_string_lossy().into(),
                "--roster".into(),
                roster.to_string_lossy().into(),
                "--courier-directory".into(),
                directory.to_string_lossy().into(),
            ],
        );
        for line in text.lines() {
            if let Some(name) = line.strip_prefix("courier=") {
                let path = directory.join(name);
                for entry in fs::read_dir(&directory).unwrap() {
                    let entry = entry.unwrap();
                    if entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with(&format!(".{name}."))
                    {
                        fs::remove_file(entry.path()).unwrap();
                    }
                }
                couriers.push(path);
            }
        }
    }
    assert_eq!(couriers.len(), 6, "expected six peer descriptors");
    for courier in &couriers {
        let name = courier.file_name().unwrap().to_string_lossy();
        let peer: u16 = name.split('-').nth(4).unwrap().parse().unwrap();
        let text = checked(
            member_bin,
            &[
                "import-config".into(),
                "--member-root".into(),
                members[(peer - 1) as usize].to_string_lossy().into(),
                "--passphrase-file".into(),
                passes[(peer - 1) as usize].to_string_lossy().into(),
                "--roster".into(),
                roster.to_string_lossy().into(),
                "--courier-file".into(),
                courier.to_string_lossy().into(),
            ],
        );
        assert!(text.contains("imported owner="), "{text}");
    }
    for member in &members {
        assert!(!member.join("mailbox").exists());
        assert!(!member.join("work").exists());
    }
    Loopback {
        root,
        members,
        passes,
        roster,
        relays,
    }
}

fn signing_context() -> SessionContext {
    SessionContext {
        vault: [9; 32],
        payment: [8; 32],
        attempt: AttemptId([7; 32]),
        pair: [1, 2],
    }
}

fn object_hashes(courier: &RelayCourier) -> (Vec<[u8; 32]>, [u8; 32]) {
    let logical = courier.database().recover_logical(0, 10).unwrap();
    assert_eq!(logical.len(), 1);
    let mut hashes = Vec::new();
    for recipient in 1..=3 {
        for requirement in courier
            .database()
            .recover_requirements(&logical[0].key, recipient, None, 100)
            .unwrap()
        {
            hashes.push(requirement.hash);
        }
    }
    assert!(!hashes.is_empty());
    (hashes, logical[0].key.message)
}

fn pump_until(courier: &mut RelayCourier, ready: impl Fn(&mut RelayCourier) -> bool) -> bool {
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        if courier.drive_once().is_err() {
            return false;
        }
        if ready(courier) {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    false
}

#[test]
fn three_loopback_relays_deliver_a_saved_carrier_and_refuse_over_quota() {
    let live = start_loopback(1_048_576, 8_388_608);
    let alice_key = Identity::new(1);
    let bob_key = Identity::new(2);
    let carol_key = Identity::new(3);
    let context = signing_context();
    let wire = alice_key
        .seal_session(
            &bob_key.public(),
            &context,
            MessageKind::Share,
            b"saved-share",
        )
        .unwrap();
    let roster = BTreeMap::from([
        (1, alice_key.public()),
        (2, bob_key.public()),
        (3, carol_key.public()),
    ]);
    let mut alice = RelayCourier::open(&live.members[0], &live.passes[0], &live.roster).unwrap();
    let route = EnvelopeRoute {
        context: &context,
        author: 1,
        recipient: 2,
        kind: MessageKind::Share,
    };
    let published = alice.publish(&route, &wire).unwrap();
    let (hashes, message) = object_hashes(&alice);
    assert_eq!(alice.publish(&route, &wire).unwrap(), published);
    let (again, same_message) = object_hashes(&alice);
    assert_eq!(again, hashes);
    assert_eq!(same_message, message);
    drop(alice);

    let mut bob = RelayCourier::open(&live.members[1], &live.passes[1], &live.roster).unwrap();
    bob.set_events(loki_poc::relay_member::PublicEventWriter::new("loopback", "member-2").unwrap());
    let mut alice = RelayCourier::open(&live.members[0], &live.passes[0], &live.roster).unwrap();
    let mut carol = RelayCourier::open(&live.members[2], &live.passes[2], &live.roster).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut opened = None;
    let mut observed = Vec::new();
    while Instant::now() < deadline && opened.is_none() {
        alice.drive_once().expect("author pump");
        bob.drive_once().expect("recipient pump");
        if let Some(message) = bob
            .receive(&bob_key, &roster, &context, MessageKind::Share, 1)
            .unwrap()
        {
            opened = Some(message);
        }
        observed.extend(bob.pop_events());
        thread::sleep(Duration::from_millis(40));
    }
    let opened = opened.expect("bob did not open the relay carrier");
    observed.extend(bob.pop_events());
    assert_eq!(opened.recipient(), 2);
    assert_eq!(opened.body(), b"saved-share");
    let authenticated = observed
        .iter()
        .find_map(|line| {
            let value: Value = serde_json::from_slice(line).ok()?;
            (value.get("event_type")?.as_str() == Some("session_envelope_authenticated"))
                .then_some(value)
        })
        .expect("inner open did not emit session_envelope_authenticated");
    assert_eq!(authenticated["authenticated_sender"], 1);
    assert_eq!(authenticated["recipient_member"], 2);
    assert_eq!(
        authenticated["kind"],
        serde_json::json!(MessageKind::Share as u8)
    );
    assert_eq!(
        authenticated["envelope_hash"],
        hex::encode(opened.wire_hash())
    );
    assert_eq!(authenticated["vault_id"], hex::encode(context.vault));
    assert_eq!(authenticated["payment_id"], hex::encode(context.payment));
    assert_eq!(authenticated["attempt_id"], hex::encode(context.attempt.0));
    let rendered = String::from_utf8(observed.iter().flatten().copied().collect()).unwrap();
    assert!(!rendered.contains("saved-share"));
    assert!(!bob
        .database()
        .recover_incoming_originals(0, 10)
        .unwrap()
        .is_empty());
    bob.note_application(false, &opened);
    let rejected = bob.pop_events();
    let rejection = rejected
        .iter()
        .find_map(|line| {
            let value: Value = serde_json::from_slice(line).ok()?;
            (value.get("event_type")?.as_str() == Some("application_rejected")).then_some(value)
        })
        .expect("invalid share stayed an authenticated transport object");
    assert_ne!(rejection["event_type"], "receipt_persisted");
    assert_eq!(rejection["envelope_hash"], hex::encode(opened.wire_hash()));
    let rejected_text = String::from_utf8(rejected.iter().flatten().copied().collect()).unwrap();
    assert!(!rejected_text.contains("saved-share"));
    assert!(bob
        .receive(&bob_key, &roster, &context, MessageKind::Share, 1)
        .unwrap()
        .is_none());
    assert!(
        pump_until(&mut carol, |courier| {
            !courier
                .database()
                .recover_incoming_originals(0, 10)
                .unwrap()
                .is_empty()
        }),
        "carol did not persist the opaque carrier"
    );
    assert!(carol
        .receive(&carol_key, &roster, &context, MessageKind::Share, 1)
        .unwrap()
        .is_none());
    for member in &live.members {
        assert!(!member.join("mailbox").exists());
    }
    assert!(!live.root.join("mailbox").exists());
    drop(live);

    let tight = start_loopback(512, 4_096);
    let mut alice = RelayCourier::open(&tight.members[0], &tight.passes[0], &tight.roster).unwrap();
    alice.publish(&route, &wire).unwrap();
    let (saved_hashes, saved_message) = object_hashes(&alice);
    let _ = pump_until(&mut alice, |courier| {
        courier.whole_attempt_stored().unwrap_or(false)
    });
    assert!(!alice.whole_attempt_stored().unwrap_or(false));
    let (kept_hashes, kept_message) = object_hashes(&alice);
    assert_eq!(kept_hashes, saved_hashes);
    assert_eq!(kept_message, saved_message);
    let loaded =
        loki_poc::relay_member::load(&tight.members[0], &tight.passes[0], &tight.roster).unwrap();
    let logical = alice.database().recover_logical(0, 10).unwrap();
    let root = alice
        .database()
        .recover_recipients(&logical[0].key)
        .unwrap()
        .into_iter()
        .find(|recipient| recipient.recipient == 1)
        .unwrap()
        .root_hash;
    let reopened = reopen_committed(
        alice.database(),
        &loaded.roster,
        &loaded.identity,
        &logical[0].key,
        &logical[0].digest,
        &root,
    )
    .expect("capacity refusal deleted the saved carrier");
    match &reopened.message().body().payload {
        Payload::Test(bytes) => {
            let carrier = loki_poc::relay_courier::Carrier::decode(bytes).unwrap();
            assert_eq!(carrier.envelope.as_slice(), wire.as_slice());
        }
        Payload::Received(_) => panic!("saved carrier changed kind"),
    }
    assert!(!tight.members[0].join("mailbox").exists());
}

#[test]
fn a_later_process_reauthenticates_an_accepted_carrier() {
    let live = start_loopback(1_048_576, 8_388_608);
    let alice_key = Identity::new(1);
    let bob_key = Identity::new(2);
    let context = signing_context();
    let wire = alice_key
        .seal_session(
            &bob_key.public(),
            &context,
            MessageKind::Package,
            b"approved-package",
        )
        .unwrap();
    let roster = BTreeMap::from([
        (1, alice_key.public()),
        (2, bob_key.public()),
        (3, Identity::new(3).public()),
    ]);
    let mut alice = RelayCourier::open(&live.members[0], &live.passes[0], &live.roster).unwrap();
    let route = EnvelopeRoute {
        context: &context,
        author: 1,
        recipient: 2,
        kind: MessageKind::Package,
    };
    alice.publish(&route, &wire).unwrap();
    let mut bob = RelayCourier::open(&live.members[1], &live.passes[1], &live.roster).unwrap();
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut first = None;
    while Instant::now() < deadline && first.is_none() {
        alice.drive_once().expect("author pump");
        bob.drive_once().expect("recipient pump");
        first = bob
            .receive(&bob_key, &roster, &context, MessageKind::Package, 1)
            .unwrap();
        thread::sleep(Duration::from_millis(40));
    }
    let first = first.expect("bob did not accept the package");
    assert_eq!(first.body(), b"approved-package");
    let saved = fs::read(live.members[1].join("accepted-carriers")).unwrap();
    let originals = bob
        .database()
        .recover_incoming_originals(0, 10)
        .unwrap()
        .len();
    drop(bob);

    let mut again = RelayCourier::open(&live.members[1], &live.passes[1], &live.roster).unwrap();
    again.set_events(
        loki_poc::relay_member::PublicEventWriter::new("loopback", "member-2").unwrap(),
    );
    assert!(
        again
            .receive(&bob_key, &roster, &context, MessageKind::Package, 1)
            .unwrap()
            .is_none(),
        "an accepted carrier is not a new signing message"
    );
    let reopened = again
        .reopen_accepted(&bob_key, &roster, &context, MessageKind::Package, 1)
        .unwrap()
        .expect("verify could not reauthenticate the accepted package");
    assert_eq!(reopened.body(), b"approved-package");
    assert_eq!(reopened.wire_hash(), first.wire_hash());
    assert_eq!(
        again
            .database()
            .recover_incoming_originals(0, 10)
            .unwrap()
            .len(),
        originals
    );
    assert_eq!(
        fs::read(live.members[1].join("accepted-carriers")).unwrap(),
        saved
    );
    assert!(again.pop_events().is_empty());
}
