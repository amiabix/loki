//! Guided two-member recovery sweep. Secrets enter through the terminal and travel
//! to the existing native setup/payment commands over inherited anonymous pipes.
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use serde_json::Value;
use zeroize::Zeroizing;

struct EchoGuard(Option<libc::termios>);

impl EchoGuard {
    fn hide() -> io::Result<Self> {
        let fd = libc::STDIN_FILENO;
        // SAFETY: These calls only inspect and update the terminal attached to stdin.
        if unsafe { libc::isatty(fd) } != 1 {
            return Ok(Self(None));
        }
        let mut old = std::mem::MaybeUninit::<libc::termios>::uninit();
        // SAFETY: `old` points to writable termios storage, and `fd` is valid stdin.
        if unsafe { libc::tcgetattr(fd, old.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: tcgetattr initialized `old` after returning zero.
        let old = unsafe { old.assume_init() };
        let mut hidden = old;
        hidden.c_lflag &= !libc::ECHO;
        // SAFETY: `hidden` is a valid termios value obtained from this terminal.
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &hidden) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(Some(old)))
    }
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        if let Some(old) = self.0.as_ref() {
            // SAFETY: Restore the same terminal's original attributes on every exit path.
            unsafe { libc::tcsetattr(libc::STDIN_FILENO, libc::TCSANOW, old) };
        }
    }
}

fn input(prompt: &str, hidden: bool) -> Result<Zeroizing<String>, String> {
    print!("{prompt}");
    io::stdout().flush().map_err(|e| e.to_string())?;
    let echo = if hidden {
        Some(EchoGuard::hide().map_err(|e| e.to_string())?)
    } else {
        None
    };
    let mut line = Zeroizing::new(String::new());
    let count = io::stdin()
        .lock()
        .take(4097)
        .read_line(&mut line)
        .map_err(|e| e.to_string())?;
    if count == 0 {
        return Err("recovery input ended".into());
    }
    if count > 4096 {
        return Err("recovery input is too long".into());
    }
    drop(echo);
    if hidden {
        println!();
    }
    while line.ends_with(['\r', '\n']) {
        line.pop();
    }
    Ok(line)
}

struct SecretPipe {
    reader: OwnedFd,
    writer: File,
    value: Zeroizing<String>,
}

impl SecretPipe {
    fn new(value: &str) -> Result<Self, String> {
        let mut fds = [0; 2];
        // SAFETY: `fds` is writable storage for exactly two file descriptors.
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error().to_string());
        }
        // SAFETY: Successful pipe returned two owned descriptors.
        let reader = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let writer = unsafe { OwnedFd::from_raw_fd(fds[1]) };
        for fd in &fds {
            // SAFETY: Mark both ends close-on-exec before any child is spawned.
            if unsafe { libc::fcntl(*fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
                return Err(io::Error::last_os_error().to_string());
            }
        }
        let writer = File::from(writer);
        Ok(Self {
            reader,
            writer,
            value: Zeroizing::new(value.to_owned()),
        })
    }

    fn path(&self) -> String {
        format!("/dev/fd/{}", self.reader.as_raw_fd())
    }
}

fn spawn(
    binary: &Path,
    args: &[String],
    mut secrets: Vec<SecretPipe>,
    sign: bool,
) -> Result<Child, String> {
    let fds: Vec<RawFd> = secrets
        .iter()
        .map(|secret| secret.reader.as_raw_fd())
        .collect();
    let mut command = Command::new(binary);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if sign {
        command.stdin(Stdio::piped());
    }
    // SAFETY: In the child before exec, fcntl is async-signal-safe. Only the
    // read endpoints for this command have CLOEXEC cleared; writers stay closed.
    unsafe {
        command.pre_exec(move || {
            for fd in &fds {
                let flags = libc::fcntl(*fd, libc::F_GETFD);
                if flags < 0 || libc::fcntl(*fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let mut child = command.spawn().map_err(|e| e.to_string())?;
    for mut secret in secrets.drain(..) {
        drop(secret.reader);
        if let Err(error) = secret.writer.write_all(secret.value.as_bytes()) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!("native recovery secret channel closed: {error}"));
        }
        drop(secret.writer);
    }
    Ok(child)
}

fn output(mut child: Child, timeout: Duration, action: &str) -> Result<String, String> {
    let stdout = child.stdout.take().ok_or("native output channel closed")?;
    let stderr = child.stderr.take().ok_or("native error channel closed")?;
    let out_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let err_reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let started = std::time::Instant::now();
    let status = loop {
        let status = match child.try_wait() {
            Ok(status) => status,
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = out_reader.join();
                let _ = err_reader.join();
                return Err(error.to_string());
            }
        };
        if let Some(status) = status {
            break status;
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            let _ = out_reader.join();
            let _ = err_reader.join();
            return Err(format!("{action} timed out"));
        }
        thread::sleep(Duration::from_millis(25));
    };
    let stdout = out_reader
        .join()
        .map_err(|_| "native output reader stopped")?
        .map_err(|e| e.to_string())?;
    let stderr = err_reader
        .join()
        .map_err(|_| "native error reader stopped")?
        .map_err(|e| e.to_string())?;
    if stdout.len() > 1024 * 1024 || stderr.len() > 1024 * 1024 {
        return Err(format!("{action} returned too much output"));
    }
    if !status.success() {
        return Err(String::from_utf8_lossy(&stderr).trim().to_owned());
    }
    String::from_utf8(stdout)
        .map(|text| text.trim().to_owned())
        .map_err(|e| e.to_string())
}

fn command(
    binary: &Path,
    action: &str,
    mut args: Vec<String>,
    secret: &str,
    timeout: Duration,
) -> Result<String, String> {
    let pipe = SecretPipe::new(secret)?;
    args.insert(1, pipe.path());
    args.insert(0, action.into());
    output(spawn(binary, &args, vec![pipe], false)?, timeout, action)
}

fn restore(
    setup: &Path,
    owner: &Path,
    card: &Path,
    words: &str,
    passphrase: &str,
) -> Result<String, String> {
    let pass = SecretPipe::new(passphrase)?;
    let mnemonic = SecretPipe::new(words)?;
    let args = vec![
        "restore".into(),
        owner.display().to_string(),
        pass.path(),
        card.display().to_string(),
        mnemonic.path(),
    ];
    output(
        spawn(setup, &args, vec![pass, mnemonic], false)?,
        Duration::from_secs(180),
        "restore",
    )
}

fn card_copy(source: &Path, destination: &Path) -> Result<(), String> {
    let metadata = fs::metadata(source).map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.len() > 64 * 1024 {
        return Err("Final recovery card is too large or is not a file".into());
    }
    fs::create_dir(destination).map_err(|e| e.to_string())?;
    let mut source = fs::File::open(source).map_err(|e| e.to_string())?;
    let mut target = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(destination.join("vault.card"))
        .map_err(|e| e.to_string())?;
    let copied = io::copy(
        &mut Read::by_ref(&mut source).take(64 * 1024 + 1),
        &mut target,
    )
    .map_err(|e| e.to_string())?;
    if copied > 64 * 1024 {
        return Err("Final recovery card is too large".into());
    }
    Ok(())
}

struct Member {
    slot: u64,
    owner: PathBuf,
    passphrase: Zeroizing<String>,
    roster: Value,
    address: String,
}

fn member(setup: &Path, session: &Path, index: usize) -> Result<Member, String> {
    println!("\nMember {index}");
    let card = input("Final recovery card file: ", false)?;
    let words = input("Your 24 backup words: ", true)?;
    if words.len() > 1024 || words.split_whitespace().count() != 24 {
        return Err("Enter exactly 24 backup words for each member".into());
    }
    let passphrase = input("New unlock passphrase (12+ characters): ", true)?;
    if !(12..=1024).contains(&passphrase.len()) {
        return Err("Use a new passphrase of 12 to 1024 bytes".into());
    }
    let folder = session.join(format!("member-{index}"));
    fs::create_dir(&folder).map_err(|e| e.to_string())?;
    let card_dir = folder.join("card");
    card_copy(Path::new(card.as_str()), &card_dir)?;
    let owner = folder.join("restored");
    let address = restore(setup, &owner, &card_dir, &words, &passphrase)?;
    let roster_path = owner.join("roster.json");
    if !roster_path.is_file() || !owner.join("secrets/activation.sealed").is_file() {
        return Err("Use each member's final spend recovery card".into());
    }
    let roster: Value = serde_json::from_slice(&fs::read(&roster_path).map_err(|e| e.to_string())?)
        .map_err(|e| e.to_string())?;
    let identity: Value = serde_json::from_str(&command(
        setup,
        "identity-public",
        vec![owner.display().to_string()],
        &passphrase,
        Duration::from_secs(180),
    )?)
    .map_err(|e| e.to_string())?;
    if !roster["members"]
        .as_array()
        .is_some_and(|members| members.contains(&identity))
    {
        return Err("Restored member is absent from the certified roster".into());
    }
    let slot = identity["id"]
        .as_u64()
        .ok_or("Restored member has no slot")?;
    Ok(Member {
        slot,
        owner,
        passphrase,
        roster,
        address,
    })
}

struct Signer {
    slot: u64,
    child: Child,
    review: Receiver<Result<String, String>>,
    reader: Option<thread::JoinHandle<()>>,
    errors: Option<thread::JoinHandle<io::Result<Vec<u8>>>>,
}

impl Drop for Signer {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
        if let Some(errors) = self.errors.take() {
            let _ = errors.join();
        }
    }
}

fn sign(payment: &Path, member: &Member, work: &Path, payment_id: &str) -> Result<Signer, String> {
    let pass = SecretPipe::new(&member.passphrase)?;
    let args = vec![
        "sign".into(),
        member.owner.display().to_string(),
        pass.path(),
        member.owner.join("roster.json").display().to_string(),
        work.display().to_string(),
    ];
    let mut child = spawn(payment, &args, vec![pass], true)?;
    let stdout = child
        .stdout
        .take()
        .ok_or("signer produced no review channel")?;
    let stderr = child
        .stderr
        .take()
        .ok_or("signer produced no error channel")?;
    let errors = thread::spawn(move || {
        let mut bytes = Vec::new();
        stderr
            .take(1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
    });
    let (tx, rx) = mpsc::channel();
    let prompt = format!("Type APPROVE {payment_id} to sign:");
    let reader = thread::spawn(move || {
        let mut lines = String::new();
        let mut sent = false;
        for line in BufReader::new(stdout.take(16 * 1024 + 1)).lines() {
            match line {
                Ok(line) => {
                    if !sent {
                        if lines.len() + line.len() > 16 * 1024 {
                            let _ = tx.send(Err("Signer review exceeded its size limit".into()));
                            sent = true;
                            continue;
                        }
                        lines.push_str(&line);
                        lines.push('\n');
                        if line.trim() == prompt {
                            let _ = tx.send(Ok(lines.clone()));
                            sent = true;
                        }
                    }
                }
                Err(error) => {
                    if !sent {
                        let _ = tx.send(Err(error.to_string()));
                    }
                    return;
                }
            }
        }
        if !sent {
            let _ = tx.send(Err("Signing stopped before review".into()));
        }
    });
    Ok(Signer {
        slot: member.slot,
        child,
        review: rx,
        reader: Some(reader),
        errors: Some(errors),
    })
}

fn wait_signer(signer: &mut Signer) -> Result<(), String> {
    let started = std::time::Instant::now();
    loop {
        if let Some(status) = signer.child.try_wait().map_err(|e| e.to_string())? {
            if status.success() {
                return Ok(());
            }
            let errors = signer
                .errors
                .take()
                .ok_or("Signer error channel closed")?
                .join()
                .map_err(|_| "Signer error reader stopped")?
                .map_err(|e| e.to_string())?;
            return Err(format!(
                "Member {} signing failed: {}",
                signer.slot,
                String::from_utf8_lossy(&errors).trim()
            ));
        }
        if started.elapsed() >= Duration::from_secs(180) {
            let _ = signer.child.kill();
            return Err(format!("Member {} signing timed out", signer.slot));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn txid(output: &str) -> Result<&str, String> {
    let value = output
        .split("broadcast txid=")
        .nth(1)
        .and_then(|tail| tail.get(..64))
        .ok_or("The node did not return a broadcast transaction ID")?;
    if !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("The node returned an invalid broadcast transaction ID".into());
    }
    Ok(value)
}

fn sweep(setup: &Path, payment: &Path) -> Result<(), String> {
    let session = tempfile::Builder::new()
        .prefix("loki-recovery-")
        .tempdir()
        .map_err(|e| e.to_string())?;
    println!(
        "Two members need their own final card and 24 words. Each chooses a new unlock passphrase."
    );
    println!("Use one trusted recovery computer together. The old vault is not revoked until funds move.");
    let first = member(setup, session.path(), 1)?;
    let second = member(setup, session.path(), 2)?;
    if first.slot == second.slot {
        return Err("Recovery needs two distinct members".into());
    }
    if first.roster != second.roster || first.address != second.address {
        return Err("The two cards do not restore the same vault".into());
    }
    let roster = loki_poc::member_state::Roster::load(&first.owner.join("roster.json"))?;
    if roster.threshold != 2 || !matches!(roster.members.len(), 3 | 4) {
        return Err("Recovery requires a 2-of-3 or 2-of-4 vault".into());
    }
    let recipient = input("Receive address of your NEW vault: ", false)?;
    if recipient.is_empty() || *recipient == first.address {
        return Err("Enter the receive address of a different vault".into());
    }
    let mut members = [first, second];
    members.sort_by_key(|member| member.slot);
    let pair = members
        .iter()
        .map(|member| char::from_u32(64 + member.slot as u32).unwrap_or('?'))
        .collect::<String>();
    let work = session.path().join("payment");
    command(
        payment,
        "prepare-sweep",
        vec![
            members[0].owner.display().to_string(),
            members[0].owner.join("roster.json").display().to_string(),
            work.display().to_string(),
            recipient.to_string(),
            "sweep".into(),
            pair.clone(),
        ],
        &members[0].passphrase,
        Duration::from_secs(300),
    )?;
    let manifest: Value =
        serde_json::from_slice(&fs::read(work.join("payment.json")).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
    if manifest["vault"] != members[0].roster["vault"]
        || manifest["pair"] != serde_json::json!([members[0].slot, members[1].slot])
        || manifest["change_zat"] != 0
    {
        return Err("Sweep proposal differs from the recovered vault".into());
    }
    let payment_id = manifest["payment"]
        .as_str()
        .filter(|value| value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()))
        .ok_or("Sweep proposal has no payment ID")?;
    let signers: Vec<_> = members
        .iter()
        .map(|member| sign(payment, member, &work, payment_id))
        .collect::<Result<_, _>>()?;
    for signer in &signers {
        let review = signer
            .review
            .recv_timeout(Duration::from_secs(300))
            .map_err(|_| "Signer review timed out")??;
        println!(
            "\nMember {}, check this verified transaction:\n{review}",
            signer.slot
        );
        let approval = input(
            &format!(
                "Member {}, type payment ID {payment_id} to approve: ",
                signer.slot
            ),
            false,
        )?;
        if approval.as_str() != payment_id {
            return Err(format!("Member {} declined the payment", signer.slot));
        }
        // Each sign child still checks its own exact APPROVE line after showing the native review.
        let mut stdin = signer
            .child
            .stdin
            .as_ref()
            .ok_or("Signer approval channel closed")?;
        stdin
            .write_all(format!("APPROVE {payment_id}\n").as_bytes())
            .map_err(|e| e.to_string())?;
    }
    for mut signer in signers {
        wait_signer(&mut signer)?;
    }
    let output = command(
        payment,
        "finish",
        vec![
            members[0].owner.display().to_string(),
            members[0].owner.join("roster.json").display().to_string(),
            work.display().to_string(),
        ],
        &members[0].passphrase,
        Duration::from_secs(900),
    )?;
    let broadcast = txid(&output)?.to_owned();
    println!("\nBroadcast transaction: {broadcast}");
    match command(payment, "verify", vec![members[0].owner.display().to_string(),
        members[0].owner.join("roster.json").display().to_string(), work.display().to_string(), broadcast.clone()],
        &members[0].passphrase, Duration::from_secs(180)) {
        Ok(value) if value.contains(&format!("verified mined txid={broadcast} confirmations=")) => {
            println!("Mined sweep verified. Check the new vault balance in your member app.");
        }
        Ok(_) => println!("Verification incomplete: chain verification did not confirm this sweep. Check the new vault balance after this transaction is mined."),
        Err(error) => println!("Verification incomplete: {error}. Check the new vault balance after this transaction is mined."),
    }
    Ok(())
}

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if !args.is_empty() && !(args.len() == 2 && args[0] == "--rpc") {
        eprintln!("usage: loki_recover [--rpc host:port]");
        std::process::exit(2);
    }
    if args.len() == 2 {
        std::env::set_var("LOKI_RPC", &args[1]);
    }
    let result = std::env::current_exe()
        .map_err(|e| e.to_string())
        .and_then(|self_path| {
            let parent = self_path
                .parent()
                .ok_or("Recovery binary has no parent directory")?;
            let setup = parent.join("loki_setup_member");
            let payment = parent.join("loki_member_payment");
            if !setup.is_file() || !payment.is_file() {
                return Err("Install the Loki member tools beside loki_recover".into());
            }
            sweep(&setup, &payment)
        });
    if let Err(error) = result {
        eprintln!("Recovery stopped: {error}");
        std::process::exit(1);
    }
}
