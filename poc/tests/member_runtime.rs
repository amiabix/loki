//! Real HTTP checks for the Rust member-runtime migration slice.

use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::TcpStream,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};

const OTHER: &str = "a1b2c3d4e5f60708";
const ALICE_VAULT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const BOB_VAULT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

struct Fixture(PathBuf);

impl Fixture {
    fn new() -> Self {
        let mut nonce = [0u8; 8];
        OsRng.fill_bytes(&mut nonce);
        let path = std::env::temp_dir().join(format!(
            "loki-member-runtime-{}-{}",
            std::process::id(),
            hex::encode(nonce)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn profile(&self, account: &str, name: &str, passphrase: &str) -> String {
        let root = if account == "default" {
            self.0.clone()
        } else {
            self.0.join("accounts").join(account)
        };
        fs::create_dir_all(&root).unwrap();
        let pass = root.join("test-passphrase");
        fs::write(&pass, passphrase).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&pass, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let output = Command::new(env!("CARGO_BIN_EXE_loki_setup_member"))
            .args([
                "profile-create",
                root.to_str().unwrap(),
                pass.to_str().unwrap(),
                name,
            ])
            .output()
            .unwrap();
        fs::remove_file(pass).unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let profile: Value = serde_json::from_slice(&output.stdout).unwrap();
        profile["id"].as_str().unwrap().to_owned()
    }

    fn vault(&self, account: &str, vault: &str, profile: &str) {
        let root = if account == "default" {
            self.0.clone()
        } else {
            self.0.join("accounts").join(account)
        };
        let folder = root.join("vaults").join(vault);
        fs::create_dir_all(&folder).unwrap();
        fs::write(
            folder.join("membership.json"),
            serde_json::to_vec(&json!({
                "vault": vault, "slot": 1, "name": "Saved vault", "profile": profile,
                "threshold": 2, "members": 3, "network": "regtest", "birth_height": null
            }))
            .unwrap(),
        )
        .unwrap();
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Server {
    child: Child,
    port: u16,
    token: String,
}

impl Server {
    fn start(root: &Path) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_loki_member_runtime"))
            .args([
                "--data",
                root.to_str().unwrap(),
                "--port",
                "0",
                "--network",
                "regtest",
            ])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut line = String::new();
        BufReader::new(child.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        let link = line
            .trim()
            .strip_prefix("Member runtime migration slice API: http://127.0.0.1:")
            .expect(&line);
        let (port, token) = link.split_once(" token=").unwrap();
        Self {
            child,
            port: port.parse().unwrap(),
            token: token.to_owned(),
        }
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        value: Option<Value>,
        token: Option<&str>,
        host: Option<&str>,
        origin: Option<&str>,
    ) -> (u16, Value) {
        let body = value.map(|v| v.to_string()).unwrap_or_default();
        let mut stream = TcpStream::connect(("127.0.0.1", self.port)).unwrap();
        stream.write_all(format!(
            "{method} {path} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nContent-Type: application/json\r\nContent-Length: {}\r\n{}{}\r\n{}",
            host.unwrap_or(&format!("127.0.0.1:{}", self.port)), body.len(),
            token.map(|t| format!("X-Loki-Token: {t}\r\n")).unwrap_or_default(),
            origin.map(|o| format!("Origin: {o}\r\n")).unwrap_or_default(), body
        ).as_bytes()).unwrap();
        let mut raw = String::new();
        stream.read_to_string(&mut raw).unwrap();
        let (headers, body) = raw.split_once("\r\n\r\n").unwrap();
        let status = headers.split_whitespace().nth(1).unwrap().parse().unwrap();
        (status, serde_json::from_str(body).unwrap_or(Value::Null))
    }

    fn post(&self, path: &str, value: Value) -> (u16, Value) {
        self.request("POST", path, Some(value), Some(&self.token), None, None)
    }

    fn get(&self, path: &str) -> (u16, Value) {
        self.request("GET", path, None, Some(&self.token), None, None)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn opens_legacy_profiles_and_keeps_vaults_bound_to_the_selected_account() {
    let root = Fixture::new();
    let alice_id = root.profile("default", "Alice", "alice passphrase");
    let bob_id = root.profile(OTHER, "Bob", "bob passphrase");
    root.vault("default", ALICE_VAULT, &alice_id);
    root.vault(OTHER, BOB_VAULT, &bob_id);
    let server = Server::start(&root.0);

    assert_eq!(server.get("/api/status").1["phase"], "locked");
    assert_eq!(
        server
            .post("/api/unlock", json!({"passphrase":"wrong passphrase"}))
            .0,
        400
    );
    assert_eq!(
        server
            .post("/api/unlock", json!({"passphrase":"alice passphrase"}))
            .1["profile"]["name"],
        "Alice"
    );
    let (_, home) = server.get("/api/status");
    assert_eq!(home["vaults"][0]["vault"], ALICE_VAULT);
    assert!(home["vaults"][0].get("address").is_none());
    assert_eq!(
        server.get(&format!("/api/status?vault={ALICE_VAULT}")).0,
        501
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let other = root.0.join("accounts").join(OTHER);
        fs::set_permissions(&other, fs::Permissions::from_mode(0o755)).unwrap();
    }
    assert_eq!(
        server
            .post("/api/account-switch", json!({"account":OTHER}))
            .1["active"],
        OTHER
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(root.0.join("accounts").join(OTHER))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
    }
    assert_eq!(server.get("/api/status").1["phase"], "locked");
    assert_eq!(
        server.get(&format!("/api/status?vault={ALICE_VAULT}")).0,
        501
    );
    assert_eq!(
        server
            .post("/api/unlock", json!({"passphrase":"alice passphrase"}))
            .0,
        400
    );
    assert_eq!(
        server
            .post("/api/unlock", json!({"passphrase":"bob passphrase"}))
            .1["profile"]["name"],
        "Bob"
    );
    let (_, home) = server.get("/api/status");
    assert_eq!(home["vaults"][0]["vault"], BOB_VAULT);
    assert_eq!(
        server.post("/api/lock", json!({})).1,
        json!({"locked":true})
    );
    assert_eq!(server.get("/api/status").1["phase"], "locked");
}

#[test]
fn rejects_untrusted_http_and_a_second_runtime_on_the_same_root() {
    let root = Fixture::new();
    let server = Server::start(&root.0);
    assert_eq!(
        server
            .request("GET", "/api/status", None, None, None, None)
            .0,
        403
    );
    assert_eq!(
        server
            .request(
                "GET",
                "/api/status",
                None,
                Some(&server.token),
                Some("attacker.example"),
                None
            )
            .0,
        403
    );
    assert_eq!(
        server
            .request(
                "POST",
                "/api/profile-create",
                Some(json!({"name":"Alice", "passphrase":"secret"})),
                Some(&server.token),
                None,
                Some("http://attacker.example")
            )
            .0,
        403
    );
    let second = Command::new(env!("CARGO_BIN_EXE_loki_member_runtime"))
        .args(["--data", root.0.to_str().unwrap(), "--port", "0"])
        .output()
        .unwrap();
    assert!(!second.status.success());
    assert_eq!(server.get("/api/status").1["phase"], "new_profile");
}

#[test]
fn rejects_a_symlinked_account_root_before_opening_any_profile() {
    let root = Fixture::new();
    let elsewhere = Fixture::new();
    root.profile("default", "Alice", "alice passphrase");
    #[cfg(unix)]
    std::os::unix::fs::symlink(&elsewhere.0, root.0.join("accounts")).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_loki_member_runtime"))
        .args(["--data", root.0.to_str().unwrap(), "--port", "0"])
        .output()
        .unwrap();
    assert!(!output.status.success());
}

#[test]
fn rejects_an_oversized_membership_before_starting_the_service() {
    let root = Fixture::new();
    let id = root.profile("default", "Alice", "alice passphrase");
    root.vault("default", ALICE_VAULT, &id);
    let mut membership: Value = serde_json::from_slice(
        &fs::read(
            root.0
                .join("vaults")
                .join(ALICE_VAULT)
                .join("membership.json"),
        )
        .unwrap(),
    )
    .unwrap();
    membership["ignored"] = json!("x".repeat(4096));
    fs::write(
        root.0
            .join("vaults")
            .join(ALICE_VAULT)
            .join("membership.json"),
        membership.to_string(),
    )
    .unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_loki_member_runtime"))
        .args(["--data", root.0.to_str().unwrap(), "--port", "0"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut exited = false;
    for _ in 0..20 {
        if child.try_wait().unwrap().is_some() {
            exited = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    if !exited {
        child.kill().unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("membership is too large"));
}

#[test]
fn rejects_explicitly_malformed_legacy_membership_fields() {
    for (field, invalid) in [
        ("network", Value::Null),
        ("threshold", json!("2")),
        ("transport", json!("surprise")),
        ("birth_height", json!(4465026)),
    ] {
        let root = Fixture::new();
        let id = root.profile("default", "Alice", "alice passphrase");
        root.vault("default", ALICE_VAULT, &id);
        let path = root
            .0
            .join("vaults")
            .join(ALICE_VAULT)
            .join("membership.json");
        let mut membership: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        membership[field] = invalid;
        fs::write(path, membership.to_string()).unwrap();
        let mut child = Command::new(env!("CARGO_BIN_EXE_loki_member_runtime"))
            .args(["--data", root.0.to_str().unwrap(), "--port", "0"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut exited = false;
        for _ in 0..20 {
            if child.try_wait().unwrap().is_some() {
                exited = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        if !exited {
            child.kill().unwrap();
        }
        let output = child.wait_with_output().unwrap();
        assert!(exited, "malformed {field} was accepted");
        assert!(!output.status.success());
    }
}

#[cfg(unix)]
#[test]
fn tightens_permissions_on_an_existing_account_root_before_unlock() {
    use std::os::unix::fs::PermissionsExt;
    let root = Fixture::new();
    root.profile("default", "Alice", "alice passphrase");
    fs::set_permissions(&root.0, fs::Permissions::from_mode(0o755)).unwrap();
    let server = Server::start(&root.0);
    assert_eq!(
        fs::metadata(&root.0).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert_eq!(
        server
            .post("/api/unlock", json!({"passphrase":"alice passphrase"}))
            .0,
        200
    );
}

#[cfg(unix)]
#[test]
fn respects_the_existing_python_installation_lock() {
    let root = Fixture::new();
    let mut python = Command::new("python3")
        .args(["-c", "import fcntl,sys,time; f=open(sys.argv[1],'a+b'); fcntl.flock(f,fcntl.LOCK_EX); print('held',flush=True); time.sleep(5)",
               root.0.join(".accounts.lock").to_str().unwrap()])
        .stdout(Stdio::piped()).spawn().unwrap();
    let mut line = String::new();
    BufReader::new(python.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert_eq!(line.trim(), "held");
    let output = Command::new(env!("CARGO_BIN_EXE_loki_member_runtime"))
        .args(["--data", root.0.to_str().unwrap(), "--port", "0"])
        .output()
        .unwrap();
    let _ = python.kill();
    let _ = python.wait();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("already open"));
}

#[cfg(unix)]
#[test]
fn a_locked_target_account_cannot_change_the_active_account() {
    let root = Fixture::new();
    root.profile("default", "Alice", "alice passphrase");
    root.profile(OTHER, "Bob", "bob passphrase");
    let server = Server::start(&root.0);
    let mut python = Command::new("python3")
        .args(["-c", "import fcntl,sys,time; f=open(sys.argv[1],'a+b'); fcntl.flock(f,fcntl.LOCK_EX); print('held',flush=True); time.sleep(5)",
               root.0.join("accounts").join(OTHER).join(".app.lock").to_str().unwrap()])
        .stdout(Stdio::piped()).spawn().unwrap();
    let mut line = String::new();
    BufReader::new(python.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    assert_eq!(line.trim(), "held");
    assert_eq!(
        server
            .post("/api/account-switch", json!({"account":OTHER}))
            .0,
        400
    );
    assert_eq!(server.get("/api/accounts").1["active"], "default");
    assert!(!root.0.join("active-account").exists());
    let _ = python.kill();
    let _ = python.wait();
}

#[test]
fn refuses_a_large_profile_request() {
    let root = Fixture::new();
    let server = Server::start(&root.0);
    let (status, _) = server.post(
        "/api/profile-create",
        json!({
            "name":"Alice", "passphrase":"x".repeat(5000)
        }),
    );
    assert_eq!(status, 413);
    assert_eq!(server.get("/api/status").1["phase"], "new_profile");
}

#[test]
fn creates_an_account_without_exposing_its_profile_when_locked() {
    let root = Fixture::new();
    let server = Server::start(&root.0);
    assert_eq!(
        server
            .post(
                "/api/profile-create",
                json!({"name":"Alice", "passphrase":"secret phrase"})
            )
            .0,
        200
    );
    let (_, accounts) = server.get("/api/accounts");
    assert_eq!(accounts["active"], "default");
    assert_eq!(accounts["accounts"][0]["name"], "Existing account");
    let (_, created) = server.post(
        "/api/account-create",
        json!({"name":"Bob", "passphrase":"other secret phrase"}),
    );
    let account = created["active"].as_str().unwrap();
    assert_eq!(account.len(), 16);
    assert_eq!(server.get("/api/status").1["phase"], "home");
    assert_eq!(server.post("/api/lock", json!({})).0, 200);
    assert_eq!(
        server.get("/api/accounts").1["accounts"][1]["name"],
        format!("Account {}", &account[..8])
    );
    assert_eq!(server.get("/api/status").1["phase"], "locked");
}
