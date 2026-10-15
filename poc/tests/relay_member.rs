#![cfg(feature = "relay-communication")]
use loki_poc::{relay_member::load, setup_transport::Identity, state::MemberDir};
use serde_json::Value;
use std::{
    ffi::{OsStr, OsString},
    fs,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::OnceLock,
    thread,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

const PASS: &str = " synthetic setup pass ";
static CERTIFIED: OnceLock<PathBuf> = OnceLock::new();
static CERTIFIED_POLICY: OnceLock<PathBuf> = OnceLock::new();
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
fn scratch() -> PathBuf {
    let p = std::env::temp_dir().join(format!(
        "loki-relay-51-{}-{}",
        std::process::id(),
        hex::encode(Identity::new(1).public().signing)
    ));
    fs::create_dir(&p).unwrap();
    private(&p, true);
    p
}
fn certified_setup() -> &'static PathBuf {
    certified_setup_with_policy(false)
}
fn certified_setup_with_policy(policy: bool) -> &'static PathBuf {
    (if policy { &CERTIFIED_POLICY } else { &CERTIFIED }).get_or_init(|| {
        let root = scratch();
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
            assert!(out.status.success(), "synthetic setup identity failed");
            public.push(serde_json::from_slice::<Value>(&out.stdout).unwrap());
        }
        let roster = root.join("roster.json");
        fs::write(
            &roster,
            serde_json::to_vec(&if policy {
                serde_json::json!({"vault":hex::encode([71;32]),"threshold":2,"members":public})
            } else {
                serde_json::json!({"vault":hex::encode([71;32]),"members":public})
            })
                .unwrap(),
        )
        .unwrap();
        let out = Command::new(exe)
            .args(["fingerprint", roster.to_str().unwrap()])
            .output()
            .unwrap();
        assert!(out.status.success());
        let fp = String::from_utf8(out.stdout).unwrap();
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
                        fp.trim(),
                    ])
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap(),
            );
        }
        let deadline = Instant::now() + Duration::from_secs(25);
        let mut ok = true;
        for mut child in children {
            while child.try_wait().unwrap().is_none() && Instant::now() < deadline {
                thread::sleep(Duration::from_millis(20));
            }
            if child.try_wait().unwrap().is_none() {
                child.kill().unwrap();
            }
            let out = child.wait_with_output().unwrap();
            ok &= out.status.success() && out.stdout.is_empty();
        }
        assert!(
            ok,
            "independent synthetic setup certificate exchange failed"
        );
        root
    })
}
#[test]
fn certified_threshold_two_roster_loads_for_relay() {
    let base = certified_setup_with_policy(true);
    let member = base.join("member-2");
    assert_eq!(load(&member, &member.join("pass"), &base.join("roster.json"))
        .unwrap().identity.public().id, 2);
}
struct Fixture {
    root: PathBuf,
    pass: PathBuf,
    roster: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        Self::with_policy(false)
    }
    fn with_policy(policy: bool) -> Self {
        let base = certified_setup_with_policy(policy);
        let root = scratch();
        let dir = MemberDir::create(&root, "secrets").unwrap();
        for file in ["identity.sealed", "vault.sealed"] {
            let dest = dir.path().join(file);
            fs::copy(base.join("member-2/secrets").join(file), &dest).unwrap();
            private(&dest, false);
        }
        let pass = root.join("pass");
        fs::copy(base.join("member-2/pass"), &pass).unwrap();
        private(&pass, false);
        let roster = root.join("roster.json");
        fs::copy(base.join("roster.json"), &roster).unwrap();
        Self { root, pass, roster }
    }
    fn loaded(&self) -> loki_poc::relay_member::MemberResult<loki_poc::relay_member::LoadedMember> {
        load(&self.root, &self.pass, &self.roster)
    }
    fn state(&self) -> Value {
        let bytes = Zeroizing::new(
            MemberDir::open(&self.root, "secrets")
                .read_sealed("vault.sealed", PASS)
                .unwrap(),
        );
        serde_json::from_slice(&bytes).unwrap()
    }
    fn seal(&self, state: &Value) {
        let d = MemberDir::open(&self.root, "secrets");
        fs::remove_file(d.path().join("vault.sealed")).unwrap();
        d.write_sealed("vault.sealed", &serde_json::to_vec(state).unwrap(), PASS)
            .unwrap();
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.root).unwrap();
    }
}
#[test]
fn certified_member_agrees() {
    let f = Fixture::new();
    let loaded = f.loaded().unwrap();
    let bytes = Zeroizing::new(
        MemberDir::open(&f.root, "secrets")
            .read_sealed("identity.sealed", PASS)
            .unwrap(),
    );
    let old = Identity::from_secret_bytes(&bytes).unwrap().public();
    let public = loaded.identity.public();
    assert_eq!(public.id, old.id);
    assert_eq!(public.signing, old.signing);
    assert_eq!(public.encryption, old.encryption);
    assert_eq!(loaded.roster.members.len(), 3);
    assert_eq!(loaded.roster.members[1], public);
    assert_ne!(
        loki_relay_protocol::types::roster_digest(&loaded.roster)
            .unwrap()
            .as_slice(),
        hex::decode(f.state()["roster_fingerprint"].as_str().unwrap()).unwrap()
    );
    for id in [1, 3] {
        let root = certified_setup().join(format!("member-{id}"));
        assert_eq!(
            load(&root, &root.join("pass"), &f.roster)
                .unwrap()
                .identity
                .public()
                .id,
            id
        );
    }
}

fn refuses(f: &Fixture, code: &str) {
    match f.loaded() {
        Ok(_) => panic!("accepted altered certified fixture"),
        Err(e) => {
            assert_eq!(e.code(), code);
            assert_eq!(format!("{e:?}"), code);
        }
    }
}
fn changed_roster(f: &Fixture, field: &str) {
    let mut roster: Value = serde_json::from_slice(&fs::read(&f.roster).unwrap()).unwrap();
    roster["members"][1][field] = roster["members"][0][field].clone();
    fs::write(&f.roster, serde_json::to_vec(&roster).unwrap()).unwrap();
    let out = Command::new(env!("CARGO_BIN_EXE_loki_setup_member"))
        .args(["fingerprint", f.roster.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(out.status.success());
    let mut state = f.state();
    state["roster_fingerprint"] =
        Value::String(String::from_utf8(out.stdout).unwrap().trim().to_owned());
    f.seal(&state);
}

#[test]
fn certified_member_wrong_passphrase() {
    let f = Fixture::new();
    fs::write(&f.pass, "wrong").unwrap();
    refuses(&f, "member_sealed");
}

#[test]
fn certified_member_wrong_vault() {
    let f = Fixture::new();
    let mut state = f.state();
    state["vault"] = Value::from(hex::encode([9; 32]));
    f.seal(&state);
    refuses(&f, "member_vault");
}

#[test]
fn certified_member_wrong_fingerprint() {
    let f = Fixture::new();
    let mut state = f.state();
    state["roster_fingerprint"] = Value::from(hex::encode([9; 32]));
    f.seal(&state);
    refuses(&f, "member_fingerprint");
}

#[test]
fn certified_member_rejects_sealed_policy_mismatch() {
    for (field, value) in [("threshold", 3), ("members", 4)] {
        let f = Fixture::with_policy(true);
        let mut state = f.state();
        state[field] = Value::from(value);
        f.seal(&state);
        refuses(&f, "member_roster");
    }
}

#[test]
fn certified_member_embedded_identity() {
    let f = Fixture::new();
    let mut state = f.state();
    let mut raw = hex::decode(state["identity_secret"].as_str().unwrap()).unwrap();
    raw[2] ^= 1;
    state["identity_secret"] = Value::from(hex::encode(raw));
    f.seal(&state);
    refuses(&f, "member_identity");
}

#[test]
fn certified_member_sealed_identity() {
    let f = Fixture::new();
    let d = MemberDir::open(&f.root, "secrets");
    let mut raw = Zeroizing::new(d.read_sealed("identity.sealed", PASS).unwrap());
    raw[34] ^= 1;
    fs::remove_file(d.path().join("identity.sealed")).unwrap();
    d.write_sealed("identity.sealed", &raw, PASS).unwrap();
    refuses(&f, "member_identity");
}

#[test]
fn certified_member_own_signing() {
    let f = Fixture::new();
    changed_roster(&f, "signing");
    refuses(&f, "member_identity");
}

#[test]
fn certified_member_own_encryption() {
    let f = Fixture::new();
    changed_roster(&f, "encryption");
    refuses(&f, "member_identity");
}

#[test]
fn certified_member_wrong_version() {
    let f = Fixture::new();
    let mut state = f.state();
    state["version"] = Value::from(1);
    f.seal(&state);
    refuses(&f, "member_markers");
}

#[test]
fn certified_member_wrong_network() {
    let f = Fixture::new();
    let mut state = f.state();
    state["network"] = Value::from("mainnet");
    f.seal(&state);
    refuses(&f, "member_markers");
}

#[test]
fn certified_member_wrong_derivation() {
    let f = Fixture::new();
    let mut state = f.state();
    state["key_derivation"] = Value::from("old");
    f.seal(&state);
    refuses(&f, "member_markers");
}

#[test]
#[cfg(unix)]
fn certified_member_pass_permissions() {
    let f = Fixture::new();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&f.pass, fs::Permissions::from_mode(0o644)).unwrap();
    refuses(&f, "member_permissions");
}

#[test]
#[cfg(unix)]
fn certified_member_sealed_permissions() {
    let f = Fixture::new();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(
        f.root.join("secrets/vault.sealed"),
        fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    refuses(&f, "member_permissions");
}

#[test]
#[cfg(unix)]
fn certified_member_directory_permissions() {
    let f = Fixture::new();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(f.root.join("secrets"), fs::Permissions::from_mode(0o755)).unwrap();
    refuses(&f, "member_permissions");
}

#[test]
#[cfg(unix)]
fn certified_member_pass_symlink() {
    let f = Fixture::new();
    let saved = f.root.join("saved-pass");
    fs::rename(&f.pass, &saved).unwrap();
    std::os::unix::fs::symlink(&saved, &f.pass).unwrap();
    refuses(&f, "member_permissions");
}

#[test]
fn certified_member_sealed_bound() {
    let f = Fixture::new();
    let file = fs::OpenOptions::new()
        .write(true)
        .open(f.root.join("secrets/vault.sealed"))
        .unwrap();
    file.set_len(1024 * 1024 + 1).unwrap();
    refuses(&f, "member_bounds");
}

#[test]
fn certified_member_json_bound() {
    let f = Fixture::new();
    fs::write(&f.roster, vec![b' '; 1024 * 1024 + 1]).unwrap();
    refuses(&f, "member_bounds");
}

#[test]
fn certified_member_pass_bound() {
    let f = Fixture::new();
    fs::write(&f.pass, vec![b'x'; 4097]).unwrap();
    refuses(&f, "member_bounds");
}

#[test]
fn certified_member_json_depth() {
    let f = Fixture::new();
    let mut roster: Value = serde_json::from_slice(&fs::read(&f.roster).unwrap()).unwrap();
    let mut deep = Value::Null;
    for _ in 0..16 {
        deep = serde_json::json!([deep]);
    }
    roster["extra"] = deep;
    fs::write(&f.roster, serde_json::to_vec(&roster).unwrap()).unwrap();
    refuses(&f, "member_bounds");
}

#[test]
fn certified_member_fixed_roster() {
    let f = Fixture::new();
    let mut roster: Value = serde_json::from_slice(&fs::read(&f.roster).unwrap()).unwrap();
    roster["members"][2]["id"] = Value::from(2);
    fs::write(&f.roster, serde_json::to_vec(&roster).unwrap()).unwrap();
    refuses(&f, "member_roster");
}

#[test]
#[cfg(unix)]
fn certified_member_existing_public_root() {
    let f = Fixture::new();
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&f.root, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(f.loaded().is_ok());
}

#[test]
fn certified_member_tampered_seal() {
    let f = Fixture::new();
    let p = f.root.join("secrets/vault.sealed");
    let mut raw = fs::read(&p).unwrap();
    *raw.last_mut().unwrap() ^= 1;
    fs::write(p, raw).unwrap();
    refuses(&f, "member_sealed");
}
#[test]
fn certified_member_malformed_roster() {
    let f = Fixture::new();
    let original: Value = serde_json::from_slice(&fs::read(&f.roster).unwrap()).unwrap();
    for id in [0u64, 4, 256, 65536] {
        let mut roster = original.clone();
        roster["members"][2]["id"] = Value::from(id);
        fs::write(&f.roster, serde_json::to_vec(&roster).unwrap()).unwrap();
        refuses(&f, "member_roster");
    }
    let mut roster = original.clone();
    roster["members"][0]["signing"] = Value::from("00");
    fs::write(&f.roster, serde_json::to_vec(&roster).unwrap()).unwrap();
    refuses(&f, "member_roster");
    let mut roster = original;
    roster["members"].as_array_mut().unwrap().pop();
    fs::write(&f.roster, serde_json::to_vec(&roster).unwrap()).unwrap();
    refuses(&f, "member_roster");
}
#[test]
fn certified_member_binary_pending() {
    let exe = env!("CARGO_BIN_EXE_loki_relay_member");
    for args in [vec![], vec!["root", "pass", "roster"]] {
        let out = Command::new(exe).args(args).output().unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert!(out.stdout.is_empty());
    }
}

fn config_members() -> Vec<loki_poc::relay_member::LoadedMember> {
    use loki_relay_client::CommIdentity;
    use loki_relay_protocol::types::Roster;
    let identities: Vec<_> = (1..=3)
        .map(|id| CommIdentity::from_serialized(&Identity::new(id).to_secret_bytes()).unwrap())
        .collect();
    let roster = Roster {
        vault: [81; 32],
        members: identities.iter().map(|i| i.public()).collect(),
    };
    identities
        .into_iter()
        .map(|identity| loki_poc::relay_member::LoadedMember {
            identity,
            roster: roster.clone(),
        })
        .collect()
}
fn config_descriptor(
    member: &loki_poc::relay_member::LoadedMember,
    revision: u64,
) -> loki_relay_client::Descriptor {
    use loki_relay_client::{Descriptor, DescriptorRelay, Secret32};
    use loki_relay_protocol::types::{roster_digest, RelayPin, RelayRoute};
    Descriptor::new(
        member.roster.vault,
        roster_digest(&member.roster).unwrap(),
        member.identity.public().id,
        revision,
        (1..=3)
            .map(|i| DescriptorRelay {
                route: RelayRoute {
                    pin: RelayPin {
                        key: [i; 32],
                        run: [i + 10; 32],
                    },
                    endpoint: format!("http://127.0.0.1:{}", 3100 + i as u16),
                    mailbox: [i + 20; 32],
                    append_revision: 1,
                },
                append: Secret32::from_bytes([i + 30; 32]),
            })
            .collect(),
    )
}
#[test]
fn sealed_revision_codec_authenticated_association() {
    use loki_poc::relay_member::LocalConfig;
    use loki_relay_client::seal_descriptor;
    let members = config_members();
    let descriptor = config_descriptor(&members[0], 1);
    let wire = seal_descriptor(
        &members[0].identity,
        &members[0].roster,
        &descriptor,
        &members[1].identity.public(),
    )
    .unwrap()
    .wire;
    let mut config = LocalConfig::empty();
    config.import(&members[1], &wire).unwrap();
    let encoded = config.encode(&members[1], 1).unwrap();
    let restored = LocalConfig::decode(&members[1], 1, &encoded).unwrap();
    assert_eq!(
        restored.authenticated(&members[1]).unwrap().peers[0].canonical_body(),
        config.authenticated(&members[1]).unwrap().peers[0].canonical_body()
    );
    assert!(LocalConfig::decode(&members[0], 1, &encoded).is_err());
    assert!(LocalConfig::decode(&members[1], 2, &encoded).is_err());
    assert!(LocalConfig::decode(&members[1], 1, b"opaque bytes").is_err());
    let mut wrong_roster = members[1].roster.clone();
    wrong_roster.vault[0] ^= 1;
    let identity =
        loki_relay_client::CommIdentity::from_serialized(&Identity::new(2).to_secret_bytes())
            .unwrap();
    let wrong = loki_poc::relay_member::LoadedMember {
        identity,
        roster: wrong_roster,
    };
    assert!(restored.authenticated(&wrong).is_err());
}
#[test]
fn sealed_revision_codec_same_body_and_conflict() {
    use loki_poc::relay_member::LocalConfig;
    use loki_relay_client::seal_descriptor;
    let members = config_members();
    let mut config = LocalConfig::empty();
    let descriptor = config_descriptor(&members[0], 2);
    let seal = |d: &loki_relay_client::Descriptor| {
        seal_descriptor(
            &members[0].identity,
            &members[0].roster,
            d,
            &members[1].identity.public(),
        )
        .unwrap()
        .wire
    };
    let wire = seal(&descriptor);
    config.import(&members[1], &wire).unwrap();
    let second = seal(&descriptor);
    assert_ne!(wire, second);
    config.import(&members[1], &second).unwrap();
    assert_eq!(config.peer_wires[0], wire);
    let mut conflict = config_descriptor(&members[0], 2);
    conflict.relays[0].route.mailbox[0] ^= 1;
    assert!(config.import(&members[1], &seal(&conflict)).is_err());
    assert!(config
        .import(&members[1], &seal(&config_descriptor(&members[0], 1)))
        .is_err());
    config
        .import(&members[1], &seal(&config_descriptor(&members[0], 3)))
        .unwrap();
    assert_eq!(
        config.authenticated(&members[1]).unwrap().peers[0]
            .body()
            .revision,
        3
    );
}
#[test]
fn sealed_revision_courier_exact_retry_conflict_and_import() {
    use loki_poc::relay_member::{CourierFile, CourierImport};
    let members = config_members();
    let directory = scratch();
    let courier = CourierFile::prepare(
        &members[0],
        &config_self_descriptor(&members[0], 1),
        &members[1].identity.public(),
    )
    .unwrap();
    let path = courier.publish(&directory).unwrap();
    let saved = fs::read(&path).unwrap();
    assert_eq!(saved, courier.wire());
    courier.publish(&directory).unwrap();
    assert_eq!(fs::read(&path).unwrap(), saved);
    let imported = CourierImport::read(&members[1], &path).unwrap();
    assert_eq!(imported.descriptor().body().owner, 1);
    assert!(CourierImport::read(&members[2], &path).is_err());
    let another = CourierFile::prepare(
        &members[0],
        &config_self_descriptor(&members[0], 1),
        &members[1].identity.public(),
    )
    .unwrap();
    assert!(another.publish(&directory).is_err());
    assert_eq!(fs::read(&path).unwrap(), saved);
    assert!(CourierFile::prepare(
        &members[0],
        &config_self_descriptor(&members[0], 1),
        &members[0].identity.public()
    )
    .is_err());
}
#[test]
fn sealed_revision_courier_name_permissions_symlink_bounds() {
    use loki_poc::relay_member::{CourierFile, CourierImport};
    let members = config_members();
    let directory = scratch();
    let courier = CourierFile::prepare(
        &members[0],
        &config_self_descriptor(&members[0], 1),
        &members[1].identity.public(),
    )
    .unwrap();
    let path = courier.publish(&directory).unwrap();
    let wrong = directory.join("wrong-name.bin");
    fs::copy(&path, &wrong).unwrap();
    private(&wrong, false);
    assert!(CourierImport::read(&members[1], &wrong).is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let links = scratch();
        symlink(&path, links.join(courier.file_name())).unwrap();
        assert!(CourierImport::read(&members[1], &links.join(courier.file_name())).is_err());
        assert!(courier.publish(&links).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(CourierImport::read(&members[1], &path).is_err());
        assert!(courier.publish(&directory).is_err());
        private(&path, false);
    }
    fs::write(&path, vec![0; 65537]).unwrap();
    assert!(CourierImport::read(&members[1], &path).is_err());
}

fn config_self_descriptor(
    member: &loki_poc::relay_member::LoadedMember,
    revision: u64,
) -> loki_relay_client::AuthenticatedDescriptor {
    let wire = loki_relay_client::seal_descriptor(
        &member.identity,
        &member.roster,
        &config_descriptor(member, revision),
        &member.identity.public(),
    )
    .unwrap()
    .wire;
    loki_relay_client::open_descriptor(&member.identity, &member.roster, &wire).unwrap()
}

fn config_owner(
    member: &loki_poc::relay_member::LoadedMember,
) -> loki_poc::relay_member::LocalConfig {
    use loki_relay_client::{OwnerInbox, Secret32};
    let descriptor = config_descriptor(member, 1);
    let self_wire = loki_relay_client::seal_descriptor(
        &member.identity,
        &member.roster,
        &descriptor,
        &member.identity.public(),
    )
    .unwrap()
    .wire;
    let mut config = loki_poc::relay_member::LocalConfig::empty();
    config.self_wire = Some(self_wire);
    config.own = descriptor
        .relays
        .into_iter()
        .enumerate()
        .map(|(i, r)| OwnerInbox {
            route: r.route,
            append: r.append,
            read: Secret32::from_bytes([61 + i as u8; 32]),
            admin: Secret32::from_bytes([71 + i as u8; 32]),
        })
        .collect();
    config
}
#[test]
fn sealed_revision_codec_owner_credentials_requests_and_saved_couriers() {
    use loki_poc::relay_member::{CourierFile, LocalConfig, PendingRequest};
    use loki_relay_client::{ConfigReference, Secret32};
    use loki_relay_protocol::{http::encode_creation, types::Creation};
    let members = config_members();
    let mut config = config_owner(&members[0]);
    let auth = loki_relay_client::open_descriptor(
        &members[0].identity,
        &members[0].roster,
        config.self_wire.as_ref().unwrap(),
    )
    .unwrap();
    config.couriers = members[1..]
        .iter()
        .map(|m| CourierFile::prepare(&members[0], &auth, &m.identity.public()).unwrap())
        .collect();
    let verifier = |role: u8, cap: &[u8; 32]| {
        let mut bytes = zeroize::Zeroizing::new(b"Loki_Relay_Capability_v1\0".to_vec());
        bytes.push(role);
        bytes.extend_from_slice(&config.own[0].route.mailbox);
        bytes.extend_from_slice(cap);
        *ConfigReference::from_ciphertext(1, &bytes).unwrap().hash()
    };
    let request = encode_creation(&Creation {
        read_verifier: verifier(1, config.own[0].read.as_bytes()),
        append_verifier: verifier(2, config.own[0].append.as_bytes()),
        admin_verifier: verifier(3, config.own[0].admin.as_bytes()),
        quota: 1000,
    })
    .unwrap();
    config.operation = Some([91; 32]);
    config.pending.push(PendingRequest::Create {
        relay: 0,
        request: zeroize::Zeroizing::new(request.clone()),
    });
    let bytes = config.encode(&members[0], 1).unwrap();
    let restored = LocalConfig::decode(&members[0], 1, &bytes).unwrap();
    assert_eq!(restored.couriers[0].wire(), config.couriers[0].wire());
    assert_eq!(
        restored.authenticated(&members[0]).unwrap().own[0]
            .admin
            .as_bytes(),
        config.own[0].admin.as_bytes()
    );
    let mut wrong = config_owner(&members[0]);
    wrong.own[0].read = Secret32::from_bytes(*wrong.own[0].admin.as_bytes());
    assert!(wrong.encode(&members[0], 1).is_err());
    let mut wrong = config_owner(&members[0]);
    wrong.own[0].route.mailbox[0] ^= 1;
    assert!(wrong.encode(&members[0], 1).is_err());
    let mut wrong = config_owner(&members[0]);
    wrong.operation = Some([91; 32]);
    let mut changed = request;
    *changed.last_mut().unwrap() ^= 1;
    wrong.pending.push(PendingRequest::Create {
        relay: 0,
        request: zeroize::Zeroizing::new(changed),
    });
    // Changing a quota alone remains a valid saved request; changing an authority does not.
    if let PendingRequest::Create { request, .. } = &mut wrong.pending[0] {
        request[5] ^= 1;
    }
    assert!(wrong.encode(&members[0], 1).is_err());
}

struct ConfigFixture {
    root: PathBuf,
    store: loki_poc::relay_member::ConfigStore,
    db: loki_relay_client::ClientStore,
    members: Vec<loki_poc::relay_member::LoadedMember>,
}
impl ConfigFixture {
    fn new() -> Self {
        let root = scratch().canonicalize().unwrap();
        MemberDir::create(&root, "secrets").unwrap();
        let pass = root.join("pass");
        fs::write(&pass, PASS).unwrap();
        private(&pass, false);
        let members = config_members();
        let store = loki_poc::relay_member::ConfigStore::open(&root, &pass).unwrap();
        let db =
            loki_relay_client::ClientStore::open(&root.join("transport"), &members[0].roster, 1)
                .unwrap();
        Self {
            root,
            store,
            db,
            members,
        }
    }
}
#[test]
fn sealed_revision_store_exact_retry_conflict_missing_hash_restart() {
    let mut f = ConfigFixture::new();
    let config = config_owner(&f.members[0]);
    assert!(f.store.load(&f.db, &f.members[0]).unwrap().is_none());
    let reference = f
        .store
        .save_revision(&mut f.db, &f.members[0], 1, &config)
        .unwrap();
    let path = f.root.join(reference.file_name());
    let wire = fs::read(&path).unwrap();
    assert_eq!(
        reference,
        loki_relay_client::ConfigReference::from_ciphertext(1, &wire).unwrap()
    );
    assert_eq!(
        f.store
            .save_revision(&mut f.db, &f.members[0], 1, &config)
            .unwrap(),
        reference
    );
    assert_eq!(fs::read(&path).unwrap(), wire);
    let conflicting = config_owner(&f.members[0]);
    assert!(f
        .store
        .save_revision(&mut f.db, &f.members[0], 1, &conflicting)
        .is_err());
    assert_eq!(fs::read(&path).unwrap(), wire);
    drop(f.db);
    f.db = loki_relay_client::ClientStore::open(&f.root.join("transport"), &f.members[0].roster, 1)
        .unwrap();
    assert!(f.store.load(&f.db, &f.members[0]).unwrap().is_some());
    let displaced = f.root.join("retained-original.sealed");
    fs::rename(&path, &displaced).unwrap();
    assert!(f.store.load(&f.db, &f.members[0]).is_err());
    let mut tampered = wire.clone();
    *tampered.last_mut().unwrap() ^= 1;
    fs::write(&path, &tampered).unwrap();
    private(&path, false);
    assert!(f.store.load(&f.db, &f.members[0]).is_err());
    fs::write(&path, &wire).unwrap();
    let other = config_owner(&f.members[0])
        .encode(&f.members[0], 1)
        .unwrap();
    let alternative = MemberDir::create(&f.root, "replacement").unwrap();
    alternative
        .write_sealed("valid.sealed", &other, PASS)
        .unwrap();
    fs::copy(alternative.path().join("valid.sealed"), &path).unwrap();
    assert!(f.store.load(&f.db, &f.members[0]).is_err());
}
#[test]
fn sealed_revision_store_wrong_association_before_publication() {
    let mut f = ConfigFixture::new();
    let config = config_owner(&f.members[0]);
    let dbroot = f.root.join("other-transport");
    let mut wrong = loki_relay_client::ClientStore::open(&dbroot, &f.members[1].roster, 2).unwrap();
    assert!(f.store.load(&wrong, &f.members[0]).is_err());
    assert!(f
        .store
        .save_revision(&mut wrong, &f.members[0], 1, &config)
        .is_err());
    assert!(wrong.config_reference().unwrap().is_none());
    assert!(!f
        .root
        .join("secrets/relay-config-0000000000000001.sealed")
        .exists());
    let mut roster = f.members[0].roster.clone();
    roster.vault[0] ^= 1;
    let mut wrong =
        loki_relay_client::ClientStore::open(&f.root.join("wrong-vault"), &roster, 1).unwrap();
    assert!(f
        .store
        .save_revision(&mut wrong, &f.members[0], 1, &config)
        .is_err());
    let mut roster = f.members[0].roster.clone();
    roster.members[2].signing = Identity::new(3).public().signing;
    let mut wrong =
        loki_relay_client::ClientStore::open(&f.root.join("wrong-roster"), &roster, 1).unwrap();
    assert!(f
        .store
        .save_revision(&mut wrong, &f.members[0], 1, &config)
        .is_err());
    let reference = f
        .store
        .save_revision(&mut f.db, &f.members[0], 1, &config)
        .unwrap();
    assert!(f.store.load(&f.db, &f.members[1]).is_err());
    assert_eq!(f.db.config_reference().unwrap(), Some(reference));
}
#[test]
fn sealed_revision_store_orphan_is_not_success_or_highest_adoption() {
    use loki_poc::relay_member::LocalConfig;
    let mut f = ConfigFixture::new();
    let initial = config_owner(&f.members[0]);
    let reference = f
        .store
        .save_revision(&mut f.db, &f.members[0], 1, &initial)
        .unwrap();
    let mut orphan = config_owner(&f.members[0]);
    orphan.predecessor = Some(reference.clone());
    let bytes = orphan.encode(&f.members[0], 2).unwrap();
    MemberDir::open(&f.root, "secrets")
        .write_sealed("relay-config-0000000000000002.sealed", &bytes, PASS)
        .unwrap();
    let loaded = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    assert!(loaded.pending.is_empty());
    assert_eq!(f.db.config_reference().unwrap(), Some(reference.clone()));
    assert!(f
        .store
        .save_revision(&mut f.db, &f.members[0], 2, &orphan)
        .is_err());
    assert_eq!(f.db.config_reference().unwrap(), Some(reference.clone()));
    let mut no_predecessor = LocalConfig::empty();
    assert!(f
        .store
        .save_revision(&mut f.db, &f.members[0], 3, &no_predecessor)
        .is_err());
    no_predecessor.predecessor = Some(reference.clone());
    assert!(f
        .store
        .save_revision(&mut f.db, &f.members[0], 3, &no_predecessor)
        .is_err());
    assert!(!f
        .root
        .join("secrets/relay-config-0000000000000003.sealed")
        .exists());
}

fn config_pending(
    member: &loki_poc::relay_member::LoadedMember,
) -> loki_poc::relay_member::LocalConfig {
    use loki_relay_client::ConfigReference;
    use loki_relay_protocol::{http::encode_append_update, types::AppendUpdate};
    let mut config = config_owner(member);
    let append = loki_relay_client::Secret32::from_bytes([93; 32]);
    let mut input = Zeroizing::new(b"Loki_Relay_Capability_v1\0".to_vec());
    input.push(2);
    input.extend_from_slice(&config.own[0].route.mailbox);
    input.extend_from_slice(append.as_bytes());
    let request = encode_append_update(&AppendUpdate {
        revision: 2,
        verifier: *ConfigReference::from_ciphertext(1, &input).unwrap().hash(),
    })
    .unwrap();
    config.operation = Some([94; 32]);
    config
        .pending
        .push(loki_poc::relay_member::PendingRequest::Rotate {
            relay: 0,
            append,
            request: Zeroizing::new(request),
        });
    config
}
#[test]
fn sealed_revision_store_matching_pending_orphan_retry_and_wrong_operation() {
    use loki_poc::relay_member::LocalConfig;
    let mut f = ConfigFixture::new();
    let initial = config_pending(&f.members[0]);
    let reference = f
        .store
        .save_revision(&mut f.db, &f.members[0], 1, &initial)
        .unwrap();
    let mut candidate = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    candidate.predecessor = Some(reference.clone());
    let bytes = candidate.encode(&f.members[0], 2).unwrap();
    let dir = MemberDir::open(&f.root, "secrets");
    dir.write_sealed("relay-config-0000000000000002.sealed", &bytes, PASS)
        .unwrap();
    let path = f.root.join("secrets/relay-config-0000000000000002.sealed");
    let saved = fs::read(&path).unwrap();
    let mut wrong = LocalConfig::decode(&f.members[0], 2, &bytes).unwrap();
    wrong.operation = Some([95; 32]);
    assert!(f
        .store
        .save_revision(&mut f.db, &f.members[0], 2, &wrong)
        .is_err());
    assert_eq!(f.db.config_reference().unwrap(), Some(reference));
    let adopted = f
        .store
        .save_revision(&mut f.db, &f.members[0], 2, &candidate)
        .unwrap();
    assert_eq!(fs::read(&path).unwrap(), saved);
    assert_eq!(f.db.config_reference().unwrap(), Some(adopted));
    let restored = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    assert_eq!(restored.operation, Some([94; 32]));
    assert_eq!(restored.pending.len(), 1);
    assert_eq!(restored.own[0].route.append_revision, 1);
}
#[test]
fn sealed_revision_store_credentials_absent_from_database_and_permissions() {
    let mut f = ConfigFixture::new();
    let config = config_owner(&f.members[0]);
    let reference = f
        .store
        .save_revision(&mut f.db, &f.members[0], 1, &config)
        .unwrap();
    for name in ["client.sqlite3", "client.sqlite3-wal", "client.sqlite3-shm"] {
        if let Ok(bytes) = fs::read(f.root.join("transport").join(name)) {
            for inbox in &config.own {
                for secret in [
                    inbox.read.as_bytes(),
                    inbox.append.as_bytes(),
                    inbox.admin.as_bytes(),
                ] {
                    assert!(!bytes.windows(32).any(|w| w == secret));
                }
            }
        }
    }
    let path = f.root.join(reference.file_name());
    #[cfg(unix)]
    {
        use std::os::unix::fs::{symlink, PermissionsExt};
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(f.store.load(&f.db, &f.members[0]).is_err());
        assert!(f
            .store
            .save_revision(&mut f.db, &f.members[0], 1, &config)
            .is_err());
        private(&path, false);
        let retained = f.root.join("original.sealed");
        fs::rename(&path, &retained).unwrap();
        symlink(&retained, &path).unwrap();
        assert!(f.store.load(&f.db, &f.members[0]).is_err());
        assert!(f
            .store
            .save_revision(&mut f.db, &f.members[0], 1, &config)
            .is_err());
    }
}

#[test]
fn sealed_revision_store_same_operation_cannot_adopt_different_pending_request() {
    use loki_relay_protocol::{http::encode_append_update, types::AppendUpdate};
    let mut f = ConfigFixture::new();
    let initial = config_pending(&f.members[0]);
    let reference = f
        .store
        .save_revision(&mut f.db, &f.members[0], 1, &initial)
        .unwrap();
    let mut changed = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    changed.predecessor = Some(reference.clone());
    let next = loki_relay_client::Secret32::from_bytes([96; 32]);
    let mut input = Zeroizing::new(b"Loki_Relay_Capability_v1\0".to_vec());
    input.push(2);
    input.extend_from_slice(&changed.own[0].route.mailbox);
    input.extend_from_slice(next.as_bytes());
    let request = encode_append_update(&AppendUpdate {
        revision: 2,
        verifier: *loki_relay_client::ConfigReference::from_ciphertext(1, &input)
            .unwrap()
            .hash(),
    })
    .unwrap();
    changed.pending[0] = loki_poc::relay_member::PendingRequest::Rotate {
        relay: 0,
        append: next,
        request: Zeroizing::new(request),
    };
    let bytes = changed.encode(&f.members[0], 2).unwrap();
    MemberDir::open(&f.root, "secrets")
        .write_sealed("relay-config-0000000000000002.sealed", &bytes, PASS)
        .unwrap();
    assert!(f
        .store
        .save_revision(&mut f.db, &f.members[0], 2, &changed)
        .is_err());
    assert_eq!(f.db.config_reference().unwrap(), Some(reference));
}

#[test]
fn sealed_revision_codec_rotation_request_scope_and_bounds() {
    let members = config_members();
    let mut config = config_pending(&members[0]);
    assert!(config.encode(&members[0], 0).is_err());
    assert!(config.encode(&members[0], i64::MAX as u64 + 1).is_err());
    let bytes = config.encode(&members[0], 1).unwrap();
    let restored = loki_poc::relay_member::LocalConfig::decode(&members[0], 1, &bytes).unwrap();
    assert_eq!(restored.pending.len(), 1);
    if let loki_poc::relay_member::PendingRequest::Rotate { request, .. } = &mut config.pending[0] {
        request[7] ^= 1;
    }
    assert!(config.encode(&members[0], 1).is_err());
    let mut config = config_pending(&members[0]);
    if let loki_poc::relay_member::PendingRequest::Rotate { relay, .. } = &mut config.pending[0] {
        *relay = 3;
    }
    assert!(config.encode(&members[0], 1).is_err());
}

#[test]
fn sealed_revision_codec_strict_version_schema_and_owner_association() {
    use loki_poc::relay_member::LocalConfig;
    use loki_relay_protocol::canonical::{self, Value};
    let members = config_members();
    let encoded = LocalConfig::empty().encode(&members[0], 1).unwrap();
    for field in [0usize, 1, 2, 3, 4] {
        let mut value = canonical::decode(&encoded, 1024 * 1024).unwrap();
        if let Value::Array(fields) = &mut value {
            fields[field] = match field {
                1 | 2 => Value::Bytes(vec![99; 32]),
                _ => Value::Integer(9.into()),
            };
        }
        assert!(LocalConfig::decode(&members[0], 1, &canonical::encode(&value).unwrap()).is_err());
    }
    let mut value = canonical::decode(&encoded, 1024 * 1024).unwrap();
    if let Value::Array(fields) = &mut value {
        fields.push(Value::Null);
    }
    assert!(LocalConfig::decode(&members[0], 1, &canonical::encode(&value).unwrap()).is_err());
    let mut config = config_owner(&members[0]);
    config.peer_wires.push(config.self_wire.clone().unwrap());
    assert!(config.encode(&members[0], 1).is_err());
    let mut config = config_owner(&members[0]);
    let wire = loki_relay_client::seal_descriptor(
        &members[1].identity,
        &members[1].roster,
        &config_descriptor(&members[1], 1),
        &members[0].identity.public(),
    )
    .unwrap()
    .wire;
    config.peer_wires.extend([wire.clone(), wire]);
    assert!(config.encode(&members[0], 1).is_err());
}

#[test]
fn sealed_revision_store_predecessor_and_revision_gap_before_file() {
    use loki_relay_client::ConfigReference;
    let mut f = ConfigFixture::new();
    let initial = config_owner(&f.members[0]);
    let reference = f
        .store
        .save_revision(&mut f.db, &f.members[0], 1, &initial)
        .unwrap();
    let mut candidate = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    candidate.predecessor = Some(ConfigReference::new(1, [99; 32]).unwrap());
    assert!(f
        .store
        .save_revision(&mut f.db, &f.members[0], 2, &candidate)
        .is_err());
    assert!(!f
        .root
        .join("secrets/relay-config-0000000000000002.sealed")
        .exists());
    candidate.predecessor = Some(reference.clone());
    assert!(f
        .store
        .save_revision(&mut f.db, &f.members[0], 3, &candidate)
        .is_err());
    assert!(!f
        .root
        .join("secrets/relay-config-0000000000000003.sealed")
        .exists());
    assert_eq!(f.db.config_reference().unwrap(), Some(reference));
}
#[test]
fn sealed_revision_store_orphan_operation_identity_revalidated() {
    let mut f = ConfigFixture::new();
    let initial = config_pending(&f.members[0]);
    let reference = f
        .store
        .save_revision(&mut f.db, &f.members[0], 1, &initial)
        .unwrap();
    let mut candidate = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    candidate.predecessor = Some(reference.clone());
    candidate.operation = Some([99; 32]);
    let bytes = candidate.encode(&f.members[0], 2).unwrap();
    MemberDir::open(&f.root, "secrets")
        .write_sealed("relay-config-0000000000000002.sealed", &bytes, PASS)
        .unwrap();
    assert!(f
        .store
        .save_revision(&mut f.db, &f.members[0], 2, &candidate)
        .is_err());
    assert_eq!(f.db.config_reference().unwrap(), Some(reference));
}

#[test]
fn owner_provision_random_pending_full_commit_and_exact_reopen() {
    use loki_poc::relay_member::ProvisionTarget;
    let mut f = ConfigFixture::new();
    let targets: Vec<_> = (1..=3u8)
        .map(|i| ProvisionTarget {
            pin: loki_relay_protocol::types::RelayPin {
                key: [i; 32],
                run: [i + 10; 32],
            },
            endpoint: format!("http://127.0.0.1:{}", 3100 + i as u16),
            quota: 4096,
        })
        .collect();
    f.store
        .prepare_provision(&mut f.db, &f.members[0], &targets)
        .unwrap();
    let saved = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    assert_eq!(saved.own.len(), 3);
    assert_eq!(saved.pending.len(), 3);
    assert!(saved.operation.is_some());
    assert!(saved.couriers.is_empty());
    let mut values = Vec::new();
    for inbox in &saved.own {
        for value in [
            &inbox.route.mailbox,
            inbox.read.as_bytes(),
            inbox.append.as_bytes(),
            inbox.admin.as_bytes(),
        ] {
            assert!(!values.contains(value));
            values.push(*value);
        }
    }
    let reference = f.db.config_reference().unwrap().unwrap();
    let bytes = saved.encode(&f.members[0], reference.revision()).unwrap();
    f.store
        .prepare_provision(&mut f.db, &f.members[0], &targets)
        .unwrap();
    assert_eq!(f.db.config_reference().unwrap(), Some(reference.clone()));
    assert_eq!(
        f.store
            .load(&f.db, &f.members[0])
            .unwrap()
            .unwrap()
            .encode(&f.members[0], reference.revision())
            .unwrap()
            .as_slice(),
        bytes.as_slice()
    );
    assert!(f.store.routing(&f.db, &f.members[0]).is_err());
}

#[test]
fn owner_cannot_reprovision_with_persisted_signing_nonces() {
    let mut f = ConfigFixture::new();
    f.store
        .prepare_provision(&mut f.db, &f.members[0], &provision_targets())
        .unwrap();
    // Simulate losing transport state while the member's signing state survives.
    fs::rename(f.root.join("transport"), f.root.join("lost-transport")).unwrap();
    f.db = loki_relay_client::ClientStore::open(&f.root.join("transport"), &f.members[0].roster, 1)
        .unwrap();
    assert!(f.db.config_reference().unwrap().is_none());
    assert!(f.store.load(&f.db, &f.members[0]).unwrap().is_none());
    let attempt = f
        .root
        .join("signing")
        .join("a".repeat(64))
        .join("b".repeat(64));
    fs::create_dir_all(&attempt).unwrap();
    fs::write(attempt.join("nonces.sealed"), b"unfinished signing attempt").unwrap();
    assert!(f
        .store
        .prepare_provision(&mut f.db, &f.members[0], &provision_targets())
        .is_err());
    assert!(f.db.config_reference().unwrap().is_none());
}

fn provision_targets() -> Vec<loki_poc::relay_member::ProvisionTarget> {
    (1..=3u8)
        .map(|i| loki_poc::relay_member::ProvisionTarget {
            pin: loki_relay_protocol::types::RelayPin {
                key: [i; 32],
                run: [i + 10; 32],
            },
            endpoint: format!("http://127.0.0.1:{}", 3100 + i as u16),
            quota: 4096,
        })
        .collect()
}
#[test]
fn owner_provision_pending_pin_quota_and_database_association() {
    let mut f = ConfigFixture::new();
    let mut targets = provision_targets();
    f.store
        .prepare_provision(&mut f.db, &f.members[0], &targets)
        .unwrap();
    targets[0].quota += 1;
    assert!(f
        .store
        .prepare_provision(&mut f.db, &f.members[0], &targets)
        .is_err());
    targets[0].quota -= 1;
    targets[0].pin.run[0] ^= 1;
    assert!(f
        .store
        .prepare_provision(&mut f.db, &f.members[0], &targets)
        .is_err());
    targets[0].pin.run[0] ^= 1;
    targets[0].endpoint.push('/');
    assert!(f
        .store
        .prepare_provision(&mut f.db, &f.members[0], &targets)
        .is_err());
    let other = loki_relay_client::ClientStore::open(
        &scratch().canonicalize().unwrap().join("transport"),
        &f.members[1].roster,
        2,
    )
    .unwrap();
    assert!(f.store.routing(&other, &f.members[0]).is_err());
}
#[test]
fn owner_provision_peer_persisted_before_route_stale_conflict_and_no_plaintext() {
    let mut f = ConfigFixture::new();
    let wire = loki_relay_client::seal_descriptor(
        &f.members[1].identity,
        &f.members[1].roster,
        &config_descriptor(&f.members[1], 1),
        &f.members[0].identity.public(),
    )
    .unwrap()
    .wire;
    let routed = f
        .store
        .accept_peer(&mut f.db, &f.members[0], &wire)
        .unwrap();
    assert_eq!(routed.peers.len(), 1);
    assert!(f.db.config_reference().unwrap().is_some());
    let saved = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    assert_eq!(saved.peer_wires, vec![wire.clone()]);
    let mut changed = config_descriptor(&f.members[1], 1);
    changed.relays[0].append = loki_relay_client::Secret32::from_bytes([99; 32]);
    let conflict = loki_relay_client::seal_descriptor(
        &f.members[1].identity,
        &f.members[1].roster,
        &changed,
        &f.members[0].identity.public(),
    )
    .unwrap()
    .wire;
    let reference = f.db.config_reference().unwrap();
    assert!(f
        .store
        .accept_peer(&mut f.db, &f.members[0], &conflict)
        .is_err());
    assert_eq!(f.db.config_reference().unwrap(), reference);
    let resealed = loki_relay_client::seal_descriptor(
        &f.members[1].identity,
        &f.members[1].roster,
        &config_descriptor(&f.members[1], 1),
        &f.members[0].identity.public(),
    )
    .unwrap()
    .wire;
    f.store
        .accept_peer(&mut f.db, &f.members[0], &resealed)
        .unwrap();
    assert_eq!(
        f.store
            .load(&f.db, &f.members[0])
            .unwrap()
            .unwrap()
            .peer_wires,
        vec![wire]
    );
    let newer = loki_relay_client::seal_descriptor(
        &f.members[1].identity,
        &f.members[1].roster,
        &config_descriptor(&f.members[1], 2),
        &f.members[0].identity.public(),
    )
    .unwrap()
    .wire;
    f.store
        .accept_peer(&mut f.db, &f.members[0], &newer)
        .unwrap();
    assert!(f
        .store
        .accept_peer(&mut f.db, &f.members[0], &resealed)
        .is_err());
    for entry in fs::read_dir(f.root.join("transport")).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            let raw = fs::read(entry.path()).unwrap();
            for peer in &routed.peers {
                for relay in &peer.body().relays {
                    assert!(!raw.windows(32).any(|w| w == relay.append.as_bytes()));
                }
            }
        }
    }
}
#[test]
fn owner_provision_peer_commit_failure_returns_no_routing() {
    let mut f = ConfigFixture::new();
    let wire = loki_relay_client::seal_descriptor(
        &f.members[1].identity,
        &f.members[1].roster,
        &config_descriptor(&f.members[1], 1),
        &f.members[0].identity.public(),
    )
    .unwrap()
    .wire;
    let mut locker=Command::new("python3").args(["-u","-c","import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('BEGIN IMMEDIATE'); print('ready',flush=True); input(); c.rollback()"])
        .arg(f.root.join("transport/client.sqlite3")).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    {
        use std::io::BufRead;
        let mut line = String::new();
        std::io::BufReader::new(locker.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line.trim(), "ready");
    }
    assert!(
        f.store
            .accept_peer(&mut f.db, &f.members[0], &wire)
            .is_err(),
        "exposed accepted peer route before FULL pointer commit"
    );
    assert!(f
        .root
        .join("secrets/relay-config-0000000000000001.sealed")
        .exists());
    assert!(f.db.config_reference().unwrap().is_none());
    {
        use std::io::Write;
        locker.stdin.take().unwrap().write_all(b"\n").unwrap();
    }
    assert!(locker.wait().unwrap().success());
    assert!(f.store.routing(&f.db, &f.members[0]).is_err());
}
#[test]
fn owner_provision_success_cannot_drop_operation_or_original_requests() {
    let mut f = ConfigFixture::new();
    f.store
        .prepare_provision(&mut f.db, &f.members[0], &provision_targets())
        .unwrap();
    let reference = f.db.config_reference().unwrap().unwrap();
    let mut saved = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    saved.predecessor = Some(reference.clone());
    saved.provisioned = Some(vec![1, 0, 0]);
    f.store
        .save_revision(&mut f.db, &f.members[0], 2, &saved)
        .unwrap();
    let reference = f.db.config_reference().unwrap().unwrap();
    let mut changed = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    changed.predecessor = Some(reference.clone());
    changed.operation = Some([99; 32]);
    assert!(
        f.store
            .save_revision(&mut f.db, &f.members[0], 3, &changed)
            .is_err(),
        "dropped operation authority"
    );
    let mut changed = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    changed.predecessor = Some(reference.clone());
    if let loki_poc::relay_member::PendingRequest::Create { request, .. } = &mut changed.pending[0]
    {
        let mut c = loki_relay_protocol::http::decode_creation(request).unwrap();
        c.quota += 1;
        *request = Zeroizing::new(loki_relay_protocol::http::encode_creation(&c).unwrap());
    }
    assert!(
        f.store
            .save_revision(&mut f.db, &f.members[0], 3, &changed)
            .is_err(),
        "changed original saved request"
    );
    let mut changed = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    changed.predecessor = Some(reference);
    changed.provisioned = Some(vec![0, 0, 0]);
    assert!(
        f.store
            .save_revision(&mut f.db, &f.members[0], 3, &changed)
            .is_err(),
        "discarded verified success"
    );
}
#[test]
fn owner_provision_unsafe_target_before_file() {
    let mut f = ConfigFixture::new();
    let mut targets = provision_targets();
    targets[0].endpoint = "http://127.1:3101".into();
    assert!(f
        .store
        .prepare_provision(&mut f.db, &f.members[0], &targets)
        .is_err());
    assert!(f.db.config_reference().unwrap().is_none());
    assert_eq!(fs::read_dir(f.root.join("secrets")).unwrap().count(), 0);
}

#[test]
fn owner_provision_os_random_independent_across_owners_and_roles() {
    let mut first = ConfigFixture::new();
    let mut second = ConfigFixture::new();
    first
        .store
        .prepare_provision(&mut first.db, &first.members[0], &provision_targets())
        .unwrap();
    second
        .store
        .prepare_provision(&mut second.db, &second.members[0], &provision_targets())
        .unwrap();
    let a = first
        .store
        .load(&first.db, &first.members[0])
        .unwrap()
        .unwrap();
    let b = second
        .store
        .load(&second.db, &second.members[0])
        .unwrap()
        .unwrap();
    let mut all = Vec::new();
    for config in [&a, &b] {
        for inbox in &config.own {
            for value in [
                &inbox.route.mailbox,
                inbox.read.as_bytes(),
                inbox.append.as_bytes(),
                inbox.admin.as_bytes(),
            ] {
                assert!(
                    !all.contains(value),
                    "reused OS random value across inbox/role/owner preparations"
                );
                all.push(*value);
            }
        }
    }
}

fn accept_control_request(listener: &std::net::TcpListener) -> (std::net::TcpStream, Vec<u8>, String) {
    use std::io::{Read, Write};
    loop {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut raw = Vec::new();
        let mut byte = [0; 1];
        while !raw.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).unwrap();
            raw.push(byte[0]);
        }
        let text = String::from_utf8(raw.clone()).unwrap();
        if text.starts_with("HEAD / HTTP/1.1") {
            // Local port probes are not provisioning requests.
            write!(stream, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n").unwrap();
            continue;
        }
        return (stream, raw, text);
    }
}

fn provision_mock(
    target: &mut loki_poc::relay_member::ProvisionTarget,
    responses: Vec<Option<(u16, u64, [u8; 32])>>,
    db_path: PathBuf,
) -> std::thread::JoinHandle<Vec<Vec<u8>>> {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    target.endpoint = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let quota = target.quota;
    std::thread::spawn(move || {
        let mut requests = Vec::new();
        for response in responses {
            let (mut stream, mut raw, text) = accept_control_request(&listener);
            let length: usize = text
                .lines()
                .find_map(|l| {
                    l.to_ascii_lowercase()
                        .strip_prefix("content-length: ")
                        .map(str::to_owned)
                })
                .unwrap()
                .parse()
                .unwrap();
            let mut body = vec![0; length];
            stream.read_exact(&mut body).unwrap();
            raw.extend(body);
            let mailbox_hex = text
                .split_whitespace()
                .nth(1)
                .unwrap()
                .strip_prefix("/v1/mailboxes/")
                .unwrap();
            let mut mailbox = [0; 32];
            hex::decode_to_slice(mailbox_hex, &mut mailbox).unwrap();
            let output=Command::new("python3").args(["-c","import sqlite3,sys,pathlib,hashlib; c=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True); r=c.execute('SELECT revision,hash FROM config_versions WHERE singleton=1').fetchone(); assert r is not None; p=pathlib.Path(sys.argv[1]).parent.parent/'secrets'/('relay-config-%016x.sealed'%r[0]); b=p.read_bytes(); assert b[:9]==b'LOKISEAL'+bytes([1]) and hashlib.sha256(b).digest()==r[1]; print(1)"]).arg(&db_path).output().unwrap();
            assert!(output.status.success());
            assert!(
                String::from_utf8(output.stdout)
                    .unwrap()
                    .trim()
                    .parse::<u64>()
                    .unwrap()
                    >= 1,
                "request preceded committed sealed pending configuration"
            );
            requests.push(raw);
            if let Some((status, revision, run)) = response {
                let body = loki_relay_protocol::http::encode_creation_result(
                    &mailbox,
                    &loki_relay_protocol::types::CreationResult {
                        created: status == 201,
                        run,
                        quota,
                        append_revision: revision,
                    },
                )
                .unwrap();
                write!(stream,"HTTP/1.1 {status} Control\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).unwrap();
                stream.write_all(&body).unwrap();
            }
        }
        requests
    })
}
fn provision_runtime() -> loki_relay_client::RelayRuntime {
    loki_relay_client::RelayRuntime::new().expect("construct owned nonnested Tokio runtime")
}
fn pending_bytes(config: &loki_poc::relay_member::LocalConfig, index: usize) -> Vec<u8> {
    match &config.pending[index] {
        loki_poc::relay_member::PendingRequest::Create { request, .. } => request.to_vec(),
        _ => panic!("unexpected rotation"),
    }
}
#[test]
fn owner_provision_lost_response_exact_retry_full_before_http_and_publish() {
    let mut f = ConfigFixture::new();
    let mut targets = provision_targets();
    let mut servers = Vec::new();
    for (i, target) in targets.iter_mut().enumerate() {
        let responses = if i == 0 {
            vec![None, Some((200, 1, target.pin.run))]
        } else {
            vec![Some((201, 1, target.pin.run))]
        };
        servers.push(provision_mock(
            target,
            responses,
            f.root.join("transport/client.sqlite3"),
        ));
    }
    f.store
        .prepare_provision(&mut f.db, &f.members[0], &targets)
        .unwrap();
    let before = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    let initial = f.db.config_reference().unwrap().unwrap();
    let caps: Vec<_> = (0..3)
        .map(|i| loki_relay_client::Secret32::from_bytes([91 + i; 32]))
        .collect();
    let runtime = provision_runtime();
    let http = loki_relay_client::RelayHttp::new().unwrap();
    assert!(runtime
        .block_on(f.store.provision(&mut f.db, &f.members[0], &http, &caps))
        .is_err());
    assert_eq!(f.db.config_reference().unwrap(), Some(initial));
    let routed = runtime
        .block_on(f.store.provision(&mut f.db, &f.members[0], &http, &caps))
        .unwrap();
    assert_eq!(routed.own.len(), 3);
    for (index, server) in servers.into_iter().enumerate() {
        let requests = server.join().unwrap();
        if index == 0 {
            assert_eq!(
                requests[0], requests[1],
                "uncertain creation resealed/regenerated request"
            );
        }
        for request in requests {
            let split = request.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
            assert_eq!(&request[split..], pending_bytes(&before, index));
            assert!(String::from_utf8_lossy(&request).starts_with(&format!(
                "PUT /v1/mailboxes/{} ",
                hex::encode(before.own[index].route.mailbox)
            )));
        }
    }
    let saved = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    assert_eq!(saved.provisioned, Some(vec![1; 3]));
    assert_eq!(saved.operation, before.operation);
    assert_eq!(saved.pending.len(), 3);
    assert_eq!(saved.couriers.len(), 2);
    let reference = f.db.config_reference().unwrap();
    runtime
        .block_on(f.store.provision(&mut f.db, &f.members[0], &http, &caps))
        .unwrap();
    assert_eq!(f.db.config_reference().unwrap(), reference);
    let dir = scratch();
    let published = f
        .store
        .publish_provision(&f.db, &f.members[0], &dir)
        .unwrap();
    let wires: Vec<_> = published.iter().map(|p| fs::read(p).unwrap()).collect();
    f.store
        .publish_provision(&f.db, &f.members[0], &dir)
        .unwrap();
    for (i, p) in published.iter().enumerate() {
        assert_eq!(fs::read(p).unwrap(), wires[i]);
        let auth = loki_relay_client::open_descriptor(
            &f.members[i + 1].identity,
            &f.members[i + 1].roster,
            &wires[i],
        )
        .unwrap();
        for (r, own) in auth.body().relays.iter().zip(&saved.own) {
            assert_eq!(r.append.as_bytes(), own.append.as_bytes());
            assert!(!r.append.as_bytes().eq(own.read.as_bytes()));
            assert!(!r.append.as_bytes().eq(own.admin.as_bytes()));
        }
    }
    for entry in fs::read_dir(f.root.join("transport")).unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_file() {
            let raw = fs::read(entry.path()).unwrap();
            for inbox in &saved.own {
                for secret in [
                    inbox.read.as_bytes(),
                    inbox.append.as_bytes(),
                    inbox.admin.as_bytes(),
                ] {
                    assert!(!raw.windows(32).any(|w| w == secret));
                }
            }
        }
    }
}
#[test]
fn owner_provision_verified_success_orphan_retry_preserves_operation() {
    let mut f = ConfigFixture::new();
    let mut targets = provision_targets();
    let mut servers = Vec::new();
    for target in &mut targets {
        let run = target.pin.run;
        servers.push(provision_mock(
            target,
            vec![Some((201, 1, run))],
            f.root.join("transport/client.sqlite3"),
        ));
    }
    f.store
        .prepare_provision(&mut f.db, &f.members[0], &targets)
        .unwrap();
    let initial = f.db.config_reference().unwrap().unwrap();
    let before = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    let mut locker = Command::new("python3")
        .args(["-u", "-c", "import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); c.execute('BEGIN IMMEDIATE'); print('ready',flush=True); input(); c.rollback()"])
        .arg(f.root.join("transport/client.sqlite3")).stdin(Stdio::piped()).stdout(Stdio::piped()).spawn().unwrap();
    {
        use std::io::BufRead;
        let mut line = String::new();
        std::io::BufReader::new(locker.stdout.take().unwrap())
            .read_line(&mut line)
            .unwrap();
        assert_eq!(line.trim(), "ready");
    }
    let runtime = provision_runtime();
    let http = loki_relay_client::RelayHttp::new().unwrap();
    let caps: Vec<_> = (0..3)
        .map(|i| loki_relay_client::Secret32::from_bytes([91 + i; 32]))
        .collect();
    assert!(runtime
        .block_on(f.store.provision(&mut f.db, &f.members[0], &http, &caps))
        .is_err());
    assert_eq!(f.db.config_reference().unwrap(), Some(initial.clone()));
    {
        use std::io::Write;
        locker.stdin.take().unwrap().write_all(b"\n").unwrap();
    }
    assert!(locker.wait().unwrap().success());
    assert_eq!(
        f.store
            .load(&f.db, &f.members[0])
            .unwrap()
            .unwrap()
            .provisioned,
        Some(vec![0; 3])
    );
    assert!(f.store.routing(&f.db, &f.members[0]).is_err());
    let orphan = f.root.join("secrets/relay-config-0000000000000002.sealed");
    assert!(orphan.exists());
    let exact = fs::read(&orphan).unwrap();

    runtime
        .block_on(f.store.provision(&mut f.db, &f.members[0], &http, &caps))
        .unwrap();
    assert_eq!(fs::read(orphan).unwrap(), exact);
    let saved = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    assert_eq!(saved.operation, before.operation);
    for (i, server) in servers.into_iter().enumerate() {
        let requests = server.join().unwrap();
        assert_eq!(
            requests.len(),
            1,
            "replayed committed verified success on relay {i}"
        );
    }
}
#[test]
fn owner_provision_current_rotation_revision_retained_without_stale_publication() {
    let mut f = ConfigFixture::new();
    let mut targets = provision_targets();
    let mut servers = Vec::new();
    for (i, target) in targets.iter_mut().enumerate() {
        let run = target.pin.run;
        servers.push(provision_mock(
            target,
            vec![Some((
                if i == 0 { 200 } else { 201 },
                if i == 0 { 7 } else { 1 },
                run,
            ))],
            f.root.join("transport/client.sqlite3"),
        ));
    }
    f.store
        .prepare_provision(&mut f.db, &f.members[0], &targets)
        .unwrap();
    let caps: Vec<_> = (0..3)
        .map(|i| loki_relay_client::Secret32::from_bytes([91 + i; 32]))
        .collect();
    assert!(provision_runtime()
        .block_on(f.store.provision(
            &mut f.db,
            &f.members[0],
            &loki_relay_client::RelayHttp::new().unwrap(),
            &caps
        ))
        .is_err());
    for server in servers {
        server.join().unwrap();
    }
    let saved = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    assert_eq!(saved.provisioned, Some(vec![7, 1, 1]));
    assert_eq!(saved.own[0].route.append_revision, 1);
    assert!(saved.couriers.is_empty());
    assert!(
        f.store
            .publish_provision(&f.db, &f.members[0], &scratch())
            .is_err(),
        "published stale append credentials after retry returned later rotation"
    );
}

#[test]
fn owner_provision_guard_four_role_values_distinct() {
    let mut f = ConfigFixture::new();
    f.store
        .prepare_provision(&mut f.db, &f.members[0], &provision_targets())
        .unwrap();
    let mut saved = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    saved.own[0].read = loki_relay_client::Secret32::from_bytes(saved.own[0].route.mailbox);
    if let loki_poc::relay_member::PendingRequest::Create { request, .. } = &mut saved.pending[0] {
        let mut c = loki_relay_protocol::http::decode_creation(request).unwrap();
        let mut preimage = b"Loki_Relay_Capability_v1\0".to_vec();
        preimage.push(1);
        preimage.extend_from_slice(&saved.own[0].route.mailbox);
        preimage.extend_from_slice(saved.own[0].read.as_bytes());
        c.read_verifier = *loki_relay_client::ConfigReference::from_ciphertext(1, &preimage)
            .unwrap()
            .hash();
        *request = Zeroizing::new(loki_relay_protocol::http::encode_creation(&c).unwrap());
    }
    assert!(
        saved.encode(&f.members[0], 1).is_err(),
        "mailbox and read capability reused same random value"
    );
}
#[test]
fn owner_provision_guard_progress_shape_and_courier_scope() {
    let mut f = ConfigFixture::new();
    f.store
        .prepare_provision(&mut f.db, &f.members[0], &provision_targets())
        .unwrap();
    let mut saved = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    saved.provisioned = Some(vec![1; 2]);
    assert!(
        saved.encode(&f.members[0], 1).is_err(),
        "accepted partial progress schema"
    );
    let mut saved = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    saved.provisioned = Some(vec![i64::MAX as u64 + 1, 0, 0]);
    assert!(
        saved.encode(&f.members[0], 1).is_err(),
        "accepted unbounded success counter"
    );
    let mut saved = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    let auth = loki_relay_client::open_descriptor(
        &f.members[0].identity,
        &f.members[0].roster,
        saved.self_wire.as_ref().unwrap(),
    )
    .unwrap();
    saved.couriers.push(
        loki_poc::relay_member::CourierFile::prepare(
            &f.members[0],
            &auth,
            &f.members[1].identity.public(),
        )
        .unwrap(),
    );
    assert!(
        saved.encode(&f.members[0], 1).is_err(),
        "accepted premature courier publication state"
    );
}

#[test]
fn owner_provision_orphan_wrong_operation_and_request_cannot_publish_pointer() {
    for change_request in [false, true] {
        let mut f = ConfigFixture::new();
        f.store
            .prepare_provision(&mut f.db, &f.members[0], &provision_targets())
            .unwrap();
        let reference = f.db.config_reference().unwrap().unwrap();
        let mut candidate = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
        candidate.predecessor = Some(reference.clone());
        candidate.provisioned = Some(vec![1, 0, 0]);
        if change_request {
            if let loki_poc::relay_member::PendingRequest::Create { request, .. } =
                &mut candidate.pending[0]
            {
                let mut c = loki_relay_protocol::http::decode_creation(request).unwrap();
                c.quota += 1;
                *request = Zeroizing::new(loki_relay_protocol::http::encode_creation(&c).unwrap());
            }
        } else {
            candidate.operation = Some([99; 32]);
        }
        MemberDir::open(&f.root, "secrets")
            .write_sealed(
                "relay-config-0000000000000002.sealed",
                &candidate.encode(&f.members[0], 2).unwrap(),
                PASS,
            )
            .unwrap();
        let caps: Vec<_> = (0..3)
            .map(|i| loki_relay_client::Secret32::from_bytes([91 + i; 32]))
            .collect();
        let result = provision_runtime().block_on(f.store.provision(
            &mut f.db,
            &f.members[0],
            &loki_relay_client::RelayHttp::new().unwrap(),
            &caps,
        ));
        assert!(result.is_err());
        assert_eq!(
            f.db.config_reference().unwrap(),
            Some(reference),
            "adopted orphan outside committed operation/original request authority"
        );
    }
}

#[derive(Clone, Copy)]
enum ControlStep {
    Create(u16, u64),
    Rotate(Option<u64>),
    Conflict,
    UnknownRun,
}
fn control_servers(
    targets: &mut [loki_poc::relay_member::ProvisionTarget],
    scripts: Vec<Vec<ControlStep>>,
    db_path: PathBuf,
    minimum: std::sync::Arc<std::sync::atomic::AtomicU64>,
) -> Vec<std::thread::JoinHandle<Vec<Vec<u8>>>> {
    use std::io::{Read, Write};
    use std::sync::atomic::Ordering;
    targets
        .iter_mut()
        .zip(scripts)
        .map(|(target, script)| {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            target.endpoint = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
            let quota = target.quota;
            let run = target.pin.run;
            let db_path = db_path.clone();
            let minimum = std::sync::Arc::clone(&minimum);
            std::thread::spawn(move || {
                let mut requests = Vec::new();
                for step in script {
                    let (mut stream, mut raw, text) = accept_control_request(&listener);
                    let length: usize = text
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length: ")
                                .map(str::to_owned)
                        })
                        .unwrap()
                        .parse()
                        .unwrap();
                    let mut body = vec![0; length];
                    stream.read_exact(&mut body).unwrap();
                    raw.extend(body);
                    let path = text.split_whitespace().nth(1).unwrap();
                    let mailbox_hex = path
                        .strip_prefix("/v1/mailboxes/")
                        .unwrap()
                        .trim_end_matches("/append-capability");
                    let mut mailbox = [0; 32];
                    hex::decode_to_slice(mailbox_hex, &mut mailbox).unwrap();
                    let minimum = minimum.load(Ordering::SeqCst);
                    let output = Command::new("python3").args(["-c", "import sqlite3,sys,pathlib,hashlib; c=sqlite3.connect('file:'+sys.argv[1]+'?mode=ro',uri=True); r=c.execute('SELECT revision,hash FROM config_versions WHERE singleton=1').fetchone(); assert r is not None and r[0] >= int(sys.argv[2]); p=pathlib.Path(sys.argv[1]).parent.parent/'secrets'/('relay-config-%016d.sealed'%r[0]); b=p.read_bytes(); assert b[:9]==b'LOKISEAL'+bytes([1]) and hashlib.sha256(b).digest()==r[1]"]).arg(&db_path).arg(minimum.to_string()).output().unwrap();
                    assert!(output.status.success(), "rotation request preceded its sealed commit");
                    requests.push(raw);
                    let response = match step {
                        ControlStep::Create(status, revision) => {
                            Some((status, loki_relay_protocol::http::encode_creation_result(&mailbox, &loki_relay_protocol::types::CreationResult { created: status == 201, run, quota, append_revision: revision }).unwrap()))
                        }
                        ControlStep::Rotate(None) => None,
                        ControlStep::Rotate(Some(revision)) => Some((200, loki_relay_protocol::http::encode_append_result(&mailbox, revision).unwrap())),
                        ControlStep::Conflict => Some((409, loki_relay_protocol::http::encode_error(loki_relay_protocol::http::ErrorCode::Conflict).unwrap())),
                        ControlStep::UnknownRun => Some((200, loki_relay_protocol::http::encode_creation_result(&mailbox, &loki_relay_protocol::types::CreationResult { created: false, run: [9; 32], quota, append_revision: 2 }).unwrap())),
                    };
                    if let Some((status, body)) = response {
                        write!(stream, "HTTP/1.1 {status} Control\r\nContent-Type: application/cbor\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).unwrap();
                        stream.write_all(&body).unwrap();
                    }
                }
                requests
            })
        })
        .collect()
}
fn bearer_secret(request: &[u8]) -> [u8; 32] {
    let header = request
        .split(|byte| *byte == b'\n')
        .map(|line| line.strip_suffix(b"\r").unwrap_or(line))
        .find(|line| line.len() >= 14 && line[..14].eq_ignore_ascii_case(b"authorization:"))
        .unwrap();
    let token = header.split(|byte| *byte == b' ').nth(2).unwrap();
    let mut output = [0u8; 32];
    let mut accumulator = 0u32;
    let mut bits = 0;
    let mut written = 0;
    for byte in token {
        let value = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
            .iter()
            .position(|candidate| candidate == byte)
            .unwrap() as u32;
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output[written] = (accumulator >> bits) as u8;
            written += 1;
            accumulator &= (1 << bits) - 1;
        }
    }
    assert_eq!(written, 32);
    output
}
fn request_body(request: &[u8]) -> &[u8] {
    let split = request
        .windows(4)
        .position(|mark| mark == b"\r\n\r\n")
        .unwrap()
        + 4;
    &request[split..]
}
fn rotate_request(config: &loki_poc::relay_member::LocalConfig, index: usize) -> Vec<u8> {
    config
        .pending
        .iter()
        .find_map(|pending| match pending {
            loki_poc::relay_member::PendingRequest::Rotate { relay, request, .. }
                if usize::from(*relay) == index =>
            {
                Some(request.to_vec())
            }
            _ => None,
        })
        .unwrap()
}
fn provision_three(f: &mut ConfigFixture, targets: &mut [loki_poc::relay_member::ProvisionTarget]) {
    let caps: Vec<_> = (0..3)
        .map(|i| loki_relay_client::Secret32::from_bytes([91 + i; 32]))
        .collect();
    f.store
        .prepare_provision(&mut f.db, &f.members[0], targets)
        .unwrap();
    provision_runtime()
        .block_on(f.store.provision(
            &mut f.db,
            &f.members[0],
            &loki_relay_client::RelayHttp::new().unwrap(),
            &caps,
        ))
        .unwrap();
}
#[test]
fn partial_rotation_timeout_after_commit_recovers_exact_unchanged_admin() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let mut f = ConfigFixture::new();
    let mut targets = provision_targets();
    let minimum = std::sync::Arc::new(AtomicU64::new(1));
    let servers = control_servers(
        &mut targets,
        vec![
            vec![
                ControlStep::Create(201, 1),
                ControlStep::Rotate(None),
                ControlStep::Rotate(Some(2)),
            ],
            vec![ControlStep::Create(201, 1), ControlStep::Rotate(Some(2))],
            vec![ControlStep::Create(201, 1), ControlStep::Rotate(Some(2))],
        ],
        f.root.join("transport/client.sqlite3"),
        std::sync::Arc::clone(&minimum),
    );
    provision_three(&mut f, &mut targets);
    let before = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    let operation = before.operation;
    let creates: Vec<_> = (0..3).map(|index| pending_bytes(&before, index)).collect();
    let prior_descriptor = loki_relay_client::open_descriptor(
        &f.members[0].identity,
        &f.members[0].roster,
        before.self_wire.as_ref().unwrap(),
    )
    .unwrap();
    let prepared = f.store.prepare_rotation(&mut f.db, &f.members[0]).unwrap();
    minimum.store(prepared.revision(), Ordering::SeqCst);
    let prepared_again = f.store.prepare_rotation(&mut f.db, &f.members[0]).unwrap();
    assert_eq!(prepared_again, prepared);
    let pending = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    assert_eq!(pending.rotated, Some(vec![0; 3]));
    assert_eq!(pending.operation, operation);
    assert_eq!(pending.self_wire, before.self_wire);
    assert_eq!(pending.couriers.len(), 2);
    for index in 0..3 {
        assert_eq!(pending_bytes(&pending, index), creates[index]);
        assert_eq!(
            pending.own[index].read.as_bytes(),
            before.own[index].read.as_bytes()
        );
        assert_eq!(
            pending.own[index].admin.as_bytes(),
            before.own[index].admin.as_bytes()
        );
        assert_eq!(
            pending.own[index].route.mailbox,
            before.own[index].route.mailbox
        );
        assert_ne!(
            *pending.own[index].append.as_bytes(),
            rotate_append(&pending, index)
        );
        assert_eq!(
            *pending.own[index].append.as_bytes(),
            *before.own[index].append.as_bytes()
        );
    }
    assert!(f
        .store
        .publish_provision(&f.db, &f.members[0], &scratch())
        .is_err());
    let http = loki_relay_client::RelayHttp::new().unwrap();
    let runtime = provision_runtime();
    assert!(runtime
        .block_on(f.store.rotate(&mut f.db, &f.members[0], &http))
        .is_err());
    let partial = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    assert_eq!(partial.rotated, Some(vec![0, 2, 2]));
    assert_eq!(partial.self_wire, before.self_wire);
    assert_eq!(partial.own[0].route.append_revision, 1);
    for index in 0..3 {
        assert_eq!(pending_bytes(&partial, index), creates[index]);
        assert_eq!(
            rotate_request(&partial, index),
            rotate_request(&pending, index)
        );
    }
    let caps: Vec<_> = (0..3)
        .map(|i| loki_relay_client::Secret32::from_bytes([91 + i; 32]))
        .collect();
    let reference = f.db.config_reference().unwrap();
    assert!(runtime
        .block_on(f.store.provision(&mut f.db, &f.members[0], &http, &caps))
        .is_err());
    assert_eq!(f.db.config_reference().unwrap(), reference);
    assert_eq!(
        f.store.load(&f.db, &f.members[0]).unwrap().unwrap().own[1]
            .append
            .as_bytes(),
        before.own[1].append.as_bytes()
    );
    runtime
        .block_on(f.store.rotate(&mut f.db, &f.members[0], &http))
        .unwrap();
    let mut requests = Vec::new();
    for server in servers {
        requests.push(server.join().unwrap());
    }
    assert_eq!(requests[0].len(), 3);
    assert_eq!(request_body(&requests[0][1]), request_body(&requests[0][2]));
    assert_eq!(
        request_body(&requests[0][2]),
        rotate_request(&pending, 0).as_slice()
    );
    let header_end = requests[0][1]
        .windows(4)
        .position(|mark| mark == b"\r\n\r\n")
        .unwrap();
    assert!(std::str::from_utf8(&requests[0][1][..header_end])
        .unwrap()
        .contains("/append-capability "));
    for request in &requests[0][1..] {
        assert_eq!(bearer_secret(request), *before.own[0].admin.as_bytes());
        assert_ne!(bearer_secret(request), *before.own[0].read.as_bytes());
        assert_ne!(bearer_secret(request), *before.own[0].append.as_bytes());
    }
    let saved = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    let descriptor = loki_relay_client::open_descriptor(
        &f.members[0].identity,
        &f.members[0].roster,
        saved.self_wire.as_ref().unwrap(),
    )
    .unwrap();
    assert_eq!(
        descriptor.body().revision,
        prior_descriptor.body().revision + 1
    );
    assert_eq!(saved.couriers.len(), 2);
    for (index, courier) in saved.couriers.iter().enumerate() {
        let peer = loki_relay_client::open_descriptor(
            &f.members[index + 1].identity,
            &f.members[index + 1].roster,
            courier.wire(),
        )
        .unwrap();
        assert_eq!(peer.canonical_body(), descriptor.canonical_body());
    }
    for index in 0..3 {
        assert_eq!(
            saved.own[index].route.mailbox,
            before.own[index].route.mailbox
        );
        assert_eq!(
            saved.own[index].read.as_bytes(),
            before.own[index].read.as_bytes()
        );
        assert_eq!(
            saved.own[index].admin.as_bytes(),
            before.own[index].admin.as_bytes()
        );
        assert_eq!(saved.own[index].route.append_revision, 2);
        assert_eq!(
            *saved.own[index].append.as_bytes(),
            rotate_append(&pending, index)
        );
        assert_eq!(pending_bytes(&saved, index), creates[index]);
        assert_ne!(
            *saved.own[index].append.as_bytes(),
            *before.own[index].append.as_bytes()
        );
    }
    let published_reference = f.db.config_reference().unwrap();
    let installed_wire = saved.self_wire.clone();
    runtime
        .block_on(f.store.rotate(&mut f.db, &f.members[0], &http))
        .unwrap();
    assert_eq!(f.db.config_reference().unwrap(), published_reference);
    assert_eq!(
        f.store
            .load(&f.db, &f.members[0])
            .unwrap()
            .unwrap()
            .self_wire,
        installed_wire
    );
    let dir = scratch();
    let published = f
        .store
        .publish_provision(&f.db, &f.members[0], &dir)
        .unwrap();
    let wires: Vec<_> = published
        .iter()
        .map(|path| fs::read(path).unwrap())
        .collect();
    f.store
        .publish_provision(&f.db, &f.members[0], &dir)
        .unwrap();
    assert_eq!(f.db.config_reference().unwrap(), published_reference);
    for (index, path) in published.iter().enumerate() {
        assert_eq!(fs::read(path).unwrap(), wires[index]);
        let owner = f.members[0].identity.public().id;
        let peer = f.members[index + 1].identity.public().id;
        assert!(path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .contains(&format!("-{owner}-{peer}-2.bin")));
        for inbox in &saved.own {
            assert!(!wires[index]
                .windows(32)
                .any(|window| window == inbox.read.as_bytes()));
            assert!(!wires[index]
                .windows(32)
                .any(|window| window == inbox.admin.as_bytes()));
        }
        let auth = loki_relay_client::open_descriptor(
            &f.members[index + 1].identity,
            &f.members[index + 1].roster,
            &wires[index],
        )
        .unwrap();
        assert_eq!(auth.digest(), descriptor.digest());
        for (relay, own) in auth.body().relays.iter().zip(&saved.own) {
            assert_eq!(relay.append.as_bytes(), own.append.as_bytes());
            assert_ne!(relay.append.as_bytes(), own.read.as_bytes());
            assert_ne!(relay.append.as_bytes(), own.admin.as_bytes());
        }
    }
    let completed_prepare = f.store.prepare_rotation(&mut f.db, &f.members[0]).unwrap();
    assert_eq!(Some(completed_prepare), published_reference);
    let republished = f
        .store
        .publish_provision(&f.db, &f.members[0], &dir)
        .unwrap();
    for (index, path) in republished.iter().enumerate() {
        assert_eq!(fs::read(path).unwrap(), wires[index]);
    }
    assert_eq!(f.db.config_reference().unwrap(), published_reference);
    let completed = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    for index in 0..3 {
        assert_eq!(
            rotate_request(&completed, index),
            rotate_request(&pending, index)
        );
        assert_eq!(
            *completed.own[index].append.as_bytes(),
            rotate_append(&pending, index)
        );
        assert_eq!(pending_bytes(&completed, index), creates[index]);
    }
    runtime
        .block_on(f.store.provision(&mut f.db, &f.members[0], &http, &caps))
        .unwrap();
    let retried = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    assert_eq!(f.db.config_reference().unwrap(), published_reference);
    for index in 0..3 {
        assert_eq!(
            retried.own[index].append.as_bytes(),
            saved.own[index].append.as_bytes()
        );
        assert_eq!(retried.own[index].route.append_revision, 2);
        assert_eq!(pending_bytes(&retried, index), creates[index]);
    }
    let peer_root = scratch().canonicalize().unwrap();
    MemberDir::create(&peer_root, "secrets").unwrap();
    let pass = peer_root.join("pass");
    fs::write(&pass, PASS).unwrap();
    private(&pass, false);
    let peer_store = loki_poc::relay_member::ConfigStore::open(&peer_root, &pass).unwrap();
    let mut peer_db = loki_relay_client::ClientStore::open(
        &peer_root.join("transport"),
        &f.members[1].roster,
        f.members[1].identity.public().id,
    )
    .unwrap();
    let routed = peer_store
        .accept_peer(&mut peer_db, &f.members[1], &wires[0])
        .unwrap();
    let imported = peer_store.load(&peer_db, &f.members[1]).unwrap().unwrap();
    assert_eq!(imported.peer_wires, vec![wires[0].clone()]);
    assert!(peer_db.config_reference().unwrap().is_some());
    assert_eq!(
        routed.peers[0].body().relays[0].append.as_bytes(),
        saved.own[0].append.as_bytes()
    );
    assert!(routed.own.is_empty());
}
fn rotate_append(config: &loki_poc::relay_member::LocalConfig, index: usize) -> [u8; 32] {
    config
        .pending
        .iter()
        .find_map(|pending| match pending {
            loki_poc::relay_member::PendingRequest::Rotate { relay, append, .. }
                if usize::from(*relay) == index =>
            {
                Some(*append.as_bytes())
            }
            _ => None,
        })
        .unwrap()
}
#[test]
fn partial_rotation_stale_conflict_unknown_run_fail_closed() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let mut f = ConfigFixture::new();
    let mut targets = provision_targets();
    let minimum = std::sync::Arc::new(AtomicU64::new(1));
    let servers = control_servers(
        &mut targets,
        vec![
            vec![ControlStep::Create(201, 1), ControlStep::Conflict],
            vec![ControlStep::Create(201, 1), ControlStep::Rotate(Some(1))],
            vec![ControlStep::Create(201, 1), ControlStep::UnknownRun],
        ],
        f.root.join("transport/client.sqlite3"),
        std::sync::Arc::clone(&minimum),
    );
    provision_three(&mut f, &mut targets);
    let prepared = f.store.prepare_rotation(&mut f.db, &f.members[0]).unwrap();
    minimum.store(prepared.revision(), Ordering::SeqCst);
    let before = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    assert!(provision_runtime()
        .block_on(f.store.rotate(
            &mut f.db,
            &f.members[0],
            &loki_relay_client::RelayHttp::new().unwrap()
        ))
        .is_err());
    for server in servers {
        server.join().unwrap();
    }
    let saved = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    assert_eq!(saved.rotated, Some(vec![0; 3]));
    assert_eq!(f.db.config_reference().unwrap().unwrap(), prepared);
    assert_eq!(saved.self_wire, before.self_wire);
    assert_eq!(
        saved.own[0].append.as_bytes(),
        before.own[0].append.as_bytes()
    );
    assert!(f
        .store
        .publish_provision(&f.db, &f.members[0], &scratch())
        .is_err());
}
#[test]
fn partial_rotation_divergent_creation_revision_fails_closed() {
    let mut f = ConfigFixture::new();
    let mut targets = provision_targets();
    let mut servers = Vec::new();
    for (index, target) in targets.iter_mut().enumerate() {
        let run = target.pin.run;
        servers.push(provision_mock(
            target,
            vec![Some((
                if index == 0 { 200 } else { 201 },
                if index == 0 { 7 } else { 1 },
                run,
            ))],
            f.root.join("transport/client.sqlite3"),
        ));
    }
    f.store
        .prepare_provision(&mut f.db, &f.members[0], &targets)
        .unwrap();
    let caps: Vec<_> = (0..3)
        .map(|i| loki_relay_client::Secret32::from_bytes([91 + i; 32]))
        .collect();
    assert!(provision_runtime()
        .block_on(f.store.provision(
            &mut f.db,
            &f.members[0],
            &loki_relay_client::RelayHttp::new().unwrap(),
            &caps
        ))
        .is_err());
    for server in servers {
        server.join().unwrap();
    }
    let before = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    assert!(f.store.prepare_rotation(&mut f.db, &f.members[0]).is_err());
    let saved = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    assert_eq!(saved.provisioned, Some(vec![7, 1, 1]));
    assert_eq!(saved.rotated, None);
    assert_eq!(
        saved.own[0].append.as_bytes(),
        before.own[0].append.as_bytes()
    );
    assert_eq!(saved.pending.len(), 3);
}
#[test]
fn partial_rotation_uncommitted_success_adopts_exact_request_without_retry() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let mut f = ConfigFixture::new();
    let mut targets = provision_targets();
    let minimum = std::sync::Arc::new(AtomicU64::new(1));
    let servers = control_servers(
        &mut targets,
        vec![
            vec![ControlStep::Create(201, 1)],
            vec![ControlStep::Create(201, 1), ControlStep::Rotate(Some(2))],
            vec![ControlStep::Create(201, 1), ControlStep::Rotate(Some(2))],
        ],
        f.root.join("transport/client.sqlite3"),
        std::sync::Arc::clone(&minimum),
    );
    provision_three(&mut f, &mut targets);
    let prepared = f.store.prepare_rotation(&mut f.db, &f.members[0]).unwrap();
    minimum.store(prepared.revision(), Ordering::SeqCst);
    let mut orphan = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    orphan.predecessor = Some(prepared.clone());
    orphan.rotated = Some(vec![2, 0, 0]);
    let revision = prepared.revision() + 1;
    MemberDir::open(&f.root, "secrets")
        .write_sealed(
            &format!("relay-config-{revision:016}.sealed"),
            &orphan.encode(&f.members[0], revision).unwrap(),
            PASS,
        )
        .unwrap();
    provision_runtime()
        .block_on(f.store.rotate(
            &mut f.db,
            &f.members[0],
            &loki_relay_client::RelayHttp::new().unwrap(),
        ))
        .unwrap();
    let requests: Vec<_> = servers
        .into_iter()
        .map(|server| server.join().unwrap())
        .collect();
    assert_eq!(
        requests[0].len(),
        1,
        "retried a relay whose success file was already sealed"
    );
    let saved = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    assert_eq!(saved.rotated, Some(vec![2, 2, 2]));
    assert_eq!(saved.operation, orphan.operation);
    assert_eq!(saved.own[0].route.append_revision, 2);
    assert_eq!(
        request_body(&requests[1][1]),
        rotate_request(&orphan, 1).as_slice()
    );
    assert_eq!(
        bearer_secret(&requests[1][1]),
        *orphan.own[1].admin.as_bytes()
    );
}
#[test]
fn partial_rotation_completed_retry_then_explicit_next_generation() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let mut f = ConfigFixture::new();
    let mut targets = provision_targets();
    let minimum = std::sync::Arc::new(AtomicU64::new(1));
    let servers = control_servers(
        &mut targets,
        vec![
            vec![
                ControlStep::Create(201, 1),
                ControlStep::Rotate(Some(2)),
                ControlStep::Rotate(Some(3)),
            ],
            vec![
                ControlStep::Create(201, 1),
                ControlStep::Rotate(Some(2)),
                ControlStep::Rotate(Some(3)),
            ],
            vec![
                ControlStep::Create(201, 1),
                ControlStep::Rotate(Some(2)),
                ControlStep::Rotate(Some(3)),
            ],
        ],
        f.root.join("transport/client.sqlite3"),
        std::sync::Arc::clone(&minimum),
    );
    provision_three(&mut f, &mut targets);
    let before = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    let creates: Vec<_> = (0..3).map(|index| pending_bytes(&before, index)).collect();
    assert!(f
        .store
        .prepare_next_rotation(&mut f.db, &f.members[0])
        .is_err());
    let prepared = f.store.prepare_rotation(&mut f.db, &f.members[0]).unwrap();
    assert_eq!(
        f.store
            .prepare_next_rotation(&mut f.db, &f.members[0])
            .unwrap(),
        prepared
    );
    minimum.store(prepared.revision(), Ordering::SeqCst);
    let http = loki_relay_client::RelayHttp::new().unwrap();
    let runtime = provision_runtime();
    runtime
        .block_on(f.store.rotate(&mut f.db, &f.members[0], &http))
        .unwrap();
    let installed = f.db.config_reference().unwrap().unwrap();
    let first = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    let first_appends: Vec<_> = (0..3)
        .map(|index| *first.own[index].append.as_bytes())
        .collect();
    let first_requests: Vec<_> = (0..3).map(|index| rotate_request(&first, index)).collect();
    assert_eq!(
        f.store.prepare_rotation(&mut f.db, &f.members[0]).unwrap(),
        installed
    );
    let dir = scratch();
    let first_published = f
        .store
        .publish_provision(&f.db, &f.members[0], &dir)
        .unwrap();
    let first_wires: Vec<_> = first_published
        .iter()
        .map(|path| fs::read(path).unwrap())
        .collect();
    assert_eq!(
        f.store.prepare_rotation(&mut f.db, &f.members[0]).unwrap(),
        installed
    );
    let republished = f
        .store
        .publish_provision(&f.db, &f.members[0], &dir)
        .unwrap();
    for (index, path) in republished.iter().enumerate() {
        assert_eq!(fs::read(path).unwrap(), first_wires[index]);
    }
    let next = f
        .store
        .prepare_next_rotation(&mut f.db, &f.members[0])
        .unwrap();
    assert_ne!(next, installed);
    minimum.store(next.revision(), Ordering::SeqCst);
    assert_eq!(
        f.store.prepare_rotation(&mut f.db, &f.members[0]).unwrap(),
        next
    );
    assert_eq!(
        f.store
            .prepare_next_rotation(&mut f.db, &f.members[0])
            .unwrap(),
        next
    );
    let advanced = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    assert_eq!(advanced.rotated, Some(vec![0; 3]));
    assert_eq!(advanced.operation, before.operation);
    assert_eq!(advanced.self_wire, first.self_wire);
    let descriptor = loki_relay_client::open_descriptor(
        &f.members[0].identity,
        &f.members[0].roster,
        advanced.self_wire.as_ref().unwrap(),
    )
    .unwrap();
    assert_eq!(descriptor.body().revision, 2);
    for index in 0..3 {
        assert_eq!(pending_bytes(&advanced, index), creates[index]);
        assert_eq!(*advanced.own[index].append.as_bytes(), first_appends[index]);
        assert_eq!(
            advanced.own[index].read.as_bytes(),
            before.own[index].read.as_bytes()
        );
        assert_eq!(
            advanced.own[index].admin.as_bytes(),
            before.own[index].admin.as_bytes()
        );
        assert_eq!(
            advanced.own[index].route.mailbox,
            before.own[index].route.mailbox
        );
        assert_eq!(advanced.own[index].route.append_revision, 2);
        assert_ne!(rotate_request(&advanced, index), first_requests[index]);
    }
    runtime
        .block_on(f.store.rotate(&mut f.db, &f.members[0], &http))
        .unwrap();
    let requests: Vec<_> = servers
        .into_iter()
        .map(|server| server.join().unwrap())
        .collect();
    for index in 0..3 {
        assert_eq!(requests[index].len(), 3);
        assert_eq!(
            request_body(&requests[index][2]),
            rotate_request(&advanced, index).as_slice()
        );
        assert_eq!(
            bearer_secret(&requests[index][2]),
            *before.own[index].admin.as_bytes()
        );
    }
    let saved = f.store.load(&f.db, &f.members[0]).unwrap().unwrap();
    let published_reference = f.db.config_reference().unwrap();
    assert_eq!(
        Some(f.store.prepare_rotation(&mut f.db, &f.members[0]).unwrap()),
        published_reference
    );
    let next_descriptor = loki_relay_client::open_descriptor(
        &f.members[0].identity,
        &f.members[0].roster,
        saved.self_wire.as_ref().unwrap(),
    )
    .unwrap();
    assert_eq!(next_descriptor.body().revision, 3);
    for index in 0..3 {
        assert_eq!(pending_bytes(&saved, index), creates[index]);
        assert_eq!(saved.own[index].route.append_revision, 3);
        assert_eq!(
            *saved.own[index].append.as_bytes(),
            rotate_append(&advanced, index)
        );
        assert_ne!(*saved.own[index].append.as_bytes(), first_appends[index]);
        assert_eq!(
            saved.own[index].admin.as_bytes(),
            before.own[index].admin.as_bytes()
        );
        assert_eq!(
            saved.own[index].read.as_bytes(),
            before.own[index].read.as_bytes()
        );
        assert_eq!(
            saved.own[index].route.mailbox,
            before.own[index].route.mailbox
        );
    }
    let published = f
        .store
        .publish_provision(&f.db, &f.members[0], &dir)
        .unwrap();
    let wires: Vec<_> = published
        .iter()
        .map(|path| fs::read(path).unwrap())
        .collect();
    f.store
        .publish_provision(&f.db, &f.members[0], &dir)
        .unwrap();
    for (index, path) in published.iter().enumerate() {
        assert_eq!(fs::read(path).unwrap(), wires[index]);
        assert_ne!(wires[index], first_wires[index]);
        let owner = f.members[0].identity.public().id;
        let peer = f.members[index + 1].identity.public().id;
        assert!(path
            .file_name()
            .unwrap()
            .to_str()
            .unwrap()
            .contains(&format!("-{owner}-{peer}-3.bin")));
    }
    assert_eq!(f.db.config_reference().unwrap(), published_reference);
}

fn member_arg(value: impl AsRef<OsStr>) -> OsString {
    value.as_ref().to_os_string()
}

struct RetainedFixture(std::mem::ManuallyDrop<Fixture>);

impl RetainedFixture {
    fn new() -> Self {
        let mut fixture = Fixture::new();
        let canonical = fixture.root.canonicalize().expect("fixture root");
        let home = PathBuf::from("/private/tmp/relay-8.2a-evidence/fixtures");
        fs::create_dir_all(&home).unwrap();
        let dest = home.join(canonical.file_name().expect("fixture name"));
        fs::rename(&canonical, &dest).expect("retain fixture");
        fixture.pass = dest.join("pass");
        fixture.roster = dest.join("roster.json");
        fixture.root = dest;
        Self(std::mem::ManuallyDrop::new(fixture))
    }
}

impl std::ops::Deref for RetainedFixture {
    type Target = Fixture;
    fn deref(&self) -> &Fixture {
        &self.0
    }
}

fn retained_root(f: &Fixture) -> PathBuf {
    // ClientStore rejects a member root when an ancestor is a symlink. macOS temp dirs sit under /var.
    f.root.canonicalize().expect("retained root")
}

fn common_member_args(f: &Fixture) -> Vec<OsString> {
    let root = retained_root(f);
    vec![
        member_arg("--member-root"),
        member_arg(&root),
        member_arg("--passphrase-file"),
        member_arg(root.join("pass")),
        member_arg("--roster"),
        member_arg(root.join("roster.json")),
    ]
}

fn member_cli(args: &[OsString]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_loki_relay_member"))
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("member cli spawn");
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut timed_out = false;
    loop {
        match child.try_wait().expect("member cli wait") {
            Some(_) => break,
            None if Instant::now() >= deadline => {
                timed_out = true;
                let _ = child.kill();
                break;
            }
            None => thread::sleep(Duration::from_millis(20)),
        }
    }
    let output = child.wait_with_output().expect("member cli reap");
    assert!(!timed_out, "member cli timed out");
    assert!(output.stdout.len() <= 65_536, "member stdout bound");
    assert!(output.stderr.len() <= 4_096, "member stderr bound");
    output
}

fn member_stderr(output: &Output) -> String {
    String::from_utf8(output.stderr.clone()).expect("member stderr text")
}

fn member_stdout(output: &Output) -> String {
    String::from_utf8(output.stdout.clone()).expect("member stdout text")
}

fn assert_usage(output: &Output) {
    assert_eq!(output.status.code(), Some(2), "usage exit");
    assert!(output.stdout.is_empty(), "usage stdout");
    assert_eq!(member_stderr(output).trim(), "member_arguments");
}

fn assert_entered(output: &Output) {
    assert_ne!(output.status.code(), Some(2), "complete command rejected as usage");
    assert_ne!(member_stderr(output).trim(), "member_arguments");
}

fn assert_hidden(haystack: &[u8], needle: &[u8]) {
    if needle.is_empty() {
        return;
    }
    assert!(
        haystack.len() < needle.len() || haystack.windows(needle.len()).all(|window| window != needle),
        "non-public bytes appeared in member output"
    );
}

fn base64_std(data: &[u8]) -> String {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut index = 0;
    while index + 3 <= data.len() {
        let n = ((data[index] as u32) << 16) | ((data[index + 1] as u32) << 8) | data[index + 2] as u32;
        out.push(ALPHA[(n >> 18) as usize] as char);
        out.push(ALPHA[((n >> 12) & 63) as usize] as char);
        out.push(ALPHA[((n >> 6) & 63) as usize] as char);
        out.push(ALPHA[(n & 63) as usize] as char);
        index += 3;
    }
    if index < data.len() {
        let remain = data.len() - index;
        let n = if remain == 1 {
            (data[index] as u32) << 16
        } else {
            ((data[index] as u32) << 16) | ((data[index + 1] as u32) << 8)
        };
        out.push(ALPHA[(n >> 18) as usize] as char);
        out.push(ALPHA[((n >> 12) & 63) as usize] as char);
        if remain == 2 {
            out.push(ALPHA[((n >> 6) & 63) as usize] as char);
        }
    }
    out
}

fn assert_secret_absent(haystack: &[u8], secret: &[u8]) {
    if secret.len() < 16 {
        return;
    }
    assert_hidden(haystack, secret);
    assert_hidden(haystack, hex::encode(secret).as_bytes());
    assert_hidden(haystack, base64_std(secret).as_bytes());
}

fn assert_stored_hex_absent(haystack: &[u8], stored: &str) {
    assert_hidden(haystack, stored.as_bytes());
    let raw = hex::decode(stored).expect("stored secret hex");
    assert_secret_absent(haystack, &raw);
}

fn assert_fixture_secrets_absent(f: &Fixture, haystack: &[u8]) {
    assert_secret_absent(haystack, PASS.as_bytes());
    let pass_file = fs::read(&f.pass).unwrap();
    assert_secret_absent(haystack, &pass_file);
    let identity_bytes = Zeroizing::new(
        MemberDir::open(&f.root, "secrets")
            .read_sealed("identity.sealed", PASS)
            .unwrap(),
    );
    let identity = Identity::from_secret_bytes(&identity_bytes).unwrap();
    let secret = identity.to_secret_bytes();
    assert_secret_absent(haystack, &secret);
    assert_secret_absent(haystack, &secret[2..34]);
    assert_secret_absent(haystack, &secret[34..]);
    let state = f.state();
    for key in ["identity_secret", "key_package", "vault_secret"] {
        let stored = state.get(key).and_then(Value::as_str).expect("secret field");
        assert_stored_hex_absent(haystack, stored);
    }
}

fn hex64(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn uint_token(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
}

fn bit_token(value: &str) -> bool {
    value == "0" || value == "1"
}

fn status_pair<'a>(token: &'a str, key: &str) -> Option<&'a str> {
    token.strip_prefix(key).and_then(|rest| rest.strip_prefix('='))
}

fn status_line_public(line: &str) -> bool {
    if matches!(line, "section=local" | "receipt_digest_alg=blake3" | "config absent=1") {
        return true;
    }
    if let Some(value) = line.strip_prefix("member=") {
        return uint_token(value);
    }
    if let Some(value) = line.strip_prefix("logical_count=") {
        return uint_token(value);
    }
    if let Some(value) = line.strip_prefix("incoming_count=") {
        return uint_token(value);
    }
    if let Some(value) = line.strip_prefix("ack_count=") {
        return uint_token(value);
    }
    if let Some(value) = line.strip_prefix("pending_transfers=") {
        return uint_token(value);
    }
    if let Some(rest) = line.strip_prefix("config revision=") {
        let mut parts = rest.split(' ');
        let revision = parts.next().unwrap_or("");
        let hash = status_pair(parts.next().unwrap_or(""), "hash");
        return uint_token(revision) && parts.next().is_none() && hash.is_some_and(hex64);
    }
    let tokens: Vec<&str> = line.split(' ').collect();
    if tokens.first() == Some(&"message") {
        return tokens.len() == 11
            && status_pair(tokens[1], "sender").is_some_and(uint_token)
            && status_pair(tokens[2], "id").is_some_and(hex64)
            && status_pair(tokens[3], "digest").is_some_and(hex64)
            && status_pair(tokens[4], "kind").is_some_and(|value| value == "test" || value == "received" || uint_token(value))
            && status_pair(tokens[5], "session").is_some_and(|value| value == "-" || hex64(value))
            && status_pair(tokens[6], "readiness").is_some_and(|value| value == "ready" || value == "pending")
            && status_pair(tokens[7], "stored_whole").is_some_and(|value| bit_token(value) || value == "unavailable")
            && status_pair(tokens[8], "received_whole").is_some_and(bit_token)
            && status_pair(tokens[9], "received_author").is_some_and(bit_token)
            && status_pair(tokens[10], "needs_route").is_some_and(uint_token);
    }
    if tokens.first() == Some(&"received_member") {
        return tokens.len() == 3
            && status_pair(tokens[1], "id").is_some_and(uint_token)
            && status_pair(tokens[2], "value").is_some_and(bit_token);
    }
    if tokens.first() == Some(&"recipient") {
        return tokens.len() == 4
            && status_pair(tokens[1], "id").is_some_and(uint_token)
            && status_pair(tokens[2], "root").is_some_and(hex64)
            && status_pair(tokens[3], "needs_route").is_some_and(bit_token);
    }
    if tokens.first() == Some(&"object") {
        return tokens.len() == 5
            && status_pair(tokens[1], "recipient").is_some_and(uint_token)
            && status_pair(tokens[2], "ordinal").is_some_and(uint_token)
            && status_pair(tokens[3], "hash").is_some_and(hex64)
            && status_pair(tokens[4], "length").is_some_and(uint_token);
    }
    if tokens.first() == Some(&"inbox") {
        let endpoint = status_pair(tokens.get(6).copied().unwrap_or(""), "endpoint");
        return tokens.len() == 7
            && status_pair(tokens[1], "member").is_some_and(uint_token)
            && status_pair(tokens[2], "pin").is_some_and(hex64)
            && status_pair(tokens[3], "run").is_some_and(hex64)
            && status_pair(tokens[4], "mailbox").is_some_and(hex64)
            && status_pair(tokens[5], "append_revision").is_some_and(uint_token)
            && endpoint.is_some_and(|value| {
                (8..2048).contains(&value.len())
                    && (value.starts_with("http://") || value.starts_with("https://"))
                    && value.bytes().all(|byte| byte.is_ascii_graphic())
            });
    }
    false
}

fn chunked_payload(mark: u8) -> Vec<u8> {
    // Above the 65,536-byte complete-object ceiling, so the outbox must be a transfer of chunks.
    let mut payload = vec![mark; 70_000];
    payload[..34].copy_from_slice(b"relay-8.2a-chunked-payload-marker!");
    payload
}

struct SavedOutbox {
    message: String,
    transfers: Vec<String>,
    hashes: Vec<String>,
    wires: Vec<Vec<u8>>,
}

fn saved_outbox(f: &Fixture) -> SavedOutbox {
    let member = f.loaded().unwrap();
    let db = loki_relay_client::ClientStore::open(
        &retained_root(f).join("transport"),
        &member.roster,
        member.identity.public().id,
    )
    .unwrap();
    let logicals = db.recover_logical(0, 100).unwrap();
    assert_eq!(logicals.len(), 1, "one logical record");
    let logical = &logicals[0];
    let recipients = db.recover_recipients(&logical.key).unwrap();
    assert_eq!(recipients.len(), 3, "three recipient sets");
    assert!(recipients.iter().all(|recipient| recipient.needs_route), "upload not bound");
    assert!(
        recipients.iter().any(|recipient| recipient.recipient == member.identity.public().id),
        "author copy"
    );
    let mut transfers = Vec::new();
    let mut hashes = Vec::new();
    let mut wires = Vec::new();
    for recipient in &recipients {
        let transfer = recipient.transfer.expect("chunk transfer");
        let encoded = hex::encode(transfer);
        assert_eq!(encoded.len(), 64, "transfer id");
        transfers.push(encoded);
        let required = db
            .recover_requirements(&logical.key, recipient.recipient, None, 100)
            .unwrap();
        assert!(required.len() >= 2, "chunked recipient objects");
        for item in &required {
            let object = db.saved_object(&item.hash).unwrap().expect("saved ciphertext");
            assert_eq!(object.wire.len() as u64, item.length, "stored length");
            hashes.push(hex::encode(item.hash));
            wires.push(object.wire);
        }
    }
    assert_eq!(transfers.len(), 3, "three transfers");
    assert_eq!(
        transfers.iter().collect::<std::collections::BTreeSet<_>>().len(),
        3,
        "distinct transfers"
    );
    assert!(
        wires.iter().enumerate().all(|(index, wire)| wires.iter().skip(index + 1).all(|other| other != wire)),
        "recipient ciphertexts differ"
    );
    assert!(db.recover_uploads(0, 100).unwrap().is_empty(), "no upload before the upload command");
    SavedOutbox {
        message: hex::encode(logical.key.message),
        transfers,
        hashes,
        wires,
    }
}

fn same_saved(left: &SavedOutbox, right: &SavedOutbox) {
    assert_eq!(left.message, right.message, "message id");
    assert_eq!(left.transfers, right.transfers, "transfer");
    assert_eq!(left.hashes, right.hashes, "hash");
    assert_eq!(left.wires.len(), right.wires.len(), "wire count");
    for (before, after) in left.wires.iter().zip(right.wires.iter()) {
        assert_eq!(before.len(), after.len(), "wire length");
        assert!(before == after, "wire bytes changed");
    }
}

#[test]
fn communication_cli_parses_required_paths_and_rejects_foreign_commands() {
    let f = RetainedFixture::new();
    for command in ["sign", "payment", "chain"] {
        let mut args = vec![member_arg(command)];
        args.extend(common_member_args(&f));
        assert_usage(&member_cli(&args));
    }
    let payload = f.root.join("payload.bin");
    fs::write(&payload, b"relay-8.2a-payload-sentinel").unwrap();
    let mut missing = vec![member_arg("send")];
    missing.extend(common_member_args(&f));
    missing.extend([member_arg("--payload-file"), member_arg(&payload)]);
    assert_usage(&member_cli(&missing));
    let mut duplicate = vec![member_arg("status")];
    duplicate.extend(common_member_args(&f));
    duplicate.extend([member_arg("--roster"), member_arg(&f.roster)]);
    assert_usage(&member_cli(&duplicate));
    let mut unknown = vec![member_arg("upload")];
    unknown.extend(common_member_args(&f));
    unknown.push(member_arg("--payment"));
    assert_usage(&member_cli(&unknown));
    let mut bad_form = vec![member_arg("send")];
    bad_form.extend(common_member_args(&f));
    bad_form.push(member_arg("--request-id=8282"));
    assert_usage(&member_cli(&bad_form));
    let mut bad_id = vec![member_arg("send")];
    bad_id.extend(common_member_args(&f));
    bad_id.extend([
        member_arg("--payload-file"),
        member_arg(&payload),
        member_arg("--request-id"),
        member_arg("AA".repeat(32)),
    ]);
    let bad_id = member_cli(&bad_id);
    assert_eq!(bad_id.status.code(), Some(1), "bad request id exit");
    assert_eq!(member_stderr(&bad_id).trim(), "member_bounds");
    assert!(bad_id.stdout.is_empty(), "bad request id stdout");
    assert!(!f.root.join("transport").exists(), "rejected commands opened transport");

    let manifest = f.root.join("manifests");
    let capabilities = f.root.join("capabilities");
    let courier_dir = f.root.join("couriers");
    let courier_file = f.root.join("courier.bin");
    fs::create_dir(&manifest).unwrap();
    fs::create_dir(&capabilities).unwrap();
    fs::create_dir(&courier_dir).unwrap();
    private(&manifest, true);
    private(&capabilities, true);
    private(&courier_dir, true);
    fs::write(&courier_file, b"not-a-courier").unwrap();
    private(&courier_file, false);
    let request = "82".repeat(32);
    let mut provision = vec![member_arg("provision")];
    provision.extend(common_member_args(&f));
    provision.extend([
        member_arg("--relay-manifest"),
        member_arg(&manifest),
        member_arg("--provision-capability-files"),
        member_arg(&capabilities),
    ]);
    let provision = member_cli(&provision);
    assert_entered(&provision);
    assert_eq!(provision.status.code(), Some(1), "provision exit");
    assert_eq!(member_stderr(&provision).trim(), "member_bounds");
    let mut export = vec![member_arg("export-config")];
    export.extend(common_member_args(&f));
    export.extend([member_arg("--courier-directory"), member_arg(&courier_dir)]);
    let export = member_cli(&export);
    assert_entered(&export);
    assert_eq!(export.status.code(), Some(1), "export exit");
    let mut import = vec![member_arg("import-config")];
    import.extend(common_member_args(&f));
    import.extend([member_arg("--courier-file"), member_arg(&courier_file)]);
    let import = member_cli(&import);
    assert_entered(&import);
    assert_eq!(import.status.code(), Some(1), "import exit");
    for command in ["rotate-append", "upload"] {
        let mut args = vec![member_arg(command)];
        args.extend(common_member_args(&f));
        let output = member_cli(&args);
        assert_entered(&output);
        assert_eq!(output.status.code(), Some(1), "command exit");
        assert_eq!(member_stderr(&output).trim(), "member_sealed");
    }
    let mut poll = vec![member_arg("poll")];
    poll.extend(common_member_args(&f));
    poll.push(member_arg("--once"));
    let poll = member_cli(&poll);
    assert_entered(&poll);
    assert_eq!(poll.status.code(), Some(1), "poll exit");
    assert_eq!(member_stderr(&poll).trim(), "member_sealed");
    let mut send = vec![member_arg("send")];
    send.extend(common_member_args(&f));
    send.extend([
        member_arg("--payload-file"),
        member_arg(&payload),
        member_arg("--request-id"),
        member_arg(&request),
    ]);
    let send = member_cli(&send);
    assert_eq!(send.status.code(), Some(0), "send exit");
    let send_text = member_stdout(&send);
    assert!(send_text.contains(&format!("request_id={request}")), "request id");
    assert!(send_text.contains("needs_route=3"), "three routes unbound");
    assert_hidden(send.stdout.as_slice(), b"relay-8.2a-payload-sentinel");
    let mut status = vec![member_arg("status")];
    status.extend(common_member_args(&f));
    let status = member_cli(&status);
    assert_eq!(status.status.code(), Some(0), "status exit");
    assert!(member_stdout(&status).contains("section=local"), "local status");
}

#[test]
fn communication_cli_send_saves_three_sets_before_upload_exact_retry_conflict() {
    let f = RetainedFixture::new();
    let payload = f.root.join("payload.bin");
    let other = f.root.join("other-payload.bin");
    fs::write(&payload, chunked_payload(0x21)).unwrap();
    fs::write(&other, chunked_payload(0x22)).unwrap();
    let request = "83".repeat(32);
    let mut send = vec![member_arg("send")];
    send.extend(common_member_args(&f));
    send.extend([
        member_arg("--payload-file"),
        member_arg(&payload),
        member_arg("--request-id"),
        member_arg(&request),
    ]);
    let first = member_cli(&send);
    assert_eq!(first.status.code(), Some(0), "first send");
    assert!(member_stdout(&first).contains("needs_route=3"), "saved before routing");
    let saved = saved_outbox(&f);
    assert!(saved.wires.len() >= 3, "three ciphertext sets");
    let retry = member_cli(&send);
    assert_eq!(retry.status.code(), Some(0), "exact retry");
    assert_eq!(member_stdout(&first), member_stdout(&retry), "retry stdout");
    same_saved(&saved, &saved_outbox(&f));
    let mut conflict = vec![member_arg("send")];
    conflict.extend(common_member_args(&f));
    conflict.extend([
        member_arg("--payload-file"),
        member_arg(&other),
        member_arg("--request-id"),
        member_arg(&request),
    ]);
    let conflict = member_cli(&conflict);
    assert_eq!(conflict.status.code(), Some(1), "conflict exit");
    assert_eq!(member_stderr(&conflict).trim(), "conflict");
    assert!(conflict.stdout.is_empty(), "conflict stdout");
    same_saved(&saved, &saved_outbox(&f));
    assert_hidden(first.stdout.as_slice(), b"relay-8.2a-chunked-payload-marker!");
    assert_hidden(conflict.stderr.as_slice(), b"relay-8.2a-chunked-payload-marker!");
}

#[test]
fn communication_cli_status_public_fields_only() {
    let f = RetainedFixture::new();
    let payload = f.root.join("payload.bin");
    let sentinel = b"relay-8.2a-status-payload-sentinel";
    fs::write(&payload, sentinel).unwrap();
    let request = "84".repeat(32);
    let mut send = vec![member_arg("send")];
    send.extend(common_member_args(&f));
    send.extend([
        member_arg("--payload-file"),
        member_arg(&payload),
        member_arg("--request-id"),
        member_arg(&request),
    ]);
    assert_eq!(member_cli(&send).status.code(), Some(0), "status setup send");
    let mut status = vec![member_arg("status")];
    status.extend(common_member_args(&f));
    let status = member_cli(&status);
    assert_eq!(status.status.code(), Some(0), "status exit");
    let text = member_stdout(&status);
    for field in [
        "section=local",
        "member=",
        "logical_count=1",
        "incoming_count=0",
        "ack_count=0",
        "kind=test",
        "readiness=",
        "digest=",
        "needs_route=3",
        "object recipient=",
        "config absent=1",
    ] {
        assert!(text.contains(field), "public status field missing");
    }
    assert!(!text.contains("section=remote"), "default status stayed local");
    assert!(!text.contains("section=diagnostics"), "diagnostics not requested");
    for line in text.lines() {
        assert!(status_line_public(line), "status line outside public schema");
    }
    assert_hidden(status.stdout.as_slice(), sentinel);
    assert_hidden(status.stderr.as_slice(), sentinel);
    assert_fixture_secrets_absent(&f, status.stdout.as_slice());
    assert_fixture_secrets_absent(&f, status.stderr.as_slice());
    assert!(member_stderr(&status).is_empty(), "status stderr");
}

#[test]
fn communication_cli_readiness_without_config_reports_no_routes() {
    let f = RetainedFixture::new();
    let mut args = vec![member_arg("readiness")];
    args.extend(common_member_args(&f));
    let result = member_cli(&args);
    assert_eq!(result.status.code(), Some(0));
    assert_eq!(member_stdout(&result), "inboxes=0 peers=0 live=0 routable=0\n");
    assert_fixture_secrets_absent(&f, result.stdout.as_slice());
}

#[test]
fn communication_cli_missing_referenced_sealed_config_fails_closed() {
    let f = RetainedFixture::new();
    let member = f.loaded().unwrap();
    let config = config_owner(&member);
    let reference = {
        let mut db = loki_relay_client::ClientStore::open(
            &retained_root(&f).join("transport"),
            &member.roster,
            member.identity.public().id,
        )
        .unwrap();
        let store = loki_poc::relay_member::ConfigStore::open(&f.root, &f.pass).unwrap();
        store.save_revision(&mut db, &member, 1, &config).unwrap()
    };
    let path = f.root.join(reference.file_name());
    let original = fs::read(&path).unwrap();
    let mut status = vec![member_arg("status")];
    status.extend(common_member_args(&f));
    let present = member_cli(&status);
    assert_eq!(present.status.code(), Some(0), "referenced config status");
    let present_text = member_stdout(&present);
    assert!(present_text.contains("config revision=1 hash="), "public config reference");
    assert!(present_text.contains("inbox member="), "authenticated public inbox");
    for secret in [[61u8; 32], [71; 32], [31; 32]] {
        assert_hidden(present.stdout.as_slice(), &secret);
        assert_hidden(present.stdout.as_slice(), hex::encode(secret).as_bytes());
    }
    for inbox in &config.own {
        assert_secret_absent(present.stdout.as_slice(), inbox.read.as_bytes());
        assert_secret_absent(present.stdout.as_slice(), inbox.append.as_bytes());
        assert_secret_absent(present.stdout.as_slice(), inbox.admin.as_bytes());
    }
    let retained = f.root.join("retained-original.sealed");
    fs::rename(&path, &retained).unwrap();
    let orphan = f.root.join("secrets").join("orphan.sealed");
    let higher = f.root.join("secrets").join("relay-config-0000000000000002.sealed");
    fs::write(&orphan, &original).unwrap();
    fs::write(&higher, &original).unwrap();
    private(&orphan, false);
    private(&higher, false);
    let missing = member_cli(&status);
    assert_eq!(missing.status.code(), Some(1), "missing seal exit");
    // bounded_read maps a missing seal's NotFound metadata to MemberError::Io. A different ciphertext stays Sealed.
    assert_eq!(member_stderr(&missing).trim(), "member_io");
    assert!(!member_stdout(&missing).contains("inbox member="), "missing seal adopted");
    let stale = config_owner(&member).encode(&member, 1).unwrap();
    assert!(stale.as_slice() != original.as_slice(), "replacement ciphertext differs");
    fs::write(&path, stale.as_slice()).unwrap();
    private(&path, false);
    let rejected = member_cli(&status);
    assert_eq!(rejected.status.code(), Some(1), "stale seal exit");
    assert_eq!(member_stderr(&rejected).trim(), "member_sealed");
    assert!(!member_stdout(&rejected).contains("inbox member="), "stale seal adopted");
    let db = loki_relay_client::ClientStore::open(
        &retained_root(&f).join("transport"),
        &member.roster,
        member.identity.public().id,
    )
    .unwrap();
    assert_eq!(db.config_reference().unwrap().as_ref(), Some(&reference));
    let retained_bytes = fs::read(&retained).unwrap();
    assert!(retained_bytes == original, "original seal retained");
}
