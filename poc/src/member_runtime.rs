//! JSON-only Rust member-runtime migration slice: profiles, accounts, and vault inventory.
//! It does not run setup, sign, approve, send, or serve the wallet UI.

use crate::{network::VaultNetwork, seal_kdf, state::MemberDir};
use axum::{
    extract::{DefaultBodyLimit, Query, Request, State},
    http::{header, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    net::Ipv4Addr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use zeroize::Zeroizing;

#[derive(Clone, Serialize, Deserialize)]
struct Profile {
    version: u8,
    id: String,
    name: String,
}

// The passphrase stays only in this Rust process until lock or account switch.
struct Unlocked {
    profile: Profile,
    passphrase: Zeroizing<String>,
}

struct Account {
    id: String,
    root: PathBuf,
    _lock: File,
    unlocked: Option<Unlocked>,
}

struct Installation {
    root: PathBuf,
    network: VaultNetwork,
    _lock: File,
    account: Mutex<Account>,
    token: String,
    port: u16,
}

#[derive(Deserialize)]
struct Credentials {
    name: Option<String>,
    passphrase: String,
}

#[derive(Deserialize)]
struct Selection {
    account: String,
}

type ApiResult = Result<Json<Value>, (StatusCode, Json<Value>)>;

fn error(code: StatusCode, message: &str) -> (StatusCode, Json<Value>) {
    (code, Json(json!({"error": message})))
}

fn bad(message: &str) -> (StatusCode, Json<Value>) {
    error(StatusCode::BAD_REQUEST, message)
}

fn checked_file(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_file() => Ok(true),
        Ok(_) => Err(format!("unsafe file: {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.to_string()),
    }
}

fn checked_dir(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_dir() => Ok(true),
        Ok(_) => Err(format!("unsafe directory: {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.to_string()),
    }
}

fn make_dir(path: &Path) -> Result<(), String> {
    fs::create_dir_all(path).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(|e| e.to_string())?;
    }
    Ok(())
}

fn private_dir(path: &Path) -> Result<(), String> {
    if !checked_dir(path)? {
        make_dir(path)?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(path)
            .map_err(|e| e.to_string())?
            .permissions()
            .mode()
            & 0o077
            != 0
        {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

fn owner_file(path: &Path) -> Result<File, String> {
    checked_file(path)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options.open(path).map_err(|e| e.to_string())?;
    file.try_lock()
        .map_err(|_| "This member data root is already open in another app".to_owned())?;
    Ok(file)
}

fn id16(id: &str) -> bool {
    id.len() == 16
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn id64(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn read_membership(path: &Path, id: &str, network: VaultNetwork) -> Result<Value, String> {
    if !checked_file(path)? {
        return Err("Missing vault membership".into());
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|e| e.to_string())?
        .take(4097)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() > 4096 {
        return Err("Vault membership is too large".into());
    }
    let item: Value = serde_json::from_slice(&bytes).map_err(|_| "Invalid vault membership")?;
    let members = item["members"].as_u64().ok_or("Invalid vault membership")?;
    let threshold = match item.get("threshold") {
        None => 2,
        Some(value) => value.as_u64().ok_or("Invalid vault membership")?,
    };
    let slot = item["slot"].as_u64().ok_or("Invalid vault membership")?;
    let saved_network = match item.get("network") {
        None => "regtest",
        Some(value) => value.as_str().ok_or("Invalid vault membership")?,
    };
    let transport = match item.get("transport") {
        None => "local",
        Some(value) => value.as_str().ok_or("Invalid vault membership")?,
    };
    let birth = item.get("birth_height");
    if item["vault"] != id
        || !id64(item["profile"].as_str().unwrap_or(""))
        || saved_network != network.label()
        || !matches!(transport, "local" | "hosted")
        || match network {
            VaultNetwork::Regtest => birth.is_some_and(|value| !value.is_null()),
            VaultNetwork::Testnet => birth.and_then(Value::as_u64).is_none_or(|height| {
                height < u64::from(crate::network::TESTNET_NU7_BIRTH)
                    || height > u64::from(u32::MAX)
            }),
        }
        || !matches!((threshold, members), (2, 3) | (2, 4) | (3, 4))
        || slot == 0
        || slot > members
        || item["name"]
            .as_str()
            .is_none_or(|name| name.is_empty() || name.len() > 80)
    {
        return Err("Invalid vault membership".into());
    }
    Ok(item)
}

fn account_root(root: &Path, id: &str) -> Result<PathBuf, String> {
    if id == "default" {
        return Ok(root.to_owned());
    }
    if !id16(id) || !checked_dir(&root.join("accounts"))? {
        return Err("Choose an existing account".into());
    }
    let path = root.join("accounts").join(id);
    if !checked_dir(&path)? {
        return Err("Choose an existing account".into());
    }
    Ok(path)
}

fn profile_path(root: &Path) -> Result<PathBuf, String> {
    let dir = root.join("profile");
    if checked_dir(&dir)? {
        checked_file(&dir.join("profile.sealed"))?;
    }
    Ok(dir.join("profile.sealed"))
}

fn read_profile(root: &Path, passphrase: &str) -> Result<Profile, String> {
    if !checked_file(&profile_path(root)?)? {
        return Err("Profile does not exist".into());
    }
    let raw = Zeroizing::new(
        MemberDir::open(root, "profile")
            .read_sealed("profile.sealed", passphrase)
            .map_err(|_| "Could not open your profile with that passphrase".to_owned())?,
    );
    let profile: Profile = serde_json::from_slice(&raw).map_err(|_| "Invalid sealed profile")?;
    if profile.version != 1
        || !id64(&profile.id)
        || profile.name.is_empty()
        || profile.name.len() > 80
    {
        return Err("Invalid sealed profile".into());
    }
    Ok(profile)
}

fn new_profile(root: &Path, name: &str, passphrase: &str) -> Result<Profile, String> {
    if !(12..=1024).contains(&passphrase.chars().count()) {
        return Err("Use a passphrase of at least 12 characters".into());
    }
    let name = name.trim();
    if name.is_empty() || name.len() > 80 {
        return Err("Enter a profile name of 1 to 80 UTF-8 bytes".into());
    }
    if checked_file(&profile_path(root)?)? {
        return Err("This profile already exists; unlock it".into());
    }
    let mut id = [0u8; 32];
    OsRng.fill_bytes(&mut id);
    let profile = Profile {
        version: 1,
        id: hex::encode(id),
        name: name.to_owned(),
    };
    MemberDir::create(root, "profile")
        .map_err(|e| e.to_string())?
        .write_sealed(
            "profile.sealed",
            &serde_json::to_vec(&profile).map_err(|e| e.to_string())?,
            passphrase,
        )
        .map_err(|e| e.to_string())?;
    Ok(profile)
}

fn account_ids(root: &Path) -> Result<Vec<String>, String> {
    let mut ids = Vec::new();
    if checked_file(&profile_path(root)?)? {
        ids.push("default".to_owned());
    }
    let accounts = root.join("accounts");
    if checked_dir(&accounts)? {
        for entry in fs::read_dir(accounts).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let id = entry.file_name().to_string_lossy().to_string();
            if id16(&id)
                && checked_dir(&entry.path())?
                && checked_file(&profile_path(&entry.path())?)?
            {
                ids.push(id);
            }
        }
    }
    ids.sort();
    if let Some(pos) = ids.iter().position(|id| id == "default") {
        ids.swap(0, pos);
    }
    Ok(ids)
}

fn load_account(root: &Path, id: &str, network: VaultNetwork) -> Result<Account, String> {
    let path = account_root(root, id)?;
    private_dir(&path)?;
    profile_path(&path)?;
    let vaults = path.join("vaults");
    if checked_dir(&vaults)? {
        for entry in fs::read_dir(vaults).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry.file_name().to_string_lossy().to_string();
            if !id64(&name) {
                continue;
            }
            if !checked_dir(&entry.path())? {
                return Err("Unsafe vault directory".into());
            }
            let membership = entry.path().join("membership.json");
            if checked_file(&membership)? {
                read_membership(&membership, &name, network)?;
            }
        }
    }
    let lock = owner_file(&path.join(".app.lock"))?;
    Ok(Account {
        id: id.to_owned(),
        root: path,
        _lock: lock,
        unlocked: None,
    })
}

fn write_active(root: &Path, id: &str) -> Result<(), String> {
    let target = root.join("active-account");
    checked_file(&target)?;
    let mut nonce = [0u8; 8];
    OsRng.fill_bytes(&mut nonce);
    let temp = root.join(format!(".active-account-{}", hex::encode(nonce)));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temp).map_err(|e| e.to_string())?;
        file.write_all(id.as_bytes()).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        fs::rename(&temp, target).map_err(|e| e.to_string())?;
        // shortcut: a failed directory sync may lose this marker on power loss; retry it when selection becomes a custody gate.
        let _ = File::open(root).and_then(|dir| dir.sync_all());
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(temp);
    }
    result
}

impl Installation {
    fn open(root: &Path, network: VaultNetwork, port: u16) -> Result<Self, String> {
        private_dir(root)?;
        let root = fs::canonicalize(root).map_err(|e| e.to_string())?;
        checked_dir(&root.join("accounts"))?;
        if checked_file(&root.join("membership.json"))? {
            return Err("Existing single-vault data root; choose a new root".into());
        }
        let lock = owner_file(&root.join(".accounts.lock"))?;
        let marker = root.join("active-account");
        let saved = if checked_file(&marker)? {
            let mut data = String::new();
            File::open(&marker)
                .map_err(|e| e.to_string())?
                .take(32)
                .read_to_string(&mut data)
                .map_err(|e| e.to_string())?;
            data.trim().to_owned()
        } else {
            "default".to_owned()
        };
        let active = if saved != "default" && account_ids(&root)?.contains(&saved) {
            saved
        } else {
            "default".to_owned()
        };
        let account = load_account(&root, &active, network)?;
        let mut token = [0u8; 32];
        OsRng.fill_bytes(&mut token);
        Ok(Self {
            root,
            network,
            _lock: lock,
            account: Mutex::new(account),
            token: hex::encode(token),
            port,
        })
    }

    fn accounts(&self) -> Result<Value, String> {
        let account = self.account.lock().map_err(|_| "Account lock failed")?;
        let mut ids = account_ids(&self.root)?;
        if account.id == "default" && !ids.iter().any(|id| id == "default") {
            ids.insert(0, "default".into());
        }
        Ok(
            json!({"active": account.id, "accounts": ids.iter().map(|id| json!({
            "id": id, "name": if id == "default" { "Existing account".to_owned() } else { format!("Account {}", &id[..8]) }
        })).collect::<Vec<_>>() }),
        )
    }

    fn vaults(&self, account: &Account) -> Result<Vec<Value>, String> {
        let unlocked = account
            .unlocked
            .as_ref()
            .ok_or("Unlock your profile first")?;
        let root = account.root.join("vaults");
        if !checked_dir(&root)? {
            return Ok(Vec::new());
        }
        let mut vaults = Vec::new();
        for entry in fs::read_dir(root).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let id = entry.file_name().to_string_lossy().to_string();
            if !id64(&id) {
                continue;
            }
            if !checked_dir(&entry.path())? {
                return Err("Unsafe vault directory".into());
            }
            let path = entry.path().join("membership.json");
            if !checked_file(&path)? {
                continue;
            }
            let item = read_membership(&path, &id, self.network)?;
            if item["profile"] != unlocked.profile.id {
                return Err("Vault membership differs from this profile".into());
            }
            let members = item["members"].as_u64().unwrap();
            let threshold = item["threshold"].as_u64().unwrap_or(2);
            let slot = item["slot"].as_u64().unwrap();
            vaults.push(
                json!({"vault":id,"profile":unlocked.profile.id,"name":item["name"],
                "slot":slot,"threshold":threshold,"members":members,"network":self.network.label(),
                "birth_height":item["birth_height"],"transport":item["transport"]}),
            );
        }
        vaults.sort_by(|a, b| a["vault"].as_str().cmp(&b["vault"].as_str()));
        Ok(vaults)
    }
}

fn reply(result: Result<Value, String>) -> ApiResult {
    result.map(Json).map_err(|message| bad(&message))
}

async fn accounts(State(app): State<Arc<Installation>>) -> ApiResult {
    reply(app.accounts())
}

async fn status(
    State(app): State<Arc<Installation>>,
    Query(query): Query<HashMap<String, String>>,
) -> ApiResult {
    if query.contains_key("vault") {
        return Err(error(
            StatusCode::NOT_IMPLEMENTED,
            "Per-vault workflow status is not in this migration slice",
        ));
    }
    let account = app.account.lock().map_err(|_| bad("Account lock failed"))?;
    if !checked_file(&profile_path(&account.root).map_err(|e| bad(&e))?).map_err(|e| bad(&e))? {
        return Ok(Json(
            json!({"phase":"new_profile","network":app.network.label(),"migration_slice":true}),
        ));
    }
    let Some(unlocked) = account.unlocked.as_ref() else {
        return Ok(Json(
            json!({"phase":"locked","network":app.network.label(),"migration_slice":true}),
        ));
    };
    let vaults = app.vaults(&account).map_err(|e| bad(&e))?;
    Ok(Json(
        json!({"phase":"home","network":app.network.label(),"profile":unlocked.profile,
        "vaults":vaults,"migration_slice":true}),
    ))
}

async fn create_profile(
    State(app): State<Arc<Installation>>,
    Json(input): Json<Credentials>,
) -> ApiResult {
    let passphrase = Zeroizing::new(input.passphrase);
    let mut account = app.account.lock().map_err(|_| bad("Account lock failed"))?;
    let profile = new_profile(
        &account.root,
        input.name.as_deref().unwrap_or(""),
        &passphrase,
    )
    .map_err(|e| bad(&e))?;
    seal_kdf::enable_session_cache(&passphrase);
    account.unlocked = Some(Unlocked {
        profile: profile.clone(),
        passphrase,
    });
    Ok(Json(json!({"profile":profile})))
}

async fn unlock(State(app): State<Arc<Installation>>, Json(input): Json<Credentials>) -> ApiResult {
    let passphrase = Zeroizing::new(input.passphrase);
    if !(12..=1024).contains(&passphrase.chars().count()) {
        return Err(bad("Use a passphrase of at least 12 characters"));
    }
    let mut account = app.account.lock().map_err(|_| bad("Account lock failed"))?;
    let profile = read_profile(&account.root, &passphrase).map_err(|e| bad(&e))?;
    seal_kdf::enable_session_cache(&passphrase);
    account.unlocked = Some(Unlocked {
        profile: profile.clone(),
        passphrase,
    });
    Ok(Json(json!({"profile":profile})))
}

async fn lock(State(app): State<Arc<Installation>>) -> ApiResult {
    let mut account = app.account.lock().map_err(|_| bad("Account lock failed"))?;
    account.unlocked = None;
    seal_kdf::clear_session_cache();
    Ok(Json(json!({"locked":true})))
}

async fn select(State(app): State<Arc<Installation>>, Json(input): Json<Selection>) -> ApiResult {
    if input.account != "default" && !id16(&input.account) {
        return Err(bad("Choose an existing account"));
    }
    {
        let mut account = app.account.lock().map_err(|_| bad("Account lock failed"))?;
        if input.account != account.id {
            if !account_ids(&app.root)
                .map_err(|e| bad(&e))?
                .contains(&input.account)
            {
                return Err(bad("Choose an existing account"));
            }
            let next = load_account(&app.root, &input.account, app.network).map_err(|e| bad(&e))?;
            write_active(&app.root, &input.account).map_err(|e| bad(&e))?;
            account.unlocked = None;
            seal_kdf::clear_session_cache();
            *account = next;
        }
    }
    reply(app.accounts())
}

async fn create_account(
    State(app): State<Arc<Installation>>,
    Json(input): Json<Credentials>,
) -> ApiResult {
    let passphrase = Zeroizing::new(input.passphrase);
    let name = input.name.unwrap_or_default();
    if !(12..=1024).contains(&passphrase.chars().count())
        || name.trim().is_empty()
        || name.trim().len() > 80
    {
        return Err(bad("Enter a name and passphrase of at least 12 characters"));
    }
    let mut account = app.account.lock().map_err(|_| bad("Account lock failed"))?;
    let accounts = app.root.join("accounts");
    if !checked_dir(&accounts).map_err(|e| bad(&e))? {
        make_dir(&accounts).map_err(|e| bad(&e))?;
    }
    let (id, root) = loop {
        let mut random = [0u8; 8];
        OsRng.fill_bytes(&mut random);
        let id = hex::encode(random);
        let root = accounts.join(&id);
        match fs::create_dir(&root) {
            Ok(()) => break (id, root),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(bad(&e.to_string())),
        }
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .map_err(|e| bad(&e.to_string()))?;
    }
    let mut next = load_account(&app.root, &id, app.network).map_err(|e| bad(&e))?;
    let profile = new_profile(&root, &name, &passphrase).map_err(|e| bad(&e))?;
    next.unlocked = Some(Unlocked {
        profile,
        passphrase,
    });
    write_active(&app.root, &id).map_err(|e| bad(&e))?;
    account.unlocked = None;
    seal_kdf::clear_session_cache();
    seal_kdf::enable_session_cache(&next.unlocked.as_ref().unwrap().passphrase);
    *account = next;
    drop(account);
    reply(app.accounts())
}

async fn authorize(State(app): State<Arc<Installation>>, request: Request, next: Next) -> Response {
    let expected_host = format!("127.0.0.1:{}", app.port);
    let host = request
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok());
    let origin = request
        .headers()
        .get(header::ORIGIN)
        .and_then(|h| h.to_str().ok());
    let supplied = request
        .headers()
        .get("x-loki-token")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    let mismatch = supplied
        .as_bytes()
        .iter()
        .zip(app.token.as_bytes())
        .fold(0u8, |diff, (a, b)| diff | (a ^ b));
    let authorized = host == Some(expected_host.as_str())
        && supplied.len() == app.token.len()
        && mismatch == 0
        && (request.method() == axum::http::Method::GET
            || origin.is_none()
            || origin == Some(format!("http://{expected_host}").as_str()));
    let mut response = if authorized {
        next.run(request).await
    } else {
        error(StatusCode::FORBIDDEN, "Unauthorized").into_response()
    };
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    response
}

/// Run a limited local JSON service. The full Python wallet remains separate during migration.
pub async fn serve(root: PathBuf, network: VaultNetwork, port: u16) -> Result<(), String> {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, port))
        .await
        .map_err(|e| e.to_string())?;
    let actual = listener.local_addr().map_err(|e| e.to_string())?.port();
    let app = Arc::new(Installation::open(&root, network, actual)?);
    let router = Router::new()
        .route("/api/accounts", get(accounts))
        .route("/api/status", get(status))
        .route("/api/profile-create", post(create_profile))
        .route("/api/unlock", post(unlock))
        .route("/api/lock", post(lock))
        .route("/api/account-switch", post(select))
        .route("/api/account-create", post(create_account))
        .layer(DefaultBodyLimit::max(4096))
        .layer(middleware::from_fn_with_state(app.clone(), authorize))
        .with_state(app.clone());
    println!(
        "Member runtime migration slice API: http://127.0.0.1:{actual} token={}",
        app.token
    );
    axum::serve(listener, router)
        .await
        .map_err(|e| e.to_string())
}
