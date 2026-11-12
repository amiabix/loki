use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use super::{
    ceremony, device, payment, recovery,
    state::{Session, Shared},
};

pub(super) type Reply = (StatusCode, Json<Value>);

pub(super) fn ok(v: Value) -> Reply {
    (StatusCode::OK, Json(v))
}

pub(super) fn err(code: StatusCode, message: impl Into<String>) -> Reply {
    (code, Json(json!({ "error": message.into() })))
}

/// Run a blocking library call (which drives the relay runtime via `block_on`) off the
/// async worker threads — calling it inline would panic (runtime-within-runtime).
pub(super) async fn blocking<F>(f: F) -> Reply
where
    F: FnOnce() -> Result<Value, String> + Send + 'static,
{
    match tokio::task::spawn_blocking(f).await {
        Ok(Ok(v)) => ok(v),
        Ok(Err(e)) => err(StatusCode::BAD_REQUEST, e),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, format!("task join: {e}")),
    }
}

pub fn router(state: Shared) -> Router {
    Router::new()
        .route("/api/profile-create", post(profile_create))
        .route("/api/unlock", post(unlock))
        .route("/api/lock", post(lock))
        .route("/api/status", get(status))
        .route("/api/registration", get(registration))
        .route("/api/create", post(ceremony::create))
        .route("/api/join", post(ceremony::join))
        .route("/api/enroll", post(ceremony::enroll))
        .route("/api/roster", get(ceremony::roster))
        .route("/api/agree", post(ceremony::agree))
        .route("/api/resume", post(ceremony::resume))
        .route("/api/agreed", post(ceremony::agreed))
        .route("/api/session", get(ceremony::session))
        .route("/api/address", get(ceremony::address))
        .route("/api/balance", post(payment::balance))
        .route("/api/payment-draft", post(payment::draft))
        .route("/api/payment-publish", post(payment::publish))
        .route("/api/payment-session", get(payment::session))
        .route("/api/payment-peer", post(payment::peer_session))
        .route("/api/payment-review", post(payment::review))
        .route("/api/payment-approve", post(payment::approve))
        .route("/api/payment-finish", post(payment::finish))
        .route("/api/payment-verify", post(payment::verify))
        .route("/api/payments", get(payment::payments))
        .route("/api/pending", get(payment::pending))
        .route("/api/proposed", get(payment::proposed))
        .route("/api/recovery-setup", post(recovery::setup))
        .route("/api/recovery-status", get(recovery::status))
        .route("/api/recovery-backup", get(recovery::fetch))
        .route("/api/recovery-restore", post(recovery::restore))
        .route("/api/device-enroll", post(device::enroll))
        .route("/api/device-challenge", get(device::challenge))
        .route("/api/device-login", post(device::login))
        .route("/api/device-revoke", post(device::revoke))
        .layer(middleware::from_fn_with_state(state.clone(), auth))
        .layer(middleware::from_fn_with_state(state.clone(), browser_origin))
        .with_state(state)
}

/// Only the explicitly paired browser origin can read this device's API. The process
/// capability is still required; CORS never authorizes a member action on its own.
async fn browser_origin(State(st): State<Shared>, req: Request, next: Next) -> Response {
    let origin = req.headers().get("origin").cloned();
    if let Some(origin) = &origin {
        let allowed = st.config.registration.as_ref().map(|c| c.coordinator.as_str());
        if allowed.is_none() || origin.to_str().ok() != allowed {
            return err(StatusCode::FORBIDDEN, "browser origin is not paired").into_response();
        }
    }
    let mut response = if req.method() == axum::http::Method::OPTIONS {
        let method = req.headers().get("access-control-request-method").and_then(|v| v.to_str().ok());
        let headers = req.headers().get("access-control-request-headers").and_then(|v| v.to_str().ok()).unwrap_or("");
        if origin.is_none() || !matches!(method, Some("GET" | "POST"))
            || headers.split(',').any(|h| !matches!(h.trim().to_ascii_lowercase().as_str(), "" | "content-type" | "x-loki-token")) {
            return err(StatusCode::FORBIDDEN, "unsupported browser request").into_response();
        }
        StatusCode::NO_CONTENT.into_response()
    } else { next.run(req).await };
    if let Some(origin) = origin {
        let headers = response.headers_mut();
        headers.insert("access-control-allow-origin", origin);
        headers.insert("access-control-allow-methods", "GET, POST".parse().unwrap());
        headers.insert("access-control-allow-headers", "content-type, x-loki-token".parse().unwrap());
        headers.insert("access-control-allow-private-network", "true".parse().unwrap());
        headers.insert("vary", "Origin".parse().unwrap());
    }
    response.headers_mut().insert("cache-control", "no-store".parse().unwrap());
    response
}

async fn registration(State(st): State<Shared>) -> Reply {
    match st.registration.read().await.as_ref() {
        Some(member) => ok(json!(member)),
        None => err(StatusCode::CONFLICT, "device has not self-registered"),
    }
}

/// Local member endpoints require the process token. Peer protocol handlers
/// authenticate their own roster-bound messages; payment-peer returns only ciphertext.
async fn auth(State(st): State<Shared>, req: Request, next: Next) -> Result<Response, Response> {
    if matches!(
        req.uri().path(),
        "/api/enroll"
            | "/api/agreed"
            | "/api/roster"
            | "/api/session"
            | "/api/payment-peer"
    ) {
        return Ok(next.run(req).await);
    }
    let presented = req
        .headers()
        .get("x-loki-token")
        .and_then(|v| v.to_str().ok());
    if presented == Some(st.config.token.as_str()) {
        Ok(next.run(req).await)
    } else {
        Err(err(StatusCode::UNAUTHORIZED, "invalid process token").into_response())
    }
}

fn str_field(body: &Value, name: &str) -> Result<String, Reply> {
    body.get(name)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, format!("missing {name}")))
}

async fn set_session(st: &Shared, passphrase: Zeroizing<String>) {
    crate::seal_kdf::enable_session_cache(&passphrase);
    *st.session.write().await = Some(Session {
        passphrase,
        data: st.config.data.clone(),
    });
}

async fn profile_create(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    let (name, pass) = match (str_field(&body, "name"), str_field(&body, "passphrase")) {
        (Ok(n), Ok(p)) => (n, p),
        (Err(e), _) | (_, Err(e)) => return e,
    };
    let data = st.config.data.clone();
    let passphrase = Zeroizing::new(pass);
    let for_block = passphrase.clone();
    let mut reply = blocking(move || crate::profile::create(&data, &for_block, &name)).await;
    if reply.0 == StatusCode::OK {
        let words = match recovery::establish_recovery(&st.config.data).await {
            Ok(words) => words,
            Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e),
        };
        reply.1 .0["recovery_words"] = json!(words.as_ref().map(|words| words.split_whitespace().collect::<Vec<_>>()));
        // Creating a profile unlocks it (the prototype's behaviour).
        set_session(&st, passphrase).await;
    }
    reply
}

async fn unlock(State(st): State<Shared>, Json(body): Json<Value>) -> Reply {
    let pass = match str_field(&body, "passphrase") {
        Ok(p) => p,
        Err(e) => return e,
    };
    let data = st.config.data.clone();
    let passphrase = Zeroizing::new(pass);
    let for_block = passphrase.clone();
    match tokio::task::spawn_blocking(move || Session::unlock(data, for_block)).await {
        Ok(Ok((session, profile))) => {
            *st.session.write().await = Some(session);
            ok(json!({ "unlocked": true, "profile": profile }))
        }
        Ok(Err(e)) => err(StatusCode::UNAUTHORIZED, e),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, format!("task join: {e}")),
    }
}

async fn lock(State(st): State<Shared>) -> Reply {
    *st.session.write().await = None;
    crate::seal_kdf::clear_session_cache();
    ok(json!({ "locked": true }))
}

async fn status(
    State(st): State<Shared>,
    axum::extract::Query(query): axum::extract::Query<std::collections::BTreeMap<String, String>>,
) -> Reply {
    if let Some(vault) = query.get("vault") {
        return ceremony::status(st, vault.clone()).await;
    }
    let network = st.config.network.clone();
    // Where this signer keeps its keys: "apple" = the device's Secure Enclave, "software" = a
    // passphrase-sealed file. The UI shows the matching key-gen step and badge.
    let secure_element = st.config.secure_element.clone();
    let session = st.session.read().await;
    let Some(session) = session.as_ref() else {
        let phase = if crate::profile::exists(&st.config.data) {
            "locked"
        } else {
            "new_profile"
        };
        return ok(json!({ "phase": phase, "network": network, "secure_element": secure_element }));
    };
    // Unlocked: re-read the profile for its name/id and list the member's vaults.
    match crate::profile::open(&session.data, &session.passphrase) {
        Ok(profile) => {
            let vaults = match ceremony::vault_summaries(&session.data, &session.passphrase) {
                Ok(v) => v,
                Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e),
            };
            ok(json!({ "phase": "home", "network": network, "secure_element": secure_element, "profile": profile, "vaults": vaults }))
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::state::{AppState, Config};
    use crate::signer::recovery::RecoveryKey;
    use std::{collections::BTreeMap, fs, path::Path};

    fn state(data: &Path) -> Shared {
        std::sync::Arc::new(AppState::new(Config {
            registration: None,
            bind: "127.0.0.1".parse().unwrap(), advertise_url: None,
            data: data.to_path_buf(), port: 3001, network: "regtest".into(),
            lightwalletd: None, transport: "local".into(), secure_element: "software".into(),
            operator_bundle: None, nonce_witnesses: None, operator_key: None, enrollment_issuer: None,
            development_http: false, token: "test".into(),
            frostd_url: "http://127.0.0.1:2744".into(), peers: BTreeMap::new(), loopback_peers: false,
        }))
    }

    #[tokio::test]
    async fn direct_device_requests_require_pairing_and_exact_browser_origin() {
        use tonic::codegen::Service;
        let mut st = state(Path::new("/unused"));
        std::sync::Arc::get_mut(&mut st).unwrap().config.registration = Some(super::super::RegistrationConfig {
            coordinator: "http://localhost:3001".into(), slot: None,
            passphrase_file: Some(Path::new("/unused").into()), name: "Member".into(), pairing_challenge: None,
        });
        let mut app = router(st);
        for (origin, capability, expected) in [
            ("http://localhost:3001", Some("test"), StatusCode::OK),
            ("http://localhost:3001", None, StatusCode::UNAUTHORIZED),
            ("http://evil.example", Some("test"), StatusCode::FORBIDDEN),
        ] {
            let mut request = Request::builder().uri("/api/status").header("origin", origin);
            if let Some(value) = capability { request = request.header("x-loki-token", value); }
            let response = app.call(request.body(axum::body::Body::empty()).unwrap()).await.unwrap();
            assert_eq!(response.status(), expected);
            if origin == "http://localhost:3001" {
                assert_eq!(response.headers()["access-control-allow-origin"], origin);
            }
        }
        let request = Request::builder().method("OPTIONS").uri("/api/status")
            .header("origin", "http://localhost:3001").header("access-control-request-method", "GET")
            .header("access-control-request-headers", "x-loki-token")
            .body(axum::body::Body::empty()).unwrap();
        assert_eq!(app.call(request).await.unwrap().status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn unaudited_repair_routes_are_unreachable() {
        use tonic::codegen::Service;
        let mut app = router(state(Path::new("/unused")));
        for path in ["repair-begin", "repair-contribute"] {
            let request = Request::builder().method("POST").uri(format!("/api/{path}"))
                .header("x-loki-token", "test").header("content-type", "application/json")
                .body(axum::body::Body::from("{}")).unwrap();
            assert_eq!(app.call(request).await.unwrap().status(), StatusCode::NOT_FOUND, "{path}");
        }
    }

    #[tokio::test]
    async fn payment_reads_require_process_authentication() {
        use tonic::codegen::Service;
        let mut app = router(state(Path::new("/unused")));
        for path in ["payment-session", "proposed"] {
            for token in [None, Some("wrong"), Some("test")] {
                let mut request = Request::builder().uri(format!("/api/{path}"));
                if let Some(token) = token { request = request.header("x-loki-token", token); }
                let request = request.body(axum::body::Body::empty()).unwrap();
                let response = app.call(request).await.unwrap();
                let expected = if token == Some("test") { StatusCode::BAD_REQUEST } else { StatusCode::UNAUTHORIZED };
                assert_eq!(response.status(), expected);
            }
        }
    }

    #[tokio::test]
    async fn profile_creation_returns_recovery_words_once_and_persists_only_public_keys() {
        let data = std::env::temp_dir().join(format!("loki-profile-recovery-{}", uuid::Uuid::new_v4()));
        let st = state(&data);
        let body = json!({ "name": "Alice", "passphrase": "pass" });
        let reply = profile_create(State(st.clone()), Json(body.clone())).await;
        assert_eq!(reply.0, StatusCode::OK);
        assert_eq!(reply.1 .0["name"], "Alice");
        let words = reply.1 .0["recovery_words"].as_array().expect("new account needs recovery words");
        assert_eq!(words.len(), 24);
        let words = Zeroizing::new(words.iter().map(|w| w.as_str().unwrap()).collect::<Vec<_>>().join(" "));
        let key = RecoveryKey::from_words(&words).unwrap();
        let pubkeys = fs::read(data.join("recovery.pub")).unwrap();
        assert_eq!(pubkeys.len(), 64);
        assert_eq!(recovery::read_encryption_pubkey(&data), Some(key.public_bytes()));
        assert_eq!(recovery::read_authz_pubkey(&data), Some(key.signing_public()));
        assert_eq!(fs::read_dir(&data).unwrap().count(), 2);
        assert!(crate::profile::open(&data, "pass").unwrap().get("recovery_words").is_none());
        assert!(st.session.read().await.is_some());
        assert_eq!(recovery::setup(State(st.clone())).await.0, StatusCode::CONFLICT);
        let reply = recovery::status(State(st.clone()), axum::extract::Query(BTreeMap::new())).await;
        assert_eq!(reply.1 .0["recovery_identity"], true);
        assert_eq!(reply.1 .0["recovery_backup"], false);
        assert_eq!(profile_create(State(st.clone()), Json(body)).await.0, StatusCode::BAD_REQUEST);
        assert_eq!(lock(State(st.clone())).await.0, StatusCode::OK);
        let reply = unlock(State(st), Json(json!({ "passphrase": "pass" }))).await;
        assert_eq!(reply.0, StatusCode::OK);
        assert!(reply.1 .0["profile"].get("recovery_words").is_none());
        assert_eq!(fs::read(data.join("recovery.pub")).unwrap(), pubkeys);
        fs::remove_dir_all(data).unwrap();
    }

    #[tokio::test]
    async fn profile_creation_preserves_an_existing_recovery_identity() {
        let data = std::env::temp_dir().join(format!("loki-existing-recovery-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&data).unwrap();
        let st = state(&data);
        assert_eq!(recovery::setup(State(st.clone())).await.0, StatusCode::UNAUTHORIZED);
        set_session(&st, Zeroizing::new("pass".into())).await;
        let reply = recovery::setup(State(st.clone())).await;
        assert_eq!(reply.0, StatusCode::OK);
        let words = reply.1 .0["words"].as_str().unwrap();
        assert_eq!(words.split_whitespace().count(), 24);
        let key = RecoveryKey::from_words(words).unwrap();
        let pubkeys = fs::read(data.join("recovery.pub")).unwrap();
        assert_eq!(recovery::read_encryption_pubkey(&data), Some(key.public_bytes()));
        assert_eq!(recovery::read_authz_pubkey(&data), Some(key.signing_public()));
        assert_eq!(lock(State(st.clone())).await.0, StatusCode::OK);

        let reply = profile_create(State(st.clone()), Json(json!({ "name": "Alice", "passphrase": "pass" }))).await;
        assert_eq!(reply.0, StatusCode::OK);
        assert_eq!(reply.1 .0.get("recovery_words"), Some(&Value::Null));
        assert_eq!(fs::read(data.join("recovery.pub")).unwrap(), pubkeys);
        assert_eq!(recovery::setup(State(st)).await.0, StatusCode::CONFLICT);
        fs::remove_dir_all(data).unwrap();
    }
}
