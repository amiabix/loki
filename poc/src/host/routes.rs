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
        .route("/api/roster", post(ceremony::roster))
        .route("/api/agree", post(ceremony::agree))
        .route("/api/agreed", post(ceremony::agreed))
        .route("/api/session", post(ceremony::session))
        .route("/api/address", get(ceremony::address))
        .route("/api/balance", post(payment::balance))
        .route("/api/payment-draft", post(payment::draft))
        .route("/api/payment-publish", post(payment::publish))
        .route("/api/payment-review", post(payment::review))
        .route("/api/payment-approve", post(payment::approve))
        .route("/api/payment-discard", post(payment::discard))
        .route("/api/payment-finish", post(payment::finish))
        .route("/api/payment-verify", post(payment::verify))
        .route("/api/payments", get(payment::payments))
        .route("/api/pending", get(payment::pending))
        .route("/api/payment-status", get(payment::status))
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
    // The ceremony endpoints are token-authenticated, member-to-member calls (also exempt from
    // the process token in `auth`): a native peer reaches them with no `Origin` and so skips the
    // pairing check, and a browser joiner from another origin reaches ONLY these four, still gated
    // by its invite token. So CORS-open them to any origin (they expose nothing the invite token
    // does not already guard); every other `/api/*` route stays locked to the paired coordinator.
    let open_ceremony = matches!(
        req.uri().path(),
        "/api/enroll" | "/api/agreed" | "/api/roster" | "/api/session"
    );
    if let Some(origin) = &origin {
        if !open_ceremony {
            let allowed = st.config.registration.as_ref().map(|c| c.coordinator.as_str());
            if allowed.is_none() || origin.to_str().ok() != allowed {
                return err(StatusCode::FORBIDDEN, "browser origin is not paired").into_response();
            }
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
        None => match st.registration_error.read().await.as_ref() {
            Some(e) => err(StatusCode::CONFLICT, format!("device has not self-registered; retrying after: {e}")),
            None => err(StatusCode::CONFLICT, "device has not self-registered"),
        },
    }
}

/// Every `/api/*` request must carry the process token (the web proxy injects it).
async fn auth(State(st): State<Shared>, req: Request, next: Next) -> Result<Response, Response> {
    if matches!(
        req.uri().path(),
        "/api/enroll" | "/api/agreed" | "/api/roster" | "/api/session"
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
    let reply = blocking(move || crate::profile::create(&data, &for_block, &name)).await;
    if reply.0 == StatusCode::OK {
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
    let unlocked = tokio::task::spawn_blocking(move || {
        let unlocked = Session::unlock(data.clone(), for_block.clone())?;
        recovery::seal_missing_backups_logged(&data, &for_block);
        Ok::<_, String>(unlocked)
    });
    match unlocked.await {
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
    let session = st.session.read().await;
    let Some(session) = session.as_ref() else {
        let phase = if crate::profile::exists(&st.config.data) {
            "locked"
        } else {
            "new_profile"
        };
        return ok(json!({ "phase": phase, "network": network }));
    };
    // Unlocked: re-read the profile for its name/id and list the member's vaults.
    match crate::profile::open(&session.data, &session.passphrase) {
        Ok(profile) => {
            let vaults = match ceremony::vault_summaries(&session.data, &session.passphrase) {
                Ok(v) => v,
                Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e),
            };
            ok(json!({ "phase": "home", "network": network, "profile": profile, "vaults": vaults }))
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}
