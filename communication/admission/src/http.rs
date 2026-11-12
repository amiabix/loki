use crate::{store::parse_package, AdmissionError, AdmissionStore};
use axum::{
    body::{Body, Bytes},
    extract::{rejection::BytesRejection, DefaultBodyLimit, Extension, Request, State},
    http::{header, HeaderMap, Method, StatusCode, Uri},
    middleware::{self, Next},
    response::Response,
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use loki_relay_protocol::{
    admission,
    canonical::{self, Value},
};
use std::{
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use zeroize::Zeroizing;
#[derive(Clone)]
struct Service {
    store: Arc<Mutex<AdmissionStore>>,
    gate: Arc<Semaphore>,
    deadline: Duration,
    provision: Arc<Notify>,
}
fn public_error(status: StatusCode, code: &str) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/cbor")
        .body(Body::from(
            canonical::encode(&Value::Array(vec![Value::Text(code.into())])).unwrap_or_default(),
        ))
        .unwrap()
}
async fn guard(State(service): State<Service>, mut request: Request, next: Next) -> Response {
    let Ok(permit) = service.gate.clone().try_acquire_owned() else {
        return public_error(StatusCode::SERVICE_UNAVAILABLE, "unavailable");
    };
    request.extensions_mut().insert(Arc::new(permit));
    match tokio::time::timeout(service.deadline, next.run(request)).await {
        Ok(reply) => reply,
        Err(_) => public_error(StatusCode::GATEWAY_TIMEOUT, "unavailable"),
    }
}
pub fn router(store: Arc<Mutex<AdmissionStore>>) -> Router {
    router_with_provisioning(store, Arc::new(Notify::new()))
}
/// As `router`, waking `provision` after every accepted mailbox command so the
/// provisioner need not wait for its next tick.
pub fn router_with_provisioning(
    store: Arc<Mutex<AdmissionStore>>,
    provision: Arc<Notify>,
) -> Router {
    let deadline = Duration::from_secs(
        store
            .lock()
            .map(|store| store.request_seconds())
            .unwrap_or(1),
    );
    let service = Service {
        store,
        deadline,
        gate: Arc::new(Semaphore::new(16)),
        provision,
    };
    Router::new()
        .route("/health", get(|| async { StatusCode::OK }))
        .route("/v1/setup", post(handle))
        .route("/v1/setup/{ceremony}", get(handle))
        .route("/v1/setup/{ceremony}/claims/{slot}", post(handle))
        .route("/v1/setup/{ceremony}/mailboxes", post(handle))
        .route("/v1/setup/{ceremony}/checkpoints/{slot}", post(handle))
        .route("/v1/setup/{ceremony}/terminal", post(handle))
        .route(
            "/v1/setup/{ceremony}/terminal-notices",
            get(handle).post(handle),
        )
        .layer(DefaultBodyLimit::max(admission::MAX_REQUEST))
        .layer(middleware::from_fn_with_state(service.clone(), guard))
        .with_state(service)
}
async fn handle(
    State(service): State<Service>,
    Extension(permit): Extension<Arc<OwnedSemaphorePermit>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: std::result::Result<Bytes, BytesRejection>,
) -> Response {
    if uri.query().is_some()
        || headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            != Some("application/cbor")
        || headers.contains_key(header::CONTENT_ENCODING)
    {
        return public_error(StatusCode::BAD_REQUEST, "malformed");
    }
    let Ok(body) = body else {
        return public_error(StatusCode::BAD_REQUEST, "malformed");
    };
    let request = match parse_package(&body) {
        Ok(request) => request,
        Err(error) => return public_error(StatusCode::BAD_REQUEST, error.code()),
    };
    let mailbox = matches!(request.command, admission::AdmissionCommand::Mailbox { .. });
    let (expected_method, path) = admission::request_target(&request.command);
    if method.as_str() != expected_method || uri.path() != path {
        return public_error(StatusCode::BAD_REQUEST, "malformed");
    }
    let credential = match headers.get(header::AUTHORIZATION) {
        None => None,
        Some(header) => {
            let decoded = (|| {
                let text = header.to_str().map_err(|_| AdmissionError::Malformed)?;
                if text.len() > 5500 {
                    return Err(AdmissionError::Malformed);
                }
                let token = text
                    .strip_prefix("Bearer ")
                    .ok_or(AdmissionError::Malformed)?;
                let decoded = Zeroizing::new(
                    URL_SAFE_NO_PAD
                        .decode(token)
                        .map_err(|_| AdmissionError::Malformed)?,
                );
                if decoded.len() > 4096 {
                    return Err(AdmissionError::Malformed);
                }
                Ok(decoded)
            })();
            match decoded {
                Ok(credential) => Some(credential),
                Err(error) => return public_error(StatusCode::BAD_REQUEST, error.code()),
            }
        }
    };
    let now = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(now) => now.as_secs(),
        Err(_) => return public_error(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    };
    let provision = service.provision.clone();
    let result = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut store = service
            .store
            .lock()
            .map_err(|_| AdmissionError::Unavailable)?;
        store.execute(&body, credential.as_ref().map(|c| c.as_slice()), now)
    })
    .await;
    if mailbox && matches!(result, Ok(Ok(_))) {
        provision.notify_one();
    }
    match result {
        Ok(Ok(reply)) => Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "application/cbor")
            .body(Body::from(reply.bytes))
            .unwrap(),
        Ok(Err(error)) => public_error(StatusCode::SERVICE_UNAVAILABLE, error.code()),
        Err(_) => public_error(StatusCode::SERVICE_UNAVAILABLE, "unavailable"),
    }
}
