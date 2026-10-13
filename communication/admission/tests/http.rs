mod support;
use ed25519_dalek::SigningKey;
use loki_relay_client::{verify_admission_reply, AdmissionHttp, AdmissionOutcome};
use loki_setup_admission::{http::router, AdmissionStore, EnrollmentVerifier};
use std::sync::{Arc, Mutex};
use support::*;
#[tokio::test]
async fn real_http_scoped_create_claim_replay_and_signed_rejection() {
    let db = OwnedDb::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());
    let cfg = config_with_admission(&endpoint);
    let store = AdmissionStore::open(
        &db.root,
        &cfg,
        EnrollmentVerifier::new(Some(
            SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
        )),
        SigningKey::from_bytes(&[8; 32]),
    )
    .unwrap();
    let app = router(Arc::new(Mutex::new(store)));
    let (stop_rx, stop_tx) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = stop_tx.await;
            })
            .await
            .unwrap()
    });
    let client = AdmissionHttp::development(&cfg).unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let g = grant_for(&cfg, 2, 48, now + 3600);
    let req = create_for(1, [70; 32], 4, &g, &cfg);
    let created = client
        .execute_authenticated(&identity(1, 1), &req, Some(&g))
        .await
        .unwrap();
    assert!(matches!(created.outcome(), AdmissionOutcome::Accepted(_)));
    let saved = created.package().to_vec();
    assert_eq!(client.execute(&req, None).await.unwrap().package(), saved);
    let claim = claim(2, [70; 32], 4, 4);
    assert!(matches!(
        client
            .execute_authenticated(&identity(4, 4), &claim, Some(&[4; 32]))
            .await
            .unwrap()
            .outcome(),
        AdmissionOutcome::Accepted(_)
    ));
    let changed = claim_for_changed_identity();
    let rejected = client
        .execute_authenticated(&identity(4, 12), &changed, Some(&[4; 32]))
        .await
        .unwrap();
    assert!(matches!(
        rejected.outcome(),
        AdmissionOutcome::Rejected("conflict")
    ));
    let mut wrong = saved.clone();
    let end = wrong.len() - 1;
    wrong[end] ^= 1;
    assert!(verify_admission_reply(&cfg, &req, &wrong).is_err());
    assert!(verify_admission_reply(&cfg, &claim, &saved).is_err());
    let default_client = AdmissionHttp::new(&cfg);
    assert!(default_client.is_err());
    stop_rx.send(()).unwrap();
    server.await.unwrap();
}
fn claim_for_changed_identity() -> Vec<u8> {
    claim(3, [70; 32], 4, 12)
}

#[tokio::test]
async fn bounded_http_refuses_wrong_target_signature_query_and_media() {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let db = OwnedDb::new();
    let cfg = config();
    let store = db.open();
    let app = router(Arc::new(Mutex::new(store)));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let grant = grant_for(&cfg, 2, 48, now + 3600);
    let valid = create_for(1, [70; 32], 4, &grant, &cfg);
    let mut bad_sig = valid.clone();
    let end = bad_sig.len() - 1;
    bad_sig[end] ^= 1;
    for (path, media, body) in [
        (
            "/v1/setup?invite=fixture",
            "application/cbor",
            valid.clone(),
        ),
        ("/v1/setup", "text/plain", valid.clone()),
        ("/v1/setup", "application/cbor", bad_sig),
        ("/v1/setup", "application/cbor", vec![0; 32769]),
        ("/v1/setup", "application/cbor", vec![]),
    ] {
        let request = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", media)
            .body(Body::from(body))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(request).await.unwrap().status(),
            StatusCode::BAD_REQUEST
        );
    }
    let req = claim(2, [70; 32], 4, 4);
    let path = format!("/v1/setup/{}/claims/3", hex::encode([70; 32]));
    let request = Request::builder()
        .method("POST")
        .uri(path)
        .header("content-type", "application/cbor")
        .body(Body::from(req))
        .unwrap();
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
}
#[tokio::test]
async fn actual_http_absent_issuer_denies_valid_scoped_grant_without_storage_effect() {
    use axum::{
        body::{to_bytes, Body},
        http::Request,
    };
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use tower::ServiceExt;
    let db = OwnedDb::new();
    let cfg = config();
    let store = AdmissionStore::open(
        &db.root,
        &cfg,
        EnrollmentVerifier::new(None),
        SigningKey::from_bytes(&[8; 32]),
    )
    .unwrap();
    let app = router(Arc::new(Mutex::new(store)));
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let grant = grant_for(&cfg, 2, 48, now + 3600);
    let signed = create_for(1, [70; 32], 4, &grant, &cfg);
    let req = Request::builder()
        .method("POST")
        .uri("/v1/setup")
        .header("content-type", "application/cbor")
        .header(
            "authorization",
            format!("Bearer {}", URL_SAFE_NO_PAD.encode(&grant)),
        )
        .body(Body::from(signed.clone()))
        .unwrap();
    let reply = app.oneshot(req).await.unwrap();
    assert_eq!(reply.status(), 200);
    let raw = to_bytes(reply.into_body(), 131072).await.unwrap();
    assert!(matches!(
        verify_admission_reply(&cfg, &signed, &raw)
            .unwrap()
            .outcome(),
        AdmissionOutcome::Rejected("enrollment")
    ));
    let conn = rusqlite::Connection::open(db.root.join("admission.sqlite")).unwrap();
    assert_eq!(
        conn.query_row("SELECT count(*) FROM ceremonies", [], |r| r
            .get::<_, u64>(0))
            .unwrap(),
        0
    );
}

#[tokio::test]
async fn signed_one_second_deadline_keeps_commit_reconcilable_after_timeout() {
    use axum::body::{to_bytes, Body};
    use axum::http::Request;
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use tower::ServiceExt;
    let db = OwnedDb::new();
    let signer = SigningKey::from_bytes(&[90; 32]);
    let raw = support::bundle(&signer, |f| {
        let loki_relay_protocol::canonical::Value::Array(limits) = &mut f[4] else {
            panic!()
        };
        limits[4] = loki_relay_protocol::canonical::Value::Integer(1.into());
    });
    let cfg =
        loki_relay_client::OperatorSet::verify(&raw, &signer.verifying_key().to_bytes()).unwrap();
    let store = AdmissionStore::open(
        &db.root,
        &cfg,
        EnrollmentVerifier::new(Some(
            SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes(),
        )),
        SigningKey::from_bytes(&[8; 32]),
    )
    .unwrap();
    assert_eq!(store.request_seconds(), 1);
    let app = router(Arc::new(Mutex::new(store)));
    let external = rusqlite::Connection::open(db.root.join("admission.sqlite")).unwrap();
    external.execute_batch("BEGIN IMMEDIATE").unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let grant = grant_for(&cfg, 2, 48, now + 3600);
    let signed = create_for(1, [70; 32], 4, &grant, &cfg);
    let request = Request::builder()
        .method("POST")
        .uri("/v1/setup")
        .header("content-type", "application/cbor")
        .header(
            "authorization",
            format!("Bearer {}", URL_SAFE_NO_PAD.encode(&grant)),
        )
        .body(Body::from(signed.clone()))
        .unwrap();
    let reply = app.clone().oneshot(request).await.unwrap();
    assert_eq!(reply.status(), 504);
    external.execute_batch("COMMIT").unwrap();
    let retry = Request::builder()
        .method("POST")
        .uri("/v1/setup")
        .header("content-type", "application/cbor")
        .body(Body::from(signed.clone()))
        .unwrap();
    let replay = app.oneshot(retry).await.unwrap();
    assert_eq!(replay.status(), 200);
    let raw = to_bytes(replay.into_body(), 131072).await.unwrap();
    assert!(matches!(
        verify_admission_reply(&cfg, &signed, &raw)
            .unwrap()
            .outcome(),
        AdmissionOutcome::Accepted(_)
    ));
}

#[tokio::test]
async fn wrong_admission_signer_receives_no_enrollment_or_invitation_credentials() {
    use axum::{
        body::Bytes,
        http::HeaderMap,
        routing::{get, post},
        Router,
    };
    use ed25519_dalek::Signer;
    use loki_relay_protocol::{
        admission,
        canonical::{self, Value},
    };
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicUsize, Ordering};
    for count in [3u16, 4] {
        let credentials = Arc::new(AtomicUsize::new(0));
        let observed = credentials.clone();
        let handler = move |headers: HeaderMap, bytes: Bytes| {
            let observed = observed.clone();
            async move {
                if headers.contains_key("authorization") {
                    observed.fetch_add(1, Ordering::SeqCst);
                }
                let Value::Array(package) =
                    canonical::decode(&bytes, admission::MAX_REQUEST).unwrap()
                else {
                    panic!()
                };
                let Value::Bytes(body) = &package[0] else {
                    panic!()
                };
                let request = admission::decode_request(body).unwrap();
                let body = canonical::encode(&Value::Array(vec![
                    Value::Integer(1.into()),
                    Value::Bytes(request.operation.to_vec()),
                    Value::Bytes(Sha256::digest(&bytes).to_vec()),
                    Value::Array(vec![
                        Value::Integer(0.into()),
                        Value::Text("identity".into()),
                    ]),
                ]))
                .unwrap();
                let key = SigningKey::from_bytes(&[7; 32]);
                let signature = key
                    .sign(&admission::signature_input(admission::RESPONSE_DOMAIN, &body).unwrap());
                let reply = canonical::encode(&Value::Array(vec![
                    Value::Bytes(body),
                    Value::Bytes(signature.to_bytes().to_vec()),
                ]))
                .unwrap();
                ([("content-type", "application/cbor")], reply)
            }
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let cfg = config_with_admission(&format!("http://{}", listener.local_addr().unwrap()));
        let app = Router::new()
            .route("/v1/setup/{ceremony}", get(handler.clone()))
            .route("/v1/setup", post(handler.clone()))
            .route("/v1/setup/{ceremony}/claims/{slot}", post(handler));
        let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let client = AdmissionHttp::development(&cfg).unwrap();
        let grant = grant_for(&cfg, 2, 48, u64::MAX / 2);
        let create = create_for(21, [77; 32], count, &grant, &cfg);
        assert!(client
            .execute_authenticated(&identity(1, 1), &create, Some(&grant))
            .await
            .is_err());
        let claim = claim(22, [77; 32], count, count as u8);
        assert!(client
            .execute_authenticated(
                &identity(count, count as u8),
                &claim,
                Some(&[count as u8; 32])
            )
            .await
            .is_err());
        assert!(client.execute(&create, Some(&grant)).await.is_err());
        assert_eq!(credentials.load(Ordering::SeqCst), 0);
        server.abort();
    }
}
