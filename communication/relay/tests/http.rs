mod support;
use loki_relay_protocol::{
    http::{encode_append_update, encode_creation},
    types::{AppendUpdate, Creation, Object},
};
use loki_relay_server::{
    capability::{provisioning_verifier, verifier},
    Capability, DbHandle, Limits, RelayError, RelayStore, Role,
};
use sha2::{Digest, Sha256};
use support::Scratch;

fn limits() -> Limits {
    Limits {
        total_bytes: 100_000,
        mailbox_bytes: 100_000,
        mailbox_count: 10,
    }
}
fn root() -> Scratch {
    let root = Scratch::new();
    drop(
        RelayStore::init(
            root.path(),
            [7; 32],
            "http://127.0.0.1:8000",
            &[8; 32],
            provisioning_verifier([7; 32], &[8; 32]),
            limits(),
        )
        .unwrap(),
    );
    root
}
fn creation() -> Vec<u8> {
    encode_creation(&Creation {
        read_verifier: verifier(Role::Read, [1; 32], &[2; 32]),
        append_verifier: verifier(Role::Append, [1; 32], &[3; 32]),
        admin_verifier: verifier(Role::Admin, [1; 32], &[4; 32]),
        quota: 100_000,
    })
    .unwrap()
}
fn update() -> Vec<u8> {
    encode_append_update(&AppendUpdate {
        revision: 2,
        verifier: verifier(Role::Append, [1; 32], &[5; 32]),
    })
    .unwrap()
}
fn object(tag: u8) -> Object {
    let mut wire = vec![tag; 1024];
    wire[..8].copy_from_slice(b"LOKIRLY1");
    wire[8] = 1;
    Object {
        hash: Sha256::digest(&wire).into(),
        wire,
    }
}

#[tokio::test(flavor = "current_thread")]
async fn writer_boundary() {
    let root = root();
    let (db, owner) = DbHandle::open(root.path().to_owned(), limits())
        .await
        .unwrap();
    assert!(RelayStore::open(root.path(), limits()).is_err());
    assert!(
        db.create([1; 32], creation(), Capability::new([8; 32]))
            .unwrap()
            .receive()
            .await
            .unwrap()
            .created
    );
    let obj = object(9);
    let saved = db
        .put([1; 32], obj.clone(), Capability::new([3; 32]))
        .unwrap()
        .receive()
        .await
        .unwrap();
    assert!(saved.created);
    assert_eq!(saved.sequence, 1);
    assert_eq!(
        db.get([1; 32], obj.hash, Capability::new([2; 32]))
            .unwrap()
            .receive()
            .await
            .unwrap(),
        obj.wire
    );
    let rotate = db
        .rotate([1; 32], update(), Capability::new([4; 32]))
        .unwrap();
    let stale = db
        .put([1; 32], object(10), Capability::new([3; 32]))
        .unwrap();
    let fresh = db
        .put([1; 32], object(10), Capability::new([5; 32]))
        .unwrap();
    assert_eq!(rotate.receive().await, Ok(2));
    assert_eq!(stale.receive().await, Err(RelayError::Capability));
    assert_eq!(fresh.receive().await.unwrap().sequence, 2);
    let retry = db
        .put([1; 32], obj.clone(), Capability::new([5; 32]))
        .unwrap()
        .receive()
        .await
        .unwrap();
    assert!(!retry.created);
    assert_eq!(retry.receipt, saved.receipt);
    assert_eq!(retry.sequence, 1);
    owner.shutdown().await.unwrap();
    assert!(matches!(
        db.get([1; 32], obj.hash, Capability::new([2; 32])),
        Err(RelayError::StorageUnavailable)
    ));
    let mut store = RelayStore::open(root.path(), limits()).unwrap();
    assert_eq!(
        store.put([1; 32], &obj, &Capability::new([5; 32])).unwrap(),
        retry
    );
    assert!(DbHandle::open(root.path().to_owned(), limits())
        .await
        .is_err());
}

#[allow(unused_macros)]
macro_rules! writer_private_tests {
    () => {

        use super::{reply, Command, Pause};
        use std::time::Duration;
        fn pause() -> (
            Pause,
            tokio::sync::oneshot::Receiver<std::thread::ThreadId>,
            std::sync::mpsc::Sender<()>,
        ) {
            let (entered, observed) = tokio::sync::oneshot::channel();
            let (release, resume) = std::sync::mpsc::channel();
            (
                Pause {
                    entered,
                    release: resume,
                },
                observed,
                release,
            )
        }
        async fn entered(observed: tokio::sync::oneshot::Receiver<std::thread::ThreadId>) {
            let thread = tokio::time::timeout(Duration::from_secs(2), observed)
                .await
                .unwrap()
                .unwrap();
            assert_ne!(thread, std::thread::current().id());
        }
        async fn barrier(db: &DbHandle) -> std::sync::mpsc::Sender<()> {
            let (pause, observed, release) = pause();
            db.admit(Command::Barrier(pause)).unwrap();
            entered(observed).await;
            release
        }
        async fn provision(db: &DbHandle) {
            db.create([1; 32], creation(), Capability::new([8; 32]))
                .unwrap()
                .receive()
                .await
                .unwrap();
        }

        #[tokio::test(flavor = "current_thread")]
        async fn writer_boundary_queue() {
            let root = root();
            let (db, owner) = DbHandle::open(root.path().to_owned(), limits())
                .await
                .unwrap();
            provision(&db).await;
            let release = barrier(&db).await;
            let mut pending = Vec::new();
            for _ in 0..64 {
                pending.push(db.get([1; 32], [0; 32], Capability::new([2; 32])).unwrap());
            }
            let error = match db.get([1; 32], [0; 32], Capability::new([2; 32])) {
                Err(error) => error,
                Ok(_) => panic!("65th queued operation was admitted"),
            };
            assert_eq!(error, RelayError::RateLimit);
            assert_eq!(error.code(), 8);
            assert!(RelayStore::open(root.path(), limits()).is_err());
            owner.stop();
            assert!(matches!(
                db.get([1; 32], [0; 32], Capability::new([2; 32])),
                Err(RelayError::StorageUnavailable)
            ));
            release.send(()).unwrap();
            for reply in pending {
                assert_eq!(reply.receive().await, Err(RelayError::ObjectNotFound));
            }
            tokio::time::timeout(Duration::from_secs(2), owner.shutdown())
                .await
                .unwrap()
                .unwrap();
            drop(RelayStore::open(root.path(), limits()).unwrap());
        }

        #[tokio::test(flavor = "current_thread")]
        async fn writer_boundary_mapping() {
            let root = root();
            let (db, owner) = DbHandle::open(root.path().to_owned(), limits())
                .await
                .unwrap();
            let release = barrier(&db).await;
            db.admit(Command::Fail).unwrap();
            let pending = db.get([1; 32], [0; 32], Capability::new([2; 32])).unwrap();
            release.send(()).unwrap();
            assert_eq!(pending.receive().await, Err(RelayError::StorageUnavailable));
            let error = match db.get([1; 32], [0; 32], Capability::new([2; 32])) {
                Err(error) => error,
                Ok(_) => panic!("failed writer accepted work"),
            };
            assert_eq!(error, RelayError::StorageUnavailable);
            assert_eq!(error.code(), 9);
            assert_eq!(owner.shutdown().await, Err(RelayError::StorageUnavailable));
            drop(RelayStore::open(root.path(), limits()).unwrap());
        }

        #[tokio::test(flavor = "current_thread")]
        async fn writer_boundary_commit() {
            let root = root();
            let (db, owner) = DbHandle::open(root.path().to_owned(), limits())
                .await
                .unwrap();
            provision(&db).await;
            let observer = rusqlite::Connection::open(root.path().join("relay.sqlite3")).unwrap();
            let obj = object(12);
            let (mut sender, mut response) = reply();
            let (pause, observed, release) = pause();
            sender.pause = Some(pause);
            db.admit(Command::Put(
                [1; 32],
                obj.clone(),
                Capability::new([3; 32]),
                sender,
            ))
            .unwrap();
            entered(observed).await;
            assert_eq!(
                response.0.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty)
            );
            let (saved, receipt, sequence): (Vec<u8>, Vec<u8>, u64) = observer
                .query_row(
                    "SELECT wire,receipt,sequence FROM objects WHERE hash=?1",
                    [obj.hash.as_slice()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .unwrap();
            assert_eq!(saved, obj.wire);
            assert_eq!(sequence, 1);
            assert!(RelayStore::open(root.path(), limits()).is_err());
            release.send(()).unwrap();
            assert_eq!(response.receive().await.unwrap().receipt, receipt);

            let release = barrier(&db).await;
            let lost = object(13);
            drop(
                db.put([1; 32], lost.clone(), Capability::new([3; 32]))
                    .unwrap(),
            );
            let retry = db
                .put([1; 32], lost.clone(), Capability::new([3; 32]))
                .unwrap();
            release.send(()).unwrap();
            let retry = retry.receive().await.unwrap();
            assert!(!retry.created);
            assert_eq!(retry.sequence, 2);
            let count: u64 = observer
                .query_row("SELECT count(*) FROM objects", [], |row| row.get(0))
                .unwrap();
            assert_eq!(count, 2);
            let persisted: Vec<u8> = observer
                .query_row(
                    "SELECT receipt FROM objects WHERE hash=?1",
                    [lost.hash.as_slice()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(retry.receipt, persisted);
            observer.execute_batch("CREATE TRIGGER reject_put BEFORE INSERT ON objects BEGIN SELECT RAISE(ABORT,'test commit failure'); END;").unwrap();
            assert_eq!(
                db.put([1; 32], object(14), Capability::new([3; 32]))
                    .unwrap()
                    .receive()
                    .await,
                Err(RelayError::StorageUnavailable)
            );
            observer.execute_batch("DROP TRIGGER reject_put;").unwrap();
            assert_eq!(
                db.put([1; 32], object(14), Capability::new([3; 32]))
                    .unwrap()
                    .receive()
                    .await
                    .unwrap()
                    .sequence,
                3
            );
            owner.shutdown().await.unwrap();
            let mut store = RelayStore::open(root.path(), limits()).unwrap();
            assert_eq!(
                store
                    .put([1; 32], &lost, &Capability::new([3; 32]))
                    .unwrap(),
                retry
            );
        }
        #[tokio::test(flavor = "current_thread")]
        async fn writer_boundary_shutdown() {
            let root = root();
            let (db, owner) = DbHandle::open(root.path().to_owned(), limits())
                .await
                .unwrap();
            provision(&db).await;
            let release = barrier(&db).await;
            let obj = object(15);
            let accepted = db
                .put([1; 32], obj.clone(), Capability::new([3; 32]))
                .unwrap();
            assert_eq!(
                tokio::time::timeout(Duration::from_secs(6), owner.shutdown())
                    .await
                    .unwrap(),
                Err(RelayError::StorageUnavailable)
            );
            assert!(RelayStore::open(root.path(), limits()).is_err());
            assert!(matches!(
                db.get([1; 32], obj.hash, Capability::new([2; 32])),
                Err(RelayError::StorageUnavailable)
            ));
            release.send(()).unwrap();
            let saved = accepted.receive().await.unwrap();
            assert_eq!(saved.sequence, 1);
            let mut store = tokio::time::timeout(Duration::from_secs(2), async {
                loop {
                    if let Ok(store) = RelayStore::open(root.path(), limits()) {
                        break store;
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            })
            .await
            .unwrap();
            assert_eq!(
                store
                    .put([1; 32], &obj, &Capability::new([3; 32]))
                    .unwrap()
                    .receipt,
                saved.receipt
            );
        }
    };
}

use axum::{
    body::{to_bytes, Body},
    http::{HeaderValue, Request},
    Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use tower::ServiceExt;

struct HttpFixture {
    app: Router,
    db: DbHandle,
    owner: loki_relay_server::DbWriter,
    _root: Scratch,
}
impl HttpFixture {
    async fn new(quota: u64) -> Self {
        let root = root();
        let (db, owner) = DbHandle::open(root.path().to_owned(), limits())
            .await
            .unwrap();
        let mut request = loki_relay_protocol::http::decode_creation(&creation()).unwrap();
        request.quota = quota;
        db.create(
            [1; 32],
            encode_creation(&request).unwrap(),
            Capability::new([8; 32]),
        )
        .unwrap()
        .receive()
        .await
        .unwrap();
        Self {
            app: loki_relay_server::http::router(db.clone()),
            db,
            owner,
            _root: root,
        }
    }
    async fn send(&self, request: Request<Body>) -> (u16, String, Vec<u8>) {
        let response = self.app.clone().oneshot(request).await.unwrap();
        let status = response.status().as_u16();
        let media = response.headers()["content-type"]
            .to_str()
            .unwrap()
            .to_owned();
        let body = to_bytes(response.into_body(), 65536)
            .await
            .unwrap()
            .to_vec();
        (status, media, body)
    }
    async fn absent(&self, hash: [u8; 32]) {
        assert_eq!(
            self.db
                .get([1; 32], hash, Capability::new([2; 32]))
                .unwrap()
                .receive()
                .await,
            Err(RelayError::ObjectNotFound)
        );
    }
}

#[tokio::test]
async fn identity_route_signs_fresh_challenge_without_mailbox_credentials() {
    use ed25519_dalek::{Signature, VerifyingKey};
    use loki_relay_protocol::{
        canonical::{self, Value},
        challenge,
    };
    let f = HttpFixture::new(1024).await;
    let request = |challenge: [u8; 32]| {
        Request::builder()
            .uri("/v1/identity")
            .header("x-loki-challenge", hex::encode(challenge))
            .body(Body::empty())
            .unwrap()
    };
    let (status, media, raw) = f.send(request([10; 32])).await;
    assert_eq!((status, media.as_str()), (200, "application/cbor"));
    let Value::Array(parts) = canonical::decode(&raw, challenge::MAX_RESPONSE).unwrap() else {
        panic!("wrapper")
    };
    let [Value::Bytes(body), Value::Bytes(signature)] = parts.as_slice() else {
        panic!("fields")
    };
    let signed = challenge::decode_body(body).unwrap();
    let manifest = std::fs::read_to_string(f._root.path().join("manifest")).unwrap();
    let pinned: [u8; 32] = hex::decode(manifest.lines().nth(2).unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    assert_eq!(signed.pin.key, pinned);
    assert_eq!(signed.pin.run, [7; 32]);
    assert_eq!(signed.endpoint, "http://127.0.0.1:8000");
    assert_eq!(signed.challenge, [10; 32]);
    VerifyingKey::from_bytes(&signed.pin.key)
        .unwrap()
        .verify_strict(
            &challenge::signature_input(body).unwrap(),
            &Signature::from_slice(signature).unwrap(),
        )
        .unwrap();
    assert_ne!(f.send(request([11; 32])).await.2, raw);
    let missing = Request::builder()
        .uri("/v1/identity")
        .body(Body::empty())
        .unwrap();
    assert_error(f.send(missing).await, 400, 1);
    f.owner.shutdown().await.unwrap();
}
fn object_uri(obj: &Object) -> String {
    format!(
        "/v1/mailboxes/{}/objects/{}",
        hex::encode([1; 32]),
        hex::encode(obj.hash)
    )
}
fn http_request(method: &str, obj: &Object, secret: u8) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(object_uri(obj))
        .header(
            "authorization",
            format!("Bearer {}", URL_SAFE_NO_PAD.encode([secret; 32])),
        )
        .header("content-type", "application/octet-stream")
        .body(if method == "PUT" {
            Body::from(obj.wire.clone())
        } else {
            Body::empty()
        })
        .unwrap()
}
fn assert_error(actual: (u16, String, Vec<u8>), status: u16, code: u8) {
    assert_eq!(
        actual,
        (status, "application/cbor".into(), vec![0x82, 1, code])
    );
}

#[tokio::test]
async fn object_routes() {
    let f = HttpFixture::new(1024).await;
    let obj = object(9);
    let first = f.send(http_request("PUT", &obj, 3)).await;
    assert_eq!((first.0, first.1.as_str()), (201, "application/cbor"));
    let saved =
        f.db.put([1; 32], obj.clone(), Capability::new([3; 32]))
            .unwrap()
            .receive()
            .await
            .unwrap();
    assert!(!saved.created);
    assert_eq!(first.2, saved.receipt);
    assert_eq!(saved.sequence, 1);
    let retry = f.send(http_request("PUT", &obj, 3)).await;
    assert_eq!(retry, (200, "application/cbor".into(), first.2));
    let mut get = http_request("GET", &obj, 2);
    get.headers_mut().remove("content-type");
    assert_eq!(
        f.send(get).await,
        (200, "application/octet-stream".into(), obj.wire)
    );
    f.owner.shutdown().await.unwrap();
}

macro_rules! negative_request {
    ($name:ident, $status:literal, $code:literal, $obj:ident, $request:ident, $change:block) => {
        #[tokio::test]
        async fn $name() {
            let f = HttpFixture::new(100_000).await;
            let $obj = object(10);
            let mut $request = http_request("PUT", &$obj, 3);
            $change
            assert_error(f.send($request).await, $status, $code);
            f.absent($obj.hash).await;
            f.owner.shutdown().await.unwrap();
        }
    };
}
negative_request!(object_routes_path_encoded_mailbox, 400, 1, obj, req, {
    *req.uri_mut() = object_uri(&obj)
        .replacen("01", "%30%31", 1)
        .parse()
        .unwrap();
});
negative_request!(object_routes_path_encoded_hash, 400, 1, obj, req, {
    *req.uri_mut() = object_uri(&obj)
        .replace(
            &hex::encode(obj.hash),
            &format!(
                "%{:02x}{}",
                hex::encode(obj.hash).as_bytes()[0],
                &hex::encode(obj.hash)[1..]
            ),
        )
        .parse()
        .unwrap();
});
negative_request!(object_routes_path_upper_hash, 400, 1, obj, req, {
    *req.uri_mut() = object_uri(&obj)
        .replace(
            &hex::encode(obj.hash),
            &hex::encode(obj.hash).to_uppercase(),
        )
        .parse()
        .unwrap();
});
negative_request!(object_routes_path_upper_mailbox, 400, 1, obj, req, {
    *req.uri_mut() = object_uri(&obj)
        .replace(&hex::encode([1; 32]), &"AB".repeat(32))
        .parse()
        .unwrap();
});
negative_request!(object_routes_path_short, 400, 1, obj, req, {
    *req.uri_mut() = object_uri(&obj)[..object_uri(&obj).len() - 1]
        .parse()
        .unwrap();
});
negative_request!(object_routes_path_long, 400, 1, obj, req, {
    *req.uri_mut() = format!("{}0", object_uri(&obj)).parse().unwrap();
});
negative_request!(object_routes_path_query, 400, 1, obj, req, {
    *req.uri_mut() = format!("{}?token=secret", object_uri(&obj))
        .parse()
        .unwrap();
});
negative_request!(object_routes_auth_missing, 401, 2, obj, req, {
    req.headers_mut().remove("authorization");
});
negative_request!(object_routes_auth_scheme, 401, 2, obj, req, {
    req.headers_mut().insert(
        "authorization",
        format!("bearer {}", URL_SAFE_NO_PAD.encode([3; 32]))
            .parse()
            .unwrap(),
    );
});
negative_request!(object_routes_auth_padded, 401, 2, obj, req, {
    req.headers_mut().insert(
        "authorization",
        format!("Bearer {}=", URL_SAFE_NO_PAD.encode([3; 32]))
            .parse()
            .unwrap(),
    );
});
negative_request!(object_routes_auth_noncanonical, 401, 2, obj, req, {
    let mut token = URL_SAFE_NO_PAD.encode([3; 32]);
    token.pop();
    token.push('N');
    req.headers_mut()
        .insert("authorization", format!("Bearer {token}").parse().unwrap());
});
negative_request!(object_routes_auth_short, 401, 2, obj, req, {
    req.headers_mut().insert(
        "authorization",
        format!("Bearer {}", URL_SAFE_NO_PAD.encode([3; 31]))
            .parse()
            .unwrap(),
    );
});
negative_request!(object_routes_auth_long, 401, 2, obj, req, {
    req.headers_mut().insert(
        "authorization",
        format!("Bearer {}", URL_SAFE_NO_PAD.encode([3; 33]))
            .parse()
            .unwrap(),
    );
});
negative_request!(object_routes_auth_duplicate, 400, 1, obj, req, {
    let duplicate = req.headers()["authorization"].clone();
    req.headers_mut().append("authorization", duplicate);
});
negative_request!(object_routes_auth_invalid_header, 400, 1, obj, req, {
    req.headers_mut()
        .insert("authorization", HeaderValue::from_bytes(&[0xff]).unwrap());
});
negative_request!(object_routes_media_missing, 415, 7, obj, req, {
    req.headers_mut().remove("content-type");
});
negative_request!(object_routes_media_wrong, 415, 7, obj, req, {
    req.headers_mut()
        .insert("content-type", "application/json".parse().unwrap());
});
negative_request!(object_routes_media_parameter, 415, 7, obj, req, {
    req.headers_mut().insert(
        "content-type",
        "application/octet-stream; charset=utf-8".parse().unwrap(),
    );
});
negative_request!(object_routes_media_duplicate, 400, 1, obj, req, {
    req.headers_mut()
        .append("content-type", "application/octet-stream".parse().unwrap());
});
negative_request!(object_routes_media_invalid_header, 400, 1, obj, req, {
    req.headers_mut()
        .insert("content-type", HeaderValue::from_bytes(&[0xff]).unwrap());
});
negative_request!(object_routes_encoding, 415, 7, obj, req, {
    req.headers_mut()
        .insert("content-encoding", "gzip".parse().unwrap());
});
negative_request!(object_routes_length_invalid, 400, 1, obj, req, {
    req.headers_mut()
        .insert("content-length", "+1024".parse().unwrap());
});
negative_request!(object_routes_length_overflow, 400, 1, obj, req, {
    req.headers_mut()
        .insert("content-length", "184467440737095516160".parse().unwrap());
});
negative_request!(object_routes_length_duplicate, 400, 1, obj, req, {
    req.headers_mut()
        .append("content-length", "1024".parse().unwrap());
    req.headers_mut()
        .append("content-length", "1024".parse().unwrap());
});
negative_request!(object_routes_length_mismatch, 400, 1, obj, req, {
    req.headers_mut()
        .insert("content-length", "1".parse().unwrap());
});
negative_request!(object_routes_length_declared_large, 413, 6, obj, req, {
    req.headers_mut()
        .insert("content-length", "65537".parse().unwrap());
});
negative_request!(object_routes_transfer_wrong, 400, 1, obj, req, {
    req.headers_mut()
        .insert("transfer-encoding", "gzip".parse().unwrap());
});
negative_request!(object_routes_transfer_ambiguous, 400, 1, obj, req, {
    req.headers_mut()
        .insert("transfer-encoding", "chunked".parse().unwrap());
    req.headers_mut()
        .insert("content-length", "1024".parse().unwrap());
});
negative_request!(object_routes_bound_absent_length, 413, 6, obj, req, {
    *req.uri_mut() = object_uri(&obj)
        .replace(&hex::encode([1; 32]), &hex::encode([0; 32]))
        .parse()
        .unwrap();
    *req.body_mut() = Body::from(vec![0; 65537]);
});
negative_request!(object_routes_bound_deceptive_length, 413, 6, obj, req, {
    *req.uri_mut() = object_uri(&obj)
        .replace(&hex::encode([1; 32]), &hex::encode([0; 32]))
        .parse()
        .unwrap();
    req.headers_mut()
        .insert("content-length", "1".parse().unwrap());
    *req.body_mut() = Body::from(vec![0; 65537]);
});
negative_request!(object_routes_wire_hash, 400, 1, obj, req, {
    let mut wrong = obj.wire.clone();
    wrong[50] ^= 1;
    *req.body_mut() = Body::from(wrong);
    *req.uri_mut() = req
        .uri()
        .to_string()
        .replace(&hex::encode([1; 32]), &hex::encode([0; 32]))
        .parse()
        .unwrap();
});
negative_request!(object_routes_wire_magic, 400, 1, obj, req, {
    let mut wrong = obj.wire.clone();
    wrong[0] ^= 1;
    let hash: [u8; 32] = Sha256::digest(&wrong).into();
    *req.uri_mut() = object_uri(&obj)
        .replace(&hex::encode(obj.hash), &hex::encode(hash))
        .parse()
        .unwrap();
    *req.body_mut() = Body::from(wrong);
    *req.uri_mut() = req
        .uri()
        .to_string()
        .replace(&hex::encode([1; 32]), &hex::encode([0; 32]))
        .parse()
        .unwrap();
});
negative_request!(object_routes_wire_version, 400, 1, obj, req, {
    let mut wrong = obj.wire.clone();
    wrong[8] = 2;
    let hash: [u8; 32] = Sha256::digest(&wrong).into();
    *req.uri_mut() = object_uri(&obj)
        .replace(&hex::encode(obj.hash), &hex::encode(hash))
        .parse()
        .unwrap();
    *req.body_mut() = Body::from(wrong);
    *req.uri_mut() = req
        .uri()
        .to_string()
        .replace(&hex::encode([1; 32]), &hex::encode([0; 32]))
        .parse()
        .unwrap();
});
negative_request!(object_routes_wire_padding, 400, 1, obj, req, {
    let wrong = vec![0; 1023];
    let hash: [u8; 32] = Sha256::digest(&wrong).into();
    *req.uri_mut() = object_uri(&obj)
        .replace(&hex::encode(obj.hash), &hex::encode(hash))
        .parse()
        .unwrap();
    *req.body_mut() = Body::from(wrong);
    *req.uri_mut() = req
        .uri()
        .to_string()
        .replace(&hex::encode([1; 32]), &hex::encode([0; 32]))
        .parse()
        .unwrap();
});
negative_request!(object_routes_put_read_role, 401, 2, obj, req, {
    *req.method_mut() = axum::http::Method::PUT;
    req.headers_mut().insert(
        "authorization",
        format!("Bearer {}", URL_SAFE_NO_PAD.encode([2; 32]))
            .parse()
            .unwrap(),
    );
});
negative_request!(object_routes_put_admin_role, 401, 2, obj, req, {
    *req.method_mut() = axum::http::Method::PUT;
    req.headers_mut().insert(
        "authorization",
        format!("Bearer {}", URL_SAFE_NO_PAD.encode([4; 32]))
            .parse()
            .unwrap(),
    );
});
negative_request!(object_routes_bad_capability, 401, 2, obj, req, {
    *req.method_mut() = axum::http::Method::PUT;
    req.headers_mut().insert(
        "authorization",
        format!("Bearer {}", URL_SAFE_NO_PAD.encode([6; 32]))
            .parse()
            .unwrap(),
    );
});
negative_request!(object_routes_unknown_mailbox, 401, 2, obj, req, {
    *req.uri_mut() = object_uri(&obj)
        .replace(&hex::encode([1; 32]), &hex::encode([0; 32]))
        .parse()
        .unwrap();
});
negative_request!(object_routes_get_append_role, 401, 2, obj, req, {
    *req.method_mut() = axum::http::Method::GET;
    req.headers_mut().insert(
        "authorization",
        format!("Bearer {}", URL_SAFE_NO_PAD.encode([3; 32]))
            .parse()
            .unwrap(),
    );
    *req.body_mut() = Body::empty();
});
negative_request!(object_routes_get_admin_role, 401, 2, obj, req, {
    *req.method_mut() = axum::http::Method::GET;
    req.headers_mut().insert(
        "authorization",
        format!("Bearer {}", URL_SAFE_NO_PAD.encode([4; 32]))
            .parse()
            .unwrap(),
    );
    *req.body_mut() = Body::empty();
});
negative_request!(object_routes_get_missing, 404, 3, obj, req, {
    *req.method_mut() = axum::http::Method::GET;
    req.headers_mut().insert(
        "authorization",
        format!("Bearer {}", URL_SAFE_NO_PAD.encode([2; 32]))
            .parse()
            .unwrap(),
    );
    *req.body_mut() = Body::empty();
});
negative_request!(object_routes_get_body, 400, 1, obj, req, {
    *req.method_mut() = axum::http::Method::GET;
    req.headers_mut().insert(
        "authorization",
        format!("Bearer {}", URL_SAFE_NO_PAD.encode([2; 32]))
            .parse()
            .unwrap(),
    );
    *req.body_mut() = Body::empty();
    *req.body_mut() = Body::from(vec![0]);
});
negative_request!(object_routes_method, 400, 1, obj, req, {
    *req.method_mut() = axum::http::Method::POST;
});
negative_request!(object_routes_extra_path, 400, 1, obj, req, {
    *req.uri_mut() = format!("{}/more", object_uri(&obj)).parse().unwrap();
});

#[tokio::test]
async fn object_routes_rotation() {
    let f = HttpFixture::new(100_000).await;
    f.db.rotate([1; 32], update(), Capability::new([4; 32]))
        .unwrap()
        .receive()
        .await
        .unwrap();
    assert_error(f.send(http_request("PUT", &object(11), 3)).await, 401, 2);
    assert_eq!(f.send(http_request("PUT", &object(11), 5)).await.0, 201);
    f.owner.shutdown().await.unwrap();
}
#[tokio::test]
async fn object_routes_quota() {
    let f = HttpFixture::new(1024).await;
    assert_eq!(f.send(http_request("PUT", &object(9), 3)).await.0, 201);
    assert_error(f.send(http_request("PUT", &object(10), 3)).await, 507, 10);
    f.absent(object(10).hash).await;
    f.owner.shutdown().await.unwrap();
}
#[tokio::test]
async fn object_routes_storage() {
    let f = HttpFixture::new(100_000).await;
    let observer = rusqlite::Connection::open(f._root.path().join("relay.sqlite3")).unwrap();
    f.db.put([1; 32], object(9), Capability::new([3; 32]))
        .unwrap()
        .receive()
        .await
        .unwrap();
    observer.execute_batch("CREATE TRIGGER reject_http_put BEFORE INSERT ON objects BEGIN SELECT RAISE(ABORT,'test failure'); END;").unwrap();
    assert_error(f.send(http_request("PUT", &object(10), 3)).await, 503, 9);
    f.absent(object(10).hash).await;
    f.owner.shutdown().await.unwrap();
}
#[tokio::test]
async fn object_routes_stopped() {
    let f = HttpFixture::new(100_000).await;
    let app = f.app.clone();
    f.owner.shutdown().await.unwrap();
    let response = app
        .oneshot(http_request("GET", &object(10), 2))
        .await
        .unwrap();
    assert_eq!(response.status(), 503);
    assert_eq!(response.headers()["content-type"], "application/cbor");
    assert_eq!(
        to_bytes(response.into_body(), 3).await.unwrap().as_ref(),
        [0x82, 1, 9]
    );
}
#[tokio::test]
async fn object_routes_maximum() {
    let f = HttpFixture::new(100_000).await;
    let mut obj = object(10);
    obj.wire.resize(65536, 10);
    obj.hash = Sha256::digest(&obj.wire).into();
    let mut req = http_request("PUT", &obj, 3);
    req.headers_mut()
        .insert("transfer-encoding", "chunked".parse().unwrap());
    assert_eq!(f.send(req).await.0, 201);
    assert_eq!(
        f.send(http_request("GET", &obj, 2)).await,
        (200, "application/octet-stream".into(), obj.wire)
    );
    f.owner.shutdown().await.unwrap();
}
#[tokio::test]
async fn object_routes_head_refused() {
    let f = HttpFixture::new(100_000).await;
    let mut req = http_request("GET", &object(10), 2);
    *req.method_mut() = axum::http::Method::HEAD;
    assert_eq!(f.send(req).await.0, 400);
    f.owner.shutdown().await.unwrap();
}

#[tokio::test]
async fn object_routes_stream_bound() {
    use std::io::{Read, Write};
    let f = HttpFixture::new(100_000).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let app = f.app.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let uri = object_uri(&object(10)).replace(&hex::encode([1; 32]), &hex::encode([0; 32]));
    let response = tokio::task::spawn_blocking(move || {
        let mut socket = std::net::TcpStream::connect(address).unwrap();
        socket.set_read_timeout(Some(std::time::Duration::from_secs(3))).unwrap();
        write!(socket, "PUT {uri} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n", URL_SAFE_NO_PAD.encode([3;32])).unwrap();
        for _ in 0..64 {
            socket.write_all(b"400\r\n").unwrap();
            socket.write_all(&[0;1024]).unwrap();
            socket.write_all(b"\r\n").unwrap();
        }
        socket.write_all(b"1\r\nx\r\n0\r\n\r\n").unwrap();
        let mut response = Vec::new();
        socket.read_to_end(&mut response).unwrap();
        response
    }).await.unwrap();
    let split = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let headers = std::str::from_utf8(&response[..split]).unwrap();
    assert!(headers.starts_with("HTTP/1.1 413"));
    assert!(headers.contains("content-type: application/cbor\r\n"));
    assert_eq!(&response[split..], [0x82, 1, 6]);
    stop.send(()).unwrap();
    server.await.unwrap();
    f.owner.shutdown().await.unwrap();
}

negative_request!(object_routes_encoding_duplicate, 400, 1, obj, req, {
    req.headers_mut()
        .append("content-encoding", "gzip".parse().unwrap());
    req.headers_mut()
        .append("content-encoding", "gzip".parse().unwrap());
});
negative_request!(object_routes_transfer_duplicate, 400, 1, obj, req, {
    req.headers_mut()
        .append("transfer-encoding", "chunked".parse().unwrap());
    req.headers_mut()
        .append("transfer-encoding", "chunked".parse().unwrap());
});
negative_request!(object_routes_length_invalid_header, 400, 1, obj, req, {
    req.headers_mut()
        .insert("content-length", HeaderValue::from_bytes(&[0xff]).unwrap());
});
negative_request!(object_routes_encoding_invalid_header, 400, 1, obj, req, {
    req.headers_mut().insert(
        "content-encoding",
        HeaderValue::from_bytes(&[0xff]).unwrap(),
    );
});
negative_request!(object_routes_transfer_invalid_header, 400, 1, obj, req, {
    req.headers_mut().insert(
        "transfer-encoding",
        HeaderValue::from_bytes(&[0xff]).unwrap(),
    );
});

#[tokio::test]
async fn object_routes_stream_error() {
    use std::io::{Read, Write};
    let f = HttpFixture::new(100_000).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let app = f.app.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let uri = object_uri(&object(10)).replace(&hex::encode([1; 32]), &hex::encode([0; 32]));
    let response = tokio::task::spawn_blocking(move || {
        let mut socket = std::net::TcpStream::connect(address).unwrap();
        socket.set_read_timeout(Some(std::time::Duration::from_secs(3))).unwrap();
        write!(socket, "PUT {uri} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Type: application/octet-stream\r\nContent-Length: 1024\r\nConnection: close\r\n\r\n", URL_SAFE_NO_PAD.encode([3;32])).unwrap();
        socket.write_all(&[0;20]).unwrap();
        socket.shutdown(std::net::Shutdown::Write).unwrap();
        let mut response = Vec::new();
        socket.read_to_end(&mut response).unwrap();
        response
    }).await.unwrap();
    let split = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let headers = std::str::from_utf8(&response[..split]).unwrap();
    assert!(headers.starts_with("HTTP/1.1 400"));
    assert!(headers.contains("content-type: application/cbor\r\n"));
    assert_eq!(&response[split..], [0x82, 1, 1]);
    stop.send(()).unwrap();
    server.await.unwrap();
    f.owner.shutdown().await.unwrap();
}

fn control_uri(rotate: bool) -> String {
    format!(
        "/v1/mailboxes/{}{}",
        hex::encode([1; 32]),
        if rotate { "/append-capability" } else { "" }
    )
}
fn control_request(rotate: bool, secret: u8, body: Vec<u8>) -> Request<Body> {
    Request::builder()
        .method("PUT")
        .uri(control_uri(rotate))
        .header(
            "authorization",
            format!("Bearer {}", URL_SAFE_NO_PAD.encode([secret; 32])),
        )
        .header("content-type", "application/cbor")
        .body(Body::from(body))
        .unwrap()
}
async fn control_fixture() -> HttpFixture {
    let root = root();
    let (db, owner) = DbHandle::open(root.path().to_owned(), limits())
        .await
        .unwrap();
    HttpFixture {
        app: loki_relay_server::http::router(db.clone()),
        db,
        owner,
        _root: root,
    }
}
fn creation_result_bytes(quota: u64, revision: u8) -> Vec<u8> {
    let mut bytes = vec![0x85, 1, 0x58, 0x20];
    bytes.extend_from_slice(&[1; 32]);
    bytes.extend_from_slice(&[0x58, 0x20]);
    bytes.extend_from_slice(&[7; 32]);
    assert_eq!(quota, 100_000);
    bytes.extend_from_slice(&[0x1a, 0, 1, 0x86, 0xa0, revision]);
    bytes
}
fn append_result_bytes(revision: u8) -> Vec<u8> {
    let mut bytes = vec![0x83, 1, 0x58, 0x20];
    bytes.extend_from_slice(&[1; 32]);
    bytes.push(revision);
    bytes
}
#[tokio::test]
async fn control_routes() {
    let f = control_fixture().await;
    assert_eq!(
        f.send(control_request(false, 8, creation())).await,
        (
            201,
            "application/cbor".into(),
            creation_result_bytes(100_000, 1)
        )
    );
    assert_eq!(
        f.send(control_request(false, 8, creation())).await,
        (
            200,
            "application/cbor".into(),
            creation_result_bytes(100_000, 1)
        )
    );
    let obj = object(9);
    let saved = f.send(http_request("PUT", &obj, 3)).await;
    assert_eq!(saved.0, 201);
    assert_eq!(
        f.send(control_request(true, 4, update())).await,
        (200, "application/cbor".into(), append_result_bytes(2))
    );
    assert_eq!(
        f.send(control_request(true, 4, update())).await,
        (200, "application/cbor".into(), append_result_bytes(2))
    );
    assert_eq!(
        f.send(control_request(false, 8, creation())).await,
        (
            200,
            "application/cbor".into(),
            creation_result_bytes(100_000, 2)
        )
    );
    assert_error(f.send(http_request("PUT", &obj, 3)).await, 401, 2);
    assert_eq!(
        f.send(http_request("PUT", &obj, 5)).await,
        (200, "application/cbor".into(), saved.2.clone())
    );
    assert_eq!(
        f.send(http_request("GET", &obj, 2)).await,
        (200, "application/octet-stream".into(), obj.wire.clone())
    );
    let retry =
        f.db.put([1; 32], obj.clone(), Capability::new([5; 32]))
            .unwrap()
            .receive()
            .await
            .unwrap();
    assert_eq!(retry.sequence, 1);
    assert_eq!(retry.receipt, saved.2);
    let second =
        f.db.put([1; 32], object(10), Capability::new([5; 32]))
            .unwrap()
            .receive()
            .await
            .unwrap();
    assert_eq!(second.sequence, 2);
    f.owner.shutdown().await.unwrap();
}
#[tokio::test]
async fn control_routes_conflicts() {
    let f = HttpFixture::new(100_000).await;
    let mut changed = loki_relay_protocol::http::decode_creation(&creation()).unwrap();
    changed.quota = 99_999;
    assert_error(
        f.send(control_request(
            false,
            8,
            encode_creation(&changed).unwrap(),
        ))
        .await,
        409,
        4,
    );
    for revision in [1, 3, i64::MAX as u64] {
        let mut wrong = loki_relay_protocol::http::decode_append_update(&update()).unwrap();
        wrong.revision = revision;
        assert_error(
            f.send(control_request(
                true,
                4,
                encode_append_update(&wrong).unwrap(),
            ))
            .await,
            409,
            4,
        );
    }
    assert_eq!(f.send(control_request(true, 4, update())).await.0, 200);
    let mut wrong = loki_relay_protocol::http::decode_append_update(&update()).unwrap();
    wrong.verifier = [99; 32];
    assert_error(
        f.send(control_request(
            true,
            4,
            encode_append_update(&wrong).unwrap(),
        ))
        .await,
        409,
        4,
    );
    wrong.revision = 3;
    wrong.verifier = verifier(Role::Append, [1; 32], &[6; 32]);
    assert_eq!(
        f.send(control_request(
            true,
            4,
            encode_append_update(&wrong).unwrap()
        ))
        .await,
        (200, "application/cbor".into(), append_result_bytes(3))
    );
    assert_error(f.send(control_request(true, 4, update())).await, 409, 4);
    assert_error(f.send(http_request("PUT", &object(9), 5)).await, 401, 2);
    assert_eq!(f.send(http_request("PUT", &object(9), 6)).await.0, 201);
    f.owner.shutdown().await.unwrap();
}
#[tokio::test]
async fn control_routes_roles() {
    let f = HttpFixture::new(100_000).await;
    for secret in [2, 3, 4, 5] {
        assert_error(
            f.send(control_request(false, secret, creation())).await,
            401,
            2,
        );
    }
    for secret in [2, 3, 5, 8] {
        assert_error(
            f.send(control_request(true, secret, update())).await,
            401,
            2,
        );
    }
    let mut unknown = control_request(true, 4, update());
    *unknown.uri_mut() = control_uri(true)
        .replace(&hex::encode([1; 32]), &hex::encode([0; 32]))
        .parse()
        .unwrap();
    assert_error(f.send(unknown).await, 401, 2);
    let obj = object(9);
    assert_eq!(f.send(http_request("PUT", &obj, 3)).await.0, 201);
    assert_error(f.send(http_request("GET", &obj, 4)).await, 401, 2);
    for uri in [control_uri(false), control_uri(true), object_uri(&obj)] {
        let mut req = control_request(false, 4, vec![]);
        *req.method_mut() = axum::http::Method::DELETE;
        *req.uri_mut() = uri.parse().unwrap();
        assert_error(f.send(req).await, 400, 1);
    }
    assert_eq!(f.send(http_request("GET", &obj, 2)).await.2, obj.wire);
    assert_eq!(f.send(http_request("PUT", &object(10), 3)).await.0, 201);
    f.owner.shutdown().await.unwrap();
}
macro_rules! control_negative {
    ($name:ident, $rotate:literal, $status:literal, $code:literal, $req:ident, $change:block) => {
        #[tokio::test]
        async fn $name() {
            let f = HttpFixture::new(100_000).await;
            let mut $req = control_request($rotate, if $rotate {4} else {8}, if $rotate {update()} else {creation()});
            $change
            assert_error(f.send($req).await, $status, $code);
            assert_eq!(f.send(http_request("PUT", &object(9), 3)).await.0, 201);
            f.owner.shutdown().await.unwrap();
        }
    };
}

control_negative!(control_routes_create_path_query, false, 400, 1, req, {
    *req.uri_mut() = format!("{}?token=secret", control_uri(false))
        .parse()
        .unwrap();
});

control_negative!(control_routes_create_path_encoded, false, 400, 1, req, {
    *req.uri_mut() = control_uri(false)
        .replacen("01", "%30%31", 1)
        .parse()
        .unwrap();
});

control_negative!(control_routes_create_path_upper, false, 400, 1, req, {
    *req.uri_mut() = control_uri(false)
        .replace(&hex::encode([1; 32]), &"AB".repeat(32))
        .parse()
        .unwrap();
});

control_negative!(control_routes_create_path_short, false, 400, 1, req, {
    *req.uri_mut() = control_uri(false)
        .replace(&hex::encode([1; 32]), &"01".repeat(31))
        .parse()
        .unwrap();
});

control_negative!(control_routes_create_path_long, false, 400, 1, req, {
    *req.uri_mut() = control_uri(false)
        .replace(&hex::encode([1; 32]), &"01".repeat(33))
        .parse()
        .unwrap();
});

control_negative!(control_routes_create_path_extra, false, 400, 1, req, {
    *req.uri_mut() = format!("{}/more", control_uri(false)).parse().unwrap();
});

control_negative!(control_routes_create_method, false, 400, 1, req, {
    *req.method_mut() = axum::http::Method::GET;
});

control_negative!(control_routes_create_auth_missing, false, 401, 2, req, {
    req.headers_mut().remove("authorization");
});

control_negative!(control_routes_create_auth_scheme, false, 401, 2, req, {
    req.headers_mut().insert(
        "authorization",
        format!("bearer {}", URL_SAFE_NO_PAD.encode([4; 32]))
            .parse()
            .unwrap(),
    );
});

control_negative!(control_routes_create_auth_padded, false, 401, 2, req, {
    req.headers_mut().insert(
        "authorization",
        format!("Bearer {}=", URL_SAFE_NO_PAD.encode([4; 32]))
            .parse()
            .unwrap(),
    );
});

control_negative!(control_routes_create_auth_short, false, 401, 2, req, {
    req.headers_mut().insert(
        "authorization",
        format!("Bearer {}", URL_SAFE_NO_PAD.encode([4; 31]))
            .parse()
            .unwrap(),
    );
});

control_negative!(control_routes_create_auth_long, false, 401, 2, req, {
    req.headers_mut().insert(
        "authorization",
        format!("Bearer {}", URL_SAFE_NO_PAD.encode([4; 33]))
            .parse()
            .unwrap(),
    );
});

control_negative!(
    control_routes_create_auth_noncanonical,
    false,
    401,
    2,
    req,
    {
        let mut token = URL_SAFE_NO_PAD.encode([4; 32]);
        token.pop();
        token.push('R');
        req.headers_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
    }
);

control_negative!(control_routes_create_auth_duplicate, false, 400, 1, req, {
    let value = req.headers()["authorization"].clone();
    req.headers_mut().append("authorization", value);
});

control_negative!(control_routes_create_media_missing, false, 415, 7, req, {
    req.headers_mut().remove("content-type");
});

control_negative!(control_routes_create_media_wrong, false, 415, 7, req, {
    req.headers_mut()
        .insert("content-type", "application/octet-stream".parse().unwrap());
});

control_negative!(control_routes_create_media_parameter, false, 415, 7, req, {
    req.headers_mut().insert(
        "content-type",
        "application/cbor; charset=utf-8".parse().unwrap(),
    );
});

control_negative!(control_routes_create_media_duplicate, false, 400, 1, req, {
    req.headers_mut()
        .append("content-type", "application/cbor".parse().unwrap());
});

control_negative!(control_routes_create_encoding, false, 415, 7, req, {
    req.headers_mut()
        .insert("content-encoding", "identity".parse().unwrap());
});

control_negative!(
    control_routes_create_encoding_duplicate,
    false,
    400,
    1,
    req,
    {
        req.headers_mut()
            .append("content-encoding", "gzip".parse().unwrap());
        req.headers_mut()
            .append("content-encoding", "gzip".parse().unwrap());
    }
);

control_negative!(control_routes_create_length_invalid, false, 400, 1, req, {
    req.headers_mut().insert(
        "content-length",
        format!("+{}", creation().len()).parse().unwrap(),
    );
});

control_negative!(control_routes_create_length_overflow, false, 400, 1, req, {
    req.headers_mut()
        .insert("content-length", "184467440737095516160".parse().unwrap());
});

control_negative!(
    control_routes_create_length_duplicate,
    false,
    400,
    1,
    req,
    {
        req.headers_mut().append(
            "content-length",
            creation().len().to_string().parse().unwrap(),
        );
        req.headers_mut().append(
            "content-length",
            creation().len().to_string().parse().unwrap(),
        );
    }
);

control_negative!(control_routes_create_length_mismatch, false, 400, 1, req, {
    req.headers_mut()
        .insert("content-length", "1".parse().unwrap());
});

control_negative!(
    control_routes_create_length_declared_large,
    false,
    413,
    6,
    req,
    {
        req.headers_mut()
            .insert("content-length", "4097".parse().unwrap());
    }
);

control_negative!(control_routes_create_transfer_wrong, false, 400, 1, req, {
    req.headers_mut()
        .insert("transfer-encoding", "gzip".parse().unwrap());
});

control_negative!(
    control_routes_create_transfer_ambiguous,
    false,
    400,
    1,
    req,
    {
        req.headers_mut()
            .insert("transfer-encoding", "chunked".parse().unwrap());
        req.headers_mut().insert(
            "content-length",
            creation().len().to_string().parse().unwrap(),
        );
    }
);

control_negative!(
    control_routes_create_transfer_duplicate,
    false,
    400,
    1,
    req,
    {
        req.headers_mut()
            .append("transfer-encoding", "chunked".parse().unwrap());
        req.headers_mut()
            .append("transfer-encoding", "chunked".parse().unwrap());
    }
);

control_negative!(control_routes_create_bound_absent, false, 413, 6, req, {
    *req.body_mut() = Body::from(vec![0; 4097]);
});

control_negative!(control_routes_create_bound_deceptive, false, 413, 6, req, {
    req.headers_mut()
        .insert("content-length", "1".parse().unwrap());
    *req.body_mut() = Body::from(vec![0; 4097]);
});

control_negative!(control_routes_create_schema_empty, false, 400, 1, req, {
    *req.body_mut() = Body::empty();
});

control_negative!(
    control_routes_create_schema_noncanonical,
    false,
    400,
    1,
    req,
    {
        let mut body = if false { update() } else { creation() };
        body.splice(1..2, [0x18, 1]);
        *req.body_mut() = Body::from(body);
    }
);

control_negative!(control_routes_create_schema_extra, false, 400, 1, req, {
    let mut body = if false { update() } else { creation() };
    body[0] += 1;
    body.push(0);
    *req.body_mut() = Body::from(body);
});

control_negative!(control_routes_create_schema_version, false, 400, 1, req, {
    let mut body = if false { update() } else { creation() };
    body[1] = 2;
    *req.body_mut() = Body::from(body);
});

control_negative!(control_routes_create_schema_trailing, false, 400, 1, req, {
    let mut body = if false { update() } else { creation() };
    body.push(0);
    *req.body_mut() = Body::from(body);
});

control_negative!(
    control_routes_create_authorization_invalid_header,
    false,
    400,
    1,
    req,
    {
        req.headers_mut()
            .insert("authorization", HeaderValue::from_bytes(&[0xff]).unwrap());
    }
);

control_negative!(
    control_routes_create_content_type_invalid_header,
    false,
    400,
    1,
    req,
    {
        req.headers_mut()
            .insert("content-type", HeaderValue::from_bytes(&[0xff]).unwrap());
    }
);

control_negative!(
    control_routes_create_content_encoding_invalid_header,
    false,
    400,
    1,
    req,
    {
        req.headers_mut().insert(
            "content-encoding",
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
    }
);

control_negative!(
    control_routes_create_content_length_invalid_header,
    false,
    400,
    1,
    req,
    {
        req.headers_mut()
            .insert("content-length", HeaderValue::from_bytes(&[0xff]).unwrap());
    }
);

control_negative!(
    control_routes_create_transfer_encoding_invalid_header,
    false,
    400,
    1,
    req,
    {
        req.headers_mut().insert(
            "transfer-encoding",
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
    }
);

control_negative!(control_routes_rotate_path_query, true, 400, 1, req, {
    *req.uri_mut() = format!("{}?token=secret", control_uri(true))
        .parse()
        .unwrap();
});

control_negative!(control_routes_rotate_path_encoded, true, 400, 1, req, {
    *req.uri_mut() = control_uri(true)
        .replacen("01", "%30%31", 1)
        .parse()
        .unwrap();
});

control_negative!(control_routes_rotate_path_upper, true, 400, 1, req, {
    *req.uri_mut() = control_uri(true)
        .replace(&hex::encode([1; 32]), &"AB".repeat(32))
        .parse()
        .unwrap();
});

control_negative!(control_routes_rotate_path_short, true, 400, 1, req, {
    *req.uri_mut() = control_uri(true)
        .replace(&hex::encode([1; 32]), &"01".repeat(31))
        .parse()
        .unwrap();
});

control_negative!(control_routes_rotate_path_long, true, 400, 1, req, {
    *req.uri_mut() = control_uri(true)
        .replace(&hex::encode([1; 32]), &"01".repeat(33))
        .parse()
        .unwrap();
});

control_negative!(control_routes_rotate_path_extra, true, 400, 1, req, {
    *req.uri_mut() = format!("{}/more", control_uri(true)).parse().unwrap();
});

control_negative!(control_routes_rotate_method, true, 400, 1, req, {
    *req.method_mut() = axum::http::Method::GET;
});

control_negative!(control_routes_rotate_auth_missing, true, 401, 2, req, {
    req.headers_mut().remove("authorization");
});

control_negative!(control_routes_rotate_auth_scheme, true, 401, 2, req, {
    req.headers_mut().insert(
        "authorization",
        format!("bearer {}", URL_SAFE_NO_PAD.encode([4; 32]))
            .parse()
            .unwrap(),
    );
});

control_negative!(control_routes_rotate_auth_padded, true, 401, 2, req, {
    req.headers_mut().insert(
        "authorization",
        format!("Bearer {}=", URL_SAFE_NO_PAD.encode([4; 32]))
            .parse()
            .unwrap(),
    );
});

control_negative!(control_routes_rotate_auth_short, true, 401, 2, req, {
    req.headers_mut().insert(
        "authorization",
        format!("Bearer {}", URL_SAFE_NO_PAD.encode([4; 31]))
            .parse()
            .unwrap(),
    );
});

control_negative!(control_routes_rotate_auth_long, true, 401, 2, req, {
    req.headers_mut().insert(
        "authorization",
        format!("Bearer {}", URL_SAFE_NO_PAD.encode([4; 33]))
            .parse()
            .unwrap(),
    );
});

control_negative!(
    control_routes_rotate_auth_noncanonical,
    true,
    401,
    2,
    req,
    {
        let mut token = URL_SAFE_NO_PAD.encode([4; 32]);
        token.pop();
        token.push('R');
        req.headers_mut()
            .insert("authorization", format!("Bearer {token}").parse().unwrap());
    }
);

control_negative!(control_routes_rotate_auth_duplicate, true, 400, 1, req, {
    let value = req.headers()["authorization"].clone();
    req.headers_mut().append("authorization", value);
});

control_negative!(control_routes_rotate_media_missing, true, 415, 7, req, {
    req.headers_mut().remove("content-type");
});

control_negative!(control_routes_rotate_media_wrong, true, 415, 7, req, {
    req.headers_mut()
        .insert("content-type", "application/octet-stream".parse().unwrap());
});

control_negative!(control_routes_rotate_media_parameter, true, 415, 7, req, {
    req.headers_mut().insert(
        "content-type",
        "application/cbor; charset=utf-8".parse().unwrap(),
    );
});

control_negative!(control_routes_rotate_media_duplicate, true, 400, 1, req, {
    req.headers_mut()
        .append("content-type", "application/cbor".parse().unwrap());
});

control_negative!(control_routes_rotate_encoding, true, 415, 7, req, {
    req.headers_mut()
        .insert("content-encoding", "identity".parse().unwrap());
});

control_negative!(
    control_routes_rotate_encoding_duplicate,
    true,
    400,
    1,
    req,
    {
        req.headers_mut()
            .append("content-encoding", "gzip".parse().unwrap());
        req.headers_mut()
            .append("content-encoding", "gzip".parse().unwrap());
    }
);

control_negative!(control_routes_rotate_length_invalid, true, 400, 1, req, {
    req.headers_mut().insert(
        "content-length",
        format!("+{}", update().len()).parse().unwrap(),
    );
});

control_negative!(control_routes_rotate_length_overflow, true, 400, 1, req, {
    req.headers_mut()
        .insert("content-length", "184467440737095516160".parse().unwrap());
});

control_negative!(control_routes_rotate_length_duplicate, true, 400, 1, req, {
    req.headers_mut().append(
        "content-length",
        update().len().to_string().parse().unwrap(),
    );
    req.headers_mut().append(
        "content-length",
        update().len().to_string().parse().unwrap(),
    );
});

control_negative!(control_routes_rotate_length_mismatch, true, 400, 1, req, {
    req.headers_mut()
        .insert("content-length", "1".parse().unwrap());
});

control_negative!(
    control_routes_rotate_length_declared_large,
    true,
    413,
    6,
    req,
    {
        req.headers_mut()
            .insert("content-length", "4097".parse().unwrap());
    }
);

control_negative!(control_routes_rotate_transfer_wrong, true, 400, 1, req, {
    req.headers_mut()
        .insert("transfer-encoding", "gzip".parse().unwrap());
});

control_negative!(
    control_routes_rotate_transfer_ambiguous,
    true,
    400,
    1,
    req,
    {
        req.headers_mut()
            .insert("transfer-encoding", "chunked".parse().unwrap());
        req.headers_mut().insert(
            "content-length",
            update().len().to_string().parse().unwrap(),
        );
    }
);

control_negative!(
    control_routes_rotate_transfer_duplicate,
    true,
    400,
    1,
    req,
    {
        req.headers_mut()
            .append("transfer-encoding", "chunked".parse().unwrap());
        req.headers_mut()
            .append("transfer-encoding", "chunked".parse().unwrap());
    }
);

control_negative!(control_routes_rotate_bound_absent, true, 413, 6, req, {
    *req.body_mut() = Body::from(vec![0; 4097]);
});

control_negative!(control_routes_rotate_bound_deceptive, true, 413, 6, req, {
    req.headers_mut()
        .insert("content-length", "1".parse().unwrap());
    *req.body_mut() = Body::from(vec![0; 4097]);
});

control_negative!(control_routes_rotate_schema_empty, true, 400, 1, req, {
    *req.body_mut() = Body::empty();
});

control_negative!(
    control_routes_rotate_schema_noncanonical,
    true,
    400,
    1,
    req,
    {
        let mut body = if true { update() } else { creation() };
        body.splice(1..2, [0x18, 1]);
        *req.body_mut() = Body::from(body);
    }
);

control_negative!(control_routes_rotate_schema_extra, true, 400, 1, req, {
    let mut body = if true { update() } else { creation() };
    body[0] += 1;
    body.push(0);
    *req.body_mut() = Body::from(body);
});

control_negative!(control_routes_rotate_schema_version, true, 400, 1, req, {
    let mut body = if true { update() } else { creation() };
    body[1] = 2;
    *req.body_mut() = Body::from(body);
});

control_negative!(control_routes_rotate_schema_trailing, true, 400, 1, req, {
    let mut body = if true { update() } else { creation() };
    body.push(0);
    *req.body_mut() = Body::from(body);
});

control_negative!(
    control_routes_rotate_authorization_invalid_header,
    true,
    400,
    1,
    req,
    {
        req.headers_mut()
            .insert("authorization", HeaderValue::from_bytes(&[0xff]).unwrap());
    }
);

control_negative!(
    control_routes_rotate_content_type_invalid_header,
    true,
    400,
    1,
    req,
    {
        req.headers_mut()
            .insert("content-type", HeaderValue::from_bytes(&[0xff]).unwrap());
    }
);

control_negative!(
    control_routes_rotate_content_encoding_invalid_header,
    true,
    400,
    1,
    req,
    {
        req.headers_mut().insert(
            "content-encoding",
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
    }
);

control_negative!(
    control_routes_rotate_content_length_invalid_header,
    true,
    400,
    1,
    req,
    {
        req.headers_mut()
            .insert("content-length", HeaderValue::from_bytes(&[0xff]).unwrap());
    }
);

control_negative!(
    control_routes_rotate_transfer_encoding_invalid_header,
    true,
    400,
    1,
    req,
    {
        req.headers_mut().insert(
            "transfer-encoding",
            HeaderValue::from_bytes(&[0xff]).unwrap(),
        );
    }
);

#[tokio::test]
async fn control_routes_schema_prevalidation() {
    let f = HttpFixture::new(100_000).await;
    for rotate in [false, true] {
        let mut req = control_request(rotate, 4, vec![0x80]);
        *req.uri_mut() = control_uri(rotate)
            .replace(&hex::encode([1; 32]), &hex::encode([0; 32]))
            .parse()
            .unwrap();
        assert_error(f.send(req).await, 400, 1);
    }
    f.owner.shutdown().await.unwrap();
}
#[tokio::test]
async fn control_routes_quota() {
    let f = control_fixture().await;
    let mut request = loki_relay_protocol::http::decode_creation(&creation()).unwrap();
    request.quota = 100_001;
    assert_error(
        f.send(control_request(
            false,
            8,
            encode_creation(&request).unwrap(),
        ))
        .await,
        507,
        10,
    );
    assert_eq!(f.send(control_request(false, 8, creation())).await.0, 201);
    f.owner.shutdown().await.unwrap();
}
#[tokio::test]
async fn control_routes_storage_create() {
    let f = HttpFixture::new(100_000).await;
    let observer = rusqlite::Connection::open(f._root.path().join("relay.sqlite3")).unwrap();
    observer.execute_batch("CREATE TRIGGER reject_http_create BEFORE INSERT ON mailboxes BEGIN SELECT RAISE(ABORT,'test failure'); END;").unwrap();
    let mut req = control_request(false, 8, creation());
    *req.uri_mut() = control_uri(false)
        .replace(&hex::encode([1; 32]), &hex::encode([0; 32]))
        .parse()
        .unwrap();
    assert_error(f.send(req).await, 503, 9);
    let count: u64 = observer
        .query_row("SELECT count(*) FROM mailboxes", [], |r| r.get(0))
        .unwrap();
    assert_eq!(count, 1);
    f.owner.shutdown().await.unwrap();
}
#[tokio::test]
async fn control_routes_storage_rotate() {
    let f = HttpFixture::new(100_000).await;
    let observer = rusqlite::Connection::open(f._root.path().join("relay.sqlite3")).unwrap();
    observer.execute_batch("CREATE TRIGGER reject_http_rotate BEFORE UPDATE ON mailboxes BEGIN SELECT RAISE(ABORT,'test failure'); END;").unwrap();
    assert_error(f.send(control_request(true, 4, update())).await, 503, 9);
    observer
        .execute_batch("DROP TRIGGER reject_http_rotate;")
        .unwrap();
    assert_eq!(f.send(http_request("PUT", &object(9), 3)).await.0, 201);
    assert_error(f.send(http_request("PUT", &object(10), 5)).await, 401, 2);
    f.owner.shutdown().await.unwrap();
}
#[tokio::test]
async fn control_routes_stopped() {
    let f = HttpFixture::new(100_000).await;
    let app = f.app.clone();
    f.owner.shutdown().await.unwrap();
    for rotate in [false, true] {
        let response = app
            .clone()
            .oneshot(control_request(
                rotate,
                if rotate { 4 } else { 8 },
                if rotate { update() } else { creation() },
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), 503);
        assert_eq!(response.headers()["content-type"], "application/cbor");
        assert_eq!(
            to_bytes(response.into_body(), 3).await.unwrap().as_ref(),
            [0x82, 1, 9]
        );
    }
}

#[tokio::test]
async fn control_routes_create_prevalidation() {
    let f = HttpFixture::new(100_000).await;
    let mut req = control_request(false, 4, vec![0x80]);
    *req.uri_mut() = control_uri(false)
        .replace(&hex::encode([1; 32]), &hex::encode([0; 32]))
        .parse()
        .unwrap();
    assert_error(f.send(req).await, 400, 1);
    f.owner.shutdown().await.unwrap();
}
#[tokio::test]
async fn control_routes_rotate_prevalidation() {
    let f = HttpFixture::new(100_000).await;
    let mut req = control_request(true, 4, vec![0x80]);
    *req.uri_mut() = control_uri(true)
        .replace(&hex::encode([1; 32]), &hex::encode([0; 32]))
        .parse()
        .unwrap();
    assert_error(f.send(req).await, 400, 1);
    f.owner.shutdown().await.unwrap();
}
#[tokio::test]
async fn control_routes_schema_bounds() {
    use loki_relay_protocol::canonical::{encode, Value};
    let f = HttpFixture::new(100_000).await;
    let uint = |n: u64| Value::Integer(n.into());
    let bytes = |n: usize| Value::Bytes(vec![0; n]);
    let mut cases = vec![];
    for revision in [0, (i64::MAX as u64) + 1] {
        cases.push((true, Value::Array(vec![uint(1), uint(revision), bytes(32)])));
    }
    for len in [31, 33] {
        cases.push((true, Value::Array(vec![uint(1), uint(2), bytes(len)])));
        for field in 1..4 {
            let mut fields = vec![uint(1), bytes(32), bytes(32), bytes(32), uint(100_000)];
            fields[field] = bytes(len);
            cases.push((false, Value::Array(fields)));
        }
    }
    cases.push((
        false,
        Value::Array(vec![
            uint(1),
            bytes(32),
            bytes(32),
            bytes(32),
            uint((i64::MAX as u64) + 1),
        ]),
    ));
    for (rotate, value) in cases {
        let mut req = control_request(rotate, 4, encode(&value).unwrap());
        *req.uri_mut() = control_uri(rotate)
            .replace(&hex::encode([1; 32]), &hex::encode([0; 32]))
            .parse()
            .unwrap();
        assert_error(f.send(req).await, 400, 1);
    }
    f.owner.shutdown().await.unwrap();
}
#[tokio::test]
async fn control_routes_boundary() {
    let f = HttpFixture::new(100_000).await;
    for rotate in [false, true] {
        assert_error(
            f.send(control_request(
                rotate,
                if rotate { 4 } else { 8 },
                vec![0; 4096],
            ))
            .await,
            400,
            1,
        );
        let body = if rotate { update() } else { creation() };
        let mut req = control_request(rotate, if rotate { 4 } else { 8 }, body.clone());
        req.headers_mut()
            .insert("content-length", body.len().to_string().parse().unwrap());
        assert_eq!(f.send(req).await.0, 200);
        let mut req = control_request(rotate, if rotate { 4 } else { 8 }, body);
        req.headers_mut()
            .insert("transfer-encoding", "chunked".parse().unwrap());
        assert_eq!(f.send(req).await.0, 200);
    }
    f.owner.shutdown().await.unwrap();
}
#[tokio::test]
async fn control_routes_restart() {
    let f = HttpFixture::new(100_000).await;
    let obj = object(9);
    let receipt = f.send(http_request("PUT", &obj, 3)).await.2;
    assert_eq!(f.send(control_request(true, 4, update())).await.0, 200);
    let root = f._root;
    f.owner.shutdown().await.unwrap();
    let (db, owner) = DbHandle::open(root.path().to_owned(), limits())
        .await
        .unwrap();
    let reopened = HttpFixture {
        app: loki_relay_server::http::router(db.clone()),
        db,
        owner,
        _root: root,
    };
    assert_eq!(
        reopened.send(control_request(false, 8, creation())).await,
        (
            200,
            "application/cbor".into(),
            creation_result_bytes(100_000, 2)
        )
    );
    assert_eq!(
        reopened.send(control_request(true, 4, update())).await,
        (200, "application/cbor".into(), append_result_bytes(2))
    );
    assert_eq!(
        reopened.send(http_request("PUT", &obj, 5)).await,
        (200, "application/cbor".into(), receipt)
    );
    assert_eq!(
        reopened.send(http_request("GET", &obj, 2)).await.2,
        obj.wire
    );
    assert_error(
        reopened.send(http_request("PUT", &object(10), 3)).await,
        401,
        2,
    );
    reopened.owner.shutdown().await.unwrap();
}
async fn control_stream(rotate: bool, overflow: bool) {
    use std::io::{Read, Write};
    let f = HttpFixture::new(100_000).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let app = f.app.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let uri = control_uri(rotate);
    let response=tokio::task::spawn_blocking(move || {
        let mut socket=std::net::TcpStream::connect(address).unwrap();
        socket.set_read_timeout(Some(std::time::Duration::from_secs(3))).unwrap();
        write!(socket,"PUT {uri} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {}\r\nContent-Type: application/cbor\r\n{}\r\nConnection: close\r\n\r\n",URL_SAFE_NO_PAD.encode([if rotate {4} else {8};32]),if overflow {"Transfer-Encoding: chunked"} else {"Content-Length: 100"}).unwrap();
        if overflow {
            for _ in 0..4 {socket.write_all(b"400\r\n").unwrap();socket.write_all(&[0;1024]).unwrap();socket.write_all(b"\r\n").unwrap();}
            socket.write_all(b"1\r\nx\r\n0\r\n\r\n").unwrap();
        } else {
            socket.write_all(&[0;20]).unwrap();socket.shutdown(std::net::Shutdown::Write).unwrap();
        }
        let mut response=Vec::new();socket.read_to_end(&mut response).unwrap();response
    }).await.unwrap();
    let split = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    let headers = std::str::from_utf8(&response[..split]).unwrap();
    assert!(headers.starts_with(if overflow {
        "HTTP/1.1 413"
    } else {
        "HTTP/1.1 400"
    }));
    assert!(headers.contains("content-type: application/cbor\r\n"));
    assert_eq!(&response[split..], [0x82, 1, if overflow { 6 } else { 1 }]);
    stop.send(()).unwrap();
    server.await.unwrap();
    assert_eq!(f.send(http_request("PUT", &object(9), 3)).await.0, 201);
    f.owner.shutdown().await.unwrap();
}
#[tokio::test]
async fn control_routes_create_stream_bound() {
    control_stream(false, true).await;
}
#[tokio::test]
async fn control_routes_rotate_stream_bound() {
    control_stream(true, true).await;
}
#[tokio::test]
async fn control_routes_create_stream_error() {
    control_stream(false, false).await;
}
#[tokio::test]
async fn control_routes_rotate_stream_error() {
    control_stream(true, false).await;
}

#[tokio::test]
async fn control_routes_short_zero_capability() {
    let root = Scratch::new();
    drop(
        RelayStore::init(
            root.path(),
            [7; 32],
            "http://127.0.0.1:8000",
            &[0; 32],
            provisioning_verifier([7; 32], &[0; 32]),
            limits(),
        )
        .unwrap(),
    );
    let (db, owner) = DbHandle::open(root.path().to_owned(), limits())
        .await
        .unwrap();
    let f = HttpFixture {
        app: loki_relay_server::http::router(db.clone()),
        db,
        owner,
        _root: root,
    };
    let mut req = control_request(false, 0, creation());
    req.headers_mut().insert(
        "authorization",
        format!("Bearer {}", URL_SAFE_NO_PAD.encode([0; 31]))
            .parse()
            .unwrap(),
    );
    assert_error(f.send(req).await, 401, 2);
    assert_eq!(f.send(control_request(false, 0, creation())).await.0, 201);
    f.owner.shutdown().await.unwrap();
}

fn page_request(query: &str, secret: u8) -> Request<Body> {
    Request::builder()
        .uri(format!(
            "/v1/mailboxes/{}/entries{query}",
            hex::encode([1; 32])
        ))
        .header(
            "authorization",
            format!("Bearer {}", URL_SAFE_NO_PAD.encode([secret; 32])),
        )
        .body(Body::empty())
        .unwrap()
}

async fn page_fixture() -> HttpFixture {
    let root = Scratch::new();
    let limits = Limits {
        total_bytes: 1_000_000,
        mailbox_bytes: 1_000_000,
        mailbox_count: 10,
    };
    drop(
        RelayStore::init(
            root.path(),
            [7; 32],
            "http://127.0.0.1:8000",
            &[8; 32],
            provisioning_verifier([7; 32], &[8; 32]),
            limits,
        )
        .unwrap(),
    );
    let (db, owner) = DbHandle::open(root.path().to_owned(), limits)
        .await
        .unwrap();
    let mut c = loki_relay_protocol::http::decode_creation(&creation()).unwrap();
    c.quota = 1_000_000;
    db.create(
        [1; 32],
        encode_creation(&c).unwrap(),
        Capability::new([8; 32]),
    )
    .unwrap()
    .receive()
    .await
    .unwrap();
    HttpFixture {
        app: loki_relay_server::http::router(db.clone()),
        db,
        owner,
        _root: root,
    }
}

#[tokio::test]
async fn snapshot_page() {
    let fixture = page_fixture().await;
    let mut saved = Vec::new();
    for tag in 0..101 {
        saved.push(
            fixture
                .db
                .put([1; 32], object(tag), Capability::new([3; 32]))
                .unwrap()
                .receive()
                .await
                .unwrap(),
        );
    }
    let (status, media, bytes) = fixture.send(page_request("", 2)).await;
    assert_eq!(status, 200);
    assert_eq!(media, "application/cbor");
    assert!(bytes.len() <= 128 * 1024);
    eprintln!(
        "snapshot metadata bytes={} limit=100 high_water=101",
        bytes.len()
    );
    let page = loki_relay_protocol::http::decode_page(&bytes).unwrap();
    assert_eq!(
        (
            page.mailbox,
            page.after,
            page.next,
            page.high_water,
            page.entries.len()
        ),
        ([1; 32], 0, 100, 101, 100)
    );
    for (i, entry) in page.entries.iter().enumerate() {
        assert_eq!(entry.sequence, i as u64 + 1);
        assert_eq!(entry.hash, object(i as u8).hash);
        assert_eq!(entry.wire_length, 1024);
        assert_eq!(entry.receipt, saved[i].receipt);
    }
    let (status, _, bytes) = fixture.send(page_request("?after=100&limit=100", 2)).await;
    assert_eq!(status, 200);
    let page = loki_relay_protocol::http::decode_page(&bytes).unwrap();
    assert_eq!(
        (page.after, page.next, page.high_water, page.entries.len()),
        (100, 101, 101, 1)
    );
    assert_eq!(page.entries[0].receipt, saved[100].receipt);
    let (status, _, bytes) = fixture.send(page_request("?after=101", 2)).await;
    assert_eq!(status, 200);
    let page = loki_relay_protocol::http::decode_page(&bytes).unwrap();
    assert_eq!(
        (page.after, page.next, page.high_water, page.entries.len()),
        (101, 101, 101, 0)
    );
    let (status, _, bytes) = fixture.send(page_request("?after=0&limit=1", 2)).await;
    assert_eq!(status, 200);
    let page = loki_relay_protocol::http::decode_page(&bytes).unwrap();
    assert_eq!((page.next, page.entries.len()), (1, 1));
    assert_eq!(
        fixture
            .db
            .get([1; 32], object(0).hash, Capability::new([2; 32]))
            .unwrap()
            .receive()
            .await
            .unwrap(),
        object(0).wire
    );
    fixture.owner.shutdown().await.unwrap();
}

macro_rules! snapshot_query_negative {
    ($name:ident, $query:expr, $status:expr, $code:expr) => {
        #[tokio::test]
        async fn $name() {
            let fixture = page_fixture().await;
            let (status, media, bytes) = fixture.send(page_request($query, 2)).await;
            assert_eq!(status, $status);
            assert_eq!(media, "application/cbor");
            assert_eq!(bytes, [0x82, 1, $code]);
            fixture.owner.shutdown().await.unwrap();
        }
    };
}
snapshot_query_negative!(snapshot_page_ahead, "?after=1", 409, 5);
snapshot_query_negative!(
    snapshot_page_u64_ahead,
    "?after=18446744073709551615",
    409,
    5
);
snapshot_query_negative!(snapshot_page_limit_zero, "?limit=0", 400, 1);
snapshot_query_negative!(snapshot_page_limit_large, "?limit=101", 400, 1);
snapshot_query_negative!(
    snapshot_page_limit_overflow,
    "?limit=18446744073709551616",
    400,
    1
);
snapshot_query_negative!(
    snapshot_page_after_overflow,
    "?after=18446744073709551616",
    400,
    1
);
snapshot_query_negative!(snapshot_page_after_leading_zero, "?after=00", 400, 1);
snapshot_query_negative!(snapshot_page_limit_leading_zero, "?limit=01", 400, 1);
snapshot_query_negative!(snapshot_page_after_plus, "?after=+1", 400, 1);
snapshot_query_negative!(snapshot_page_after_negative, "?after=-1", 400, 1);
snapshot_query_negative!(snapshot_page_after_encoded, "?after=%30", 400, 1);
snapshot_query_negative!(snapshot_page_key_encoded, "?%61fter=0", 400, 1);
snapshot_query_negative!(snapshot_page_duplicate_after, "?after=0&after=0", 400, 1);
snapshot_query_negative!(snapshot_page_duplicate_limit, "?limit=1&limit=1", 400, 1);
snapshot_query_negative!(snapshot_page_unknown_query, "?unknown=0", 400, 1);
snapshot_query_negative!(snapshot_page_empty_query, "?", 400, 1);
snapshot_query_negative!(snapshot_page_empty_value, "?after=", 400, 1);
snapshot_query_negative!(snapshot_page_missing_equals, "?after", 400, 1);
snapshot_query_negative!(snapshot_page_trailing_separator, "?after=0&", 400, 1);

macro_rules! snapshot_request_negative {
    ($name:ident, $status:expr, $code:expr, $req:ident, $change:block) => {
        #[tokio::test]
        async fn $name() {
            let fixture = page_fixture().await;
            let mut $req = page_request("", 2);
            $change
            let (status, media, bytes) = fixture.send($req).await;
            assert_eq!(status, $status);
            assert_eq!(media, "application/cbor");
            assert_eq!(bytes, [0x82, 1, $code]);
            fixture.owner.shutdown().await.unwrap();
        }
    };
}
snapshot_request_negative!(snapshot_page_append_role, 401, 2, req, {
    req.headers_mut().insert(
        "authorization",
        format!("Bearer {}", URL_SAFE_NO_PAD.encode([3; 32]))
            .parse()
            .unwrap(),
    );
});
snapshot_request_negative!(snapshot_page_admin_role, 401, 2, req, {
    req.headers_mut().insert(
        "authorization",
        format!("Bearer {}", URL_SAFE_NO_PAD.encode([4; 32]))
            .parse()
            .unwrap(),
    );
});
snapshot_request_negative!(snapshot_page_unknown_mailbox, 401, 2, req, {
    *req.uri_mut() = format!("/v1/mailboxes/{}/entries", hex::encode([9; 32]))
        .parse()
        .unwrap();
});
snapshot_request_negative!(snapshot_page_raw_mailbox, 400, 1, req, {
    *req.uri_mut() = format!("/v1/mailboxes/%30{}/entries", &hex::encode([1; 32])[1..])
        .parse()
        .unwrap();
});
snapshot_request_negative!(snapshot_page_upper_mailbox, 400, 1, req, {
    *req.uri_mut() = format!("/v1/mailboxes/{}/entries", "AB".repeat(32))
        .parse()
        .unwrap();
});
snapshot_request_negative!(snapshot_page_body, 400, 1, req, {
    *req.body_mut() = Body::from(vec![1]);
});
snapshot_request_negative!(snapshot_page_length_mismatch, 400, 1, req, {
    req.headers_mut()
        .insert("content-length", "1".parse().unwrap());
});
snapshot_request_negative!(snapshot_page_auth_missing, 401, 2, req, {
    req.headers_mut().remove("authorization");
});
snapshot_request_negative!(snapshot_page_auth_duplicate, 400, 1, req, {
    let value = req.headers()["authorization"].clone();
    req.headers_mut().append("authorization", value);
});
snapshot_request_negative!(snapshot_page_auth_bad_shape, 401, 2, req, {
    req.headers_mut()
        .insert("authorization", "Bearer x".parse().unwrap());
});
snapshot_request_negative!(snapshot_page_media, 415, 7, req, {
    req.headers_mut()
        .insert("content-type", "application/cbor".parse().unwrap());
});
snapshot_request_negative!(snapshot_page_encoding, 415, 7, req, {
    req.headers_mut()
        .insert("content-encoding", "gzip".parse().unwrap());
});
snapshot_request_negative!(snapshot_page_length_bad, 400, 1, req, {
    req.headers_mut()
        .insert("content-length", "x".parse().unwrap());
});
snapshot_request_negative!(snapshot_page_transfer_bad, 400, 1, req, {
    req.headers_mut()
        .insert("transfer-encoding", "gzip".parse().unwrap());
});
snapshot_request_negative!(snapshot_page_transfer_length, 400, 1, req, {
    req.headers_mut()
        .insert("transfer-encoding", "chunked".parse().unwrap());
    req.headers_mut()
        .insert("content-length", "0".parse().unwrap());
});

#[tokio::test]
async fn snapshot_page_mailbox_scope() {
    let fixture = page_fixture().await;
    let c = loki_relay_protocol::types::Creation {
        read_verifier: verifier(Role::Read, [6; 32], &[2; 32]),
        append_verifier: verifier(Role::Append, [6; 32], &[3; 32]),
        admin_verifier: verifier(Role::Admin, [6; 32], &[4; 32]),
        quota: 100_000,
    };
    fixture
        .db
        .create(
            [6; 32],
            encode_creation(&c).unwrap(),
            Capability::new([8; 32]),
        )
        .unwrap()
        .receive()
        .await
        .unwrap();
    fixture
        .db
        .put([6; 32], object(9), Capability::new([3; 32]))
        .unwrap()
        .receive()
        .await
        .unwrap();
    let (status, _, bytes) = fixture.send(page_request("", 2)).await;
    assert_eq!(status, 200);
    let page = loki_relay_protocol::http::decode_page(&bytes).unwrap();
    assert_eq!((page.high_water, page.next, page.entries.len()), (0, 0, 0));
    fixture
        .db
        .put([1; 32], object(10), Capability::new([3; 32]))
        .unwrap()
        .receive()
        .await
        .unwrap();
    let (status, _, bytes) = fixture.send(page_request("", 2)).await;
    assert_eq!(status, 200);
    let page = loki_relay_protocol::http::decode_page(&bytes).unwrap();
    assert_eq!((page.high_water, page.next, page.entries.len()), (1, 1, 1));
    assert_eq!(page.entries[0].hash, object(10).hash);
    fixture.owner.shutdown().await.unwrap();
}

#[tokio::test]
async fn snapshot_page_restart_exact_receipt() {
    let fixture = page_fixture().await;
    fixture
        .db
        .put([1; 32], object(9), Capability::new([3; 32]))
        .unwrap()
        .receive()
        .await
        .unwrap();
    let (status, _, before) = fixture.send(page_request("", 2)).await;
    assert_eq!(status, 200);
    let root = fixture._root.path().to_owned();
    fixture.owner.shutdown().await.unwrap();
    let (db, owner) = DbHandle::open(
        root,
        Limits {
            total_bytes: 1_000_000,
            mailbox_bytes: 1_000_000,
            mailbox_count: 10,
        },
    )
    .await
    .unwrap();
    let page = db
        .page([1; 32], 0, 100, Capability::new([2; 32]))
        .unwrap()
        .receive()
        .await
        .unwrap();
    assert_eq!(
        loki_relay_protocol::http::encode_page(&page).unwrap(),
        before
    );
    owner.shutdown().await.unwrap();
}

#[tokio::test]
async fn snapshot_page_closed_writer() {
    let fixture = page_fixture().await;
    let app = fixture.app.clone();
    fixture.owner.shutdown().await.unwrap();
    let response = app.oneshot(page_request("", 2)).await.unwrap();
    assert_eq!(response.status().as_u16(), 503);
    assert_eq!(
        to_bytes(response.into_body(), 3).await.unwrap().as_ref(),
        [0x82, 1, 9]
    );
}

snapshot_request_negative!(snapshot_page_body_bound, 413, 6, req, {
    *req.body_mut() = Body::from(vec![0; 65537]);
});
snapshot_request_negative!(snapshot_page_length_bound, 413, 6, req, {
    req.headers_mut()
        .insert("content-length", "65537".parse().unwrap());
});
snapshot_request_negative!(snapshot_page_method, 400, 1, req, {
    *req.method_mut() = axum::http::Method::POST;
});
snapshot_request_negative!(snapshot_page_duplicate_length, 400, 1, req, {
    req.headers_mut()
        .append("content-length", "0".parse().unwrap());
    req.headers_mut()
        .append("content-length", "0".parse().unwrap());
});
snapshot_request_negative!(snapshot_page_duplicate_media, 400, 1, req, {
    req.headers_mut()
        .append("content-type", "application/octet-stream".parse().unwrap());
    req.headers_mut()
        .append("content-type", "application/octet-stream".parse().unwrap());
});
snapshot_request_negative!(snapshot_page_short_mailbox, 400, 1, req, {
    *req.uri_mut() = "/v1/mailboxes/01/entries".parse().unwrap();
});

#[allow(unused_macros)]
macro_rules! snapshot_writer_tests {
    () => {
        #[tokio::test(flavor = "current_thread")]
        async fn snapshot_page_queue_and_shutdown() {
            let fixture = page_fixture().await;
            let release = barrier(&fixture.db).await;
            let mut pending = Vec::new();
            for _ in 0..64 {
                pending.push(
                    fixture
                        .db
                        .page([1; 32], 0, 100, Capability::new([2; 32]))
                        .unwrap(),
                );
            }
            assert!(matches!(
                fixture.db.page([1; 32], 0, 100, Capability::new([2; 32])),
                Err(RelayError::RateLimit)
            ));
            let (status, _, bytes) = fixture.send(page_request("", 2)).await;
            assert_eq!((status, bytes), (429, vec![0x82, 1, 8]));
            fixture.owner.stop();
            assert!(matches!(
                fixture.db.page([1; 32], 0, 100, Capability::new([2; 32])),
                Err(RelayError::StorageUnavailable)
            ));
            release.send(()).unwrap();
            for reply in pending {
                assert!(reply.receive().await.unwrap().entries.is_empty());
            }
            fixture.owner.shutdown().await.unwrap();
        }
    };
}

#[tokio::test]
async fn snapshot_page_head() {
    let fixture = page_fixture().await;
    let mut req = page_request("", 2);
    *req.method_mut() = axum::http::Method::HEAD;
    let response = fixture.app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status().as_u16(), 400);
    fixture.owner.shutdown().await.unwrap();
}

#[tokio::test]
async fn snapshot_page_loopback() {
    use std::io::{Read, Write};
    let fixture = page_fixture().await;
    fixture
        .db
        .put([1; 32], object(9), Capability::new([3; 32]))
        .unwrap()
        .receive()
        .await
        .unwrap();
    let (_, _, expected) = fixture.send(page_request("?after=0&limit=1", 2)).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let app = fixture.app.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let request = format!("GET /v1/mailboxes/{}/entries?after=0&limit=1 HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {}\r\nConnection: close\r\n\r\n", hex::encode([1; 32]), URL_SAFE_NO_PAD.encode([2; 32]));
    let response = tokio::task::spawn_blocking(move || {
        let mut socket = std::net::TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        socket
            .set_write_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        socket.write_all(request.as_bytes()).unwrap();
        let mut bytes = Vec::new();
        socket.read_to_end(&mut bytes).unwrap();
        bytes
    })
    .await
    .unwrap();
    let split = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
    let headers = std::str::from_utf8(&response[..split]).unwrap();
    assert!(headers.starts_with("HTTP/1.1 200"));
    assert!(headers.contains("content-type: application/cbor"));
    assert_eq!(&response[split + 4..], expected);
    stop.send(()).unwrap();
    server.await.unwrap();
    fixture.owner.shutdown().await.unwrap();
}

use loki_relay_server::DbReply;
use loki_relay_server::StoredResult;

fn included_in_writer_unit_tests() -> bool {
    module_path!().contains("writer::tests")
}

struct FreshSaturation {
    fixture: HttpFixture,
    lock: rusqlite::Connection,
    pending: Vec<DbReply<StoredResult>>,
    duplicate: Object,
    receipt: Vec<u8>,
    admitted: usize,
}

async fn saturate_fresh_puts() -> FreshSaturation {
    let fixture = HttpFixture::new(100_000).await;
    let duplicate = object(9);
    let saved = fixture
        .db
        .put([1; 32], duplicate.clone(), Capability::new([3; 32]))
        .unwrap()
        .receive()
        .await
        .unwrap();
    assert!(saved.created);
    let receipt = saved.receipt;
    let lock = rusqlite::Connection::open(fixture._root.path().join("relay.sqlite3")).unwrap();
    lock.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut pending = Vec::new();
    let mut admitted = 0usize;
    let refusal = loop {
        if admitted == 80 {
            break None;
        }
        match fixture.db.put(
            [1; 32],
            object(20u8.wrapping_add(admitted as u8)),
            Capability::new([3; 32]),
        ) {
            Ok(reply) => {
                pending.push(reply);
                admitted += 1;
            }
            Err(error) => break Some(error),
        }
    };
    assert_eq!(
        refusal,
        Some(RelayError::RateLimit),
        "fresh admission refused with {refusal:?} after {admitted} accepts"
    );
    FreshSaturation {
        fixture,
        lock,
        pending,
        duplicate,
        receipt,
        admitted,
    }
}

async fn finish_saturation(saturation: FreshSaturation) {
    saturation.lock.execute_batch("ROLLBACK").unwrap();
    drop(saturation.lock);
    for reply in saturation.pending {
        tokio::time::timeout(std::time::Duration::from_secs(3), reply.receive())
            .await
            .expect("accepted fresh put did not finish")
            .expect("accepted fresh put failed");
    }
    saturation.fixture.owner.shutdown().await.unwrap();
}

fn integer_retry_after(headers: &axum::http::HeaderMap) -> u64 {
    let value = headers
        .get("retry-after")
        .expect("admission failure carries Retry-After")
        .to_str()
        .unwrap();
    assert!(
        !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()),
        "Retry-After must be an integer delta, got {value}"
    );
    value.parse().unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_limits_reserved_under_new_admission() {
    let saturation = saturate_fresh_puts().await;
    assert!(
        saturation.admitted < 64,
        "fresh puts occupied the whole 64-slot queue ({})",
        saturation.admitted
    );
    assert!(
        saturation.admitted >= 32,
        "fresh capacity collapsed to {}",
        saturation.admitted
    );
    let app = saturation.fixture.app.clone();
    let mut get_request = http_request("GET", &saturation.duplicate, 2);
    get_request.headers_mut().remove("content-type");
    let expected_wire = saturation.duplicate.wire.clone();
    let receipt = saturation.receipt.clone();
    let duplicate = saturation.duplicate.clone();
    let get_app = app.clone();
    let get_task = tokio::spawn(async move {
        let response = get_app.oneshot(get_request).await.unwrap();
        let status = response.status().as_u16();
        let body = to_bytes(response.into_body(), 70_000)
            .await
            .unwrap()
            .to_vec();
        (status, body)
    });
    let dup_request = http_request("PUT", &duplicate, 3);
    let dup_task = tokio::spawn(async move {
        let response = app.oneshot(dup_request).await.unwrap();
        let status = response.status().as_u16();
        let body = to_bytes(response.into_body(), 70_000)
            .await
            .unwrap()
            .to_vec();
        (status, body)
    });
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    assert!(
        !get_task.is_finished(),
        "authenticated read was refused while fresh admission was full"
    );
    assert!(
        !dup_task.is_finished(),
        "exact duplicate PUT was refused while fresh admission was full"
    );
    finish_saturation(saturation).await;
    let (status, body) = tokio::time::timeout(std::time::Duration::from_secs(3), get_task)
        .await
        .expect("reserved read did not finish")
        .unwrap();
    assert_eq!((status, body), (200, expected_wire));
    let (status, body) = tokio::time::timeout(std::time::Duration::from_secs(3), dup_task)
        .await
        .expect("reserved duplicate did not finish")
        .unwrap();
    assert_eq!((status, body), (200, receipt));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_limits_retry_after_integer() {
    let saturation = saturate_fresh_puts().await;
    let response = saturation
        .fixture
        .app
        .clone()
        .oneshot(http_request("PUT", &object(7), 3))
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 429);
    let retry_after = integer_retry_after(response.headers());
    assert!(retry_after <= 30);
    assert_eq!(
        to_bytes(response.into_body(), 8).await.unwrap().as_ref(),
        [0x82, 1, 8]
    );
    finish_saturation(saturation).await;
}

#[tokio::test]
async fn http_limits_retry_after_absent_on_malformed() {
    let fixture = HttpFixture::new(100_000).await;
    let mut request = http_request("PUT", &object(10), 3);
    *request.uri_mut() = "/v1/not-a-mailbox".parse().unwrap();
    let response = fixture.app.clone().oneshot(request).await.unwrap();
    assert_eq!(response.status().as_u16(), 400);
    assert!(response.headers().get("retry-after").is_none());
    assert_eq!(
        to_bytes(response.into_body(), 8).await.unwrap().as_ref(),
        [0x82, 1, 1]
    );
    fixture.owner.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_limits_concurrency_bounds() {
    let fixture = HttpFixture::new(100_000).await;
    let lock = rusqlite::Connection::open(fixture._root.path().join("relay.sqlite3")).unwrap();
    lock.execute_batch("BEGIN IMMEDIATE").unwrap();
    let mut tasks = Vec::new();
    for tag in 20..50 {
        let app = fixture.app.clone();
        let request = http_request("PUT", &object(tag), 3);
        tasks.push(tokio::spawn(async move {
            app.oneshot(request).await.unwrap().status().as_u16()
        }));
    }
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let extra = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        fixture
            .app
            .clone()
            .oneshot(http_request("PUT", &object(7), 3)),
    )
    .await
    .expect("31st fresh request was not refused")
    .unwrap();
    assert_eq!(extra.status().as_u16(), 429);
    let mut get = http_request("GET", &object(9), 2);
    get.headers_mut().remove("content-type");
    let get_task = tokio::spawn({
        let app = fixture.app.clone();
        async move { app.oneshot(get).await.unwrap().status().as_u16() }
    });
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    assert!(
        !get_task.is_finished(),
        "read was refused before total concurrency was full"
    );
    lock.execute_batch("ROLLBACK").unwrap();
    drop(lock);
    for task in tasks {
        let status = tokio::time::timeout(std::time::Duration::from_secs(3), task)
            .await
            .expect("fresh request did not finish")
            .unwrap();
        assert_eq!(status, 201);
    }
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(3), get_task)
            .await
            .expect("read did not finish")
            .unwrap(),
        404
    );
    fixture.owner.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_limits_total_concurrency() {
    let fixture = HttpFixture::new(100_000).await;
    let lock = rusqlite::Connection::open(fixture._root.path().join("relay.sqlite3")).unwrap();
    lock.execute_batch("BEGIN IMMEDIATE").unwrap();
    let blocker = fixture
        .db
        .put([1; 32], object(21), Capability::new([3; 32]))
        .unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut reads = Vec::new();
    for _ in 0..32 {
        let app = fixture.app.clone();
        let mut request = http_request("GET", &object(9), 2);
        request.headers_mut().remove("content-type");
        reads.push(tokio::spawn(async move {
            app.oneshot(request).await.unwrap().status().as_u16()
        }));
    }
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
    let mut extra = http_request("GET", &object(9), 2);
    extra.headers_mut().remove("content-type");
    let response = tokio::time::timeout(
        std::time::Duration::from_millis(500),
        fixture.app.clone().oneshot(extra),
    )
    .await
    .expect("33rd request was not refused")
    .unwrap();
    assert_eq!(response.status().as_u16(), 429);
    lock.execute_batch("ROLLBACK").unwrap();
    drop(lock);
    blocker.receive().await.unwrap();
    for read in reads {
        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), read).await;
    }
    fixture.owner.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_limits_deadline() {
    use std::io::{Read, Write};
    let fixture = HttpFixture::new(100_000).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let app = fixture.app.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let uri = object_uri(&object(10));
    let response = tokio::task::spawn_blocking(move || {
        let mut socket = std::net::TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(12)))
            .unwrap();
        socket
            .set_write_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        write!(
            socket,
            "PUT {uri} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {}\r\nContent-Type: application/octet-stream\r\nContent-Length: 1024\r\nConnection: close\r\n\r\n",
            URL_SAFE_NO_PAD.encode([3; 32])
        )
        .unwrap();
        socket.write_all(&[0]).unwrap();
        let mut response = Vec::new();
        socket.read_to_end(&mut response).expect("request deadline");
        response
    })
    .await
    .unwrap();
    let split = response
        .windows(4)
        .position(|mark| mark == b"\r\n\r\n")
        .expect("deadline response")
        + 4;
    let headers = std::str::from_utf8(&response[..split]).unwrap();
    assert!(
        headers.starts_with("HTTP/1.1 503"),
        "slow body was not closed with 503: {headers}"
    );
    assert_eq!(&response[split..], [0x82, 1, 9]);
    stop.send(()).unwrap();
    server.await.unwrap();
    fixture.owner.shutdown().await.unwrap();
}

negative_request!(http_limits_deceptive_content_length, 413, 6, obj, req, {
    req.headers_mut()
        .insert("content-length", "65537".parse().unwrap());
});

#[tokio::test]
async fn http_limits_absent_length_still_capped() {
    use std::io::{Read, Write};
    let fixture = HttpFixture::new(100_000).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let app = fixture.app.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let uri = object_uri(&object(10));
    let response = tokio::task::spawn_blocking(move || {
        let mut socket = std::net::TcpStream::connect(address).unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .unwrap();
        write!(
            socket,
            "PUT {uri} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {}\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
            URL_SAFE_NO_PAD.encode([3; 32])
        )
        .unwrap();
        for _ in 0..64 {
            socket.write_all(b"400\r\n").unwrap();
            socket.write_all(&[0; 1024]).unwrap();
            socket.write_all(b"\r\n").unwrap();
        }
        socket.write_all(b"1\r\nx\r\n0\r\n\r\n").unwrap();
        let mut response = Vec::new();
        socket.read_to_end(&mut response).unwrap();
        response
    })
    .await
    .unwrap();
    let split = response
        .windows(4)
        .position(|mark| mark == b"\r\n\r\n")
        .unwrap()
        + 4;
    assert!(std::str::from_utf8(&response[..split])
        .unwrap()
        .starts_with("HTTP/1.1 413"));
    assert_eq!(&response[split..], [0x82, 1, 6]);
    stop.send(()).unwrap();
    server.await.unwrap();
    fixture.owner.shutdown().await.unwrap();
}

#[tokio::test]
async fn http_limits_errors_exact() {
    let fixture = HttpFixture::new(100_000).await;
    assert_error(
        fixture
            .send({
                let mut request = http_request("PUT", &object(10), 3);
                *request.uri_mut() = "/v1/nope".parse().unwrap();
                request
            })
            .await,
        400,
        1,
    );
    assert_error(
        fixture.send(http_request("GET", &object(10), 1)).await,
        401,
        2,
    );
    let mut missing = http_request("GET", &object(10), 2);
    missing.headers_mut().remove("content-type");
    assert_error(fixture.send(missing).await, 404, 3);
    assert_error(
        fixture
            .send(control_request(
                true,
                4,
                encode_append_update(&AppendUpdate {
                    revision: 4,
                    verifier: verifier(Role::Append, [1; 32], &[5; 32]),
                })
                .unwrap(),
            ))
            .await,
        409,
        4,
    );
    assert_error(fixture.send(page_request("?after=1", 2)).await, 409, 5);
    assert_error(
        fixture
            .send({
                let mut request = http_request("PUT", &object(10), 3);
                *request.body_mut() = Body::from(vec![0; 65_537]);
                request
            })
            .await,
        413,
        6,
    );
    assert_error(
        fixture
            .send({
                let mut request = http_request("PUT", &object(10), 3);
                request
                    .headers_mut()
                    .insert("content-type", "text/plain".parse().unwrap());
                request
            })
            .await,
        415,
        7,
    );
    let saturated = saturate_fresh_puts().await;
    let response = saturated
        .fixture
        .app
        .clone()
        .oneshot(http_request("PUT", &object(7), 3))
        .await
        .unwrap();
    assert_eq!(response.status().as_u16(), 429);
    assert_eq!(
        to_bytes(response.into_body(), 8).await.unwrap().as_ref(),
        [0x82, 1, 8]
    );
    finish_saturation(saturated).await;
    fixture.owner.shutdown().await.unwrap();
    let stopped = HttpFixture::new(100_000).await;
    let app = stopped.app.clone();
    stopped.owner.shutdown().await.unwrap();
    let response = app
        .oneshot(http_request("GET", &object(10), 2))
        .await
        .unwrap();
    let status = response.status().as_u16();
    let media = response.headers()["content-type"]
        .to_str()
        .unwrap()
        .to_owned();
    let body = to_bytes(response.into_body(), 8).await.unwrap().to_vec();
    assert_error((status, media, body), 503, 9);
    let quota = HttpFixture::new(1_024).await;
    assert_eq!(quota.send(http_request("PUT", &object(10), 3)).await.0, 201);
    assert_error(
        quota.send(http_request("PUT", &object(11), 3)).await,
        507,
        10,
    );
    quota.owner.shutdown().await.unwrap();
}

fn relay_binary() -> std::path::PathBuf {
    if let Some(path) = option_env!("CARGO_BIN_EXE_loki_relay_server") {
        return std::path::PathBuf::from(path);
    }
    let current = std::env::current_exe().expect("loki-relay-server binary");
    current
        .parent()
        .and_then(std::path::Path::parent)
        .unwrap()
        .join("loki-relay-server")
}

fn write_provision(directory: &std::path::Path) -> std::path::PathBuf {
    let path = directory.join("provision.bin");
    std::fs::write(&path, [8u8; 32]).unwrap();
    path
}

fn init_server(root: &std::path::Path, listen: &str) -> std::process::ExitStatus {
    std::fs::create_dir_all(root.parent().unwrap()).unwrap();
    let provision = write_provision(root.parent().unwrap());
    std::process::Command::new(relay_binary())
        .args([
            "init",
            "--root",
            root.to_str().unwrap(),
            "--provision-capability-file",
            provision.to_str().unwrap(),
            "--total-bytes",
            "100000",
            "--mailbox-bytes",
            "100000",
            "--mailbox-count",
            "3",
            "--listen",
            listen,
        ])
        .status()
        .unwrap()
}

struct SpawnedServer {
    child: std::process::Child,
    stdout: Option<std::process::ChildStdout>,
    stderr: Option<std::process::ChildStderr>,
}
impl Drop for SpawnedServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn serve_server(root: &std::path::Path, listen: &str) -> SpawnedServer {
    let mut child = std::process::Command::new(relay_binary())
        .args([
            "serve",
            "--root",
            root.to_str().unwrap(),
            "--listen",
            listen,
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    SpawnedServer {
        child,
        stdout,
        stderr,
    }
}

fn read_bound_line(stdout: &mut std::process::ChildStdout) -> String {
    use std::os::fd::AsFd;
    let owned = stdout.as_fd().try_clone_to_owned().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut file = std::fs::File::from(owned);
        let mut line = String::new();
        let _ = std::io::BufRead::read_line(
            &mut std::io::BufReader::with_capacity(1, &mut file),
            &mut line,
        );
        let _ = sender.send(line);
    });
    receiver
        .recv_timeout(std::time::Duration::from_secs(5))
        .expect("server did not announce its bound URL")
}

fn free_listen(bind: &str) -> String {
    let listener = std::net::TcpListener::bind(bind).unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    if address.is_ipv4() {
        format!("127.0.0.1:{}", address.port())
    } else {
        format!("[::1]:{}", address.port())
    }
}

fn manifest_lines(root: &std::path::Path) -> Vec<String> {
    std::fs::read_to_string(root.join("manifest"))
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

#[tokio::test]
async fn http_limits_loopback_only() {
    if included_in_writer_unit_tests() {
        return;
    }
    let scratch = Scratch::new();
    let root = scratch.path().join("run");
    assert!(
        !init_server(&root, "0.0.0.0:9").success(),
        "non-loopback init was accepted"
    );
    assert!(!root.join("receipt.seed").exists());
    assert!(init_server(&root, "127.0.0.1:9").success());
    let lines = manifest_lines(&root);
    assert_eq!(lines[0], "http://127.0.0.1:9");
    let mismatch = std::process::Command::new(relay_binary())
        .args([
            "serve",
            "--root",
            root.to_str().unwrap(),
            "--listen",
            "127.0.0.1:10",
        ])
        .status()
        .unwrap();
    assert!(!mismatch.success());
    assert_eq!(manifest_lines(&root), lines);
    let wildcard = std::process::Command::new(relay_binary())
        .args([
            "serve",
            "--root",
            root.to_str().unwrap(),
            "--listen",
            "0.0.0.0:9",
        ])
        .status()
        .unwrap();
    assert!(!wildcard.success());
    assert_eq!(manifest_lines(&root), lines);
}

#[tokio::test]
async fn http_limits_occupied_port_does_not_kill() {
    if included_in_writer_unit_tests() {
        return;
    }
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let scratch = Scratch::new();
    let root = scratch.path().join("run");
    let listen = format!("127.0.0.1:{port}");
    assert!(init_server(&root, &listen).success());
    let mut server = serve_server(&root, &listen);
    let status = server
        .child
        .wait()
        .expect("occupied-port serve did not exit");
    assert!(!status.success());
    drop(server);
    assert!(listener.local_addr().is_ok());
    let probe = std::net::TcpListener::bind(("127.0.0.1", port));
    assert!(probe.is_err(), "serve replaced the occupied socket");
}

#[tokio::test]
async fn http_limits_restart_preserves_identity() {
    if included_in_writer_unit_tests() {
        return;
    }
    let scratch = Scratch::new();
    let root = scratch.path().join("run");
    let listen = free_listen("127.0.0.1:0");
    assert!(init_server(&root, &listen).success());
    let before = manifest_lines(&root);
    assert_eq!(before[0], format!("http://{listen}"));
    let mut server = serve_server(&root, &listen);
    let bound = read_bound_line(server.stdout.as_mut().unwrap());
    assert_eq!(bound.trim(), format!("http://{listen}"));
    assert!(std::process::Command::new("kill")
        .args(["-TERM", &server.child.id().to_string()])
        .status()
        .unwrap()
        .success());
    let status = server.child.wait().unwrap();
    assert!(status.success());
    assert_eq!(manifest_lines(&root), before);
    let again = init_server(&root, &listen);
    assert!(!again.success(), "restart init replaced the run");
    assert_eq!(manifest_lines(&root), before);
    let limits = Limits {
        total_bytes: 100_000,
        mailbox_bytes: 100_000,
        mailbox_count: 3,
    };
    let increased = Limits {
        total_bytes: 200_000,
        mailbox_bytes: 100_000,
        mailbox_count: 3,
    };
    drop(RelayStore::open(&root, limits).unwrap());
    assert!(RelayStore::open(&root, increased).is_err());
    let raised = std::process::Command::new(relay_binary())
        .args([
            "serve",
            "--root",
            root.to_str().unwrap(),
            "--listen",
            &listen,
            "--total-bytes",
            "200000",
        ])
        .status()
        .unwrap();
    assert!(!raised.success());
    assert_eq!(manifest_lines(&root), before);
}

#[tokio::test]
async fn http_limits_v6_loopback() {
    if included_in_writer_unit_tests() {
        return;
    }
    let scratch = Scratch::new();
    let root = scratch.path().join("run");
    let listen = free_listen("[::1]:0");
    assert!(init_server(&root, &listen).success());
    assert_eq!(manifest_lines(&root)[0], format!("http://{listen}"));
    let mut server = serve_server(&root, &listen);
    let bound = read_bound_line(server.stdout.as_mut().unwrap());
    assert_eq!(bound.trim(), format!("http://{listen}"), "{bound}");
}

#[tokio::test]
async fn http_limits_redaction() {
    if included_in_writer_unit_tests() {
        return;
    }
    let scratch = Scratch::new();
    let root = scratch.path().join("run");
    let listen = free_listen("127.0.0.1:0");
    assert!(init_server(&root, &listen).success());
    let mut server = serve_server(&root, &listen);
    let bound = read_bound_line(server.stdout.as_mut().unwrap());
    let address = bound.trim().trim_start_matches("http://");
    let token = URL_SAFE_NO_PAD.encode([9u8; 32]);
    let mut body = vec![4u8; 1024];
    body[..8].copy_from_slice(b"LOKIRLY1");
    body[8] = 1;
    let hash = hex::encode(Sha256::digest(&body));
    let mailbox = hex::encode([1u8; 32]);
    let request = format!(
        "PUT /v1/mailboxes/{mailbox}/objects/{hash} HTTP/1.1\r\nHost: {address}\r\nAuthorization: Bearer {token}\r\nContent-Type: application/octet-stream\r\nContent-Length: 1024\r\nConnection: close\r\n\r\n"
    );
    let response = std::thread::scope(|scope| {
        let handle = scope.spawn(|| {
            let mut socket = std::net::TcpStream::connect(address).unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(3)))
                .unwrap();
            use std::io::Write;
            socket.write_all(request.as_bytes()).unwrap();
            socket.write_all(&body).unwrap();
            let mut response = Vec::new();
            let _ = std::io::Read::read_to_end(&mut socket, &mut response);
            response
        });
        handle.join().unwrap()
    });
    assert!(!response.is_empty());
    assert!(!response
        .windows(token.len())
        .any(|window| window == token.as_bytes()));
    assert!(!response.windows(8).any(|window| window == b"LOKIRLY1"));
    let _ = std::process::Command::new("kill")
        .args(["-TERM", &server.child.id().to_string()])
        .status();
    let _ = server.child.wait();
    let mut stderr = String::new();
    let mut stdout = String::new();
    use std::io::Read;
    server
        .stderr
        .as_mut()
        .unwrap()
        .read_to_string(&mut stderr)
        .unwrap();
    server
        .stdout
        .as_mut()
        .unwrap()
        .read_to_string(&mut stdout)
        .unwrap();
    let combined = format!("{bound}{stdout}{stderr}");
    assert!(
        !combined.contains(&token),
        "credential reached a log or URL"
    );
    assert!(!combined.contains("LOKIRLY1"), "object body reached a log");
    assert!(
        !stderr.contains("provision"),
        "stderr mentioned provisioning material"
    );
}

fn http_response_complete(response: &[u8]) -> bool {
    let Some(split) = response.windows(4).position(|mark| mark == b"\r\n\r\n") else {
        return false;
    };
    let headers = std::str::from_utf8(&response[..split]).unwrap_or("");
    for line in headers.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.eq_ignore_ascii_case("content-length") {
            let length = value.trim().parse::<usize>().unwrap_or(usize::MAX);
            return response.len() >= split + 4 + length;
        }
    }
    false
}

fn read_http_response(socket: &mut std::net::TcpStream) -> Vec<u8> {
    use std::io::Read;
    let mut response = Vec::new();
    let mut buffer = [0u8; 2048];
    loop {
        if http_response_complete(&response) {
            break;
        }
        match socket.read(&mut buffer) {
            Ok(0) => break,
            Ok(count) => response.extend_from_slice(&buffer[..count]),
            Err(error)
                if error.kind() == std::io::ErrorKind::WouldBlock
                    || error.kind() == std::io::ErrorKind::TimedOut =>
            {
                break;
            }
            Err(error) => panic!("http read failed: {error}"),
        }
    }
    response
}

fn split_http(response: &[u8]) -> (u16, &str, &[u8]) {
    let split = response
        .windows(4)
        .position(|mark| mark == b"\r\n\r\n")
        .expect("http response headers")
        + 4;
    let headers = std::str::from_utf8(&response[..split - 4]).unwrap();
    let status = headers.split_whitespace().nth(1).unwrap().parse().unwrap();
    (status, headers, &response[split..])
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_limits_slow_fresh_body_reserves_read_and_duplicate() {
    use std::io::Write;
    let fixture = HttpFixture::new(100_000).await;
    let duplicate = object(9);
    let saved = fixture
        .db
        .put([1; 32], duplicate.clone(), Capability::new([3; 32]))
        .unwrap()
        .receive()
        .await
        .unwrap();
    assert!(saved.created);
    let receipt = saved.receipt.clone();
    let wire = duplicate.wire.clone();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let app = fixture.app.clone();
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = stopped.await;
            })
            .await
            .unwrap();
    });
    let append = URL_SAFE_NO_PAD.encode([3u8; 32]);
    let read = URL_SAFE_NO_PAD.encode([2u8; 32]);
    tokio::task::spawn_blocking(move || {
        let mut holders = Vec::new();
        for tag in 0..30u8 {
            let obj = object(20u8.wrapping_add(tag));
            let mut socket = std::net::TcpStream::connect(address).unwrap();
            socket
                .set_write_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            socket.set_nodelay(true).unwrap();
            write!(
                socket,
                "PUT {} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {append}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                object_uri(&obj),
                obj.wire.len()
            )
            .unwrap();
            socket.write_all(&obj.wire[..1]).unwrap();
            socket.flush().unwrap();
            holders.push(socket);
        }
        std::thread::sleep(std::time::Duration::from_millis(200));
        for tag in [80u8, 81] {
            let obj = object(tag);
            let mut socket = std::net::TcpStream::connect(address).unwrap();
            socket
                .set_read_timeout(Some(std::time::Duration::from_secs(1)))
                .unwrap();
            socket
                .set_write_timeout(Some(std::time::Duration::from_secs(2)))
                .unwrap();
            write!(
                socket,
                "PUT {} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {append}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                object_uri(&obj),
                obj.wire.len()
            )
            .unwrap();
            socket.write_all(&obj.wire[..1]).unwrap();
            socket.flush().unwrap();
            let response = read_http_response(&mut socket);
            let (status, headers, body) = split_http(&response);
            assert_eq!(status, 429, "slow fresh body occupied a reserved slot: {headers}");
            assert!(
                headers.lines().any(|line| {
                    line.to_ascii_lowercase().starts_with("retry-after:")
                        && line.split_once(':').unwrap().1.trim().bytes().all(|b| b.is_ascii_digit())
                }),
                "slow fresh refusal missing integer Retry-After: {headers}"
            );
            assert_eq!(body, [0x82, 1, 8]);
        }
        let mut control = std::net::TcpStream::connect(address).unwrap();
        control
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        write!(
            control,
            "PUT /v1/mailboxes/{} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {append}\r\nContent-Type: application/cbor\r\nContent-Length: 512\r\nConnection: close\r\n\r\n",
            hex::encode([1u8; 32])
        )
        .unwrap();
        control.write_all(b"{").unwrap();
        control.flush().unwrap();
        let response = read_http_response(&mut control);
        let (status, headers, body) = split_http(&response);
        assert_eq!(status, 429, "control write occupied a reserved slot: {headers}");
        assert_eq!(body, [0x82, 1, 8]);
        let mut get = std::net::TcpStream::connect(address).unwrap();
        get.set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .unwrap();
        write!(
            get,
            "GET {} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {read}\r\nConnection: close\r\n\r\n",
            object_uri(&duplicate)
        )
        .unwrap();
        let response = read_http_response(&mut get);
        let (status, headers, body) = split_http(&response);
        assert_eq!((status, body), (200, wire.as_slice()), "{headers}");
        let mut put = std::net::TcpStream::connect(address).unwrap();
        put.set_read_timeout(Some(std::time::Duration::from_secs(3)))
            .unwrap();
        write!(
            put,
            "PUT {} HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer {append}\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            object_uri(&duplicate),
            duplicate.wire.len()
        )
        .unwrap();
        put.write_all(&duplicate.wire).unwrap();
        let response = read_http_response(&mut put);
        let (status, headers, body) = split_http(&response);
        assert_eq!((status, body), (200, receipt.as_slice()), "{headers}");
        for mut socket in holders {
            socket.set_nonblocking(true).unwrap();
            let mut buffer = [0u8; 64];
            match std::io::Read::read(&mut socket, &mut buffer) {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                other => panic!("slow fresh body did not keep its slot: {other:?}"),
            }
        }
    })
    .await
    .expect("slow-body reservation proof");
    stop.send(()).unwrap();
    server.await.unwrap();
    fixture.owner.shutdown().await.unwrap();
}

#[tokio::test]
async fn http_limits_zero_port_refused() {
    if included_in_writer_unit_tests() {
        return;
    }
    let scratch = Scratch::new();
    let root = scratch.path().join("run");
    assert!(
        !init_server(&root, "127.0.0.1:0").success(),
        "init persisted a zero port"
    );
    assert!(
        !root.join("receipt.seed").exists(),
        "zero-port init wrote the root"
    );
    assert!(!root.join("manifest").exists());
    assert!(
        !init_server(&root, "[::1]:0").success(),
        "init persisted an IPv6 zero port"
    );
    assert!(!root.join("receipt.seed").exists());
    let listen = free_listen("127.0.0.1:0");
    assert!(init_server(&root, &listen).success());
    let lines = manifest_lines(&root);
    assert_eq!(lines[0], format!("http://{listen}"));
    for zero in ["127.0.0.1:0", "[::1]:0"] {
        let status = std::process::Command::new(relay_binary())
            .args(["serve", "--root", root.to_str().unwrap(), "--listen", zero])
            .status()
            .unwrap();
        assert!(!status.success(), "serve accepted {zero}");
        assert_eq!(manifest_lines(&root), lines);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_limits_control_uses_fresh_lane() {
    let saturation = saturate_fresh_puts().await;
    assert_eq!(
        saturation.admitted, 62,
        "control lane shared the reserved queue slots"
    );
    let mailbox = [1u8; 32];
    assert!(
        matches!(
            saturation
                .fixture
                .db
                .create(mailbox, creation(), Capability::new([8; 32])),
            Err(RelayError::RateLimit)
        ),
        "create used a reserved writer slot"
    );
    assert!(
        matches!(
            saturation
                .fixture
                .db
                .rotate(mailbox, update(), Capability::new([4; 32])),
            Err(RelayError::RateLimit)
        ),
        "rotate used a reserved writer slot"
    );
    saturation
        .fixture
        .db
        .get(mailbox, saturation.duplicate.hash, Capability::new([2; 32]))
        .expect("read lost its reserved queue slot to control");
    finish_saturation(saturation).await;
}

#[tokio::test]
async fn http_limits_manifest_listen_mismatch() {
    if included_in_writer_unit_tests() {
        return;
    }
    let scratch = Scratch::new();
    let root = scratch.path().join("run");
    let manifest_listen = free_listen("127.0.0.1:0");
    let serve_listen = free_listen("127.0.0.1:0");
    assert_ne!(manifest_listen, serve_listen, "listen ports collided");
    assert!(init_server(&root, &manifest_listen).success());
    let lines = manifest_lines(&root);
    assert_eq!(lines[0], format!("http://{manifest_listen}"));
    let mut server = serve_server(&root, &serve_listen);
    let started = std::time::Instant::now();
    let status = loop {
        match server.child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {
                if started.elapsed() > std::time::Duration::from_secs(2) {
                    let _ = server.child.kill();
                    let _ = server.child.wait();
                    panic!("serve stayed up for a different loopback port");
                }
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(error) => panic!("serve wait failed: {error}"),
        }
    };
    assert!(
        !status.success(),
        "serve accepted a manifest listen mismatch"
    );
    let mut stderr = String::new();
    std::io::Read::read_to_string(server.stderr.as_mut().unwrap(), &mut stderr).unwrap();
    assert!(
        stderr.contains("relay_error_1"),
        "manifest mismatch was not malformed: {stderr}"
    );
    assert_eq!(manifest_lines(&root), lines);
    drop(server);
}

#[tokio::test]
async fn hosted_public_origin_is_immutable_and_independent_of_private_listen() {
    if included_in_writer_unit_tests() { return; }
    let scratch = Scratch::new();
    std::fs::create_dir_all(scratch.path()).unwrap();
    let root = scratch.path().join("hosted");
    let provision = write_provision(scratch.path());
    let listen = free_listen("127.0.0.1:0");
    assert!(std::process::Command::new(relay_binary()).args([
        "init", "--root", root.to_str().unwrap(), "--provision-capability-file", provision.to_str().unwrap(),
        "--total-bytes", "100000", "--mailbox-bytes", "100000", "--mailbox-count", "3",
        "--listen", &listen, "--public-origin", "https://relay.example:443",
    ]).status().unwrap().success());
    let before = manifest_lines(&root);
    assert_eq!(before[0], "https://relay.example:443");
    let mut server = serve_server(&root, &listen);
    assert_eq!(read_bound_line(server.stdout.as_mut().unwrap()).trim(), format!("http://{listen}"));
    let response = std::thread::spawn(move || {
        use std::io::{Read, Write};
        let mut stream = std::net::TcpStream::connect(&listen).unwrap();
        stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
        stream.write_all(format!("GET /v1/identity HTTP/1.1\r\nHost: attacker.example\r\nX-Forwarded-Host: attacker.example\r\nx-loki-challenge: {}\r\nConnection: close\r\n\r\n", "11".repeat(32)).as_bytes()).unwrap();
        let mut raw = Vec::new(); stream.read_to_end(&mut raw).unwrap(); raw
    }).join().unwrap();
    assert!(response.windows(b"https://relay.example:443".len()).any(|b| b == b"https://relay.example:443"));
    assert!(!response.windows(b"attacker.example".len()).any(|b| b == b"attacker.example"));
    drop(server);
    assert_eq!(manifest_lines(&root), before);
}

#[test]
fn hosted_origin_validation_rejects_credential_and_path_substitution() {
    for raw in ["http://relay.example", "https://u:p@relay.example", "https://relay.example?", "https://relay.example#", "https://relay.example/path", "https://relay.example/..", "https://relay.example//", "https://relay.example:0", "https://relay.example:65536", "https://relay.example\\", "https://relay.example\n", "https:///relay.example"] {
        assert!(loki_relay_server::validate_public_origin(raw).is_err(), "{raw}");
    }
    for raw in ["https://relay.example", "https://relay.example:443/", "https://[::1]:8443"] {
        assert!(loki_relay_server::validate_public_origin(raw).is_ok(), "{raw}");
    }
}
