# feat(communication): durable encrypted offline relay

Run three independent local relay stores with per-member inboxes. The relay stores opaque HPKE ciphertext and returns signed storage receipts; clients authenticate certified senders, assemble chunked messages, retry saved bytes, and return Received acknowledgements after local persistence. The optional PoC adapter provides the member CLI. This is a communication harness for a fixed three-member roster.

The native harness certifies Alice, Bob and Carol through the existing file setup, provisions nine independent inboxes, and distributes six signed, recipient-encrypted descriptors. Alice saves separately encrypted copies for all three members before any upload. Whole-vault Stored requires the same two distinct pinned relay identities to acknowledge every object of all three copies. Received is a separate authenticated observation.

The real acceptance run on 2026-10-10 delivered 64-byte and 65,537-byte payloads with Bob and Carol offline during publication. After Alice's commands exited, both recipients authenticated their own copies. Alice later reconciled two self records without a self acknowledgement and retrieved four Received messages. Ciphertext, sequences and saved receipt digests remained identical through relay restart. The public evidence is retained at `/private/tmp/loki-relay-acceptance-20261010-a/acceptance-report.json`.

## build(communication): pinned native workspace

`protocol`, `relay` and `client` form a separate Rust workspace. The optional PoC feature `relay-communication` provides the certified member adapter and `loki_relay_member`. The relay's normal/build graph excludes the client, HPKE, Zcash, Zakura and FROST. The client's test-only dependency on the server exercises a real opaque store carrying a forged inner sender.

The selected toolchain is rustc 1.98.0 / Cargo 1.98.0 on native macOS. Communication declares Rust 1.89; the resolved native graph's highest declared floor is 1.89. The PoC's Zakura packages declare 1.91. These are declared dependency floors, not builds using the minimum compiler. Other targets were not verified.

HPKE is exactly 0.14.1 with default features disabled and `alloc,getrandom,x25519,chacha`. The fixed suite is RFC 9180 base mode, X25519/HKDF-SHA256/ChaCha20Poly1305. Sender setup returns the encapsulation before header-derived AAD is constructed; one padded record is sealed and the context discarded. Message and configuration signing/encryption domains are distinct.

Other direct pins are Axum 0.8.6, Tokio 1.53.2, Tower 0.5.2, rusqlite 0.37.0 with bundled SQLite, reqwest 0.13.5 without default features, ciborium/ciborium-ll 0.2.2, sha2 0.10.9, ed25519-dalek 2.2.0, base64 0.22.1, hex 0.4.3, getrandom 0.4.3, subtle 2.6.1 and zeroize 1.8.2. Both lockfiles retain the previously verified package versions. `poc/scripts/verify_relay_source_isolation.py` verifies cached published archive bytes, vendor files, manifest redirects and both exact resolved graphs, including only the new client dev edge to the server. Existing Zakura/FROST pins remain unchanged.

## test(communication): verification

The final workspace gate passed 1,031 checks, including 34 compile-fail doctests; eight ignored helper entry points are invoked by their parent tests where applicable. The PoC gate passed 69 checks across `relay_member`, `setup_transport`, `setup_processes` and `distributed_setup`. The Python harness suite passed 35 checks. The dependency graph test and source-isolation verifier passed. See the [harness instructions](harness/README.md) for fault classifications and retained evidence.

```sh
cargo test --manifest-path communication/Cargo.toml --workspace --locked --offline
cargo test --manifest-path poc/Cargo.toml --features relay-communication --locked --offline --test relay_member --test setup_transport --test setup_processes --test distributed_setup
python3 -m unittest discover -s poc/tests -p test_dependency_graph.py
python3 -m unittest discover -s communication/harness -p test_run.py
python3 poc/scripts/verify_relay_source_isolation.py
cargo build --manifest-path communication/Cargo.toml --locked --offline -p loki-relay-server
cargo build --manifest-path poc/Cargo.toml --locked --offline --features relay-communication --bin loki_relay_member --bin loki_setup_member
python3 communication/harness/run.py acceptance --run-root /private/tmp/loki-relay-acceptance-new --ports 39101 39102 39103
python3 communication/harness/run.py faults --run-root /private/tmp/loki-relay-faults-new --ports 39111 39112 39113
```

Build before running the harness; choose new run directories and free ports for each run. Reports are saved under those directories and all owned processes stop when the command exits. Data remains until explicit deletion using the run ID. See [harness instructions](harness/README.md) for selected scenarios and deletion, and [Ponytail review](REVIEW.md) for the cleanup and follow-up boundary.

## docs(communication): scope and durability limits

Production endpoints use bounded loopback HTTP with no redirects, proxy use, push or SSE. Capabilities are kept in sealed member configuration; shared descriptors omit read and administration capabilities. Persistent transport payloads remain encrypted. Public reports contain identities, hashes, lengths, counts and state, with secret values and plaintext excluded.

SQLite uses WAL, synchronous FULL and exclusive owned-root locks. Accepted objects and first-write nonce claims have no automatic expiry or eviction. The nonce claim requires the inbox owner's private read capability; peers' shared append capabilities cannot preclaim it. A signed response binds a fresh challenge, the exact encrypted record hash and whether this was the first write. The regtest signer requires fresh receipts from two relay identities pinned in its sealed nonce record. Crash fixtures prove intact-store recovery at tested process boundaries. They do not establish physical power-loss durability, browser/WASM durability, independent operators or malicious-relay retention. Wallet custody remains a separate gate.
