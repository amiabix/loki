# Retiring the bespoke relay stack (C17)

The product routes DKG and signing through ZF `frostd` (`poc/src/transport.rs`). The
bespoke relay (`communication/`) and its PoC adapters stay behind the off-by-default
`relay-communication` feature (`poc/Cargo.toml` `[features]`).

## Done in this change

- `pub mod host` (the native member HTTP API) is no longer feature-gated (`poc/src/lib.rs`);
  `axum` is a normal dependency and `loki_member_app` builds with a plain
  `cargo build --bin loki_member_app`. Building with `--features relay-communication` still works.
- The one host file that uses the relay crates, `host/nonce_witness.rs` (relay-mailbox nonce
  witnesses), is gated with the relay stack (`poc/src/host/mod.rs`).
- `examples/provision_nonce_witnesses.rs` gets `required-features = ["relay-communication"]`.
  Without it, a default `cargo test --locked` on main fails to compile that example.

## What still depends on `communication/` (`loki-relay-client` / `loki-relay-protocol`)

Everything below compiles only with `relay-communication`:

| Item | Product use today |
|---|---|
| `poc/src/relay_member/`, `bin/loki_relay_member.rs` | none (legacy relay member) |
| `poc/src/setup_relay.rs`, `setup_relay/`, `setup_relay_tests.rs`, `setup_backup.rs`, `setup_retry.rs` | none (legacy hosted setup) |
| `poc/src/member_service.rs`, `bin/loki_member_service.rs` | none (legacy stdin/stdout service) |
| `poc/src/setup_ceremony/admission_checkpoint.rs`, `AcceptedCeremonyRoster::from_transport` (`setup_ceremony/mod.rs`) | only called by `setup_relay` |
| `poc/src/host/nonce_witness.rs` (`RelayWitness`, `WitnessConfig`) | none: `RelayWitness::open` is called only by its own tests; `Config.nonce_witnesses` is parsed (`host/mod.rs`) and never read |
| `bin/loki_setup_member.rs` relay commands, `bin/loki_member_payment.rs` `TwoRelays` | legacy CLI paths |
| `examples/hosted_ops.rs`, `examples/provision_nonce_witnesses.rs` | test fixtures / provisioning for the above |
| `tests/relay_member.rs`, `setup_relay.rs`, `setup_handoff.rs`, `setup_hosted_resume.rs`, `tests/support/hosted_services.rs` | tests of the above |
| `communication/deploy/*.sh`, `communication/harness/*.py` | scripts; `bringup.sh` starts `loki-relay-server` |

Also dead in every build: `Config.operator_bundle` / `operator_key` /
`enrollment_issuer` / `transport` are parsed in `host/mod.rs` but only `None`/`"local"` is
ever constructed in tests; no host code reads them (`grep -E "\.(transport|operator_key|enrollment_issuer|operator_bundle|nonce_witnesses)\b" src/host` finds no reads).

## Removal plan (not done today)

1. Confirm no live deployment uses the relay stack. The omarchy relay (`loki-relay-server`
   on :39201-3) and any `communication/deploy` users must be retired first; this change does
   not touch them.
2. Delete `host/nonce_witness.rs`, the `WitnessConfig` re-export, `--nonce-witnesses`, and
   `examples/provision_nonce_witnesses.rs`; drop the unused `Config` fields above (touches
   host test fixtures in `ceremony.rs`, `payment.rs`, `repair_tests.rs`, `state.rs` — coordinate
   with the host owner).
3. Delete the modules, bins, examples and tests in the table, the `relay-communication` and
   `setup-fault-injection` features, and the `loki-relay-*` optional dependencies.
4. Remove the gated items in `setup_ceremony/mod.rs` and `engine.rs`, and the
   `#[cfg(feature = "relay-communication")]` branches in `loki_setup_member.rs` and
   `loki_member_payment.rs`.
5. Delete `communication/` (its own workspace) and the `vendor/relay-source-isolation*.json`
   manifests; update `communication/deploy` users, `web/wallet/README.md` and
   `poc/signer-app/build.sh` (both still pass `--features relay-communication`, which is no
   longer needed for the host).
6. Verify: `cargo test --locked` in `poc/`, `cargo test --locked -p loki-signer-core`, and
   `cargo build --locked --all-targets`.
