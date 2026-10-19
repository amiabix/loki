# Senior clean pass — refactor notes

Scope: the code we own on the keyless-coordinator / isolated-signer line
(`signer/*`, `coordinator_boundary.rs`, `transport.rs`, `setup_ceremony/*`,
`distributed_setup.rs`, the bins). Behavior-preserving only — the proof is the
full suite staying at **174 passed / 0 failed** before and after, with both the
default `cargo build` and `cargo build --features relay-communication` now
**warning-clean** (baseline: 5 lib warnings).

## Removed / fixed

- **`distributed_setup.rs`** — deleted `Completed::members()`. Dead getter, zero
  callers anywhere (the `members` field stays; it is still read by
  `Completed::checkpoint`). This was 1 of the default-build warnings.
- **`signer/wysiwys.rs`** — dropped a needless `mut` on the `run` closure in
  `sighash_of_pczt` (it captures by shared ref and is called once; unlike the
  sibling closure in `render_payment`, which mutates captures and keeps `mut`).

## Gated instead of deleted (live under `relay-communication`, dead in the default build)

The default `cargo build` does not compile `setup_relay` (it is
`#[cfg(feature = "relay-communication")]` in `lib.rs`), so the methods only the
hosted setup driver reaches showed up as dead code. They are real code under the
feature, so they are gated, not removed:

- `setup_ceremony/engine.rs` — `certified_group_key`, `begin_activation`,
  `activation_marker` → `#[cfg(feature = "relay-communication")]`
  (only callers live in `setup_relay` / `setup_relay/*`).
- `setup_ceremony/engine.rs` — `saved_phase`, `abort_saved_checkpoint` and
  `setup_ceremony/mod.rs` — `hosted_context_digest` →
  `#[cfg(any(feature = "relay-communication", test))]`. These have gated callers
  **and** `#[cfg(test)]` callers that run in the default `cargo test`, so the
  `test` arm keeps them available for the suite.
- `setup_ceremony/mod.rs` — the `TESTNET_NU7_BIRTH` import is now gated to match
  its only use (`from_transport`, feature-only), clearing the unused-import warning.

## Flagged, left as-is (out of scope: legacy / not ours to rewrite)

- **`src/bin/loki.rs` — the G1-TX fixed-key research harness** (guarded by
  `LOKI_ALLOW_FIXED_VIEWING_KEY`; header: "the point of the exercise is …").
  The PCZT prove→finalize→extract sequence is **duplicated inside this file**:
  inline at ~`1638–1695` and again as `prove_and_extract` at ~`2136–2211`, each
  with its own `println!` progress logging and `label`/`name` error strings.
  This is legacy harness code we did not touch; per the surgical rule it is
  flagged, not refactored. The clean product version of the same sequence lives
  once in `src/bin/loki_member_payment.rs::prove` (~`932–978`) — no logging,
  strict error text, pre-built witnesses. Merging the legacy copies into the
  product helper would drag the harness's logging/error contract into product
  crypto and risk behavior drift, so it is deliberately left alone.
- **`relay_member/config.rs` (~129 KB)** and **`setup_relay.rs` (~4 kLOC)** —
  large bespoke relay-stack modules marked `RETIRING (WS3/WS4)` in `lib.rs`
  (superseded by the `frostd` `transport` seam). Not cleaned: they are on the
  deprecation path and rewriting them now is churn against code slated for
  removal.
- **`vendor/` (zakura-*, bip32)** — vendored upstream crypto crates; untouched.

## Checked, already clean (no action)

- `coordinator_boundary.rs` — a prior pass already collapsed the duplicate
  `SignerClient` trait into the single `signer::Signer` seam; load-bearing
  keyless-invariant doc comments and the source deny-list test are intentional.
- `transport.rs` — the per-method `base/client/token` triples are trivial field
  reads needed by each `block_on` closure; wrapping them would add indirection,
  not remove duplication.
- No meaningful shared-helper duplication between `loki_member_payment.rs` and
  `loki_relay_member.rs` (only `main`/`runtime`, which are legitimately per-bin).
