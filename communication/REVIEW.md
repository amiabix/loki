# refactor(relay): Ponytail implementation review

Reviewed the relay implementation added by `553ae1b`, then integrated `main` at `9284d04`. The pass traced production callers, searched for unused APIs, compared duplicated logic, and checked the cleanup independently. It is a targeted redundancy review, not a cryptographic audit.

## refactor(relay): applied findings

- `client/src/store.rs`: delete unused `recover_transfer_groups`, `TransferGroupView`, `recover_actionable_received`, and `recover_actionable_dependencies`. Inline the remaining full-history queries and remove their unused phase-filter argument. Preserve phase derivation, recovery tables, and capacity accounting.
- `client/src/http.rs`: reuse bearer construction, media validation, and bounded response collection. Preserve overflow error classification, encoding rejection, stream limits, and mutation guard markers. Provisioning responses now also use the shared declared-length consistency check.
- `poc/src/bin/loki_relay_member.rs`: replace three pagination loops with one collector. Preserve the 400-row diagnostic cap and rejection of invalid or stalled cursors; add tests at 399/400/401 rows and invalid/stalled IDs.
- `harness/run.py`: delete `_retry_identity`; it had no callers in the harness or tests.

Net: 133 production lines removed. No dependencies, schema, protocol version, encrypted object format, or storage completion criteria changed. The removed public APIs belong to the new unpublished client crate; no repository consumers use them.

## docs(relay): retained complexity and follow-up

Keep trust-boundary validation, durable journals, staged-transfer recovery, exclusive root locks, receipt verification, and fault fixtures. These enforce the communication contract. Keep the adapter's roster loader: directly using `member_state::Roster::load` would lose bounded reads and depth checks.

If roster validation changes again, extract a pure parsed-value validator and fingerprint shared by both loaders; retain each loader's read bounds and secret wiping, and verify malformed/deep/oversized inputs in both entry points. This is deferred because the current small duplication does not justify changing the existing wallet API.

Clippy completed on Rust 1.98 with existing style/arity/enum-size and test-helper warnings. A strict `-D warnings` run fails on those baseline warnings. They are not evidence of unused production paths and were not suppressed or expanded into unrelated refactors.

The 2026-10-10 verification artifacts describe the original implementation. Use the commands in [README.md](README.md) to verify this revision; the PR records fresh results and harness evidence. Local restart and SIGKILL tests do not prove physical power-loss durability, malicious-relay retention, or separate operators. Payment approval/signing, nonce-consumption safety, chain actions, public deployment, browser/WASM, membership changes, and read/admin credential recovery remain outside this harness.

## test(relay): fresh verification

After main integration and cleanup, 1,031 communication checks, 180 PoC checks (including the two pagination tests), 35 Python harness tests, and the dependency/source-isolation checks passed. The real acceptance passed all eight checks; the fault campaign passed all 17 scenarios and 26 coverage rows. Both owned runs stopped and retained their data. The [verification summary](harness/review-verification-2026-10-10.json) records commands, source/log/report hashes, and the limits of those observations.
