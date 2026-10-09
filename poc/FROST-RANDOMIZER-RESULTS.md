# test(signing): persisted randomizer seed validation

Issue [#3](https://github.com/amiabix/loki-zcash-frost/issues/3), 9 October 2026.
Published as [PR #6](https://github.com/amiabix/loki-zcash-frost/pull/6), targeting main; no merge was performed.
Herdr execution used only `/private/tmp/loki-frost-randomizer-seeds` on
`refactor/frost-randomizer-seeds`. Final base is fetched main
`754445a445efdea1adf6be378ca2dd2a453b61dc`; PR #2's THS migration, experimental
ZIP 2005 fixtures, checked-backup gate, Cargo graph and vendor patches are preserved.
The original dirty checkout and issue #4 instance were not modified.

## test(signing): local checks

| Check | Outcome | Audit log under `/private/tmp/loki-issue3-evidence/` |
| --- | --- | --- |
| `cargo build` | Pass | `validated-build.log` |
| Full default `cargo test` after final rebase | Pass: 76 tests (54 library, 13 CLI, 9 integration) | `validated-cargo-test.log` |
| `cargo clippy --all-targets` after final rebase | Pass, no diagnostics | `validated-clippy.log` |
| `cargo fmt --check` | Fails on inherited formatting in `rpc.rs`, `scan.rs`, `scanstate.rs`, `vault.rs`, `verify.rs` | `validated-fmt.log` |
| Scoped `rustfmt --check` on all changed Rust files | Pass | `validated-scoped-fmt.log` |
| Python THS adapter tests | 9 pass | `ths-python-tests.log` |
| AB/AC/BC independent two-input finishing | Pass; all three aggregate, prove and extract after approver/source files are removed; final sighash, both real nullifiers and fee checked | `all-pair-independent-finish.log` |

The supplied e66f97c baseline passed 64 tests and warning-free Clippy; its formatting
check already failed on 12 files. Both original logs are retained as `baseline-fmt.log`
and `baseline-clippy.log`. Changed Rust files were formatted; no vendor formatting was
performed. `probe-zip2005` intentionally fails compilation and was excluded.

Focused regressions reject missing, malformed, wrong-version, swapped and incorrectly
associated records, changed seeds/commitments against fixed candidates, seedless legacy
sessions, altered alpha and mismatched vault packages. Failures in Alice's final AC
spend leave all AB/AC shares absent and nonces byte-identical. A missing later nonce also
emits no partial batch. Surplus or noncanonical-index seed records are refused before
share output, loading or replica creation, covering mixed saved batches. Ordinary reproposal refuses without changing saved bytes; a
nonempty replica destination is refused with every earlier artifact unchanged.

## test(regtest): dedicated THS evidence

The controller prepared and owns `loki-frost-issue3`; harnesses never start, stop or
reset THS. Discovered endpoints: RPC `127.0.0.1:18312`, dashboard `127.0.0.1:32885`,
lightwalletd `127.0.0.1:9147`, P2P `127.0.0.1:18313`. NU6.3 branch `37a5165b` was active.
Endpoint/status and runtime ownership/bindings are recorded in `ths-endpoints.json`,
`ths-status.json` and `ths-runtime-identity.log` in the audit directory.

Selected images were app `0.3.0` (`0353489e…`), `zakuracore/zakura:1.6.0`
(`bf53c178…`) and lightwalletd `0.3.0` (`9022dd9a…`); the identity log records full
SHA-256 IDs and matching instance labels. No THS source or image edits were required.

All live commands ran from `poc/` with:

```sh
export TMPDIR=/private/tmp
export LOKI_THS_INSTANCE=loki-frost-issue3
export CARGO_TARGET_DIR=/private/tmp/loki-frost-randomizer-seeds/poc/target
LOKI_STATE=/private/tmp/loki-issue3-regtest-validated ./run-regtest.sh
LOKI_STATE=/private/tmp/loki-issue3-second-device-validated ./run-second-device.sh
LOKI_STATE=/private/tmp/loki-issue3-tamper-validated ./tamper-tests.sh
LOKI_STATE=/private/tmp/loki-issue3-rollback-validated \
  LOKI_BIN=/private/tmp/loki-frost-randomizer-seeds/poc/target/debug/loki \
  ./nonce-reuse-drill.sh --setup
```

These state paths must be absent before a new run. Shell scratch paths use
`${TMPDIR:-/tmp}` and remain portable. Source-built Loki was used throughout;
build identity is recorded in `final-artifact-identity.log`.

| Harness | Actual outcome | Log |
| --- | --- | --- |
| Regtest | AC mined at height 131 with 3 confirmations; recipient, memo, amount, change, fee and input verified; installation preserved sighash | `regtest-validated.log` |
| Second device | Four AC payments mined and effects verified; paths A/B, each with one and two inputs; approver state moved out of reach | `second-device-validated.log` |
| Tamper, stable rerun | 19 passed, 0 failed, 1 known fee-only fixture unconstructible; all eight seed cases refuse in final AC input with zero AB/AC shares and unchanged nonces | `tamper-validated.log` |
| Nonce rollback | Stage A refuses changed commitments against the fixed saved candidate, zero shares and unchanged nonces; Stage B restores consumed nonce/session, then a tamper-only consistent rebuild produces a different share with that same nonce | `rollback-validated.log` |

Regtest txid:
`2d0094db430bbc016378fbd5aa355bbc371f5287d41a67d066731e81eb021b7a`.

| Second-device payment | Inputs | Path | Mined txid |
| --- | --- | --- | --- |
| p1 | 1 | A, posted final | `3157a8af4e2d47f31037fb6faacca8c44bd39340870e340c34df87012d5fc75f` |
| p2 | 1 | B, re-proving | `5a26292911703a2e28b826f759263041016f970a228e349a8d457951c32b9881` |
| p3 | 2 | B, re-proving | `53e51e1d6d6b3e0fb5fe337382adebe1d9838755d95e52ac4c5ba7fb7f5e706e` |
| p4 | 2 | A, posted final | `9f36486deb6f242a5edaa1d1a4b9733bd3647425e0d6857ebc2f6d47d6526944` |

The second-device log also checks candidate/seed byte preservation across separate
review processes and refused reproposal, fresh seeds across all pairs/spends/rounds,
0700 replica directories/0600 seed files, and local missing/swapped-seed refusals for
every path/input count. Five existing bad-replica/final/double-spend checks remain.

The first tamper attempt overlapped a rebase and failed Cargo compilation (14 passed,
5 failed, 1 unconstructible). Its `tamper.log` is retained as invalid evidence; only
the complete stable rerun is accepted. All four final live harnesses were rerun on the stable final source after the surplus-record guard. Each exited zero. `live-validated-status.json` records commands, fresh state paths, exit codes and elapsed times (regtest 73.64s, second device 291.62s, tamper 42.31s, rollback 5.51s). Earlier successful runs and the invalid first attempt remain available for audit. The final full Rust suite also covers main's preserved ZIP 2005 and separate-member transaction-signing fixtures.

## docs(signing): boundaries

The recommended library generator removes the custom seed assumption. It does not
prove honest coordinator randomness, repair nonce reuse, prevent profile rollback,
supply a security proof or extend NCC's published audit to rerandomized FROST.
Stage B measures that limitation, rather than claiming rollback prevention.

Seeds need confidential transport. Local directories/files are protected on Unix;
this prototype implements no authenticated encrypted relay and is regtest-only.
Share writes and nonce deletion remain non-atomic plain-file operations. Live CLI
finishing remains AC; all three pairs finish offline. Fee-only tampering cannot build
an unbalanced candidate; the fee refusal arm remains unexercised by that fixture.
The legacy payment CLI uses its documented test-only vault splice; main's experimental
separate-member ZIP 2005 path and checked-backup activation are preserved.
