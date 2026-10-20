# Rust product harness — design (finalized after council review)

Status: finalized for implementation. Target: the **frostd/host product** (`frostd` +
`loki_member_app` + `web/wallet`). The old `communication/` relay and its Python harness retire
together, gated (see §10). This revision incorporates a three-lens adversarial review (security,
performance, completeness); the material corrections are called out as **[council]**.

## 1. Goal & non-goals

**Goal.** One fast, deterministic, CI-able Rust harness that exercises the shipped product
end-to-end — account → vault DKG → funding → multi-party payment → confirmed, plus restart
durability and fault cases — and replaces the 13-file Python harness (`communication/harness/`)
and the ad-hoc bash drivers (`omarchy_demo.sh`; the test logic in `deploy_demo.sh`).

**Why now.** The Python harness tests the retiring `communication/` relay, not the product, and is
a sloth: fixed sleep-polling (`native_hosted.py:62` `sleep(.15)`×100–500 = 15–75s DKG;
`testnet_hosted_payment.py:76` `sleep(30)`; 12-iteration loops `run.py:1417/1439/1461`; 25s tunnel
`acceptance_resume.py:167`), sequential startup, 300s blanket timeouts (`run.py:172`), SSH latency,
per-step Python startup.

**Non-goals.** Not a benchmark; not a replacement for unit tests; not a deploy tool
(`deploy_demo.sh` stays as the operator deploy). No macOS-sandbox isolation proofs.

## 2. What it replaces / retires (gated — see §10)

| Retired | Replaced by |
|---|---|
| `communication/harness/*.py` (13) + `poc/ths.py` | this harness |
| `tests/support/hosted_services.rs` (relay+admission) | `harness::services` (frostd/lwd/node/THS) |
| `omarchy_demo.sh` | Tier-2 scenario `ceremony_fund_pay_confirm` |

Modular Rust tests (`payment_over_frostd`, `frostd_transport`, `sign_driver`, `keyless_loop`) stay;
their shared setup folds into Tier-1 primitives.

## 3. Architecture

`poc/harness/` — **a workspace member of the `poc` package tree so `CARGO_BIN_EXE_loki_member_app`
resolves** [council: a separate crate would NOT get that env var; alternatively accept
`$LOKI_MEMBER_APP`]. Used two ways: a library of tiered scenarios that `#[test]`s call, and a thin
`loki-harness` bin for operators/CI. **Do not force `--release`** — workspace deps already build at
opt-level 3 (`poc/Cargo.toml`); report compile time separately from scenario time. [council]

```
poc/harness/
  src/
    wait.rs      // readiness: immediate first check, then tight fixed poll (local) / backoff (remote); deadline-bounded
    proc.rs      // OwnedProcess: spawn into its own process GROUP, capture+REDACT logs, kill-group on drop
    services.rs  // ServiceTopology: connect/own frostd, lightwalletd, regtest node, THS + chain-identity guard
    member.rs    // MemberApp: spawn loki_member_app + typed client over all 21 /api routes
    vault.rs     // Tier-1 in-process driver (signer primitives only — NOT the product flow)
    chain.rs     // regtest: generate(n) in ONE rpc call, confirmations(txid), fund(addr); fail-closed network guard
    scenario/    // ceremony, payment, restart, faults, isolation, account (see §8 matrix)
    secret.rs    // SecretString: in-memory only, Debug-redacted, never logged/written
  bin/loki-harness.rs
  tests/         // #[test] entrypoints per tier
```

## 4. Tiers — and exactly what each proves

| Tier | Scope | Services | When | Gate role |
|---|---|---|---|---|
| **1 — in-process** | signer **primitives only**: v2 DKG (full, not dealer-dealt) + signing + faults via `signer::coordination` over an in-memory relay | none | every `cargo test` | NOT a product gate [council] |
| **2 — real frostd + local regtest** | the **product**: N `loki_member_app` processes over real `frostd`, through the axum `/api` host flow, ceremony→fund→payment→**confirmed** | frostd, lightwalletd, regtest node, THS | CI job w/ services + local/omarchy | **the required product gate** |
| **3 — testnet / separate-host** | real testnet; optional multi-host | testnet lwd/node/faucet; SSH | opt-in / nightly | — |

**[council] Tier 1 is a true test only of the library primitives** — `signer::coordination` stops at
a signed PCZT (`coordination.rs:21`) and bypasses host draft/persist/approve/prove/broadcast
(`host/payment.rs:528,795`). It can pass while the product is broken. Tier 1 must include a **full
v2 DKG-then-sign** path (not the dealer-dealt `keyless_loop` shortcut, `coordination.rs:320`) to be
a real baseline, but the product correctness gate is Tier 2.

**[council] `MemoryTransport` in `payment_over_frostd.rs:44` drops all messages** — Tier 1 needs a
real in-memory relay with queues keyed by session id, one instance per scenario.

## 5. Primitives — the anti-sloth toolkit (fixed `sleep` as readiness is banned)

- `wait::until(deadline, || cond)` — **immediate first check, then a tight fixed poll (~20ms) for
  local transitions**; exponential backoff is reserved for Tier-3/remote only. [council: a 10→500ms
  backoff would add ~0.25–0.5s per milestone — for a 2-of-10 run with ~10 milestones that is
  seconds of pure overhead.]
- `proc::OwnedProcess` — spawns into its **own process group**, kills the group on drop (no orphans),
  captures stdout/stderr to a bounded ring buffer with **the token/secret line redacted on
  ingest** (the member app prints `Signer: …/#<token>`). Event-readiness via `wait_log(regex)`.
- Parallel bring-up with `thread::scope`; **but reserve all member ports up front and retry the
  whole topology on bind failure, or inherit the `TcpListener` fd into the child** — do not
  bind-`:0`-then-release-then-pass-port (TOCTOU at 10 parallel spawns). [council]
- `chain::generate(n)` issues **one** `generate(n)` RPC (not n calls) and **does not run a full
  wallet sync inside a poll loop**; it polls lightwalletd height once then checks spendability.
  [council, vs `deploy_demo.sh:93` `mine 12`]
- Port alloc, temp isolation (private `0700` run root), deterministic teardown (§9).

**[council] No wall-clock promises until measured.** The app itself has internal sleeps
(`ceremony.rs:907` 100ms creator-session, `:983` 50ms/DKG-pass) and N relay round-trips. P1 must
**measure the phase breakdown** for a 2-of-10 run and set deadlines from the measurement; the doc
makes no "seconds to ~1 min" claim.

## 6. Service topology (`services.rs`) — fail closed

Connects to running services (omarchy/CI) or owns them. **[council] Tier 2 must be chain-isolated:**
- Require **loopback or explicitly-owned** endpoints for frostd/node/lwd/THS; refuse remote URLs.
- Verify node + lightwalletd + the vault network all report the **same disposable regtest** chain
  identity before any `fund` or `broadcast`; **fail closed** otherwise (never risk a real faucet /
  a real-network broadcast). Tier 3 requires an explicit network confirmation flag.
- Missing service → **skip only for a local opt-in run; the dedicated Tier-2 CI job hard-fails**
  and reports the executed-scenario count. [council: my prior "skip" was wrong —
  `payment_over_frostd.rs:86` fails without `FROSTD_URL`.]

## 7. Drivers

- **Tier 1 (`vault.rs`)**: `LocalSigner`s over `SoftwareSecureElement`, driving the real v2 DKG
  (`member_dkg_step`/`relay_dkg`) + `drive_to_signed_pczt` over the in-memory relay. **[council]
  document the software-custody limit; `create_with_identity`/`hosted_material` must be test-gated
  or kept behind the signer boundary — they currently export a key package + vault secret
  (`signer/local.rs:511,652`) and are not test-only.**
- **Tier 2/3 (`member.rs`)**: spawn `loki_member_app`; typed client over **all 21 routes**
  (`routes.rs:42`). Readiness via status-phase through `wait::until` (replaces `deploy_demo.sh:84`
  `for n in seq 1 300`).

## 8. Scenario catalog — route-to-scenario matrix (params `members`,`threshold`; cap `MAX_MEMBERS`=16)

[council: 21 routes, not 20; prior catalog omitted unlock/lock/enroll/roster/agreed/session/
payment-session, multi-vault, balance, payment-verify, payment history.]

| Route(s) | Scenario | Tier |
|---|---|---|
| profile-create, unlock, lock, status | `account`: create → lock → **wrong-passphrase refusal** → unlock → vault list; two vaults/profile | 1(app)/2 |
| create, join, enroll, roster, agree, agreed, session, address | `ceremony(n,t)` → **active**, same address all members; + **invalid/reused invite**, **roster-fingerprint mismatch** refusal | 1 & 2 |
| (restart) | `interrupt`: kill mid-DKG → assert host reports `setup_interrupted` and **refuses re-agreement** (the real behavior, `ceremony.rs:649/705/843`); fresh-vault recovery. **[council: "resume mid-DKG and complete" is NOT a product capability — do not assert it; true resume is separate product work.]** | 2 |
| balance, payment-draft/publish/session/review/approve/finish/verify, payments | `payment(quorum)`: fund → **scanned-spendable assertion** → draft → publish → review/approve×t → finish → **`broadcast`→`confirmed` transition** → `payment-verify` by txid → `payments` lists the attempt+txid | 2 (Tier-1 variant stops at signed PCZT) |
| (persisted phases) | `payment-restart`: kill at each **named persisted phase**, restart, assert the defined post-restart invariant (not a vague "recovers"). **[council: specify kill points + assertions per phase; approval is marked requested before background signing, `payment.rs:636`.]** | 2 |
| signing faults | `faults`: missing share / late msg / offline member → **specific endpoint, rejection status, and state-unchanged assertion** (wraps `signing_faults.rs`) | 1 |
| web `/api/u` + token | `isolation`: drive the **web proxy** with each member slug, a wrong slug, a missing slug, a substituted token, and **each of the 5 token-exempt peer routes** (`routes.rs:63-83`) — assert denials AND the intended public responses. **[council: a direct member-port check alone does not validate the capability-URL model.]** | 2 |
| backup (if present) | `backup`: artifact exists, survives restart, address + member identity unchanged | 2 |

## 9. Determinism, secrets, teardown, observability [mostly council]

- **Determinism:** pin/record the sources — `OsRng` usage, frostd session TTL bounds, lightwalletd
  scan lag (assert scanned-height, don't sleep), the port handoff (§5). CI deadlines sized from
  measurement with headroom, not guesses; flakiness is a failure, not a retry-until-green.
- **Secrets:** `SecretString` (in-memory, `Debug`-redacted); never in env, argv, logs, or files;
  redact the token line on log ingest. **Stop writing `passphrases.txt` + the plaintext token
  access map** the way `deploy_demo.sh:57-59,98-105` does (or gate it to a loopback-only dev run).
  Document that `TempDir` deletion is **not** secure erasure of sealed shares.
- **Teardown:** kill the process **group**; provide an explicit cleanup path for abandoned runs
  (hard crash leaves no `Drop`); private `0700` run root.
- **Observability:** on failure, emit a bounded, **redacted** artifact: scenario, member, stage,
  last status, retained tail logs — so a CI failure is diagnosable.

## 10. Retirement plan — gated, build-safe [council]

1. Land Tier 1 + Tier 2 `ceremony`+`payment`+`interrupt`+`payment-restart`+`isolation`.
2. **Before deleting anything:** enumerate (a) the exact crates `loki_member_app` needs — it is
   feature-gated on `communication/client` + `communication/protocol` (`poc/Cargo.toml`), so
   "delete communication" is **not** a blanket `rm`; (b) every existing test that uses
   `tests/support/hosted_services.rs`; (c) each **security property** the relay/admission suites
   cover (capability rejection, authenticated claim replay, partial-provision recovery —
   `communication/relay/tests/*`, `communication/admission/tests/*`) mapped to its replacement
   frostd/host assertion.
3. Delete the Python harness + `poc/ths.py` + the relay-only code/tests **only after** each mapped
   replacement passes, and **build the product binary (`loki_member_app`) after every deletion
   step** to prove the boundary is intact. Migrate `hosted_services.rs` dependents first.
4. Replace `omarchy_demo.sh` with `loki-harness --tier 2 --scenario payment`; keep `deploy_demo.sh`.

## 11. Open questions — resolved by council

1. **CI service provisioning:** pinned/owned service images in an isolated CI network with
   mandatory health **and chain-identity** checks; the Tier-2 job **hard-fails** if any service is
   absent. A local connect-to-running mode may skip. (Compose for CI.)
2. **frostd for Tier 2:** explicit version-pinned binary or managed CI service; **no PATH fallback
   or build inside a timed run**; require an endpoint/chain confirmation before any login key is
   used. On omarchy, connect-to-running.
3. **Delete the relay when?** Only **after** Tier 2 passes a full 2-of-10 run (incl. interrupt +
   payment) **and** the §10.2 build/dependency + security-coverage-equivalence gate. The combined
   deletion in the first draft was too coarse.

## 12. Phasing

- **P1** — `secret`/`wait`/`proc`/`services`/`chain`/`member` primitives + Tier-1 full-DKG-then-sign
  + `ceremony`; **measure the 2-of-10 phase breakdown** and set deadlines from it.
- **P2** — Tier-2 `ceremony`+`payment` (fund→confirmed, with the real transition/verify assertions)
  + chain-isolation guard; replace `omarchy_demo.sh`.
- **P3** — `interrupt`+`payment-restart`+`faults`+`isolation`+`account`; wire the Tier-2 CI job
  (hard-fail on missing services).
- **P4** — retirement per §10 (inventory → map → delete-and-build-check).
- **P5** (opt-in) — Tier 3 testnet.

## Appendix — known product hardening the harness should pin, not paper over
- Frostd login key currently reuses the member X25519 encryption secret
  (`host/ceremony.rs`, `host/payment.rs`, `FrostdLoginKey::from_secret_bytes`). A dedicated sealed
  login key bound to the roster is the fix; the harness should test whichever is shipped, and the
  isolation scenario should not assume separation that doesn't exist yet.
