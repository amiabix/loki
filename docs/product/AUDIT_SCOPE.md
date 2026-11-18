# Loki — External Audit Scope

Status: **DEMO / TEST-NETWORK ONLY. NOT FOR REAL FUNDS.**

This is the concrete file/module list an external auditor must review, the
out-of-custody-scope remainder, a reproducible-build recipe verified on a real
machine, and the #1094 / #490 alignment notes required by
`ws6-standards-and-audit.md` §6.

Companion docs: `SECURITY.md` (what is proven vs dangerous, pre-custody
checklist), `ws1-signer.md`, `ws6-standards-and-audit.md` §3.

---

## 1. In scope — review every line

The ZF `frost-rerandomized` / `reddsa` threshold crypto is already audited
(`ADOPTION.md` §1–2). Loki writes the *shell* around it. The shell is the entire
custody surface and is small on purpose. All paths are under `poc/`.

### 1a. Signer shell (WS1) — the highest-value target

What stands between an attacker and a FROST share. ~2,900 lines.

| File | Lines | What to review |
|---|---:|---|
| `src/signer/mod.rs` | 189 | The one signer seam (`Signer` trait); the return-type allow-list audit (`known_signer_return_types_are_public_artifacts`). Confirm no method returns a share/nonce/spend type. |
| `src/signer/local.rs` | 1231 | `LocalSigner`: share sealed at rest, unsealed only for the two FROST rounds; `connect` network/vault/identity checks; `sign_approve` WYSIWYS→sighash binding; `dkg_step` (see 1c). |
| `src/signer/nonce.rs` | 386 | Nonce single-use + crash-safety: persist-before-emit (round 1), atomic burn-before-removal with fsync (round 2), reuse-for-different-message hard-refusal. |
| `src/signer/wysiwys.rs` | 316 | `describe_pczt` + `sighash_of_pczt`: the signer independently parses the PCZT, renders what it pays, recomputes the signed bytes, and binds fee to `cv_net`. The `fee_verified == false` branch is defensive and **not yet reachable from the public builder** — audit it against an adversarial PCZT (`SECURITY.md` §3). |
| `src/signer/secure_element.rs` | 247 | `SecureElement` trait + `SoftwareSecureElement`. The software KEK lives in process memory and `from_kek` reconstructs it — this is a **known demo gap** (defeats stolen-device A3); audit the trait boundary a real Enclave/StrongBox/TPM backend must satisfy, not the software stub as production. |
| `src/signer/backup.rs` | 419 | Share backup / restore-to-new-device and the nonce-epoch reset on restore (no old-nonce replay). |
| `src/signer/coordination.rs` | 333 | Signer-side coordination of the rounds. |

### 1b. Keyless coordinator boundary (WS2 §4, invariant #1)

Prove no share/nonce/spend path exists in the coordinator/browser.

| File | Lines | What to review |
|---|---:|---|
| `src/coordinator_boundary.rs` | 140 | The single re-exported signer seam; `assert_keyless` start-up check; the source deny-list test `coordinator_source_links_no_secret_type`. Both guards are narrow (one file; named types only) — confirm the whole coordinator process actually stays keyless, not just this file. |
| `src/coordinator.rs` | 253 | Coordinator round driver / aggregation / broadcast. Public data + encrypted DKG only. |

### 1c. DKG seal path

The round-two DKG package is a recipient's share contribution; a relay observer
collecting a threshold of raw packages could reconstruct the vault key. It must
be sealed to the recipient before it leaves the signer.

- `src/signer/local.rs` `dkg_step` (**line 374**): round 1 produces round-2
  packages, each sealed via `Identity::seal_round2` (**line 441**); inbound
  round-2 packages unsealed via `open_round2` (**line 463**).
- `src/signer/coordination.rs` — the signer requires a signed
  `AcceptedCeremonyRoster` (`src/setup_ceremony/`) and checks vault, policy,
  network, and its own identity before sealing.
- Regression: `tests/frostd_transport.rs` (commit `c9f6ad1`) proves a relay
  observer holding every wire byte cannot deserialize any `round2::Package`,
  only the intended recipient can unseal, and DKG still reaches the same group
  key. **Note:** the relay transport this test exercises is being retired;
  review the seal/open primitives, which the member path reuses, not the relay.

### 1d. ZIP-2005 FVK derivation (WS5, #1094)

| File | Lines | What to review |
|---|---:|---|
| `src/zip2005.rs` | 66 | `use_qsk = true` FVK derivation from the group key. Cross-checked against vectors, **not yet reviewed upstream (ZF #1094)**. An error here corrupts which address the vault controls. Regtest-only until reviewed (file header). See §4. |

### 1e. Thin enrollment / roster layer (WS3 §4)

| File | Lines | What to review |
|---|---:|---|
| `src/setup_transport.rs` | 530 | `Identity`, `PublicIdentity`, session sealing/opening used by DKG and signing transport. |
| `src/setup_ceremony/` | — | `AcceptedCeremonyRoster` production and the signed setup agreement the signer verifies. Human fingerprint review binding each peer key to a person is **not yet proven** (`SECURITY.md` §3). |

---

## 2. Out of custody scope

Non-custodial public-data code. A bug here can lose availability or leak
*viewing* activity (a privacy review, separate from custody), but cannot move
funds, because none of it holds a share, nonce, or spend authorization. Lower
review priority.

- `src/scan.rs`, `src/scanstate.rs`, `src/witness.rs` — chain scan / note
  selection / witnesses (public viewing-key data).
- `src/wallet_store.rs` — SQLCipher wallet DB, balance, broadcast, pending-note
  reservation (reservation is a correctness/UX guard, not a custody boundary).
- `src/rpc.rs`, `src/bin/loki_wallet_sync.rs`, `src/bin/loki_indexer.rs` —
  node/lightwalletd I/O.
- `src/bin/loki_member_payment.rs`, `src/candidate.rs`, `src/intent.rs`,
  `src/verify.rs` — PCZT build / intent / post-mine verification. These shape
  what the signer is *asked* to sign; the signer independently re-derives and
  binds the sighash (1a `wysiwys.rs`), so a bug here cannot forge an approval —
  but the intent→PCZT path is worth a correctness pass.
- `src/payment_manifest.rs`, `src/transport.rs`, `src/setup_relay*.rs`,
  `src/relay_member/`, `communication/` — **relay transport, being retired.**
  Not in custody scope.
- `poc/wallet/*.py`, `poc/wallet/*.js` — the host app / browser UI. The browser
  holds no key; recovery words entered for restore are cleared from the DOM on
  leave/lock (`app.js` `selectVault`). UI delivery trust is §3 (reproducible
  builds), not source audit.

Everything not listed in §1 is out of custody scope.

---

## 3. Reproducible builds (verified)

The signer's delivery is custody (`ws6` §4): a targeted malicious build must be
detectable. Two clean builds of each signer must produce the same hash.

**Artifacts:** the native signer `loki_member_app` (`--features
relay-communication`, the packaged member binary `run-member.sh` runs) and the
browser signer bundle `poc/loki-signer-wasm` (wasm-pack `--release --no-opt
--target web`, what `web/wallet/scripts/copy-signer.mjs` serves). The Xcode
`LokiSigner.app` (`poc/signer-app`) is not covered.

**Recipe:** `poc/scripts/repro-build.sh > SHA256SUMS`. It exports the committed
`HEAD` to `/tmp/loki-repro/src` and builds there with `CARGO_HOME` and the target
dir also under `/tmp/loki-repro`, rustc 1.95.0, `--locked`,
`SOURCE_DATE_EPOCH=1700000000`, `CARGO_INCREMENTAL=0`, `-C codegen-units=1`,
`--remap-path-prefix=/tmp/loki-repro=/build`. CI (`.github/workflows/repro.yml`)
builds twice from two checkouts on ubuntu-24.04 and fails on any difference.

Why a fixed root (measured, so it is not retried):
- Per-checkout `--remap-path-prefix` is not enough. `communication/*` crates are
  path deps outside the `poc/` workspace, so cargo's metadata hash for
  `loki_relay_client`, `loki_relay_protocol` and `loki_poc` changed with the
  checkout path, which reordered the binary's contents.
- Vendored OpenSSL (via `rusqlite` sqlcipher) bakes its OUT_DIR install prefix into
  the binary as `ENGINESDIR`/`MODULESDIR` strings, so the target dir must not vary.
- Without `codegen-units=1` two clean builds alternated between two hashes.

**Verification (macOS arm64, rustc 1.95.0, two checkouts at different paths):**
both runs printed identical output:
```
ce2af70ad66490d1debe087c9d10ff62e688c25cda256c41b1daaa3510b43647  target/release/loki_member_app
f2907a8dea9f895f1ca451f8e2deb16f85ba835d3cd631c9d4f9e49c2a8323f2  wasm-pkg/loki_signer_wasm_bg.wasm
218b0373097414c1408a2627db2faf5db42ab389312b7d93470644a8340831ab  wasm-pkg/loki_signer_wasm.js
```
Hashes are per OS + arch: macOS and Linux differ, which is expected.

**Still needed for independent delivery** (`ws6` §4, SECURITY.md item 8):
- A second builder on different hardware, run by someone else, that reproduces the
  hashes for each release tag and publishes them independently.
- Release hashes signed by a key that is not the CI's (e.g. a maintainer's
  signing key), so a compromised CI cannot publish its own hashes.
- One agreed publication place for `SHA256SUMS` plus signatures (e.g. the GitHub
  release and a second channel), checked by members before they install.

---

## 4. #1094 (ZIP-2005 FVK) disposition

- **Current state:** Loki derives the vault FVK with its own `use_qsk = true`
  branch in `src/zip2005.rs` (66 lines), cross-checked against ZIP-2005 vectors
  but **not reviewed upstream**. ZIP-2005 is still Proposed. The file is
  **regtest-only** until the derivation and the key/backup flow are reviewed.
- **Not N/A:** Loki is **not** on an audited `zcash-sign generate` derivation,
  so the WS5 "Option A kept" case applies — this must be reviewed.
- **Plan (per `ws5-fvk-derivation.md` §4):** read `zcash-sign`'s `generate.rs`
  to decide if it implements the quantum-recoverable derivation. If yes, switch
  to it (Option B) and drop `zip2005.rs` from scope. If no, drive the
  vector-matched `use_qsk` derivation through ZF `frost#1094` and land it
  reviewed. Until one of those closes, `zip2005.rs` is in audit scope (§1d) and
  mainnet is blocked (`SECURITY.md` item 7).

## 5. #490 (QR handoff + backup format) alignment

- **Spec:** Grant #490 is an open spec for the coordinator↔co-signer **QR**
  handoff and a backup artifact format, so an isolated / air-gapped / hardware
  signer can interoperate.
- **What matches:** Loki already uses **PCZT** as the coordinator→signer
  interchange (`ws6` §2; the WYSIWYS path parses a PCZT), which is the format
  #490 and the hardware-signing trajectory build on. The signer approve/backup
  surface is the narrow `Signer` trait (`src/signer/mod.rs`) plus
  `src/signer/backup.rs`.
- **What diverges:** Loki's current transport is the (being-retired) relay
  framing and a local-directory courier, **not** a QR handoff; the backup
  artifact in `src/signer/backup.rs` is Loki-defined, not yet the #490 format.
- **Plan:** pull the current #490 draft **before** freezing the WS1
  approve/backup formats, then converge the `Signer` approve/backup surface and
  the PCZT message framing onto the spec so an external signer interops.
  Zconnect (web-coordinator ↔ external signer) is the longer-term target
  (`ws6` §2). This is an interop-convergence task, not a custody blocker.
