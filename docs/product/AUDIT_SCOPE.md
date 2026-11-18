> **For Ayush (delete before sending).** Send to the audit firms on your shortlist (your
> call; none has been contacted). Things to arrange with them: (1) a commit to pin;
> re-measure the line counts below at that commit; (2) scope is §1, §2 is out; (3) whether
> the browser signer (§1g) is in this round or a second one; (4) a macOS host with an
> Apple Team ID if they want to run the Secure Enclave path (§1a); (5) a reproducible-build
> check on their own machine (§3); (6) the #1094 status (§4) at audit time.

# Loki — External Audit Scope

Status: **DEMO / TEST-NETWORK ONLY. NOT FOR REAL FUNDS.**

What an external auditor must review, what is out of custody scope, a
reproducible-build recipe, and the #1094 / #490 alignment notes required by
`ws6-standards-and-audit.md` §6. Companion docs: `SECURITY.md`, `ws1-signer.md`,
`ws6-standards-and-audit.md`.

Paths are relative to `poc/` unless they start with `web/`. `core/` means
`poc/loki-signer-core/src/`. Line counts are `wc -l` at commit `9d7c06b`.

---

## 1. In scope — review every line

The ZF `frost-core` / `frost-rerandomized` / `reddsa` crates are already audited
(`ADOPTION.md` §1–2). Loki writes the shell around them; that shell is the custody
surface.

### 1a. Signer shell and at-rest sealing

| File | Lines | What to review |
|---|---:|---|
| `core/signer/mod.rs` | 375 | The one signer seam, `pub trait Signer` (226). Return-type allow-list test `known_signer_return_types_are_public_artifacts` (352); it pins current methods only and does not inspect opaque bytes (comment at 353-354). |
| `core/signer/local.rs` | 2015 | `LocalSigner`. Share unsealed only in `open_key` (813-819). `connect` (1203-1248): network check, origin shown to a `connect_approval` prompt. `check_roster` (861-885). `sign_commit` (1461-1475), `sign_approve` (1477-1526, see 1c). |
| `core/signer/store.rs` | 179 | Signer data dir layout (1-20). Every `.sealed` file except the KEK is a `SealedShare` with AAD `file_binding(kind, vault, member)`; `write` 148-159, `read` 161-178. |
| `core/signer/durable.rs` | 186 | Atomic writes. Native: temp file 0600, fsync, rename, dir fsync (18-115). wasm: OPFS sync handles (117-184); **no atomic rename, `replace_durable` overwrites in place (122-128); `sync_dir` is a no-op (180)**. |
| `core/signer/secure_element.rs` | 367 | KEK→DEK→share hierarchy (1-16). `SecureElement` trait (36-41). `SoftwareSecureElement`: KEK in process memory, `from_kek` (60), `persistent` stores the KEK in `kek.sealed` under the passphrase (70-102), `from_passphrase` (108-112). `WRAP_AAD` (129), `file_binding` (176-183), `SealedShare` (190-309). The software KEK is a known demo gap, not a hardware boundary. |
| `core/seal_kdf.rs` | 244 | Single Argon2id call, `Argon2::default()` (header 1-14, `derive_uncached` 153-162). Per-process session key cache keyed by keyed BLAKE3 of secret+salt (22-151). |
| `core/signer/secure_element_apple.rs` | 164 | Secure Enclave KEK via ECIES; persistent key with biometric access control (doc 9-16). Compiled only with feature `apple-enclave` on macOS (`core/signer/mod.rs:29-30`). Swift side: `poc/enclave-spike/se_backend.swift`. |
| `src/enclave_ffi.rs` | 49 | C-ABI `loki_signer_enclave_selftest` (13-49) for `poc/signer-app`: seals a stand-in share under a persistent Enclave key, reopens by tag. Same cfg gate (`src/lib.rs:28-29`). |
| `core/signer/secure_element_webauthn.rs` | 123 | Browser KEK = HKDF-SHA256(PRF secret, info `Loki_signer_webauthn_prf_kek_v1`) (29, 53-61); wrap format is `SoftwareSecureElement`'s (63-71). |
| `core/signer/backup.rs` | 630 | Share backup / restore and nonce-epoch reset on restore. |
| `core/signer/coordination.rs` | 433 | `drive_to_signed_pczt` (51): keyless drive loop over `dyn Signer` (doc 1-20). |

### 1b. Nonce safety

| File | Lines | What to review |
|---|---:|---|
| `core/signer/nonce.rs` | 367 | Crash states (doc 1-23). `commit` persists the sealed nonce before returning the commitment (107-133). `load` refuses a nonce from another backup epoch (135-153). `sign_and_burn` (165-220): same-message resend replays the recorded partial, different message → `NonceError::Reuse`; burn record fsync'd before the nonce file is removed. Nonce id = payment id ‖ attempt id (`local.rs:821-828`). On wasm the final `sync_dir` is a no-op (see `durable.rs:180`). |

### 1c. WYSIWYS → sighash binding

| File | Lines | What to review |
|---|---:|---|
| `core/signer/wysiwys.rs` | 316 | `describe_pczt` (51-139) renders payee/amount/change/fee/memo from PCZT openings and the vault FVK. `fee_verified` clears when any action fails `verify_cv_net` (72, 86-87). `sighash_of_pczt` (149-182) runs `verify_cv_net`, `verify_nullifier`, `verify_rk` against the vault FVK, then computes the shielded sighash. |
| `core/signer/local.rs` | — | `sign_approve` (1477-1526): render → recompute sighash → member approval → refuse unless `pkg.message() == local_sighash` (1507-1509) → only then unseal the share and burn the nonce. |

### 1d. Keyless coordinator boundary

| File | Lines | What to review |
|---|---:|---|
| `src/coordinator_boundary.rs` | 213 | Re-exported seam (21). `assert_keyless` (27-32) only calls `list_vaults`; its own doc says it proves nothing about other paths (23-26). Source deny-list tests: `coordinator_source_links_no_secret_type` (46-80, this file only) and `coordinator_drive_loop_is_viewing_key_less` (90-131, token grep of `core/signer/coordination.rs`). |
| `src/payment_transport.rs` | 265 | `coordinate` (144): the payment coordinator. Gets the candidate from the proposer's local hand-off, not the relay (doc 141-143). |
| `src/host/payment.rs` | 3342 | `aggregate` (1499-1547): one-shot coordinator identity in the proposer's member process; reads the plaintext candidate from the member's encrypted store (1530-1543), written at 1423-1428. |
| `core/transport.rs` | 431 | `SealedCandidate` (146-170): the candidate sent to other members is sealed per recipient. |

**Viewing-key boundary, stated accurately.** The coordinator *does* see the vault viewing
key. The candidate PCZT carries the FVK in each Orchard spend: the vendored builder sets
`fvk: Some(self.fvk)` (`vendor/zakura-orchard/src/builder.rs:517`), the PCZT format
serializes it (`zakura-pczt 0.1.0-rc4`, `src/orchard.rs:604`), and Loki does not strip
it (no redaction code under `core/` or `src/`). A throwaway test on this commit built a
candidate with `core/builder.rs` `build_candidate_for_vault` and found the 96-byte FVK
in the PCZT bytes (`FVK_IN_CANDIDATE=true`). So: the frostd relay sees only sealed
envelopes (`core/transport.rs:146-170`; relay tape audit `tests/frostd_transport.rs:462-481`
asserts no plaintext PCZT crosses), but every party that opens the candidate — each
signing member and the proposer-side coordinator (`src/host/payment.rs:1530-1543`) —
holds the FVK. The "never reads a viewing key" line in `coordinator_boundary.rs:7` and
`coordination.rs:13-15` is true of those files' code tokens, not of the data the
coordinator handles. No share, nonce, or spend key reaches the coordinator through this
path.

`src/coordinator.rs` (253) is compiled only under `#[cfg(test)]` (`src/lib.rs:25-26`); it
is not shipped code.

### 1e. DKG roster binding and round-two encryption

| File | Lines | What to review |
|---|---:|---|
| `core/dkg_core.rs` | 830 | Phases (doc 1-29). `DkgCore::new` refuses an identity not in the roster with the same keys (347-352). Round 2 seals each peer's `contribution ‖ FROST round-2 package` with `seal_round2_v2` (474-520, call at 498). `finish` opens with `open_round2_v2` (522+, call at 536). Certificate body binds certificate digest, `vs` digest, roster fingerprint, ZIP 2005 `VERSION` (610-616). |
| `core/setup_transport.rs` | 813 | v1 vs v2 envelopes (doc 1-9). `seal_round2` / `open_round2` (v1, `LOKIDKG1`, 349 / 385; only `loki_setup_member run` uses it). `seal_round2_v2` (457), `verify_round2_v2` (497), `open_round2_v2` (535): key from both one-setup fresh keys, vault, both ids and round-one transcript; header is AEAD AAD; envelope signed by the identity key. |
| `src/frost_roster.rs` | 60 | `FrostRoster::fingerprint` (30-48): BLAKE2b `Loki_frostr_v1` over vault, threshold, member ids and keys. |
| `src/setup_ceremony/` | 2688 | `mod.rs` 156, `engine.rs` 1316, `journal.rs` 626, `admission_checkpoint.rs` 590. `AcceptedCeremonyRoster` (`mod.rs:24-41`): network label + non-zero operator digest, then `ValidatedRoster::new`. Human fingerprint review binding each key to a person is not yet proven (`SECURITY.md` §3). |
| `core/signer/local.rs` | — | `check_roster` (861-885): setup version 2, network, vault, own identity present. |

Regression: `tests/frostd_transport.rs` `audit` (462-481) asserts every round-two wire is
`LOKIDKG2` and none deserializes as a `round2::Package`; run on the in-memory relay
(484-510). The live-frostd variant (513+) skips unless `FROSTD_URL` is set.

### 1f. ZIP-2005 FVK derivation (#1094)

| File | Lines | What to review |
|---|---:|---|
| `core/zip2005.rs` | 66 | `frost_viewing_key` (39-66), `use_qsk = true`. Matched against 8 frost-tools #610 vectors (`tests/zip2005_vectors.rs`) and 2 independent vectors (`tests/zip2005_keys.rs`); not reviewed upstream. File header: regtest-only until reviewed (3-4). An error here changes the address the vault controls. Details: `ZIP2005_1094.md`. |

### 1g. Browser signer origin model

| File | Lines | What to review |
|---|---:|---|
| `loki-signer-wasm/src/lib.rs` | 970 | wasm bindings over `LocalSigner`. `browser_prompts` (611-623) auto-approves: `connect` → `true` (613), roster → `Match` (615), payment approval → `true` (621). `connect` is called with the literal origin `"https://coordinator"` (797, 873). So the Rust signer does **no** origin binding in the browser; approval UI and origin isolation are in JS / the browser. `sign_approve` still enforces the 1c sighash binding (`signApprove`, 542-552 → `LocalSigner::sign_approve`). |
| `loki-signer-wasm/signer-worker.js` | 421 | Worker driving DKG/payment over frostd; `drivePayment` (271-338) opens the proposer's sealed candidate and calls `paymentReview` then `signApprove`. |
| `loki-signer-wasm/signer-client.js` | 58 | Main-thread ↔ Worker RPC. |
| `wasm-transport/src/lib.rs` | 464 | Browser frostd client over Fetch; TLS required off loopback (header 1-30). |
| `web/wallet/src/lib/webauthn.ts` | 62 | **RP ID binding**: `rp.id = window.location.hostname` at create (27), `rpId = window.location.hostname` at get (51); fixed PRF salt `loki/signer/share-kek/v1` (9); `userVerification: "required"` (36, 53). The passkey, hence the PRF secret and the share KEK, is scoped to the serving hostname. Same logic in `poc/web/webauthn_prf.js` (93; 33, 41, 71, 75). |
| `web/wallet/src/lib/signer.ts` | 355 | `enroll` (205-219): device ECDSA key signs `loki-member-registration-v1 ‖ origin ‖ … ‖ challenge`; origin defaults to `window.location.origin` (207, 215). |
| `web/wallet/src/lib/members.ts` | 244 | Server side: `publicOrigin` requires HTTPS except loopback (39-47); `registerMember` (199-225) consumes the challenge, requires the issued origin equal the request origin (214), verifies the device signature over the origin-bound transcript (148-150, 216-217). |
| `web/wallet/server.js` | — | Request origin derives from `HOSTNAME` / `PUBLIC_PORT` env (13-23); a misconfigured value changes the origin registrations are checked against. |
| `src/host/routes.rs` | 240 | Native member API `browser_origin` (82-120): non-ceremony `/api/*` requests with an `Origin` must equal the paired coordinator origin; the four ceremony routes are CORS-open but token-gated (84-91). |

Audit questions for 1g: whether WebAuthn RP-ID scoping plus browser per-origin storage
is a sufficient boundary given the Rust-side auto-approve; who can serve JS on the wallet
hostname (§3 covers delivery); the no-op `sync_dir` on wasm (1b).

---

## 2. Out of custody scope

Non-custodial code. A bug here can lose availability or leak *viewing* activity (a
privacy review, separate from custody), but holds no share, nonce, or spend
authorization. Lower priority.

- `src/scan.rs`, `src/scanstate.rs`, `src/witness.rs` — chain scan, note selection,
  witnesses (viewing-key data).
- `src/wallet_store.rs` — SQLCipher wallet DB, balance, broadcast, pending-note
  reservation.
- `src/rpc.rs`, `src/bin/loki_wallet_sync.rs`, `src/bin/loki_indexer.rs` —
  node/lightwalletd I/O.
- `src/bin/loki_member_payment.rs`, `core/candidate.rs`, `core/builder.rs`,
  `core/intent.rs`, `core/verify.rs` — PCZT build / intent / post-mine verification.
  The signer re-derives and binds the sighash itself (1c), so a bug here cannot forge an
  approval; the intent→PCZT path still deserves a correctness pass.
- `core/payment_manifest.rs`, `src/transport.rs`, `src/setup_relay*.rs`,
  `src/relay_member/`, repo-root `communication/` — relay transport. Not in custody scope.
- `web/wallet/` UI outside the files in 1g — holds no key. UI delivery trust is §3.

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
Hashes are per OS + arch: macOS and Linux differ, which is expected. The native
half also reproduced on Linux arm64 (two fresh ubuntu:24.04 containers):
`d2ea2083ae002cfb0b17b48ea986b579120bbaa72dabd2bc2de5c9abfabe3065  loki_member_app`.

**Open: the wasm signer does not link on Linux,** so the CI job fails until this is
fixed. `loki-signer-wasm/src/lib.rs` defines secp256k1's
`context_preallocated_*` functions in Rust, assuming no C toolchain compiles
secp256k1 for wasm. That holds on macOS, where `ar` writes an empty
`libsecp256k1.a` for wasm objects. On Linux the C does compile, and rust-lld
reports `duplicate symbol: rustsecp256k1_v0_10_0_context_preallocated_size`
(measured with default and `codegen-units=1`; forcing GNU `ar` does not help).
So today the bundle's contents depend on the host's C archiver. The signer owner
has to pick one of two fixes: compile the real secp256k1 C on every host and drop
the stubs, or keep the stubs and stop the C from being linked on every host.

**Still needed for independent delivery** (`ws6` §4, SECURITY.md item 8):
- A second builder on different hardware, run by someone else, that reproduces the
  hashes for each release tag and publishes them independently.
- Release hashes signed by a key that is not the CI's (e.g. a maintainer's
  signing key), so a compromised CI cannot publish its own hashes.
- One agreed publication place for `SHA256SUMS` plus signatures (e.g. the GitHub
  release and a second channel), checked by members before they install.

---

## 4. #1094 (ZIP-2005 FVK) disposition

- Loki derives the vault FVK with its own `use_qsk = true` code in `core/zip2005.rs`
  (66 lines), matched against vectors (§1f), not reviewed upstream. ZIP 2005 is still
  Proposed (`core/zip2005.rs:4`).
- Loki is not on `zcash-sign generate`: `tests/zf_spine.rs:79-144` shows its FVK
  differs in `rivk`. So this is in scope, not N/A.
- Until ZF `frost#1094` reviews the derivation, `core/zip2005.rs` stays in audit scope
  (§1f) and mainnet is blocked (`SECURITY.md` §4 item 7). Review packet:
  `ZIP2005_1094.md`.

## 5. #490 (QR handoff + backup format) alignment

- **Spec:** Grant #490 is an open spec for the coordinator↔co-signer QR handoff and a
  backup artifact format, so an isolated / air-gapped / hardware signer can interoperate.
- **Matches:** PCZT is the coordinator→signer interchange (the WYSIWYS path parses a
  PCZT, `core/signer/wysiwys.rs:51,149`). The approve/backup surface is the `Signer` trait
  (`core/signer/mod.rs:226`) plus `core/signer/backup.rs`.
- **Diverges:** transport is frostd envelopes, not a QR handoff; the backup artifact in
  `core/signer/backup.rs` is Loki-defined, not the #490 format.
- **Plan:** pull the current #490 draft before freezing the approve/backup formats, then
  converge on it. Interop task, not a custody blocker.
