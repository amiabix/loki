# FROST Randomizer Seeds Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use executing-plans to implement this plan task-by-task in the new Herdr session. Steps use checkbox syntax for tracking. The user has already requested execution and PR creation; no further design or execution-choice approval is needed.

**Goal:** Implement all of issue #3's recommended seed generation, persistence, signing, independent finishing and refusal requirements.

**Architecture:** Generate a seed and randomized parameters from the exact commitments before building each real spend. Persist an associated seed record alongside the candidate, then regenerate and verify parameters during review and aggregation. Preserve deferred proof/anchor construction and the existing vault implementation.

**Tech Stack:** Rust 2021, frost-rerandomized 3.0.0, reddsa FROST RedPallas, PCZT, patched Orchard/zcash_primitives, Python and Bash regtest harnesses.

**Spec:** `docs/superpowers/specs/2026-10-09-frost-randomizer-seeds-design.md`, derived from https://github.com/amiabix/loki-zcash-frost/issues/3 (no comments at inspection).

## Execution provenance

Originally planned and baseline-tested on `e66f97ce894e3784efa53e5625919a0b8abce9e4` (64 tests, inherited formatting failure, warning-free Clippy). Rebased onto `0aee73a` before implementation, then onto `3f66967` to preserve PR #2's THS migration and main's backup gate, and finally onto `754445a` to retain the expanded separate-member transaction-signing fixture. The current commands below target THS; obsolete standalone setup changes were discarded before live validation.

## Global Constraints

- Base is latest fetched origin/main `754445a445efdea1adf6be378ca2dd2a453b61dc`.
- Work only in `/private/tmp/loki-frost-randomizer-seeds`, branch `refactor/frost-randomizer-seeds`. Preserve the dirty original checkout.
- Keep regtest-only claims and pinned caller-alpha vendor patches. Preserve main's THS runtime migration and checked-backup gate. No crypto dependency migration (#4) or ZIP 2005 implementation changes.
- Never commit generated seeds, key packages, nonce secrets, run state or demo sandbox contents.
- Read `/Users/megabyte/.codex/skills/conventional-commits/SKILL.md` before source comments, commits, PR text or change-summary comments.
- Regression refusal tests must check the reason and absence of all new signature-share files, including earlier candidates/spends in the batch.
- Use loopback services and isolated temporary state; inspect `LOKI_STATE` and scripts before running destructive setup.
- Exclude intentionally uncompilable `probe-zip2005` from routine checks.
- Document that saved seeds require confidential handoff, do not prove honest coordinator RNG, do not prevent nonce rollback, and do not extend NCC audit coverage.

## File Map

- `poc/src/intent.rs`: retain canonical intent/proposal ID; remove custom `alpha_seed`; expose library seed generation/reconstruction or move those helpers to a focused `randomizer.rs` if storage needs justify it.
- `poc/src/bin/loki.rs`: per-spend seed files and association checks in propose, review_sign, finish, tamper, aggregate_and_apply, loaders, replicate and CLI tests.
- `poc/src/state.rs`: only narrowly needed protected seed-file IO; reuse existing MemberDir where possible.
- `poc/src/candidate.rs`, `lib.rs`, `refresh.rs`, `coordinator.rs`, `nonce_binding.rs`: adapt relevant tests and remove false API-impossibility comments. Direct-scalar adversarial research tests may retain deprecated API only with an accurate explanation of that deliberate scope.
- `poc/tamper-tests.sh`, `run-second-device.sh`, `nonce-reuse-drill.sh`: add seed failure cases, confidential replicas and saved-session rollback evidence.
- `README.md`, `poc/DEPENDENCIES.md`, `RESULTS.md`, `THREAT-MODEL.md`, `SECOND-DEVICE-RESULTS.md`: explain current behavior and record actual validation, preserving historical evidence as historical.

### Task 1: Generate and persist associated per-spend seed records

**Files:** intent.rs, bin/loki.rs; optionally focused randomizer.rs and lib.rs export.

**Interfaces:** Library parameters are `RandomizedParams<frost::PallasBlake2b512>`, commitments are `BTreeMap<frost::Identifier, frost::round1::SigningCommitments>`, seed is exactly 32 bytes for this pinned ciphersuite. Persist `randomizer_seed_AB.hex` for spend 0 and `randomizer_seed_AB_1.hex` for spend 1 (same rule for AC/BC), with versioned association metadata in the same record or companion file. Record proposal ID, pair, index, nullifier and exact commitments; loader takes expected association and returns seed bytes or a descriptive refusal.

- [x] Add generation/reconstruction tests and record association tests. Test same saved seed/commitments reconstructs identical alpha/rk, independent calls produce fresh seeds, changed commitments alter alpha, invalid length/hex/version fails, and swapped pair/spend/nullifier/proposal metadata fails. Use this library flow:

```rust
let (params, seed) = frost_rerandomized::RandomizedParams::new_from_commitments(
    public_package.verifying_key(), &commitments, rand_core::OsRng,
).unwrap();
let restored = frost_rerandomized::RandomizedParams::regenerate_from_seed_and_commitments(
    public_package.verifying_key(), &seed, &commitments,
).unwrap();
assert_eq!(seed.len(), 32);
assert_eq!(params.randomizer().serialize(), restored.randomizer().serialize());
assert_eq!(params.randomized_verifying_key().serialize().unwrap(),
           restored.randomized_verifying_key().serialize().unwrap());
```

- [x] Run `cd poc && cargo test randomizer` and applicable CLI tests to establish failure before implementing record IO.
- [x] Replace `alpha_seed` production use in propose with the library call; convert `params.randomizer().serialize()` through `alpha_from_canonical_bytes` into the existing builder. Persist the seed association before any signature can be produced. Do not regenerate seeds for an existing fixed candidate on restart.
- [x] Define reproposal handling explicitly: unchanged commitments retain original candidate bytes/seeds or are refused unchanged; new honest sessions require fresh commitments and fresh seeds. Mixed/incomplete session files fail closed. Never rebuild a randomized PCZT message with the same nonce commitments as an ordinary restart.
- [x] Run targeted tests, including a multi-input fixture; commit only source/tests/docs with `refactor(signing): persist library-generated randomizer seeds`.

### Task 2: Review, sign and aggregate using saved seeds

**Files:** bin/loki.rs, candidate.rs, relevant library tests.

**Interfaces:** Review's per-spend checked batch carries `(SigningPackage, saved seed)` rather than an accepted direct scalar. AggregateInputs gains one associated seed record per intended input; loaders must reject a count mismatch.

- [x] Extend the existing CLI two-input fixture (`second_device_checks` area) so all AB/AC/BC pairs generate separate nonces/seeds for each input and reconstruct parameters against their exact commitments. Assert correct sighash and alpha/rk before signing and a valid aggregated signature on each real input.
- [x] Add fixed-candidate failures for changed seed and changed commitments, missing/short/malformed seed, another candidate's seed, reversed multi-input seed records, and seedless legacy proposals. CLI `review-sign` assertions use:

```rust
assert!(error.contains(expected_refusal), "{error}");
for pair in ["AB", "AC"] {
    for spend in 0..2 {
        assert!(!shared.path().join(share_file(pair, "alice", spend)).exists());
    }
}
```

Test bad records in the final reviewed candidate/spend too, to prove earlier checks cannot emit partial approval. Check nonce files remain untouched on these review failures.

- [x] Run the targeted CLI tests and observe the expected failures.
- [x] In review_sign, load/validate the seed before batching, reconstruct parameters, preserve independent payment verification, local sighash, canonical alpha comparison and known-vault rk comparison. Then call:

```rust
let share = frost_rerandomized::sign_with_randomizer_seed(
    &package, &nonces, &key_package, &seed,
)?;
```

- [x] In finish and aggregate_and_apply, load seed records, reconstruct `RandomizedParams` with the public package's verifying key and exact commitments, verify real-spend alpha/rk by intent nullifier, and pass the reconstructed params to aggregate. Check the public package agrees with the known vault key. Update tamper candidate construction to use the saved seed for the intended fixed signing session so payment-tamper tests reach their intended refusal.
- [x] Update relevant test helpers to seed API. Remove inaccurate comments saying the seed path cannot be used. Keep adversarial tests faithful where intentionally direct-scalar use is required.
- [x] Run `cargo test` and `cargo build`; commit as `refactor(signing): verify and sign with persisted randomizer seeds`.

### Task 3: Confidential second-device handoff and restart regressions

**Files:** bin/loki.rs replica/loaders/tests, run-second-device.sh, SECOND-DEVICE-RESULTS.md.

**Interfaces:** The replica copies all selected candidate seed records, commitments, shares and association metadata; AggregateInputs is self-contained. No access to approver key packages, nonces or scan output is permitted. Refuse a nonempty replica destination before writing any bytes. The replica's local directory is private (0700 where supported); seed records use restrictive permissions where practical.

- [x] Add second-device tests with two real inputs and no approver state. For all pair independent finishing fixtures prove signatures precede anchor/witness/proof, then prove/extract with approver files removed and verify extracted sighash and both real nullifiers; the existing live CLI second-device path remains AC unless an existing pair option is present. Test both posted-final and re-proving replica paths load saved seed records. A swapped/missing replica seed fails locally before node broadcast.
- [x] Add restart checks using separate review-sign processes and reload from disk. Save the seed and candidate bytes; validate neither changed across the restart. Check a new session with fresh commit material gets fresh seeds.
- [x] Implement replica copying/manifest updates and seed loading, protect the local handoff directory, and clearly describe the confidential transport requirement. Do not advertise raw seeds as public relay material or implement an unrelated networking/encryption layer.
- [x] Run CLI fixture tests and then `./run-second-device.sh` with isolated state and the selected THS instance. Use the already-built target directory via `CARGO_TARGET_DIR` to avoid needless recompilation. Record actual paths/txids and distinguish any blocked case from a pass.
- [x] Commit as `fix(finisher): carry confidential randomizer seeds in replicas`.

### Task 4: Adversarial harnesses, documentation and PR

**Files:** tamper-tests.sh, nonce-reuse-drill.sh, affected docs and any narrow harness setup fixes necessary for safe validation.

- [x] Extend tamper harness with explicit seed failures and assert exact refusals plus no shares. Snapshot/restore seed association with candidate/commitments so unrelated tests retain their intended oracle.
- [x] Adapt rollback drill to snapshot saved seeds, fixed candidate bytes, commitments and nonce files. Stage A changes commitments or seed against a fixed candidate and must refuse with zero new shares. Stage B deliberately rebuilds a consistent candidate while restoring an already-used nonce, with seed association updated to match; it must continue to expose the nonce-reuse boundary. If ordinary reproposal refuses reused commitments, construct the adversarial rebuilt candidate through a test/tamper-only path rather than weaken normal session checks.
- [x] Update dependencies, intent module docs, threat model and result caveats. State that library-generated seeds remove the custom derivation assumption but do not prove coordinator randomness or supply a security proof/audit. Preserve existing vendor patches and current main's experimental vault changes.
- [x] Inspect `LOKI_STATE`, selected THS endpoints and runtime identities. Use fresh `/private/tmp/loki-issue3-*` state, `${TMPDIR:-/tmp}` portable scratch directories and loopback services. Select the controller-owned `loki-frost-issue3` instance; never start, stop or reset another instance. Preserve main's THS harnesses and removed standalone config. Read `.agents/skills/ths-regtest-verifier/SKILL.md` and THS runtime guidance from the original checkout. Record current source-built Loki binary, runtime image identities and logs under `/private/tmp/loki-issue3-evidence`.
- [x] Run and capture these checks in this worktree, without `--all-features`:

```sh
cd poc
export CARGO_TARGET_DIR=/private/tmp/loki-frost-randomizer-seeds/poc/target
export LOKI_THS_INSTANCE=loki-frost-issue3
cargo build
cargo test
cargo fmt --check
cargo clippy --all-targets
LOKI_STATE=/private/tmp/loki-issue3-regtest-final ./run-regtest.sh
LOKI_STATE=/private/tmp/loki-issue3-second-device-final ./run-second-device.sh
LOKI_STATE=/private/tmp/loki-issue3-tamper ./tamper-tests.sh
LOKI_STATE=/private/tmp/loki-issue3-rollback LOKI_BIN=/private/tmp/loki-frost-randomizer-seeds/poc/target/debug/loki ./nonce-reuse-drill.sh --setup
```

The last drill creates a fresh vault and uses the selected THS faucet to fund its unspent inputs. The controller keeps this isolated instance alive; the harnesses discover loopback endpoints and never manage its lifecycle. Scope formatter changes to affected files where baseline formatting is already broken, and report baseline diagnostics accurately. Do not claim a broad check passes unless its final result does.

- [x] Review the full diff against each acceptance criterion in the spec. Verify git contains no generated state/seeds/secrets. Record actual validation in a concise result document, commit using Conventional Commits, and push only `refactor/frost-randomizer-seeds`.
- [x] Create a PR targeting main, title `refactor(signing): adopt recommended FROST randomizer seeds`, with `Closes #3`, behavior, validation results and limitations. Read the conventional-commits skill first. `gh pr create --body-file` is available; use a temporary file for exact multiline prose.
- [x] Return the PR URL, commit head, tests/harness outcomes and material remaining limitations to the controller. Do not merge the PR.

## Completion Matrix

| Issue requirement | Evidence |
| --- | --- |
| Library seed generation before build/sighash | Task 1 code and reconstruction tests |
| Correct candidate and real-spend association | Tasks 1–3 record validation and multi-input tests |
| Restart and confidential second-device reuse | Task 3 persisted-byte tests and independent live finishing |
| Payment review, local sighash, nullifier equality, alpha/rk checks | Task 2 review/aggregation code and original/expanded regressions |
| Malformed/missing/swapped/changed records; legacy refusal; zero shares | Tasks 2 and 4 refusal assertions |
| AB/AC/BC, signatures before proof/anchor/witness | Task 2 all-pair multi-input fixtures plus live harness |
| Regtest, second device, tamper, nonce rollback | Task 4 actual command results |
| Audit/security limitations and vendor patches retained | Task 4 documentation and full diff review |
| Implementation plan, new Herdr agent, PR | This document, Herdr agent identity, verified open PR |


## Execution evidence

Herdr completed implementation and validation against `754445a`. Final source commit
`265d6a7` passed 76 Rust tests, build and warning-free Clippy. Changed Rust files pass
scoped formatting; repository formatting still fails on five inherited files. All four
THS harnesses exited zero on final stable source; concrete logs, transaction IDs and
limitations are in `poc/FROST-RANDOMIZER-RESULTS.md`. The first tamper run overlapped a
rebase and is explicitly invalid; the final full rerun is the accepted evidence.
PR creation/mergeability are recorded in the final GitHub PR and local audit ledger.

Created [PR #6](https://github.com/amiabix/loki-zcash-frost/pull/6) targeting main.
Final source validation remains commit `265d6a7`; subsequent commits update only
documentation and publication evidence. The controller receives the final branch head
and independently queryable mergeability with the completion report.
