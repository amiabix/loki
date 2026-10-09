# Zakura Dependency Migration Implementation Plan

> **For agentic workers:** Use the executing-plans skill to implement this plan task-by-task in the dedicated Herdr agent. Steps use checkbox syntax for tracking.

**Goal:** Implement issue #4 by moving Loki's entire production transaction, signing, scanning, and proving graph to compatible Zakura packages while preserving payment approval and saved-artifact behavior.

**Architecture:** Keep existing Rust import names through Cargo `package` aliases. Vendor only the packages requiring local caller-supplied alpha or transitive compatibility changes, rebase the two narrow alpha patches, and resolve one Zakura crypto family. Preserve encoded protocol/state boundaries, remove only conversions caused by obsolete Rust type splits, and retain the FROST 0.6 versus transaction 0.10 RNG boundary.

**Tech Stack:** Rust 2021 Loki application, Zakura Common packages (starting at 2.2.0), Zakura PCZT (starting at 0.1.0-rc4), FROST core/rerandomized 3.0.0, Python THS harnesses, Docker regtest.

**Spec:** https://github.com/amiabix/loki-zcash-frost/issues/4

## Global Constraints

- Regtest only; preserve existing test_only_* key derivation and independent ZIP 2005 setup limitations.
- Keep `frost-core` and `frost-rerandomized` at 3.0.0.
- Preserve recipient, amount, memo, change, exact fee, input, expiry, forbidden-pool, local-sighash, and alpha/rk checks before emitting shares.
- Preserve seed-based signing if issue #3 is present; do not introduce new deprecated signing calls. Existing seed derivation in `intent.rs` is already present on the base; inspect issue #3 and concurrent PRs before finalizing.
- Never commit key packages, nonce secrets, run state, or `demo/.sandbox/`. Synthetic fixture generators may create deterministic test keys at runtime; committed fixture data must contain public artifacts or non-secret hashes only.
- Unsupported saved artifacts must fail explicitly; never silently recreate keys or regenerate/reuse nonces.
- Keep services on loopback. Inspect state paths before harnesses; use fresh disposable paths and a dedicated named THS instance. Do not stop or reset another developer's instance.
- Read `/Users/megabyte/.codex/skills/conventional-commits/SKILL.md` before comments, commits, and PR prose.
- Existing dirty main checkout is unrelated work and must remain untouched.

## Starting evidence and work location

- Dedicated worktree: `/private/tmp/loki-zakura-dependencies`, branch `refactor/zakura-dependencies`.
- `git pull --ff-only origin main` completed on this branch, base `3f66967` (THS migration merged).
- `cd poc && cargo test --locked --lib`: 53 passed, 0 failed on the base.
- Common source inspected at `dec5f56fd0c2a93d78550d14ab44231fd4b779b8`; wallet source at `d7cf5a3ebb4653db4f0c8e5d327bcbb59c9138b5`.
- Common has coordinated version 2.2.0, Rust floor 1.91, `ff`/`group` 0.14 and `rand_core` 0.10. RedPallas FROST explicitly uses `rand_core_06` and an internal RNG adapter.
- Wallet workspace at the issue revision declares PCZT 0.1.0-rc4, semver Common 2.0.0 requirements, `zcash_note_encryption` 0.4.1, `incrementalmerkletree` 0.8.2. These are starting points, not a demonstrated compatible graph. Inspect the published manifests before choosing exact releases.
- Docker CLI/THS exist, but Docker's configured socket was absent at planning time. Diagnose/start the installed Docker app if necessary; record any genuinely unavailable prerequisite rather than claiming live passes.

## File map

| Files | Responsibility |
| --- | --- |
| `poc/Cargo.toml`, `poc/Cargo.lock` | Aliases, pinned versions, patch package identities, compatible production graph |
| `poc/vendor/zakura-orchard/`, `poc/vendor/zakura-primitives/` | Published self-contained forks with minimal alpha changes |
| `poc/vendor/zakura-pczt/` (only if needed) | Narrow transitive manifest compatibility correction; no semantic changes without explicit tests |
| `poc/vendor/*-b2-alpha.patch`, optional PCZT manifest patch, `poc/vendor/README.md` | Reproducible patch diffs and exact provenance |
| `poc/tests/dependency_compatibility.rs`, `poc/tests/fixtures/zakura-migration-public.json` | Old-public-artifact decoding/verification, synthetic serialized-key compatibility and corrupt-artifact rejection |
| `poc/src/candidate.rs`, `intent.rs`, `verify.rs`, `vault.rs`, `zip2005.rs`, `scan.rs`, `witness.rs`, `refresh.rs`, `coordinator.rs`, `nonce_binding.rs`, `bin/loki.rs`, setup modules/tests | Only changes required for APIs, shared field traits, type composition, artifacts, and regression coverage |
| `poc/run-ths.py`, `poc/demo/test_ths.py` or focused harness tests | Pair-selectable live coverage if the existing default AB-only finisher cannot exercise AC/BC |
| `poc/DEPENDENCIES.md`, `README.md`, `poc/RESULTS.md`, dedicated migration result document | Current graph, upstream residuals, artifact policy, measured validation, limitations |

### Task 1: Freeze old-artifact and behavior evidence before changing the graph

**Consumes:** Existing Loki APIs and pinned upstream Cargo.lock on the base.
**Produces:** Public fixtures plus runtime synthetic key serialization compatibility assertions.

- [x] Read issue #3, `README.md`, `poc/THREAT-MODEL.md`, `poc/RESULTS.md`, `poc/SECOND-DEVICE-RESULTS.md`, `poc/DEPENDENCIES.md`, `poc/vendor/README.md`, and relevant tests. Save the selected original graph/provenance in the migration results document.
- [x] Run the full baseline `cd poc && cargo test --locked`, `cargo build --locked`, `cargo fmt --check`, and `cargo clippy --locked --all-targets` (exclude the intentional `probe-zip2005` feature). Record warnings separately from failures.
- [x] Generate deterministic synthetic 2-of-3 shares using `rand_chacha::ChaCha20Rng::from_seed([42; 32])` under the old graph. Capture hashes of serialized key packages and public-key-package bytes, identifiers, group key, a randomized signature and its message/alpha, and a deterministic unproved PCZT. Do not commit private key package or nonce bytes. Build the fixture generator as temporary test code before the dependency edit, and retain only non-secret fixture data and the deterministic reproduction in the final tests.

```rust
use rand_core::SeedableRng;
use reddsa_frost::frost::redpallas as frost;
let mut rng = rand_chacha::ChaCha20Rng::from_seed([42; 32]);
let (shares, public) = frost::keys::generate_with_dealer(
    3, 2, frost::keys::IdentifierList::Default, &mut rng,
).unwrap();
for (id, share) in shares {
    let key = frost::keys::KeyPackage::try_from(share).unwrap();
    let encoded = key.serialize().unwrap();
    assert_eq!(frost::keys::KeyPackage::deserialize(&encoded).unwrap().serialize().unwrap(), encoded);
    // Persist a non-secret digest and public identifier, never `encoded`.
    let digest = blake3::hash(&encoded).to_hex().to_string();
    assert!(!digest.is_empty());
    assert!(!id.serialize().is_empty());
}
assert!(!public.serialize().unwrap().is_empty());
```

- [x] Use `candidate.rs`'s existing synthetic-note setup and a transaction RNG seeded deterministically to capture the old PCZT. Treat PCZTs with note secrets as sensitive: construct a redacted public fixture through `pczt::roles::redactor` if possible, or store only non-secret hashes and create the full artifact at test runtime. State exactly which bytes were checked.
- [x] Tests must decode old public fixtures under the migrated graph, check byte round trips and signature verification, regenerate deterministic runtime keys and compare old serialization digests, and reject malformed/corrupted saved artifacts without creating share files. For an incompatible format, document rejection and exercise CLI reads with a temporary synthetic artifact; no key replacement or nonce reset.
- [x] Retain the existing `c3_two_notes_become_two_spends_with_distinct_rk`, mismatch-alpha count, DKG, share-verification, refresh, and approval test cases. Add a case matching each spend by its nullifier after builder shuffling to establish alpha association independently of output order.

### Task 2: Vendor Zakura and resolve a coherent package graph

**Consumes:** Old fixture evidence and inspected published Zakura manifests.
**Produces:** Locked aliased production graph and reproducible alpha patches.

- [x] Download/extract exact published Common crate sources (starting 2.2.0) and PCZT (starting 0.1.0-rc4). Record registry checksums, repository revisions when known, and package versions. Prefer self-contained published manifests to workspace-inherited Git manifests. Keep upstream licences.
- [x] Create `poc/vendor/zakura-orchard/` and `poc/vendor/zakura-primitives/`. Rebase the old patches on their actual builder code, not with blind text substitution. Carry over all three `loki_b2_alpha` tests.

```rust
// In SpendInfo, initialized to None at every existing construction site:
pub(crate) alpha: Option<pallas::Scalar>,
// In the original alpha sampling location:
let alpha = self.alpha.unwrap_or_else(|| pallas::Scalar::random(&mut rng));
let rk = ak.randomize(&alpha);
```

- [x] Preserve `SpendInfo::new_with_alpha`, `unwitnessed_with_alpha`, `Builder::add_spend_unwitnessed_with_alpha(fvk, note, alpha)` and `DeferredPcztBuilder::add_ironwood_spend_with_alpha<FE>(fvk, note, alpha) -> Result<(), Error<FE>>`. The primitives method must retain the V3 note-version check and delegate through the Orchard builder; never rewrite rk on a built PCZT.
- [x] Replace dependencies using real package names. The initial manifest shape is:

```toml
orchard = { package = "zakura-orchard", version = "=2.2.0" }
zcash_primitives = { package = "zakura-primitives", version = "=2.2.0" }
pczt = { package = "zakura-pczt", version = "=0.1.0-rc4", features = ["orchard", "signer", "io-finalizer", "prover", "spend-finalizer", "tx-extractor", "zcp-builder"] }
reddsa_frost = { package = "zakura-reddsa", version = "=2.2.0", features = ["frost"] }
pasta_curves = { package = "zakura-pasta-curves", version = "=2.2.0" }
zcash_address = { package = "zakura-address", version = "=2.2.0" }
zcash_protocol = { package = "zakura-protocol", version = "=2.2.0" }
zcash_transparent = { package = "zakura-transparent", version = "=2.2.0" }
sapling-crypto = { package = "zakura-sapling-crypto", version = "=2.2.0" }
frost-core = { version = "=3.0.0", features = ["serialization"] }
frost-rerandomized = { version = "=3.0.0", features = ["serialization"] }

[patch.crates-io]
zakura-orchard = { path = "vendor/zakura-orchard" }
zakura-primitives = { path = "vendor/zakura-primitives" }
```

- [x] Verify PCZT's actual published transitive graph. Resolve matching note-encryption and Merkle-tree versions from compiler/public-type evidence; update direct dependencies accordingly. If the selected PCZT still requires incompatible 0.4 note encryption alongside Common 0.5, vendor PCZT and patch only the manifest edge to the matching version, adding `zakura-pczt` to `[patch.crates-io]` and recording a separate patch. A later published compatible PCZT release is an alternative only after documenting exact versions and verifying its APIs/artifacts. Do not suppress type errors by retaining a second upstream crypto universe.
- [x] Run `cargo metadata --format-version 1` and `cargo tree --edges normal,build`. Inspect the graph for upstream orchard, reddsa, pasta_curves, primitives, PCZT, Sapling, halo2, jubjub, bellman, and corresponding proving dependencies. Document intentional remaining upstream utility/protocol crates and RNG versions. Add a focused automated production-graph assertion if useful; exclude dev-only differential oracle edges explicitly.
- [x] Delete old `vendor/orchard/` and `vendor/zcash_primitives/` once replaced. Regenerate patch files against clean exact downloaded releases; verify patches apply cleanly to pristine sources.

### Task 3: Adapt APIs and preserve approval and artifact handling

**Consumes:** Zakura graph and rebased builders.
**Produces:** Compiling Loki with preserved checked protocol/state boundaries.

- [x] Run `cd poc && cargo check --locked --all-targets` and fix actual API differences at their source. Align direct `ff`/`group` traits to 0.14 when types compose; remove obsolete `ff_zp` aliases only when no call site needs them.
- [x] Use typed `Randomizer::from_scalar`/shared scalar interfaces where public APIs permit. `Randomizer::to_scalar` is crate-private in FROST 3.0.0, so do not assume it is callable. Keep serialization where it is a genuine saved/wire/canonical-validation boundary or an API exposes no scalar getter. Remove stale comments claiming two unrelated Pallas type universes.
- [x] Retain `rand_core` 0.6 for FROST APIs and deterministic nonce tests, plus transaction RNG 0.10. Do not make custom entropy adapters unless an actual public API boundary requires one; Zakura already provides its internal FROST adapter.
- [x] Preserve current `alpha_seed` domain separation, commitment-based derivation, pair sorting, per-spend indices, local sighash, and rk verification. Existing calls to the deprecated explicit-randomizer signing API are coordinated with #3; migrate to its seed flow if merged/present, otherwise preserve behavior and document the coordination.
- [x] Run the compatibility tests from Task 1 and all existing Rust tests. If a fixture is incompatible, prove explicit refusal without output or file regeneration and document supported/rejected formats; do not weaken validation merely to round trip.
- [x] Verify two-input association through shuffled actions by nullifier, sign each real spend under the expected alpha, install witnesses/anchor afterward, prove/extract, and check the effects sighash is unchanged. Preserve mismatch count rejection and distinct rk checks.
- [x] Run vendor regression tests using `cargo test --manifest-path vendor/zakura-orchard/Cargo.toml --lib loki_b2`; ensure standalone vendor test resolution uses the intended family/patches.

### Task 4: Prove AB, AC, BC and independent finishing on THS

**Consumes:** Migrated built CLI and existing THS adapter/harnesses.
**Produces:** Live mined payment evidence for every pair, tamper/handoff/nonce results.

- [x] Read `poc/harness/README.md`, `run-ths.py`, `run-second-device.sh`, `tamper-tests.sh`, and `nonce-reuse-drill.sh`. Inspect current `LOKI_STATE`, `LOKI_THS_INSTANCE`, `BOB_STATE`, and `ATTIC` without printing unrelated environment secrets. Select fresh paths and a dedicated THS name.
- [x] Diagnose Docker/THS, start only a dedicated disposable instance, and discover loopback endpoints. Verify the selected runtime image/version and NU6.3 branch `37a5165b`. If needed, start the installed Docker application; never prune shared resources or replace the node.
- [x] The current harness signs all members, while local finishing and handoffs hardcode AC. Add `--pair {AB,AC,BC}` to `run-ths.py` (default AB for the new harness option) and select only the requested pair's available shares before finishing, while allowing every member to publish its existing commitments. Thread pair selection through local finishing, posted final transactions, replication, independent finishing, and chain-effects verification; preserve AC as the historical CLI default. Exercise independent finisher access without approver secret directories. Test command plumbing and require the resulting receipt to name the selected pair.

```python
PAIR_MEMBERS = {"AB": ("alice", "bob"), "AC": ("alice", "carol"), "BC": ("bob", "carol")}
parser.add_argument("--pair", choices=tuple(PAIR_MEMBERS), default="AB")
for member in PAIR_MEMBERS[args.pair]:
    loki("review-sign", state, member)
```

- [x] Run the standard required harnesses and additional pair coverage:

```sh
cargo build --locked
./run-regtest.sh
./run-second-device.sh
./tamper-tests.sh
python3 run-ths.py --name loki-zakura-issue4 --pair AB --finish-mode replica
python3 run-ths.py --name loki-zakura-issue4 --pair AC --finish-mode replica
python3 run-ths.py --name loki-zakura-issue4 --pair BC --finish-mode replica
```

- [x] Run `nonce-reuse-drill.sh` against fresh funded/unspent disposable state, not a state whose payment already consumed its note. Assert stage A refusal/no shares and preserve stage B's measured rollback reuse limitation; its weak exit code alone does not prove stage B ran successfully. Record output observations explicitly.
- [x] Record actual txids, selected pair, sign-before-anchor/proof checks, unchanged sighashes, mined confirmation heights, independent finishing and nine refused tamper cases/no shares. Fee-only fixture remains unconstructible unless a genuinely equivalent test is added. Report skipped/blocked cases distinctly from passes.
- [ ] Stop only the THS instance created for this work after validation; keep secrets and state outside tracked files. Root owns this instance and will perform shutdown after independent validation.

### Task 5: Documentation, review, and PR delivery

**Consumes:** Locked graph, fixtures, test/harness evidence.
**Produces:** Reviewable implementation commits and PR closing #4 when all acceptance checks are satisfied.

- [x] Update `poc/DEPENDENCIES.md` with exact final package versions, matching PCZT transitive dependencies, residual upstream dependencies, RNG boundary, artifact results, and continued key-derivation limitations. Preserve dated historical findings as historical rather than presenting the old graph as current.
- [x] Update `poc/vendor/README.md`, root README vendor names/licences, and migration results. Record patch base revisions/checksums, paths, reproducible commands, audit provenance (fork ancestry is not audit coverage), and no intended approval-policy change.
- [x] Final checks: `cargo build --locked`, `cargo test --locked`, `cargo fmt --check`, `cargo clippy --locked --all-targets`, focused vendor alpha tests, relevant Python harness tests, and all Task 4 live checks. No intentional probe feature in routine checks.
- [x] Review the final diff against every issue requirement, including multiple-input alpha association, old artifact handling, seed-flow coordination, and production graph closure. Fix actionable findings and rerun affected checks.
- [ ] Commit only relevant changes using Conventional Commits, for example `refactor(deps): migrate transaction and crypto stack to Zakura`. Do not stage temporary generators, synthetic secret state, registry extraction metadata secrets, or unrelated main changes.
- [ ] Root agent independently reviews evidence, pushes `refactor/zakura-dependencies`, and creates a PR against main with a concrete behavior description, `Closes #4` when verified, actual validation results, and material limitations. PR creation is already authorized by the user; no further approval ceremony is required.

## Completion audit

Every issue acceptance item maps to a task: production family closure (2), DKG/signature/share/refresh and serialized artifacts (1/3), three pairs/independent finishing/unchanged sign-before-proof/multi-input association (3/4), tamper/no-share/handoff/nonce reuse (4), build/test/fmt/clippy and patch tests (3/5), dependency/vendor documentation and #3 coordination (2/3/5). A green build alone is insufficient; pending live gates remain pending.
