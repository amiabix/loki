# Loki dependency graph

## Current graph — 9 October 2026

Issue #4 migrates transaction construction, signing, scanning, witness construction,
PCZT roles, and proving to one Zakura family. Cargo aliases preserve existing Rust
import names and application payment interfaces; library API call sites are adapted
where required by the selected releases. The Common releases require Rust 1.91 or later.

| Existing import | Exact package/version |
| --- | --- |
| `orchard` | `zakura-orchard 2.2.0`, local alpha patch |
| `zcash_primitives` | `zakura-primitives 2.2.0`, local alpha delegation patch |
| `pczt` | `zakura-pczt 0.1.0-rc4`, unmodified registry release |
| `reddsa_frost` | `zakura-reddsa 2.2.0`, `frost` feature |
| `pasta_curves` | `zakura-pasta-curves 2.2.0` |
| `zcash_address`, `zcash_protocol`, `zcash_transparent` | `zakura-address`, `zakura-protocol`, `zakura-transparent` 2.2.0 |
| `sapling_crypto` | `zakura-sapling-crypto 2.2.0` |
| `frost_core`, `frost_rerandomized` | `frost-core`, `frost-rerandomized` exactly 3.0.0 |

The locked production graph contains 20 Zakura packages: these direct packages and
`zakura-bellman`, `zakura-bls12-381`, `zakura-equihash`, `zakura-halo2-gadgets`,
`zakura-halo2-legacy-pdqsort`, `zakura-halo2-poseidon`, `zakura-halo2-proofs`,
`zakura-jubjub`, `zakura-pairing`, `zakura-redjubjub`, and `zakura-sinsemilla`. All
Common packages resolve to 2.2.0. No upstream Orchard, RedDSA, Pasta, PCZT,
primitives, Sapling, Halo 2, Jubjub, Bellman, BLS12-381, pairing, or Sinsemilla
package remains on normal/build edges. `tests/test_dependency_graph.py` checks this
production closure using `cargo tree --locked --edges normal,build`; no differential
old-graph oracle is included as a dev dependency.

The published PCZT/Common manifests compose with `zcash_note_encryption 0.4.2`
and `incrementalmerkletree 0.8.2`. The planned optional PCZT manifest patch is
unnecessary. Intentional remaining upstream utilities include `ff/group 0.14.0`,
`zcash_encoding 0.4.0`, `zcash_script 0.4.5`, `zcash_spec 0.2.1`, `zip32 0.2.1`,
`f4jumble 0.1.1`, `corez 0.1.1`, serialization, hash, KDF/AEAD, and separate-member
Ed25519/X25519 transport dependencies. These do not reintroduce a Zcash crypto family.

FROST 3.0.0 retains `rand_core 0.6.4` and deterministic tests use `rand_chacha
0.3.1`. Transactions use `rand_core 0.10.1` and `rand 0.10.3`. Zakura adapts RNGs
internally for its FROST ciphersuite. PCZT rc4 uses an internal system RNG for IO
finalization, proving, and extraction rather than accepting an RNG argument. No
application entropy adapter was added. Shared Pallas types compose with `ff/group
0.14`; the obsolete `ff_zp` alias is removed. Canonical bytes remain at saved/wire
boundaries and where FROST exposes no scalar getter (`Randomizer::to_scalar` is
private).

`zakura-primitives` pins `crypto-common = 0.2.0-rc.1`. That conflicts with the
stable 0.2 requirement of `chacha20poly1305 0.11.0`, so Loki uses 0.10.1, which
also matches note encryption. This changes the Rust nonce API, not the LOKISEAL
header, Argon2 parameters, AAD, XChaCha20-Poly1305 construction, or ciphertext
format. An independent 0.11.0 oracle generated a sealed **public** payload;
`MemberDir::read_sealed` opens those exact old bytes and leaves the file unchanged.
Wrong-passphrase and authentication-tamper tests remain enforced.

Compatibility evidence was captured under the old graph **before** editing dependencies:
public-package and identifier byte round trips, old randomized-signature verification,
three deterministic key-package serialization hashes, a redacted unproved PCZT byte
round trip, and exact hashes of deterministic full unproved PCZT bytes. Synthetic
private keys and complete candidates are regenerated at test runtime. Fixtures contain
only public bytes or hashes; none contains a key package, nonce, or note secret. Actual
CLI `commit`/`review-sign` tests reject corrupt/truncated keys and corrupt/truncated/
unknown-version PCZTs with the expected reason, zero shares, and byte-identical key,
nonce, commitment, and proposal state. Supported old artifacts require no regeneration.

The original migration was validated while issue #3 remained open, preserving its
then-current custom flow. Integration of main at `10a91fe` retains merged PR #6's
recommended generated-seed API: saved records reconstruct the exact parameters and
production review signs with `sign_with_randomizer_seed`. Key and PCZT byte
compatibility is retained; legacy signing sessions without seed records are explicitly
refused rather than regenerated, as required by #3. This migration adds no production
deprecated signing calls.
Payment approval, local sighash, nullifier equality, alpha/rk checks, and forbidden-pool
checks are unchanged. Test-only payment FVK derivation and the independent, unreviewed
ZIP 2005 setup path remain separate limitations. Fork ancestry is not audit coverage.

See [migration results](ZAKURA-MIGRATION-RESULTS.md) for actual offline and live evidence,
and [vendor provenance](vendor/README.md) for reproducible patches and checksums.

## Historical checkpoint 1: pinned library path

The following dated record describes the replaced graph and its original findings.
Use the current graph above for dependencies and RNG/API composition.

> Historical experiment record. Node build/configuration details below describe the
> original run. Current local-chain setup uses THS; see [harness/README.md](harness/README.md)
> for current local-chain instructions.

Date: 2026-10-03 · Host: macOS 27 aarch64 · `rustc 1.95.0 (59807616e 2026-04-14)`

Historical checkpoint result: **2 PASS, 1 PATCHED, 1 BLOCKED.** B2 is patched and verified. B1 stops full G1;
per the 3 October decision the POC proceeds as **G1-TX** around it.

Reproduce everything here with:

```
cd poc
cargo test                              # the two requirements that hold
cargo build --features probe-zip2005    # blocker B1, as a compiler error
(cd vendor/orchard && cargo test --lib loki_b2)   # the B2 patch, 3 tests
```

---

## docs(signing): current recommended seed flow

The 9 October refactor keeps this pinned graph and both caller-alpha vendor patches.
For each real spend and pair, `RandomizedParams::new_from_commitments(group_key,
&commitments, OsRng)` returns parameters and a fresh 32-byte seed before candidate
construction and sighash calculation. Canonical serialization bridges the library
randomizer to the patched builder. Saved records bind the proposal, pair, spend index,
nullifier and exact commitments; review and finishing use
`regenerate_from_seed_and_commitments`, and review signs with
`sign_with_randomizer_seed`. Zcash can use the recommended API by generating α before
the builder fixes `rk`; there is no requirement to keep the deprecated direct-scalar
API in production.

This removes the custom seed derivation assumption, without proving coordinator RNG
use, repairing nonce reuse/rollback, establishing a security proof, or extending NCC
audit coverage to rerandomized FROST. Seed handoff must be confidential. Current
validation, separate from the historical checkpoint below, is recorded in
[FROST-RANDOMIZER-RESULTS.md](FROST-RANDOMIZER-RESULTS.md).

## Pinned versions

Resolved and locked in `Cargo.lock`. The 1 October list was the starting point; these
are what actually compose.

| Crate | Pinned | Note |
|---|---|---|
| `orchard` | 0.16.0 | Ironwood present: `ValuePool::Ironwood`, `IronwoodVersion` note-encryption domain, post-NU6.3 circuit |
| `zcash_primitives` | 0.31.0-pre.0 | carries `DeferredPcztBuilder` |
| `pczt` | 0.10.0-pre.0 | 285 Ironwood references incl. `ironwood_anchor: None` |
| `frost-core` | 3.0.0 | |
| `frost-rerandomized` | 3.0.0 | |
| `reddsa` (as `reddsa_frost`) | **0.5.2** | FROST ciphersuite. See F3 |
| `reddsa` (transitive, via orchard) | 0.6.1 | no FROST module at all |

Deviations from the 1 October list, each forced:

- **`zcash_protocol` cannot be pinned to 0.7.** Every `core2 ^0.3` release is yanked, so
  0.7.0 is unresolvable. Left transitive; resolves to 0.11.0-pre.0.
- **`pczt` has no `verifier` *feature*, but it does have the role.** `roles::verifier`
  compiles unconditionally, as do `creator`, `updater`, `redactor` and
  `low_level_signer`; only `io-finalizer`, `prover`, `signer`, `spend-finalizer` and
  `tx-extractor` are feature-gated. An earlier draft of this file read the missing
  feature as a missing role. **It is not:** step 4 can use `Verifier` directly.
- **`reddsa 0.6.1` has no `frost` feature.** See F3.

---

## F1 — FROST Pallas ciphersuite: **PASS**

DKG, preprocessing, rerandomized signing, share verification and aggregation are all
present in `reddsa 0.5.2`'s `frost::redpallas`.

- `c1_1_frost_pallas_signs_under_a_caller_supplied_alpha` — 2-of-3 keygen, `round1::commit`,
  `frost_rerandomized::sign` under an α **we** supply, `aggregate`, and verification under
  the randomized group key.
- `c1_1_dkg_three_members_reach_one_group_key` — three-member `dkg::part1/2/3`, all three
  members reach the same group key, and it has even y (required for an Orchard `ak`).

The original checkpoint exercised the now-deprecated explicit `Randomizer` API.
Current production signing uses the recommended persisted-seed API described above.
Direct-scalar calls remain only where adversarial research tests deliberately need them.

---

## F2 — deferred v6 PCZT path: **PASS**

`zcash_primitives::transaction::builder::DeferredPcztBuilder` exists at
`builder.rs:475`, with the methods G1 needs:

```
new(..)                     with_expiry_height(..)
add_orchard_spend(..)       add_ironwood_spend(..)
add_orchard_output(..)      add_ironwood_output(..)
add_orchard_change_output(..)
get_fee(..)                 build_for_pczt(..)
```

`pczt 0.10.0-pre.0` models the deferred anchor directly (`roles.rs:166`,
`ironwood_anchor: None`). `c1_3_deferred_pczt_builder_and_ironwood_roles_resolve`
compiles against both.

**At this checkpoint, not yet proven:** installation of anchor and witness after signing
without disturbing the effects sighash. The subsequent historical regtest run in
[RESULTS.md](RESULTS.md) demonstrated it.

---

## F3 — the graph splits into two crypto universes

`orchard 0.16.0` requires `reddsa = "0.6"` (`Cargo.toml:217-219`). **`reddsa 0.6.1`
deleted `src/frost/` entirely** — its features are now only `alloc, default, hex,
internal, nightly, serde, std, thiserror, zeroize`. There is no standalone
`frost-redpallas` crate on crates.io.

So FROST RedPallas exists only in `reddsa 0.5.x`, and the resolved graph contains both:

| | FROST side | Orchard side |
|---|---|---|
| `reddsa` | 0.5.2 | 0.6.1 |
| `pasta_curves` | 0.5.2 | 0.6.0 |
| `group` / `ff` | 0.13 | 0.14 |

20 crates appear at two versions. **Consequence:** the FROST group key and orchard's `ak`
are different Rust types from different crate versions. They can meet only through
32-byte serialization, which does work and is exercised in
`c1_2_group_key_becomes_an_address_but_only_pre_zip2005`.

This also applies to α: `frost_rerandomized::Randomizer` (pasta 0.5) and the builder's
`pallas::Scalar` (pasta 0.6) must be converted byte-wise, and the conversion needs an
explicit canonicality check on both sides. The current seed flow retains explicit canonicality checks at this boundary.

---

## B1 — ZIP 2005 `use_qsk` derivation: **local implementation, not yet a G1 pass**

9 October update: `src/zip2005.rs` implements the current proposed derivation for
separate-member regtest setup. Its FVK bytes match an independently calculated
Python `hashlib`/`blake3` vector. Orchard still has no upstream API, the implementation
has no independent security review, and no payment from this derived FVK has been
mined. The compile probe below now records the **upstream API gap**, not the absence
of a local implementation. Public testnet and custody use remain blocked.

The brief requires an FVK from a DKG-derived `ak` plus the ZIP 2005 `use_qsk = true`
derivation, and states that a pre-ZIP-2005 method alone is **not a pass**.

ZIP 2005 specifies, for FROST-generated keys:

```
qsk  --H^qk-->  qk
rivk_ext = H^rivk_ext_qk(ak, nk)      keyed by qk, selected by use_qsk
```

At the dates checked below, none of it was implemented in these upstream crates:

| Source | Checked | `qsk` occurrences |
|---|---|---|
| `orchard` 0.16.0 (crates.io) | 2026-10-03 | **0** |
| `zcash/orchard` HEAD `616a669d` | 2026-09-30 | **0** |
| `zcash/librustzcash` HEAD `9c5705f5` | 2026-10-02 | **0** |
| `pczt` 0.10.0-pre.0, `zcash_primitives` 0.31.0-pre.0 | 2026-10-03 | **0** |

Ironwood itself *is* implemented (178 references in the orchard repo). It is specifically
the quantum-key derivation that is absent. **ZIP 2005 is `Status: Proposed`, not Final.**

`orchard::keys::FullViewingKey` exposes exactly one constructor, `from_bytes(&[u8; 96])`
over `ak || nk || rivk`. `CommitIvkRandomness` is private and reachable only
`From<&SpendingKey>`, which is the pre-ZIP-2005 path.

Smallest failing call — `cargo build --features probe-zip2005`:

```
error[E0433]: cannot find `QuantumIntermediateKey` in `keys`                  src/lib.rs:38
error[E0603]: struct `CommitIvkRandomness` is private                         src/lib.rs:39
error[E0599]: no function `from_qk` for `keys::CommitIvkRandomness`           src/lib.rs:39
error[E0599]: no function `from_parts_with_qsk` for `FullViewingKey`          src/lib.rs:40
```

**Required upstream change:** implement ZIP 2005 key derivation in `orchard` — `H^qk`,
`H^rivk_ext`, the `use_qsk` selector on `rivk` derivation, and a public `FullViewingKey`
constructor taking `(ak, nk, rivk_ext, use_qsk)`. This is new cryptographic surface for a
Proposed ZIP, not a small isolated patch, and it is outside what this brief authorizes.

---

## B2 — caller-selected `alpha`: **PATCHED and verified**

`orchard::builder::SpendInfo::build` samples α itself and exposes no seam:

```rust
// orchard-0.16.0/src/builder.rs:449
let alpha = pallas::Scalar::random(&mut rng);
let rk = ak.randomize(&alpha);
```

`SpendInfo::new(fvk, note, merkle_path)` (`builder.rs:366`) took no α, and neither did
`Builder::add_spend_unwitnessed` or `DeferredPcztBuilder::add_ironwood_spend`, so the
value could not reach a deferred-witness spend at all.

**This is the patch the brief anticipates**, applied at the single point where α is
sampled plus the two methods needed to thread it there:

1. Add `SpendInfo { alpha: Option<pallas::Scalar> }`, defaulting to `None`.
2. Add `SpendInfo::new_with_alpha(..)` setting it.
3. In `build()` (`:449`), use `self.alpha.unwrap_or_else(|| pallas::Scalar::random(&mut rng))`.

4. `Builder::add_spend_unwitnessed_with_alpha(..)` in orchard.
5. `DeferredPcztBuilder::add_ironwood_spend_with_alpha(..)` in `zcash_primitives`.

Verified by `loki_b2_alpha::{rk_follows_the_caller_selected_alpha,
a_chosen_alpha_is_deterministic_across_builds,
without_a_chosen_alpha_the_builder_still_samples}` inside the patched crate, and
end-to-end through the deferred builder by
`c3_three_candidates_share_effects_and_differ_only_in_rk`.

`rk` continues to be derived from α inside `build()`, so nothing mutates `rk` or a built
PCZT afterwards, as the brief requires. α already flows into `crate::pczt::Spend`
(`builder.rs:469`, `alpha: Some(alpha)`), so the value is followed through the PCZT
without further change. Vendor `orchard` at `616a669d` plus this patch and record both.

---

## What this means for the sequence

The original checkpoint did not pass as written: **G1 was BLOCKED on B1**. Current
main (`3f66967`) includes experimental separate-member ZIP 2005 derivation, an
independent vector and a backup gate; this refactor preserves them. Full G1 remains
unestablished pending review/upstream support and a payment from the derived FVK.

Per the 3 October decision the POC continues as **G1-TX**, substituting a documented
test-only FVK (see `src/vault.rs`) so the v6 sign-before-proof path can be exercised.
B2 is no longer a blocker. Progress is tracked in `RESULTS.md`.

### Historical node availability at checkpoint 1

- No `zebrad`, `zaino`, `zainod`, `zcashd`, `zcash-cli`, `lightwalletd` or
  `zcash-devtool` on PATH at that checkpoint. A standalone `zebrad` was subsequently
  built for the original run. Current chain flows use THS; see `harness/README.md`.
