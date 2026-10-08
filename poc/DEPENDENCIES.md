# Loki G1 POC — checkpoint 1: pinned library path

> Historical experiment record. Node build/configuration details below describe the
> original run. Current local-chain setup uses THS; see [harness/README.md](harness/README.md)
> for current local-chain instructions.

Date: 2026-10-03 · Host: macOS 27 aarch64 · `rustc 1.95.0 (59807616e 2026-04-14)`

Result: **2 PASS, 1 PATCHED, 1 BLOCKED.** B2 is patched and verified. B1 stops full G1;
per the 3 October decision the POC proceeds as **G1-TX** around it.

Reproduce everything here with:

```
cd poc
cargo test                              # the two requirements that hold
cargo build --features probe-zip2005    # blocker B1, as a compiler error
(cd vendor/orchard && cargo test --lib loki_b2)   # the B2 patch, 3 tests
```

---

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

Relevant to step 3: `frost_rerandomized::sign` takes an explicit `Randomizer`, which is
what Loki's per-pair α derivation needs. Note it is **deprecated** in 3.0.0 in favour of a
coordinator-generated seed — a path Zcash cannot use, because α is fixed by the
transaction. The explicit call must be kept with `#[allow(deprecated)]`.

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

**Not yet proven:** that anchor and witness can be installed *after* signing without
disturbing the effects sighash. That is step 5's check and needs a live node.

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
explicit canonicality check on both sides. Record this as an assumption for step 3.

---

## B1 — ZIP 2005 `use_qsk` derivation: **BLOCKED, not patchable at POC scope**

The brief requires an FVK from a DKG-derived `ak` plus the ZIP 2005 `use_qsk = true`
derivation, and states that a pre-ZIP-2005 method alone is **not a pass**.

ZIP 2005 specifies, for FROST-generated keys:

```
qsk  --H^qk-->  qk
rivk_ext = H^rivk_ext_qk(ak, nk)      keyed by qk, selected by use_qsk
```

None of it is implemented anywhere:

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

Checkpoint 1 does not pass as written: **G1 is BLOCKED on B1**, and stays blocked until
ZIP 2005's derivation and an independent vector exist.

Per the 3 October decision the POC continues as **G1-TX**, substituting a documented
test-only FVK (see `src/vault.rs`) so the v6 sign-before-proof path can be exercised.
B2 is no longer a blocker. Progress is tracked in `RESULTS.md`.

### Also unresolved, for whoever unblocks B1

- No `zebrad`, `zaino`, `zainod`, `zcashd`, `zcash-cli`, `lightwalletd` or
  `zcash-devtool` on PATH. `zebrad` is now built from source; see `harness/README.md`.
