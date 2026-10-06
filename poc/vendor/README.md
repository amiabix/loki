# Vendored upstream

## orchard

- Upstream: https://github.com/zcash/orchard
- Pinned commit: `616a669df8c9a59c33d47064d3ce04b25d026b2e` (2026-09-30)
- Version at that commit: `0.16.0` (identical to the crates.io release)
- Local change: `orchard-b2-alpha.patch`, applied to `src/builder.rs` only

### Why

`SpendInfo::build()` sampled the spend-authorization randomizer internally
(`let alpha = pallas::Scalar::random(&mut rng)`), so a FROST signer set had no way to
agree on it beforehand. ZIP 312 requires every signer to sign under the same `alpha`, and
on Zcash that value is fixed by the transaction rather than chosen by a coordinator.

### What the patch does

1. `SpendInfo` gains `alpha: Option<pallas::Scalar>`, defaulting to `None` at all four
   construction sites, so upstream behaviour is byte-for-byte unchanged when unset.
2. Adds `SpendInfo::new_with_alpha(..)` and `unwitnessed_with_alpha(..)`.
3. `build()` uses `self.alpha.unwrap_or_else(|| pallas::Scalar::random(&mut rng))`.
4. Adds `Builder::add_spend_unwitnessed_with_alpha(..)`, because the deferred-witness
   path goes through the Builder and `add_spend_unwitnessed` has no seam for alpha.

`rk` is still derived from `alpha` inside `build()`, and `alpha` already flowed into
`crate::pczt::Spend`. Nothing mutates `rk` or a built PCZT afterwards.

Verified by `b2_patch_makes_rk_follow_the_caller_selected_alpha`.

## zcash_primitives

- Upstream: crates.io `zcash_primitives 0.31.0-pre.0`
- Local change: `zcash_primitives-b2-alpha.patch`, applied to
  `src/transaction/builder.rs` and `Cargo.toml`

`DeferredPcztBuilder::add_ironwood_spend` calls orchard's `add_spend_unwitnessed`, which
takes no alpha, so the value could not reach the spend. The patch adds
`add_ironwood_spend_with_alpha(fvk, note, alpha)` alongside it, delegating to the orchard
method above, and adds `pasta_curves 0.6` as a dependency for the parameter type. That is
the version orchard already pulls, so no new crate enters the graph.

The original method is untouched: callers that do not need a chosen alpha behave exactly
as before.
