# Vendored Zakura packages

Loki uses exact published crates with two narrow caller-alpha patches. The normalized
published manifests are self-contained; `Cargo.toml.orig` and upstream licences are
retained for provenance. No Git workspace inheritance is needed to build Loki.

| Package | Version | Published source revision | Archive SHA-256 (registry checksum) |
| --- | --- | --- | --- |
| `zakura-orchard` | 2.2.0 | Common `b6cf4cefe38fdccc6d2b0dc868f7d6ef01683413`, `crates/orchard` | `b460a562603ba2e9820cb988b5f873ef470bd007c6c2f86e50abaa91b45e241e` |
| `zakura-primitives` | 2.2.0 | Common `b6cf4cefe38fdccc6d2b0dc868f7d6ef01683413`, `crates/zcash_primitives` | `1799865d3780d60184209d04132037d4179e3fa6dbf9daf525966a967a0472c4` |
| `zakura-pczt` (registry, unmodified) | 0.1.0-rc4 | wallet `f94186c7153ba14af6f9ce21898942c2c788d611`, `librustzcash/pczt` | `d9804652bad6d01e18e4ce5b993aacdb1eaa1cfaa08a63f53d252fc3bdce6814` |

The revisions above come from each published `.cargo_vcs_info.json`; archive hashes
were calculated before extraction. Source repositories are
[Zakura Common](https://github.com/zakura-core/common) and
[wallet libraries](https://github.com/zakura-core/wallet-libraries). Both vendored
packages declare `MIT OR Apache-2.0`; upstream `COPYING.md`, `LICENSE-MIT`, and
`LICENSE-APACHE` files are retained where supplied. Fork ancestry does not extend an
upstream audit to these releases, the local patches, or Loki's integration.

## Caller-selected alpha

`zakura-orchard-b2-alpha.patch` changes only `src/builder.rs`:

- `SpendInfo` carries `Option<pallas::Scalar>`, initialized to `None` at all four
  construction sites.
- `new_with_alpha`, `unwitnessed_with_alpha`, and
  `Builder::add_spend_unwitnessed_with_alpha` preserve the original ownership,
  spend-enabled, and deferred-witness checks.
- At the original sampling site, `Some(alpha)` supplies the randomizer and `None`
  samples it as upstream does. `rk` remains derived there; no built PCZT is rewritten.
- The three `loki_b2_alpha` tests verify chosen-alpha/rk binding, deterministic chosen
  alpha across builds, and continued sampling when alpha is absent.

`zakura-primitives-b2-alpha.patch` changes its normalized `Cargo.toml` and
`src/transaction/builder.rs`. It adds the shared `zakura-pasta-curves 2.2.0` type
alias and `DeferredPcztBuilder::add_ironwood_spend_with_alpha`, preserving the V3
note-version check and delegating through the Orchard builder. This adds no second
Pallas family. Existing unparameterized methods retain their behavior.

The actual published manifests consistently require note-encryption 0.4 and Merkle
0.8. Loki resolves `zcash_note_encryption 0.4.2` and `incrementalmerkletree 0.8.2`.
PCZT therefore needs no local manifest correction or vendoring.

## Reproduce the patch base

From `poc/`, use a new disposable directory for pristine sources:

```sh
mkdir -p /tmp/loki-zakura-pristine
curl -fLsS https://static.crates.io/crates/zakura-orchard/zakura-orchard-2.2.0.crate -o /tmp/zakura-orchard-2.2.0.crate
curl -fLsS https://static.crates.io/crates/zakura-primitives/zakura-primitives-2.2.0.crate -o /tmp/zakura-primitives-2.2.0.crate
shasum -a 256 /tmp/zakura-orchard-2.2.0.crate /tmp/zakura-primitives-2.2.0.crate
tar -xzf /tmp/zakura-orchard-2.2.0.crate -C /tmp/loki-zakura-pristine
tar -xzf /tmp/zakura-primitives-2.2.0.crate -C /tmp/loki-zakura-pristine
patch -d /tmp/loki-zakura-pristine/zakura-orchard-2.2.0 -p1 < vendor/zakura-orchard-b2-alpha.patch
patch -d /tmp/loki-zakura-pristine/zakura-primitives-2.2.0 -p1 < vendor/zakura-primitives-b2-alpha.patch
cargo test --locked --manifest-path vendor/zakura-orchard/Cargo.toml --lib loki_b2
```

Both patches were applied to freshly extracted releases and the resulting files were
compared byte-for-byte with the vendored implementation. The standalone Orchard
lockfile resolves the same Zakura 2.2.0 family; its additional dependencies serve
upstream tests and benchmarks, not Loki's production graph.

Historical bases were `orchard 0.16.0` at Zcash commit
`616a669df8c9a59c33d47064d3ce04b25d026b2e` and published
`zcash_primitives 0.31.0-pre.0`. Those trees and patches have been replaced. See
[dependency history](../DEPENDENCIES.md) and
[migration results](../ZAKURA-MIGRATION-RESULTS.md).
