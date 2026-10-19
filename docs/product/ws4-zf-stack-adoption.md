# WS4 — ZF Stack Adoption

Parent: `00-architecture.md`. Upholds invariant 5 (audited crypto only).

> The integration spine. WS1/WS2/WS3 all sit on the crates this workstream brings in.

---

## 1. Goal

Adopt the audited Zcash Foundation FROST stack as Loki's crypto + coordination base,
and **retire Loki's bespoke FROST, relay, ceremony, and admission code** so that the
code Loki ships (and must get audited) shrinks to: the **signer shell** (WS1), the
**keyless coordinator/wallet** (WS2), the **thin enrollment/roster layer** (WS3 §4),
and **FVK derivation** (WS5).

## 2. The ZF components and their roles in Loki

| ZF component | Audited? | Role in Loki |
|---|---|---|
| `frost-core` | yes | FROST primitives (key packages, signing packages, aggregation). |
| `frost-rerandomized` | yes | Rerandomized signing (randomizer = tx `alpha`), required for Zcash. |
| `reddsa` (RedPallas) | yes | The Pallas-curve signature scheme Zcash uses. |
| `frostd` | yes (Least Authority) | JSON-HTTPS coordination relay (WS3). |
| `frost-client` | yes; becoming a library | CLI/lib that holds shares/group/contacts and runs the participant + coordinator protocol over `frostd`. Loki embeds the **participant** side in WS1 and the **coordinator** side in WS2. |
| `zcash-sign` | — | Tooling: `generate` (FVK from group key) and `sign` (apply FROST signing to a PCZT / transaction plan). Used by WS2 for aggregation→PCZT and considered for WS5. |

`zcash-sign` source modules observed: `args.rs`, `generate.rs`, `lib.rs`, `main.rs`,
`sign.rs`, `sign_ywallet.rs`, `transaction_plan.rs`; commands `generate` + `sign`.

## 3. Adoption strategy

`frost-client` is a CLI today and is **becoming a library**. Two integration modes:

- **Mode A — library (preferred):** depend on `frost-client` as a crate; call its
  participant API from the WS1 signer and its coordinator API from WS2. Cleanest, but
  depends on the library surface being published/stable.
- **Mode B — vendored/driver (fallback):** if the library surface isn't ready, drive
  the audited `frostd` protocol directly using `frost-core`/`frost-rerandomized`/
  `reddsa` (all already libraries) for the math, and the `frostd` wire protocol for
  transport — i.e. reimplement only the thin *client orchestration*, never the crypto.

Decision gate: check the current `frost-client` library surface at build start; pick A
if the participant/coordinator entry points are exposed, else B. Either way the
**math and the relay are the audited crates** — Loki writes orchestration + UX only.

## 4. What Loki retires (delete after parity)

| Loki code | Replaced by |
|---|---|
| bespoke FROST signing/aggregation | `frost-core` / `frost-rerandomized` / `reddsa` |
| `relay_member`, `setup_relay`, courier | `frostd` |
| admission service + enrollment issuer | thin Loki roster layer over `frostd` (WS3 §4) |
| `deploy/bringup.sh` / `teardown.sh` relay stack | `frostd` deployment |
| bespoke DKG transport plumbing | `frost-client` participant DKG over `frostd` |

Keep: `scan`/`witness`/`scanstate`, `loki_wallet_sync`, `loki_indexer`,
`payment_manifest`, candidate builder/verifier, the `zakura-*` PCZT/Orchard builder,
`member_state` sealed store, `signing_session` nonce rules (re-homed into WS1). These
are coordinator/scan/signer-shell code, not the threshold crypto.

## 5. Mapping Loki concepts → ZF concepts

| Loki | ZF |
|---|---|
| member share (sealed) | `KeyPackage` (participant secret) |
| group key / vault verifying key | `PublicKeyPackage` |
| DKG ceremony | `frost-client` DKG (participant rounds 1–3) |
| proposal commitments | `SigningCommitments` (round 1) |
| signing package + randomizer | `SigningPackage` + rerandomizer (`alpha`) |
| approval share | `SignatureShare` (round 2) |
| finish/aggregate | `frost-core` aggregate → `zcash-sign` apply to PCZT |
| relay | `frostd` |

## 6. Acceptance criteria

1. A 2-of-3 testnet vault created via the ZF DKG (through `frost-client`/`frostd`),
   not Loki's bespoke ceremony; print the vault address.
2. A confirmed testnet payment signed via `frost-core`/`frost-rerandomized` partials
   aggregated and applied with `zcash-sign`, broadcast; print txid.
3. The bespoke relay/admission/courier binaries are removed from the default build and
   nothing in the product path imports them (grep proof).
4. A short `ADOPTION.md` records Mode A vs B chosen and the exact `frost-client` /
   `zcash-sign` versions pinned.

## 7. Open questions

- `frost-client` library surface readiness (gates Mode A vs B) — check at start.
- Does `zcash-sign`'s PCZT/`transaction_plan` path cover Ironwood/Orchard V6 as Loki
  builds them, or is a small adapter needed from the `zakura-*` builder output? Verify
  against a real testnet PCZT before committing WS2's finish step to `zcash-sign`.
- Version/pinning + build reproducibility feed into WS6.
</content>
