# WS5 — FVK Derivation

Parent: `00-architecture.md`. One decision to lock, with real consequences for
recovery and audit.

---

## 1. The question

From the FROST **group key** (the joint verifying key `group_ak`), Loki must derive a
Zcash **Full Viewing Key (FVK)** so the vault has a receive address and can be scanned.
Two paths exist, and they differ in **quantum recoverability** and **review status**.

## 2. Option A — recoverable `zip2005` (Loki's current implementation)

- File: `poc/src/zip2005.rs`. Implements ZIP-2005 "`use_qsk`" quantum-recoverable FVK
  derivation:
  `nk = expand(sk, 0x07)`, `qsk = expand(sk, 0x0c)[:32]`,
  `qk = blake3::derive_key("Zcash ZIP 2005 qk-derivation v1", qsk)`,
  `rivk = expand(qk, 0x0d, ak‖nk)`, `FVK = ak‖nk‖rivk`.
- **Cross-checked 8/8** against zafe's `frost-tools#610` published vectors (throwaway
  test, since removed). The WASM spike also re-verified `zip2005_fvk_vector = true`.
- **Pro:** quantum-recoverable derivation path (the property ZIP-2005 is about);
  already implemented and vector-matched in Loki.
- **Con:** the **derivation is not yet reviewed upstream** — ZF `frost` issue **#1094**
  tracks that the FROST FVK derivation is unreviewed. Shipping this on mainnet means
  Loki carries an unreviewed crypto derivation (audit burden, WS6).

`poc/src/vault.rs` also has a regtest-only `test_only_fvk(group_ak)` fixed-tail splice
that **predates** the real `zip2005` implementation — it is test scaffolding, not a
derivation option, and must not reach any real-funds path.

## 3. Option B — `zcash-sign generate` (ZF tooling)

- `zcash-sign`'s `generate` command derives an FVK from the group key as part of the
  audited ZF tooling.
- **Pro:** comes from the ZF stack we are already adopting (WS4); less bespoke crypto
  for Loki to own and get audited; aligned with upstream.
- **Con:** need to confirm whether its derivation is the **quantum-recoverable**
  (`use_qsk`) variant or the non-recoverable constructor
  (`from_sk_ak_incompatible_with_quantum_recoverability_and_will_be_removed`). If it is
  the non-recoverable one, Loki loses the quantum-recoverability property that
  `zip2005.rs` provides.

## 4. Decision criteria

1. **Recoverability**: does the vault need quantum-recoverable FVK derivation as a
   product guarantee? If yes → the derivation must be the `use_qsk` path regardless of
   which code produces it.
2. **Audit surface**: Option B minimizes Loki-owned crypto (fits WS4's "retire bespoke
   crypto"); Option A keeps a Loki-owned derivation that needs review (#1094).
3. **Upstream trajectory**: if `zcash-sign generate` moves to the recoverable path
   upstream, Option B gives recoverability *and* audited code — the best outcome.

## 5. Recommendation (to lock)

**Prefer Option B (`zcash-sign generate`) IF it implements the quantum-recoverable
`use_qsk` derivation.** That gives recoverability *and* audited, upstream-aligned code,
and keeps Loki out of the bespoke-crypto / #1094 audit burden.

**Fallback:** if `zcash-sign generate` is the non-recoverable constructor and
quantum-recoverability is a required product property, keep `zip2005.rs` (Option A) and
**drive ZF issue #1094** to get the derivation reviewed — i.e. contribute the
vector-matched derivation upstream rather than carrying it privately.

Action to resolve the "IF": read `zcash-sign`'s `generate.rs`, determine which
derivation it uses, and compare its output against the `frost-tools#610` vectors that
`zip2005.rs` already matches. This is a concrete, verifiable check — do it before
locking.

## 6. Acceptance criteria

1. A written determination (with the `generate.rs` evidence) of whether `zcash-sign
   generate` is recoverable or not.
2. Whichever path is chosen: the derived FVK produces the **same vault address** that
   members scan to find funds, verified against a real testnet funding + scan.
3. If Option A is kept: an upstream #1094 note/PR with the matched vectors.
4. The regtest `test_only_fvk` splice is gated out of all real-network builds.

## 7. Dependencies

WS4 (`zcash-sign` availability), WS2 (scan seeding uses the FVK), WS6 (#1094 review
coordination, audit scope).
</content>
