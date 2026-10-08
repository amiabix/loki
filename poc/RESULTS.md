# Loki G1-TX POC — results

> Historical experiment record. Node build/configuration details below describe the
> original run. Current local-chain setup uses THS; see [harness/README.md](harness/README.md)
> and [THS-RESULTS.md](THS-RESULTS.md) for current instructions and evidence.

## G1-TX PASS; G1 BLOCKED (ZIP 2005)

Date 2026-10-03. Scope is **G1-TX** per the 3 October decision in the brief: the v6
sign-before-proof transaction path, on a documented test-only FVK.

```
txid     bae10db64c5303bbeabf5d9d1a82b1adac497ee666bf5c3eabbd3d34cc5088f9
mined    height 36, 2 confirmations
anchor   d793fd9834b13a4c…  (installed after signing, at height 21)
network  Regtest, NU6.3 (Ironwood) branch 37a5165b, active from height 1
```

A real Ironwood payment, authorized by two of three FROST members, **signed before its
anchor and proof were installed**.

## Run

One command, genesis to mined, nonzero on any failure:

```
./poc/run-regtest.sh
```

Component checks:

```
cd poc
cargo test                                       # 23 tests
cargo build --features probe-zip2005             # blocker B1, as a compiler error
(cd vendor/orchard && cargo test --lib loki_b2)  # 3 tests, the B2 patch
./tamper-tests.sh                                # 10 adversarial cases, self-contained
./run-second-device.sh                           # second-device finishing, both paths
```

One-time cost: `zebrad` is built from source (2m26s, see `harness/README.md`). There are
no proving-parameter downloads — Orchard uses Halo 2, so `ProvingKey::build` is local.

## Checkpoints

| # | Requirement | Status |
|---|---|---|
| 1 | Pin and prove the library path | **done** (2 PASS, B1 blocked, B2 patched) |
| 2 | Create and fund a 2-of-3 vault | **done** |
| 3 | Build three unproved candidates | **done** |
| 4 | Review and sign in separate processes | **done** |
| 5 | Finish and mine AC | **done** |

### The central claim, demonstrated

```
AC  signature applied to action 0
AC  anchor d793fd9834b13a4c at height 21
AC  anchor and witness installed after signing
AC  effects sighash unchanged by anchor/witness installation
```

The sighash is computed before the anchor exists, checked again after installation, and is
byte-identical. The proof is then created and the transaction passes consensus.

### Checkpoint 3 — three candidates

```
AB  rk eb700bc2…  alpha 28786d18…  3594 bytes, anchor deferred, no witness, no proof
AC  rk 10142102…  alpha b876cc72…  3594 bytes, anchor deferred, no witness, no proof
BC  rk 08879cee…  alpha 2fb8e78b…  3594 bytes, anchor deferred, no witness, no proof
```

Identical nullifier, recipient, amount, memo, fee and expiry; only `rk` differs, because
each pair derives its own α. `proposal_id` carries no transaction randomness, so all three
share it.

### Checkpoint 4 — approval binding

Each member runs as its own process, parses the PCZT bytes itself and computes its own
sighash. Pairs agree independently: AB `9fba68…`, AC `f98850…`, BC `0188be…`. Each
verifies `rk` against an α it **recomputed** from the proposal and that pair's
commitments, and builds the FROST signing package locally from its own sighash rather
than accepting one.

Every candidate containing a member is reviewed before that member emits any share, and
each nonce is assigned to one candidate and deleted on use.

`src/verify.rs` holds the approval check. Everything below is proven against the PCZT and
its cryptographic openings; nothing is taken from a proposer annotation, and **an absent
opening is a refusal, not a skipped check**:

| Checked | How |
|---|---|
| input set | the set of nullifiers with non-zero spend value must **equal** the intent's, exactly |
| recipient and value | each output's note is rebuilt from its openings and must reproduce the action's own `cmx` |
| memo | the note is **re-encrypted** with the intended memo and must reproduce `enc_ciphertext` byte for byte |
| change address | derived by the signer from the vault FVK, never read from the intent |
| change amount | must equal the intent's |
| exact fee | `sum(real spend values) − sum(output values)`, compared with the intent. **Implemented, UNTESTED against a real candidate.** See the fee note below |
| permitted pools | the Orchard, transparent and Sapling bundles must all be empty; any output to an unnamed address is refused |
| expiry and version | read from the PCZT global |

The memo check works because `enc_ciphertext` is a deterministic function of the note and
its memo: the ephemeral secret is derived from the note's `rseed`, so no randomness
remains to differ. Re-encrypting binds memo, openings and ciphertext together, and a
proposer cannot alter the memo without the ciphertext changing.

### Adversarial tests

Two layers, because they test different things.

**`./tamper-tests.sh` — the candidate is the attacker.** Each case replaces the
*serialized* candidate AC with one a hostile proposer could have built: produced by the
real builder, structurally valid, correctly randomized, but not the payment the intent
names. It then runs the real `review-sign` process and requires **both** a nonzero exit
carrying a refusal **and** no share file. The second condition is the one that matters: a
signer that printed a refusal and still emitted a share would have approved the
transaction anyway.

```
memo            refused, 0 shares  <- MemoDiffers: re-encrypting with the intended memo
                                      does not reproduce enc_ciphertext
recipient       refused, 0 shares  <- ExtraOutputOrPool: 40000000 zat to an address the
                                      intent does not name
amount          refused, 0 shares  <- AmountDiffers { what: "change", expected: 584990000,
                                      found: 584989999 }
change-amount   refused, 0 shares  <- AmountDiffers { what: "payment", expected: 40000000,
                                      found: 39999999 }
change-address  refused, 0 shares  <- ExtraOutputOrPool: 584990000 zat to an address the
                                      intent does not name
fee             COULD NOT CONSTRUCT: build_for_pczt: ChangeRequired(ZatBalance(1000))
input           refused, 0 shares  <- InputSetDiffers { expected: 1, found: 1 }
expiry          refused, 0 shares  <- expiry height differs: intent says 9216,
                                      candidate says 10368
transparent     refused, 0 shares  <- the transparent pool is in use: 0 input(s),
                                      1 output(s)
sapling         refused, 0 shares  <- the Sapling pool is in use: 0 spend(s), 1 output(s)
control         honest candidate accepted, share emitted

10 passed, 0 failed, 1 could not be constructed
```

Every case asserts the **specific** refusal, not merely a nonzero exit. That distinction
matters: a signer that refused for an unrelated reason (a stale α, a sighash mismatch)
would otherwise count as a pass while the check under test went unexercised. Refusals
raised inside the `Verifier` surface as `Custom(<variant>)`; the pool and expiry checks
run in `review_sign` itself and print through `Display`.

The harness runs its own `commit` and `propose` so the candidate and the published
commitments always agree; without that, every case refuses on a mismatched α instead of
the effect under test. It restores the honest candidate and alice's unspent nonces between
cases, and re-runs the honest candidate at the end as a control.

**Correction to an earlier version of this file.** It recorded `transparent` and `sapling`
as not constructible, on the grounds that `DeferredPcztBuilder` has no methods for those
pools. That was wrong about the conclusion, if right about the builder. `PcztParts` exposes
`transparent` and `sapling` as **public fields**
(`zcash_primitives-0.31.0-pre.0/src/transaction/builder.rs:790`), and both pools expose
public PCZT constructors — `zcash_transparent::pczt::Bundle::parse` and
`sapling_crypto::pczt::Bundle::parse`. So a component can be constructed directly and
grafted onto an otherwise honest candidate before `Creator::build_from_parts`
(`src/candidate.rs`, `forbidden_transparent_bundle` and `forbidden_sapling_bundle`). Such
a candidate could never prove or mine, which is exactly the point: the signer has to
refuse it long before a prover runs, and now a positive fixture shows that it does.

Two details the fixtures needed. The Sapling `cv` has to be a genuine non-small-order
point, so it is derived from a trapdoor of 1; a zero trapdoor on a zero value gives the
identity, which `Output::parse` rejects. And the IO Finalizer needs that same trapdoor
back, or it fails with `SaplingFinalize(MissingValueCommitTrapdoor)`.

**fee: UNTESTED, because the case cannot be constructed**

A candidate whose **fee alone** is wrong does not exist. The implied fee is
`total_in - total_out`, and `check_candidate` pins the input set by nullifier and both
output values exactly, so the fee is pinned with them. Attempting it anyway — taking 1000
zat out of the change and leaving everything else alone — leaves the bundle unbalanced and
`build_for_pczt` refuses:

```
fee  COULD NOT CONSTRUCT: build_for_pczt: ChangeRequired(ZatBalance(1000))
```

So the `FeeDiffers` arm (`src/verify.rs:275`) is **untested against a real candidate**. It
is defence in depth: reachable only if one of the input or output checks were removed or
weakened. The `Expectations` unit test that covers it proves nothing about a candidate a
proposer could actually send, and is not counted above. Recorded as a gap, not a pass.

**One note on the amount cases.** The builder does not preserve the order outputs were
added in, so whichever of the payment and the change the verifier reaches first reports
the shift — which is why `amount` names the change above and `change-amount` names the
payment. Both values are bound, which is what the cases have to establish; the harness
asserts `AmountDiffers` and the log records which output it named.

**`cargo test` — the intent is the attacker.** Ten tests in `src/verify.rs` vary the
`Expectations` against one honest candidate. These are a weaker instrument than the
harness above and are **not** counted as coverage of the checks: altering what the signer
expects is not the same as altering what the proposer sent. They are kept because they
cover `check_candidate`'s arms cheaply and in isolation, including the `FeeDiffers` arm
that no real candidate can reach. One honest case is approved first, so the refusals
cannot pass for the wrong reason:

```
c4_honest_candidate_is_approved .............. ok
c4_tampered_memo_is_refused .................. ok
c4_tampered_amount_is_refused ................ ok
c4_tampered_change_amount_is_refused ......... ok
c4_tampered_fee_is_refused ................... ok
c4_tampered_recipient_is_refused ............. ok
c4_tampered_input_nullifier_is_refused ....... ok
c4_an_extra_expected_input_is_refused ........ ok
c4_change_to_a_foreign_address_is_refused .... ok
c4_expiry_is_carried_for_checking ............ ok
```

Each refusal happens inside the review pass, before any share exists: `review_sign`
reviews every candidate it is in and returns on the first refusal. `tamper-tests.sh`
confirms that on disk.

### Checkpoint 5 — finish

The finishing process holds no signature share and never opens Bob's directory. It
verifies Alice's and Carol's shares, aggregates, confirms the group signature verifies
under `ak + [α]G` before the node sees it, applies it, and only then installs the anchor
and witness, proves, extracts the v6 transaction and broadcasts.

## Two failures worth keeping

**`MissingBindingSignatureSigningKey` at extraction.** The IO Finalizer had been skipped.
It derives the binding signature signing key and must run **before anyone computes a
sighash**, or the signers sign a transaction whose inputs and outputs are still open.

**`incorrect consensus branch id` at broadcast.** The POC's `Regtest` parameters activated
*every* upgrade at height 1, so `BranchId::for_height` chose a branch later than the node
accepts. It surfaces only at broadcast, after proving. The parameters now stop at NU6.3
and must match `harness/zebrad-regtest.toml` exactly.

## The B2 patch grew

`DeferredPcztBuilder::add_ironwood_spend` delegates to orchard's
`add_spend_unwitnessed`, which had no α seam either, so the value could not reach a
deferred-witness spend at all. The patch is now two crates:

- `orchard` at `616a669d`: `SpendInfo.alpha`, `new_with_alpha`, `unwitnessed_with_alpha`,
  `Builder::add_spend_unwitnessed_with_alpha`, and the sampling site using
  `unwrap_or_else`. Upstream behaviour is unchanged when α is unset, which is asserted.
- `zcash_primitives` 0.31.0-pre.0: `add_ironwood_spend_with_alpha`, plus `pasta_curves`
  0.6 as a dependency for the parameter type (already in the graph via orchard).

Both patches are in `vendor/*.patch`; see `vendor/README.md`.

## Facts worth carrying forward

- **Ironwood has no receiver typecode.** `zcash_address` 0.14 knows only Orchard,
  Sapling, P2PKH and P2SH. Ironwood reuses the **Orchard receiver**; the pool is chosen by
  the sending bundle.
- **Zebra pays shielded coinbase to a unified address**, which removed the need for any
  transparent spending machinery to fund the vault.
- **Shielded coinbase has no transparent maturity rule.**
- **A deferred anchor is a flag, not an `Option`.** `Bundle::anchor_deferred` is true and
  `anchor` carries `Anchor::empty_tree()` as a placeholder a serializer emits as absent.
- **`pczt` has no `verifier` feature, but the role is unconditional.** An earlier draft of
  `DEPENDENCIES.md` misread that; corrected.
- **The graph carries two crypto universes.** FROST on `reddsa` 0.5.2 / `pasta_curves` 0.5
  / `ff` 0.13 / `rand_core` 0.6; orchard and `zcash_primitives` on 0.6.1 / 0.6 / 0.14 /
  0.10. Every crossing is a canonical 32- or 64-byte encoding, checked on arrival.
- **The TOML key is `"NU6.3"`**, not `NU6_3`.

## What this does NOT establish

- **G1.** The vault FVK is the test-only `ak || nk || rivk` splice. ZIP 2005's
  `qsk → qk → rivk_ext` is implemented nowhere — not orchard 0.16, not `zcash/orchard`
  HEAD `616a669d`, not `librustzcash` HEAD `9c5705f5` — and the ZIP is `Status: Proposed`.
  The compile probe and blocker report stay in place. No ZIP 2005 vector was fabricated.
- **The α seed derivation is a research assumption pending O1 review.** The library's
  seed-to-α derivation is unchanged; only the seed's origin differs, and
  `frost-rerandomized` explicitly advises against supplying your own.
- **G3 crash or restore safety.** The G1 CLI uses file state with no rollback guarantee.
  A nonce is deleted after use, which is not the same as a crash-safe consumed-nonce
  ledger. G3 is prototyped separately in `g3/` and reported in `g3/G3-RESULTS.md`. It is
  **PARTIAL**: 29 of 32 drills pass on Chromium 153 and 6 of 8 on Playwright WebKit 26.6
  behind a 2-of-3 signed-receipt gate across three simulated relay operators. Firefox 155
  would not launch, Playwright WebKit is not Safari and native Safari is untested, two
  colluding acknowledgers still defeat the gate, and **no device case has been tested**:
  power loss, OS backup restore and the whole platform matrix are unrun.
- **A real second device.** `run-second-device.sh` and `SECOND-DEVICE-RESULTS.md` show a
  finisher that holds no approver file completing both payments, one by broadcasting an
  already posted final transaction and one by re-proving the signed candidate from its own
  chain scan. It is a second *process* on the same machine reading a locally copied
  replica: no relay, no transport authentication, no second piece of hardware.
- **M0, one-visit approvals, production nonce safety, independent recovery, custody
  readiness.** None of these follow from this POC.
- **Outgoing viewing key material is not checked.** The PCZT outputs carry no populated
  `ock`, so the `out_ciphertext` is not verified. That field lets the sender recover the
  note later; it does not affect what the recipient receives, and every value the intent
  names is bound by the checks above. Verifying it would need the `ock` opening added to
  the handoff.
- **The exact-fee check is untested against a real candidate.** `FeeDiffers`
  (`src/verify.rs:275`) is correct but unreachable: the fee is `in - out`, both of which
  are pinned exactly, so a candidate whose fee alone is wrong will not build
  (`ChangeRequired(ZatBalance(1000))`). Defence in depth, recorded as a gap.
- **Only the Ironwood pool is exercised.** The Orchard, transparent and Sapling bundles
  are required to be empty rather than independently verified.
