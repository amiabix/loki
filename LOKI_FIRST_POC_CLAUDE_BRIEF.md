# Loki first POC — implementation brief for Claude

Copy the section below into Claude with access to this directory. This is an implementation request, not a request for another architecture review.

---

## Objective and authority

Implement the first decisive Loki protocol POC: **a real, mined, shielded Ironwood payment on NU6.3 regtest, authorized by two members of a 2-of-3 FROST vault, where the transaction is signed before its anchor and proof are installed**. Build the three prepared pair candidates (AB, AC, BC) from one payment intent and one funded note; independently review and sign all three pairs; prove and mine only AC. Bob must not participate in finishing AC. Record the on-chain result and enough artifacts to rerun it. The 3 October checkpoint-1 findings below authorize a test-only path around the missing ZIP 2005 viewing-key API; that path can pass **G1-TX**, never full **G1**.

The **1 October 2026 Loki Overview and Engineering spec**, if supplied alongside this brief, govern the design. In particular use Engineering sections 5–9, 14–15 and Appendix A. This brief contains the G1 requirements needed to start even if the full spec is unavailable. The Markdown files already in this directory are older research. They disagree on native versus web, thresholds, backup design, randomizer derivation and milestones; use them only for leads, never as authority over this brief. This brief deliberately covers **G1 only**. A passing G1 is evidence for the transaction path, not M0 completion or custody readiness.

This directory currently contains documents and no code. Rust and Docker are installed, but Zebra, Zaino and Zcash CLI binaries were not found on PATH when this brief was written. The enclosing Git repository is `/Users/abix`, so keep all new files under this directory. Do not commit or push unless asked.

## Scope

Use one native Rust POC crate under `poc/`, a reproducible local NU6.3 regtest harness under `poc/`, and file handoffs between three distinct signer processes. Use established Zcash and ZF FROST crates. Pin a *compatible* dependency graph in `Cargo.lock`; the October 1 version list is a starting point, not proof that all APIs compose. A small, isolated patch to an upstream builder is acceptable if W1 or W4 requires it. Record the exact upstream commit and patch. Do not rewrite Zcash transaction serialization, RedPallas, FROST or proving code.

Use **only test funds and generated test keys**. No browser app, relay service, passkeys, push, persistent wallet sync, late approvals, transparent outputs, 2-of-4, backup card or production nonce store in this POC. They are later gates. A file transport is sufficient to prove the candidate and signature path. Do not present it as safe for async production signing; there is no crash or rollback guarantee here.

## Required sequence

Complete each checkpoint before starting the next. The sole exception is the documented ZIP 2005 viewing-key blocker B1: preserve its reproducer and continue with the isolated test-only path below. For any other blocker, leave a minimal runnable reproducer and a concrete blocker report rather than substituting mock transaction bytes, a normal Orchard spend, a single-signer signature, or an interactive signing flow.

### Decision after checkpoint 1 — 3 October 2026

Checkpoint 1 found that the inspected `orchard` and `librustzcash` versions do not expose the ZIP 2005 `qsk -> qk -> rivk_ext` path. Keep B1 **BLOCKED** in `poc/RESULTS.md` and keep its failing compile probe. Proceed with checkpoints 2–5 as **G1-TX**, a transaction-path experiment. In `poc/` only, construct the FVK by parsing canonical `ak || nk || rivk` bytes, where `ak` comes from the real 2-of-3 DKG and `nk`/`rivk` come from fixed, documented test inputs shared by the three processes. Parse and round-trip the components; reject noncanonical values. Name this helper `test_only_fvk` and make every call site visibly test-only. This is a deliberate deviation from ZIP 2005. Do not call the address a production Loki vault address or claim quantum recovery.

The B2 caller-selected-`alpha` patch remains in scope. Keep it isolated against a pinned upstream commit and test it through actual PCZT construction, proving and node acceptance. The two `reddsa` versions may cross only through canonical 32-byte encodings; reject invalid encodings on both sides. `pczt` having no `verifier` feature means the signer checks in checkpoint 4 must use the available parsing and Orchard/Ironwood verification APIs or a small explicit verifier in the POC; no blind-signing shortcut is authorized.

Preserve the ZIP 2005 commit-reveal and vector requirements below as **open G1 work**. Do not fabricate a passing vector with the test-only FVK. If G1-TX succeeds, the report must say `G1-TX PASS; G1 BLOCKED (ZIP 2005)` and include the mined transaction evidence. If it fails, report the exact remaining transaction-path blocker. No changes from this POC should be presented as custody-ready.

### 1. Pin and prove the library path

Inspect the actual source and feature flags for the selected versions of `frost-core`, `frost-rerandomized`, `reddsa`, `orchard`, `pczt`, `zcash_primitives` and any required wallet crates. Write `poc/DEPENDENCIES.md` with exact versions/commits and links to the methods used. Confirm:

- The FROST Pallas ciphersuite, DKG, preprocessing, rerandomized signing, share verification and aggregation are available.
- A full viewing key can be constructed from a DKG-derived group `ak` plus the ZIP 2005 `use_qsk = true` derivation. A pre-ZIP-2005 `from_sk_ak` fork method alone is **not** a pass.
- The deferred v6 PCZT path creates an Ironwood spend without anchor or witness and can install both after signing.
- Whether the builder can accept a caller-selected `alpha` **for each real Ironwood spend**. If it cannot, add the smallest isolated patch at the point where the builder currently samples `alpha`; do not mutate `rk` or a built PCZT afterward. Follow the value through PCZT, signing, proving and consensus validation.

Put a ZIP 2005 test vector in a runnable test: fixed test inputs, expected `ak`, `nk`, `qsk`, `qk`, `rivk`, FVK/address bytes, and agreement with the pinned implementation. If there is no independent published vector for the FROST branch, derive one from the specification, cross-check it with a separate implementation or direct primitive-level calculation, and say exactly what was independently checked. Never mark a round-trip against the same function as an independent vector.

### 2. Create and fund a 2-of-3 vault

Run three-member 2-of-3 DKG using the pinned FROST library. Each member must get its own key package and the common public package; the vault's spend key must never be materialized. For G1-TX use the test-only FVK described above. For full G1, agree on the ZIP 2005 shared `sk`/vault secret by committing to each member's fresh 32-byte contribution `c_i`, revealing all three, checking the commitments, then deriving `vs = BLAKE2b-256("Loki_vs_v1", transcript_hash || c_A || c_B || c_C)` in member-identifier order. The shared secret is not a dealer-selected constant. Use `vs` as the ZIP 2005 `sk` with `use_qsk = true`; do not accidentally derive `ak` from it instead of the DKG.

Create the Ironwood FVK and a receive address from those values. On a local NU6.3 regtest network, fund that address with a real Ironwood V3 note and mine it. Save the note, its nullifier, amount, witness and the block/anchor information needed later using an existing wallet or regtest helper. A narrow test fixture is fine; implementing a general scanner is outside G1. Show that two independently initialized member processes derive the same FVK/address and can identify the funded note. Keep secret packages outside version control; emit public hashes and address only in logs.

### 3. Build three unproved candidates

Use one fixed test payment intent: fund the vault with 1 ZEC, pay 0.4 ZEC to one Ironwood recipient with a nonempty memo, fix the builder-calculated ZIP 317 fee, return the exact remainder to vault change, and use a one-week expiry rounded up to a 1,152-block boundary. The intent contains proposer, created height, input nullifier, recipient/amount/memo, vault-internal change policy, exact fee, exact change amount and expiry. Set `proposal_id = BLAKE2b-256("Loki_intent_v1", canonical_CBOR(intent))` **without transaction randomness**. Set the same input nullifier set, recipient, amount, memo, fee, change amount and expiry on AB, AC and BC. Record these expected values in a machine-readable fixture that signer processes read; do not rely on a human-readable proposal annotation for the checks.

Each pair must use a distinct preprocessed nonce pair per signer and spend. For each candidate, compute `seed = BLAKE2b-256("Loki_alpha_v1", proposal_id || sorted_pair || spend_index)`, then use the pinned rerandomization library and that pair's sorted commitments to derive `alpha`. The signer must recompute it. Apply that exact `alpha` through the builder **before** creating the unproved PCZT. Candidate transactions may have different `rk` and bytes; their payment effects and input nullifiers must match. Save each serialized unproved PCZT and signing package. Assert that all three PCZTs have absent anchor/witness/proof at this point.

Document the exact serialization/domain-separation used for proposal ID and seed. Do not silently replace the October 1 proposal-derived seed with the crate's coordinator-generated random seed. This custom derivation is a research assumption pending O1 review, not a security result from the crate.

### 4. Review and sign in separate processes

Provide a minimal CLI or script with `setup`, `propose`, `review-sign` and `finish` stages. `review-sign` receives only that member's key package, public vault material, intent and serialized candidates, plus its own nonce secrets. It must **parse the PCZT bytes itself** and compute its own sighash. It must reject before emitting any share if the network/version is wrong, the spend/nullifier is not the funded vault note, a candidate differs in recipient/amount/memo/fee/change/expiry, an extra output or pool appears, its `rk` does not match recomputed `alpha`, or the FROST package does not name the exact local sighash and sorted commitments. Review every candidate containing the signer before emitting that member's share batch.

Use the library's PCZT and Orchard/Ironwood verification APIs. Do not infer shielded output details from an untrusted annotation or accept a coordinator-provided sighash. If the PCZT does not carry enough openings for independent recipient, memo and change verification, extend the POC handoff with the needed openings and verify them against the ciphertext, commitments and FVK; report the exact missing field/API. A verifier that only checks equality with an intent supplied by the proposer is insufficient.

Run Alice, Bob and Carol as separate CLI invocations with separate state directories. Produce valid shares for AB, AC and BC. The CLI may use simple test-only file state, but each nonce must be assigned to one candidate/package and removed after use. State explicitly that this does **not** establish G3 crash or restore safety.

### 5. Finish and mine AC

In a process that has **no Alice or Carol secret share**, verify their AC signature shares, aggregate the RedPallas signature and apply it to the AC PCZT. After signing, install a current Ironwood anchor and witness, produce the proof, finalize, extract the v6 transaction, broadcast and mine it. Bob's package must not be read in this step. Verify the node accepted the transaction, the AC nullifier was spent, the recipient can decrypt the expected amount and memo, and the vault received the expected change. Confirm that AB and BC could not also be mined from that same note. Keep a record of the exact txid, mined height and network tip/branch.

Add one check that changing the anchor/witness after the signing step does not change the effect sighash or invalidate the spend signature. The final proof still must pass consensus. Do not claim that a mocked or locally verified signature is an on-chain success.

## Minimum checks and evidence

Provide one repeatable command, `./poc/run-regtest.sh`, that starts or connects to the pinned local test network, runs the stages and exits nonzero on failure. Document any one-time downloads or proving parameters. Add focused automated tests for:

1. For G1-TX: canonical parsing of the test-only FVK and agreement on its address across member processes. For full G1: the independent ZIP 2005 vector and shared FVK/address agreement.
2. Three candidate families with identical effects/nullifiers and distinct per-pair `rk`/nonce assignments.
3. Tampering one recipient, amount, memo, fee, change, expiry, nullifier, `rk` or package sighash produces **zero shares** and an identifiable refusal.
4. AC aggregation and an actual mined v6 Ironwood payment with proof added after signing.

Save `poc/RESULTS.md` with the exact run command, dependency lock/commits, test output, txid, mined height, which signer processes ran, which checks were automated, and any unproven assumptions. Keep actual secret material and generated private fixtures out of the repository. A failed G1 is a useful result: show the smallest failing call and the required upstream change.

## Completion rule

Report **G1-TX PASS** only if the repeatable run actually mines the AC transaction under the stated key and transaction conditions; continue reporting **G1 BLOCKED (ZIP 2005)** until its derivation and vector are implemented and checked. Report **G1-TX BLOCKED** with the exact W1/API/consensus failure if the transaction path does not mine. Do not proceed to browser UI, relays or G3 in the same implementation pass. Do not claim M0, one-visit approvals, production nonce safety, independent recovery, or custody readiness from this POC.

## Primary technical references

- [ZIP 229: v6 transaction format and deferred anchors](https://zips.z.cash/zip-0229)
- [ZIP 2005: Ironwood key derivation and FROST usage](https://zips.z.cash/zip-2005)
- [ZIP 312: rerandomized FROST and signer verification](https://zips.z.cash/zip-0312)
- [DeferredPcztBuilder API](https://docs.rs/zcash_primitives/latest/zcash_primitives/transaction/builder/struct.DeferredPcztBuilder.html)
- [frost-rerandomized 3.0.0 API](https://docs.rs/frost-rerandomized/3.0.0/frost_rerandomized/)
- [orchard 0.15.5 FVK API](https://docs.rs/orchard/0.15.5/orchard/keys/struct.FullViewingKey.html)

---

After G1, the next POC is G3's standalone nonce store and two-relay receipt/crash drill. G4/G5 (second-device finishing and backup restore) follow that. This order tests the transaction dependency before building its browser and relay machinery.
