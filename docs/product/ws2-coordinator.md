# WS2 — Coordinator / Wallet (keyless)

Parent: `00-architecture.md`. Upholds invariants 1, 3, 4, 6.

> The "easy part." Everything here touches only **public** data. If a feature needs a
> share, a nonce, or a spend key, it belongs in WS1, not here.

---

## 1. Goal

The application a member actually uses: list vaults, scan the chain, show balance and
a receive address, **build an unsigned PCZT payment**, **drive the FROST rounds** by
shuttling public messages between signers, **apply the combined signature** and
**broadcast**, and track confirmation. It holds the vault **viewing key** and public
protocol state — and **no spend secret of any kind**. It may be delivered as a web app.

## 2. Scope

- Vault dashboard: names, roster, slots, setup status, pending payments, history.
- Chain sync: birth-height/frontier-seeded incremental scan, balance at a named
  height, reorg-safe, via lightwalletd on testnet/mainnet (reuse Loki's existing
  `scan`/`witness`/`scanstate`, `loki_wallet_sync`, and `loki_indexer`).
- Receive: show the vault address / UA.
- Propose: recipient + amount + memo → fee/change/expiry → **unsigned PCZT** bound to
  one `PaymentIntent`; build candidates for every eligible quorum pair.
- Coordinate: collect `SigningCommitments`, assemble `SigningPackage`s + the
  rerandomization `randomizer`, fan out to signers, collect `SignatureShare`s.
- Finish: aggregate partials and apply to the PCZT (`zcash-sign` / `frost-client`
  aggregate), prove, serialize, **broadcast** (lightwalletd `SendTransaction` on
  testnet/mainnet; node RPC on regtest — both paths already exist in
  `loki_member_payment`).
- Status tracking: Draft → Collecting commitments → Waiting for approvals → Ready →
  Broadcast → Confirmed, with reorg rollback (states already defined in
  `WALLET_BUILD.md`).

## 3. Non-goals

- Holding or touching a share/nonce/spend key (WS1).
- Deciding the final signature's validity by trusting signer *claims* — it aggregates
  cryptographic partials; a bad partial fails aggregation.
- Implementing FROST or transaction crypto (WS4 / `zakura-*` builder).

## 4. Keyless guarantee (how we enforce invariant 1)

- The coordinator process links **no** module that can read a share. The share-holding
  code (WS1) lives in a separate binary/process/address space; the only channel is the
  narrow signer API (ws1 §7), which returns only public artifacts.
- In the web deployment: the browser bundle contains the PCZT builder, scanner client,
  and relay client — all public-data code — and talks to signers over `frostd`/IPC. It
  has **no code path** that receives a share. A build-time lint + a runtime assertion
  enforce this (ws1 acceptance §11.2).
- The coordinator **may** hold the vault viewing key (needed to scan/build). That is a
  balance-privacy exposure to the coordinator operator, not a spend risk (threat
  §5.3). Members wanting balance privacy use **Privacy mode** (§7).

## 5. PCZT build pipeline

1. Resolve spendable notes for the `PaymentIntent` from the synced wallet store
   (combine multiple vault notes as needed — logic already in the payment worker).
2. Build an **unsigned PCZT** (deferred/partial Zcash tx): outputs, change, fee,
   anchor, expiry; reserve inputs (input-reservation already exists), release on
   abandon.
3. Derive the per-signature **randomizer** (`alpha`) for rerandomized FROST and bind it
   to the candidate.
4. Produce, for each eligible pair, a candidate bound to the single intent (all-pairs
   orchestration is listed as required work in `WALLET_BUILD.md`).
5. Hand the PCZT + signing package + randomizer to signers via the signer API. The
   signer re-parses the PCZT itself (WYSIWYS) — the coordinator cannot shortcut that.

## 6. Coordination loop

```
for candidate in eligible_pairs(intent):
    commits = {m: signer[m].signCommit(candidate)   for m in pair}   # round 1 (public)
    pkg     = build_signing_package(candidate, commits, randomizer)   # public
    shares  = {m: signer[m].signApprove(candidate, pczt, pkg, rand)   # round 2; may REFUSE
               for m in pair}
    sig     = aggregate(pkg, shares, group_pubkey)                    # zcash-sign/frost
    tx      = apply_signature_to_pczt(pczt, sig); prove(tx)
    broadcast(tx); track_confirmation(txid)
```

Any synced member app can finish/broadcast (does not require having approved) —
matches `WALLET_BUILD.md` §9.

## 7. Privacy mode (optional, member balance privacy from the coordinator)

For members who do not want even balances visible to a hosted coordinator: run the
scan **inside the signer / local native app** using the viewing key held there, and
feed the coordinator only the minimum public artifacts needed to coordinate signing.
This trades the convenience of a thin web client for stronger privacy. v1 may ship
coordinator-side scan (simpler) with Privacy mode as a documented follow-up.

## 8. Reuse map (existing Loki code → coordinator)

| Need | Existing code |
|---|---|
| Incremental, reorg-safe scan | `poc/src/scan.rs`, `scanstate.rs`, `witness.rs` |
| Testnet sync via lightwalletd | `poc/src/bin/loki_wallet_sync.rs` (TLS/webpki + aws-lc-rs) |
| Reusable indexer / birth-height seed | `poc/src/bin/loki_indexer.rs` (`--from-height`) |
| Payment build + broadcast (both paths) | `poc/src/bin/loki_member_payment.rs` |
| Network-tagged proposals | `poc/src/payment_manifest.rs` |
| Candidate build/verify | existing candidate builder/verifier |
| Dashboard/signer split UI (loopback origins) | `poc/wallet/` member app (`index.html`/`app.js`), already split dashboard vs signer origins |

## 9. Deployment forms

1. **Bundled native (v1):** coordinator + signer in one installed app, logically split;
   no key ever crosses the internal boundary. Smallest path to the safety property.
2. **Web coordinator + native signer (target):** coordinator served as a web app; each
   member runs the native signer; they connect per the Safe contract. This is the
   product vision ("a web app you log into and still be safe with").
3. **Self-hosted coordinator:** an operator (or the member) hosts the coordinator;
   signers stay on devices. Pairs with self-hosted `frostd` (WS3).

## 10. Acceptance criteria

1. Scan a funded testnet vault to correct balance at a named height; survive an
   injected reorg (rollback then re-advance). Paste heights/balances.
2. Build an unsigned PCZT for a 2-of-3 intent, drive both rounds against two WS1
   signers, aggregate, broadcast on testnet, confirm ≥1 block; print txid.
3. All-pairs: the same intent completes with each of the three eligible pairs, and with
   one approver offline.
4. Keyless proof: coordinator bundle/process contains no share/nonce/vk-spend path
   (shared assertion with ws1 §11.2).
5. Web deployment: the coordinator served over HTTPS drives a confirmed testnet payment
   with the share only ever on the native signer (network capture shows no secret
   crossing the wire).

## 11. Dependencies

WS1 (signer API), WS3 (transport), WS4 (ZF aggregate + PCZT builder), WS5 (viewing key
derivation affects scan seeding).
</content>
