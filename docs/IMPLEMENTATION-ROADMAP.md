# Loki implementation roadmap

9 October 2026. Target: the original browser wallet, starting with a narrow 2-of-3 research prototype on local regtest. This is an implementation contract, not a custody release plan.

## The first complete result

Three members open Loki in separate browser profiles. Each creates and keeps only their own signing share. They compare the same vault fingerprint, each saves and tests a 24-word phrase and backup card, and only then see a receive address derived from the certified group key. The vault receives an Ironwood note. Two members independently review the transaction effects and approve it; a different synced browser proves and broadcasts it. Each member's own chain sync sees confirmation. A member restores on a clean device from just their words and card, with every Loki service and relay offline.

The first payment can use prepared members, one note, one shielded recipient, one memo, and one expiry window. Late approvals, 2-of-4, transparent payments, push, phone proving, and policy controls follow this path. The app must state when a payment is signed but waiting for a synced computer.

The browser app and its workers are one origin and one trust boundary. A compromised host controls the code it serves. For a 2-of-3 vault to remain safe from compromise of Loki's hosted app, at most one member may use that hosted channel. The prototype must record each member's channel and show this status; worker separation alone does not provide it.

## What exists today

| Piece | Evidence | Still missing |
| --- | --- | --- |
| FROST and transaction path | `poc/src/bin/loki.rs` has mined a 2-of-3 Ironwood spend on regtest; candidate review has tamper tests. | Its setup holds all three shares during creation, its nonce files are unsafe for custody, and its viewing key is test-only. |
| Separate member setup | `loki_setup_member` completes DKG in three isolated processes, authenticates messages, seals one share per member, and locally derives a ZIP 2005 viewing key on regtest. | Independent derivation review, browser integration, tested backup, and connection to the payment path. |
| Finishing and scanning | A second process can finish from replicated public data; a narrow regtest scanner finds notes. | Browser wallet sync, witnesses and reorg handling on real devices. |
| Nonce experiments | `poc/g3` explores crash and browser storage behavior. | A real FROST signer using that state machine and durable receipts from independent relays. |

The `poc` CLI and demo remain regression fixtures. Passing their tests does not activate a vault or satisfy the browser milestone. Preserve the current uncommitted work; do not reset it or silently turn the fixture into product code.

## Build in this order

1. **Keys and address.** A local module now derives ZIP 2005's `use_qsk = true` FVK from the DKG group `ak` and shared vault secret and matches an independently calculated vector. Obtain upstream API support or independent review and a mined payment from this FVK before closing G1. The old transaction CLI's fixed `ak || nk || rivk` splice remains a regtest fixture. Do not display a public testnet receive address yet.
2. **Signing state.** Make G3's write-ahead and relay receipt protocol drive the actual FROST nonce store. A nonce may yield a share for exactly one package digest, including across two tabs, crashes and restored browser storage under the stated honest-relay assumption. A failed durability drill blocks approval. Use three relays from three operators in the gate; operator identity matters more than three hostnames.
3. **Vault creation and backup.** Port the separate-member DKG flow into the browser keys worker. Bind the roster, network, threshold, group key, shared secret and channels into the certificate. Require every member to load back their encrypted backup card and check their words before exposing a receive address. Restore into a clean origin with no relay or Loki service.
4. **Wallet and proposal.** Use an Ironwood-capable wallet sync library for notes, witnesses and reorgs; the narrow `poc/src/scan*.rs` scanner is only a regtest fixture. Build one unproved candidate per prepared pair, with the same input notes and exact payment intent. Keep the caller-supplied alpha patch isolated; resolve issue #3's seed generation and verification before changing the dependency graph for issue #4.
5. **Review, sign and finish.** The keys worker fetches immutable candidate bytes, derives the display model itself, runs the existing effect checks plus every remaining V1–V10 check, and signs only that candidate's locally computed sighash. The prover holds no shares. A different synced browser reconstructs the authorized candidate from relay messages, installs a current anchor, proves, shares the finished bytes and broadcasts. A closing approver cannot strand the payment.
6. **Recovery and release evidence.** Restore a member from only the two artifacts and spend from two exported shares without Loki services. Run the complete flow on three real browsers/devices, including crash, conflicting proposal, month-old chain state and reorg drills. Seek independent review of key derivation, alpha derivation, nonce protocol, backup and delivered-code threat model before any custody claim.

## Gates and stop rules

- **G1:** the local ZIP 2005 FVK has not been reviewed or used for a mined payment; no public testnet vault. A mined spend using the fixed viewing-key tail is transaction evidence only.
- **G3:** no crash and rollback safe nonce store, no asynchronous approval release. Strict IndexedDB durability is a test subject, not a guarantee.
- **G4/G9:** no independent finisher or reliable chain sync, no claim that a payment sends without the approvers returning.
- **G5/G6:** no two-artifact restore and independent spend, no claim that members can recover without Loki.
- **Custody:** no mainnet release on regtest evidence alone. Browser code delivery and the threshold's hosted-member count are part of the security claim.

The next implementable change is G1's key derivation vector and API audit. In parallel, the standalone G3 signer can be tested without a wallet UI. Both are prerequisites for calling the browser flow a vault; issue #4's package migration is maintenance and does not close either gate.
