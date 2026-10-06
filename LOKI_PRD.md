# Loki — Product Requirements Document

**Version:** 0.1 · 30 September 2026  
**Status:** proposed release requirements; protocol and performance claims are gated by [the implementation spec](LOKI_IMPLEMENTATION_SPEC.md)  
**Product:** a local-first, shielded Zcash group wallet using threshold spend authorization

## 1. Problem and product thesis

People and small teams holding shielded ZEC currently face a poor choice: one device can authorize a spend, or a group must operate a technical signing ceremony. A secure threshold wallet has to solve the whole payment journey: knowing what funds are available, proposing a payment, independently understanding its effects, collecting approvals across time zones, finishing despite a missing member, and recovering when a device is lost.

Loki makes the **member's device** the unit of trust. Each member has a complete local wallet view, a separate FROST share, and a private record of group decisions. Encrypted mailboxes deliver messages, but hold no viewing or signing key and are replaceable. For supported transaction shapes, a member reviews the verified payment, authorizes it once, and leaves. Any later quorum can complete the spend without that member reopening the app.

**Local-first** means wallet state and secrets live on member devices, work is possible against cached state while offline, and messages reconcile when connectivity returns. It does not mean that every balance is current offline, that the Secure Enclave performs RedPallas signatures, or that a powered-off device can answer a later FROST round.

The product is a **full wallet**, rather than a signer companion: receive, scan, show history and memos, propose, approve, prove, broadcast, confirm, and recover are all first-class tasks.

## 2. Audience and jobs

| User | Typical vault | Job |
| --- | --- | --- |
| Individual custodian | 2-of-3 across personal devices and a recovery seat | Keep one lost or compromised device from becoming a single point of failure |
| Small treasury | 2-of-3 or 3-of-5 members across locations | Pay from shielded funds without coordinating a live call |
| Rotating team | 3-of-5 or 4-of-6 | See who approved what, replace lost devices, and migrate safely when membership or privacy requirements change |

The first release is optimized for a small treasury. Personal vaults use the same protocol and UI. Loki supports `2 <= t < n <= 6`; the UI explains the exact availability tradeoff for the chosen threshold. `t = n` is excluded because one lost member would block helper-based recovery.

## 3. User outcomes and product principles

1. **My phone tells me what I am authorizing.** The review screen is derived from verified transaction data. Names and proposer notes are annotations.
2. **My approval is a decision, not a ceremony.** Eligible prepared-subset payments need one user authorization and no return visit. Ineligible payments are clearly labeled as interactive before the first approval.
3. **The group keeps moving.** Any eligible `t` members may complete a payment. One missing or faulty member does not stall a prepared proposal with an honest quorum.
4. **My vault exists on my devices.** I can inspect cached balance and history without Loki's infrastructure; a sufficiently synced member device can build, prove, and broadcast.
5. **Failure is legible.** The wallet distinguishes awaiting approvals, authorized, proving, broadcast, and confirmed. It tells users when state is stale or a proposal must be rebuilt.
6. **Recovery says what it can and cannot fix.** Loss without copying may use share repair. Possible compromise or a departing viewer calls for a new vault and a shielded sweep when future security or confidentiality matters.

## 4. Release scope

### V1 required

- Ironwood shielded receive and send on iOS and Android, with local compact-block scanning, note state, balance, memos, and history; a desktop client may use the same core.
- Distributed vault creation with authenticated member identities, group-code comparison, ZIP 2005-compatible viewing material, and a verified backup gate.
- Encrypted, signed proposal and approval delivery through two replaceable mailboxes, with a sealed-file exchange route when relays are unavailable.
- On-device review of every candidate's complete effects and its FROST package before a signature share is produced.
- Prepared-subset asynchronous approval where the eligibility and safety gates pass; an explicit interactive fallback elsewhere.
- Broadcast and confirmation tracking, transaction-byte persistence, conflict/expiry handling, and honest status labels.
- Lost-device repair and backup restoration; new-vault migration for compromised shares or membership/threshold changes.
- Local contacts, first-time-recipient warning, verified change labeling, clear fee/expiry display, and content-free optional push.

### Outside V1

Transparent and Sapling vault funds; programmable spending policies; hardware devices that directly hold RedPallas shares; web signing; automatic on-chain memo transport; private transaction history between members; groups above six; same-address revocation of a confirmed compromised member; post-quantum `t`-of-`n` spend security.

## 5. User journeys and acceptance criteria

### 5.1 Create and fund a vault

The creator chooses the network, `t`, and `n`, invites members, and sees each person's verified identity and setup progress. Members compare a short group code through an independent channel. No receive address is enabled until all required certificates and a tested backup set exist. A deposit appears on each phone after its own chain sync.

**Acceptance:** a completed vault has identical group key, viewing identity, member roster, threshold, and transcript hash on all devices; a mismatch aborts. Every member can independently derive the same receive address and scan a test deposit. Setup time is measured on real devices, not promised before the DKG and backup workflow is tested.

### 5.2 Receive and understand funds

The home screen shows confirmed balance, available-to-propose balance, tentative reservations, sync height/time, and pending group activity. Offline access shows the last known state and its age. Members can see full memos and transaction history because the group viewing material is shared.

**Acceptance:** the UI never labels a stale balance current or a tentative reservation chain-locked. Two devices reconciling from the same chain tip agree on confirmed balance and spendable notes, including after a reorg.

### 5.3 Propose and review a payment

A member enters exact recipients, amounts, and memos. The wallet selects notes, a fee, change, and expiry, then builds transaction candidates. All members see the proposal after mailbox sync. Each phone independently verifies its own candidate bytes and renders recipients, full address on demand, amounts, memos, fee, verified change, and expiry. Contacts and the proposer's note are labeled as local or untrusted annotations.

**Acceptance:** a hidden output, altered recipient, altered memo, unverified change, inflated fee, mismatched input set, different sighash, wrong network, or malformed package yields a named refusal and **zero** signature shares. First-time recipients are warned based on that device's local history.

### 5.4 Approve across time zones

An eligible member opens the request, reviews, and performs one biometric or passcode authorization. The device prepares and durably queues all required shares in that action; it may upload later without further consent. The UI immediately shows that the member's approval was recorded locally and whether delivery has completed. Push is optional and contains no payment details.

**Acceptance:** on a Mode A eligible, nonconflicted proposal whose commitments remain assigned to it, any `t` members may each approve once in any order before expiry; no successfully queued approver must return to sign. An unavailable member's subset does not block another complete subset. A concurrent proposal that claims a signer’s same nonce inventory must be rejected or rebuilt with fresh commitments. If a proposal is not eligible, the UI states that it needs a later signing step *before* accepting the user's approval. This is a release gate, not a claim inferred from preprocessing alone.

### 5.5 Finish and track

When a candidate has valid shares, a sufficiently synced member device proves it, saves the final transaction bytes, broadcasts, and tracks confirmation. A bad share is attributed to its authenticated sender and its candidate is abandoned; another prepared subset may succeed. If proving or broadcast fails, a member can resume or resend without recollecting signatures when the signed candidate remains valid.

**Acceptance:** the app does not show “sent” before broadcast, or “confirmed” before chain confirmation. Repeated delivery and restart cause no second share computation with the same nonce. A competing mined spend or expiry changes the proposal to a terminal state and a replacement needs fresh approvals.

### 5.6 Recover and change the group

The first recovery choice is whether the old device might be copied. For an ordinary loss with at least `t` surviving helpers, the group repairs the seat; all remaining members then participate in refresh and certification before the new device is active. If a remaining member cannot join that ceremony but a signing quorum remains, the group can instead move funds to a new vault. A verified set of offline Group Cards provides a separate path if live helpers are unavailable. Possible compromise, member removal with future privacy, or threshold change creates a new vault and a signed sweep; Loki retires the former receive addresses in the UI.

**Acceptance:** a repaired member can sign a test payment under the unchanged address; an old single share fails against the refreshed package. The interface explicitly warns that **historical copies of `t` old shares remain dangerous** and that former holders of the viewing key can read the old vault's future activity until funds move. Recovery with fewer than `t` surviving live shares or valid cards is not represented as possible.

## 6. Functional requirements

| ID | Requirement | Release evidence |
| --- | --- | --- |
| P-01 | Create `2 <= t < n <= 6` vault without a trusted key dealer | Multi-device DKG transcript and independent address match |
| P-02 | Each phone scans Ironwood and owns its local history | Deposit, reorg, memo, and nullifier sync tests on both platforms |
| P-03 | Any synced member device can propose, prove, and broadcast | Desk-removed end-to-end test |
| P-04 | Review is derived from the verified PCZT | Field mutation and hidden-output refusal suite |
| P-05 | Eligible proposals accept one human action per signer | `t`-subset schedule tests with app closures after each approval |
| P-06 | Ineligible proposals show the interactive requirement in advance | UI tests for missing commitments and excessive candidate cost |
| P-07 | Members see proposal and approval status after sync | Duplicate, reorder, and offline reconciliation tests |
| P-08 | A finisher retries a saved signed candidate or final transaction | Crash and endpoint failure tests |
| P-09 | Loss, compromise, and membership change use distinct flows | Recovery and migration drills with real devices |
| P-10 | Mailboxes hold only authenticated ciphertext; push contains no content | Relay-log inspection and envelope tamper tests |
| P-11 | A group can use sealed-file exchange if Loki relays disappear | Relay-shutdown spend drill |
| P-12 | A member can export a documented recovery package | Independent reader import and regtest spend |

## 7. Non-functional requirements and measurement

These are **targets**, not statements about present software. They become release criteria after baseline benchmarks on a 2022 midrange iPhone, a comparable Android phone, and a midrange laptop.

| Area | Target / rule | Measurement |
| --- | --- | --- |
| Review responsiveness | Verified display appears within 2 seconds for a one-note, one-recipient candidate family | On-device p95 after bytes are local |
| Delivery | A small proposal or approval appears within 15 seconds when relays and both devices are online | End-to-end p95; exclude chain sync |
| Last approval to broadcast | Show measured proving and network time; set a numeric SLA only after mobile benchmarks | p50/p95 by action count and device |
| Offline use | Cached vault and queued decisions remain readable without relay or chain connection | Airplane-mode journey test |
| Durability | No nonce reuse or lost final transaction across supported crashes/restores | Fault injection and platform restore matrix |
| Accessibility | Review, warnings, and status usable with screen reader, large text, and non-color status cues | iOS/Android accessibility pass |
| Privacy | No plaintext payment or viewing key in relay or push logs | Traffic/log inspection |
| Compatibility | Exact dependency and consensus versions pinned per release | Regtest and testnet matrix |

## 8. Success measures

- **Primary:** fraction of eligible proposals that complete after exactly one human authorization from each of `t` signers, without any signer reopening the app.
- **Safety:** zero signature shares emitted by tamper fixtures; zero repeated nonce use in crash/restore tests; every finish verifies before broadcast.
- **Recovery:** proportion of scheduled backup drills and lost-device repairs completed without developer intervention.
- **Clarity:** users correctly identify recipient, amount, fee, memo, change, expiry, and transaction status in moderated tests.
- **Reliability:** protocol-caused failed proposals, excluding user refusal, chain conflict, and expiry; report by failure reason, not as a single success rate.

No mainnet custody claim follows from a successful prototype alone. The implementation spec requires cryptographic review, real-device restore tests, and a small-value canary.

## 9. Stories

1. As a creator, I want to choose a threshold and see its failure tolerance, so I know how many members can disappear.
2. As an invitee, I want to authenticate the group I joined, so I do not fund an attacker-created vault.
3. As a member, I want my own synced history and memos, so a Desk outage does not hide my funds.
4. As a member, I want to see how old my chain and mailbox state are, so I can tell whether I am caught up.
5. As a proposer, I want exact recipient, memo, fee, and expiry review before publication, so I can correct mistakes.
6. As an approver, I want my phone to derive the payment effects from verified bytes, so a compromised proposer cannot substitute what I sign.
7. As an approver, I want a first-time-recipient warning, so an address swap attracts attention.
8. As an approver, I want one authorization and no hidden return visit on eligible payments, so I can approve asynchronously.
9. As an approver, I want to know in advance when a payment is interactive, so I can plan a later signing step.
10. As a member, I want every proposal and approval receipt after sync, so I can see how the vault is being used.
11. As a finisher, I want to resume a signed payment after a crash, so approvals are not wasted.
12. As a member, I want a faulty share attributed correctly, so the group can use another eligible subset and investigate.
13. As a member, I want refusal and cancellation to have honest labels, so I do not mistake a cooperative stop for cryptographic revocation.
14. As a member with a lost device, I want guided repair when the old share was not copied, so I can keep the address.
15. As a member with a possibly stolen device, I want a new-vault migration path, so copied old material cannot quietly remain a custody risk.
16. As a member, I want an offline backup drill, so recovery is tested before I need it.
17. As a member, I want sealed-file exchange when relays disappear, so I am not tied to Loki's infrastructure.
18. As a member leaving Loki, I want a documented export readable by an independent tool, so the wallet is not my only recovery path.

## 10. Dependencies, decisions, and exclusions

The asynchronous promise depends first on creating real Ironwood PCZTs with caller-selected spend randomizers and on signing before anchor/proof installation. It also depends on a reviewed candidate-family verifier, safe nonce persistence on each platform, and measured cost at each supported `t,n` and action count. If any gate fails, ship the full wallet with an explicit interactive signing flow; do not relabel it one-tap.

The shared viewing material means a member can view the group's history; membership privacy inside a vault is not promised. ZIP 2005 recovery material has separate post-quantum implications. Source and decision detail live in [the technical implementation spec](LOKI_IMPLEMENTATION_SPEC.md), with the earlier [design review](LOKI_WALLET_TECHNICAL_DESIGN.md) retained as background.

## 11. Testing decisions

Tests assert observable wallet and chain behavior, not internal call counts. The release suites cover PCZT tampering, all allowed thresholds and subsets, encrypted transport under duplication/reordering/censorship, crash points around nonce consumption and broadcast, real iOS/Android restore paths, chain reorg/conflict/expiry, accessibility, and a relay-shutdown restoration drill. No existing application test pattern is available in this repository; the prior research summary describes a FROST spike, but its files are not present here and are not counted as release evidence.
