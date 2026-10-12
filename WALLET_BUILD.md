# Building Loki as a member-owned wallet

Status: implementation plan for the first usable wallet flow, not a custody release. The member app under `poc/wallet/` has one local profile per process and a separate sealed share for each vault membership. It covers create, join, roster comparison, DKG, backup and restore, a manual chain balance scan, and a fixed-pair 2-of-3 payment screen. Proposals and signing messages can travel through configured relays; a funded CLI harness has mined and received such a payment. Relay provisioning remains external to the app, setup still uses a timed local courier, and a completed browser journey has not been demonstrated. The relay adapter accepts only three-member rosters. The app hides the 2-of-4 receive address because it cannot spend from that vault through its payment screen. Persistent chain sync, resumable setup, every-pair payment orchestration, independent recovery spending, external wallet integration, and passkey unlock remain open. A crash between nonce consumption and saved-share persistence can strand an approval, so crash-safe approval is not yet established.

## Intent and scope

A person opens Loki as themselves, creates or unlocks a local profile, creates or joins a vault, and sees only the vaults in which that profile is a member. They can receive, propose, review, approve, and follow payments from their own app. A vault has a fixed member roster and threshold after activation. The first complete wallet flow still targets 2-of-3. The setup and local payment CLI now also exercise 2-of-4; its relay and payment UI are not integrated. Names, devices, proposer, approvers, and finisher are chosen by people and protocol state, not assigned to Alice, Bob, and Carol in code.

“Zcash account” means an account controlled by a person's seed wallet. “Loki profile” means the local app state that lists that person's vault memberships. A profile may belong to several vaults. The regtest reference wallet can sign a fresh challenge with its Orchard account key to make an optional local link. The random profile ID and passphrase alone prove no control of an external Zcash account, and no such proof is needed for Loki's DKG. No remote Loki service holds a member's seed, share or viewing key.

**Account connection is separate from vault signing.** Today Loki exports a fresh, expiring, domain-separated challenge naming the vault and the member's vault-specific identity. The separate reference wallet command signs it with account 0's Orchard spend authorization key; Loki verifies the proof locally. A QR or deep link and an external-wallet adapter are future transport work. The setup certificate contains the vault-specific identity, not the person's ordinary payment address or reusable account key. One wallet account can join several vaults with different member identities. Scanning a Unified Address QR alone only supplies an address; it is not proof of control. An ordinary Zcash wallet also cannot produce a Loki FROST share merely by connecting: the member's Loki signer generates that share in the group DKG. For a wallet to hold and use the share itself, it must implement Loki's FROST signing and safe nonce-storage protocol.

Recovery has a second capability requirement. The DKG share is not deterministically recoverable from the personal wallet seed. If a connected wallet can derive a domain-separated per-vault wrapping key, the member's encrypted backup card can be recovered with that wallet plus the card; otherwise the existing 24-word-and-card backup remains required. Loki must never suggest that scanning an address or restoring only the personal wallet seed restores the vault. It must not reuse a personal payment address or one public identity across vault rosters, because that would link memberships. A QR connector is implemented against one verified wallet capability at a time; the interface lists supported wallets and does not claim every Zcash wallet works.

The first implementation targets regtest. Test funding and mining are developer controls outside the member journey. No screen offers “add one test ZEC” as if it were a wallet action.

## Member journey

### What connecting the Loki signer means

Safe [connects a signer wallet](https://help.safe.global/articles/8997878213-why-do-i-need-to-connect-a-signer-wallet) that holds an owner key. That wallet, not Safe's page,
approves the eventual transaction; the Safe address is separate from the
signer's address. Loki needs the same user contract: the connected **Loki signer**
holds this member's FROST share and independently reviews a payment before
releasing a share. A personal Zcash wallet can prove account control or send funds
to the vault, but a message signature from it does not approve a FROST spend.

Example: Alice opens Loki and chooses **Connect Loki signer**. Her signer shows
Loki's origin, regtest network, requested access, and a short-lived challenge;
Alice approves there. Loki shows Alice's signer as connected and lists only the
vaults whose membership records that signer can open. Alice creates a 2-of-3
vault, sends one invite each to Bob and Carol, and waits while their own signers
join the DKG. Each person checks the same roster code and backs up their own
share. The vault then shows one receive address. Later Bob proposes a payment;
Alice opens it, and her signer independently checks the transaction and asks her
to approve. Carol does the same. A synced member finishes and broadcasts it.
Disconnecting Alice's signer ends this browser session; it does not remove her
from the vault or delete her share. Reconnecting it restores her vault list.

The regtest app now serves a dashboard and signer on separate loopback origins
from one local process. The dashboard session has explicit approval and
disconnect, reads only vault names, member slots and setup status, and can
request a vault draft that the signer separately approves. Joining, roster
agreement and backup stay in the signer window; the payment review request and relay inbox
are not connected to the dashboard. Its reference-wallet proof links an
Orchard account locally and does not give an external wallet a FROST share.

1. **Open / connect / unlock.** The regtest app creates or unlocks a local Loki profile and shows **Create vault**, **Join vault**, and the vault list. No personal-wallet proof is needed. A fresh transport identity is created for each vault; the profile does not publish one stable identity across all its vaults. A reference Zcash account may be linked separately. External-wallet QR connection and passkey unlock remain future work.
2. **Create vault.** The creator enters a name and selects 2-of-3 or 2-of-4. The app makes a random vault ID and one invite for each other member. The creator is one member by default. It shows who has accepted; the vault is a draft with no receive address.
3. **Join.** Each invitee opens the link in their own app, creates or unlocks a profile, sees the vault name, threshold, inviter identity and their assigned slot, then accepts. The bearer secret stays in the link fragment, expires, and can claim a slot only once. If someone else claims it first, the roster comparison must reveal the wrong identity and setup stops. Member labels are display names; the certified public keys and slot IDs are the identities the protocol checks.
4. **Agree and create keys.** Once all slots are filled, every app shows the same roster fingerprint and short comparison code. Each member confirms it against the others through an existing trusted channel. The apps run the existing dealerless DKG over authenticated, encrypted relay messages. DKG progress survives app restarts and does not require everyone to keep a tab open together. A mismatch or timeout stops setup and names the action needed; it never publishes a receive address.
5. **Back up.** Each member saves their own 24 words and backup card and proves they can load them. Each app publishes its signed backup confirmation. The vault becomes **Active** and reveals the shared receive address only when all three certificates and backup confirmations agree.
6. **Use the vault.** The overview shows balance at a named chain height, receive address, member list, pending payments and history. Funding comes from an external sender or a developer faucet in regtest. Each member syncs the chain for themselves.
7. **Propose.** Any member enters recipient, amount and memo. The app shows fee, change and expiry. The proposer does not choose a signing pair. The proposal fixes one payment intent and its notes and effects. The first wallet uses fresh signing commitments, sealed in each member's store, and a second visit when a candidate is ready; it does not promise one-visit approval. As commitments arrive, the clients build a candidate for each eligible pair, all bound to that intent. The first visit publishes a commitment and is labelled **Preparing**, not **Approved**.
8. **Review and approve.** Each member sees the candidate in their own inbox. Their signer rebuilds and checks every candidate that may use their share, returns the verified display, and asks for explicit approval plus unlock. A refusal is a member decision, not a veto. A share is released only for the exact checked package under the existing nonce and relay-receipt rules. Any two eligible members can complete the proposal, with the required return visit shown before anyone acts.
9. **Send and confirm.** Once a candidate has two valid shares, any synced member app can install the current anchor, prove, share the final bytes and broadcast. Each app marks **Confirmed** only after its own chain sync sees the mined payment; a reorg rolls the chain status back.
10. **Recover / leave.** A member restores from their own words and card on a new device. Leaving or removing a compromised member creates a new vault and sweeps funds; changing a label does not change the cryptographic roster.

For Alice, this means she can create the vault and also approve a payment later, but neither action makes her a permanent proposer or signer. Bob can propose while Alice and Carol approve, then finish without holding either approval share.

The app navigation follows this ownership: **Unlock Loki signer → Vault list → Create or join → Setup and backup → Vault overview / Receive / Payments / History**. Linking a personal Zcash wallet is optional and separate. There is no Alice/Bob/Carol switcher, coordinator link, or panel showing another member's private review. **Create vault** starts a draft; it cannot fabricate the invitees' profiles, accept for them, or check their backups. A test faucet and block mining live in developer tools, outside these screens.

## Boundaries and state

```mermaid
flowchart LR
  A["Alice's member app\nprofile + own share"] <-->|encrypted records| R[Relays]
  B["Bob's member app\nprofile + own share"] <-->|encrypted records| R
  C["Carol's member app\nprofile + own share"] <-->|encrypted records| R
  A --> Z[Zcash chain]
  B --> Z
  C --> Z
```

Each member app has one local profile store, one sealed vault-share store per membership, a viewing and chain-sync store, and an outbox/inbox. It may read only its own secret store. Relays retain ciphertext and receipts, and do not create vaults, choose signers, hold shares or act as a coordinator. The chain is the source of truth for balances and confirmation. A local app service may host the interface for the first native client, but each member runs a separate service and data root; no shared process owns all members. Separate directories under one OS user are useful for organization, but are not a security boundary; isolation tests use separate OS users, sandboxes or devices.

App delivery is part of custody. A hosted origin can change its code and read unlocked keys. Workers inside that origin do not protect its members from the host. A custody design needs an independently delivered app in every possible approving pair and must count every device each member uses; the regtest flow below is not a custody claim.

The durable objects are `Profile` (local identity and unlock), an optional account-control proof, `VaultDraft` (invite slots and setup progress), `VaultCertificate` (roster, threshold, group key, vault-specific member identities and confirmations), `VaultMembership` (this member's sealed share and backup epoch), `PaymentIntent` (exact effects), `Candidate` (one quorum's transaction and signing packages), and `ApprovalRecord` (one member's exact signed packages and relay receipts). The UI reads these states; it does not infer authority from an address QR, screen name or browser URL token.

Vault states are **Draft → Waiting for members → Verifying roster → Creating keys → Backing up → Active**, with explicit **Stopped** on disagreement. Payment states are **Draft → Collecting commitments → Waiting for approvals → Ready to send → Broadcast → Confirmed**; chain observations can return to an earlier pending state after a reorg. An expired, conflicting, declined or failed attempt says why and how to make a new proposal. Neither setup nor a payment silently restarts with reused signing material.

## Decisions and trade-offs

| Decision | Reason and consequence |
| --- | --- |
| Member-owned client, one store per person | This is the ownership boundary the current demo lacks. The first working client can reuse Rust through a local app service and browser interface. A browser-only WASM signer remains a separate custody-client decision; moving the code into a web worker does not by itself isolate it from its origin. |
| Invite and roster before DKG | Slot IDs and identity keys become immutable before anyone generates shares. Replacing a member during setup aborts and starts a new draft. This adds a setup step but prevents an invite or label change from silently changing the group key. |
| All eligible pairs per proposal | A 2-of-3 payment must not lock Bob out because Alice selected AC in a form. Candidates can appear as fresh commitments arrive, up to three for this configuration. This reuses the candidate and FROST primitives but needs new orchestration and tests. Preprocessed one-visit signing waits for the nonce-use witness and real-device crash gate. |
| Keep the test harness | `poc/demo/member_demo.py` and `poc/run-member-payment.py` remain disposable integration tools. Product screens do not call a process that creates every member store, auto-confirms all backups, funds from a faucet, or mines blocks. |
| Wallet connection is a capability, not an address import | A connector must demonstrate challenge signing with a verifiable account binding before Loki calls it connected. Seed-derived backup wrapping and wallet-held FROST are distinct optional capabilities, never inferred from a QR scan. The current reference command proves only the protocol shape; each external wallet needs its own compatibility check. |

## Existing code and required changes

Reusable, subject to its existing review gates: `distributed_setup` for member DKG, `setup_transport` for authenticated sealed messages, `loki_setup_member` backup and certificate checks, `member_state` sealed membership loading, `signing_session` nonce and approval rules, the candidate builder and verifier, `scan` and `witness` as the start of local chain sync, and the relay's opaque durable delivery. Setup and local courier signing now accept certified three- or four-member rosters at threshold two. The relay protocol remains fixed to three member IDs, so 2-of-4 is not yet a relay-backed wallet configuration.

Required integration work, in order:

1. A member runtime with profile creation/unlock and a private data root. Start three isolated instances in one end-to-end test; verify that a client cannot read another's store across the chosen OS or device boundary. Expose commands to the UI for **create draft**, **accept invite**, **show setup status**, **back up**, **list vaults**, and **unlock**. No global Alice/Bob/Carol server. A personal-wallet proof does not gate key creation; OS/device isolation is still unverified.
1a. The optional reference command demonstrates a short-lived challenge, verified account proof, replay refusal and a vault-specific member identity. Before a generic **Connect wallet** button, choose an external wallet that supports this signing capability, then implement QR handoff, wallet approval, disconnect and reconnect. Separately test whether it can derive a backup wrapping key or hold a FROST share; keep the two-artifact backup until those capabilities work.
2. Persisted, resumable setup messages over the relay. Adapt the current file-exchange DKG ceremony into steps that each member app advances when it opens. Verify the roster and backup gate before activation.
3. Per-member chain scan, receive screen and balance at a named height. The developer faucet stays in test tooling.
4. Payment family creation and relay publication for all three pairs. Keep one intent and exact effects, then connect each member's independent review, nonce consumption and approval to its own inbox.
5. Finishing from any synced member and confirmation from each member's chain view. Add recovery and interrupted-session drills before calling the flow complete.
6. Replace the demo navigation with profile, vault list, create/join progress, active vault, payment inbox and verified review. The UI never receives a signing share, nonce, viewing key or signature share, and cannot request signing without the member's verified approval. The unlock flow still trusts the code delivered to that member's app.

## Acceptance for the first vertical slice

Three people unlock separate Loki signers and run isolated app instances and data roots, with separate OS users, sandboxes or devices for the ownership test. None links a personal Zcash account. Alice creates and invites Bob and Carol; each accepts and keeps only their own share. Every member sees the same certified vault and restore artifacts before its address appears. An external test sender funds it; each app independently observes the deposit. Bob proposes one payment. Alice and Carol approve from their own stores, with no pair selector and no access to Bob's or each other's secrets. Bob, who did not approve, finishes on a synced device. All three apps independently show the mined transaction. Repeat with the other two pairs and with one approver offline. Kill and restart each app at setup, approval and finishing boundaries; neither activation nor signing skips a required check. Test the optional account link separately, including replay and mismatched account refusal. The previous all-in-one demo is not evidence for these checks.

## Release boundary

This design can produce a credible wallet flow on regtest. Real custody still depends on the existing ZIP 2005 and randomizer review, browser or native key-storage decision, physical crash and rollback tests, independent recovery spend, chain-sync and reorg validation, and an external security review. The first vertical slice must display its test-network status plainly and must not accept real funds.
