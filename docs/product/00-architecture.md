# Loki Product Architecture — Decision Record & Threat Model

Status: **LOCKED** (2026-10-18). This is the authoritative architecture for turning
Loki from a regtest research harness into a usable, non-custodial shielded Zcash
multisig wallet. All workstream specs (`ws1`…`ws6`) derive from this document.
Supersedes the earlier "web app holds keys (WASM)" direction.

---

## 1. The decision in one paragraph

Loki is a **Safe-shaped** application split into a **keyless coordinator** (the part
that proposes transactions, shows the UI, and relays messages — can be a web app)
and an **isolated signer** (the part that holds a member's FROST share and approves —
a native app whose share is wrapped by the platform secure element and gated by
biometrics). The share is **born inside the signer** during the group DKG, **never
enters the browser**, and is **decrypted into memory only at signing time** under a
biometric unlock. The coordinator only ever handles **public** data (viewing keys,
addresses, unsigned transactions, protocol messages). Signing always requires the
member's own device, and the **real transaction is confirmed on the signer**, not in
the browser. Crypto and coordination are built on the **audited Zcash Foundation (ZF)
FROST stack** (`frost-core` / `frost-rerandomized` / `reddsa`, `frostd`, and the
`frost-client` / `zcash-sign` tooling), retiring Loki's bespoke FROST, relay, and
ceremony code.

This resolves the open item in `WALLET_BUILD.md` ("browser or native key-storage
decision") and the custody warning in its *Boundaries and state* section ("a hosted
origin can change its code and read unlocked keys").

---

## 2. Why this shape (and not the alternatives)

### 2.1 The keys-in-browser problem
A web page is **server-delivered code, re-fetched every session**. Whoever controls
the origin (or compromises it, or is compelled to serve a targeted bundle) can ship
JavaScript that exfiltrates any key the page can read. Moving crypto into a Web
Worker or WASM does **not** help: the worker runs inside the same origin and the host
still chooses its code. Therefore **a web page must never hold a spend key**, not even
transiently, not even "encrypted" if the same page also holds the unlock secret.

### 2.2 How the reference wallets avoid it
- **zkool** sidesteps the problem by **not being a website**: it is a native app
  (Flutter + Rust). Each member runs their own zkool; each device holds **only that
  member's share** in a local encrypted database; **the app is the signer**. FROST
  coordination travels over **Zcash memos** (on-chain), so there is no mandatory
  central relay. Sources: Zcash forum "Multisig" thread; deepwiki `hhanh00/zkool2`.
- **vizor** ships single-sig shielded with **hardware signing** (Keystone/Ledger) via
  **PCZT** — the key lives on a device that is not the general-purpose computer.

The common thread: **the key lives somewhere the untrusted web code cannot read it.**

### 2.3 Why we still want a web coordinator
A native-only product (zkool's path) is the simplest safe option, but a web
coordinator gives the Safe-style UX the product wants: open a URL, log in, see your
vaults, propose and track payments, with **no key ever in the page**. We get that UX
*and* safety by keeping the key in a separate signer. The browser becomes a **dumb,
untrusted terminal**; worst case a malicious bundle can only *propose a wrong
transaction*, which the signer's on-device confirmation defeats (§5.4).

### 2.4 Why the Secure Enclave cannot *be* the signer
Apple's Secure Enclave (and WebAuthn/passkeys, and most TPM/StrongBox key stores)
only generate and operate **P-256 (secp256r1)** keys. Zcash FROST uses the **Pallas**
curve (RedPallas / `reddsa` over `pasta_curves`). The secure element therefore
**cannot run the FROST partial-signature math**. Its correct role is a **lock on the
share, not the signer**: it holds the wrapping key that encrypts the share at rest,
released only under biometric auth. The share is decrypted into app memory for the
duration of one signing operation, then zeroed. This is the realistic ceiling until
**FROST-capable hardware wallets** (Keystone / Frostsnap, which speak Pallas) ship;
the design keeps that upgrade path open (ws1 §Hardware).

---

## 3. Components

```
          ┌───────────────────────────────────────────────┐
          │ COORDINATOR  (keyless — may be a web app)       │
          │  • vault list / dashboard                       │
          │  • chain scan, balance, receive address         │
          │  • build unsigned PCZT payment                  │
          │  • drive FROST rounds (relay messages only)     │
          │  • apply combined signature, broadcast          │
          │  HOLDS: viewing keys, addresses, PCZTs, pubmsgs │
          │  HOLDS NO SHARE, NO NONCE, NO SPEND KEY         │
          └───────────────┬───────────────────────────────┘
                          │ frostd (audited JSON-HTTPS relay)
                          │ or serverless Zcash-memo transport
          ┌───────────────┴───────────────────────────────┐
          │ SIGNER  (native app, one per member)            │
          │  • holds THIS member's FROST share              │
          │  • runs ZF participant role (frost-client lib)  │
          │  • round 1 commitments, round 2 partial sig     │
          │  • renders the real tx; demands biometric       │
          │  SHARE: encrypted at rest, wrapped by Secure    │
          │  Enclave / StrongBox key, Face/Touch-ID gated   │
          └─────────────────────────────────────────────────┘
```

| Component | Trust | Holds keys? | Form (v1) | Form (later) |
|---|---|---|---|---|
| **Coordinator** | Untrusted terminal | No | Web app (or bundled native shell) | PWA / native |
| **Signer** | Trusted, isolated | **Yes (one share)** | Native app, Enclave-wrapped share | FROST hardware (Keystone/Frostsnap) |
| **Transport** | Honest-but-curious; sees only ciphertext | No | `frostd` (self-hostable) | serverless Zcash-memo option |

A single device may run both the coordinator and signer in one installed native app
(simplest shippable v1). "Keyless coordinator" is a **logical** boundary enforced by
process/module isolation and the rule that the share-holding module never exposes the
share across the boundary — not necessarily two machines.

---

## 4. Key lifecycle (where the secret is, at every moment)

1. **Creation (DKG).** Each member's share is generated **inside their signer** during
   the dealerless group ceremony. No share ever exists as a whole key anywhere; no
   coordinator or relay sees any share. Only **public** DKG messages cross the
   transport.
2. **At rest.** The share is sealed with a data key that is **wrapped by a secure
   element key** (Secure Enclave on iOS/macOS, StrongBox/Keystore on Android, TPM or
   OS keychain on desktop), unlockable only with the member's biometric/passphrase.
3. **Backup.** A recovery artifact (24 words + card, or a wallet-derived wrapping key
   per `WALLET_BUILD.md`) lets the member restore the share on a new device. The DKG
   share is **not** deterministically derivable from a personal wallet seed.
4. **In use (signing).** On explicit biometric approval, the share is decrypted into
   signer memory, used for the two FROST rounds for **one** candidate bound to one
   payment intent, then zeroed. Nonces are consumed under the existing single-use /
   crash-safe rules; **nonces never leave the signer**.
5. **Never.** The share, nonce, or spend authorization is **never** sent to the
   coordinator, the browser, the relay, or any Loki service.

---

## 5. Threat model

### 5.1 Assets
Member FROST shares; signing nonces; vault viewing key (confidentiality of balances
and payment graph); correctness of the signed transaction (right amount/recipient).

### 5.2 Adversaries
- **A1 — Malicious/compromised coordinator origin.** Can serve arbitrary web code.
- **A2 — Malicious relay / network MITM.** Can read, drop, reorder, replay messages.
- **A3 — Stolen/lost member device.** Attacker has the signer binary + at-rest data.
- **A4 — Compromised co-member (up to threshold-1).** A quorum-minus-one colludes.
- **A5 — Supply-chain / app-delivery.** Tampered signer binary.

### 5.3 Guarantees
| | A1 coordinator | A2 relay/MITM | A3 stolen device | A4 sub-threshold collusion | A5 supply chain |
|---|---|---|---|---|---|
| Can read a share? | **No** (never in browser) | **No** (sees ciphertext) | **No** w/o biometric (Enclave-wrapped) | **No** (each holds only own) | Mitigated by signed, independently delivered builds (ws6) |
| Can forge a spend? | **No** (needs threshold shares + device confirms) | **No** | **No** w/o biometric + still needs another member | **No** (below threshold) | Mitigated by reproducible builds + per-pair independent delivery |
| Can show a fake tx? | **Yes — defeated by §5.4** | **Yes — defeated by §5.4** | n/a | n/a | n/a |
| Can learn balances? | Yes (coordinator legitimately holds the viewing key) | **No** | Only if unlocked | Yes (members see vault) | n/a |

### 5.4 The "what you see is what you sign" rule (defeats A1/A2 tx-substitution)
The signer **independently parses the PCZT it is about to sign** and renders the
**recipient, amount, fee, change, and memo** from the bytes themselves — not from
anything the coordinator *says*. The member approves **on the signer**. A malicious
coordinator can therefore only cause a *refused* signature, never a wrong one. This
is the single most important UI invariant and is non-negotiable (ws1).

### 5.5 Out of scope / accepted
Full A5 defense (reproducible builds, signature transparency, N independently
delivered approving clients) is a hardening track (ws6), not a v1 blocker but must be
disclosed. Coordinator legitimately sees balances (it is the viewing-key holder);
members who want balance privacy from the coordinator run the signer-side scan option
(ws2 §Privacy mode). Physical coercion and endpoint malware with biometric capture
are out of scope for v1.

---

## 6. Workstreams (specs in this directory)

| ID | Title | One line | File |
|---|---|---|---|
| **WS1** | Signer | Native, Enclave-wrapped share, ZF participant, on-device tx confirmation | `ws1-signer.md` |
| **WS2** | Coordinator / Wallet | Keyless web app: scan, balance, build PCZT, drive rounds, broadcast, UX | `ws2-coordinator.md` |
| **WS3** | Transport | `frostd` adoption; serverless-memo option | `ws3-transport.md` |
| **WS4** | ZF stack adoption | Integrate `frost-client`/`zcash-sign`/`frostd`; retire bespoke FROST/relays | `ws4-zf-stack-adoption.md` |
| **WS5** | FVK derivation | Recoverable `zip2005` vs `zcash-sign generate` — decide & lock | `ws5-fvk-derivation.md` |
| **WS6** | Standards, trust & audit | ZIP-2005 #1094, grant #490 QR, Zconnect, audit scope, reproducible builds | `ws6-standards-and-audit.md` |

Sequencing and milestones: `07-roadmap.md`.

---

## 7. Invariants every workstream must uphold

1. **No key in the browser.** The coordinator module can read no share, nonce, or
   spend key — ever, encrypted or not.
2. **Share born and kept in the signer.** DKG runs in the signer; backups restore to a
   signer; the share is secure-element-wrapped and biometric-gated at rest.
3. **Confirm on the signer.** The approving member sees the real amount/recipient
   parsed from the PCZT on their own device before any share is released.
4. **Only public data crosses the coordinator boundary.** Viewing keys, addresses,
   PCZTs, and protocol messages — nothing secret.
5. **Audited crypto only.** FROST math and coordination come from the ZF stack; Loki
   writes glue, UX, scan, and the signer shell — not new threshold crypto.
6. **Test-network honesty.** Every pre-custody build shows its network plainly and
   refuses real funds, per `WALLET_BUILD.md` release boundary.
</content>
</invoke>
