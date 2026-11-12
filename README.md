# Loki

Loki is a **shielded Zcash FROST multisig wallet**. It splits, Safe-style, into a
**keyless coordinator** that builds and tracks transactions and an **isolated signer**
that holds a member's key share and approves on-device. The share is **born in the
signer during DKG, never enters the browser**, and every member **confirms the real
transaction on their own device** before signing. Threshold signing and coordination
run on the audited Zcash Foundation FROST stack.

> Status: **test-network only, not custody.** Every build shows its network and refuses
> mainnet funds. See [`docs/product/SECURITY.md`](docs/product/SECURITY.md) for the
> pre-custody checklist.

## Architecture

```mermaid
flowchart TB
  subgraph C["Coordinator — keyless (may be a web app)"]
    UI["Wallet UI · vaults · propose · track"]
    BUILD["Scan · balance · build unsigned PCZT"]
    AGG["Aggregate partials · apply · broadcast"]
  end
  subgraph S["Signer — isolated, one per member"]
    SHARE[("FROST share<br/>secure-element-wrapped")]
    WYS["WYSIWYS: parse PCZT →<br/>render → approve → sign"]
  end
  CHAIN[("Zcash chain<br/>via lightwalletd")]

  C <-->|"frostd — public FROST messages only"| S
  BUILD <--> CHAIN
  AGG --> CHAIN

  classDef keyless fill:#0b3,stroke:#063,color:#fff;
  classDef secret fill:#915,stroke:#508,color:#fff;
  class C keyless
  class S secret
```

The coordinator holds **public protocol messages and the vault address** — never a
share, nonce, viewing key, or spend key; the signer builds the candidate PCZT. The
signer holds exactly **one share**, wrapped by the device secure element (Secure Enclave
/ StrongBox / TPM; software fallback for dev). `frostd` relays only public FROST
messages and DKG round-two envelopes sealed under one-setup fresh keys. Any `t`-of-`n`
policy with 2 ≤ t < n ≤ 16 is supported.

Full design, threat model, and invariants: [`docs/product/`](docs/product/).

## What works today

| Area | State |
|---|---|
| General **t-of-n** DKG → sign → aggregate → verify (2 ≤ t < n ≤ 16) | ✅ `(2,3) (3,5) (15,16)` on the hosted engine and the new signer; 2-of-5 over the real relay stack |
| Keyless coordinator boundary (no share/nonce/spend key) | ✅ compile-time + deny-list enforced |
| Signer: **WYSIWYS→sighash binding**, single-use crash-safe nonces, fee integrity | ✅ tested |
| Share born-in-signer (v2 DKG: on-device roster code, fresh-key round two, ready after every backup) + **backup / restore** with nonce-epoch reset | ✅ tested |
| Transport over audited **`frostd`** (typed sends, coordinator relay log) | ✅ live 2-of-3 setup + signing through `LocalSigner` |
| Secure Enclave backend (wrap/unwrap the share key) | 🔬 spike proven ([`poc/enclave-spike`](poc/enclave-spike)) |

## Pending (pre-custody)

Real Secure Enclave / StrongBox backend + biometric gate; native app shell + web
coordinator deployment; retire the bespoke relays; external security audit; reorg/crash
and recovery-spend drills. Tracked in [`docs/product/07-roadmap.md`](docs/product/07-roadmap.md).

## Repository layout

| Path | What |
|---|---|
| `poc/src/signer/` | The isolated signer: `Signer` trait, `LocalSigner`, sealing, nonces, WYSIWYS, backup |
| `poc/src/coordinator_boundary.rs` | The keyless coordinator↔signer seam |
| `poc/src/transport.rs` | `frostd` transport |
| `poc/src/distributed_setup.rs`, `candidate.rs`, `signing_session.rs` | General t-of-n DKG + signing |
| `poc/src/scan.rs`, `witness.rs`, `loki_wallet_sync` | Chain scan / balance (coordinator) |
| `poc/wallet/design/` | Wallet UI design prototype |
| `poc/enclave-spike/` | Secure Enclave feasibility spike |
| `communication/` | Bespoke relay stack (being retired in favour of `frostd`) |
| `docs/product/` | Architecture, per-workstream specs, security, roadmap, design |

## Build & test

The crypto core builds with Cargo; threshold tests exercise the audited FROST crates.

```sh
cd poc
cargo test --locked
```

Preview the wallet UI design prototype:

```sh
poc/wallet/design/serve.sh   # then open http://localhost:8080/design/
```

Use only disposable test-network funds.
