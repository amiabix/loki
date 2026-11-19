![Loki](docs/images/loki-banner.jpg)

> [!WARNING]
> **Testnet only**, Loki is not ready for real funds and refuses mainnet, use disposable
> testnet ZEC.

# Loki

**A shielded Zcash multisig wallet where no single machine can move funds.**

Loki splits a vault's spending key into FROST shares, one per member, and any `t` of the
`n` members must approve and sign a payment together, fewer than `t` cannot spend and no
server ever holds a share.

## How it works

- **Vaults are t-of-n**, any policy with `2 ≤ t < n ≤ 16`.
- **Shares are born on the member's device**, members run a dealerless key generation
  (DKG), each share is created inside that member's signer and never leaves it, and all
  members end up with the same vault address.
- **Members check who they are signing with**, everyone compares a 24-digit roster code
  out of band before keys are generated, so nobody can slip in an extra member.
- **Every signer checks the real transaction**, before signing, each member's signer
  rebuilds the transaction hash from the raw transaction and shows the recipient, amount
  and fee it is about to sign, and anything that doesn't match is refused.
- **The coordinator holds no keys**, it publishes the roster and relays messages, with no
  share, nonce or spend key, so it cannot sign anything on its own.
- **Members only dial out**, all signing traffic goes through a
  [`frostd`](https://github.com/ZcashFoundation/frost) relay that every party connects
  to, so a member needs no open ports.
- **Nonces are single-use**, each signing nonce is claimed at two independent witness
  relays before it is used, so a restored or cloned device cannot sign twice with the same
  nonce.

## Two kinds of signer

| | Native | Browser |
|---|---|---|
| Where the share lives | On the member's machine, on macOS LokiSigner seals it under a Secure Enclave key | In the browser's private storage, sealed under a passkey or passphrase |
| Approving a payment | A native dialog, with Face ID / Touch ID in LokiSigner | A signer page on its own origin, with a passkey prompt |

The browser signer runs the same signer core compiled to WebAssembly, on a separate origin
from the wallet, and whoever controls the site that serves it could capture the share.

## A payment, end to end

1. A member proposes a payment in the wallet.
2. Every member sees the request, and the first `t` to approve form the signing group.
3. The proposer's app builds the unsigned transaction and sends it to the group.
4. Each signer re-derives what it is signing, shows it and asks its member to approve.
5. Each approving signer produces a signature share, the shares are combined into one
   signature and the transaction is broadcast.

A failed payment can be retried or cancelled, and since a retry spends the same note, at
most one of them is ever mined.

## Try it

Build the browser signer once, then run the wallet:

```sh
cd core/loki-signer-wasm && RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack build --dev --target web
cd ../wasm-transport    && wasm-pack build --target web
cd ../../web/wallet     && npm install && npm run dev        # http://localhost:3001
```

The signer must be served from its own origin and the relays need CORS for it, see
[`web/wallet/README.md`](web/wallet/README.md) for the full setup,
[`communication/deploy/`](communication/deploy/) for deploy scripts and
[`core/signer-app/README.md`](core/signer-app/README.md) to build the macOS signer.

## Architecture

Every party dials out, secrets stay on member devices, and the shared services only ever
see public or sealed data.

```mermaid
%%{init: {"theme":"base","themeVariables":{"background":"#0A0C10","primaryColor":"#12151C","primaryTextColor":"#E8EAF0","primaryBorderColor":"#2FD8A8","lineColor":"#5B6475","secondaryColor":"#181C25","tertiaryColor":"#0A0C10","clusterBkg":"#0E1117","clusterBorder":"#2A303C","fontFamily":"Inter, sans-serif","fontSize":"14px","edgeLabelBackground":"#0A0C10"}}}%%
flowchart TB
  subgraph MEMBERS["Member devices · the only place a share exists"]
    direction LR
    subgraph NATIVE["Native member"]
      direction LR
      NAPP["Member app<br/>vault setup · payments · recovery"]
      NCORE["Signer core<br/>FROST share · nonce store · tx checks"]
      SE[("Secure Enclave key<br/>seals the share")]
      NAPP --> NCORE --> SE
    end
    subgraph BROWSER["Browser member"]
      direction LR
      PAGE["Wallet page<br/>wallet origin"]
      SPAGE["Signer page<br/>own origin · strict CSP"]
      WORKER["Signer core in WASM<br/>Web Worker · chain scan"]
      OPFS[("OPFS + IndexedDB<br/>sealed by passkey PRF")]
      PAGE -- postMessage --> SPAGE --> WORKER --> OPFS
    end
  end

  subgraph SHARED["Shared services · no shares, no nonces, no spend keys"]
    direction LR
    COORD["Keyless coordinator<br/>public roster · pairing"]
    FROSTD{{"frostd relay<br/>DKG + signing rounds<br/>sealed member messages"}}
    WIT{{"2 witness relays<br/>single-use nonce claims"}}
    LWD[("lightwalletd<br/>gRPC · gRPC-web front")]
  end

  ZEC[("Zcash")]

  MEMBERS -- "enroll · roster" --> COORD
  MEMBERS -- "dial out" --> FROSTD
  MEMBERS -- "claim nonce" --> WIT
  MEMBERS -- "scan · broadcast" --> LWD
  LWD --- ZEC

  classDef member fill:#12151C,stroke:#2FD8A8,color:#E8EAF0;
  classDef secret fill:#1A1608,stroke:#E8B44A,color:#F3E3B8;
  classDef shared fill:#12151C,stroke:#5B6475,color:#C9CED9;
  classDef chain fill:#0A0C10,stroke:#E8B44A,color:#E8B44A;
  class NAPP,NCORE,PAGE,SPAGE,WORKER member
  class SE,OPFS secret
  class COORD,FROSTD,WIT,LWD shared
  class ZEC chain
```

A payment, from proposal to broadcast:

```mermaid
%%{init: {"theme":"base","themeVariables":{"background":"#0A0C10","primaryColor":"#12151C","primaryTextColor":"#E8EAF0","primaryBorderColor":"#2FD8A8","lineColor":"#5B6475","actorBkg":"#12151C","actorBorder":"#2FD8A8","actorTextColor":"#E8EAF0","signalColor":"#8B93A7","signalTextColor":"#E8EAF0","noteBkgColor":"#181C25","noteBorderColor":"#E8B44A","noteTextColor":"#E8EAF0","activationBkgColor":"#13A57E","activationBorderColor":"#2FD8A8","sequenceNumberColor":"#0A0C10","fontFamily":"Inter, sans-serif"}}}%%
sequenceDiagram
  autonumber
  participant P as Proposer
  participant F as frostd
  participant M as Other members
  participant W as Witness relays
  participant L as lightwalletd

  P->>F: payment intent, sealed to each member
  F->>M: intent
  M->>F: approvals, the first t form the signing group
  Note right of P: build the unsigned transaction (PCZT)
  P->>F: candidate transaction to the group
  F->>M: candidate
  Note over P,M: each signer re-derives the sighash from the raw transaction,<br/>shows recipient, amount and fee, and asks its member to approve
  P->>W: claim signing nonce
  M->>W: claim signing nonce
  M->>F: signature share
  Note right of P: aggregate t shares into one signature
  P->>L: broadcast
```

Built on the Zcash Foundation's audited FROST crates and its `frostd` relay.

## Build and test

```sh
cd core && cargo test --locked --lib
cd web/wallet && npm test
```
