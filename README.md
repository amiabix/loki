# Loki

**A shielded Zcash multisig wallet where no single machine can move funds.**

Loki splits a vault's spending key into FROST shares, one per member. Any `t` of the `n`
members must approve and sign a payment together; fewer than `t` cannot spend, and no
server ever holds a share.

![Loki](docs/images/loki-banner.jpg)

> **Testnet only.** Loki is not ready for real funds and refuses mainnet. Use disposable
> testnet ZEC.

## How it works

- **Vaults are t-of-n.** Any policy with `2 ≤ t < n ≤ 16`.
- **Shares are born on the member's device.** Members run a dealerless key generation
  (DKG); each share is created inside that member's signer and never leaves it. All
  members end up with the same vault address.
- **Members check who they are signing with.** Everyone compares a 24-digit roster code
  out of band before keys are generated, so nobody can slip in an extra member.
- **Every signer checks the real transaction.** Before signing, each member's signer
  rebuilds the transaction hash from the raw transaction and shows the recipient, amount
  and fee it is about to sign. Anything that doesn't match is refused.
- **The coordinator holds no keys.** It publishes the roster and relays messages. It has
  no share, nonce or spend key, so it cannot sign anything on its own.
- **Members only dial out.** All signing traffic goes through a
  [`frostd`](https://github.com/ZcashFoundation/frost) relay that every party connects
  to, so a member needs no open ports.
- **Nonces are single-use.** Each signing nonce is claimed at two independent witness
  relays before it is used, so a restored or cloned device cannot sign twice with the same
  nonce.

## Two kinds of signer

| | Native | Browser |
|---|---|---|
| Where the share lives | On the member's machine; on macOS, LokiSigner seals it under a Secure Enclave key | In the browser's private storage, sealed under a passkey or passphrase |
| Approving a payment | A native dialog (Face ID / Touch ID in LokiSigner) | A signer page on its own origin, with a passkey prompt |
| Status | Signs on testnet; the LokiSigner app is not yet hand-tested end to end | Joins, approves and signs on testnet |

The browser signer runs the same signer core compiled to WebAssembly, on a separate origin
from the wallet. It is testnet-only by design: whoever controls the site that serves it
could capture the share.

## A payment, end to end

1. A member proposes a payment in the wallet.
2. Every member sees the request; the first `t` to approve form the signing group.
3. The proposer's app builds the unsigned transaction and sends it to the group.
4. Each signer re-derives what it is signing, shows it, and asks its member to approve.
5. Each approving signer produces a signature share; the shares are combined into one
   signature and the transaction is broadcast.

A failed payment can be retried or cancelled. A retry spends the same note, so at most one
of them is ever mined.

## Status

Tested end to end on Zcash testnet: vault creation, funding, payments signed by native and
browser members together, retry and cancel, and restoring a browser member from its 24
words plus an encrypted backup.

Not done yet:

- An external security audit and an independent reproducible build.
- A browser member can approve and sign, but cannot propose a payment yet.
- The browser member's own balance and history (in review).
- The native signer app is macOS only.

## Try it (testnet)

Build the browser signer once, then run the wallet:

```sh
cd poc/loki-signer-wasm && RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack build --dev --target web
cd ../wasm-transport    && wasm-pack build --target web
cd ../../web/wallet     && npm install && npm run dev        # http://localhost:3001
```

The signer must be served from its own origin, and the relays need CORS for it. See
[`web/wallet/README.md`](web/wallet/README.md) for the full setup and
[`communication/deploy/`](communication/deploy/) for deploy scripts. To build the macOS
signer, see [`poc/signer-app/README.md`](poc/signer-app/README.md).

## Repository

| Path | What |
|---|---|
| `web/wallet/` | The wallet web app and keyless coordinator |
| `poc/loki-signer-core/` | The signer: shares, sealing, nonces, transaction checks, recovery |
| `poc/loki-signer-wasm/` | The signer core for the browser, and its signer page |
| `poc/signer-app/` | LokiSigner, the native macOS signer |
| `poc/src/host/` | The native member app: vault setup, payments, recovery |
| `communication/deploy/` | Deploy scripts for relays and fronts |

Built on the Zcash Foundation's audited FROST crates and its `frostd` relay.

## Build and test

```sh
cd poc && cargo test --locked --lib
cd web/wallet && npm test
```
