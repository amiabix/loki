# Loki

Loki is a research prototype for shielded Zcash threshold payments. It has
separate-member command-line and local browser-app flows, plus a newer
coordinator / signer interface. **It is not a custody wallet. Use only disposable
regtest or Testnet funds.** The [research harness](poc/README.md) describes the
runs completed so far; the [security brief](docs/product/SECURITY.md) describes
the trust boundaries and work remaining before custody use.

## What runs today

| Path | Evidence and limit |
|---|---|
| Separate-member CLI and local member app | A 3-of-4 payment has been mined on regtest. The local app exposes Testnet setup and payment screens, but a public Testnet payment through the browser has not yet been mined end to end. See the [research results](poc/README.md) and [member-app runbook](poc/wallet/README.md). |
| `Signer` / `LocalSigner` seam | DKG encrypts round-two packages for roster members and seals the resulting share. The coordinator loop asks a signer to build one unsigned candidate, gathers partial signatures, and returns a signed PCZT. That loop stops before proof, broadcast, and chain confirmation ([code](poc/src/signer/coordination.rs)). |
| `frostd` transport | The relay adapter has a live 2-of-3 DKG and signature round-trip. This transport test does not establish an end-to-end payment through the newer signer seam ([adoption notes](docs/product/ADOPTION.md)). |
| Native signer | A provisioned macOS app proves persistent Secure Enclave wrapping and a Rust share-sealing self-test. It is not yet a delivered signing and approval app ([signer-app notes](poc/signer-app/README.md)). |

The newer coordinator loop does not request a share or secret nonce through its
`Signer` interface. Its request passes payment details to the proposer signer,
which builds a PCZT with its own viewing key and selected note. **The current
serialized PCZT carries the vault full viewing key in its spend data**, so the
coordinator that receives that PCZT can learn the viewing key and wallet activity.
Keyless here means no spend authority through the interface; viewing-key privacy
needs a PCZT redaction and verification fix ([candidate builder](poc/src/candidate.rs),
[PCZT spend data](poc/vendor/zakura-orchard/src/pczt.rs)). The `frostd` relay also
sees routing and session metadata.

The interface tests do not establish process isolation: `LocalSigner` is an
in-process implementation with a software key wrapper and an approval callback
([interface](poc/src/signer/mod.rs), [implementation](poc/src/signer/local.rs)).
The local Python member app holds the unlock passphrase while unlocked and can
pass it through a short-lived file to native commands ([app](poc/wallet/member_app.py)).
The separate [Testnet split-payment binary](poc/src/bin/loki_split_payment.rs)
is a research harness: it opens two members' state in one process and
auto-approves. It does not demonstrate independent signer approval.

## Before custody use

Prevent viewing-key disclosure through coordinator-visible PCZTs; finish and
test separate signer delivery and a real member confirmation and unlock gate;
validate hostile PCZTs; complete independent-device, recovery, crash, and public
Testnet payment drills; independently review Loki's ZIP-2005 viewing-key
derivation and signer/coordinator integration; and arrange an external security
audit. The [security brief](docs/product/SECURITY.md) tracks these boundaries.
The rest of [docs/product](docs/product/) includes target architecture and
workstream designs; those designs are not claims that their acceptance gates
have passed.

## Repository layout

| Path | What it contains |
|---|---|
| `poc/src/signer/` | Signer interface, local implementation, sealing, nonces, payment review, backup, and coordination loop |
| `poc/src/transport.rs` | `frostd` adapter |
| `poc/src/distributed_setup.rs`, `candidate.rs`, `signing_session.rs` | Earlier separate-member DKG and signing path |
| `poc/wallet/` | Local member app and browser UI |
| `poc/signer-app/` | macOS Secure Enclave self-test app |
| `communication/` | Bespoke relay stack used by research flows |
| `docs/product/` | Design, adoption notes, security brief, and roadmap |

## Build and test

```sh
cd poc
cargo test --locked
```

The [research harness](poc/README.md) gives the demo commands and
network-specific precautions.
