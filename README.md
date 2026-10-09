# Loki

A research prototype for **threshold-signed shielded Zcash payments**: a 2-of-3 FROST
account that spends an Ironwood note, where the signature is produced **before** the
transaction has a proof or an anchor.

This is a prototype on a local regtest chain. **It is not a wallet and not custody
software.** What it does and does not establish is stated precisely below and in the
result documents, which are the authority.

## Status

| | |
|---|---|
| **G1-TX** | **demonstrated on regtest** — a real Ironwood payment, authorised by two of three FROST members, signed before its anchor and proof existed, mined |
| **Full G1** | **BLOCKED** on ZIP 2005 key derivation. `qsk → qk → rivk_ext` is implemented in no crate and the ZIP is `Status: Proposed`. The account key here is a documented **test-only** splice |
| **G3** (browser nonce safety) | **PARTIAL** and separate. 29/32 drills on Chromium, 6/8 on WebKit, Firefox would not launch, no physical device case tested |
| **Second-device finishing** | demonstrated: a party holding none of the approvers' files completed two payments, one from posted bytes and one by re-proving |
| **Separate-member setup** | three isolated processes complete DKG with encrypted peer shares and matching certificates on one machine; regtest-only, not yet connected to payments ([details](poc/SEPARATE-MEMBER-SETUP.md)) |
| **Recovery, key rotation, custody** | **not established.** No drill, no review |

## Quick start

Prerequisites: Rust, Python 3, and `zebrad` built from the pinned commit in
[`poc/harness/README.md`](poc/harness/README.md) (the 87MB binary is not committed).

```sh
cd poc
cargo build

# the interactive account UI: run the prototype from a browser
python3 demo/server.py          # → http://127.0.0.1:8787

# or straight from the terminal
./run-regtest.sh                # genesis to a mined transaction
./run-second-device.sh          # finishing without the approvers' files
./tamper-tests.sh               # the signer's refusals, 10 adversarial cases
cd g3 && ./run-g3.sh            # browser nonce-safety drills
```

## What is here

```
poc/
  src/                    the Rust prototype
    verify.rs             what a signer checks before agreeing to sign
    candidate.rs          building one unproved candidate per signing pair
    scan.rs  witness.rs   finding the account's notes, rebuilding the commitment tree
    bin/loki.rs           the CLI: setup, scan, commit, propose, review-sign, finish …
  demo/                   a local account UI that drives the real prototype
  g3/                     the standalone browser nonce-safety prototype
  harness/                regtest config, and how to build the node
  vendor/                 orchard and zcash_primitives, patched so a caller can choose
                          the signing randomiser (see vendor/README.md)

  RESULTS.md                  G1-TX: the mined transaction and the approval checks
  SECOND-DEVICE-RESULTS.md    finishing without the approvers' files
  DEPENDENCIES.md             the pinned library path, and the ZIP 2005 blocker
  g3/G3-RESULTS.md            the browser drills, per engine
```

## The claim this exists to test

A FROST signature is normally produced over a finished transaction. ZIP 229 allows the
anchor, the link to a particular chain state, to be installed afterwards. So:

```
two owners sign  →  anchor and witness installed  →  proof generated  →  mined
                    ↑ the signed content must be byte-identical across this step
```

The prototype checks that the effects sighash is unchanged by the installation, and the
resulting transaction passes consensus. That is the whole point: approval can happen
before the transaction is finishable, which is what makes asynchronous approval possible.

## What a signer checks

A signer is handed bytes by someone else; approving the wrong bytes is the entire risk.
Everything is re-derived from the transaction's own cryptography rather than trusted from
a description attached to it. The change address, for example, is computed by the signer
from the account key and never read from the proposal.

Recipient, amount, memo, change address, change amount, input set, expiry and permitted
pools are all bound. **A rejected candidate produces no signature share**, so there is
nothing to leak and nothing to retract. `./tamper-tests.sh` alters one field at a time and
asserts both the specific refusal and zero share files.

One gap, stated plainly: the **exact-fee** check is implemented but **untested against a
real candidate**, because the fee is pinned by the inputs and outputs, so a candidate with
only the fee wrong will not build. See `RESULTS.md`.

## Honest limits

- The account key is a **test-only** `ak || nk || rivk` splice, not ZIP 2005 derivation.
- Regtest only, one machine, one mined note per payment and one recipient. A two-note candidate signs, proves and extracts offline, but has not been mined in the current run.
- Member state is plain files with no rollback guarantee. A nonce is deleted after use,
  which is not a crash-safe consumed-nonce ledger.
- The "second device" is a second process on the same machine reading a locally copied
  replica. No relay, no transport authentication, no second piece of hardware.
- G3's three relays are local processes on loopback. Three processes on one machine are
  not three independent operators, and that assumption is exactly what they cannot test.

## Licence

Not yet chosen. `poc/vendor/` contains third-party crates (`orchard`,
`zcash_primitives`) carrying their own upstream licences; see `poc/vendor/README.md` for
the pinned commits and the patches applied.
