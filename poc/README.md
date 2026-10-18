# Loki research harness

A research prototype for **threshold-signed shielded Zcash payments**. It supports
2-of-3, 2-of-4, and 3-of-4 FROST vaults. Members sign an Ironwood payment
**before** the transaction has a proof or an anchor. A 3-of-4 regtest payment
has been mined through both the local courier and the separate member app relay flow.

The separate-member `loki_setup_member` and `loki_member_payment` commands are the
command-line vault path. The local member app also exposes Testnet setup and payment
screens with operator-configured relays ([runbook](wallet/README.md)).
The older `loki` binary uses a fixed test viewing-key
tail and refuses to run unless `LOKI_ALLOW_FIXED_VIEWING_KEY=1` is explicitly set.
The terminal research harnesses set this flag themselves. The older account demo
requires the same opt-in at server startup; the separate-member demo does not.

This is research software. **It is not a custody wallet.** What it does and does not establish is stated precisely below and in the
result documents, which are the authority.

## Public Testnet research run

The separate-member CLI accepts a `testnet` roster for a narrow two-member
approval and a third-member finish. The local member app carries that network
through create, join, backup, review, approval and send. Both paths need a fully
synced local NU7 Testnet Zebra node. The CLI uses a shared courier directory
and its volatile signing attempt; both approvers must be online. The browser
path uses the relay-backed signer and needs each member's relay connection.
Neither path has **yet** mined a public
Testnet payment. Use disposable Testnet funds only, and do not call it a released
wallet.

From `poc/`, first run `cargo build --locked --bins` and
`python3 testnet.py --rpc http://127.0.0.1:18232 --cookie-file /path/to/zebra/.cookie`.
The preflight checks genesis, NU7 branch, sync lag, and Ironwood tree availability.
Set `LOKI_TESTNET_COOKIE_FILE` to the same owner-only cookie path; optionally set
`LOKI_TESTNET_RPC` to a loopback `host:port` (default `127.0.0.1:18232`). Never put
RPC credentials in a URL or command argument.

1. Each member runs `loki_setup_member identity <member-dir> <id> <passphrase-file>`
   on their own files and shares only the printed public identity. IDs are 1, 2,
   and 3. Keep each passphrase file at mode `0600`.
2. Assemble one identical `roster.json` with a fresh random 32-byte hex `vault`,
   `"threshold":2`, `"network":"testnet"`, `"birth_height":<preflight height>`,
   and the three printed identities in `members`. No one funds the vault until
   everyone has finished backup. Every member independently runs
   `loki_setup_member fingerprint roster.json` and compares the result through a
   channel outside the courier.
3. Run `loki_setup_member run <member-dir> <passphrase-file> roster.json
   <shared-exchange-dir> <agreed-fingerprint>` in all three member processes at
   the same time. For each member, run `backup-create`, `backup-verify`, then,
   after all three verify, `backup-finalize`; `address` reveals the common Testnet
   address only after the confirmations. The exact argument order and recovery
   sequence are exercised in `tests/setup_processes.rs` and `run-member-payment.py`.
4. Fund a single Ironwood note with a small amount of Testnet ZEC from an external
   wallet, then run `loki_wallet_sync <member-dir> <passphrase-file> roster.json
   <lightwalletd-url>` and check `loki_member_payment balance <member-dir>
   <passphrase-file> roster.json`. Run `prepare <member-dir> <passphrase-file> roster.json
   <shared-payment-dir> <recipient-Testnet-UA> <amount-zat> <memo> AB`.
   Members 1 and 2 each run `loki_member_payment sign <their-member-dir>
   <their-passphrase-file> roster.json <shared-payment-dir>` at the same time and
   explicitly approve the reviewed effects. Member 3 runs the same prefix with
   `finish` in place of `sign`, syncs the indexed wallet after mining, then runs
   `verify` with the mined txid appended.

Testnet vault state binds the network and birth height into the roster fingerprint.
Balance and spending use the same encrypted, indexed wallet database. Sync it before
spending; the finisher checks its scanned block hash against the node and builds
witnesses from the stored tree data. ZIP 2005 key derivation
and the recovery tool still need independent review and a public Testnet recovery
spend before real custody use.

## Status

| | |
|---|---|
| **G1-TX** | **demonstrated on regtest** — real Ironwood payments authorized by 2-of-3 and 3-of-4 FROST groups, signed before an anchor or proof was installed, then mined |
| **Full G1** | **BLOCKED**. Separate-member setup has a local ZIP 2005 `use_qsk` derivation with an independently calculated vector and a mined regtest payment, but the derivation has not been independently reviewed or upstreamed. The original transaction CLI still uses its documented **test-only** key splice |
| **G3** (browser nonce safety) | **PARTIAL** and separate. 29/32 drills on Chromium, 6/8 on WebKit, Firefox would not launch, no physical device case tested |
| **Second-device finishing** | seed-flow THS validation: a party holding none of the approvers' files completed both posted and re-proving paths with one and two inputs. Replicas carry confidential randomizer seeds ([evidence](FROST-RANDOMIZER-RESULTS.md)) |
| **Separate-member setup** | three or four isolated processes complete DKG at threshold two or three; each member checks a 24-word and card backup before the regtest address appears. A restored 3-of-4 member signed a mined regtest payment ([details](SEPARATE-MEMBER-SETUP.md)) |
| **Signing sessions** | the relay-backed `commit`/`package`/`approve` path seals nonces across invocations and requires two pinned relay nonce receipts before signing. A separate-member 3-of-4 relay journey confirmed a payment and rejected signing from restored old nonce state; all four signer triples passed exact-set tests. The simultaneous local-courier `sign` command also mined a 3-of-4 payment but remains a RAM-only demo ([scope](SIGNING-SESSION.md)) |
| **Structured review** | the relay-enabled CLI can return a verified payment summary and exact-package review token, then recheck that token before `approve-reviewed` signs. The token binds bytes; an app still has to show the summary and obtain the member's explicit consent |
| **Recovery, key rotation, custody** | guided two-card relay-free regtest sweep added with offline scenario tests; live member journey, key rotation in the wallet, and custody readiness **not established** ([Step 4 status](../STEP4-STATUS.md)) |

## Quick start

Prerequisites: Rust, Python 3, Docker, and [THS](https://github.com/zcashlabs/thus-spoke-zakura).
No standalone node build or binary is required. See
[`harness/README.md`](harness/README.md) for installation and lifecycle details.

```sh
cd poc
cargo build --locked --bins
python3 demo/member_demo.py     # separate-member payment UI at http://127.0.0.1:8790
```

Open the coordinator link printed in the terminal. It creates a disposable
regtest vault and payment; open Alice and Bob's review links in separate browser
sessions, approve in each, then ask Carol to prove and send. See
[`demo/MEMBER-DEMO.md`](demo/MEMBER-DEMO.md) for the exact flow and limits.

The earlier account UI is still available with `LOKI_ALLOW_FIXED_VIEWING_KEY=1 python3 demo/server.py` on port
8787. In that browser UI, create the account and click **Start the test network**. It
launches its own named THS environment, discovers free loopback ports, waits for
the services, and funds the vault. Stop network, Reset, and graceful server
shutdown delete that instance using `ths --name <instance> stop`. Closing a browser
tab leaves it running. No separate THS terminal or standalone node build is needed.

For the terminal harnesses, start a separate developer-owned THS environment in
one terminal and keep it running:

```sh
ths --name loki start --no-open --port-offset 10
```

In another terminal, from `poc/`:

```sh
export LOKI_THS_INSTANCE=loki

./run-regtest.sh                # new vault, faucet funding, payment, mined effects
./run-second-device.sh          # both finishing paths and failure checks
./tamper-tests.sh               # specific signer refusals and zero shares
cd g3 && ./run-g3.sh             # separate browser nonce-safety drills
```

Loki discovers RPC from `ths endpoints`, checks the active regtest branch, funds
through the THS faucet, and mines through `ths mine`. Each CLI flow uses new
state; a supplied `LOKI_STATE` must not already exist. The CLI harnesses leave their
selected THS environment running; stop that THS terminal when finished. The
browser demo stores its account and owned-instance record under `poc/demo/.sandbox`.
After deleting its network, reset before a fresh run. Keep terminal-harness THS
instances dedicated to the experiment because those flows fund vaults and mine blocks.

Local THS setup and usage are documented in
[`harness/README.md`](harness/README.md). Earlier result documents retain
historical node details and are not instructions for the current THS setup.

## What is here

```
poc/
  src/                    the Rust prototype
    verify.rs             what a signer checks before agreeing to sign
    candidate.rs          building one unproved candidate per signing pair
    signing_session.rs    offline member-driven attempt and encrypted mailbox
    scan.rs  witness.rs   finding the account's notes, rebuilding the commitment tree
    bin/loki.rs           the CLI: setup, scan, commit, propose, review-sign, finish …
  demo/                   local account and separate-member payment UIs
  g3/                     the standalone browser nonce-safety prototype
  harness/                THS regtest setup and lifecycle instructions
  vendor/                 zakura-orchard and zakura-primitives, patched so a caller can choose
                          the signing randomiser (see vendor/README.md)

  FROST-RANDOMIZER-RESULTS.md  current seed-flow validation and live-run status
  RESULTS.md                  historical G1-TX mined transaction and approval checks
  SECOND-DEVICE-RESULTS.md    finishing without the approvers' files
  DEPENDENCIES.md             the current Zakura graph and dependency history
  ZAKURA-MIGRATION-RESULTS.md  artifact compatibility and live pair/finisher evidence
  g3/G3-RESULTS.md            the browser drills, per engine
```

The regtest indexer accepts `loki_indexer <state-dir> [cache-file] --from-height N`.
It seeds its cache from the node's Ironwood tree at block `N-1`, then scans from
block `N`. Omit the flag for the existing genesis scan. The reported `actions`
count includes commitments before `N`.

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

Recipient, amount, memo, fee, change address, change amount, input set, expiry and permitted
pools are all bound. Each signer verifies the canonical proposal ID, computes the effects
sighash locally, and checks every real spend's canonical α and `rk` against the known
vault key. It validates all relevant candidates and computes all shares before writing
any share or deleting a nonce. **A validation or signing refusal produces no new share.** `./tamper-tests.sh` alters one field at a time and
asserts both the specific refusal and zero share files.

One gap, stated plainly: the **exact-fee** check is implemented but **untested against a
real candidate**, because the fee is pinned by the inputs and outputs, so a candidate with
only the fee wrong will not build. See `RESULTS.md`.

For each real spend in AB, AC and BC, the coordinator calls the pinned library's
`RandomizedParams::new_from_commitments` with `OsRng` before passing α to the patched
builder. The returned 32-byte seed is saved in a versioned JSON record named
`randomizer_seed_AB.hex` for spend zero, `randomizer_seed_AB_1.hex` for spend one, and
likewise for AC/BC. Each record binds the proposal ID, pair, spend index, input nullifier
and exact serialized signer commitments. Review reconstructs parameters with
`regenerate_from_seed_and_commitments` and signs with `sign_with_randomizer_seed`;
finishers reconstruct and check the same parameters before aggregation. Missing or
mixed records, including seedless legacy proposals, are refused.

Restart uses the saved candidate and seed bytes. `propose` refuses any round already
containing intent, candidate, seed, alpha or share files without changing them; a fresh
honest session needs a new `LOKI_ROUND` and fresh nonce commitments. See
[current validation](FROST-RANDOMIZER-RESULTS.md) and the
[threat model](THREAT-MODEL.md).

## Honest limits

- The legacy transaction CLI uses a **test-only** `ak || nk || rivk` splice. The
  separate-member regtest flow has mined a payment using its local ZIP 2005
  derivation, but that derivation and backup format have not been independently
  reviewed.
- Regtest only, one machine and one recipient. AB/AC/BC payments and independent finishing mined under the migration; seed-based AB/AC/BC independent two-input finishing is verified offline.
- The staged relay-backed signer has a durable first-write nonce index and burns an
  interrupted attempt. Its rollback defense assumes one honest, reachable relay
  in the pinned pair. The old simultaneous signer and other prototype paths do
  not have this defense. Browser and physical power-loss behavior remain untested.
- The "second device" is a second process on the same machine reading a locally copied
  replica. Seeds require a confidential handoff; on Unix the replica directory is 0700
  and seed files are 0600. No deployed relay or second piece of hardware is
  implemented. Approver keys, nonce secrets and scan state are withheld.
- Recommended seed generation removes the custom seed derivation assumption. It does
  not prove the coordinator used honest randomness, repair nonce reuse or rollback,
  supply a security proof, or extend NCC's published audit to rerandomized FROST.
- G3's three relays are local processes on loopback. Three processes on one machine are
  not three independent operators, and that assumption is exactly what they cannot test.

## Licence

Not yet chosen. `poc/vendor/` contains third-party crates (`zakura-orchard`,
`zakura-primitives`) carrying their own upstream licences; see `poc/vendor/README.md` for
the exact published releases, upstream licences, and patches applied.
