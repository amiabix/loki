# Loki on THS regtest

Date: 2026-10-08. Loki source revision: `6b31535`, with the THS harness added in
this working tree. The initial experiment left unrelated demo edits untouched.

## Reproduce

Prerequisites: Rust, Python 3, an installed `ths`, Docker, and THS runtime images.
Use an unused instance name and free loopback ports. Start THS in one terminal:

```sh
ths --name loki-experiment start --no-open --port-offset 10
```

Keep it running. In another terminal, from the repository root:

```sh
python3 poc/run-ths.py --name loki-experiment
python3 poc/run-ths.py --name loki-experiment --tamper --finish-mode replica
python3 poc/run-ths.py --name loki-experiment --finish-mode posted
```

Each invocation builds the current Loki CLI and creates a fresh temporary state
directory. It retains state and writes `ths-result.json` there on success. These
directories contain disposable member secrets: do not commit or share them.
The harness reads endpoints from THS and verifies the live node's NU6.3 branch.
It clears inherited `LOKI_ROUND` and sets `LOKI_RPC` for every Loki invocation.
It does not launch, reset, or stop THS, overwrite node configuration, or run the
original shell harnesses. Interrupt the THS terminal when finished; THS deletes
that dedicated environment. Loki's temporary files remain for local inspection.

The faucet API is called with an explicit idempotency key because the installed
launcher's faucet command failed against the running app. Details and exact image
IDs are in [THS-ISSUES.md](THS-ISSUES.md). Mining uses `ths mine`.

## Observed local finishing run

Instance: `loki-poc-20261008`; installed launcher `ths 0.3.0`; node image
`zakuracore/zakura:1.6.0`. Zakura RPC: `127.0.0.1:18242`; dashboard:
`http://127.0.0.1:32815`. The node reported NU6.3 active at height 1 and
consensus branch `37a5165b`.

- Faucet transaction:
  `de082220d4fc1a92b411bda00ceef73c68b082d22cd864574a619b88ba8ab264`.
- Vault funding: 100,000,000 zat at height 104, commitment position 4.
- Alice, Bob, and Carol reviewed and signed their respective candidates before
  the real spend had an anchor, witness, or proof.
- Alice–Carol aggregation verified under `ak + alpha`.
- Installing the anchor and witness left the effects sighash unchanged.
- Zakura accepted the proved v6 transaction:
  `1664574cab4a88aaf4efdb2bf8ae79300613ee97f4d0995341bddfc193ff748b`.
- `ths --name loki-poc-20261008 mine 3 --json` succeeded.
- `verify-effects` independently verified the mined transaction at height 105
  with 3 confirmations: payment 40,000,000 zat, change 59,990,000 zat, fee 10,000
  zat, memo `loki ths regtest`, and the expected spent nullifier.

Local state: `/tmp/loki-ths-20261008.91eRIl`.

## Observed replica finishing and refusal run

Command, from the repository root:

```sh
python3 poc/run-ths.py --name loki-poc-20261008 --tamper --finish-mode replica
```

Result: exit 0. Nine candidate alterations were refused for their expected
reasons, with neither of Alice's signature shares written: memo, recipient,
amount, change amount, change address, input, expiry, transparent pool, and
Sapling pool. The fee-only fixture could not be constructed (`ChangeRequired`)
and is not counted as a signer refusal pass. The restored honest candidates
were accepted and signed by all three members.

The replica excluded key packages, nonce secrets, and approver scan artifacts.
The finisher performed its own 110-block scan, reconstructed the witness,
aggregated the two shares, verified the unchanged sighash, proved, and broadcast:

```text
783e3250bc098162db14308d93d48952ba7d43b9afbbd0c6fe5a9978e1a350a3
```

THS mined three blocks; the transaction was included at height 111 with three
confirmations. On-chain input, recipient, payment, memo, and change matched the
intent. Amounts and fee were the same as the local finishing run.

Local state and machine-readable report:
`/var/folders/0z/lpyf2_bx1ys598dbd38c9h4r0000gn/T/loki-ths-6uzmkxrl/ths-result.json`.
This is a second process on the same machine, not a physical second device.

## Observed posted-transaction finishing run

```sh
python3 poc/run-ths.py --name loki-poc-20261008 --finish-mode posted
```

Result: exit 0. Loki proved and posted the transaction without broadcasting it.
The public replica included those bytes but no key packages, nonces, or scan
artifacts. A separate finisher scanned the chain, parsed the posted transaction,
checked the expected input nullifier, and broadcast:

```text
d201e22d973a060a3c99ad5bf798e69401980b0f12d9353ae6b3892d71d411a7
```

The transaction was mined at height 115 with three confirmations. `verify-effects`
passed with the same payment, change, fee, and memo as the other runs.
Local report:
`/var/folders/0z/lpyf2_bx1ys598dbd38c9h4r0000gn/T/loki-ths-_9qmq6a2/ths-result.json`.

## Validation

- Current-source `cargo build --locked --bin loki`: passed.
- Baseline `cargo test --locked`: 50 library tests passed; no CLI or doc tests.
- Python syntax parsing for `run-ths.py`: passed.
- `git diff --check`: passed.
- Live local finishing, replica re-proving, and posted-transaction finishing:
  passed against the artifact IDs recorded in `THS-ISSUES.md`.
- Browser engines and G3 nonce-safety drills: not run for this change.

## Limits

This establishes the exercised G1-TX flow against THS's Zakura node, not full G1.
The test-only viewing-key splice and alpha derivation assumptions still apply.
No mainnet, physical second device, relay authentication, or crash/rollback nonce
safety is established. THS supplies the chain and funding; Loki continues to own
threshold signing and proof construction. lightwalletd and the THS user-wallet
UI are not Loki's scanner or signer. The original experiment predates the demo migration; migration validation is
recorded below.

## THS replacement validation for issue #1

The migration makes THS the supported chain for every harness and the browser
runner; the standalone node configuration and binary setup have been removed.
The source branch is `feat/ths-regtest`, based on `6b31535`.

Against the same `loki-poc-20261008` instance and image IDs recorded above:

- `LOKI_THS_INSTANCE=loki-poc-20261008 ./run-regtest.sh`: exit 0, transaction
  `043bfcf9bbd1dd4d2352e6174148ef3a06027397a47f5af288c2046a12e9ff49`,
  mined at height 143 with three confirmations; approved effects verified.
- `./tamper-tests.sh` with that instance: exit 0; nine specific refusals with
  neither Alice share written, honest control accepted, fee fixture explicitly
  unconstructible. Unexpected fixture failures now fail the harness.
- `./run-second-device.sh` with that instance, rerun from a finalized script:
  exit 0. Path A transaction
  `71e00b8b04889460e1f3d1d9bf2bbe9e30050c3d263c00a56b55ca457d4e6f00`
  and path B transaction
  `4b1e00d010a609d49902ab4144c933dfe921a5e59d4a1e3115cd55dd5dab8ec3`
  were mined and verified. Approver state was moved aside during finishing.
  All five failure checks passed: approver scan artifact, missing share,
  unparseable posted bytes, another intent's posted transaction, and rebroadcast.
- Demo API setup, THS attachment/funding, scan, commitment, proposal, Alice/Carol
  signing, finish, mining, and effects verification: passed. Transaction
  `4fa0c2d88f4e6570f159bb8ddfff9c9ee6ec8adc367dedf066eefac26349659e`
  was mined at height 131 with three confirmations.
- Playwright Chromium: dynamic THS label and disconnect control verified;
  disconnect and reset left the external node reachable and its chain height
  unchanged. Screenshot: [THS demo](../docs/images/ths-demo.png).
  Firefox, WebKit, and G3 drills were not run for this migration.
- Current-source `cargo test --locked --offline`: 50 library tests passed.
- `python3 -m unittest discover -s poc/tests -v`: nine tests passed, covering
  endpoint restrictions, branch checks, funding idempotency, external ownership,
  unreachable status, and refusal/share-leak reporting.
- Python syntax parsing, shell syntax checks, and `git diff --check`: passed.

The earlier second-process run was disrupted by editing its shell script while
it was running and is not counted as a full harness pass. The finalized rerun
above completed all stages. No THS runtime or wallet source was changed.
