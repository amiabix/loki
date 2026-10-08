# Loki-managed THS implementation plan

Implement the approved managed-instance design in the existing
`/private/tmp/loki-ths-migration` worktree. The user explicitly defers all test
authoring until later; do not create or modify tests in this implementation.

- [x] Add a focused browser-runtime helper for dedicated instance startup,
  ownership records, available ports, live readiness, funding, and scoped stop.
  Preserve `poc/ths.py` as the external-instance helper used by terminal harnesses.
- [x] Integrate the helper with the runner, operation cancellation, stage
  prerequisites, ended-run protection, and graceful server shutdown/recovery.
- [x] Update browser status, funding progress, failures, and stop/reset controls.
- [x] Update usage documentation and remove external-instance instructions from
  the browser flow. Preserve its two 1-ZEC funding notes, required by the existing
  alternate-input security drill.
- [x] Build the worktree's Loki binary, check Python/JavaScript syntax and whitespace,
  and exercise the real browser/API flow against a disposable managed THS instance.
- [x] Verify explicit stop, interrupted startup/server shutdown, recovery, and
  preservation of the recorded unrelated Docker resources. Record actual artifacts
  and results without claiming deferred tests passed.


## Verification evidence — 2026-10-08

No test files were added or changed, and no automated test suite was run. Validation
used syntax checks, the worktree build, native Brave interaction, and the live API.

- `cargo build --locked --bin loki` passed in this worktree.
- Python compilation of `managed_ths.py`, `runner.py`, and `server.py`,
  `node --check demo/static/wallet.js`, and `git diff --check` passed.
- Brave displayed the assigned instance, block height, RPC port, distinct vault
  funding status, step progress, and the completed transaction. Browser actions
  exercised repeated Start, scan, commitments, proposal, both signatures, and Execute.
- Instance `loki-demo-a239c2d0b71441d38f6ad60c` ran on dashboard 32825,
  RPC 18252, P2P 18253, and lightwalletd 9087. Two confirmed 1-ZEC payments
  produced a 2-ZEC Loki scan. Repeated Start reused the instance and saved funding.
- Payment `0f51124ae1e5bd40093a6a8977c44032f122937312f8837774f35040fe2bc6c2`
  mined at height 107 with three confirmations. `verify-effects` confirmed
  40,000,000 zatoshis paid, memo `loki g1-tx`, 59,990,000 zatoshis change,
  and a 10,000-zatoshi fee. Only then did the UI mark it executed.
- Explicit Stop removed the owned containers, volumes, and network. An attempted
  scan on the ended run was refused. Reset removed its local account artifacts.
- A second server on port 8788 refused ownership without disturbing the live run.
- SIGTERM cleaned a running funded instance
  `loki-demo-4c55b7633d3d4d0382024ac6`. SIGTERM during partial allocation of
  `loki-demo-2189285193084055a60f6626` cleaned it before funding began.
- SIGKILL during allocation of `loki-demo-14a7c223db80485282953e02` retained
  ownership information. The next server start identified the saved launcher,
  stopped it, invoked scoped cleanup, and verified removal.
- Recovery was repeated successfully for `loki-demo-c7a0f3ba56e74a6c89706908`
  after adding ownership validation before any launcher signal.
- After these checks Docker had no containers; all four preexisting THS networks
  retained their original IDs, and all sixteen preexisting THS volumes remained.
  The demo was reset and left serving a fresh account flow at port 8787.

Artifacts: installed `ths 0.3.0`; app image
`sha256:0353489e7e1566cb55d5a788d4d081e10ee0746cd900e9b5dd9a4d99a79d173d`,
lightwalletd image
`sha256:9022dd9a5849863c8e07cf3a15e7d5268db7e52aff0edc2c3293eb8743c36693`,
and Zakura image
`sha256:bf53c178e9549217fce7cfaa21efc85c478129ba6dc5307d55640514affeb0ac`.
The installed launcher creates an unlabeled Docker network; startup recorded its
identity after an empty-name preflight. Automatic faucet replay remains disabled;
uncertain funding requires a reset until the deployed contract is independently verified.
