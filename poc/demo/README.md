# Loki account demo on managed THS

The `/` account UI runs the real Loki prototype against a dedicated disposable
THS regtest environment that the demo starts and deletes. `/notes` keeps historical
results separate from the live network probe. This remains a research demonstration,
not custody software.

## Start

Install THS and Docker as described in [../harness/README.md](../harness/README.md),
start Docker, and make `ths` and `docker` available on PATH. `ths pull` can prepare
the launcher's runtime images beforehand. From `poc/`:

```sh
cargo build
python3 demo/server.py
```

Open `http://127.0.0.1:8787`. Pass a different demo port if needed, for example
`python3 demo/server.py 8788`. The server does not compile Loki. You do not need
to start THS in another terminal, and `LOKI_THS_INSTANCE` does not select the
browser demo's environment. That variable still selects an external environment
for the terminal harnesses.

## Account flow

Create the vault locally, then click **Start the test network**. The runner selects
an unused instance name and available loopback ports, starts `ths --no-open`,
discovers endpoints, verifies active NU6.3 regtest and current THS wallet readiness,
then requests two confirmed 1-ZEC faucet notes. The second equal-value note keeps
the existing alternate-input refusal experiment usable.

Network and funding progress are separate. The Overview shows startup, the live
block height, funding progress, and failures. Console contains launcher output.
First-time image preparation can take longer than a cached launch. Clicking
**Check network** after funding checks the same instance without recreating its
chain or requesting more funds.

Scan, prepare nonces, and propose. Alice and Carol approve; Execute aggregates,
proves, broadcasts, mines three blocks through THS, and verifies the mined effects
against the intent. A broadcast is displayed as submitted until inclusion and
effects verification succeed. Retrying Execute after a mining failure uses the
original recorded transaction instead of constructing another payment.

Security experiments restore the honest candidate and unused test nonces before
each case. A refusal requires the expected reason and no share; the honest control
must accept. This intentional nonce restoration is an experiment facility, not
crash/rollback safety.

`POST /api/run` returning `started: true` means the background operation was
accepted, not completed. Poll `/api/state` for its outcome. That endpoint includes
`network_state`, `chain_running`, `ths_instance`, discovered `endpoints`,
`funding_state`, `run_ended`, and the event buffer. Endpoint metadata and an old
completion artifact alone cannot mark the network running.

## Stop, reset, and recovery

**Stop network** invokes `ths --name <owned-instance> stop`, verifies removal of
that run's Docker resources, and reaps its launcher process. Local account artifacts
remain inspectable, but the run is ended and its stages are disabled. Reset is
required before starting another chain. **Reset** first performs the same THS
cleanup, then deletes only `poc/demo/.sandbox`.

Graceful server exit, Ctrl+C, and SIGTERM cancel or settle the active stage and
perform the same scoped cleanup. Closing or refreshing the browser tab does not
stop the network. Cleanup failures remain visible and retain the ownership record
so **Stop network** can be retried. Do not manually delete the sandbox before
cleanup: it contains the resource identities needed for recovery.

Forced termination cannot execute shutdown hooks. On the next server start, the
saved instance and launcher identities are checked and the old run is cleaned up
before a replacement can start. A fixed advisory lock beside the sandbox prevents
two demo servers from controlling it, including servers on different HTTP ports.

Faucet request identities and confirmed results are saved before proceeding.
An uncertain response is not automatically retried: the installed external-address
faucet's replay behavior is not assumed from a version string. Reset this
disposable run if funding is uncertain, rather than issuing another request that
could pay twice.

## Ownership and boundaries

Loki writes account state and the ownership manifest under the fixed
`poc/demo/.sandbox`, and holds `demo/.sandbox-server.lock`. THS owns its separate
Docker resources and launcher metadata. The demo records exact resource identities,
checks instance labels, and refuses foreign resources or replacements before
cleanup. Older launchers' unlabeled networks are accepted only when observed after
the generated name's empty preflight or matched to an already recorded identity.
Unrelated THS environments are preserved; no shared Docker pruning is performed.

All discovered HTTP endpoints and published ports stay on loopback. No browser
request supplies a path, instance name, endpoint, flag, or shell command. The
fixed step and tamper allowlists select commands with argument lists, never a shell.
Loki still owns DKG, scanning, threshold approvals, proofs, and effects verification.
THS supplies the chain, funding, and mining. The test-only vault derivation remains.

Static assets use a fixed URL-to-file map. `/notes` evidence reads only
`RESULTS.md`, `SECOND-DEVICE-RESULTS.md`, `g3/G3-RESULTS.md`, and `DEPENDENCIES.md`.
Its separate `/api/node` probe asks this demo's managed network; reachability says
nothing about inclusion of a historical recorded transaction.

## Files

- `server.py`: loopback HTTP API, static assets, server ownership lock.
- `runner.py`: fixed account stages, prerequisites, cancellation, and state.
- `managed_ths.py`: startup, resource identity, readiness, funding, mining, cleanup.
- `static/wallet.*`: account UI and operation status.
- `../ths.py`: external-instance adapter retained for the terminal harnesses.

New test authoring is deferred at the user's request. Syntax checks and a live
disposable run verify this implementation; the existing tests still describe the
previous external-instance lifecycle and need a later update.
