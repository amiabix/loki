# Loki account demo on THS

The `/` account UI runs the real Loki prototype against a selected external THS
regtest chain. `/notes` shows historical results, separately from a live THS probe.
This remains a research demonstration, not custody software.

## Start

Install THS and Docker as described in [../harness/README.md](../harness/README.md).
In one terminal:

```sh
ths --name loki start --no-open --port-offset 10
```

In another terminal, from `poc/`:

```sh
cargo build
LOKI_THS_INSTANCE=loki python3 demo/server.py
```

Open `http://127.0.0.1:8787`. Pass a different demo port if needed, for example
`python3 demo/server.py 8788`. The server does not compile Loki or start THS.

## Account flow

Create the vault, then **Connect to THS and fund the vault**. The runner discovers
endpoints with `ths endpoints`, verifies active NU6.3 regtest, and requests two
confirmed equal-value faucet notes. Scan, prepare nonces, and propose. Alice and
Carol approve; Execute aggregates, proves, broadcasts, mines three blocks through
THS, and verifies the mined effects against the intent.

Security tests restore the honest candidate and unused test nonces before each
case. A refusal requires no share; the honest control must accept. This intentional
nonce restoration is an experiment facility, not crash/rollback safety.

`POST /api/run` returning `started: true` means the task was accepted, not completed.
Poll `/api/state` and inspect Console for the outcome. The chain indicator reports
live reachability of the attached THS node, not a remembered startup result.

## Ownership

Loki writes account state only under `poc/demo/.sandbox`, a fixed path never supplied
by a web request. THS owns Docker resources, node configuration, and chain state.
**Disconnect THS**, sandbox reset, and server shutdown preserve that environment.
Reset deletes only the fixed Loki sandbox. Stop THS in its own terminal when done.

The instance name comes from `LOKI_THS_INSTANCE` at server startup (default `loki`).
All discovered HTTP services must bind loopback. No request supplies a path,
instance, flag, or shell command. Commands run with argument lists and no shell.
The faucet uses explicit idempotency keys; its CLI compatibility issue is recorded
in [../THS-ISSUES.md](../THS-ISSUES.md).

Static assets have a fixed URL-to-file map. `/notes` evidence is read only from
`RESULTS.md`, `SECOND-DEVICE-RESULTS.md`, `g3/G3-RESULTS.md`, and `DEPENDENCIES.md`.
The separate `/api/node` probe asks the selected THS environment; a reachable node
says nothing about inclusion of a historical recorded transaction.

## Check

```sh
python3 -m unittest discover -s tests -p 'test_*.py' -v
```

Run this from `poc/`. Browser and live THS checks are described in
[../THS-RESULTS.md](../THS-RESULTS.md).
