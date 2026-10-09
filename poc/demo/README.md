# Loki account demo

Two things on one local server:

- **`/`** — the **account**: a 2-of-3 multisig interface that runs the real prototype
  against a throwaway chain, and lets you try to slip an altered transaction past a signer.
- **`/notes`** — a written walkthrough of an earlier recorded run.

It is a demo of a 2-of-3 Ironwood FROST transaction, **not a usable custody wallet**.

## Start it

```
cd poc && cargo build          # once: the UI runs this binary, it will not compile for you
python3 demo/server.py         # → http://127.0.0.1:8787
```

No dependencies beyond the Python standard library. If port 8787 is taken the server says
so and exits; pass another: `python3 demo/server.py 8788`.

## Using it

The root page is the **account**: owners, balance, a transaction queue, history.

**Overview** carries a setup checklist. Each item runs a real stage against the sandbox:
create the account (2-of-3 key generation), start the test network, scan for funds, prepare
signing material, create the transaction. The whole sequence takes a few minutes, most of it
mining and generating the Halo 2 proof.

**Queue** shows the pending transaction with a confirmation counter. Expand *What exactly is
being signed* to see what an owner is agreeing to: recipient, amount, memo, change, fee, the
coin being spent, expiry. Sign as each owner in turn; at 2 of 2 the Execute button lights up
and proves, broadcasts and mines.

**Security tests** is the part worth playing with. Pick a field and the account rebuilds the
pending transaction with that one thing changed, hands it to Alice, and shows what she does.
A tile goes green only when **both** conditions hold: she rejected it *and* no signature file
was produced. A rejection that still produced one shows as `GOT THROUGH ✗`.

Run the **honest control** too. Until you have seen an owner accept a correct transaction, a
rejection proves nothing: an owner that rejects everything would score full marks.

The honest candidate and Alice's unspent nonces are snapshotted at `propose` and restored
before every case, so the experiments are repeatable and independent. Without that, re-running
`commit` would rotate her commitments and every case would reject on a stale randomiser rather
than on the field under test.

## The sandbox

| | |
|---|---|
| writes only to | `poc/demo/.sandbox` — a constant, never derived from a request |
| chain port | **18242**, not 18232, so it cannot collide with or be mistaken for a script-started node |
| zebrad config | generated into the sandbox; `harness/zebrad-regtest.toml` is never read or written |
| process control | the zebrad child is held as an object and only that object is signalled — no `pkill`, no pattern match |
| concurrency | one run at a time; a second request while busy is refused, not queued |
| teardown | `atexit` + SIGINT/SIGTERM, plus an explicit stop. **`kill -9` on the server orphans the chain** — nothing can prevent that; use `pgrep -f "harness/zebrad -c"` to find it |
| shell | none. `subprocess` with fully formed argv lists, never `shell=True` |

A request names a step from a fixed table and, for tamper, a case from a fixed set. It never
supplies a path, a flag, or an argument. `{"step":"rm -rf /"}` returns
`unknown step 'rm -rf /'`.
`POST /api/run` also requires JSON and rejects a browser Origin outside this loopback server.

**Delete the sandbox** from the page, or `rm -rf poc/demo/.sandbox`. The reset refuses to
delete anything whose resolved path is not exactly that directory.

## What the /notes page reads

Exactly four files, resolved once at startup and checked by exact path on every read:

```
poc/RESULTS.md
poc/SECOND-DEVICE-RESULTS.md
poc/g3/G3-RESULTS.md
poc/DEPENDENCIES.md
```

Every transaction id, height, `rk`, `alpha`, sighash and refusal reason on the page is
extracted from those documents at request time and carries the file it came from. A value
the extractor cannot find renders as **"not recorded"** rather than being filled in.

## What it will not do

These are properties of `server.py`, not promises:

- **No state directories, ever.** It cannot open a member directory, a key package, a
  nonce file, a note secret, or a run state directory. The allowlist above is the whole
  set of readable files.
- **No arbitrary paths.** Static assets are served from a fixed map of exact request paths
  to exact files. There is no path join from request data anywhere in the file, so there
  is no traversal to defend against. `/../RESULTS.md`, `/static/../server.py` and
  `/etc/passwd` all return 404.
- **Loopback only.** `HOST` is `127.0.0.1` and there is no flag to change it.
- **No shell.** The runner does spawn processes, but only the built `loki` binary and
  `harness/zebrad`, with fully formed argv lists chosen from a fixed table in `runner.py`.
  Never `shell=True`.

## Recorded, not live

This applies to `/notes`, not the account UI, where everything you see is a run you just
started. Everything substantive on the **walkthrough** page is from a **recorded** run and is badged as such.
There is exactly one live reading in the whole demo: `GET /api/node` asks a local node on
`127.0.0.1:18232` for its block count, and the page shows it under a separate **Live
check** badge with the explicit note that a reachable node says nothing about whether the
recorded transaction is on it.

No approval is ever animated, no progress bar fills, and selecting a stage reveals what
that stage recorded rather than playing it out.

## Why the UI does not call the shell scripts

The runner owns its sequence so the web request can show each stage and stop its own node.
Both shell scripts now create isolated scratch directories, check the ports and stop only the
node process they started. `run-second-device.sh` covers paths that the UI does not.

## Files

```
demo/server.py           stdlib HTTP server: static assets and the JSON API
demo/runner.py           the sandboxed runner: steps, process control, teardown
demo/static/wallet.html  the account UI
demo/static/wallet.css   its visual system
demo/static/wallet.js    thin client: names a step, polls state, renders the runner's events
demo/static/index.html   the written walkthrough at /notes
demo/static/app.css      the shared visual system
demo/static/app.js       walkthrough rendering
```

## One change outside demo/

`Rpc::regtest()` in `src/rpc.rs` reads `LOKI_RPC`, defaulting to the previous hard-coded
`127.0.0.1:18232`. Without it the CLI could only talk to the default port and the sandbox
could not have one of its own. Six call sites in `src/bin/loki.rs` now use it. Every
existing script behaves exactly as before.

## Checking it

```
curl -s localhost:8787/api/evidence | python3 -m json.tool | head -40
curl -s -o /dev/null -w '%{http_code}\n' 'localhost:8787/../RESULTS.md'   # 404
python3 -B demo/test_runner.py
```
