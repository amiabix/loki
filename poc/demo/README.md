# Loki POC lab

Two things on one local server:

- **`/`** — the **lab**: run the real prototype against a throwaway chain, and try to slip
  an altered transaction past a signer.
- **`/notes`** — a written walkthrough of an earlier recorded run.

It is a demo of a 2-of-3 Ironwood FROST transaction, **not a usable custody wallet**.

## Start it

```
cd poc && cargo build          # once: the lab runs the binary, it will not compile for you
python3 poc/demo/server.py     # → http://127.0.0.1:8787
```

No dependencies beyond the Python standard library. If port 8787 is taken the server says
so and exits; pass another: `python3 poc/demo/server.py 8788`.

## Using the lab

**1 · Build a payment.** Eight buttons, in dependency order. "Run all in order" does the
lot; it takes a few minutes, mostly mining and generating the Halo 2 proof. A step you run
out of order tells you what it needs.

**2 · Try to slip something past the signer.** This is the part worth playing with. Pick a
field and the lab rebuilds candidate AC with that one field changed, hands it to Alice, and
reports what she did. A tile goes green only when **both** conditions hold: a non-zero exit
*and* no share file on disk. A signer that printed a refusal and still wrote a share would
show as `NOT REFUSED ✗`.

Run the **honest control** too. Until you have seen the signer accept a correct candidate,
a refusal is not evidence of anything: a signer that refuses everything would score ten out
of ten.

The honest candidate and Alice's unspent nonces are snapshotted at `propose` and restored
before every case, so the experiments are repeatable and independent. Without that, re-running
`commit` would rotate her commitments and every case would refuse on a stale randomiser
rather than on the field under test.

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
- **No shell.** The lab does spawn processes, but only the built `loki` binary and
  `harness/zebrad`, with fully formed argv lists chosen from a fixed table in `runner.py`.
  Never `shell=True`.

## Recorded, not live

This applies to `/notes`, not the lab: in the lab everything you see is a run you just
started. Everything substantive on the **walkthrough** page is from a **recorded** run and is badged as such.
There is exactly one live reading in the whole demo: `GET /api/node` asks a local node on
`127.0.0.1:18232` for its block count, and the page shows it under a separate **Live
check** badge with the explicit note that a reachable node says nothing about whether the
recorded transaction is on it.

No approval is ever animated, no progress bar fills, and selecting a stage reveals what
that stage recorded rather than playing it out.

## Why the lab does not call the shell scripts

The lab reimplements the sequence rather than invoking `run-regtest.sh` or
`run-second-device.sh`, because those scripts are fine in a terminal and not fine behind a
web request. Four reasons, all still true of the scripts:

| hazard | where |
|---|---|
| `pkill -f 'zebrad -c harness'` matches on a command line, so it kills any `zebrad` on the machine, including one unrelated to this prototype | `run-regtest.sh:25`, `run-second-device.sh:58` |
| `rm -rf "$STATE"` where `$STATE` comes from the `LOKI_STATE` environment variable, so the path to delete is caller supplied | `run-regtest.sh:27`, `run-second-device.sh:60` |
| the scripts rewrite the tracked file `harness/zebrad-regtest.toml` in place to inject a mining address | `run-regtest.sh:36-39`, `run-second-device.sh:67-69` |
| `run-regtest.sh` does not check that port 18232 is free before starting a node on it (`run-second-device.sh` does) | `run-second-device.sh:52` |

`runner.py` does each of those things instead: its own sandbox directory, its own generated
config, its own port with a pre-flight check, a held process object rather than a pattern
kill, guaranteed teardown, and a single-run lock. The shell scripts are unchanged and remain
the way to run the full flow, including the second-device paths the lab does not cover.

## Files

```
demo/server.py           stdlib HTTP server: static assets and the JSON API
demo/runner.py           the sandboxed runner: steps, process control, teardown
demo/static/lab.html     the lab
demo/static/lab.css      control-panel layer
demo/static/lab.js       thin client: names a step, polls state, renders the runner's events
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
```
