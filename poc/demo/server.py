#!/usr/bin/env python3
"""Local demo server for the Loki research POC.

Loopback-only and deliberately narrow. It exposes three things:

  GET  /                 the account UI: run Loki stages against a demo-owned THS chain
  GET  /notes            the written walkthrough of the recorded run
  GET  /api/evidence     numbers extracted from an ALLOWLIST of public result files
  GET  /api/node         whether the demo-owned THS regtest node answers
  GET  /api/state        sandbox runner state and its event buffer
  POST /api/run          start one named step from a fixed list (see runner.py)

What it will not do, by construction rather than by convention:

  * It never opens a member directory, a key package, a nonce file, a note secret, or a
    state directory. The only files it may read are the four public result documents in
    SOURCES below, resolved once at startup and compared by exact path.
  * It serves static assets only from demo/static, by exact filename from a fixed map.
    There is no path join from request data anywhere in this file.
  * It binds 127.0.0.1. There is no option to bind anything else.
  * It runs no SHELL. The runner does spawn processes, but only the built `loki` binary and
    fixed THS, Docker inspection, and process inspection commands.
    A request names a step; it never supplies a path, a flag, or an argument. See
    runner.py for the sandbox, port and teardown guarantees.

Everything /api/evidence returns is from a RECORDED run and is labelled as such. The /notes live probe is reported separately from its historical evidence. The account
UI runs real stages against THS.
"""

from __future__ import annotations

import json
import fcntl
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from runner import SANDBOX as RUNNER_SANDBOX, RUNNER, TAMPER_CASES, loki_bin

HOST = "127.0.0.1"
PORT = 8787

DEMO = Path(__file__).resolve().parent
POC = DEMO.parent
STATIC = DEMO / "static"

# The complete set of files this server may read. Resolved at import time; any read is
# checked against these exact resolved paths.
SOURCES = {
    "g1": POC / "RESULTS.md",
    "second_device": POC / "SECOND-DEVICE-RESULTS.md",
    "g3": POC / "g3" / "G3-RESULTS.md",
    "deps": POC / "DEPENDENCIES.md",
}
_ALLOWED = {p.resolve() for p in SOURCES.values()}

# Static assets, by exact name. Nothing is derived from the request path.
ASSETS = {
    "/": (STATIC / "wallet.html", "text/html; charset=utf-8"),
    "/wallet.html": (STATIC / "wallet.html", "text/html; charset=utf-8"),
    "/wallet.css": (STATIC / "wallet.css", "text/css; charset=utf-8"),
    "/wallet.js": (STATIC / "wallet.js", "text/javascript; charset=utf-8"),
    "/notes": (STATIC / "index.html", "text/html; charset=utf-8"),
    "/index.html": (STATIC / "index.html", "text/html; charset=utf-8"),
    "/app.css": (STATIC / "app.css", "text/css; charset=utf-8"),
    "/app.js": (STATIC / "app.js", "text/javascript; charset=utf-8"),
}


def read_source(key: str) -> str:
    """Read one allowlisted file. Raises if the path is not in the allowlist."""
    path = SOURCES[key].resolve()
    if path not in _ALLOWED:
        raise PermissionError(f"not an allowlisted source: {path}")
    return path.read_text(encoding="utf-8")


def find(text: str, pattern: str, group: int = 1):
    m = re.search(pattern, text, re.MULTILINE)
    return m.group(group).strip() if m else None


def datum(value, source: str, note: str = ""):
    """One piece of evidence, carrying where it came from.

    `provenance` is always "recorded": nothing in this endpoint is live. A missing value
    stays None so the page can say "not recorded" instead of inventing a number.
    """
    return {"value": value, "source": source, "provenance": "recorded", "note": note}


def build_evidence() -> dict:
    g1 = read_source("g1")
    sd = read_source("second_device")
    g3 = read_source("g3")

    # ── the mined G1-TX payment ─────────────────────────────────────────────
    txid = find(g1, r"^txid\s+([0-9a-f]{64})$")
    mined = find(g1, r"^mined\s+height (\d+), (\d+) confirmation", 0)
    height = find(g1, r"^mined\s+height (\d+),")
    confs = find(g1, r"^mined\s+height \d+, (\d+) confirmation")
    anchor = find(g1, r"^anchor\s+([0-9a-f]+)…")
    anchor_h = find(g1, r"installed after signing, at height (\d+)")
    network = find(g1, r"^network\s+(.+)$")
    date = find(g1, r"^Date (\S+)\.")

    # ── the three candidate pairs ───────────────────────────────────────────
    pairs = []
    for name in ("AB", "AC", "BC"):
        row = find(g1, rf"^{name}\s+rk ([0-9a-f]+)…\s+alpha ([0-9a-f]+)…\s+(\d+) bytes", 0)
        rk = find(g1, rf"^{name}\s+rk ([0-9a-f]+)…")
        alpha = find(g1, rf"^{name}\s+rk [0-9a-f]+…\s+alpha ([0-9a-f]+)…")
        size = find(g1, rf"^{name}\s+rk [0-9a-f]+…\s+alpha [0-9a-f]+…\s+(\d+) bytes")
        sighash = find(g1, rf"{name} `([0-9a-f]+)…`")
        pairs.append({
            "name": name,
            "members": {"AB": ["alice", "bob"], "AC": ["alice", "carol"],
                        "BC": ["bob", "carol"]}[name],
            "rk": rk, "alpha": alpha, "bytes": int(size) if size else None,
            "sighash": sighash,
            "mined": name == "AC",
            "raw": row,
        })

    # ── the signer's refusals, from the adversarial run ─────────────────────
    # The block in RESULTS.md wraps long reasons onto deeply indented continuation lines.
    # Those are rejoined here so the page shows the whole reason, not a truncated one.
    tamper = []
    for line in g1.splitlines():
        m = re.match(r"^(\S+)\s+refused, 0 shares\s+<- (.+)$", line)
        if m:
            tamper.append({"case": m.group(1), "outcome": "refused, 0 shares",
                           "reason": m.group(2).strip()})
            continue
        m = re.match(r"^(\S+)\s+COULD NOT CONSTRUCT: (.+)$", line)
        if m:
            tamper.append({"case": m.group(1), "outcome": "could not construct",
                           "reason": m.group(2).strip()})
            continue
        if tamper and re.match(r"^ {30,}\S", line):
            tamper[-1]["reason"] += " " + line.strip()
    # `fee` appears twice in the document: once in the run block and again in the section
    # that explains why it cannot be constructed. Keep the first occurrence only.
    seen, deduped = set(), []
    for c in tamper:
        if c["case"] in seen:
            continue
        seen.add(c["case"])
        deduped.append(c)
    tamper = deduped
    tamper_total = find(g1, r"^(\d+ passed, \d+ failed, \d+ could not be constructed)$")

    # ── second device ───────────────────────────────────────────────────────
    sd_paths = []
    for tag, label in (("p1", "A"), ("p2", "B")):
        tx = find(sd, rf"^{tag}\s+path {label}\s+txid ([0-9a-f]{{64}})$")
        scan = find(sd, rf"^{tag}\s+own scan: (.+)$")
        sd_paths.append({"payment": tag, "path": label, "txid": tx, "own_scan": scan})
    sd_h = re.search(r"^\| mined at height \| (.+?) \| (.+?) \|$", sd, re.MULTILINE)
    if sd_h:
        sd_paths[0]["mined"] = sd_h.group(1).strip()
        sd_paths[1]["mined"] = sd_h.group(2).strip()

    # ── G3 ─────────────────────────────────────────────────────────────────
    g3_rows = []
    for engine in ("chromium", "webkit", "firefox"):
        row = re.search(rf"^{engine}\s+(\S+)\s+(full|portable) suite\s+(.+)$",
                        g3, re.MULTILINE)
        g3_rows.append({
            "engine": engine,
            "version": row.group(1) if row else None,
            "suite": row.group(2) if row else None,
            "counts": row.group(3).strip() if row else None,
        })
    g3_headline = find(g3, r"^## (G3 PARTIAL\..+)$")

    return {
        "generated_by": "poc/demo/server.py",
        "provenance_note": (
            "Every value below comes from a RECORDED run, read out of the result "
            "documents listed in `sources`. Nothing here is live. The only live reading "
            "in this demo is /api/node."
        ),
        "recorded_date": date,
        "sources": {k: str(v.relative_to(POC.parent)) for k, v in SOURCES.items()},
        "g1tx": {
            "txid": datum(txid, "RESULTS.md"),
            "height": datum(int(height) if height else None, "RESULTS.md"),
            "confirmations": datum(int(confs) if confs else None, "RESULTS.md"),
            "anchor": datum(anchor, "RESULTS.md",
                            f"installed after signing, at height {anchor_h}"),
            "anchor_height": datum(int(anchor_h) if anchor_h else None, "RESULTS.md"),
            "network": datum(network, "RESULTS.md"),
        },
        "pairs": pairs,
        "tamper": {"cases": tamper, "total": datum(tamper_total, "RESULTS.md")},
        "second_device": {"paths": sd_paths, "source": "SECOND-DEVICE-RESULTS.md"},
        "g3": {"headline": datum(g3_headline, "g3/G3-RESULTS.md"), "engines": g3_rows},
        "status": [
            {"id": "g1tx", "state": "demonstrated",
             "label": "G1-TX demonstrated on regtest",
             "short": "G1-TX shown",
             "detail": "A real Ironwood payment, authorised by two of three FROST "
                       "members, signed before its anchor and proof existed, mined on a "
                       "local regtest chain."},
            {"id": "g1", "state": "blocked",
             "label": "Full G1 blocked by ZIP 2005 key derivation",
             "short": "G1 blocked",
             "detail": "The vault key is a documented TEST-ONLY splice. ZIP 2005's "
                       "qsk to qk to rivk_ext derivation is implemented in no crate and "
                       "the ZIP is Status: Proposed."},
            {"id": "g3", "state": "partial",
             "label": "G3 browser nonce work partial and separate",
             "short": "G3 partial",
             "detail": "A standalone browser prototype, not part of this transaction "
                       "path. Two colluding relays still defeat it and no physical "
                       "device case has been tested."},
            {"id": "custody", "state": "not-established",
             "label": "Recovery and custody release not established",
             "short": "custody: no",
             "detail": "No recovery drill, no key rotation, no custody review. Two "
                       "regtest payments on a test-only key are not custody evidence."},
        ],
    }


def probe_node(timeout: float = 0.6) -> dict:
    """Probe the demo-owned chain separately from historical experiment evidence."""
    endpoint = None
    try:
        chain = RUNNER.ths
        if not chain or RUNNER.network.ended:
            raise RuntimeError("start the demo test network first")
        endpoint = chain.rpc_address
        chain.check()
        return {"reachable": True, "tip": chain.rpc("getblockcount", timeout=timeout),
                "endpoint": endpoint, "provenance": "live",
                "note": "A THS node answered. This does not establish inclusion of a recorded payment."}
    except Exception as error:
        return {"reachable": False, "endpoint": endpoint, "provenance": "live",
                "reason": str(error),
                "note": "Demo THS instance unavailable; historical evidence is unaffected."}


class Handler(BaseHTTPRequestHandler):
    server_version = "loki-demo"

    def _send(self, code: int, body: bytes, ctype: str):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        # The page is self-contained: no external origins, no inline event handlers.
        self.send_header("Content-Security-Policy",
                         "default-src 'none'; style-src 'self'; script-src 'self'; "
                         "img-src 'self' data:; connect-src 'self'; base-uri 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj):
        self._send(code, json.dumps(obj, indent=2).encode(), "application/json")

    def do_GET(self):
        path = self.path.split("?", 1)[0]

        if path == "/api/evidence":
            try:
                return self._json(200, build_evidence())
            except Exception as e:                       # surface it, do not fake data
                return self._json(500, {"error": f"{type(e).__name__}: {e}"})

        if path == "/api/node":
            return self._json(200, probe_node())

        if path == "/api/wallet":
            return self._json(200, RUNNER.wallet())

        if path == "/api/state":
            st = RUNNER.snapshot()
            st["loki_built"] = loki_bin() is not None
            st["tamper_cases"] = list(TAMPER_CASES)
            return self._json(200, st)

        asset = ASSETS.get(path)
        if asset is None:
            return self._json(404, {"error": "not found", "served": sorted(ASSETS)})
        file, ctype = asset
        try:
            return self._send(200, file.read_bytes(), ctype)
        except OSError as e:
            return self._json(500, {"error": f"{type(e).__name__}: {e}"})

    def do_POST(self):
        path = self.path.split("?", 1)[0]
        if path != "/api/run":
            return self._json(404, {"error": "not found"})
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(min(n, 4096)) or b"{}")
        except (ValueError, OSError) as e:
            return self._json(400, {"error": f"bad body: {e}"})
        # Only a step name and, for tamper, a case name. Both are checked against fixed
        # sets inside the runner; nothing from here becomes a path, a flag or a command.
        step = str(body.get("step", ""))[:40]
        arg = body.get("case")
        arg = str(arg)[:40] if arg is not None else None
        return self._json(200, RUNNER.start(step, arg))

    def log_message(self, fmt, *args):
        sys.stderr.write(f"  {self.address_string()} {fmt % args}\n")


def main() -> int:
    port = PORT
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            print(f"usage: {sys.argv[0]} [port]", file=sys.stderr)
            return 2

    missing = [str(p) for p in SOURCES.values() if not p.exists()]
    if missing:
        print("missing result files:", *missing, sep="\n  ", file=sys.stderr)
        return 1

    lock = (DEMO / ".sandbox-server.lock").open("a")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        print("another demo server already owns this sandbox; stop it first", file=sys.stderr)
        lock.close()
        return 1

    try:
        srv = ThreadingHTTPServer((HOST, port), Handler)
    except OSError as e:
        # Without this the process dies quietly into a log file and an older instance
        # keeps serving stale code, which is exactly how this went wrong once.
        print(f"cannot bind {HOST}:{port}: {e}", file=sys.stderr)
        print(f"something is already listening. Stop it, or pass another port: "
              f"python3 {sys.argv[0]} 8788", file=sys.stderr)
        return 1
    print(f"Loki account demo on http://{HOST}:{port}")
    if loki_bin() is None:
        print("  WARNING: the loki binary is not built. Run: cd poc && cargo build")
    print(f"  reading only: {', '.join(str(p.relative_to(POC)) for p in SOURCES.values())}")
    print(f"  loopback only. Runs the prototype in a sandbox: {RUNNER_SANDBOX}")
    RUNNER.active = True
    RUNNER.recover()
    print("  Start test network launches a dedicated THS instance and funds the vault")
    print("  ctrl-c stops the demo and deletes its THS instance with ths stop")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        RUNNER.shutdown()
        srv.server_close()
        lock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
