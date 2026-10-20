#!/usr/bin/env python3
"""Stand up the hosted (relay) stack for the web UI demo, on testnet, on macOS.

One local dev operator (hosted_ops: three loki-relay-server + loki-setup-admission)
and three member_app.py processes, all on loopback. Unlike hosted_flow.py this does
NOT use `unshare`/namespaces or the latency proxy (Linux-only, and only there to
simulate RTT) — the services bind 127.0.0.1 directly and operator.cbor already
advertises those loopback ports, so member apps reach them unchanged.

Writes web/wallet/.members.json ({members:[{id,port,token}]}) for the Next proxy,
then stays up until Ctrl-C.

    python3 wallet/launch_testnet_demo.py [--root ~/loki-hosted-demo] [--base 39100]
"""

import argparse
import json
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent          # poc/wallet
POC = HERE.parent                                # poc
REPO = POC.parent                                # repo root
LIGHTWALLETD = "https://testnet.zec.rocks:443"


def bin_poc(name):
    return POC / "target" / "release" / name


def bin_comm(name):
    return REPO / "communication" / "target" / "release" / name


def wait_port(port, limit=30):
    end = time.time() + limit
    while time.time() < end:
        try:
            socket.create_connection(("127.0.0.1", port), 0.2).close()
            return
        except OSError:
            time.sleep(0.05)
    raise SystemExit(f"port {port} never opened")


class Stack:
    def __init__(self, root, base):
        self.root = Path(root).expanduser().resolve()
        self.ports = [base + i for i in (1, 2, 3, 4)]   # relay1, relay2, relay3, admission
        self.member_ports = [base + 20 + i for i in range(3)]
        self.procs = []
        self.logs = self.root / "logs"
        self.logs.mkdir(parents=True, exist_ok=True)

    def spawn(self, argv, name, env=None):
        log = open(self.logs / f"{name}.log", "w")
        p = subprocess.Popen([str(a) for a in argv], stdout=log, stderr=subprocess.STDOUT,
                             env={**os.environ, **(env or {})})
        self.procs.append(p)
        return p

    def operators(self):
        tool = bin_poc("examples/hosted_ops")
        relay = bin_comm("loki-relay-server")
        admission = bin_comm("loki-setup-admission")
        for path in (tool, relay, admission):
            if not path.is_file():
                raise SystemExit(f"missing {path}; build with --features relay-communication (see plan)")
        ops = self.root / "ops"
        # hosted_ops init writes operator.cbor advertising 127.0.0.1:<ports>, config/issuer/signing keys,
        # per-relay provision secrets, and a provision-order; it prints the operator config key.
        self.key = subprocess.check_output(
            [str(tool), "init", str(ops), str(relay), *map(str, self.ports)], text=True).strip()
        order = (ops / "provision-order").read_text().split()
        (ops / "admission").mkdir(mode=0o700, exist_ok=True)

        admission_argv = [admission, "serve", "--root", ops / "admission",
                          "--listen", f"127.0.0.1:{self.ports[3]}", "--development"]
        for flag, name in (("--bundle-file", "operator.cbor"), ("--config-key-file", "config.key"),
                           ("--issuer-key-file", "issuer.key"), ("--signing-key-file", "signing.seed")):
            admission_argv += [flag, ops / name]
        for index, slot in enumerate(order):
            admission_argv += [f"--relay-{index + 1}-provision-file", ops / f"relay-{slot}.secret"]

        # Run the services DIRECTLY on loopback (no namespace, no proxy).
        for i in range(3):
            self.spawn([relay, "serve", "--root", ops / f"relay-{i + 1}",
                        "--listen", f"127.0.0.1:{self.ports[i]}"], f"relay-{i + 1}")
        self.spawn(admission_argv, "admission")
        for port in self.ports:
            wait_port(port)

        # The issuer wrapper member_app calls to mint its scoped enrollment grant.
        issuer = self.root / "issuer.sh"
        issuer.write_text(f'#!/bin/sh\nexec {tool} grant "$@"\n')
        issuer.chmod(0o700)
        self.issuer = issuer
        self.bundle = ops / "operator.cbor"

    def member(self, member_id, port, testnet_env):
        name = f"member-{member_id}"
        data = self.root / name / "data"
        data.mkdir(parents=True, exist_ok=True)
        exchange = self.root / name / "exchange"
        exchange.mkdir(parents=True, exist_ok=True)
        argv = [sys.executable, HERE / "member_app.py", "--bin-profile", "release",
                "--network", "testnet", "--lightwalletd-url", LIGHTWALLETD,
                "--data", data, "--exchange", exchange, "--port", str(port),
                "--transport", "hosted", "--operator-bundle", self.bundle,
                "--operator-key", self.key, "--enrollment-issuer", self.issuer,
                "--development-http"]
        p = subprocess.Popen([str(a) for a in argv], stdout=subprocess.PIPE,
                             stderr=open(self.logs / f"{name}.stderr", "w"), text=True,
                             env={**os.environ, **testnet_env})
        self.procs.append(p)
        # member_app prints "Signer: http://127.0.0.1:<port>/#<token>"
        while True:
            line = p.stdout.readline()
            if not line:
                raise SystemExit(f"{name} exited early; see logs/{name}.stderr")
            if line.startswith("Signer:"):
                return line.strip().split("#", 1)[1]

    def stop(self, *_):
        for p in reversed(self.procs):
            if p.poll() is None:
                p.terminate()
        for p in self.procs:
            try:
                p.wait(10)
            except subprocess.TimeoutExpired:
                p.kill()
        sys.exit(0)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default="~/loki-hosted-demo")
    ap.add_argument("--base", type=int, default=39100)
    ap.add_argument("--members-file", default=str(REPO / "web" / "wallet" / ".members.json"))
    args = ap.parse_args()

    # Testnet RPC for any birth-height / node query during the hosted ceremony.
    testnet_env = {}
    cookie = Path.home() / "loki-hosted-demo" / "zebra.cookie"
    try:
        raw = subprocess.check_output(
            ["docker", "exec", "loki-testnet-zebra", "cat", "/home/zebra/.cache/zebra/.cookie"])
        cookie.parent.mkdir(parents=True, exist_ok=True)
        cookie.write_bytes(raw)
        cookie.chmod(0o600)
        testnet_env = {"LOKI_TESTNET_RPC": "127.0.0.1:18232", "LOKI_TESTNET_COOKIE_FILE": str(cookie)}
    except Exception as e:
        print(f"warning: no Zebra cookie ({e}); continuing without testnet RPC env", flush=True)

    stack = Stack(args.root, args.base)
    signal.signal(signal.SIGINT, stack.stop)
    signal.signal(signal.SIGTERM, stack.stop)

    print("starting operator (hosted_ops + 3 relays + admission) on loopback...", flush=True)
    stack.operators()
    print(f"operator ready; key={stack.key[:16]}…", flush=True)

    members = []
    for i, port in enumerate(stack.member_ports, start=1):
        token = stack.member(i, port, testnet_env)
        members.append({"id": i, "port": port, "token": token})
        print(f"member {i}: http://127.0.0.1:{port}/#{token[:12]}…", flush=True)

    Path(args.members_file).write_text(json.dumps({"members": members}, indent=2))
    print(f"\nwrote {args.members_file}", flush=True)
    print("stack up. Ctrl-C to stop.", flush=True)
    while True:
        time.sleep(1)
        for p in stack.procs:
            if p.poll() is not None:
                print(f"a process exited (code {p.returncode}); see {stack.logs}", flush=True)
                stack.stop()


if __name__ == "__main__":
    main()
