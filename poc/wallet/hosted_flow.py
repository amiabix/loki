"""Hosted (relay) mode end to end: real operators, three member apps, one mined payment.

    python3 wallet/hosted_flow.py run --root NEW_DIR [--profile release|debug] [--rtt MS]
                                      [--ths NAME] [--skip-payment] [--isolation unshare|netns]
    python3 wallet/hosted_flow.py report DIR

`run` starts three `loki-relay-server` processes and `loki-setup-admission` in their
own network namespace, three `member_app.py --transport hosted` processes, and drives
the whole journey through the same signer API the browser uses, acting immediately on
every human step and polling every 0.1 s. It writes `DIR/hosted-flow-report.json`:
phase marks and segment durations, per-command native timings (`LOKI_TIMING_LOG`),
HTTP requests and TCP connections per operator, and Argon2id counts when the binaries
were built with `--features kdf-stats`.

Isolation. Relays must listen on the loopback endpoint written in their manifest, so a
latency proxy cannot sit on the same port in the same namespace. The default
`unshare` mode needs no root: operators run under `unshare -rn` (a private user and
network namespace) and are reached through Unix sockets; a proxy in the host namespace
listens on each manifest endpoint and adds RTT/2 per direction. `--isolation netns`
uses a prepared root network namespace instead:

    sudo ip netns add lokins
    sudo ip link add veth-host type veth peer name veth-ns
    sudo ip link set veth-ns netns lokins
    sudo ip addr add 10.200.0.1/24 dev veth-host && sudo ip link set veth-host up
    sudo ip netns exec lokins sh -c 'ip addr add 10.200.0.2/24 dev veth-ns; ip link set veth-ns up; ip link set lo up'

The binaries come from `poc/target/<profile>` (including `examples/hosted_ops`, built
with `cargo build --profile <profile> --example hosted_ops --features relay-communication`)
and `communication/target/<profile>`. A THS regtest instance is needed only for the
payment part.
"""
import argparse
import collections
import json
import os
from pathlib import Path
import signal
import socket
import statistics
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
PROXY = HERE / "hosted_flow_proxy.py"
SERVICES = ("relay1", "relay2", "relay3", "admission")

# Segments reported against the baseline (`start`, `end` marks).
SEGMENTS = (
    ("create → invites ready", "profiles_created", "invites_ready"),
    ("last join → roster proposed", "joined_carol", "creator_fingerprint_shown"),
    ("creator proposal → joiners show fingerprint", "creator_fingerprint_shown", "joiner_fingerprints_in_ui"),
    ("DKG (agree → backup phase)", "agreed", "dkg_done_backup_phase"),
    ("backups + certify + final card + activate", "dkg_done_backup_phase", "payment_activation_ready"),
    ("setup total", "profiles_created", "payment_activation_ready"),
    ("publish → both reviews ready", "payment_published", "reviews_ready"),
    ("approve → broadcast", "reviews_ready", "broadcast"),
    ("mined → all 3 members confirmed", "mined", "confirmed_all"),
    ("payment total (draft → all confirmed)", "payment_drafted", "confirmed_all"),
    ("whole journey (excluding funding)", None, None),
)


def poc_binary(profile, name):
    target = Path(os.environ.get("CARGO_TARGET_DIR", REPO / "poc" / "target"))
    return target / profile / name


def communication_binary(profile, name):
    # LOKI_HOSTED_FLOW_COMM_BIN points at a directory of saved operator binaries (for
    # comparing runs against another build); otherwise the communication workspace target.
    saved = os.environ.get("LOKI_HOSTED_FLOW_COMM_BIN")
    if saved:
        return Path(saved) / name
    return REPO / "communication" / "target" / profile / name


class Refused(Exception):
    pass


class Flow:
    def __init__(self, args):
        self.args = args
        self.root = Path(args.root).resolve()
        self.root.mkdir(parents=True)
        os.chmod(self.root, 0o700)
        self.procs = []
        self.marks = []
        self.started = time.time()
        self.ports = [args.base + i for i in (1, 2, 3, 4)]

    def mark(self, name, **extra):
        self.marks.append({"step": name, "t": round(time.time() - self.started, 3), **extra})
        print(f"[{time.time() - self.started:8.1f}s] {name} {extra if extra else ''}", flush=True)

    def start(self, argv, log, env=None, **kwargs):
        process = subprocess.Popen(argv, stdout=open(log, "w"), stderr=subprocess.STDOUT,
                                   env={**os.environ, **(env or {})}, **kwargs)
        self.procs.append(process)
        return process

    def wait_port(self, port, limit=30):
        end = time.time() + limit
        while time.time() < end:
            try:
                socket.create_connection(("127.0.0.1", port), 0.2).close()
                return
            except OSError:
                time.sleep(0.05)
        raise SystemExit(f"port {port} never opened")

    def operators(self):
        profile = self.args.operator_profile
        ops = self.root / "ops"
        tool = poc_binary(profile, "examples/hosted_ops")
        relay = communication_binary(profile, "loki-relay-server")
        admission = communication_binary(profile, "loki-setup-admission")
        for path in (tool, relay, admission):
            if not path.is_file():
                raise SystemExit(f"missing {path}; see this module's docstring for the build commands")
        self.key = subprocess.check_output([str(tool), "init", str(ops), str(relay), *map(str, self.ports)],
                                           text=True).strip()
        order = (ops / "provision-order").read_text().split()
        (ops / "admission").mkdir(mode=0o700)
        argv = [str(admission), "serve", "--root", str(ops / "admission"), "--listen",
                f"127.0.0.1:{self.ports[3]}", "--development"]
        for flag, name in (("--bundle-file", "operator.cbor"), ("--config-key-file", "config.key"),
                           ("--issuer-key-file", "issuer.key"), ("--signing-key-file", "signing.seed")):
            argv += [flag, str(ops / name)]
        for index, slot in enumerate(order):
            argv += [f"--relay-{index + 1}-provision-file", str(ops / f"relay-{slot}.secret")]
        plan = {"relays": [[str(relay), "serve", "--root", str(ops / f"relay-{i + 1}"),
                            "--listen", f"127.0.0.1:{self.ports[i]}"] for i in range(3)],
                "admission": argv, "ports": self.ports, "isolation": self.args.isolation,
                "sockets": [str(self.root / f"{name}.sock") for name in SERVICES], "logs": str(self.root)}
        (self.root / "operators.json").write_text(json.dumps(plan))
        if self.args.isolation == "unshare":
            namespace = self.start(["unshare", "-rn", sys.executable, str(Path(__file__).resolve()),
                                    "operators", str(self.root / "operators.json")],
                                   self.root / "operators.log")
            targets = [f"unix:{path}" for path in plan["sockets"]]
            deadline = time.time() + 30
            while not all(Path(path).exists() for path in plan["sockets"]):
                if namespace.poll() is not None or time.time() > deadline:
                    raise SystemExit("operators did not start; see operators.log")
                time.sleep(0.1)
        else:
            user = os.environ.get("USER", "user")
            prefix = ["sudo", "ip", "netns", "exec", self.args.isolation_name, "sudo", "-u", user]
            self.start(prefix + [sys.executable, str(Path(__file__).resolve()), "operators",
                                 str(self.root / "operators.json")], self.root / "operators.log")
            targets = [f"tcp:10.200.0.2:{port}" for port in self.ports]
            time.sleep(3)
        for index, name in enumerate(SERVICES):
            self.start([sys.executable, str(PROXY), f"tcp:127.0.0.1:{self.ports[index]}", targets[index],
                        name, str(self.args.rtt), str(self.root / "http.jsonl")], self.root / f"proxy-{name}.log")
            self.wait_port(self.ports[index])
        issuer = self.root / "issuer.sh"
        issuer.write_text(f"#!/bin/sh\nexec {tool} grant \"$@\"\n")
        issuer.chmod(0o700)
        self.issuer = issuer
        self.bundle = ops / "operator.cbor"

    def apps(self, rpc):
        apps = []
        for index, name in enumerate(("alice", "bob", "carol")):
            apps.append(App(self, name, self.args.base + 20 + index, rpc))
        return apps

    def stop(self):
        (self.root / "marks.json").write_text(json.dumps(self.marks, indent=1))
        for process in reversed(self.procs):
            if process.poll() is None:
                process.terminate()
        for process in self.procs:
            try:
                process.wait(10)
            except subprocess.TimeoutExpired:
                process.kill()


class App:
    def __init__(self, flow, name, port, rpc):
        self.flow, self.name, self.port = flow, name, port
        root = flow.root / name
        app = str(Path(flow.args.app).resolve())
        argv = [sys.executable, app]
        env = {"LOKI_TIMING_LOG": str(flow.root / f"{name}.timing.jsonl")}
        if flow.args.legacy_app:
            # Unmodified older apps hard-code target/debug; time them through a shim.
            argv = [sys.executable, str(Path(__file__).resolve()), "legacy-app", flow.args.profile, app]
        else:
            argv += ["--bin-profile", flow.args.profile]
        argv += ["--data", str(root / "data"), "--port", str(port), "--transport", "hosted",
                 "--operator-bundle", str(flow.bundle), "--operator-key", flow.key,
                 "--enrollment-issuer", str(flow.issuer), "--development-http"]
        if not flow.args.no_exchange:
            argv += ["--exchange", str(root / "exchange")]
        if rpc:
            env["LOKI_RPC"] = rpc
        self.process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=open(flow.root / f"{name}.stderr", "w"),
                                        text=True, env={**os.environ, **env})
        flow.procs.append(self.process)
        while True:
            line = self.process.stdout.readline()
            if not line:
                raise SystemExit(f"{name} exited; see {name}.stderr")
            if line.startswith("Signer:"):
                self.token = line.strip().split("#", 1)[1]
                break

    def api(self, path, body=None, timeout=900):
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/api/{path}",
            data=None if body is None else json.dumps(body).encode(),
            headers={"X-Loki-Token": self.token, "Content-Type": "application/json"},
            method="GET" if body is None else "POST")
        started = time.time()
        failed = False
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as error:
            failed = True
            raise Refused(json.loads(error.read())["error"]) from None
        finally:
            with open(self.flow.root / "api.jsonl", "a") as output:
                output.write(json.dumps({"app": self.name, "path": path.split("?")[0],
                                         "t": started, "dur": time.time() - started, "err": failed}) + "\n")

    def status(self, vault):
        return self.api(f"status?vault={vault}")


def until(read, check, what, limit=900, every=0.1):
    end = time.time() + limit
    last = None
    while time.time() < end:
        try:
            last = read()
            if check(last):
                return last
        except Refused as error:
            last = str(error)
        time.sleep(every)
    raise SystemExit(f"timeout waiting for {what}: {last}")


def journey(flow):
    args = flow.args
    chain = None
    rpc = None
    if not args.skip_payment:
        sys.path.insert(0, str(REPO / "poc"))
        from ths import THS
        chain = THS(args.ths)
        chain.check()
        rpc = chain.rpc_address
    flow.operators()
    flow.mark("operators_ready")
    apps = flow.apps(rpc)
    flow.mark("apps_started")
    for app in apps:
        app.api("profile-create", {"name": app.name, "passphrase": f"pass for {app.name} only"})
    flow.mark("profiles_created")
    vault = apps[0].api("create", {"name": "Hosted flow", "members": 3})["vault"]
    flow.mark("vault_created")
    state = until(lambda: apps[0].status(vault), lambda s: len(s.get("invites", [])) == 2, "invites")
    flow.mark("invites_ready")
    for app, row in zip(apps[1:], state["invites"]):
        assert app.api("join", {"invite": row["code"]})["vault"] == vault
        flow.mark(f"joined_{app.name}")
    fingerprint = until(lambda: apps[0].status(vault),
                        lambda s: s.get("fingerprint") and s["phase"] == "compare_roster",
                        "creator fingerprint")["fingerprint"]
    flow.mark("creator_fingerprint_shown")
    shown = {}
    end = time.time() + args.joiner_wait
    while time.time() < end and len(shown) < 2:
        for app in apps[1:]:
            if app.name not in shown:
                state = app.status(vault)
                if state.get("fingerprint") and state["phase"] == "compare_roster":
                    shown[app.name] = state["fingerprint"]
        time.sleep(0.1)
    if len(shown) == 2:
        flow.mark("joiner_fingerprints_in_ui")
    else:
        flow.mark("joiner_fingerprint_missing", missing=[a.name for a in apps[1:] if a.name not in shown])
    if any(value != fingerprint for value in shown.values()):
        raise SystemExit(f"fingerprint mismatch: {shown} vs {fingerprint}")
    for app in apps:
        app.api("agree", {"vault": vault, "fingerprint": shown.get(app.name, fingerprint)})
    flow.mark("agreed")
    for app in apps:
        until(lambda app=app: app.status(vault), lambda s: s["phase"] == "back_up", f"dkg {app.name}")
    flow.mark("dkg_done_backup_phase")
    words = {}
    for app in apps:
        words[app.name] = app.api("backup", {"vault": vault})["words"]
        app.api("verify", {"vault": vault, "words": words[app.name]})
    flow.mark("provisional_backups_checked")
    for app in apps:
        until(lambda app=app: app.status(vault), lambda s: s["phase"] == "final_backup", f"certified {app.name}")
    flow.mark("certified_final_backup_phase")
    for app in apps:
        app.api("finalize-backup", {"vault": vault, "words": words[app.name]})
        card = app.api(f"final-card?vault={vault}")["card"]
        app.api("verify-final-backup", {"vault": vault, "words": words[app.name], "card": card})
    flow.mark("final_cards_checked")
    for app in apps:
        until(lambda app=app: app.status(vault), lambda s: s["phase"] == "active", f"activation {app.name}")
    flow.mark("payment_activation_ready")
    addresses = {app.api("address", {"vault": vault})["address"] for app in apps}
    assert len(addresses) == 1, addresses
    flow.mark("address_agreed")
    if args.skip_payment:
        return
    payment(flow, apps, vault, chain, addresses.pop())


def payment(flow, apps, vault, chain, source):
    import ths
    pump = flow.args.pump == "driver"

    def fund():
        # THS address-faucet replies carry `block_hash` once mined.
        return ths.post(chain.app_url + "/api/v1/faucet/address",
                        {"address": source, "amount_zatoshi": 100_000_000,
                         "idempotency_key": "hosted-flow-" + vault[:24]}).get("block_hash")
    until(fund, bool, "faucet", limit=300, every=2)
    flow.mark("funded_on_chain")
    until(lambda: apps[0].api("balance", {"vault": vault}), lambda b: b["balance_zat"] >= 100_000_000,
          "balance", every=0.5)
    flow.mark("balance_visible")
    balances = json.loads(subprocess.check_output(["ths", "--name", chain.name, "wallet", "balances", "--json"], text=True))
    recipient = next(row for row in balances if row["id"] == 2)["unified_address"]
    draft = apps[0].api("payment-draft", {"vault": vault, "recipient": recipient,
                                          "amount_zat": "40000000", "memo": "hosted flow"})
    attempt = draft["attempt"]
    flow.mark("payment_drafted")
    apps[0].api("payment-publish", {"vault": vault, "attempt": attempt})
    flow.mark("payment_published")

    def reviews():
        if pump:
            for app in apps:
                app.api("payment-sync", {"vault": vault})
            for app in apps[:2]:
                app.api("payment-advance", {"vault": vault, "attempt": attempt})
        return [app.api("payment-review", {"vault": vault, "attempt": attempt}) for app in apps[:2]]
    found = until(reviews, lambda r: len(r) == 2, "reviews")
    flow.mark("reviews_ready")
    for app, review in zip(apps[:2], found):
        app.api("payment-approve", {"vault": vault, "attempt": attempt, "review_token": review["review_token"]})
    flow.mark("approved")

    def finish():
        if pump:
            for app in apps:
                app.api("payment-sync", {"vault": vault})
        else:
            # Like the signer page: Send appears once the app reports ready_to_send.
            listed = apps[2].api(f"payments?vault={vault}")["payments"]
            if not any(item["attempt"] == attempt and item["ready_to_send"] for item in listed):
                return {"phase": "waiting"}
        return apps[2].api("payment-finish", {"vault": vault, "attempt": attempt})
    sent = until(finish, lambda r: r["phase"] == "broadcast", "broadcast")
    flow.mark("broadcast")
    chain.mine(1)
    flow.mark("mined")
    until(lambda: apps[2].api("payment-verify", {"vault": vault, "attempt": attempt, "txid": sent["txid"]}),
          lambda r: r["phase"] == "confirmed", "confirm", every=0.2)
    flow.mark("confirmed_finisher")
    for app in apps:
        def listing(app=app):
            if pump:
                app.api("payment-sync", {"vault": vault})
                try:
                    app.api("payment-advance", {"vault": vault, "attempt": attempt})
                except Refused:
                    pass
            return app.api(f"payments?vault={vault}")
        until(listing, lambda r: r["payments"] and r["payments"][0]["phase"] == "confirmed",
              f"confirmed {app.name}", every=0.2)
        flow.mark(f"confirmed_{app.name}")
    flow.mark("confirmed_all")
    for app in apps:
        until(lambda app=app: app.api("balance", {"vault": vault}),
              lambda b: b["balance_zat"] == int(draft["change_zat"]), f"balance {app.name}", every=0.5)
    flow.mark("balances_updated")


def percentile(values, fraction):
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1))))]


def report(root):
    root = Path(root)
    marks = json.loads((root / "marks.json").read_text())
    at = {mark["step"]: mark["t"] for mark in marks}
    segments = {}
    for label, start, end in SEGMENTS:
        if start is None:
            if "confirmed_all" in at:
                funding = at["balance_visible"] - at["address_agreed"]
                segments[label] = round(at["confirmed_all"] - at["profiles_created"] - funding, 1)
            continue
        if start in at and end in at:
            segments[label] = round(at[end] - at[start], 1)
    commands = collections.defaultdict(list)
    failures = collections.Counter()
    kdf = collections.defaultdict(list)
    for path in sorted(root.glob("*.timing.jsonl")):
        for line in path.read_text().splitlines():
            row = json.loads(line)
            commands[row["op"]].append(row["ms"] / 1000)
            failures[row["op"]] += row["rc"] != 0
            if "kdf" in row:
                kdf[row["op"]].append(row["kdf"])
    command_rows = {op: {"n": len(values), "total_s": round(sum(values), 2),
                         "avg_s": round(statistics.mean(values), 3), "p95_s": round(percentile(values, 0.95), 3),
                         "max_s": round(max(values), 3), "failed": failures[op]}
                    for op, values in sorted(commands.items(), key=lambda item: -sum(item[1]))}
    http = collections.Counter()
    connections = collections.Counter()
    state_polls = 0
    log = root / "http.jsonl"
    for line in (log.read_text().splitlines() if log.is_file() else []):
        row = json.loads(line)
        if row["m"] == "CONNECT":
            connections[row["svc"]] += 1
        else:
            http[row["svc"]] += 1
            state_polls += row["svc"] == "admission" and row["m"] == "GET" and row["p"].startswith("/v1/setup/")
    result = {"marks": marks, "segments_s": segments, "commands": command_rows,
              "kdf_derivations": {op: {"n": len(v), "avg": round(statistics.mean(v), 1), "max": max(v)}
                                  for op, v in kdf.items()},
              "http": {"requests": sum(http.values()), "connections": sum(connections.values()),
                       "admission_state_polls": state_polls, "requests_by_service": dict(http),
                       "connections_by_service": dict(connections)}}
    settings = root / "settings.json"
    if settings.is_file():
        result["settings"] = json.loads(settings.read_text())
    (root / "hosted-flow-report.json").write_text(json.dumps(result, indent=1))
    return result


def print_report(result):
    print("== segments (s)")
    for label, value in result["segments_s"].items():
        print(f"  {label:45} {value:8.1f}")
    print("== native commands (sum over apps)")
    for op, row in list(result["commands"].items())[:16]:
        print(f"  {op:40} n={row['n']:4} total={row['total_s']:8.1f}s avg={row['avg_s']:6.3f}s "
              f"p95={row['p95_s']:6.3f}s max={row['max_s']:6.2f}s failed={row['failed']}")
    http = result["http"]
    print(f"== HTTP: {http['requests']} requests over {http['connections']} connections; "
          f"{http['admission_state_polls']} admission state polls")


def operators_main(plan_path):
    """Inside the operator namespace: relays, admission and Unix-socket forwarders."""
    plan = json.loads(Path(plan_path).read_text())
    logs = Path(plan["logs"])
    if plan["isolation"] == "unshare":
        subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    children = []

    def spawn(argv, name):
        children.append(subprocess.Popen(argv, stdout=open(logs / f"{name}.log", "w"), stderr=subprocess.STDOUT))
    for index, argv in enumerate(plan["relays"]):
        spawn(argv, f"relay-{index + 1}")
    time.sleep(1)
    spawn(plan["admission"], "admission")
    for index, name in enumerate(SERVICES):
        port = plan["ports"][index]
        listen = f"unix:{plan['sockets'][index]}" if plan["isolation"] == "unshare" else f"tcp:10.200.0.2:{port}"
        spawn([sys.executable, str(PROXY), listen, f"tcp:127.0.0.1:{port}", name, "0", "-"], f"forward-{name}")
    stop = []
    signal.signal(signal.SIGTERM, lambda *_: stop.append(1))
    while not stop and all(child.poll() is None for child in children):
        time.sleep(0.2)
    for child in children:
        child.terminate()
    for child in children:
        try:
            child.wait(10)
        except subprocess.TimeoutExpired:
            child.kill()


def legacy_app_main(profile, app, args):
    """Run an unmodified older member_app.py against `profile` binaries, timing each call."""
    sys.path.insert(0, str(HERE))
    import timing
    base = subprocess.Popen

    class Timed(base):
        def __init__(self, argv, *rest, **kwargs):
            self._started = time.monotonic()
            self._argv = [str(part) for part in (argv if isinstance(argv, (list, tuple)) else [argv])]
            self._logged = False
            super().__init__(argv, *rest, **kwargs)

        def wait(self, timeout=None):
            code = super().wait(timeout)
            if not self._logged and len(self._argv) > 1:
                self._logged = True
                timing.record(f"{Path(self._argv[0]).name} {self._argv[1]}", self._started, code, *self._argv[2:])
            return code
    subprocess.Popen = Timed
    sys.argv = [app, *args]
    source = Path(app).read_text().replace('"target" / "debug"', f'"target" / "{profile}"')
    sys.path.insert(0, str(Path(app).parent))
    exec(compile(source, app, "exec"), {"__name__": "__main__", "__file__": app})


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "operators":
        return operators_main(sys.argv[2])
    if len(sys.argv) > 1 and sys.argv[1] == "legacy-app":
        return legacy_app_main(sys.argv[2], sys.argv[3], sys.argv[4:])
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run")
    run.add_argument("--root", required=True)
    run.add_argument("--profile", choices=("release", "debug"), default="release")
    run.add_argument("--operator-profile", choices=("release", "debug"), default="release")
    run.add_argument("--rtt", type=float, default=0, help="added round-trip time to every operator, in ms")
    run.add_argument("--ths", default=os.environ.get("LOKI_THS_INSTANCE", "loki-hosted"))
    run.add_argument("--base", type=int, default=39100)
    run.add_argument("--skip-payment", action="store_true")
    run.add_argument("--isolation", choices=("unshare", "netns"), default="unshare")
    run.add_argument("--isolation-name", default="lokins")
    run.add_argument("--joiner-wait", type=float, default=60,
                     help="seconds to wait for joiners' own fingerprint before using the creator's")
    run.add_argument("--pump", choices=("driver", "none"), default="driver",
                     help="driver: call payment-sync/advance like the open signer page")
    run.add_argument("--no-exchange", action="store_true", help="start hosted apps without --exchange")
    run.add_argument("--legacy-app", action="store_true", help="time an unmodified older member_app.py")
    run.add_argument("--app", default=str(HERE / "member_app.py"), help="member_app.py to run")
    show = commands.add_parser("report")
    show.add_argument("root")
    args = parser.parse_args()
    if args.command == "report":
        print_report(report(args.root))
        return
    flow = Flow(args)
    (flow.root / "settings.json").write_text(json.dumps({key: getattr(args, key) for key in
        ("profile", "operator_profile", "rtt", "isolation", "pump", "skip_payment", "legacy_app")}))
    try:
        journey(flow)
    finally:
        flow.stop()
    result = report(flow.root)
    print_report(result)
    return result


if __name__ == "__main__":
    main()
