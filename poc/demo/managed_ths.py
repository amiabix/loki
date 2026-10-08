"""The browser demo's owned, disposable THS environment."""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import socket
import subprocess
import threading
import time
import urllib.parse
import urllib.request
import uuid
from pathlib import Path

from ths import THS, loopback_url, post


LABEL = "com.zakura.ths.instance"
BASE_PORTS = (32805, 18232, 18233, 9067)


def command(argv, cancel=None, timeout=30, cwd=None, env=None):
    """Capture a fixed command and stop its child when the operation is cancelled."""
    if cancel and cancel.is_set():
        raise RuntimeError("operation cancelled")
    child = subprocess.Popen(argv, cwd=cwd, env=env, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True)
    deadline = time.monotonic() + timeout
    try:
        while True:
            if cancel and cancel.is_set():
                raise RuntimeError("operation cancelled")
            if time.monotonic() >= deadline:
                raise RuntimeError(f"{Path(argv[0]).name} timed out after {timeout}s")
            try:
                out, err = child.communicate(timeout=0.25)
                return subprocess.CompletedProcess(argv, child.returncode, out, err)
            except subprocess.TimeoutExpired:
                continue
    finally:
        if child.poll() is None:
            child.terminate()
            try:
                child.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate(timeout=5)


class ManagedTHS:
    def __init__(self, sandbox, emit, cancel):
        self.sandbox = sandbox
        self.manifest = sandbox / "ths-instance.json"
        self.emit = emit
        self.cancel = cancel
        self.child = None
        self.client = None
        self.log_offset = 0
        self.phase = "stopped"
        self.error = None
        self.tip = None
        self.wallet_ready = False
        self.probe_lock = threading.Lock()
        self.probed_at = 0
        self.data = {}
        if self.manifest.exists():
            self.data = json.loads(self.manifest.read_text())
            if (self.data.get("version") != 1 or not re.fullmatch(
                    r"loki-demo-[0-9a-f]{24}", self.data.get("name", ""))):
                raise RuntimeError("invalid managed THS ownership manifest; refusing cleanup")
            self.phase = "stopped" if self.data.get("deleted") else "failed"
            self.error = self.data.get("error")

    @property
    def name(self):
        return self.data.get("name")

    @property
    def ended(self):
        return bool(self.data.get("ended"))

    @property
    def funding_state(self):
        return self.data.get("funding_state", "not_started")

    def save(self):
        self.sandbox.mkdir(parents=True, exist_ok=True)
        temporary = self.manifest.with_suffix(".tmp")
        temporary.write_text(json.dumps(self.data, indent=2) + "\n")
        temporary.replace(self.manifest)

    def checked(self, argv, timeout=30, cancellable=True):
        result = command(argv, self.cancel if cancellable else None, timeout)
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or result.stdout.strip()
                               or f"{Path(argv[0]).name} exited {result.returncode}")
        return result.stdout

    def resources(self):
        """Inspect only the selected instance's exact container, volume and network names."""
        prefix = f"ths-{self.name}"
        expected = {
            "container": [f"{prefix}-{s}" for s in ("app", "lightwalletd", "zakura", "init")],
            "volume": [f"{prefix}-{s}" for s in ("chain", "wallet", "lightwalletd", "config")],
            "network": [prefix],
        }
        found = {}
        for kind, names in expected.items():
            field = "Names" if kind == "container" else "Name"
            args = ["docker", kind, "ls"]
            if kind == "container":
                args.append("-a")
            listed = self.checked(args + ["--format", "{{." + field + "}}"],
                                  cancellable=False).splitlines()
            for name in names:
                if listed.count(name) > 1:
                    raise RuntimeError(f"ambiguous Docker resource {name}")
                if name not in listed:
                    continue
                item = json.loads(self.checked(["docker", kind, "inspect", name],
                                               cancellable=False))[0]
                labels = item.get("Config", {}).get("Labels") if kind == "container" else item.get("Labels")
                found[name] = {
                    "kind": kind, "id": item.get("Id", item.get("Name")),
                    "created": item.get("Created", item.get("CreatedAt")),
                    "label": (labels or {}).get(LABEL),
                    "image": item.get("Image") if kind == "container" else None,
                }
        return found

    def capture_resources(self, starting=False):
        current = self.resources()
        recorded = self.data.get("resources", {})
        for name, resource in current.items():
            old = recorded.get(name)
            if old and (resource["id"], resource["created"]) != (old["id"], old["created"]):
                raise RuntimeError(f"resource identity changed: {name}; refusing cleanup")
            if resource["label"] != self.name:
                # Older launchers leave their network unlabeled. Only a network observed
                # after our empty-name preflight, or its recorded identity, is accepted.
                legacy_network = (resource["kind"] == "network" and resource["label"] is None
                                  and (old is not None or starting))
                if not legacy_network:
                    raise RuntimeError(f"{name} is not owned by this Loki run; refusing cleanup")
            recorded[name] = resource
        self.data["resources"] = recorded
        self.save()
        return current

    def drain_log(self):
        logfile = self.sandbox / "ths.log"
        if not logfile.exists():
            return
        with logfile.open() as log:
            log.seek(self.log_offset)
            for line in log:
                if line.strip():
                    self.emit("info", "THS: " + line.rstrip())
            self.log_offset = log.tell()

    def probe(self, timeout=1):
        if not self.client or not self.child or self.child.poll() is not None or self.ended:
            self.tip = None
            self.wallet_ready = False
            if self.client and not self.ended:
                self.phase = "failed"
                self.error = "THS launcher exited; stop the network and reset this run"
            return False
        try:
            info = self.client.rpc("getblockchaininfo", timeout=timeout)
            if (info.get("chain") != "test"
                    or info.get("upgrades", {}).get("37a5165b", {}).get("status") != "active"
                    or info.get("consensus", {}).get("nextblock") != "37a5165b"):
                raise RuntimeError("expected regtest with the pinned NU6.3 branch active")
            with urllib.request.urlopen(self.client.app_url + "/api/v1/status", timeout=timeout) as response:
                status = json.load(response)
            if status.get("instance") != self.name or status.get("network", "").lower() != "regtest":
                raise RuntimeError("THS app identity or network differs from this run")
            sync = status.get("wallet_sync", {})
            self.wallet_ready = (sync.get("state") == "ready"
                                 and sync.get("fully_scanned_height") is not None
                                 and sync.get("fully_scanned_height") == sync.get("observed_height")
                                 and bool(sync.get("fully_scanned_hash"))
                                 and sync.get("fully_scanned_hash") == sync.get("observed_hash"))
            self.tip = info["blocks"]
            self.error = None
            return True
        except (OSError, ValueError, RuntimeError, KeyError) as error:
            self.tip = None
            self.wallet_ready = False
            self.error = str(error)
            return False

    def snapshot(self):
        if self.phase in ("running", "failed") and not self.ended and self.client:
            if time.monotonic() - self.probed_at >= 2 and self.probe_lock.acquire(False):
                try:
                    self.phase = "running" if self.probe() else "failed"
                    self.probed_at = time.monotonic()
                finally:
                    self.probe_lock.release()
        endpoints = self.data.get("endpoints", {})
        return {
            "network_state": self.phase, "network_error": self.error,
            "chain_running": self.phase == "running" and self.tip is not None,
            "chain_pid": self.child.pid if self.child and self.child.poll() is None else None,
            "ths_instance": self.name, "endpoints": endpoints,
            "rpc_port": urllib.parse.urlparse(endpoints["rpc"]).port if endpoints.get("rpc") else None,
            "tip": self.tip, "wallet_ready": self.wallet_ready, "run_ended": self.ended,
            "can_stop": bool(self.name and not self.data.get("deleted")),
            "funding_state": self.funding_state, "funding_error": self.data.get("funding_error"),
            "funding": self.data.get("funding", []),
        }

    def start(self):
        if self.ended:
            raise RuntimeError("this network has ended; reset the demo before starting a fresh run")
        if self.name:
            if self.probe():
                self.phase = "running"
                return
            raise RuntimeError("this THS instance is unavailable; stop it and reset the demo")
        for exe in ("ths", "docker"):
            if not shutil.which(exe):
                raise RuntimeError(f"{exe} is not installed or is not on PATH")
        self.checked(["docker", "info", "--format", "{{.ServerVersion}}"])
        offset = self.available_offset()
        self.data = {"version": 1, "name": "loki-demo-" + uuid.uuid4().hex[:24],
                     "offset": offset, "resources": {}, "ended": False,
                     "deleted": False, "funding": [], "funding_state": "not_started"}
        if self.resources():
            self.data = {}
            raise RuntimeError("generated THS name is already occupied; start again")
        self.data["launcher_version"] = self.checked(["ths", "--version"]).strip()
        self.save()
        self.phase = "starting"
        self.error = None
        self.emit("info", f"starting dedicated THS {self.name}; preparing services and runtime images")
        self.emit("cmd", f"ths --name {self.name} start --no-open --port-offset {offset}")
        try:
            with (self.sandbox / "ths.log").open("w") as log:
                self.child = subprocess.Popen(
                    ["ths", "--name", self.name, "start", "--no-open", "--port-offset", str(offset)],
                    stdout=log, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                )
            self.data["launcher_pid"] = self.child.pid
            self.data["launcher_identity"] = self.process_identity(self.child.pid)
            self.save()
            deadline = time.monotonic() + 300
            last_error = "services have not published endpoints yet"
            while time.monotonic() < deadline:
                if self.cancel.is_set():
                    raise RuntimeError("THS startup cancelled")
                self.drain_log()
                self.capture_resources(starting=True)
                if self.child.poll() is not None:
                    raise RuntimeError(f"THS exited during startup ({self.child.returncode}); see Console")
                try:
                    self.client = THS(self.name)
                    for key in ("dashboard", "rpc", "lightwalletd"):
                        loopback_url(self.client.endpoints[key])
                    p2p = urllib.parse.urlparse("http://" + self.client.endpoints["p2p"])
                    if p2p.hostname != "127.0.0.1" or not p2p.port or p2p.username:
                        raise RuntimeError("THS P2P endpoint is not loopback")
                    self.data["endpoints"] = self.client.endpoints
                    self.save()
                    if self.probe(timeout=3) and self.wallet_ready:
                        self.capture_resources(starting=True)
                        self.phase = "running"
                        self.emit("ok", f"THS {self.name} ready at block {self.tip}")
                        return
                    last_error = self.error or "waiting for the THS wallet to finish scanning"
                except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
                    last_error = str(error)
                self.cancel.wait(1)
            raise RuntimeError(f"THS did not become ready within 300s: {last_error}")
        except Exception as error:
            self.error = str(error)
            self.emit("fail", self.error)
            try:
                self.stop()
            except Exception as cleanup_error:
                self.emit("fail", f"THS cleanup failed: {cleanup_error}; retry Stop network")
            self.phase = "failed"
            self.error = str(error)
            raise

    @staticmethod
    def available_offset():
        for offset in range(20, 10000, 10):
            sockets = []
            try:
                for base in BASE_PORTS:
                    listener = socket.socket()
                    sockets.append(listener)
                    listener.bind(("127.0.0.1", base + offset))
                return offset
            except OSError:
                continue
            finally:
                for listener in sockets:
                    listener.close()
        raise RuntimeError("no free loopback ports are available for THS")

    def fund(self, address):
        if self.funding_state == "confirmed":
            self.emit("info", "vault funding is already confirmed for this run")
            return
        if self.funding_state in ("funding", "uncertain"):
            raise RuntimeError("funding outcome is uncertain; reset this disposable run rather than requesting funds twice")
        if not self.probe(timeout=3) or not self.wallet_ready:
            raise RuntimeError(self.error or "THS wallet is not ready for faucet funding; try Start again")
        for index in range(len(self.data["funding"]), 2):
            if self.cancel.is_set():
                raise RuntimeError("funding cancelled")
            self.data.update(funding_state="funding", funding_error=None,
                             funding_key=f"{self.name}-fund-{index}")
            self.save()
            self.emit("info", f"funding the vault through THS ({index + 1}/2, 1 ZEC each)")
            try:
                result = post(self.client.app_url + "/api/v1/faucet/address", {
                    "address": address, "amount_zatoshi": 100_000_000,
                    "idempotency_key": self.data["funding_key"],
                }, timeout=45)
                if (result.get("status") != "confirmed" or not result.get("block_hash")
                        or not re.fullmatch(r"[0-9a-f]{64}", result.get("txid", ""))):
                    raise RuntimeError("faucet did not establish confirmed funding")
                self.data["funding"].append(result)
                self.save()
                self.emit("ok", f"THS faucet confirmed {result['txid']}")
            except Exception as error:
                self.data.update(funding_state="uncertain", funding_error=str(error))
                self.save()
                raise RuntimeError(f"funding outcome is uncertain: {error}; reset before another funding request") from error
        self.data.update(funding_state="confirmed", funding_error=None)
        self.save()

    def mine(self, blocks=3):
        self.emit("cmd", f"ths --name {self.name} mine {blocks} --json")
        output = self.checked(["ths", "--name", self.name, "mine", str(blocks), "--json"], timeout=600)
        for line in output.splitlines():
            self.emit("out", line)

    def reap(self):
        if self.child and self.child.poll() is None:
            self.child.terminate()
            try:
                self.child.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.child.kill()
                self.child.wait(timeout=5)

    def stop(self):
        if not self.name or self.data.get("deleted"):
            return
        starting = self.phase == "starting"
        self.phase = "stopping"
        self.data["ended"] = True
        self.save()
        try:
            self.capture_resources(starting=starting)
            # During allocation, settle the launcher first so it cannot create resources
            # after `ths stop` has removed them. Ready launchers are reaped afterward.
            if starting:
                self.reap()
            self.capture_resources()
            self.emit("cmd", f"ths --name {self.name} stop")
            output = self.checked(["ths", "--name", self.name, "stop"], timeout=60, cancellable=False)
            for line in output.splitlines():
                self.emit("info", line)
            self.reap()
            self.drain_log()
            if self.resources():
                raise RuntimeError("THS resources remain after stop; retry cleanup")
            self.data.update(deleted=True, error=None)
            self.save()
            self.phase = "stopped"
            self.error = None
            self.tip = None
            self.client = None
            self.emit("ok", "owned THS instance deleted; reset the demo to begin a fresh run")
        except Exception as error:
            self.phase = "failed"
            self.error = f"cleanup failed: {error}"
            self.data["error"] = self.error
            self.save()
            raise

    def recover(self):
        if self.name and not self.data.get("deleted"):
            self.emit("info", f"recovering cleanup of the previous Loki run, {self.name}")
            self.capture_resources()
            pid = self.data.get("launcher_pid")
            identity = self.data.get("launcher_identity")
            if pid and identity and self.process_identity(pid) == identity:
                if f"--name {self.name} start" not in identity:
                    raise RuntimeError("saved launcher identity does not match this instance")
                os.kill(pid, signal.SIGTERM)
                deadline = time.monotonic() + 20
                while self.process_identity(pid) == identity and time.monotonic() < deadline:
                    time.sleep(0.25)
                if self.process_identity(pid) == identity:
                    os.kill(pid, signal.SIGKILL)
            self.stop()

    def process_identity(self, pid):
        result = command(["ps", "-p", str(pid), "-o", "lstart=,args="], timeout=5)
        if result.returncode == 1 and not result.stdout:
            return None
        if result.returncode:
            raise RuntimeError(result.stderr.strip() or "could not inspect the managed launcher")
        return result.stdout.strip()
