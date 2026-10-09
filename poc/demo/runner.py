#!/usr/bin/env python3
"""Sandboxed Loki stages with a dedicated, demo-owned THS regtest instance.

Requests select fixed stages and tamper cases. Loki state lives only under
`demo/.sandbox`. THS manages its Docker data and launcher metadata separately.
Explicit stop, reset, and graceful server shutdown delete only this run's instance.
"""

from __future__ import annotations

import atexit
import os
import re
import shutil
import signal
import sys
import threading
import time
import urllib.error
from pathlib import Path

DEMO = Path(__file__).resolve().parent
POC = DEMO.parent

# The one writable path. A constant, never derived from a request.
SANDBOX = DEMO / ".sandbox"
STATE = SANDBOX / "state"
SNAP = SANDBOX / "snapshot"

sys.path.insert(0, str(POC))
from managed_ths import ManagedTHS, command


def loki_bin() -> Path | None:
    """The built CLI. Not rebuilt here: a web request should not trigger a compile."""
    target = Path(os.environ["CARGO_TARGET_DIR"]) if "CARGO_TARGET_DIR" in os.environ else POC / "target"
    if not target.is_absolute():
        target = POC / target
    for p in (target / "debug" / "loki", target / "release" / "loki"):
        if p.exists() and os.access(p, os.X_OK):
            return p
    return None


# ── step definitions ────────────────────────────────────────────────────────
#
# The browser sends a key from this table and nothing else. Each value is a list of
# argv lists, already fully formed. There is no interpolation from request data.

MEMBERS = ("alice", "bob", "carol")

TAMPER_CASES = (
    "memo", "recipient", "amount", "change-amount", "change-address",
    "input", "expiry", "transparent", "sapling",
)


class Runner:
    def __init__(self):
        self.lock = threading.Lock()
        self.cancel = threading.Event()
        self.closing = False
        self.active = False
        self.worker = None
        self.events: list[dict] = []
        self.seq = 0
        self.busy: str | None = None
        self.done: set[str] = set()
        self.network = ManagedTHS(SANDBOX, self.emit, self.cancel)
        atexit.register(self.shutdown)
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, self._on_signal)
            except (ValueError, OSError):
                pass            # not on the main thread; atexit still covers teardown

    def _on_signal(self, signum, _frame):
        """Cancel the active stage, delete our THS instance, then exit."""
        self.shutdown()
        signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)

    # ── events ──────────────────────────────────────────────────────────────

    def emit(self, kind: str, text: str):
        self.seq += 1
        self.events.append({"seq": self.seq, "t": time.time(), "kind": kind, "text": text})
        del self.events[:-600]

    def completed_on_disk(self) -> set[str]:
        """Which steps the sandbox already shows evidence of.

        `done` is in-memory, so without this a server restart would grey out the tamper
        UI even though the candidates are sitting right there. Each entry is keyed on an
        artifact that only that step produces. `start-chain` is absent on purpose: a
        running process is not something a file can vouch for.
        """
        pub = STATE / "public"
        marks = {
            "setup": STATE / "public" / "vault_address.txt",
            "scan": pub / "funded_note.txt",
            "commit": pub / "commitment_AC_alice.hex",
            "propose": SNAP / "candidate_AC.pczt.hex",
            "sign-alice": pub / "share_AC_alice.hex",
            "sign-carol": pub / "share_AC_carol.hex",
            "finish": pub / "verified.txt",
        }
        return {k for k, f in marks.items() if f.exists()}

    def snapshot(self) -> dict:
        network = self.network.snapshot()
        done = self.done | self.completed_on_disk()
        if network["run_ended"]:
            done = done & {"setup"}
        if not network["chain_running"] or network["funding_state"] != "confirmed":
            done.discard("start-chain")
        return {
            **network,
            "busy": self.busy,
            "done": sorted(done),
            "done_this_session": sorted(self.done),
            "events": self.events[-400:],
            "seq": self.seq,
            "sandbox": str(SANDBOX.relative_to(POC.parent)),
        }

    @property
    def ths(self):
        return self.network.client

    def recover(self):
        """Finish cleanup of a run whose server could not execute its shutdown hooks."""
        try:
            self.network.recover()
        except Exception as error:
            self.emit("fail", f"previous THS cleanup failed: {error}; retry Stop network")

    def shutdown(self):
        if not self.active:
            return
        self.closing = True
        self.cancel.set()
        if self.worker and self.worker is not threading.current_thread():
            self.worker.join(timeout=60)
            if self.worker.is_alive():
                self.emit("fail", "active stage did not settle before shutdown; ownership record retained")
                return
        try:
            self.stop_chain()
        except Exception as error:
            self.emit("fail", f"THS shutdown cleanup failed: {error}; ownership record retained")
            print(f"THS cleanup failed: {error}", file=sys.stderr)

    def wallet(self) -> dict:
        """The account, in multisig terms.

        Reads only the sandbox, and only named fields. `funded_note.txt` holds `rho` and
        `rseed`, which are note secrets: they are never read here. Nothing in this method
        returns a key package, a nonce, or a note secret, and it cannot be pointed at any
        directory other than the sandbox.
        """
        pub = STATE / "public"

        def kv(name: str, keep: tuple[str, ...]) -> dict:
            f = pub / name
            if not f.exists():
                return {}
            out = {}
            for line in f.read_text().splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    if k.strip() in keep:
                        out[k.strip()] = v.strip()
            return out

        addr = (pub / "vault_address.txt").read_text().strip() if (pub / "vault_address.txt").exists() else None
        bal = kv("balance.txt", ("total_zat",)).get("total_zat")
        note = kv("funded_note.txt", ("value_zat", "position", "height"))
        intent = kv("intent.txt", (
            "proposal_id", "recipient", "amount_zat", "memo", "fee_zat",
            "change_zat", "expiry_height", "created_height", "input_nullifier",
        ))
        mined = kv("mined.txt", ("txid", "broadcast_at_height", "anchor"))

        # Who has confirmed, read from which share files exist. AC is the pair the
        # finisher uses, so that is the one the queue tracks.
        owners = []
        for name in MEMBERS:
            pairs = [p for p in ("AB", "AC", "BC") if name[0].upper() in p]
            owners.append({
                "name": name,
                "confirmed_ac": (pub / f"share_AC_{name}.hex").exists(),
                "in_ac": "AC" in pairs,
                "committed": any((pub / f"commitment_{p}_{name}.hex").exists() for p in pairs),
            })

        confirmations = sum(1 for o in owners if o["confirmed_ac"])
        candidates = [p for p in ("AB", "AC", "BC") if (pub / f"candidate_{p}.pczt.hex").exists()]

        # `no_funds` is a distinct state from `no_transaction`: an account can exist
        # without having been scanned, and saying "funded" then would be a plain lie.
        verified = (pub / "verified.txt").exists()
        if mined.get("txid") and verified:
            status = "executed"
        elif mined.get("txid"):
            status = "submitted"
        elif confirmations >= 2:
            status = "ready"
        elif intent:
            status = "awaiting_confirmations"
        elif addr and bal:
            status = "no_transaction"
        elif addr:
            status = "no_funds"
        else:
            status = "no_account"

        return {
            "address": addr,
            "threshold": 2,
            "owner_count": 3,
            "balance_zat": int(bal) if bal else None,
            "note": {k: int(v) for k, v in note.items()} if note else {},
            "owners": owners,
            "candidates": candidates,
            "transaction": intent or None,
            "confirmations": confirmations,
            "status": status,
            "executed": mined if verified else None,
            "broadcast": mined or None,
            "run_ended": self.network.ended,
        }

    # ── process plumbing ────────────────────────────────────────────────────

    def run_cli(self, args: list[str], label: str, timeout: int = 600) -> bool:
        """Run the loki CLI. Never a shell, never a caller-supplied path."""
        exe = loki_bin()
        if exe is None:
            self.emit("fail", "the loki binary is not built. Run: cd poc && cargo build")
            return False
        self.emit("cmd", f"loki {' '.join(args)}")
        env = self.ths.env() if self.ths else dict(os.environ)
        env.pop("LOKI_ROUND", None)
        if label not in ("setup",) and args[0] in ("scan", "propose", "finish", "verify-effects") and not self.ths:
            self.emit("fail", "start the test network first")
            return False
        p = self.cli_command(exe, args, env, timeout)
        for line in (p.stdout or "").splitlines():
            if line.strip():
                self.emit("out", line.rstrip())
        for line in (p.stderr or "").splitlines():
            if line.strip():
                self.emit("err", line.rstrip())
        if p.returncode != 0:
            self.emit("fail", f"{label}: exit {p.returncode}")
            return False
        return True

    def cli_command(self, exe, args, env, timeout):
        return command([str(exe), *args], self.cancel, timeout, cwd=str(POC), env=env)

    # ── steps ───────────────────────────────────────────────────────────────

    def step_start_chain(self) -> bool:
        addr_file = STATE / "public" / "vault_address.txt"
        if not addr_file.exists():
            self.emit("fail", "run setup first so THS can fund the vault")
            return False
        if loki_bin() is None:
            self.emit("fail", "the loki binary is not built. Run: cd poc && cargo build")
            return False
        self.network.start()
        self.network.fund(addr_file.read_text().strip())
        self.emit("ok", "test network and vault funding are ready; scan for funds next")
        return True

    def step_setup(self) -> bool:
        STATE.mkdir(parents=True, exist_ok=True)
        if not self.run_cli(["setup", str(STATE)], "setup", timeout=120):
            return False
        exe = loki_bin()
        env = dict(os.environ)
        env.pop("LOKI_RPC", None)
        env.pop("LOKI_ROUND", None)
        p = self.cli_command(exe, ["address", str(STATE)], env, 60)
        addr = (p.stdout or "").strip()
        if p.returncode != 0 or not addr:
            self.emit("fail", "could not read the vault address")
            return False
        (STATE / "public").mkdir(parents=True, exist_ok=True)
        (STATE / "public" / "vault_address.txt").write_text(addr + "\n")
        self.emit("ok", f"vault address {addr}")
        return True

    def step_scan(self) -> bool:
        exe = loki_bin()
        if exe is None:
            self.emit("fail", "the loki binary is not built. Run: cd poc && cargo build")
            return False
        self.emit("cmd", f"loki scan {STATE}")
        if not self.ths:
            self.emit("fail", "start the test network first")
            return False
        env = self.ths.env()
        p = self.cli_command(exe, ["scan", str(STATE)], env, 300)
        for line in (p.stdout or "").splitlines():
            if line.strip():
                self.emit("out", line.rstrip())
        for line in (p.stderr or "").splitlines():
            if line.strip():
                self.emit("err", line.rstrip())
        if p.returncode != 0:
            self.emit("fail", f"scan: exit {p.returncode}")
            return False
        # The account balance comes from the scan, which is the only thing that knows it:
        # a shielded chain does not say which outputs are ours.
        for line in (p.stdout or "").splitlines():
            m = re.match(r"^total (\d+) zat", line.strip())
            if m:
                (STATE / "public" / "balance.txt").write_text(f"total_zat={m.group(1)}\n")
        return True

    def step_commit(self) -> bool:
        return all(self.run_cli(["commit", str(STATE), m], f"commit {m}", timeout=120)
                   for m in MEMBERS)

    def step_propose(self) -> bool:
        if not self.run_cli(["propose", str(STATE)], "propose", timeout=300):
            return False
        # Snapshot what the security tests have to restore between runs: the honest
        # candidate, and alice's unspent nonces. Without this, re-running `commit` would
        # rotate her commitments and every tamper case would refuse on a stale alpha
        # rather than on the field under test.
        SNAP.mkdir(parents=True, exist_ok=True)
        pub = STATE / "public"
        shutil.copy2(pub / "candidate_AC.pczt.hex", SNAP / "candidate_AC.pczt.hex")
        for f in ("nonces_AB.hex", "nonces_AC.hex"):
            src = STATE / "alice" / f
            if src.exists():
                shutil.copy2(src, SNAP / f)
        self.emit("info", "snapshotted the honest candidate and alice's unspent nonces "
                          "so tamper experiments are repeatable")
        return True

    def step_review_sign(self, who: str) -> bool:
        return self.run_cli(["review-sign", str(STATE), who], f"review-sign {who}", timeout=300)

    def step_finish(self) -> bool:
        """Aggregate, install the anchor after signing, prove, broadcast, WAIT FOR MINING,
        then check the mined transaction against the approved intent.

        Stopping at `broadcast` would be the easy lie: a node accepting bytes is not the
        same as a block containing them, and a mined transaction is not the same as the
        payment that was approved. Both are checked here.
        """
        mined = STATE / "public" / "mined.txt"
        if not mined.exists() and not self.run_cli(["finish", str(STATE)], "finish", timeout=900):
            return False
        if not mined.exists():
            self.emit("fail", "finish did not record a txid")
            return False
        txid = ""
        for line in mined.read_text().splitlines():
            if line.startswith("txid="):
                txid = line.split("=", 1)[1].strip()
        if not txid:
            self.emit("fail", "no txid in mined.txt")
            return False

        self.emit("info", f"broadcast {txid}; mining three blocks through THS")
        self.network.mine(3)
        for _ in range(120):
            try:
                tx = self.ths.rpc("getrawtransaction", [txid, 1], timeout=3.0) or {}
            except (urllib.error.URLError, OSError, ValueError, TimeoutError, RuntimeError):
                tx = {}
            conf = tx.get("confirmations") or 0
            if conf >= 1:
                self.emit("ok", f"MINED at height {tx.get('height')}, "
                                f"{conf} confirmation(s): {txid}")
                break
            if self.cancel.wait(2):
                raise RuntimeError("execution cancelled")
        else:
            self.emit("fail", f"{txid} was accepted but no block confirmed it within 240s")
            return False

        # The effects check reads the chain, not any local file.
        self.emit("info", "verifying the mined transaction against the approved intent")
        verified = self.run_cli(
            ["verify-effects", str(STATE / "public"), txid], "verify-effects", timeout=300,
        )
        if verified:
            (STATE / "public" / "verified.txt").write_text(f"txid={txid}\n")
        return verified

    def restore_honest(self):
        pub = STATE / "public"
        if (SNAP / "candidate_AC.pczt.hex").exists():
            shutil.copy2(SNAP / "candidate_AC.pczt.hex", pub / "candidate_AC.pczt.hex")
        for f in ("nonces_AB.hex", "nonces_AC.hex"):
            if (SNAP / f).exists():
                shutil.copy2(SNAP / f, STATE / "alice" / f)
        for f in ("share_AC_alice.hex", "share_AB_alice.hex"):
            (pub / f).unlink(missing_ok=True)

    def step_tamper(self, case: str) -> bool:
        """Alter one field of the candidate, then let the signer react to it.

        This is the experiment worth running by hand: the signer is given bytes that are
        structurally valid and correctly randomised, and differ from the agreed payment in
        exactly one field. The pass condition is a refusal AND no share on disk.
        """
        if case not in TAMPER_CASES:
            self.emit("fail", f"unknown case {case!r}")
            return False
        if not (SNAP / "candidate_AC.pczt.hex").exists():
            self.emit("fail", "run `propose` first")
            return False

        self.restore_honest()
        self.emit("info", f"restored the honest candidate, then altering: {case}")
        if not self.run_cli(["tamper", str(STATE), case], f"tamper {case}", timeout=300):
            return False

        self.emit("info", "now asking alice to review the altered candidate")
        before = self.seq
        ok = self.run_cli(["review-sign", str(STATE), "alice"], "review-sign alice", timeout=300)
        share = any((STATE / "public" / f"share_{pair}_alice.hex").exists() for pair in ("AB", "AC"))
        expected = {
            "memo": "MemoDiffers", "recipient": "ExtraOutputOrPool", "amount": "AmountDiffers",
            "change-amount": "AmountDiffers", "change-address": "ExtraOutputOrPool",
            "input": "InputSetDiffers", "expiry": "expiry height differs",
            "transparent": "the transparent pool is in use", "sapling": "the Sapling pool is in use",
        }[case]
        output = "\n".join(event["text"] for event in self.events if event["seq"] > before)

        if ok:
            self.emit("fail", f"UNEXPECTED: alice accepted the altered candidate ({case})")
            return False
        if share:
            self.emit("fail", f"UNEXPECTED: alice refused but a share file exists ({case})")
            return False
        if expected not in output:
            self.emit("fail", f"UNEXPECTED: signer failed without the expected refusal {expected}")
            self.restore_honest()
            return False
        self.emit("ok", f"refused, and no share was written. The altered field was: {case}")
        self.restore_honest()
        return True

    def step_honest_control(self) -> bool:
        """The control. Without it, a refusal proves nothing: everything might refuse."""
        self.restore_honest()
        self.emit("info", "restored the honest candidate and asking alice again")
        ok = self.run_cli(["review-sign", str(STATE), "alice"], "review-sign alice", timeout=300)
        share = (STATE / "public" / "share_AC_alice.hex").exists()
        if ok and share:
            self.emit("ok", "the honest candidate was accepted and a share was written")
            return True
        self.emit("fail", "the honest candidate was NOT signed; the tamper results above "
                          "cannot be trusted until this passes")
        return False

    # ── teardown ────────────────────────────────────────────────────────────

    def stop_chain(self):
        self.network.stop()
        self.done.discard("start-chain")
        return True

    def step_reset(self) -> bool:
        self.stop_chain()
        target = SANDBOX.resolve()
        # Belt and braces: only ever this one directory, by name and by parent.
        if target.name != ".sandbox" or target.parent != DEMO:
            self.emit("fail", f"refusing to delete {target}")
            return False
        if target.exists():
            shutil.rmtree(target)
        self.done.clear()
        self.network = ManagedTHS(SANDBOX, self.emit, self.cancel)
        self.emit("ok", f"removed {target.relative_to(POC.parent)} and its owned THS environment")
        return True

    # ── dispatch ────────────────────────────────────────────────────────────

    def start(self, step: str, arg: str | None = None) -> dict:
        if self.closing:
            return {"started": False, "reason": "demo server is shutting down"}
        if not self.lock.acquire(blocking=False):
            return {"started": False, "reason": f"busy with {self.busy}"}

        table = {
            "setup": self.step_setup,
            "start-chain": self.step_start_chain,
            "scan": self.step_scan,
            "commit": self.step_commit,
            "propose": self.step_propose,
            "sign-alice": lambda: self.step_review_sign("alice"),
            "sign-carol": lambda: self.step_review_sign("carol"),
            "finish": self.step_finish,
            "honest-control": self.step_honest_control,
            "stop-chain": self.stop_chain,
            "reset": self.step_reset,
        }
        if step == "tamper":
            if arg not in TAMPER_CASES:
                self.lock.release()
                return {"started": False, "reason": f"unknown tamper case {arg!r}"}
            fn, label = (lambda a=arg: self.step_tamper(a)), f"tamper:{arg}"
        elif step in table:
            fn, label = table[step], step
        else:
            self.lock.release()
            return {"started": False, "reason": f"unknown step {step!r}"}

        try:
            reason = self.refusal(step)
        except Exception as error:
            self.lock.release()
            return {"started": False, "reason": str(error)}
        if reason:
            self.lock.release()
            return {"started": False, "reason": reason}

        self.busy = label
        self.emit("step", f"── {label} ──")

        def work():
            try:
                if fn() and not self.cancel.is_set():
                    self.done.add(label)
                    self.emit("done", f"{label} finished")
                else:
                    self.emit("stop", f"{label} did not complete")
            except Exception as e:                       # surface it, never swallow
                self.emit("fail", f"{label}: {type(e).__name__}: {e}")
            finally:
                self.busy = None
                self.lock.release()

        self.worker = threading.Thread(target=work, daemon=True)
        self.worker.start()
        return {"started": True, "step": label}

    def refusal(self, step):
        if step in ("reset", "stop-chain"):
            return None
        if self.network.ended:
            return "this network has ended; reset the demo before starting a fresh run"
        done = self.done | self.completed_on_disk()
        if step == "setup":
            return "account already exists; reset before creating another" if "setup" in done else None
        if step == "start-chain":
            return None if "setup" in done else "create the account first"
        if not self.ths or not self.network.probe():
            return "start the test network first; it must be live before running account stages"
        if self.network.funding_state != "confirmed":
            return "vault funding is not confirmed; check the Overview before proceeding"
        prerequisite = {
            "scan": "setup", "commit": "scan", "propose": "commit",
            "sign-alice": "propose", "sign-carol": "propose",
            "finish": "sign-carol", "tamper": "propose", "honest-control": "propose",
        }.get(step)
        if prerequisite and prerequisite not in done:
            return f"run {prerequisite} first"
        if step == "finish" and "sign-alice" not in done:
            return "Alice and Carol must both sign before execution"
        if step in ("commit", "propose") and "propose" in done:
            return "a transaction already exists; reset before replacing its signing material"
        if step in ("scan", "sign-alice", "sign-carol", "tamper", "honest-control") and (STATE / "public" / "mined.txt").exists():
            return "a transaction is already broadcast; execute it to verify the original payment"
        if step in ("sign-alice", "sign-carol", "finish", "tamper", "honest-control") and "finish" in done:
            return "this transaction has already been executed; reset before a fresh run"
        return None


RUNNER = Runner()
