#!/usr/bin/env python3
"""Live gate for one relay payment and the labelled recovery scenarios.

The public report records identities, carrier evidence, and scenario results.
It never records the coordinator token, the coordinator URL, or secret paths.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

DEMO = Path(__file__).resolve().parent
POC = DEMO.parent
REPO = POC.parent
HARNESS = REPO / "communication" / "harness"

SCENARIOS = (
    "normal_transfer",
    "recipient_offline_resume",
    "sender_exits_after_stored",
    "relay_unavailable_fallback",
    "missing_chunk_recovery",
    "duplicate_restart",
    "payment_stored_before_approver_exit",
)
ALLOWED = {
    "version", "run_id", "source_revision", "binary_hashes", "vault",
    "roster_fingerprint", "relays", "carriers", "receipt_digests",
    "mailbox_denial", "scenarios", "txid", "checks", "approver_stored",
}
DROPPED = {"token", "coordinator_url", "url", "links", "passphrase", "password"}


class GateError(RuntimeError):
    pass


def public_failure(text: str) -> str:
    """Keep a payment failure reason without paths or coordinator URLs."""
    if not isinstance(text, str) or not text.strip():
        return "payment failed"
    cleaned = re.sub(r"https?://\S+", " ", text)
    cleaned = re.sub(r"(?:/[^\s\"']+|[A-Za-z]:\\[^\s\"']+)", " ", cleaned)
    cleaned = " ".join(cleaned.split())
    return cleaned[:180] or "payment failed"


def build_report(raw: dict, *, forbidden: tuple[str, ...]) -> dict:
    for key, value in raw.items():
        if key in DROPPED:
            continue
        blob = json.dumps(value)
        for secret in forbidden:
            if secret and secret in blob:
                raise ValueError("report contains a secret")
    report = {key: raw[key] for key in ALLOWED if key in raw}
    encoded = json.dumps(report)
    for secret in forbidden:
        if secret and secret in encoded:
            raise ValueError("report contains a secret")
    return report


def require_evidence(report: dict) -> None:
    """The public report must contain the carrier, envelope, and receipt evidence."""
    carriers = report.get("carriers") or []
    if not any(isinstance(row, dict) and row.get("message_id") for row in carriers):
        raise GateError("report has no carrier id")
    if not any(isinstance(row, dict) and row.get("message_digest") for row in carriers):
        raise GateError("report has no carrier digest")
    if not any(isinstance(row, dict) and row.get("envelope_hash") for row in carriers):
        raise GateError("report has no inner envelope hash")
    if not any(isinstance(item, str) and item for item in (report.get("receipt_digests") or [])):
        raise GateError("report has no receipt digest")


def require_scenarios(scenarios: list[dict]) -> None:
    names = [item.get("name") for item in scenarios]
    if names != list(SCENARIOS):
        raise GateError("scenarios")
    for item in scenarios:
        if item.get("executed") is not True or item.get("result") != "passed":
            raise GateError(str(item.get("name")))
        if item.get("label") not in ("payment", "transport", "native_fixture"):
            raise GateError("label")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _request(base: str, method: str, path: str, token: str, body: dict | None = None):
    data = None if body is None else json.dumps(body).encode()
    headers = {"X-Loki-Token": token}
    if body is not None:
        headers["Content-Type"] = "application/json"
        headers["Origin"] = base
    request = urllib.request.Request(base + path, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        detail = error.read().decode(errors="replace")[:300]
        raise GateError(f"http {error.code}") from None


def _token_from_link(link: str) -> str:
    return link.rsplit("#", 1)[1]


def _events(base: str, token: str) -> list[dict]:
    events = []
    after = 0
    for _ in range(100):
        page = _request(base, "GET", f"/api/relay/events?after={after}", token)
        events.extend(page.get("events") or [])
        nxt = page.get("next")
        if type(nxt) is not int or nxt == after:
            break
        after = nxt
    return events


def drive_payment(base: str, admin: str, deadline: float) -> dict:
    _request(base, "POST", "/api/start", admin, {
        "amount_zat": 12_000_000, "memo": "relay payment gate"})
    alice = bob = None
    approved = set()
    finished = False
    while time.monotonic() < deadline:
        state = _request(base, "GET", "/api/state", admin)
        phase = state.get("phase")
        if phase == "failed":
            raise GateError(public_failure(str(state.get("error") or "")))
        if phase == "waiting_for_reviews" and alice is None:
            links = state.get("links") or {}
            alice = _token_from_link(links["alice"])
            bob = _token_from_link(links["bob"])
        if alice and bob and phase == "waiting_for_reviews":
            for role, token in (("alice", alice), ("bob", bob)):
                if role in approved:
                    continue
                member = _request(base, "GET", "/api/state", token)
                if member.get("signers", {}).get(role) == "reviewing":
                    _request(base, "POST", "/api/decide", token, {"action": "approve"})
                    approved.add(role)
        if phase == "ready_to_send" and not finished:
            _request(base, "POST", "/api/finish", admin, {})
            finished = True
        if phase == "confirmed" and isinstance(state.get("txid"), str):
            network = _request(base, "GET", "/api/relay/state", admin)
            return {"state": state, "network": network, "events": _events(base, admin)}
        time.sleep(1)
    raise GateError("payment deadline")


def _scenario(name: str, label: str, passed: bool, *, harness: str | None = None,
              harness_run: str | None = None) -> dict:
    item = {
        "name": name, "label": label, "executed": True, "result": "passed" if passed else "failed",
    }
    if harness:
        item["harness_scenario"] = harness
    if harness_run:
        item["harness_run_id"] = harness_run
    return item


def prepare_transport_root(root: Path) -> None:
    """Remove one retained harness root so the next fault run can create it."""
    root = Path(root)
    if not root.exists():
        return
    if not (root / ".harness-owner.json").is_file():
        raise GateError("transport root exists and is not a harness run")
    shutil.rmtree(root)


def transport_scenarios(root: Path, timeout: float) -> dict[str, dict]:
    prepare_transport_root(root)
    if str(HARNESS) not in sys.path:
        sys.path.insert(0, str(HARNESS))
    import run  # noqa: E402
    sys.path.insert(0, str(DEMO))
    import relay_demo  # noqa: E402
    ports = relay_demo.free_ports()
    report = run.run_faults(
        root, ports, communication_workspace=REPO / "communication", poc_workspace=POC,
        timeout=timeout, scenarios=("offline_delivery", "outage", "missing_chunk"))
    if isinstance(report, run.FaultResult):
        report = report.public_report()
    return {item["scenario"]: item for item in report["scenarios"]}


def _passed(item: dict | None) -> bool:
    return bool(item) and item.get("outcome") == "passed" and item.get("simulation") is not True


def assemble(payment: dict, harness: dict[str, dict], canary: dict, mailbox_absent: bool,
             identities: dict) -> dict:
    events = payment["events"]
    kinds = {event.get("event_type") for event in events}
    network = payment["network"]
    offline = harness.get("offline_delivery")
    outage = harness.get("outage")
    chunk = harness.get("missing_chunk")
    offline_ok = _passed(offline)
    approvers = payment["state"].get("approver_stored") or {}
    approver_stored = {
        "alice": approvers.get("alice") is True,
        "bob": approvers.get("bob") is True,
    }
    scenarios = [
        _scenario("normal_transfer", "payment",
                  "request_start" in kinds and network.get("stored", 0) > 0),
        _scenario("recipient_offline_resume", "transport", offline_ok,
                  harness="offline_delivery", harness_run=(offline or {}).get("scenario_run_id")),
        _scenario("sender_exits_after_stored", "transport", offline_ok,
                  harness="offline_delivery", harness_run=(offline or {}).get("scenario_run_id")),
        _scenario("relay_unavailable_fallback", "transport", _passed(outage),
                  harness="outage", harness_run=(outage or {}).get("scenario_run_id")),
        _scenario("missing_chunk_recovery", "native_fixture",
                  bool(chunk) and chunk.get("outcome") == "passed",
                  harness="missing_chunk", harness_run=(chunk or {}).get("scenario_run_id")),
        _scenario("duplicate_restart", "transport", offline_ok,
                  harness="offline_delivery", harness_run=(offline or {}).get("scenario_run_id")),
        _scenario("payment_stored_before_approver_exit", "payment",
                  payment["state"].get("phase") == "confirmed"
                  and approver_stored["alice"] and approver_stored["bob"]
                  and network.get("stored", 0) > 0
                  and mailbox_absent and canary.get("mailbox_denial") is True),
    ]
    carriers_by_message = {}
    envelopes = []
    digests = []
    for event in events:
        message = event.get("message_id")
        envelope = event.get("envelope_hash")
        message_digest = event.get("message_digest")
        if isinstance(message, str):
            row = carriers_by_message.setdefault(message, {"message_id": message})
            if isinstance(message_digest, str) and "message_digest" not in row:
                row["message_digest"] = message_digest
            if isinstance(envelope, str) and "envelope_hash" not in row:
                row["envelope_hash"] = envelope
        elif isinstance(envelope, str):
            row = {"envelope_hash": envelope}
            if row not in envelopes:
                envelopes.append(row)
        digest = event.get("receipt_digest")
        if isinstance(digest, str) and digest not in digests:
            digests.append(digest)
    carriers = [*carriers_by_message.values(), *envelopes]
    relays = []
    for relay in (identities.get("relays") or []):
        relays.append({
            "run_id": relay.get("run_id"),
            "receipt_key": relay.get("receipt_key"),
        })
    return {
        "version": 1,
        "run_id": identities.get("run_id") or payment["network"].get("run_id"),
        "source_revision": identities["source_revision"],
        "binary_hashes": identities["binary_hashes"],
        "vault": identities.get("vault"),
        "roster_fingerprint": identities.get("roster_fingerprint"),
        "relays": relays,
        "carriers": carriers,
        "receipt_digests": digests,
        "mailbox_denial": canary.get("mailbox_denial") is True and mailbox_absent,
        "approver_stored": approver_stored,
        "scenarios": scenarios,
        "txid": payment["state"].get("txid"),
        "checks": {
            "own_read": canary.get("own_read") is True,
            "peer_denial": canary.get("peer_denial") is True,
            "relay_denial": canary.get("relay_denial") is True,
            "confirmed": payment["state"].get("phase") == "confirmed",
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--timeout", type=float, default=1800)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535 or args.timeout <= 0:
        parser.error("port and timeout must be usable")
    if sys.platform != "darwin":
        print("macOS sandbox-exec is required; the live gate was not run", file=sys.stderr)
        return 2
    sys.path.insert(0, str(DEMO))
    import relay_sandbox  # noqa: E402
    deadline = time.monotonic() + args.timeout
    sandbox = Path(os.environ.get("LOKI_VERIFY_SANDBOX") or (DEMO / ".relay-payment-sandbox")).resolve()
    if sandbox == (DEMO / ".member-sandbox").resolve():
        parser.error("the verifier must not recover the existing member sandbox")
    sandbox.mkdir(parents=True, exist_ok=True)
    canary = relay_sandbox.denial_canary(sandbox)
    if str(HARNESS) not in sys.path:
        sys.path.insert(0, str(HARNESS))
    import run  # noqa: E402
    binaries = {
        "loki-relay-server": _sha256(run.find_binary(
            "loki-relay-server", workspace=REPO / "communication")),
        "loki_member_payment": _sha256(run.find_binary("loki_member_payment", workspace=POC)),
        "loki_relay_member": _sha256(run.find_binary("loki_relay_member", workspace=POC)),
        "loki_setup_member": _sha256(run.find_binary("loki_setup_member", workspace=POC)),
    }
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=REPO, check=True, capture_output=True, text=True,
    ).stdout.strip()
    env = os.environ.copy()
    env["LOKI_MEMBER_SANDBOX"] = "1"
    server = subprocess.Popen(
        [sys.executable, "-B", str(DEMO / "member_demo.py"), "--port", str(args.port),
         "--sandbox", str(sandbox)],
        cwd=str(REPO), env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    report_path = sandbox / "run" / "relay-payment-demo-report.json"
    try:
        line = server.stdout.readline() if server.stdout is not None else ""
        if "Coordinator: " not in line:
            raise GateError("coordinator did not start")
        threading.Thread(target=server.stdout.read, daemon=True).start()
        base = line.split("Coordinator: ", 1)[1].strip().split("/#", 1)[0]
        admin = line.split("#", 1)[1].strip()
        payment = drive_payment(base, admin, deadline)
        manifest = {}
        manifest_path = sandbox / "relay" / "relay-demo.json"
        if manifest_path.is_file():
            manifest = json.loads(manifest_path.read_text())
        remaining = deadline - time.monotonic()
        harness = {}
        if remaining > 30:
            harness = transport_scenarios(sandbox / "transport-scenarios", remaining)
        else:
            raise GateError("no time left for recovery scenarios")
        mailbox = sandbox / "run" / "payment" / "work" / "mailbox"
        report = assemble(payment, harness, canary, not mailbox.exists(), {
            "source_revision": revision,
            "binary_hashes": binaries,
            "run_id": manifest.get("harness_run_id") or payment["network"].get("run_id"),
            "vault": manifest.get("vault"),
            "roster_fingerprint": manifest.get("roster_fingerprint"),
            "relays": manifest.get("relays") or [],
        })
        public = build_report(report, forbidden=(admin, base, "pass.txt", "passphrase"))
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(public, indent=2, sort_keys=True) + "\n")
        report_path.chmod(0o644)
        require_scenarios(public["scenarios"])
        require_evidence(public)
        print(f"relay payment verified txid={public['txid']}", flush=True)
        return 0
    except Exception as error:
        print(f"relay payment gate failed: {error.__class__.__name__}: {error}", file=sys.stderr)
        return 1
    finally:
        if server.poll() is None:
            server.terminate()
            try:
                server.wait(timeout=20)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=5)


if __name__ == "__main__":
    sys.exit(main())
