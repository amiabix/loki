#!/usr/bin/env python3
"""Resume a local 2-of-3 Testnet ceremony against the owned loopback stack.

Build poc/loki_setup_member with relay-communication and the communication
loki-owned-test-inputs release binary first. Private state stays in --root.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import shlex
import stat
import subprocess
import tempfile
import time

from acceptance_resume import TERMINAL, agreement_needed, backup_actions, write_new

REPO = Path(__file__).resolve().parents[2]


def private_dir(path):
    if not path.exists():
        path.mkdir(mode=0o700)
    if not path.is_dir() or stat.S_IMODE(path.stat().st_mode) != 0o700:
        raise RuntimeError(f"private directory must have mode 0700: {path}")


def command(binary, action, *args, raw=False):
    argv = [str(binary), action, *map(str, args)]
    result = subprocess.run(argv, capture_output=True, timeout=180)
    if result.returncode:
        raise RuntimeError(f"{shlex.join(argv)}: {result.stderr.decode(errors='replace').strip()}")
    return result.stdout if raw else json.loads(result.stdout)


class Member:
    def __init__(self, slot, root, binary):
        self.slot = slot
        self.root = root / f"member-{slot}"
        self.passfile = self.root / "passphrase"
        self.binary = binary

    def call(self, action, *args, raw=False):
        return command(self.binary, action, self.root, self.passfile, *args, raw=raw)

    def step(self):
        return self.call("setup-step")

    def status(self):
        return command(self.binary, "setup-status", self.root)


def together(members, action):
    with ThreadPoolExecutor(max_workers=len(members)) as pool:
        return list(pool.map(action, members))


def drive(members, stage, done):
    deadline = time.monotonic() + 1200
    previous = None
    while time.monotonic() < deadline:
        states = together(members, Member.step)
        phases = [state["phase"] for state in states]
        if phases != previous:
            print(json.dumps({"stage": stage, "phases": phases}), flush=True)
            previous = phases
        if any(phase in TERMINAL for phase in phases):
            raise RuntimeError(f"{stage}: terminal ceremony phase {phases}")
        if done(states):
            return
        time.sleep(0.2)
    raise RuntimeError(f"{stage}: timed out at {previous}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("/tmp/loki-testnet-hosted-ceremony"))
    parser.add_argument("--inputs", type=Path, default=Path("/tmp/loki-tn-inputs"))
    parser.add_argument("--member-bin", type=Path, default=REPO / "poc/target/debug/loki_setup_member")
    parser.add_argument("--grant-bin", type=Path, default=REPO / "communication/target/release/loki-owned-test-inputs")
    args = parser.parse_args()
    root, inputs = args.root.resolve(), args.inputs.resolve()
    private_dir(root)
    key = (inputs / "config-key").read_bytes()
    if len(key) != 32:
        raise RuntimeError("operator config-key must be 32 bytes")
    bundle = root / "bundle"
    if not bundle.exists():
        write_new(bundle, (inputs / "bundle").read_bytes())
    elif bundle.read_bytes() != (inputs / "bundle").read_bytes():
        raise RuntimeError("saved operator bundle differs from inputs")
    members = [Member(slot, root, args.member_bin) for slot in (1, 2, 3)]
    for member in members:
        private_dir(member.root)
        if not member.passfile.exists():
            write_new(member.passfile, os.urandom(32).hex().encode())

    creator = members[0]
    if not (creator.root / "secrets/identity.sealed").exists():
        command(args.member_bin, "identity", creator.root, 1, creator.passfile)
    if not (creator.root / "secrets/hosted-context.sealed").exists():
        grant = root / "enrollment.grant"
        if not grant.exists():
            with tempfile.TemporaryDirectory(prefix=".issuer-", dir=root) as temporary:
                grant_root = Path(temporary)
                private_dir(grant_root / "inputs")
                for name in ("config-key", "issuer-signing-key"):
                    write_new(grant_root / "inputs" / name, (inputs / name).read_bytes())
                identity = creator.call("identity-public")
                write_new(grant, command(args.grant_bin, "grant", grant_root,
                                         "--device-key", identity["signing"],
                                         "--operator-bundle", bundle,
                                         "--policy", "2-of-3", raw=True))
        creator.call("setup-create", bundle, grant, "2-of-3", "--operator-key", key.hex(),
                     "--network", "testnet", "--development-http")

    deadline = time.monotonic() + 180
    while creator.step()["phase"] in ("admission_pending", "provisioning"):
        if time.monotonic() > deadline:
            raise RuntimeError("creator provisioning timed out")
    print(json.dumps({"stage": "creator-provisioned", "phase": creator.status()["phase"]}), flush=True)

    for peer in members[1:]:
        invite = creator.root / f"invite-{peer.slot}.private"
        if not invite.exists():
            creator.call("setup-invite", peer.slot, invite)
        peer_invite = peer.root / "invitation.private"
        if not peer_invite.exists():
            write_new(peer_invite, invite.read_bytes())
        elif peer_invite.read_bytes() != invite.read_bytes():
            raise RuntimeError(f"member {peer.slot} has a different saved invitation")
        if not (peer.root / "secrets/hosted-context.sealed").exists():
            peer.call("setup-join", peer_invite, bundle, "--operator-key", key.hex(),
                      "--network", "testnet", "--development-http")

    fingerprint = None

    def proposed(_states):
        nonlocal fingerprint
        info = together(members, lambda member: member.call("setup-info"))
        values = [item["fingerprint"] for item in info]
        if any(value is None for value in values):
            return False
        if len(set(values)) != 1:
            raise RuntimeError(f"member fingerprints differ: {values}")
        fingerprint = values[0]
        return True

    drive(members, "fingerprint", proposed)
    for member in members:
        if agreement_needed(member.status(), fingerprint):
            member.call("setup-agree", fingerprint)
    drive(members, "dkg-certificate", lambda states: all(
        state["phase"] in ("awaiting_backups", "certified", "payment_handoff", "active")
        for state in states))

    for member in members:
        words = member.root / "checked-words"
        final = member.root / "final-card/vault.card"
        actions = backup_actions(member.status(), words=words.exists(), final_card=final.exists())
        card = member.root / "provisional-card"
        if "create" in actions:
            write_new(words, member.call("setup-backup-create", card, raw=True))
        if "verify" in actions:
            member.call("setup-backup-verify", card, words)
    drive(members, "backup-receipts", lambda states: all(
        state["phase"] in ("certified", "payment_handoff", "active") for state in states))

    for member in members:
        if not (member.root / "final-card/vault.card").exists():
            member.call("setup-backup-finalize", member.root / "provisional-card",
                        member.root / "final-card", member.root / "checked-words")
    drive(members, "activation", lambda states: all(
        state["phase"] == "active" and state["handoff"] == "ready" for state in states))

    evidence = together(members, lambda member: member.call("setup-evidence"))
    for field in ("policy", "vault", "fingerprint", "address", "group_ak", "configuration_digest", "relays"):
        if any(item[field] != evidence[0][field] for item in evidence):
            raise RuntimeError(f"member evidence differs: {field}")
    if (evidence[0]["policy"] != "2-of-3" or not evidence[0]["address"].startswith("utest")
            or {item["own_slot"] for item in evidence} != {1, 2, 3}
            or any(item["handoff"] != "ready" or item["development"] is not True for item in evidence)
            or {route["endpoint"] for route in evidence[0]["relays"]} !=
            {f"http://127.0.0.1:{port}" for port in (39201, 39202, 39203)}):
        raise RuntimeError("incomplete Testnet activation evidence")
    print(json.dumps({"address": evidence[0]["address"], "group_ak": evidence[0]["group_ak"],
                      "vault": evidence[0]["vault"], "policy": evidence[0]["policy"]}), flush=True)


if __name__ == "__main__":
    main()
