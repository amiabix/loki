#!/usr/bin/env python3
"""Make one funded 2-of-3 Testnet self-payment on the the build host relay stack."""

import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import time

ROOT = Path.home() / "tn-ceremony-state"
BIN = Path.home() / "loki/poc/target/debug"
LIGHTWALLETD = "https://testnet.zec.rocks:443"
ADDRESS = "utest1489sr06ervmjft2fv0gyhy7u9esv7lxmx787g62e5cvyg70pyzy3crn7h22g9e4kqhcfvq5l055esh9rrcrhs67fc5sp2wc0lsfzsq7s"
AMOUNT = 5_000_000
MEMO = "loki testnet"
WORK = ROOT / "member-1/payments/testnet-self-1"
PENDING = re.compile(r"error: waiting for member [1-3] (Commitment|Package|Share); sync relay inbox and retry\n")


def run(argv, timeout=180, pending=False):
    env = os.environ.copy()
    env["LOKI_LIGHTWALLETD"] = LIGHTWALLETD
    result = subprocess.run(list(map(str, argv)), cwd=Path.home() / "loki/poc",
                            env=env, capture_output=True, text=True, timeout=timeout)
    if result.returncode:
        if pending and PENDING.fullmatch(result.stderr):
            return None
        raise RuntimeError(f"{shlex.join(list(map(str, argv)))}: {result.stderr.strip()}")
    return result.stdout.strip()


def member(slot):
    root = ROOT / f"member-{slot}"
    return root, root / "passphrase", ROOT / f"roster-{slot}.json"


def payment(slot, work, action, *extra, pending=False, timeout=180):
    return run([BIN / "loki_member_payment", action, *member(slot), work, *extra],
               pending=pending, timeout=timeout)


def relay(slot, action, *extra):
    root, passfile, roster = member(slot)
    return run([BIN / "loki_relay_member", action, "--member-root", root,
                "--passphrase-file", passfile, "--roster", roster, *extra])


def sync(slot):
    result = json.loads(run([BIN / "loki_wallet_sync", *member(slot), LIGHTWALLETD], timeout=600))
    print(json.dumps({"stage": "sync", "member": slot, **result}), flush=True)
    return result


def check_manifest(manifest):
    if (manifest.get("network") != "testnet" or manifest.get("pair") != [1, 2]
            or manifest.get("amount_zat") != AMOUNT or manifest.get("memo") != MEMO.encode().hex()
            or not re.fullmatch(r"[0-9a-f]{64}", manifest.get("attempt", ""))):
        raise RuntimeError("prepared payment differs from the requested Testnet self-payment")


def await_confirmation(txid):
    if not re.fullmatch(r"[0-9a-f]{64}", txid):
        raise RuntimeError("saved broadcast txid is invalid")
    deadline = time.monotonic() + 1800
    while time.monotonic() < deadline:
        try:
            sync(1)
            result = run([BIN / "loki_member_payment", "confirm-mined", *member(1), WORK, txid])
        except RuntimeError as error:
            if (not str(error).endswith(": error: transaction is not mined in this wallet")
                    and not str(error).endswith(": error: lightwalletd tip is behind the scanned wallet")):
                raise
            print(json.dumps({"stage": "await-confirmation", "txid": txid}), flush=True)
            time.sleep(30)
            continue
        print(json.dumps({"stage": "confirmed", "output": result}), flush=True)
        return
    raise RuntimeError(f"confirmation deadline for txid={txid}")


def main():
    if run([BIN / "loki_member_payment", "features"]) != "relay-backed-signing=1":
        raise RuntimeError("loki_member_payment lacks relay-backed signing")
    broadcast_file = WORK / "broadcast.json"
    if broadcast_file.exists():
        await_confirmation(json.loads(broadcast_file.read_text())["txid"])
        return
    initial = sync(1)
    if initial["network"] != "testnet" or initial["balance_zat"] < AMOUNT:
        raise RuntimeError("funded Testnet balance is too small")
    if not (WORK / "payment.json").exists():
        print(json.dumps({"stage": "prepare", "output": payment(1, WORK, "prepare", ADDRESS,
                         AMOUNT, MEMO, "AB")}), flush=True)
    manifest = json.loads((WORK / "payment.json").read_text())
    check_manifest(manifest)
    attempt = manifest["attempt"]
    works = {1: WORK, 2: ROOT / "member-2/payments" / attempt,
             3: ROOT / "member-3/payments" / attempt}
    if not broadcast_file.exists():
        # shortcut: an interrupted signing attempt needs manual reconciliation before rerun.
        if any((works[slot] / "payment.json").exists() for slot in (2, 3)):
            raise RuntimeError("existing unbroadcast attempt requires manual reconciliation")
        relay(1, "send-proposal", "--proposal-file", WORK / "payment.json")
        deadline = time.monotonic() + 1200
        while time.monotonic() < deadline:
            relay(1, "upload")
            for slot in (2, 3):
                relay(slot, "poll", "--once")
                relay(slot, "import-proposals", "--payments-dir", member(slot)[0] / "payments")
                relay(slot, "upload")
            if all((work / "payment.json").exists() for work in works.values()):
                break
        else:
            raise RuntimeError("proposal did not reach all members")
        original = (WORK / "payment.json").read_bytes()
        if any((work / "payment.json").read_bytes() != original for work in works.values()):
            raise RuntimeError("imported proposal differs from member 1")
        print(json.dumps({"stage": "proposal", "attempt": attempt}), flush=True)
        sent = set()

        def pump():
            if time.monotonic() >= deadline:
                raise RuntimeError("signing transport deadline")
            for slot, work in works.items():
                wires = json.loads(payment(slot, work, "local-wires"))["wires"]
                if not isinstance(wires, list) or any(not re.fullmatch(r"[0-9a-f]{64}", w) for w in wires):
                    raise RuntimeError("invalid signing wire inventory")
                for wire in wires:
                    if (slot, wire) not in sent:
                        relay(slot, "send-signing", "--payload-file", work / "mailbox" / wire,
                              "--attempt", attempt)
                        sent.add((slot, wire))
                relay(slot, "upload")
            for slot, work in works.items():
                relay(slot, "poll", "--once")
                relay(slot, "export-signing", "--work-dir", work, "--attempt", attempt)

        def ready(slot, action):
            while time.monotonic() < deadline:
                value = payment(slot, works[slot], action, pending=True)
                if value is not None:
                    return value
                pump()
            raise RuntimeError(f"{action} deadline")

        for slot in (1, 2):
            print(json.dumps({"stage": "commit", "member": slot,
                              "output": payment(slot, works[slot], "commit")}), flush=True)
            pump()
        sync(1)
        print(json.dumps({"stage": "package", "output": ready(1, "package")}), flush=True)
        pump()
        for slot in (1, 2):
            review = json.loads(ready(slot, "review"))
            expected = {key: manifest[key] for key in ("vault", "payment", "attempt", "pair",
                        "amount_zat", "fee_zat", "change_zat", "expiry_height", "input_nullifiers")}
            if (review.get("authorization_required") is not True
                    or review.get("memo_hex") != manifest["memo"]
                    or review.get("recipient") != ADDRESS
                    or any(review.get(key) != value for key, value in expected.items())):
                raise RuntimeError(f"member {slot} review differs from approved intent")
            print(json.dumps({"stage": "review", "member": slot, "amount_zat": review["amount_zat"],
                              "fee_zat": review["fee_zat"], "recipient": review["recipient"]}), flush=True)
            print(json.dumps({"stage": "approve", "member": slot,
                              "output": payment(slot, works[slot], "approve-reviewed",
                                                review["review_token"])}), flush=True)
            pump()
        print(json.dumps({"stage": "finish-check", "output": ready(3, "finish-check")}), flush=True)
        sync(3)
        output = payment(3, works[3], "finish", LIGHTWALLETD, timeout=900)
        match = re.search(r"broadcast txid=([0-9a-f]{64})", output)
        if not match:
            raise RuntimeError(f"finish returned no broadcast txid: {output}")
        txid = match.group(1)
        fd = os.open(broadcast_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as file:
            json.dump({"txid": txid}, file)
        print(json.dumps({"stage": "broadcast", "output": output}), flush=True)
    await_confirmation(txid)


if __name__ == "__main__":
    main()
