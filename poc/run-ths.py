#!/usr/bin/env python3
"""Run Loki against an already running, disposable THS regtest instance."""

import argparse
import json
from pathlib import Path
import subprocess
import shutil
import tempfile
from ths import THS


POC = Path(__file__).resolve().parent
PAIR_MEMBERS = {"AB": ("alice", "bob"), "AC": ("alice", "carol"), "BC": ("bob", "carol")}


def run(argv, **kwargs):
    return subprocess.run(argv, check=True, text=True, **kwargs)


def finish_without_approvers(loki, state, replica, work):
    withheld = Path(tempfile.mkdtemp(prefix="loki-approvers-withheld-"))
    moved = []
    try:
        for member in ("alice", "bob", "carol"):
            shutil.move(str(state / member), str(withheld / member))
            moved.append(member)
        loki("finish-second", replica, work)
    finally:
        failures = []
        for member in ("alice", "bob", "carol"):
            if member in moved or (withheld / member).exists():
                try:
                    shutil.move(str(withheld / member), str(state / member))
                except OSError as error:
                    failures.append(f"{member}: {error}")
        if failures:
            raise RuntimeError(f"approver state retained at {withheld}; restore failed: {'; '.join(failures)}")
        withheld.rmdir()


def parse_args(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True, help="running THS instance name")
    parser.add_argument("--tamper", action="store_true", help="run signer refusal cases")
    parser.add_argument("--finish-mode", choices=("local", "replica", "posted"), default="local")
    parser.add_argument("--state", type=Path, help="new state directory; existing paths are refused")
    parser.add_argument("--pair", choices=tuple(PAIR_MEMBERS), default="AB")
    return parser.parse_args(argv)


def main():
    args = parse_args()

    chain = THS(args.name)
    chain.check()
    endpoints = chain.endpoints
    rpc = chain.rpc

    build = run(
        ["cargo", "build", "--locked", "--bin", "loki", "--message-format=json"],
        cwd=POC, stdout=subprocess.PIPE,
    )
    binary = next(
        item["executable"] for line in build.stdout.splitlines()
        if (item := json.loads(line)).get("reason") == "compiler-artifact"
        and item.get("executable") and item["target"]["name"] == "loki"
    )
    if args.state:
        state = args.state.resolve()
        state.mkdir(parents=True, exist_ok=False)
    else:
        state = Path(tempfile.mkdtemp(prefix="loki-ths-"))
    env = chain.env()
    print(f"THS instance: {args.name}\nState: {state}", flush=True)

    def loki(stage, *params, capture=False):
        return run([binary, stage, *map(str, params)], env=env, capture_output=capture)

    loki("setup", state)
    address = loki("address", state, capture=True).stdout.strip()
    funding = chain.fund(address, 2 if args.tamper else 1)
    for result in funding:
        print(f"Funding confirmed: {result['txid']}", flush=True)

    loki("scan", state)
    for member in ("alice", "bob", "carol"):
        loki("commit", state, member)
    loki("propose", state, "--memo", "loki ths regtest")
    public = state / "public"
    tamper_results = []
    if args.tamper:
        snapshot = {
            path: path.read_bytes()
            for pattern in ("public/candidate_*.hex", "public/randomizer_seed_*.hex",
                            "public/commitment_*.hex", "*/nonces_*.hex")
            for path in state.glob(pattern)
        }
        cases = {
            "memo": "MemoDiffers", "recipient": "ExtraOutputOrPool",
            "amount": "AmountDiffers", "change-amount": "AmountDiffers",
            "change-address": "ExtraOutputOrPool", "input": "InputSetDiffers",
            "expiry": "expiry height differs", "transparent": "the transparent pool is in use",
            "sapling": "the Sapling pool is in use", "fee": "ChangeRequired",
        }
        for case, reason in cases.items():
            for path, content in snapshot.items():
                path.write_bytes(content)
            changed = subprocess.run(
                [binary, "tamper", str(state), case], env=env, text=True, capture_output=True
            )
            if case == "fee":
                if changed.returncode == 0 or reason not in changed.stderr:
                    raise RuntimeError(f"unexpected fee fixture result: {changed.stderr}")
                status = "not constructible"
            else:
                changed.check_returncode()
                reviewed = subprocess.run(
                    [binary, "review-sign", str(state), "alice"],
                    env=env, text=True, capture_output=True,
                )
                if reviewed.returncode == 0 or reason not in reviewed.stderr:
                    raise RuntimeError(f"{case}: wrong refusal: {reviewed.stderr}")
                if list(public.glob("share_*.hex")):
                    raise RuntimeError(f"{case}: a rejected candidate emitted a share")
                status = "refused, zero shares"
            tamper_results.append({"case": case, "status": status})
            print(f"Tamper {case}: {status}", flush=True)
        for path, content in snapshot.items():
            path.write_bytes(content)

    for member in PAIR_MEMBERS[args.pair]:
        loki("review-sign", state, member)
    complete = [pair for pair, members in PAIR_MEMBERS.items()
                if all((public / f"share_{pair}_{member}.hex").is_file() for member in members)]
    if complete != [args.pair]:
        raise RuntimeError(f"expected only {args.pair} to be finishable, found {complete}")

    if args.finish_mode == "local":
        loki("finish", state, "--pair", args.pair)
        finished = public / "mined.txt"
    else:
        replica = state / "replica"
        work = state / "finisher"
        if args.finish_mode == "posted":
            loki("post-final", state, "--pair", args.pair)
        loki("replicate", state, replica, "--pair", args.pair, *(["--with-final"] if args.finish_mode == "posted" else []))
        finish_without_approvers(loki, state, replica, work)
        finished = work / "self" / "finished.txt"

    fields = dict(line.split("=", 1) for line in finished.read_text().splitlines() if "=" in line)
    if fields.get("pair") != args.pair:
        raise RuntimeError(f"finisher used {fields.get('pair')}, expected {args.pair}")
    txid = fields["txid"]
    chain.mine(3)
    loki("verify-effects", public if args.finish_mode == "local" else replica, txid)
    transaction = rpc("getrawtransaction", [txid, 1])
    if transaction.get("confirmations", 0) < 1:
        raise RuntimeError("transaction was not confirmed")
    report = {
        "instance": args.name, "endpoints": endpoints, "funding": funding,
        "finish_mode": args.finish_mode, "pair": args.pair, "txid": txid,
        "height": transaction.get("height"), "confirmations": transaction["confirmations"],
        "tamper": tamper_results,
    }
    (state / "ths-result.json").write_text(json.dumps(report, indent=2) + "\n")
    print(f"G1-TX PASS on THS; state retained at {state}; full G1 remains blocked on ZIP 2005")


if __name__ == "__main__":
    main()
