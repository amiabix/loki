#!/usr/bin/env python3
"""One real, separate-process member vault payment on an existing THS regtest instance."""

import argparse
import concurrent.futures
import json
import os
import pathlib
import shlex
import subprocess
import sys

from ths import THS


def run(argv, env, timeout=180):
    result = subprocess.run(argv, env=env, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{' '.join(map(str, argv[:2]))}: {result.stderr.strip()}")
    return result.stdout.strip()


def create_vault(root, vault_id, setup, env, member_count=3):
    root.mkdir(mode=0o700)
    exchange = root / "exchange"
    exchange.mkdir()
    members = []
    publics = []
    for number in range(1, member_count + 1):
        owner = root / f"member-{number}"
        owner.mkdir(mode=0o700)
        password = owner / "pass.txt"
        password.write_text("regtest passphrase for member %d\n" % number)
        password.chmod(0o600)
        publics.append(json.loads(run([setup, "identity", owner, str(number), password], env)))
        members.append((owner, password))
    roster = root / "roster.json"
    roster.write_text(json.dumps({"vault": f"{vault_id:02x}" * 32,
                                  "threshold": 2, "members": publics}))
    fingerprint = run([setup, "fingerprint", roster], env)
    with concurrent.futures.ThreadPoolExecutor(max_workers=member_count) as pool:
        futures = [pool.submit(run, [setup, "run", owner, password, roster, exchange, fingerprint], env)
                   for owner, password in members]
        for future in futures:
            future.result()

    for number, (owner, password) in enumerate(members, 1):
        card = root / f"card-{number}"
        words = run([setup, "backup-create", owner, password, card], env)
        words_file = root / f"words-{number}.txt"
        words_file.write_text(words + "\n")
        words_file.chmod(0o600)
        run([setup, "backup-verify", owner, password, card, words_file, roster, exchange], env)
    addresses = [run([setup, "address", owner, password, roster, exchange], env)
                 for owner, password in members]
    if len(set(addresses)) != 1:
        raise RuntimeError("members derived different vault addresses")
    for number, (owner, password) in enumerate(members, 1):
        run([setup, "backup-finalize", owner, password, root / f"card-{number}",
             root / f"final-card-{number}", root / f"words-{number}.txt", roster, exchange], env)
    return members, roster, addresses[0]


def restore_pair(root, setup, env, numbers, vault):
    signers = []
    for number in numbers:
        recovered = root / f"recovered-member-{number}"
        recovered.mkdir(mode=0o700)
        password = recovered / "pass.txt"
        password.write_text(f"new regtest passphrase for member {number}\n")
        password.chmod(0o600)
        owner = recovered / "member"
        card = root / "source" / f"final-card-{number}"
        words = root / "source" / f"words-{number}.txt"
        if run([setup, "restore", owner, password, card, words], env) != vault:
            raise RuntimeError("recovered signer derived another vault address")
        signers.append((owner, password))
        print(f"restored signing member {number} from exported final card and words", flush=True)
    return signers, signers[0][0] / "roster.json"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True, help="already running THS instance")
    parser.add_argument("--state", type=pathlib.Path, required=True, help="new, private test directory")
    parser.add_argument("--manual", action="store_true", help="prepare, then print commands for two human signers")
    parser.add_argument("--recover-signers", action="store_true", help="spend using only two restored source members and their exported final cards and words")
    parser.add_argument("--members", type=int, choices=(3, 4), default=3,
                        help="number of vault members; two approvals required")
    parser.add_argument("--stage", choices=("all", "setup", "fund", "prepare"), default="all",
                        help="run one step for the local member UI")
    parser.add_argument("--pair", choices=("AB", "AC", "AD", "BC", "BD", "CD"), default="AB", help="members who approve this payment")
    parser.add_argument("--proposer", type=int, help="member creating the payment; first signer in recovery mode")
    parser.add_argument("--recipient", help="recipient unified address; defaults to the local test recipient")
    parser.add_argument("--finisher", type=int, help="member who proves and sends; first signer in recovery mode")
    parser.add_argument("--amount-zat", type=int, default=40_000_000, help="regtest payment amount")
    parser.add_argument("--memo", default="separate member payment", help="shielded payment memo")
    args = parser.parse_args()
    if not 0 < args.amount_zat < 100_000_000:
        parser.error("amount must be between 1 and 99,999,999 zat")
    if not args.memo or len(args.memo.encode()) > 512:
        parser.error("memo must contain 1 to 512 UTF-8 bytes")
    root = args.state.resolve()
    if args.stage in ("all", "setup"):
        root.mkdir(mode=0o700, parents=True, exist_ok=False)
    elif not root.is_dir():
        parser.error("set up the vault before funding or preparing a payment")
    work = root / "payment"
    chain = THS(args.name)
    chain.check()
    env = chain.env()
    here = pathlib.Path(__file__).resolve().parent
    target = pathlib.Path(os.environ.get("CARGO_TARGET_DIR", here / "target"))
    if not target.is_absolute():
        target = here / target
    setup = target / "debug/loki_setup_member"
    pay = target / "debug/loki_member_payment"
    if not setup.is_file() or not pay.is_file():
        raise RuntimeError("run cargo build --locked --bins in poc/ first")

    if args.stage in ("all", "setup"):
        member_count = args.members
        members, roster, vault = create_vault(root / "source", 7, setup, env, member_count)
        recipient_members, recipient_roster, recipient_address = create_vault(root / "recipient", 8, setup, env, member_count)
        if vault == recipient_address:
            raise RuntimeError("recipient has the sender's address")
        (root / "vaults.json").write_text(json.dumps({"source": vault, "recipient": recipient_address,
                                                       "members": member_count, "funded": False}))
        print("activated source and independent recipient vaults", flush=True)
        print(f"Source vault: {vault}", flush=True)
        print(f"Independent recipient: {recipient_address}", flush=True)
        if args.stage == "setup":
            return
    else:
        vaults = json.loads((root / "vaults.json").read_text())
        member_count = vaults.get("members", 3)
        vault, recipient_address = vaults["source"], vaults["recipient"]
        members = [(root / "source" / f"member-{number}", root / "source" / f"member-{number}" / "pass.txt")
                   for number in range(1, member_count + 1)]
        roster = root / "source" / "roster.json"
        recipient_members = [(root / "recipient" / f"member-{number}", root / "recipient" / f"member-{number}" / "pass.txt")
                             for number in range(1, member_count + 1)]
        recipient_roster = root / "recipient" / "roster.json"
    if args.stage in ("all", "fund"):
        if args.stage == "fund" and vaults["funded"]:
            raise RuntimeError("source vault is already funded")
        chain.fund(vault, 1)
        (root / "vaults.json").write_text(json.dumps({"source": vault, "recipient": recipient_address,
                                                       "members": member_count, "funded": True}))
        print("funded source vault on THS", flush=True)
        if args.stage == "fund":
            return
    elif not vaults["funded"]:
        raise RuntimeError("fund the source vault before preparing a payment")

    pair = tuple(ord(letter) - ord("A") + 1 for letter in args.pair)
    if any(number > member_count for number in pair):
        parser.error("payment pair is outside this vault")
    proposer_id = args.proposer or (pair[0] if args.recover_signers else 1)
    finisher_id = args.finisher or (pair[0] if args.recover_signers else next(
        number for number in range(1, member_count + 1) if number not in pair))
    if args.recover_signers and (proposer_id not in pair or finisher_id not in pair):
        parser.error("recovery proposer and finisher must be restored signers")
    if proposer_id not in range(1, member_count + 1) or finisher_id not in range(1, member_count + 1):
        parser.error("proposer or finisher is outside this vault")
    restored, roster = restore_pair(root, setup, env, pair if args.recover_signers else pair[:1], vault)
    if args.recover_signers:
        members = [None] * member_count
    for number, signer in zip(pair, restored):
        members[number - 1] = signer

    destination = args.recipient or recipient_address
    owner, password = members[proposer_id - 1]
    run([pay, "prepare", owner, password, roster, work, destination, str(args.amount_zat), args.memo, args.pair], env)
    manifest = json.loads((work / "payment.json").read_text())
    signers = [members[number - 1] for number in manifest["pair"]]
    finisher = members[finisher_id - 1]
    if args.manual:
        def command(argv):
            return shlex.join(["env", f"LOKI_RPC={env['LOKI_RPC']}", *map(str, argv)])

        lines = [
            f"Source vault: {vault}",
            f"Independent recipient: {recipient_address}",
            f"Payment recipient: {destination}",
            f"Proposer: member {proposer_id}",
            f"Payment ID: {manifest['payment']}",
            "Run the next two commands at the same time in separate terminals. Read each review, then type its exact APPROVE prompt:",
            *(command([pay, "sign", *signer, roster, work]) for signer in signers),
            "After both say approved, run:",
            command([pay, "finish", *finisher, roster, work]),
            "Copy the txid from the finish output, then run:",
            shlex.join(["ths", "--name", args.name, "mine", "3"]),
            command([pay, "verify", *finisher, roster, work, "<TXID>"]),
        ]
        if destination == recipient_address:
            lines.append(command([pay, "receive", *recipient_members[0], recipient_roster, work, "<TXID>"]))
        (root / "manual-steps.txt").write_text("\n".join(lines) + "\n")
        print("\n".join(lines), flush=True)
        return
    approval = "APPROVE " + manifest["payment"] + "\n"

    def sign(number):
        member_owner, member_password = members[number - 1]
        result = subprocess.run(
            [pay, "sign", member_owner, member_password, roster, work],
            input=approval, text=True, capture_output=True, env=env, timeout=180,
        )
        if result.returncode:
            raise RuntimeError(f"member {number}: {result.stderr.strip()}\n{result.stdout.strip()}")
        return result.stdout.strip()

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(sign, number) for number in manifest["pair"]]
        for future in futures:
            print(future.result().splitlines()[-1], flush=True)

    owner, password = finisher
    finished = run([pay, "finish", owner, password, roster, work], env, timeout=900)
    print(finished, flush=True)
    txid = finished.split("txid=", 1)[1].split()[0]
    chain.mine(3)
    verified = run([pay, "verify", owner, password, roster, work, txid], env)
    print(verified, flush=True)
    received = None
    if destination == recipient_address:
        recipient_owner, recipient_password = recipient_members[0]
        received = run([pay, "receive", recipient_owner, recipient_password, recipient_roster, work, txid], env)
        print(received, flush=True)
    (root / "result.json").write_text(json.dumps({
        "vault": vault, "recipient": destination,
        "payment": manifest["payment"], "txid": txid,
        "verification": verified, "recipient_verification": received,
    }, indent=2) + "\n")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
