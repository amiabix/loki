#!/usr/bin/env python3
"""One real, separate-process member vault payment on an existing THS regtest instance."""

import argparse
import concurrent.futures
import json
import pathlib
import subprocess
import sys

from ths import THS


def run(argv, env, timeout=180):
    result = subprocess.run(argv, env=env, text=True, capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{' '.join(map(str, argv[:2]))}: {result.stderr.strip()}")
    return result.stdout.strip()


def create_vault(root, vault_id, setup, env):
    root.mkdir(mode=0o700)
    exchange = root / "exchange"
    exchange.mkdir()
    members = []
    publics = []
    for number in (1, 2, 3):
        owner = root / f"member-{number}"
        owner.mkdir(mode=0o700)
        password = owner / "pass.txt"
        password.write_text("regtest passphrase for member %d\n" % number)
        password.chmod(0o600)
        publics.append(json.loads(run([setup, "identity", owner, str(number), password], env)))
        members.append((owner, password))
    roster = root / "roster.json"
    roster.write_text(json.dumps({"vault": f"{vault_id:02x}" * 32, "members": publics}))
    fingerprint = run([setup, "fingerprint", roster], env)
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        futures = [pool.submit(run, [setup, "run", owner, password, roster, exchange, fingerprint], env)
                   for owner, password in members]
        for future in futures:
            future.result()

    for number, (owner, password) in enumerate(members, 1):
        card = root / f"card-{number}"
        words = run([setup, "backup-create", owner, password, card], env)
        words_file = owner / "words.txt"
        words_file.write_text(words + "\n")
        words_file.chmod(0o600)
        run([setup, "backup-verify", owner, password, card, words_file, roster, exchange], env)
    addresses = [run([setup, "address", owner, password, roster, exchange], env)
                 for owner, password in members]
    if len(set(addresses)) != 1:
        raise RuntimeError("members derived different vault addresses")
    return members, roster, addresses[0]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--name", required=True, help="already running THS instance")
    parser.add_argument("--state", type=pathlib.Path, required=True, help="new, private test directory")
    args = parser.parse_args()
    root = args.state.resolve()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    work = root / "payment"
    chain = THS(args.name)
    chain.check()
    env = chain.env()
    here = pathlib.Path(__file__).resolve().parent
    setup = here / "target/debug/loki_setup_member"
    pay = here / "target/debug/loki_member_payment"
    if not setup.is_file() or not pay.is_file():
        raise RuntimeError("run cargo build --locked --bins in poc/ first")

    members, roster, vault = create_vault(root / "source", 7, setup, env)
    recipient_members, recipient_roster, recipient_address = create_vault(root / "recipient", 8, setup, env)
    if vault == recipient_address:
        raise RuntimeError("recipient has the sender's address")
    print("activated source and independent recipient vaults", flush=True)
    chain.fund(vault, 1)
    print("funded source vault on THS", flush=True)

    owner, password = members[0]
    run([pay, "prepare", owner, password, roster, work, recipient_address, "40000000", "separate member payment"], env)
    manifest = json.loads((work / "payment.json").read_text())
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
        futures = [pool.submit(sign, number) for number in (1, 2)]
        for future in futures:
            print(future.result().splitlines()[-1], flush=True)

    owner, password = members[2]
    finished = run([pay, "finish", owner, password, roster, work], env, timeout=900)
    print(finished, flush=True)
    txid = finished.split("txid=", 1)[1].split()[0]
    chain.mine(3)
    verified = run([pay, "verify", owner, password, roster, work, txid], env)
    print(verified, flush=True)
    recipient_owner, recipient_password = recipient_members[0]
    received = run([pay, "receive", recipient_owner, recipient_password, recipient_roster, work, txid], env)
    print(received, flush=True)
    (root / "result.json").write_text(json.dumps({
        "vault": vault, "recipient": recipient_address,
        "payment": manifest["payment"], "txid": txid,
        "verification": verified, "recipient_verification": received,
    }, indent=2) + "\n")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(f"error: {error}", file=sys.stderr)
        sys.exit(1)
