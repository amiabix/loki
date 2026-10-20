#!/usr/bin/env python3
"""Guided, relay-free regtest exit for two members with final cards and words."""

import argparse
import getpass
import json
import os
import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path


HERE = Path(__file__).resolve().parent
SETUP = HERE.parent / "target/debug/loki_setup_member"
PAYMENT = HERE.parent / "target/debug/loki_member_payment"


class _Secret(str):
    pass


class RecoveryTool:
    def __init__(self, setup=SETUP, payment=PAYMENT, env=None):
        self.setup = Path(setup)
        self.payment = Path(payment)
        self.env = env or os.environ.copy()
        self.temporary = None
        self.root = None

    def __enter__(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="loki-recovery-")
        self.root = Path(self.temporary.name)
        return self

    def __exit__(self, *_):
        self.temporary.cleanup()

    @contextmanager
    def _argv(self, binary, action, args):
        argv = [str(binary), action]
        secrets = []
        try:
            for arg in args:
                if isinstance(arg, _Secret):
                    # The file is unlinked immediately, even if recovery is later killed.
                    secret = tempfile.TemporaryFile(dir=self.root)
                    secrets.append(secret)
                    secret.write(arg.encode())
                    secret.seek(0)
                    argv.append(f"/dev/fd/{secret.fileno()}")
                else:
                    argv.append(str(arg))
            yield argv, [secret.fileno() for secret in secrets]
        finally:
            for secret in secrets:
                secret.close()

    def command(self, binary, action, *args, timeout=180):
        with self._argv(binary, action, args) as (argv, readers):
            result = subprocess.run(argv, env=self.env, pass_fds=readers,
                                    text=True, capture_output=True, timeout=timeout)
        if result.returncode:
            raise ValueError(result.stderr.strip() or result.stdout.strip() or f"{action} failed")
        return result.stdout.strip()

    def sweep(self, artifacts, recipient, approve):
        if len(artifacts) != 2:
            raise ValueError("Two members must bring their own final card and words")
        session = Path(tempfile.mkdtemp(prefix="session-", dir=self.root))
        restored = []
        processes = []
        try:
            for index, (card_file, words, passphrase) in enumerate(artifacts):
                if not isinstance(words, str) or len(words.encode()) > 1024 or len(words.split()) != 24:
                    raise ValueError("Enter exactly 24 backup words for each member")
                if not isinstance(passphrase, str) or len(passphrase) < 12 or len(passphrase.encode()) > 1024:
                    raise ValueError("Choose a new passphrase of at least 12 characters")
                folder = session / f"member-{index + 1}"
                folder.mkdir(mode=0o700)
                card = folder / "card"
                card.mkdir(mode=0o700)
                if Path(card_file).stat().st_size > 64 * 1024:
                    raise ValueError("Final recovery card is too large")
                raw_card = Path(card_file).read_bytes()
                if len(raw_card) > 64 * 1024:
                    raise ValueError("Final recovery card is too large")
                with os.fdopen(os.open(card / "vault.card", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as out:
                    out.write(raw_card)
                owner = folder / "restored"
                address = self.command(self.setup, "restore", owner, _Secret(passphrase), card,
                                       _Secret(words))
                if not (owner / "roster.json").is_file() or not (owner / "secrets" / "activation.sealed").is_file():
                    raise ValueError("Use each member's final spend recovery card")
                roster = json.loads((owner / "roster.json").read_text())
                identity = json.loads(self.command(self.setup, "identity-public", owner,
                                                   _Secret(passphrase)))
                if identity not in roster.get("members", []):
                    raise ValueError("Restored member is absent from the certified roster")
                restored.append((identity["id"], owner, passphrase, roster, address))
            first, second = restored
            if first[0] == second[0]:
                raise ValueError("Recovery needs two distinct members")
            if first[3] != second[3] or first[4] != second[4]:
                raise ValueError("The two cards do not restore the same vault")
            if first[3].get("threshold") != 2 or len(first[3].get("members", [])) not in (3, 4):
                raise ValueError("Recovery requires a 2-of-3 or 2-of-4 vault")
            if not recipient or recipient == first[4]:
                raise ValueError("Enter the receive address of a different vault")
            pair = "".join(chr(64 + slot) for slot in sorted((first[0], second[0])))
            work = session / "payment"
            self.command(self.payment, "prepare-sweep", first[1], _Secret(first[2]),
                         first[1] / "roster.json", work, recipient, "sweep", pair, timeout=300)
            manifest = json.loads((work / "payment.json").read_text())
            if manifest.get("vault") != first[3]["vault"] or manifest.get("pair") != sorted((first[0], second[0])) \
                    or manifest.get("change_zat") != 0:
                raise ValueError("Sweep proposal differs from the recovered vault")
            payment_id = manifest["payment"]
            for slot, owner, password, *_ in restored:
                with self._argv(self.payment, "sign", (owner, _Secret(password),
                                                        owner / "roster.json", work)) as (argv, readers):
                    process = subprocess.Popen(argv, env=self.env, pass_fds=readers,
                                               text=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                               stderr=subprocess.STDOUT, bufsize=1)
                processes.append((slot, process))
            reviews = []
            for slot, process in processes:
                lines = []
                for line in process.stdout:
                    lines.append(line)
                    if line.strip() == f"Type APPROVE {payment_id} to sign:":
                        break
                else:
                    raise ValueError("Signing stopped before review: " + "".join(lines).strip())
                review = "".join(lines)
                reviews.append(review)
                if not approve(slot, review, payment_id):
                    raise ValueError(f"Member {slot} declined the payment")
                process.stdin.write(f"APPROVE {payment_id}\n")
                process.stdin.flush()
                process.stdin.close()
            for slot, process in processes:
                output = process.stdout.read()
                if process.wait(timeout=180):
                    raise ValueError(f"Member {slot} signing failed: {output.strip()}")
            output = self.command(self.payment, "finish", first[1], _Secret(first[2]),
                                  first[1] / "roster.json", work, timeout=900)
            match = re.search(r"\bbroadcast txid=([0-9a-f]{64})\b", output)
            if not match:
                raise ValueError("The node did not return a broadcast transaction ID")
            txid = match.group(1)
            verification_error = None
            try:
                verified = self.command(self.payment, "verify", first[1], _Secret(first[2]),
                                        first[1] / "roster.json", work, txid, timeout=180)
            except (ValueError, OSError, subprocess.TimeoutExpired) as error:
                verified = ""
                verification_error = str(error)
            if verified and f"verified mined txid={txid} confirmations=" not in verified:
                verification_error = "Chain verification did not confirm this sweep"
                verified = ""
            return {"txid": txid, "verified": bool(verified), "pair": pair,
                    "amount_zat": manifest["amount_zat"], "fee_zat": manifest["fee_zat"],
                    "reviews": reviews, "verification_error": verification_error}
        finally:
            for _, process in processes:
                if process.poll() is None:
                    process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()
                if process.stdin:
                    process.stdin.close()
                if process.stdout:
                    process.stdout.close()
            shutil.rmtree(session)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc", help="regtest node host:port; default 127.0.0.1:18232")
    args = parser.parse_args()
    if not SETUP.is_file() or not PAYMENT.is_file():
        parser.error("Install/build the Loki member tools before recovery")
    env = os.environ.copy()
    if args.rpc:
        env["LOKI_RPC"] = args.rpc
    print("Two members need their own final card and 24 words. Each chooses a NEW unlock passphrase.")
    print("Use one trusted recovery computer together. The old vault is not revoked until funds move.")
    artifacts = []
    for number in (1, 2):
        print(f"\nMember {number}")
        card = Path(input("Final recovery card file: ").strip()).expanduser()
        words = getpass.getpass("Your 24 backup words: ").strip()
        password = getpass.getpass("New unlock passphrase (12+ characters): ")
        if len(password) < 12:
            parser.error("Use a new passphrase of at least 12 characters")
        artifacts.append((card, words, password))
    recipient = input("Receive address of your NEW vault: ").strip()

    def approve(slot, review, payment_id):
        print(f"\nMember {slot}, check this verified transaction:\n{review}")
        return input(f"Member {slot}, type payment ID {payment_id} to approve: ").strip() == payment_id

    with RecoveryTool(env=env) as tool:
        result = tool.sweep(artifacts, recipient, approve)
    print(f"\nBroadcast transaction: {result['txid']}")
    if result["verified"]:
        print("Mined sweep verified. Check the new vault balance in your member app.")
    else:
        print(f"Verification incomplete: {result['verification_error']}")
        print("Check the new vault balance after this transaction is mined.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        raise SystemExit(f"Recovery stopped: {error}")
