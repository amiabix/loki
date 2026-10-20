#!/usr/bin/env python3
"""Drive the 3 running member_app processes (from web/wallet/.members.json) through the
full hosted journey on testnet. Mirrors hosted_flow.journey/payment but against already
running members and without the THS chain. This is the Phase-0 gate + the exact endpoint
sequence the React screens reproduce.

    python3 wallet/walk_journey.py setup                 # account -> create -> invite -> join -> DKG -> active
    python3 wallet/walk_journey.py pay <recipient-UA> <amount_zat>
"""

import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
MEMBERS = json.loads((REPO / "web" / "wallet" / ".members.json").read_text())["members"]
VAULT_FILE = Path.home() / "loki-hosted-demo" / "vault.txt"


def api(member, path, body=None, timeout=900):
    m = MEMBERS[member]
    req = urllib.request.Request(
        f"http://127.0.0.1:{m['port']}/api/{path}",
        data=None if body is None else json.dumps(body).encode(),
        headers={"X-Loki-Token": m["token"], "Content-Type": "application/json"},
        method="GET" if body is None else "POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"{path}: {json.loads(e.read()).get('error')}") from None


def until(read, check, what, limit=300, every=0.5):
    end = time.time() + limit
    last = None
    while time.time() < end:
        try:
            last = read()
            if check(last):
                return last
        except RuntimeError as e:
            last = str(e)
        time.sleep(every)
    raise SystemExit(f"timeout: {what}: {last}")


def status(member, vault):
    return api(member, f"status?vault={vault}")


def setup():
    for i in range(3):
        api(i, "profile-create", {"name": f"Member {i + 1}", "passphrase": f"pass-member-{i + 1}"})
    print("profiles created")
    vault = api(0, "create", {"name": "Hosted demo", "members": 3})["vault"]
    print(f"vault {vault}")
    state = until(lambda: status(0, vault), lambda s: len(s.get("invites", [])) == 2, "invites")
    codes = [row["code"] for row in state["invites"]]
    print(f"invites: {codes[0][:28]}… , {codes[1][:28]}…")
    for i, code in zip((1, 2), codes):
        assert api(i, "join", {"invite": code})["vault"] == vault
        print(f"member {i + 1} joined")
    fp = until(lambda: status(0, vault),
               lambda s: s.get("fingerprint") and s["phase"] == "compare_roster", "fingerprint")["fingerprint"]
    print(f"roster fingerprint {fp}")
    for i in (1, 2):
        until(lambda i=i: status(i, vault), lambda s: s.get("fingerprint") == fp and s["phase"] == "compare_roster",
              f"member {i + 1} fingerprint")
    for i in range(3):
        api(i, "agree", {"vault": vault, "fingerprint": fp})
    print("all agreed; running DKG…")
    for i in range(3):
        until(lambda i=i: status(i, vault), lambda s: s["phase"] == "back_up", f"dkg member {i + 1}")
    words = {}
    for i in range(3):
        words[i] = api(i, "backup", {"vault": vault})["words"]
        api(i, "verify", {"vault": vault, "words": words[i]})
    print("provisional backups checked")
    for i in range(3):
        until(lambda i=i: status(i, vault), lambda s: s["phase"] == "final_backup", f"certified member {i + 1}")
    for i in range(3):
        api(i, "finalize-backup", {"vault": vault, "words": words[i]})
        card = api(i, f"final-card?vault={vault}")["card"]
        api(i, "verify-final-backup", {"vault": vault, "words": words[i], "card": card})
    print("final cards checked")
    for i in range(3):
        until(lambda i=i: status(i, vault), lambda s: s["phase"] == "active", f"activation member {i + 1}")
    addrs = {api(i, "address", {"vault": vault})["address"] for i in range(3)}
    assert len(addrs) == 1, addrs
    address = addrs.pop()
    VAULT_FILE.write_text(json.dumps({"vault": vault, "address": address}))
    print(f"\nACTIVE. vault={vault}\naddress={address}\nsaved {VAULT_FILE}")


def pay(recipient, amount_zat):
    saved = json.loads(VAULT_FILE.read_text())
    vault = saved["vault"]
    bal = until(lambda: api(0, "balance", {"vault": vault}), lambda b: b["balance_zat"] > 0, "funds")
    print(f"balance {bal['balance_zat']} zat")
    draft = api(0, "payment-draft", {"vault": vault, "recipient": recipient,
                                     "amount_zat": str(amount_zat), "memo": "loki demo"})
    attempt = draft["attempt"]
    print(f"drafted attempt {attempt} fee={draft.get('fee_zat')} change={draft.get('change_zat')}")
    api(0, "payment-publish", {"vault": vault, "attempt": attempt})

    def reviews():
        for i in range(3):
            api(i, "payment-sync", {"vault": vault})
        for i in (0, 1):
            try:
                api(i, "payment-advance", {"vault": vault, "attempt": attempt})
            except RuntimeError:
                pass
        out = []
        for i in (0, 1):
            try:
                out.append(api(i, "payment-review", {"vault": vault, "attempt": attempt}))
            except RuntimeError:
                pass
        return out
    found = until(reviews, lambda r: len(r) == 2, "reviews")
    for i, review in zip((0, 1), found):
        api(i, "payment-approve", {"vault": vault, "attempt": attempt, "review_token": review["review_token"]})
    print("both signers approved")

    def finish():
        for i in range(3):
            api(i, "payment-sync", {"vault": vault})
        listed = api(2, f"payments?vault={vault}")["payments"]
        if not any(p["attempt"] == attempt and p["ready_to_send"] for p in listed):
            return {"phase": "waiting"}
        return api(2, "payment-finish", {"vault": vault, "attempt": attempt})
    sent = until(finish, lambda r: r["phase"] == "broadcast", "broadcast", limit=300)
    print(f"BROADCAST txid={sent['txid']}")
    until(lambda: api(2, "payment-verify", {"vault": vault, "attempt": attempt, "txid": sent["txid"]}),
          lambda r: r["phase"] == "confirmed", "confirm", limit=900, every=5)
    print("CONFIRMED on testnet")


if __name__ == "__main__":
    if sys.argv[1:] and sys.argv[1] == "setup":
        setup()
    elif sys.argv[1:] and sys.argv[1] == "pay":
        pay(sys.argv[2], int(sys.argv[3]))
    else:
        print(__doc__)
        sys.exit(2)
