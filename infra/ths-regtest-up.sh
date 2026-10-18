#!/usr/bin/env bash
# Bring up (and verify) the THS regtest node the demo broadcasts onto, on omarchy.
# Re-runnable: starts a fresh "loki" env if none is running, then proves the chain
# matches the contract demo/managed_ths.py expects (branch 37a5165b, /api/v1/status,
# mine, lightwalletd). Does NOT spend funds.
#
# Prereqs on the host: Docker running, and the `ths` launcher built from the
# thus-spoke-zakura checkout at ~/Projects/thus-spoke-zakura:
#   cargo build --release --bin ths      # produces target/release/ths
#   ln -sf ~/Projects/thus-spoke-zakura/target/release/ths ~/.local/bin/ths
#   ths pull                             # fetch matching runtime images (zakura 1.6.0)
#
# ponytail: assumes the single env name "loki"; pass $NAME to run a second one.
set -euo pipefail
NAME="${NAME:-loki}"

command -v ths >/dev/null || { echo "ths launcher not on PATH; build it (see header)"; exit 1; }

if ! ths --name "$NAME" endpoints --json 2>/dev/null | grep -q '"rpc"'; then
  echo "starting THS regtest env '$NAME'..."
  nohup ths --name "$NAME" start --no-open >"$HOME/ths-$NAME.log" 2>&1 &
  until ths --name "$NAME" endpoints --json 2>/dev/null | grep -q '"rpc"'; do
    if grep -qiE 'error|failed|panic' "$HOME/ths-$NAME.log"; then
      echo "THS startup failed:"; tail -20 "$HOME/ths-$NAME.log"; exit 1
    fi
    sleep 3
  done
fi

eval "$(ths --name "$NAME" endpoints --json | python3 -c '
import sys, json
e = json.load(sys.stdin)
for k, v in (("RPC", "rpc"), ("DASH", "dashboard"), ("LWD", "lightwalletd")):
    print("%s=%s" % (k, e[v]))')"

echo "== endpoints =="; echo "rpc=$RPC dashboard=$DASH lightwalletd=$LWD"

echo "== chain branch (demo requires nextblock 37a5165b active) =="
curl -s -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","id":1,"method":"getblockchaininfo","params":[]}' "$RPC" \
| python3 -c '
import sys, json
d = json.load(sys.stdin)["result"]
nb = d["consensus"]["nextblock"]; st = d["upgrades"]["37a5165b"]["status"]
print("chain", d["chain"], "height", d["blocks"], "nextblock", nb, "nu6.3", st)
assert d["chain"] == "test" and nb == "37a5165b" and st == "active", "wrong branch for Loki regtest"'

echo "== dashboard /api/v1/status (demo probe) =="
curl -s "$DASH/api/v1/status" | python3 -c '
import sys, json
s = json.load(sys.stdin); w = s["wallet_sync"]
print("instance", s["instance"], "network", s["network"], "wallet", w["state"],
      "scanned", w["fully_scanned_height"], "observed", w["observed_height"])
assert s["network"].lower() == "regtest" and w["state"] == "ready", "wallet not ready"'

echo "== mine 1 (demo confirms via: ths --name $NAME mine <n> --json) =="
ths --name "$NAME" mine 1 --json | python3 -c 'import sys,json;print("mined", json.load(sys.stdin))'

echo "OK: regtest node up and matches the demo contract."
