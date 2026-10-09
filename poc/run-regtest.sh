#!/usr/bin/env bash
# Loki G1-TX: one repeatable run, genesis to a mined AC transaction.
#
# Exits nonzero on any failure. Requires `harness/zebrad` (see harness/README.md for how
# it is built) and a free port 18232.
set -euo pipefail

cd "$(dirname "$0")"
WORK_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/loki-regtest.XXXXXX")
STATE="$WORK_ROOT/state"
CONF="$WORK_ROOT/zebrad.toml"
RPC="http://127.0.0.1:18232/"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/loki}"
export CARGO_TARGET_DIR

rpc() {
  curl -s -X POST -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-[]}}" "$RPC"
}
height() { rpc getblockcount | python3 -c 'import json,sys;print(json.load(sys.stdin)["result"])'; }
loki() { cargo run --quiet --bin loki -- "$@"; }

cleanup() { [ -n "${ZPID:-}" ] && kill "$ZPID" 2>/dev/null || true; }
trap cleanup EXIT

if lsof -nP -iTCP:18232 -sTCP:LISTEN >/dev/null 2>&1 ||
   lsof -nP -iTCP:18243 -sTCP:LISTEN >/dev/null 2>&1; then
  echo "regtest port 18232 or 18243 is already in use; stop the other node first" >&2
  exit 1
fi

echo "== 0. fresh isolated state: $WORK_ROOT =="

echo "== 1. DKG: a 2-of-3 vault =="
loki setup "$STATE"
VAULT=$(loki address "$STATE")

echo "== 2. start regtest, mining to the vault =="
python3 - "$VAULT" "$CONF" <<'PY'
import io, re, sys
p = 'harness/zebrad-regtest.toml'
s = io.open(p).read()
s = re.sub(r"miner_address = '[^']*'", "miner_address = '%s'" % sys.argv[1], s)
s = s.replace('network = "Regtest"', 'network = "Regtest"\nlisten_addr = "127.0.0.1:18243"')
io.open(sys.argv[2], 'w').write(s)
PY
harness/zebrad -c "$CONF" start > "$WORK_ROOT/zebrad.log" 2>&1 &
ZPID=$!

for _ in $(seq 1 30); do
  sleep 2
  if rpc getblockcount | grep -q result; then break; fi
done

# A shielded coinbase needs depth before the chain has an anchor to spend against.
echo "   mining..."
until [ "$(height)" -ge 20 ]; do sleep 2; done
echo "   height $(height), NU6.3 $(rpc getblockchaininfo | python3 -c '
import json,sys
for k,v in json.load(sys.stdin)["result"]["upgrades"].items():
    if "NU6.3" in v["name"]: print(v["status"])')"

echo "== 3. find the funded note =="
loki scan "$STATE" | tail -4

echo "== 4. round 1: each member preprocesses nonces =="
for m in alice bob carol; do loki commit "$STATE" "$m"; done

echo "== 5. build the three unproved candidates =="
loki propose "$STATE"

echo "== 6. review and sign, as three separate processes =="
for m in alice bob carol; do loki review-sign "$STATE" "$m"; done

echo "== 7. finish AC: aggregate, install anchor, prove, broadcast =="
loki finish "$STATE"

echo "== 8. mine it and confirm =="
TXID=$(grep '^txid=' "$STATE/public/mined.txt" | cut -d= -f2)
START=$(height)
until [ "$(height)" -ge $((START + 3)) ]; do sleep 2; done

CONF=$(rpc getrawtransaction "[\"$TXID\", 1]" | python3 -c '
import json,sys
r = json.load(sys.stdin)
if r.get("error"): print("ERROR", r["error"]); raise SystemExit(1)
t = r["result"]
print(t.get("confirmations", 0), t.get("height", "?"))')

echo "   txid $TXID"
echo "   confirmations/height: $CONF"
[ "${CONF%% *}" -ge 1 ] || { echo "AC was not mined"; exit 1; }

echo
echo "G1-TX PASS; G1 BLOCKED (ZIP 2005)"
