#!/usr/bin/env bash
# Second-device finishing, on the existing test-only G1 transaction path.
#
# Alice proposes. Alice and Carol review and sign. Both approver processes then END, and
# their state is MOVED ASIDE so nothing can reach it. Bob starts in a directory that has
# never held an approver file and finishes from a replica of public artifacts plus his own
# chain scan.
#
# Two payments, two paths:
#   payment 1, path A   a final transaction was already produced and posted. Bob checks it
#                       and broadcasts it.
#   payment 2, path B   no final transaction exists. Bob aggregates the shares, finds the
#                       note and the anchor by his own scan, installs them after the
#                       signature, proves, extracts and broadcasts.
#
# The vault FVK is the documented TEST-ONLY splice of the DKG group ak into
# `ak || nk || rivk`. It is NOT the ZIP 2005 `qsk -> qk -> rivk_ext` derivation, which is
# implemented nowhere. Full G1 stays BLOCKED on that. This establishes nothing about G3,
# nothing about recovery, and nothing about custody readiness.
set -uo pipefail
cd "$(dirname "$0")"

STATE="${LOKI_STATE:-/tmp/loki-2dev}"
BOB="${BOB_STATE:-/tmp/loki-2dev-bob}"
ATTIC="${ATTIC:-/tmp/loki-2dev-attic}"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/loki}"
export CARGO_TARGET_DIR

loki() { cargo run --quiet --bin loki -- "$@"; }
# Run a stage and abort on failure. Piping into `sed` would otherwise discard the exit
# code and the script would carry on past a broken stage, which is how the first version
# of this script "passed" four stages that had all failed.
step() {
  local label=$1; shift
  local out rc
  out=$("$@" 2>&1); rc=$?
  printf '%s\n' "$out" | sed 's/^/   /'
  if [ $rc -ne 0 ]; then echo "   STAGE FAILED: $label (rc=$rc)"; return 1; fi
  return 0
}
rpc() {
  curl -s -X POST -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-[]}}" \
    http://127.0.0.1:18232/
}
height() { rpc getblockcount | python3 -c 'import json,sys;print(json.load(sys.stdin)["result"])'; }
mine_to() { local t=$1; until [ "$(height)" -ge "$t" ]; do sleep 2; done; }

cleanup() { [ -n "${ZPID:-}" ] && kill "$ZPID" 2>/dev/null || true; }
trap cleanup EXIT

if lsof -nP -iTCP:18232 -sTCP:LISTEN >/dev/null 2>&1; then
  echo "port 18232 is already in use; stop the other zebrad first" >&2
  exit 1
fi

echo "== 0. a fresh regtest chain and a funded 2-of-3 vault =="
pkill -f 'zebrad -c harness' 2>/dev/null || true
sleep 2
rm -rf "$STATE" "$BOB" "$ATTIC"
loki setup "$STATE" >/dev/null
VAULT=$(loki address "$STATE")
echo "   vault $VAULT"

python3 - "$VAULT" <<'PY'
import io, re, sys
p = 'harness/zebrad-regtest.toml'
s = io.open(p).read()
s = re.sub(r"miner_address = '[^']*'", "miner_address = '%s'" % sys.argv[1], s)
io.open(p, 'w').write(s)
PY

harness/zebrad -c harness/zebrad-regtest.toml start > /tmp/zebrad-2dev.log 2>&1 &
ZPID=$!
for _ in $(seq 1 40); do sleep 2; rpc getblockcount | grep -q result && break; done
mine_to 20
loki scan "$STATE" | tail -4
[ -s "$STATE/public/funded_note_alt.txt" ] || { echo "need two vault notes"; exit 1; }

# ─────────────────────────────────────────────────────────────────────────────
run_payment() {
  local ROUND=$1 NOTE=$2 PATHNAME=$3 WITH_FINAL=$4
  local PUB="$STATE/public_$ROUND"
  local REPLICA="$BOB/replica_$ROUND"
  local WORK="$BOB/work_$ROUND"

  echo
  echo "======================================================================"
  echo " payment $ROUND, path $PATHNAME"
  echo "======================================================================"

  echo "-- round 1: every member preprocesses a fresh nonce pair for this payment"
  for M in alice bob carol; do
    LOKI_ROUND="$ROUND" step "commit $M" env LOKI_ROUND="$ROUND" \
      cargo run --quiet --bin loki -- commit "$STATE" "$M" >/dev/null || return 1
  done
  echo "   alice, bob, carol committed"

  echo "-- Alice proposes (note file: $NOTE)"
  LOKI_ROUND="$ROUND" step "propose" env LOKI_ROUND="$ROUND" \
    cargo run --quiet --bin loki -- propose "$STATE" "$NOTE" || return 1

  echo "-- Alice and Carol review and sign, as separate processes"
  for M in alice carol; do
    step "review-sign $M" env LOKI_ROUND="$ROUND" \
      cargo run --quiet --bin loki -- review-sign "$STATE" "$M" || return 1
  done

  if [ "$WITH_FINAL" = yes ]; then
    echo "-- Alice produces the final transaction and POSTS it, without broadcasting"
    step "post-final" env LOKI_ROUND="$ROUND" \
      cargo run --quiet --bin loki -- post-final "$STATE" || return 1
  fi

  echo "-- replicate the public artifacts Bob is allowed to have"
  if [ "$WITH_FINAL" = yes ]; then
    step "replicate" env LOKI_ROUND="$ROUND" \
      cargo run --quiet --bin loki -- replicate "$STATE" "$REPLICA" --with-final || return 1
  else
    step "replicate" env LOKI_ROUND="$ROUND" \
      cargo run --quiet --bin loki -- replicate "$STATE" "$REPLICA" || return 1
  fi

  echo "-- both approver apps close, and their state is MOVED OUT OF REACH"
  mkdir -p "$ATTIC"
  mv "$STATE" "$ATTIC/state_$ROUND"
  if [ -e "$STATE" ]; then echo "   FAILED to move approver state aside"; return 1; fi
  echo "   $STATE no longer exists; only $REPLICA remains"
  echo "   replica contents:"
  ls -1 "$REPLICA" | sed 's/^/     /'

  echo "-- Bob finishes in a fresh directory"
  mkdir -p "$WORK"
  local OUT TXID
  OUT=$(loki finish-second "$REPLICA" "$WORK" 2>&1); local RC=$?
  printf '%s\n' "$OUT" | sed 's/^/   /'
  [ $RC -eq 0 ] || { echo "   path $PATHNAME FAILED"; mv "$ATTIC/state_$ROUND" "$STATE"; return 1; }
  TXID=$(printf '%s\n' "$OUT" | tail -1)

  echo "-- mine it"
  mine_to $(( $(height) + 3 ))
  loki verify-effects "$REPLICA" "$TXID" | sed 's/^/   /' || {
    echo "   effects did NOT match the approved intent"; mv "$ATTIC/state_$ROUND" "$STATE"; return 1; }

  # Alice and Carol come back only so the next payment can be proposed. The finish above
  # already happened without them.
  mv "$ATTIC/state_$ROUND" "$STATE"
  echo "$ROUND path=$PATHNAME txid=$TXID" >> /tmp/loki-2dev-results.txt
  return 0
}

: > /tmp/loki-2dev-results.txt

echo
echo "== Bob's starting state =="
mkdir -p "$BOB"
echo "   $BOB created empty; it has never held an approver file"
ls -A "$BOB" | sed 's/^/     /' || true

run_payment p1 funded_note.txt     A yes || exit 1
run_payment p2 funded_note_alt.txt B no  || exit 1

echo
echo "== failure cases, asserted rather than asserted-about =="
FAILS=0
# Refused, AND for the stated reason, AND without any node call. `sendrawtransaction` in
# the output means the bytes reached a node, which for a local validation failure is itself
# the bug.
check_local() {
  local label=$1 want=$2; shift 2
  local out; out=$("$@" 2>&1); local rc=$?
  if [ $rc -eq 0 ]; then
    echo "   $label  NOT REFUSED (rc=0)"; FAILS=$((FAILS+1))
  elif printf '%s' "$out" | grep -q 'sendrawtransaction'; then
    echo "   $label  refused, but only by the NODE: $(printf '%s' "$out" | tail -1 | cut -c1-64)"
    FAILS=$((FAILS+1))
  elif ! printf '%s' "$out" | grep -qF "$want"; then
    echo "   $label  refused for the WRONG reason"
    echo "                                          wanted: $want"
    echo "                                          got:    $(printf '%s' "$out" | tail -1 | cut -c1-72)"
    FAILS=$((FAILS+1))
  else
    echo "   $label  refused locally: $(printf '%s' "$out" | tail -1 | cut -c1-72)"
  fi
}

check_fails() {
  local label=$1; shift
  local out; out=$("$@" 2>&1); local rc=$?
  if [ $rc -eq 0 ]; then
    echo "   $label  NOT REFUSED (rc=0)"; FAILS=$((FAILS+1))
  else
    echo "   $label  refused: $(printf '%s' "$out" | tail -1 | cut -c1-96)"
  fi
}

# A replica carrying an approver's scan output must be rejected: that is the whole point.
cp "$ATTIC/../loki-2dev/public/funded_note.txt" "$BOB/replica_p2/funded_note.txt" 2>/dev/null \
  || cp "$STATE/public/funded_note.txt" "$BOB/replica_p2/funded_note.txt"
check_fails "replica carries an approver scan file " \
  cargo run --quiet --bin loki -- finish-second "$BOB/replica_p2" "$BOB/work_reject"
rm -f "$BOB/replica_p2/funded_note.txt"

# A replica missing a share cannot be finished at all.
rm -rf "$BOB/replica_broken"; cp -R "$BOB/replica_p2" "$BOB/replica_broken"
rm -f "$BOB/replica_broken/share_AC_carol.hex"
check_fails "replica missing carol's share        " \
  cargo run --quiet --bin loki -- finish-second "$BOB/replica_broken" "$BOB/work_broken"

# A posted final transaction that does not parse must be refused by BOB, locally, before
# anything reaches a node. The earlier version of this case flipped a byte in the proof of
# an already-spent transaction, so the node rejected it as a double spend and the case
# proved nothing about Bob's checking. It now asserts which component refused.
rm -rf "$BOB/replica_badfinal"; cp -R "$BOB/replica_p1" "$BOB/replica_badfinal"
python3 -c 'import io,sys; p=sys.argv[1]; s=io.open(p).read().strip(); io.open(p,"w").write(s[:len(s)//2])' \
  "$BOB/replica_badfinal/final_tx.hex"
check_local "posted final tx does not parse        " \
  "does not parse" \
  cargo run --quiet --bin loki -- finish-second "$BOB/replica_badfinal" "$BOB/work_badfinal"

# A posted final transaction that parses perfectly but belongs to a DIFFERENT intent.
# Payment 2's mined transaction is substituted into payment 1's replica. Bob must notice
# that it does not spend the nullifier payment 1's intent names, and must notice it LOCALLY.
P2=$(grep '^p2 ' /tmp/loki-2dev-results.txt | sed 's/.*txid=//')
rm -rf "$BOB/replica_wrongtx"; cp -R "$BOB/replica_p1" "$BOB/replica_wrongtx"
rpc getrawtransaction "[\"$P2\"]" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"])' \
  > "$BOB/replica_wrongtx/final_tx.hex"
check_local "posted final tx is for another intent " \
  "does not spend the note the intent names" \
  cargo run --quiet --bin loki -- finish-second "$BOB/replica_wrongtx" "$BOB/work_wrongtx"

# Re-broadcasting payment 1 must be rejected. This one is rejected by the NODE, which is
# the correct layer for it: the nullifier is already spent on chain.
check_fails "payment 1 broadcast a second time     " \
  cargo run --quiet --bin loki -- finish-second "$BOB/replica_p1" "$BOB/work_again"

echo
echo "== results =="
cat /tmp/loki-2dev-results.txt | sed 's/^/   /'
echo
if [ $FAILS -ne 0 ]; then
  echo "$FAILS failure case(s) were NOT refused"
  exit 1
fi
echo "second-device finishing: both paths mined and verified"
echo "G1-TX second-device PASS; G1 BLOCKED (ZIP 2005); G3 unaffected; no custody claim"
