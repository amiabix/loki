#!/usr/bin/env bash
# Second-device finishing, on the existing test-only G1 transaction path.
#
# Alice proposes. Alice and Carol review and sign. Both approver processes then END, and
# their state is MOVED ASIDE so nothing can reach it. Bob starts in a directory that has
# never held an approver file and finishes from a confidential replica of approved
# artifacts plus his own chain scan.
#
# The original two one-note payments plus two payments that require two notes:
#   payment 1, path A   a final transaction was already produced and posted. Bob checks it
#                       and broadcasts it.
#   payment 2, path B   no final transaction exists. Bob aggregates the shares, finds the
#                       note and the anchor by his own scan, installs them after the
#                       signature, proves, extracts and broadcasts.
#   payments 3 and 4    repeat paths B and A with two input notes each.
#
# The vault FVK is the documented TEST-ONLY splice of the DKG group ak into
# `ak || nk || rivk`. Separate-member setup has a local ZIP 2005 derivation, but this
# payment path does not use it. Full G1 stays BLOCKED. This establishes nothing about G3,
# nothing about recovery, and nothing about custody readiness.
set -uo pipefail
unset LOKI_ROUND
cd "$(dirname "$0")"
export LOKI_ALLOW_FIXED_VIEWING_KEY=1

RUN_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/loki-issue3-2dev.XXXXXX") || exit 1
STATE="${LOKI_STATE:-$RUN_ROOT/state}"
BOB="${BOB_STATE:-$RUN_ROOT/bob}"
ATTIC="${ATTIC:-$RUN_ROOT/attic}"
RESULTS="$RUN_ROOT/results.txt"
export LOKI_THS_INSTANCE="${LOKI_THS_INSTANCE:-loki}"
LOKI_RPC=$(python3 ths.py address) || exit 1
export LOKI_RPC
for path in "$STATE" "$BOB" "$ATTIC"; do
  if [ -e "$path" ] || [ -L "$path" ]; then echo "refusing existing state path: $path" >&2; exit 1; fi
done
python3 - "$STATE" "$BOB" "$ATTIC" <<'CHECK_PATHS' || exit 1
from pathlib import Path
import sys
paths = [Path(value).resolve() for value in sys.argv[1:]]
for index, first in enumerate(paths):
    for second in paths[index + 1:]:
        if first == second or first in second.parents or second in first.parents:
            raise SystemExit("state, finisher, and attic paths must be separate: %s, %s" % (first, second))
CHECK_PATHS

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
rpc() { python3 ths.py rpc "$1" "${2:-[]}"; }
height() { rpc getblockcount | python3 -c 'import json,sys;print(json.load(sys.stdin)["result"])'; }
mine_next() { python3 ths.py mine 3; }

echo "== a funded 2-of-3 vault on THS =="
loki setup "$STATE" >/dev/null || exit 1
VAULT=$(loki address "$STATE") || exit 1
python3 ths.py fund "$VAULT" 2 || exit 1
loki scan "$STATE" | tail -4 || exit 1
[ -s "$STATE/public/funded_note_alt.txt" ] || { echo "need two vault notes"; exit 1; }

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


session_snapshot() {
  python3 - "$1" "$2" "$3" <<'PY_SESSION'
import hashlib, json, pathlib, sys
root, output = map(pathlib.Path, sys.argv[1:3])
spends = int(sys.argv[3])
files = sorted(root.glob('candidate_*.pczt.hex')) + sorted(root.glob('randomizer_seed_*.hex'))
assert len(files) == 3 + 3 * spends, 'missing candidate or per-spend seed record'
manifest = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
output.write_text(json.dumps(manifest, sort_keys=True))
PY_SESSION
}

seeds_fresh_and_private() {
  python3 - "$1" "$2" "$3" "$4" <<'PY_PRIVATE'
import hashlib, json, pathlib, stat, sys
root, history = map(pathlib.Path, sys.argv[1:3])
expected = int(sys.argv[3])
assert stat.S_IMODE(root.stat().st_mode) == 0o700, 'handoff directory must be 0700'
files = sorted(root.glob('randomizer_seed_*.hex'))
assert len(files) == expected, 'wrong number of replica seed records'
source = pathlib.Path(sys.argv[4])
for path in files:
    assert stat.S_IMODE(path.stat().st_mode) == 0o600, 'seed record must be 0600'
    assert path.read_bytes() == (source / path.name).read_bytes(), 'replica changed saved seed bytes'
assert (root / 'candidate_AC.pczt.hex').read_bytes() == (source / 'candidate_AC.pczt.hex').read_bytes(), 'replica changed candidate bytes'
files = sorted(source.glob('randomizer_seed_*.hex'))
assert len(files) == 3 * expected, 'wrong number of source seed records'
seen = set(history.read_text().splitlines()) if history.exists() else set()
current = []
for path in files:
    assert stat.S_IMODE(path.stat().st_mode) == 0o600, 'seed record must be 0600'
    digest = hashlib.sha256(bytes.fromhex(json.loads(path.read_text())['seed'])).hexdigest()
    assert digest not in seen and digest not in current, 'seed reused across spends or sessions'
    current.append(digest)
with history.open('a') as output:
    output.write(''.join(digest + '\n' for digest in current))
PY_PRIVATE
}

# ─────────────────────────────────────────────────────────────────────────────
run_payment() {
  local ROUND=$1 NOTE=$2 PATHNAME=$3 WITH_FINAL=$4 SPENDS=${5:-1} AMOUNT=${6:-}
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
      cargo run --quiet --bin loki -- commit "$STATE" "$M" --spends "$SPENDS" >/dev/null || return 1
  done
  echo "   alice, bob, carol committed"

  if [ -n "$AMOUNT" ]; then
    echo "-- Alice proposes $AMOUNT zat from $SPENDS notes"
    LOKI_ROUND="$ROUND" step "propose" env LOKI_ROUND="$ROUND" \
      cargo run --quiet --bin loki -- propose "$STATE" --amount "$AMOUNT" || return 1
  else
    echo "-- Alice proposes (note file: $NOTE)"
    LOKI_ROUND="$ROUND" step "propose" env LOKI_ROUND="$ROUND" \
      cargo run --quiet --bin loki -- propose "$STATE" "$NOTE" || return 1
  fi
  local ACTUAL
  ACTUAL=$(awk -F= '/^input_nullifier=/{print split($2, a, ",")}' "$PUB/intent.txt")
  [ "$ACTUAL" = "$SPENDS" ] || {
    echo "   STAGE FAILED: expected $SPENDS input notes, proposal selected $ACTUAL"; return 1;
  }

  local SAVED="$RUN_ROOT/session_$ROUND.json" RELOADED="$RUN_ROOT/reloaded_$ROUND.json"
  session_snapshot "$PUB" "$SAVED" "$SPENDS" || return 1
  local REPROPOSE RC
  REPROPOSE=$(env LOKI_ROUND="$ROUND" cargo run --quiet --bin loki -- propose "$STATE" 2>&1); RC=$?
  if [ "$RC" -eq 0 ] || ! printf '%s' "$REPROPOSE" | grep -qF 'saved signing session exists'; then
    echo '   STAGE FAILED: ordinary reproposal did not refuse the saved session'
    printf '%s\n' "$REPROPOSE" | tail -2
    return 1
  fi
  session_snapshot "$PUB" "$RELOADED" "$SPENDS" || return 1
  cmp -s "$SAVED" "$RELOADED" || { echo 'reproposal changed saved candidates/seeds'; return 1; }

  echo "-- Alice and Carol review and sign, as separate processes"
  for M in alice carol; do
    step "review-sign $M" env LOKI_ROUND="$ROUND" \
      cargo run --quiet --bin loki -- review-sign "$STATE" "$M" || return 1
    session_snapshot "$PUB" "$RELOADED" "$SPENDS" || return 1
    cmp -s "$SAVED" "$RELOADED" || { echo 'signing restart changed saved candidates/seeds'; return 1; }
  done
  echo '   candidate and seed bytes survived refusal and both signing process restarts'

  if [ "$WITH_FINAL" = yes ]; then
    echo "-- Alice produces the final transaction and POSTS it, without broadcasting"
    step "post-final" env LOKI_ROUND="$ROUND" \
      cargo run --quiet --bin loki -- post-final "$STATE" || return 1
  fi

  echo "-- replicate approved artifacts and confidential saved seeds for Bob"
  if [ "$WITH_FINAL" = yes ]; then
    step "replicate" env LOKI_ROUND="$ROUND" \
      cargo run --quiet --bin loki -- replicate "$STATE" "$REPLICA" --with-final || return 1
  else
    step "replicate" env LOKI_ROUND="$ROUND" \
      cargo run --quiet --bin loki -- replicate "$STATE" "$REPLICA" || return 1
  fi

  seeds_fresh_and_private "$REPLICA" "$RUN_ROOT/seen_seeds.txt" "$SPENDS" "$PUB" || return 1
  local BAD="$BOB/replica_seed_bad_$ROUND" SEED='randomizer_seed_AC.hex' ABSEED='randomizer_seed_AB.hex'
  if [ "$SPENDS" -gt 1 ]; then SEED='randomizer_seed_AC_1.hex'; ABSEED='randomizer_seed_AB_1.hex'; fi
  cp -R "$REPLICA" "$BAD"
  rm "$BAD/$SEED"
  check_local "path $PATHNAME ($SPENDS inputs), missing saved seed" 'missing randomizer seed record' \
    cargo run --quiet --bin loki -- finish-second "$BAD" "$BOB/work_seed_missing_$ROUND"
  cp "$PUB/$ABSEED" "$BAD/$SEED"
  check_local "path $PATHNAME ($SPENDS inputs), swapped pair seed" 'randomizer seed pair mismatch' \
    cargo run --quiet --bin loki -- finish-second "$BAD" "$BOB/work_seed_swapped_$ROUND"
  rm -rf "$BAD"

  echo "-- both approver apps close, and their state is MOVED OUT OF REACH"
  mkdir -p "$ATTIC"
  mv "$STATE" "$ATTIC/state_$ROUND" || return 1
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
  mine_next || return 1
  loki verify-effects "$REPLICA" "$TXID" | sed 's/^/   /' || {
    echo "   effects did NOT match the approved intent"; mv "$ATTIC/state_$ROUND" "$STATE"; return 1; }

  # Alice and Carol come back only so the next payment can be proposed. The finish above
  # already happened without them.
  mv "$ATTIC/state_$ROUND" "$STATE" || return 1
  echo "$ROUND path=$PATHNAME txid=$TXID" >> "$RESULTS"
  return 0
}

: > "$RESULTS"

echo
echo "== Bob's starting state =="
mkdir -p "$BOB"
echo "   $BOB created empty; it has never held an approver file"
ls -A "$BOB" | sed 's/^/     /' || true

run_payment p1 funded_note.txt     A yes || exit 1
run_payment p2 funded_note_alt.txt B no  || exit 1

# The payment recipient belongs to the same test FVK, so the first two payments leave
# two 0.5999-ZEC change notes from the two 1-ZEC faucet notes. Refresh the scan,
# then pay more than either note can cover while staying within the funded balance.
step "scan before two-note payment" cargo run --quiet --bin loki -- scan "$STATE" || exit 1
run_payment p3 "" B no 2 100000000 || exit 1
step "scan before second two-note payment" cargo run --quiet --bin loki -- scan "$STATE" || exit 1
run_payment p4 "" A yes 2 110000000 || exit 1

echo
echo "== failure cases, asserted rather than asserted-about =="

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
cp "$STATE/public/funded_note.txt" "$BOB/replica_p2/funded_note.txt"
check_fails "replica carries an approver scan file " \
  cargo run --quiet --bin loki -- finish-second "$BOB/replica_p2" "$BOB/work_reject"
rm -f "$BOB/replica_p2/funded_note.txt"

# A replica missing a share cannot be finished at all.
cp -R "$BOB/replica_p2" "$BOB/replica_broken"
rm -f "$BOB/replica_broken/share_AC_carol.hex"
check_fails "replica missing carol's share        " \
  cargo run --quiet --bin loki -- finish-second "$BOB/replica_broken" "$BOB/work_broken"

# A posted final transaction that does not parse must be refused by BOB, locally, before
# anything reaches a node. The earlier version of this case flipped a byte in the proof of
# an already-spent transaction, so the node rejected it as a double spend and the case
# proved nothing about Bob's checking. It now asserts which component refused.
cp -R "$BOB/replica_p1" "$BOB/replica_badfinal"
python3 -c 'import io,sys; p=sys.argv[1]; s=io.open(p).read().strip(); io.open(p,"w").write(s[:len(s)//2])' \
  "$BOB/replica_badfinal/final_tx.hex"
check_local "posted final tx does not parse        " \
  "does not parse" \
  cargo run --quiet --bin loki -- finish-second "$BOB/replica_badfinal" "$BOB/work_badfinal"

# A posted final transaction that parses perfectly but belongs to a DIFFERENT intent.
# Payment 2's mined transaction is substituted into payment 1's replica. Bob must notice
# that it does not spend the nullifier payment 1's intent names, and must notice it LOCALLY.
P2=$(grep '^p2 ' "$RESULTS" | sed 's/.*txid=//')
cp -R "$BOB/replica_p1" "$BOB/replica_wrongtx"
rpc getrawtransaction "[\"$P2\"]" \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)["result"])' \
  > "$BOB/replica_wrongtx/final_tx.hex"
check_local "posted final tx is for another intent " \
  "effects differ from the signed candidate" \
  cargo run --quiet --bin loki -- finish-second "$BOB/replica_wrongtx" "$BOB/work_wrongtx"

# Re-broadcasting payment 1 must be rejected. The finisher's own scan now excludes
# spent notes, so this may be refused locally before the bytes reach the node.
check_fails "payment 1 broadcast a second time     " \
  cargo run --quiet --bin loki -- finish-second "$BOB/replica_p1" "$BOB/work_again"

echo
echo "== results =="
sed 's/^/   /' "$RESULTS"
echo
if [ $FAILS -ne 0 ]; then
  echo "$FAILS failure case(s) were NOT refused"
  exit 1
fi
echo "second-device finishing: both paths, one and two inputs, mined and verified"
echo "G1-TX second-device PASS; G1 BLOCKED (ZIP 2005); G3 unaffected; no custody claim"
