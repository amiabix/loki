#!/usr/bin/env bash
# Checkpoint 4 adversarial tests.
#
# Each case replaces the SERIALIZED candidate AC with one a hostile proposer could have
# built: structurally valid, built by the real builder, correctly randomized, but not the
# payment the intent names. The test then runs the real `review-sign` process and requires
# BOTH:
#
#   1. a nonzero exit carrying a refusal, and
#   2. no share file written for that candidate.
#
# The second condition is the one that matters. A signer that printed a refusal and still
# emitted a share would have approved the transaction anyway.
#
# The harness runs its own commit and propose so the candidate and the published
# commitments always agree; otherwise every case refuses on a mismatched alpha instead of
# the effect under test.
set -uo pipefail

cd "$(dirname "$0")"
STATE="${LOKI_STATE:-/tmp/loki-tamper-state}"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/tmp/loki}"
export CARGO_TARGET_DIR
PUB="$STATE/public"
SNAP="/tmp/loki-tamper-snapshot"

loki() { cargo run --quiet --bin loki -- "$@"; }
rpc() {
  curl -s -X POST -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"$1\",\"params\":${2:-[]}}" \
    http://127.0.0.1:18232/
}
height() { rpc getblockcount | python3 -c 'import json,sys;print(json.load(sys.stdin)["result"])'; }

cleanup() { [ -n "${ZPID:-}" ] && kill "$ZPID" 2>/dev/null || true; }
trap cleanup EXIT

echo "== setting up a vault and three honest candidates =="
pkill -f 'zebrad -c harness' 2>/dev/null || true
sleep 2
rm -rf "$STATE"
loki setup "$STATE" >/dev/null
VAULT=$(loki address "$STATE")

python3 - "$VAULT" <<'PY'
import io, re, sys
p = 'harness/zebrad-regtest.toml'
s = io.open(p).read()
s = re.sub(r"miner_address = '[^']*'", "miner_address = '%s'" % sys.argv[1], s)
io.open(p, 'w').write(s)
PY

harness/zebrad -c harness/zebrad-regtest.toml start > /tmp/zebrad-tamper.log 2>&1 &
ZPID=$!
for _ in $(seq 1 30); do sleep 2; rpc getblockcount | grep -q result && break; done
until [ "$(height)" -ge 20 ]; do sleep 2; done

loki scan "$STATE" >/dev/null
for m in alice bob carol; do loki commit "$STATE" "$m" >/dev/null; done
loki propose "$STATE" >/dev/null
echo "   ready at height $(height)"
echo

# Snapshot the honest candidate, alice's unspent nonces, and her published commitments.
rm -rf "$SNAP"; mkdir -p "$SNAP"
cp "$PUB/candidate_AC.pczt.hex" "$SNAP/candidate_AC.hex"
cp "$STATE/alice/nonces_AB.hex" "$SNAP/"
cp "$STATE/alice/nonces_AC.hex" "$SNAP/"

restore() {
  cp "$SNAP/candidate_AC.hex" "$PUB/candidate_AC.pczt.hex"
  cp "$SNAP/nonces_AB.hex" "$STATE/alice/nonces_AB.hex"
  cp "$SNAP/nonces_AC.hex" "$STATE/alice/nonces_AC.hex"
  rm -f "$PUB/share_AC_alice.hex" "$PUB/share_AB_alice.hex"
}

echo "== tamper cases =="
# For each case, the refusal that must fire, verbatim from Refusal's Display impl.
# Asserting the exact refusal is what makes the test mean something: a signer that refused
# for an unrelated reason (a stale alpha, a sighash mismatch) would otherwise look like a
# pass while the check under test went unexercised.
# Refusals raised inside the Verifier surface as `Custom(<variant>)`, so these name the
# Refusal variant; the two raised by review_sign directly print through Display.
want() {
  case "$1" in
    memo)           echo 'MemoDiffers' ;;
    recipient)      echo 'ExtraOutputOrPool' ;;
    amount)         echo 'AmountDiffers' ;;
    change-amount)  echo 'AmountDiffers' ;;
    change-address) echo 'ExtraOutputOrPool' ;;
    fee)            echo 'AmountDiffers' ;;
    input)          echo 'InputSetDiffers' ;;
    expiry)         echo 'expiry height differs' ;;
    transparent)    echo 'the transparent pool is in use' ;;
    sapling)        echo 'the Sapling pool is in use' ;;
  esac
}

CASES="memo recipient amount change-amount change-address fee input expiry transparent sapling"
PASS=0; FAIL=0; SKIP=0

for CASE in $CASES; do
  WANT=$(want "$CASE")
  restore
  if ! ERR=$(loki tamper "$STATE" "$CASE" 2>&1); then
    echo "  $(printf '%-15s' "$CASE") COULD NOT CONSTRUCT: $(printf '%s' "$ERR" | tail -1)"
    SKIP=$((SKIP+1)); continue
  fi

  OUT=$(loki review-sign "$STATE" alice 2>&1); RC=$?
  SHARE=no; [ -f "$PUB/share_AC_alice.hex" ] && SHARE=yes
  REASON=$(printf '%s' "$OUT" | grep -o 'REFUSED: .*' | head -1)

  if [ $RC -eq 0 ] || [ "$SHARE" = yes ]; then
    echo "  $(printf '%-15s' "$CASE") FAIL: not refused (rc=$RC share_written=$SHARE)"
    printf '%s\n' "$OUT" | tail -2
    FAIL=$((FAIL+1))
  elif ! printf '%s' "$REASON" | grep -qF "$WANT"; then
    echo "  $(printf '%-15s' "$CASE") FAIL: refused, but for the wrong reason"
    echo "                  wanted: $WANT"
    echo "                  got:    ${REASON:-<no refusal printed>}"
    FAIL=$((FAIL+1))
  else
    echo "  $(printf '%-15s' "$CASE") refused, 0 shares  <- $(printf '%s' "$REASON" | cut -c1-84)"
    PASS=$((PASS+1))
  fi
done

restore
if loki review-sign "$STATE" alice >/dev/null 2>&1 && [ -f "$PUB/share_AC_alice.hex" ]; then
  echo "  $(printf '%-15s' "control") honest candidate accepted, share emitted"
  PASS=$((PASS+1))
else
  echo "  $(printf '%-15s' "control") FAIL: the honest candidate was not signed"
  FAIL=$((FAIL+1))
fi

echo
echo "tamper cases: $PASS passed, $FAIL failed, $SKIP could not be constructed"
echo
echo "notes:"
echo "  fee             NOT CONSTRUCTIBLE, and the builder says so: taking 1000 zat out of"
echo "                  the change leaves the bundle unbalanced, and build_for_pczt"
echo "                  refuses with ChangeRequired(ZatBalance(1000)). The implied fee is"
echo "                  in - out, so pinning the input set and both output values pins"
echo "                  the fee exactly; a candidate whose fee alone is wrong cannot be"
echo "                  built. The FeeDiffers arm is defence in depth, unreachable while"
echo "                  the input and output checks pass."
echo "  amount          the builder does not preserve the order the outputs were added in,"
echo "                  so whichever of the payment and the change the verifier reaches"
echo "                  first reports the shift. Both values are bound, which is what the"
echo "                  case has to establish; the test asserts AmountDiffers and the log"
echo "                  above records which output it named."
echo "  change-address  sending change to a diversified address the intent does not name"
echo "                  is caught by the per-output address check, which fires before the"
echo "                  change-count check can report ChangeAddressDiffers."
echo "  transparent     DeferredPcztBuilder has no transparent or Sapling methods, so"
echo "  sapling         these components are constructed through the public"
echo "                  zcash_transparent::pczt and sapling_crypto::pczt parse"
echo "                  constructors and grafted onto PcztParts, whose pool fields are"
echo "                  public. Such a candidate could never prove or mine, which is the"
echo "                  point: the signer must refuse it long before a prover runs."
[ $FAIL -eq 0 ]
