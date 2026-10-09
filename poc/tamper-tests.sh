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
STATE="${LOKI_STATE:-$(mktemp -d "${TMPDIR:-/tmp}/loki-issue3-tamper.XXXXXX")/state}"
if [ -e "$STATE" ] || [ -L "$STATE" ]; then echo "refusing existing state path: $STATE" >&2; exit 1; fi
export LOKI_THS_INSTANCE="${LOKI_THS_INSTANCE:-loki}"
LOKI_RPC=$(python3 ths.py address) || exit 1
export LOKI_RPC
unset LOKI_ROUND
PUB="$STATE/public"
SNAP=$(mktemp -d "${TMPDIR:-/tmp}/loki-issue3-tamper-snapshot.XXXXXX") || exit 1
trap 'rm -rf "$SNAP"' EXIT
loki() { cargo run --quiet --bin loki -- "$@"; }
echo "== funding a fresh vault on THS =="
loki setup "$STATE" >/dev/null || exit 1
VAULT=$(loki address "$STATE") || exit 1
python3 ths.py fund "$VAULT" 2 || exit 1
loki scan "$STATE" >/dev/null || exit 1
for m in alice bob carol; do loki commit "$STATE" "$m" >/dev/null || exit 1; done
loki propose "$STATE" >/dev/null || exit 1
# Restore the whole saved signing session, including seed associations and commitments.
snapshot() {
  rm -rf "$SNAP/public" "$SNAP/alice"
  cp -R "$PUB" "$SNAP/public"
  cp -R "$STATE/alice" "$SNAP/alice"
}
restore() {
  rm -rf "$PUB" "$STATE/alice"
  cp -R "$SNAP/public" "$PUB"
  cp -R "$SNAP/alice" "$STATE/alice"
  rm -f "$PUB"/share_*.hex
}
zero_shares() {
  [ -z "$(find "$PUB" -name 'share_*.hex' -print)" ]
}
nonces_unchanged() {
  python3 - "$SNAP/alice" "$STATE/alice" <<'PY_NONCES'
import pathlib, sys
before, after = map(pathlib.Path, sys.argv[1:])
for source in before.glob('nonces_*.hex'):
    target = after / source.name
    if not target.exists() or source.read_bytes() != target.read_bytes():
        raise SystemExit(f'nonce changed on refusal: {source.name}')
PY_NONCES
}
snapshot

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
    if [ "$CASE" = fee ] && printf '%s' "$ERR" | grep -qF 'ChangeRequired'; then
      echo "  fee             COULD NOT CONSTRUCT: $(printf '%s' "$ERR" | tail -1)"
      SKIP=$((SKIP+1))
    else
      echo "  $CASE FAIL: unexpected fixture construction failure: $ERR"
      FAIL=$((FAIL+1))
    fi
    continue
  fi

  OUT=$(loki review-sign "$STATE" alice 2>&1); RC=$?
  SHARE=no; zero_shares || SHARE=yes
  REASON=$(printf '%s' "$OUT" | grep -o 'REFUSED: .*' | head -1)

  if [ $RC -eq 0 ] || [ "$SHARE" = yes ]; then
    echo "  $(printf '%-15s' "$CASE") FAIL: not refused (rc=$RC share_written=$SHARE)"
    printf '%s\n' "$OUT" | tail -2
    FAIL=$((FAIL+1))
  elif ! nonces_unchanged; then
    echo "  $CASE FAIL: nonce state changed on refusal"
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
echo "== saved-seed failures in the last spend of the last reviewed pair =="
export LOKI_ROUND=seed_batch
PUB="$STATE/public_$LOKI_ROUND"
for m in alice bob carol; do loki commit "$STATE" "$m" --spends 2 >/dev/null || exit 1; done
loki propose "$STATE" --amount 100000000 >/dev/null || exit 1
[ "$(awk -F= '/^input_nullifier=/{print split($2, a, ",")}' "$PUB/intent.txt")" = 2 ] || {
  echo 'seed batch needs exactly two real inputs'; exit 1;
}
snapshot
for CASE in missing short badhex wrong-version swap-pair swap-spend changed-seed changed-commitments; do
  restore
  case "$CASE" in
    missing) WANT='missing randomizer seed record' ;;
    short) WANT='randomizer seed must be exactly 32 bytes' ;;
    badhex) WANT='invalid randomizer seed hex' ;;
    wrong-version) WANT='unsupported randomizer seed record version' ;;
    swap-pair) WANT='randomizer seed pair mismatch' ;;
    swap-spend) WANT='randomizer seed spend index mismatch' ;;
    changed-seed) WANT='rk does not match' ;;
    changed-commitments) WANT='randomizer seed commitments mismatch' ;;
  esac
  python3 - "$PUB" "$CASE" <<'PY_SEED'
import json, pathlib, sys
root = pathlib.Path(sys.argv[1])
case = sys.argv[2]
path = root / 'randomizer_seed_AC_1.hex'
if case == 'missing':
    path.unlink()
elif case == 'swap-pair':
    path.write_bytes((root / 'randomizer_seed_AB_1.hex').read_bytes())
elif case == 'swap-spend':
    path.write_bytes((root / 'randomizer_seed_AC.hex').read_bytes())
elif case == 'changed-commitments':
    (root / 'commitment_AC_carol_1.hex').write_bytes((root / 'commitment_BC_carol_1.hex').read_bytes())
else:
    record = json.loads(path.read_text())
    if case == 'short': record['seed'] = '00'
    elif case == 'badhex': record['seed'] = 'gg' * 32
    elif case == 'wrong-version': record['version'] = 999
    elif case == 'changed-seed':
        record['seed'] = ('01' if record['seed'][:2] == '00' else '00') + record['seed'][2:]
    path.write_text(json.dumps(record))
PY_SEED
  OUT=$(loki review-sign "$STATE" alice 2>&1); RC=$?
  if [ "$RC" -eq 0 ] || ! zero_shares || ! nonces_unchanged || ! printf '%s' "$OUT" | grep -qF "$WANT"; then
    echo "  $CASE FAIL: rc=$RC; expected $WANT and zero shares/unchanged nonces"
    printf '%s\n' "$OUT" | tail -3
    FAIL=$((FAIL+1))
  else
    echo "  $CASE refused: $WANT; zero shares across AB/AC and both inputs"
    PASS=$((PASS+1))
  fi
done
restore
if loki review-sign "$STATE" alice >/dev/null 2>&1 &&
   [ -f "$PUB/share_AB_alice.hex" ] && [ -f "$PUB/share_AB_alice_1.hex" ] &&
   [ -f "$PUB/share_AC_alice.hex" ] && [ -f "$PUB/share_AC_alice_1.hex" ]; then
  echo '  seed-batch control accepted: four shares emitted'
  PASS=$((PASS+1))
else
  echo '  seed-batch control FAIL'
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
