#!/usr/bin/env bash
# Measure fixed-session refusal and nonce reuse after a deliberately consistent rebuild.
# Saved seeds do not prevent a profile restore from reviving consumed nonce secrets.
# --setup creates and funds a fresh disposable vault on the already running THS instance.
set -euo pipefail
unset LOKI_ROUND
cd "$(dirname "$0")"
WORK_ROOT=$(mktemp -d "${TMPDIR:-/tmp}/loki-issue3-rollback.XXXXXX")
L="${LOKI_BIN:-${CARGO_TARGET_DIR:-target}/debug/loki}"
export LOKI_THS_INSTANCE="${LOKI_THS_INSTANCE:-loki}"
LOKI_RPC=$(python3 ths.py address)
export LOKI_RPC
[ -x "$L" ] || { echo "no loki binary at $L; run cargo build" >&2; exit 1; }
if [ "${1:-}" = --setup ] && [ "$#" -eq 1 ]; then
  S="${LOKI_STATE:-$WORK_ROOT/state}"
  if [ -e "$S" ] || [ -L "$S" ]; then
    echo "refusing existing state path: $S" >&2; exit 1
  fi
  "$L" setup "$S" >/dev/null
  VAULT=$("$L" address "$S")
  python3 ths.py fund "$VAULT" 2
elif [ "$#" -eq 0 ]; then
  S="${LOKI_STATE:?supply disposable funded LOKI_STATE or use --setup}"
  [ -d "$S/alice" ] || { echo 'no account; use --setup with a fresh state path' >&2; exit 1; }
else
  echo 'usage: nonce-reuse-drill.sh [--setup]' >&2; exit 1
fi
"$L" scan "$S" >/dev/null || { echo "scan failed at THS endpoint $LOKI_RPC" >&2; exit 1; }
echo "   artifacts $WORK_ROOT; state $S"

fresh() {
  export LOKI_ROUND="rollback_${1}_$(basename "$WORK_ROOT" | cut -d. -f2)"
  PUB="$S/public_$LOKI_ROUND"
  for m in alice bob carol; do "$L" commit "$S" "$m" >/dev/null; done
  "$L" propose "$S" funded_note.txt >/dev/null
}
snapshot() {
  local dest=$1
  mkdir -p "$dest/nonces"
  cp -R "$PUB" "$dest/public"
  for member in alice bob carol; do
    mkdir -p "$dest/nonces/$member"
    cp "$S/$member"/nonces_*.hex "$dest/nonces/$member/"
  done
  for pair in AB AC BC; do
    [ -s "$dest/public/randomizer_seed_$pair.hex" ]
    [ -s "$dest/public/candidate_$pair.pczt.hex" ]
  done
}
zero_shares() { [ -z "$(find "$PUB" -name 'share_*.hex' -print)" ]; }

FAILS=0
echo '== stage A: changed commitments against a fixed saved candidate =='
fresh a
snapshot "$WORK_ROOT/stage_a"
"$L" tamper "$S" cosigner-recommit | sed 's/^/   /'
OUT=$("$L" review-sign "$S" alice 2>&1) && RC=0 || RC=$?
if [ "$RC" -ne 0 ] && zero_shares && printf '%s' "$OUT" | grep -qF 'randomizer seed commitments mismatch'; then
  cmp "$WORK_ROOT/stage_a/nonces/alice/nonces_AB.hex" "$S/alice/nonces_AB.hex"
  cmp "$WORK_ROOT/stage_a/nonces/alice/nonces_AC.hex" "$S/alice/nonces_AC.hex"
  for pair in AB AC BC; do
    cmp "$WORK_ROOT/stage_a/public/candidate_$pair.pczt.hex" "$PUB/candidate_$pair.pczt.hex"
    cmp "$WORK_ROOT/stage_a/public/randomizer_seed_$pair.hex" "$PUB/randomizer_seed_$pair.hex"
  done
  echo '   REFUSED: randomizer seed commitments mismatch; zero shares and unchanged Alice nonces'
else
  echo "   FAIL: fixed session was not refused with zero shares (rc=$RC)"
  printf '%s\n' "$OUT" | tail -3
  FAILS=$((FAILS+1))
fi

echo
echo '== stage B: consumed nonce restore, new commitments and adversarial session rebuild =='
fresh b
snapshot "$WORK_ROOT/stage_b"
"$L" review-sign "$S" alice >/dev/null
[ -f "$PUB/share_AB_alice.hex" ] && [ -f "$PUB/share_AC_alice.hex" ] || {
  echo 'control failed: Alice did not sign both honest candidates'; exit 1;
}
[ ! -e "$S/alice/nonces_AB.hex" ] && [ ! -e "$S/alice/nonces_AC.hex" ] || {
  echo 'control failed: honest signing did not consume Alice nonces'; exit 1;
}
cp "$PUB/share_AC_alice.hex" "$WORK_ROOT/share1.hex"
echo '   1. Alice signed honestly and consumed both nonce files'

# Restore the exact saved session and consumed nonce bytes, as a profile rollback would.
rm -rf "$PUB"
cp -R "$WORK_ROOT/stage_b/public" "$PUB"
cp "$WORK_ROOT/stage_b/nonces/alice"/nonces_*.hex "$S/alice/"
cmp "$WORK_ROOT/stage_b/nonces/alice/nonces_AC.hex" "$S/alice/nonces_AC.hex"
echo '   2. saved seeds/candidates/commitments and used Alice nonce files restored'

"$L" commit "$S" carol >/dev/null
"$L" tamper "$S" rebuild-session >/dev/null
cmp -s "$WORK_ROOT/stage_b/public/commitment_AC_carol.hex" "$PUB/commitment_AC_carol.hex" && {
  echo 'FAIL: Carol commitment did not change'; exit 1;
}
cmp -s "$WORK_ROOT/stage_b/public/candidate_AC.pczt.hex" "$PUB/candidate_AC.pczt.hex" && {
  echo 'FAIL: adversarial candidate did not change'; exit 1;
}
cmp "$WORK_ROOT/stage_b/nonces/alice/nonces_AC.hex" "$S/alice/nonces_AC.hex"
echo '   3. Carol re-committed; tamper-only rebuild made the seed association and candidate consistent'

OUT=$("$L" review-sign "$S" alice 2>&1) && RC=0 || RC=$?
if [ "$RC" -eq 0 ] && [ -s "$PUB/share_AC_alice.hex" ] &&
   ! cmp -s "$WORK_ROOT/share1.hex" "$PUB/share_AC_alice.hex"; then
  cp "$PUB/share_AC_alice.hex" "$WORK_ROOT/share2.hex"
  echo '   4. Alice signed again: identical restored nonce, different signature share'
else
  echo "   FAIL: stage B did not reproduce changed-share nonce reuse (rc=$RC)"
  printf '%s\n' "$OUT" | tail -3
  FAILS=$((FAILS+1))
fi

echo
echo 'A measures fixed-session refusal. B measures the existing profile-rollback boundary.'
echo 'Persisted randomizer seeds do not make consumed-nonce deletion rollback-resistant.'
[ "$FAILS" -eq 0 ]
