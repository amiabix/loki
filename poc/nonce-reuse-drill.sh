#!/usr/bin/env bash
# Does Loki's alpha-from-commitments derivation protect a signer whose nonce state is
# rolled back?
#
# Background. src/nonce_binding.rs (Phase A) showed that in bare FROST a co-signer who
# commits a second time moves the binding factor while a fixed nonce stays put, which is
# the precondition for recovering a signing share. Loki is not bare FROST: it derives the
# per-pair randomiser from the proposal AND the published commitment set, and every signer
# recomputes it rather than accepting one. So the naive attack is caught by the rk check.
#
# This drill asks the harder question: what if the attacker also rebuilds the candidate so
# that rk matches the new alpha? Then nothing is inconsistent any more, and the only thing
# left between the signer and a reused nonce is that it deleted the nonce file after using
# it. Which is exactly the state G3 showed a profile restore can roll back.
#
# Two stages, and the drill reports what each one shows:
#
#   A  naive: carol re-commits, candidate untouched          expected REFUSED
#   B  composed: rollback + re-commit + candidate rebuilt    expected REUSE
#
# Stage B producing reuse is NOT a bug in the signer. It is the measured boundary of what
# the rk check can do, and it says plainly that the prototype's safety here rests entirely
# on nonce deletion surviving, nothing else.
set -uo pipefail
cd "$(dirname "$0")"

S="${LOKI_STATE:-demo/.sandbox/state}"
L="${LOKI_BIN:-${CARGO_TARGET_DIR:-target}/debug/loki}"
LOKI_RPC=$(python3 ths.py address) || exit 1
export LOKI_RPC
SNAP=$(mktemp -d)
trap 'rm -rf "$SNAP"' EXIT

[ -x "$L" ] || { echo "no loki binary at $L; run: cargo build" >&2; exit 1; }
[ -d "$S/alice" ] || { echo "no account at $S; run setup/scan first" >&2; exit 1; }
"$L" scan "$S" >/dev/null 2>&1 || { echo "scan failed: is the node up on $LOKI_RPC?" >&2; exit 1; }

fresh() {                     # everyone commits, proposer builds, alice has no shares
  for m in alice bob carol; do "$L" commit "$S" "$m" >/dev/null 2>&1; done
  "$L" propose "$S" >/dev/null 2>&1
  rm -f "$S"/public/share_*_alice.hex
}

FAILS=0
echo "== stage A: carol re-commits, the candidate is left alone =="
fresh
"$L" tamper "$S" cosigner-recommit 2>&1 | sed 's/^/   /'
OUT=$("$L" review-sign "$S" alice 2>&1); RC=$?
printf '   alice: '
if [ $RC -ne 0 ] && [ ! -f "$S/public/share_AC_alice.hex" ]; then
  echo "REFUSED, no share  <- $(printf '%s' "$OUT" | grep -o 'REFUSED.*' | cut -c1-72)"
else
  echo "NOT REFUSED (rc=$RC) -- the rk check did not fire"; FAILS=$((FAILS+1))
fi

echo
echo "== stage B: rollback, re-commit, and rebuild the candidate to match =="
fresh
cp "$S/alice/nonces_AB.hex" "$S/alice/nonces_AC.hex" "$SNAP/"

"$L" review-sign "$S" alice >/dev/null 2>&1
[ -f "$S/public/share_AC_alice.hex" ] || { echo "   control failed: alice did not sign the honest candidate"; exit 1; }
cp "$S/public/share_AC_alice.hex" "$SNAP/share1"
echo "   1. alice signed honestly, nonce consumed"

# The rollback. A profile restore puts back what the device deleted.
cp "$SNAP/nonces_AB.hex" "$SNAP/nonces_AC.hex" "$S/alice/"
rm -f "$S"/public/share_*_alice.hex
echo "   2. nonce files restored, shares dropped: the device believes it never signed"

# The attacker moves the commitment set AND rebuilds the candidate, so rk is consistent
# again and the signer has nothing to object to.
"$L" commit "$S" carol >/dev/null 2>&1
"$L" propose "$S" >/dev/null 2>&1
echo "   3. carol re-committed; candidate rebuilt so rk matches the new alpha"

OUT=$("$L" review-sign "$S" alice 2>&1)
printf '   4. alice: '
if [ ! -f "$S/public/share_AC_alice.hex" ]; then
  echo "no second share"
else
  cp "$S/public/share_AC_alice.hex" "$SNAP/share2"
  if cmp -s "$SNAP/share1" "$SNAP/share2"; then
    echo "signed again, but the share is IDENTICAL -- nothing new leaked"
  else
    echo "signed again, and the share DIFFERS"
    echo
    echo "   share 1 $(cut -c1-40 "$SNAP/share1")..."
    echo "   share 2 $(cut -c1-40 "$SNAP/share2")..."
    echo "   same nonce, two different shares: the reuse precondition G3 turns into a"
    echo "   recovered key. The rk check cannot see this, because the attacker made the"
    echo "   candidate consistent with the commitment set it moved."
  fi
fi

echo
echo "== what this measures =="
echo "   A  the alpha-from-commitments derivation DOES catch a co-signer who re-commits"
echo "      while the candidate stays put. That is a real defence and it holds."
echo "   B  it does NOT survive a rollback paired with a rebuilt candidate. Nothing is"
echo "      inconsistent for the signer to notice, so the only thing protecting the nonce"
echo "      is that its file was deleted. That is local state, and G3 showed a profile"
echo "      restore puts it back."
echo
echo "   Conclusion: nonce safety here rests on deletion surviving, not on the rk check."
[ $FAILS -eq 0 ]
