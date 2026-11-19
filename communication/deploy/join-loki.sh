#!/usr/bin/env bash
# One command to join a Loki vault against a public coordinator.
#
#   join-loki.sh <coordinator-url> [slot]
#
# Builds the member binary if missing, ensures frostd is reachable on loopback,
# auto-picks the next free roster slot if none is given, then launches a member
# via run-member.sh and prints the local pairing link to paste into the
# coordinator web UI. Peer-over-frostd is on main, so members need zero inbound
# (NO_TUNNEL=1) — no per-member tunnel.
#
# Env:
#   FROSTD_URL   frostd loopback url     (default http://127.0.0.1:2744)
#   FROSTD_HOST  ssh host for the tunnel (default omarchy)
# Plus anything run-member.sh honours (DATA, PORT, LWD_URL, NETWORK, MEMBER_BIN).
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 || $1 != http* ]]; then
  echo 'usage: join-loki.sh <coordinator-url> [slot]' >&2
  exit 2
fi
coordinator=${1%/}
slot=${2:-}
[[ -z $slot || $slot =~ ^[0-9]+$ ]] || { echo "slot must be a number" >&2; exit 2; }

deploy=$(cd "$(dirname "$0")" && pwd -P)
repo=$(cd "$deploy/../.." && pwd -P)
member_bin=${MEMBER_BIN:-$repo/core/target/release/loki_member_app}
frostd=${FROSTD_URL:-http://127.0.0.1:2744}
frostd_host=${FROSTD_HOST:-omarchy}

# 1. Build the member binary on first run.
if [[ ! -x $member_bin && -z ${MEMBER_BIN:-} ]]; then
  echo "== building loki_member_app (first run, a few minutes) =="
  ( cd "$repo/core" && cargo build --release --features relay-communication --bin loki_member_app )
fi
[[ -x $member_bin ]] || { echo "member binary not found: $member_bin" >&2; exit 1; }

# 2. frostd must be reachable on loopback (https off loopback is enforced).
reachable() { curl -s -o /dev/null --max-time 3 "$frostd/challenge"; }
if reachable; then
  echo "frostd reachable at $frostd"
else
  echo "opening ssh tunnel to $frostd_host"
  ssh -f -N -L 2744:localhost:2744 "$frostd_host" || true
  reachable || { echo "frostd unreachable at $frostd (forward it: ssh -N -L 2744:localhost:2744 $frostd_host)" >&2; exit 1; }
  echo "frostd reachable via tunnel"
fi

# 3. Auto-pick the next free slot (1..16) from the coordinator roster.
if [[ -z $slot ]]; then
  taken=$(curl -sf --max-time 10 "$coordinator/api/members" | grep -oE '"slot":[0-9]+' | grep -oE '[0-9]+' || true)
  for n in $(seq 1 16); do
    grep -qx "$n" <<<"$taken" || { slot=$n; break; }
  done
  [[ -n $slot ]] || { echo "no free slot (1..16) on $coordinator" >&2; exit 1; }
  echo "auto-picked free slot $slot"
fi

# 4. Launch via run-member.sh (no per-member tunnel; peer-over-frostd is on main).
echo "== joining $coordinator as slot $slot =="
NO_TUNNEL=1 MEMBER_BIN="$member_bin" FROSTD_URL="$frostd" exec "$deploy/run-member.sh" "$coordinator" "$slot"
