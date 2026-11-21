#!/usr/bin/env bash
# Run one self-custody member against a public coordinator, from a packaged binary.
#
#   run-member.sh <coordinator-url> <slot>
#
# Self-registers to the coordinator (the browser-origin middleware only accepts the
# coordinator URL the member was launched with), then prints the local pairing link
# to open in a browser. The binary needs no Rust toolchain.
#
# Remote ceremony peers use a free cloudflared quick tunnel to the member's separate,
# ceremony-only loopback listener. Never tunnel the private member API on PORT.
#
# frostd must be reachable on loopback (https off loopback is enforced): forward the
# shared relay first, e.g.  ssh -N -L 2744:localhost:2744 omarchy
#
# Env:
#   MEMBER_BIN   path to loki_member_app  (default <repo>/core/target/release/loki_member_app)
#   DATA         member data dir          (default ./loki-member-<slot>)
#   PORT         local member port        (default 3610 + slot)
#   PEER_PORT    ceremony backend port    (default 4610 + slot)
#   FROSTD_URL   frostd loopback url       (default http://127.0.0.1:2744)
#   LWD_URL      lightwalletd base url     (default https://testnet.zec.rocks:443)
#   NETWORK      vault network             (default testnet)
#   ADVERTISE_URL  use your own TLS proxy to PEER_PORT (default: own cloudflared tunnel)
#   NO_TUNNEL=1    skip the per-member tunnel
set -euo pipefail

if [[ $# != 2 || $1 != http* || ! $2 =~ ^[0-9]+$ ]]; then
  echo 'usage: run-member.sh <coordinator-url> <slot>' >&2
  exit 2
fi
coordinator=${1%/}
slot=$2
deploy=$(cd "$(dirname "$0")" && pwd -P)
repo=$(cd "$deploy/../.." && pwd -P)

member_bin=${MEMBER_BIN:-$repo/core/target/release/loki_member_app}
data=${DATA:-$PWD/loki-member-$slot}
port=${PORT:-$((3610 + slot))}
peer_port=${PEER_PORT:-$((4610 + slot))}
frostd=${FROSTD_URL:-http://127.0.0.1:2744}
lwd=${LWD_URL:-https://testnet.zec.rocks:443}
network=${NETWORK:-testnet}
cloudflared=/opt/homebrew/bin/cloudflared

[[ -x $member_bin ]] || { echo "member binary not found: $member_bin (build with: cargo build --release --features relay-communication --bin loki_member_app)" >&2; exit 1; }
advertise=${ADVERTISE_URL:-}
if [[ -n $advertise || ${NO_TUNNEL:-} != 1 ]]; then
  if ! [[ $port =~ ^[0-9]{1,5}$ && $peer_port =~ ^[0-9]{1,5}$ ]] ||
     (( 10#$peer_port == 0 || 10#$peer_port > 65535 || 10#$peer_port == 10#$port )); then
    echo 'PEER_PORT must be a valid port distinct from the private PORT' >&2
    exit 2
  fi
fi
mkdir -p "$data"
: > "$data/pids"
cleanup() { while read -r pid; do kill -INT "$pid" 2>/dev/null || true; done < "$data/pids"; }
trap cleanup EXIT
trap 'exit 1' INT TERM

if [[ -z $advertise && ${NO_TUNNEL:-} != 1 ]]; then
  echo "== cloudflared quick tunnel -> 127.0.0.1:$peer_port (ceremony only) =="
  "$cloudflared" tunnel --url "http://127.0.0.1:$peer_port" >"$data/cloudflared.log" 2>&1 &
  echo $! >> "$data/pids"
  for _ in {1..80}; do
    advertise=$(grep -oE 'https://[a-z0-9-]+\.trycloudflare\.com' "$data/cloudflared.log" | head -1 || true)
    [[ -n $advertise ]] && break; sleep 0.5
  done
  [[ -n $advertise ]] || { echo "member tunnel never came up; see $data/cloudflared.log" >&2; exit 1; }
  echo "advertising peer url: $advertise"
fi

pass="$data/local.pass"
[[ -f $pass ]] || { openssl rand -hex 16 > "$pass"; chmod 600 "$pass"; }

echo "== member slot $slot on :$port -> $coordinator =="
"$member_bin" --data "$data/state" --port "$port" --network "$network" \
  --lightwalletd-url "$lwd" --frostd-url "$frostd" --secure-element software \
  --coordinator-url "$coordinator" --local-passphrase-file "$pass" \
  --registration-slot "$slot" --profile-name "Member $slot" \
  ${advertise:+--peer-port "$peer_port" --advertise-url "$advertise"} >"$data/member.log" 2>&1 &
echo $! >> "$data/pids"

token=""
for _ in {1..90}; do
  token=$(grep -oE "http://127.0.0.1:${port}/#[A-Za-z0-9_-]+" "$data/member.log" 2>/dev/null | tail -1 | sed 's#.*/##;s/^#//' || true)
  [[ -n $token ]] && break
  grep -q 'error:' "$data/member.log" && { echo "member failed:"; tail -4 "$data/member.log"; exit 1; }
  sleep 0.4
done
[[ -n $token ]] || { echo "member never started; see $data/member.log" >&2; exit 1; }

# The member serves locally even when the coordinator refuses or is unreachable; it keeps
# retrying registration and logs each failure to member.log.
curl -sf --max-time 10 "$coordinator/api/members" | grep -q "\"slot\": *$slot\|\"slot\":$slot" \
  || { echo "warning: slot $slot not yet visible in $coordinator/api/members; registration retries, see $data/member.log" >&2; }

echo "=============================================================="
echo "member slot $slot running; registering with $coordinator"
echo "open in a browser to pair this device:  http://127.0.0.1:$port/#$token"
echo "recovery words are never written to member.log; if this member has none yet, set them up"
echo "once (the reply shows them once):"
echo "  curl -s -X POST -H 'X-Loki-Token: $token' http://127.0.0.1:$port/api/recovery-setup"
echo "=============================================================="
trap - EXIT INT TERM
echo "member still running; stop with: kill \$(cat $data/pids)"
