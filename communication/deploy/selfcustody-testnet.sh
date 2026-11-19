#!/usr/bin/env bash
# Single-host self-custody bringup for the v2 (frostd) stack on main.
#
# Stands up the public-roster web coordinator plus N member apps that self-register,
# then drives a t-of-n DKG ceremony to `active` and prints the shared testnet address.
# Each member holds its own share; the coordinator only ever sees public roster data.
#
# This is NOT the owned-relay operator toolkit (bringup.sh) — main's ceremony speaks
# frostd, not the owned relays. Point FROSTD_URL at a reachable frostd. frostd must be
# https off loopback (transport::require_tls_off_loopback); for a remote plaintext dev
# relay, forward it to loopback first, e.g. `ssh -N -L 2744:localhost:2744 host` and use
# the default http://127.0.0.1:2744.
#
# Env:
#   FROSTD_URL   frostd base url           (default http://127.0.0.1:2744)
#   LWD_URL      lightwalletd base url     (default https://testnet.zec.rocks:443)
#   NETWORK      vault network             (default testnet)
#   MEMBERS      member count n            (default 3)
#   THRESHOLD    approvals t               (default 2)
#   WEB_PORT     coordinator port          (default 3001)
#   BASE_PORT    first member port         (default 3601)
set -euo pipefail

if [[ $# != 1 || $1 != /* || -e $1 ]]; then
  echo 'usage: selfcustody-testnet.sh /absolute/new/root' >&2
  exit 2
fi
root=$1
deploy=$(cd "$(dirname "$0")" && pwd -P)
workspace=$(cd "$deploy/.." && pwd -P)
repo=$(cd "$workspace/.." && pwd -P)
poc="$repo/core"
web="$repo/web/wallet"

frostd=${FROSTD_URL:-http://127.0.0.1:2744}
lwd=${LWD_URL:-https://testnet.zec.rocks:443}
network=${NETWORK:-testnet}
members=${MEMBERS:-3}
threshold=${THRESHOLD:-2}
web_port=${WEB_PORT:-3001}
base_port=${BASE_PORT:-3601}
coordinator="http://localhost:$web_port"

mkdir -p "$root"
: > "$root/pids"

cleanup() { while read -r pid; do kill -INT "$pid" 2>/dev/null || true; done < "$root/pids"; }
trap cleanup EXIT
trap 'exit 1' INT TERM

echo "== build =="
( cd "$core" && cargo build --release --locked --features relay-communication --bin loki_member_app )
member_bin="$core/target/release/loki_member_app"
( cd "$web" && npm run build >/dev/null )

echo "== coordinator on :$web_port =="
( cd "$web" && PORT="$web_port" LOKI_REGISTRY="$root/registry.json" node server.js >"$root/coordinator.log" 2>&1 ) &
echo $! >> "$root/pids"
for _ in {1..50}; do curl -sf --max-time 1 "$coordinator/api/members" >/dev/null && break; sleep 0.2; done
curl -sf --max-time 2 "$coordinator/api/members" >/dev/null || { echo "coordinator did not start; see $root/coordinator.log" >&2; exit 1; }

echo "== $members members self-registering =="
declare -a tokens ports
for n in $(seq 1 "$members"); do
  port=$((base_port + n - 1))
  ports[n]=$port
  pass="$root/member-$n.pass"
  openssl rand -hex 16 > "$pass"; chmod 600 "$pass"
  "$member_bin" --data "$root/member-$n" --port "$port" --network "$network" \
    --lightwalletd-url "$lwd" --frostd-url "$frostd" \
    --allow-loopback-peers --secure-element software --development-http \
    --coordinator-url "$coordinator" --local-passphrase-file "$pass" \
    --registration-slot "$n" --profile-name "Member $n" >"$root/member-$n.log" 2>&1 &
  echo $! >> "$root/pids"
done

# Wait for each member to self-register and emit its local process token.
for n in $(seq 1 "$members"); do
  for _ in {1..75}; do
    # Tolerate no-match: the member has not written its pairing line yet (set -e + pipefail).
    token=$(grep -oE "http://127.0.0.1:${ports[n]}/#[A-Za-z0-9_-]+" "$root/member-$n.log" 2>/dev/null | tail -1 | sed 's#.*/##;s/^#//' || true)
    [[ -n $token ]] && break
    grep -q 'error:' "$root/member-$n.log" && { echo "member $n failed:"; tail -3 "$root/member-$n.log"; exit 1; }
    sleep 0.4
  done
  [[ -n $token ]] || { echo "member $n never registered; see $root/member-$n.log" >&2; exit 1; }
  tokens[n]=$token
done
registered=$(curl -s "$coordinator/api/members" | python3 -c 'import sys,json;print(len(json.load(sys.stdin)["slots"]))')
[[ $registered == "$members" ]] || { echo "roster has $registered of $members members" >&2; exit 1; }
echo "roster: $registered/$members members self-registered"

api() { # api <port> <token> <method> <path> [json-body]
  local port=$1 token=$2 method=$3 path=$4 body=${5:-}
  if [[ -n $body ]]; then
    curl -s --max-time 30 -X "$method" -H "x-loki-token: $token" -H 'content-type: application/json' -d "$body" "http://127.0.0.1:$port$path"
  else
    curl -s --max-time 30 -H "x-loki-token: $token" "http://127.0.0.1:$port$path"
  fi
}
jq_py() { python3 -c "import sys,json;d=json.load(sys.stdin);print($1)"; }

echo "== ceremony: $threshold-of-$members DKG =="
create=$(api "${ports[1]}" "${tokens[1]}" POST /api/create "{\"name\":\"TestnetVault\",\"members\":$members,\"threshold\":$threshold}")
vault=$(echo "$create" | jq_py 'd["vault"]')
[[ ${#vault} == 64 ]] || { echo "create failed: $create" >&2; exit 1; }
echo "vault: $vault"
for n in $(seq 2 "$members"); do
  code=$(echo "$create" | python3 -c "import sys,json;print([i for i in json.load(sys.stdin)['invites'] if i['slot']==$n][0]['code'])")
  join=$(api "${ports[n]}" "${tokens[n]}" POST /api/join "{\"invite\":\"$code\"}")
  echo "$join" | grep -q "$vault" || { echo "member $n join failed: $join" >&2; exit 1; }
done

fp=""
for _ in {1..20}; do
  fp=$(api "${ports[1]}" "${tokens[1]}" GET "/api/status?vault=$vault" | jq_py 'd.get("fingerprint") or ""')
  [[ -n $fp ]] && break; sleep 2
done
[[ -n $fp ]] || { echo "roster never converged" >&2; exit 1; }
echo "roster fingerprint: $fp"
for n in $(seq 1 "$members"); do
  ok=$(api "${ports[n]}" "${tokens[n]}" POST /api/agree "{\"vault\":\"$vault\",\"fingerprint\":\"$fp\"}" | jq_py 'd.get("ok")')
  [[ $ok == True ]] || { echo "member $n agree failed" >&2; exit 1; }
done

phase=""
for _ in {1..30}; do
  status=$(api "${ports[1]}" "${tokens[1]}" GET "/api/status?vault=$vault")
  phase=$(echo "$status" | jq_py 'd.get("phase")')
  echo "  phase: $phase"
  [[ $phase == active ]] && break
  [[ $phase == setup_interrupted ]] && { echo "DKG interrupted: $(echo "$status" | jq_py 'd.get("error")')" >&2; exit 1; }
  sleep 4
done
[[ $phase == active ]] || { echo "ceremony did not reach active" >&2; exit 1; }

address=$(api "${ports[1]}" "${tokens[1]}" GET "/api/address?vault=$vault" | jq_py 'd["address"]')
echo "=============================================================="
echo "vault $vault is ACTIVE ($threshold-of-$members, $network)"
echo "address: $address"
echo "coordinator: $coordinator   members: ${ports[*]}"
echo "=============================================================="
trap - EXIT INT TERM
echo "stack still running; stop with: kill \$(cat $root/pids)"
