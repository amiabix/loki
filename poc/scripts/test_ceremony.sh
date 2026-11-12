#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
bin="${LOKI_MEMBER_APP_BIN:-$PWD/target/debug/loki_member_app}"
frostd="${FROSTD_URL:-http://127.0.0.1:2744}"
tmp="$(mktemp -d)"
pids=()
cleanup() {
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  rm -rf "$tmp"
}
fail() {
  echo "FAIL: $1"
  if [[ -s "$tmp/last_curl" ]]; then echo "curl output: $(cat "$tmp/last_curl")"; fi
  for i in 1 2 3; do
    echo "member $i log:"
    tail -20 "$tmp/$i.log" 2>/dev/null || true
  done
  exit 1
}
trap cleanup EXIT

[[ -x "$bin" ]] || fail "missing $bin; build loki_member_app first"
command -v jq >/dev/null || fail "jq is required"
for i in 1 2 3; do
  port=$((3000+i))
  "$bin" --data "$tmp/$i" --port "$port" --frostd-url "$frostd" \
    --peer 1=http://127.0.0.1:3001 --peer 2=http://127.0.0.1:3002 \
    --peer 3=http://127.0.0.1:3003 >"$tmp/$i.log" 2>&1 &
  pids+=("$!")
done
for i in 1 2 3; do
  for _ in {1..100}; do
    token="$(sed -n 's|.*Signer: http://127.0.0.1:[0-9]*/#||p' "$tmp/$i.log" | head -1)"
    [[ -n "$token" ]] && break
    sleep 0.1
  done
  [[ -n "$token" ]] || fail "member $i did not start"
  printf '%s' "$token" >"$tmp/$i.token"
done
api() {
  local i="$1" method="$2" path="$3" body="${4:-}"
  local token output
  token="$(cat "$tmp/$i.token")"
  if [[ "$method" == POST ]]; then
    output="$(curl -sS -m 20 -X POST "http://127.0.0.1:$((3000+i))$path" \
      -H "X-Loki-Token: $token" -H 'Content-Type: application/json' -d "$body")" || return 1
  else
    output="$(curl -sS -m 20 "http://127.0.0.1:$((3000+i))$path" -H "X-Loki-Token: $token")" || return 1
  fi
  printf '%s' "$output" >"$tmp/last_curl"
  printf '%s' "$output"
}
for i in 1 2 3; do
  api "$i" POST /api/profile-create '{"name":"Member '"$i"'","passphrase":"ceremony test pass '"$i"'"}' | jq -e '.name == "Member '"$i"'"' >/dev/null || fail "profile $i"
done
created="$(api 1 POST /api/create '{"name":"Three member vault","members":3,"threshold":2}')" || fail create
vault="$(jq -er '.vault' <<<"$created")" || fail "create response"
for i in 2 3; do
  code="$(jq -er --argjson slot "$i" '.invites[] | select(.slot == $slot) | .code' <<<"$created")" || fail "invite $i"
  api "$i" POST /api/join "$(jq -nc --arg invite "$code" '{invite:$invite}')" | jq -e --arg vault "$vault" '.vault == $vault' >/dev/null || fail "join $i"
done
for i in 1 2 3; do
  ready=false
  for _ in {1..100}; do
    status="$(api "$i" GET "/api/status?vault=$vault")" || fail "status $i"
    if [[ "$(jq -r '.phase' <<<"$status")" == compare_roster ]]; then ready=true; break; fi
    sleep 0.1
  done
  [[ "$ready" == true ]] || fail "member $i did not reach compare_roster: $status"
done
for i in 1 2 3; do
  fingerprint="$(api "$i" GET "/api/status?vault=$vault" | jq -er '.fingerprint')" || fail "fingerprint $i"
  api "$i" POST /api/agree "$(jq -nc --arg vault "$vault" --arg fingerprint "$fingerprint" '{vault:$vault,fingerprint:$fingerprint}')" \
    | jq -e '.ok == true' >/dev/null || fail "agree $i"
done
for i in 1 2 3; do
  active=false
  for _ in {1..300}; do
    status="$(api "$i" GET "/api/status?vault=$vault")" || fail "status $i"
    if [[ "$(jq -r '.phase' <<<"$status")" == active ]]; then active=true; break; fi
    if [[ "$(jq -r '.error // empty' <<<"$status")" != "" ]]; then fail "DKG member $i: $status"; fi
    sleep 0.1
  done
  [[ "$active" == true ]] || fail "member $i did not reach active: $status"
  address="$(api "$i" GET "/api/address?vault=$vault" | jq -er '.address')" || fail "address $i"
  printf '%s' "$address" >"$tmp/$i.address"
  echo "member $i address: $address"
done
[[ "$(cat "$tmp/1.address")" == "$(cat "$tmp/2.address")" && "$(cat "$tmp/2.address")" == "$(cat "$tmp/3.address")" ]] \
  || fail "addresses differ"
echo "PASS: three members share one ACTIVE vault address"
