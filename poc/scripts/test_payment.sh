#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
: "${LIGHTWALLETD_URL:?set LIGHTWALLETD_URL to a Testnet lightwalletd endpoint}"
: "${RECIPIENT:?set RECIPIENT to a Testnet unified address with an Orchard receiver}"
: "${AMOUNT_ZAT:?set AMOUNT_ZAT to the amount in zat}"

bin="${LOKI_MEMBER_APP_BIN:-$PWD/target/debug/loki_member_app}"
frostd="${FROSTD_URL:-http://127.0.0.1:2744}"
base_port="${BASE_PORT:-3300}"
funding_timeout="${FUNDING_TIMEOUT:-3600}"
tmp="$(mktemp -d)"
pids=()
cleanup() {
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  echo "member data preserved: $tmp"
}
trap cleanup EXIT
fail() {
  echo "FAIL: $1" >&2
  for i in 1 2 3; do tail -20 "$tmp/$i.log" 2>/dev/null || true; done
  exit 1
}
[[ -x "$bin" ]] || fail "missing $bin; build loki_member_app first"
command -v jq >/dev/null || fail 'jq is required'
for i in 1 2 3; do
  port=$((base_port+i))
  "$bin" --data "$tmp/$i" --port "$port" --network testnet \
    --lightwalletd-url "$LIGHTWALLETD_URL" --frostd-url "$frostd" \
    --peer "1=http://127.0.0.1:$((base_port+1))" \
    --peer "2=http://127.0.0.1:$((base_port+2))" \
    --peer "3=http://127.0.0.1:$((base_port+3))" >"$tmp/$i.log" 2>&1 &
  pids+=("$!")
done
for i in 1 2 3; do
  token=''
  for _ in {1..100}; do
    token="$(sed -n 's|.*Signer: http://127.0.0.1:[0-9]*/#||p' "$tmp/$i.log" | head -1)"
    [[ -n "$token" ]] && break
    sleep 0.1
  done
  [[ -n "$token" ]] || fail "member $i did not start"
  printf '%s' "$token" >"$tmp/$i.token"
done
api() {
  local i="$1" method="$2" path="$3" body="${4:-}" token
  token="$(cat "$tmp/$i.token")"
  if [[ "$method" == POST ]]; then
    curl -fsS -m 600 -X POST "http://127.0.0.1:$((base_port+i))$path" \
      -H "X-Loki-Token: $token" -H 'Content-Type: application/json' -d "$body"
  else
    curl -fsS -m 600 "http://127.0.0.1:$((base_port+i))$path" -H "X-Loki-Token: $token"
  fi
}
for i in 1 2 3; do
  api "$i" POST /api/profile-create "$(jq -nc --arg name "Member $i" --arg passphrase "testnet payment member $i" '{name:$name,passphrase:$passphrase}')" | jq -e '.name' >/dev/null || fail "profile $i"
done
created="$(api 1 POST /api/create '{"name":"Testnet payment vault","members":3,"threshold":2}')" || fail create
vault="$(jq -er '.vault' <<<"$created")" || fail vault
for i in 2 3; do
  code="$(jq -er --argjson slot "$i" '.invites[] | select(.slot == $slot) | .code' <<<"$created")" || fail "invite $i"
  api "$i" POST /api/join "$(jq -nc --arg invite "$code" '{invite:$invite}')" | jq -e --arg vault "$vault" '.vault == $vault' >/dev/null || fail "join $i"
done
for i in 1 2 3; do
  ready=false
  for _ in {1..100}; do
    status="$(api "$i" GET "/api/status?vault=$vault")"
    [[ "$(jq -r '.phase' <<<"$status")" == compare_roster ]] && { ready=true; break; }
    sleep 0.1
  done
  [[ "$ready" == true ]] || fail "roster $i: $status"
done
for i in 1 2 3; do
  fingerprint="$(api "$i" GET "/api/status?vault=$vault" | jq -er '.fingerprint')" || fail "fingerprint $i"
  api "$i" POST /api/agree "$(jq -nc --arg vault "$vault" --arg fingerprint "$fingerprint" '{vault:$vault,fingerprint:$fingerprint}')" | jq -e '.ok == true' >/dev/null || fail "agree $i"
done
for i in 1 2 3; do
  active=false
  for _ in {1..300}; do
    status="$(api "$i" GET "/api/status?vault=$vault")"
    [[ "$(jq -r '.phase' <<<"$status")" == active ]] && { active=true; break; }
    [[ "$(jq -r '.error // empty' <<<"$status")" == '' ]] || fail "DKG member $i: $status"
    sleep 0.1
  done
  [[ "$active" == true ]] || fail "DKG member $i: $status"
done
address="$(api 1 GET "/api/address?vault=$vault" | jq -er '.address')" || fail address
echo "Back up all three member directories before funding: $tmp"
echo "Fund this vault with one Ironwood note worth more than amount plus fee: $address"
ready=false
for ((n=0; n<funding_timeout; n+=15)); do
  balance="$(api 1 POST /api/balance "$(jq -nc --arg vault "$vault" '{vault:$vault}')")" || fail balance
  if (( $(jq -r '.balance_zat // 0' <<<"$balance") > AMOUNT_ZAT + 100000 )); then ready=true; break; fi
  sleep 15
done
[[ "$ready" == true ]] || fail "funding not scanned within $funding_timeout seconds"
draft="$(api 1 POST /api/payment-draft "$(jq -nc --arg vault "$vault" --arg recipient "$RECIPIENT" --arg amount_zat "$AMOUNT_ZAT" --arg memo "${MEMO:-testnet payment}" '{vault:$vault,recipient:$recipient,amount_zat:$amount_zat,memo:$memo}')")" || fail draft
attempt="$(jq -er '.attempt' <<<"$draft")" || fail 'draft attempt'
api 1 POST /api/payment-publish "$(jq -nc --arg vault "$vault" --arg attempt "$attempt" '{vault:$vault,attempt:$attempt}')" | jq -e '.phase == "signing"' >/dev/null || fail publish
for i in 1 2; do
  review="$(api "$i" POST /api/payment-review "$(jq -nc --arg vault "$vault" --arg attempt "$attempt" '{vault:$vault,attempt:$attempt}')")" || fail "review $i"
  jq -e --arg recipient "$RECIPIENT" --arg amount "$AMOUNT_ZAT" '.recipient == $recipient and .amount_zat == $amount' <<<"$review" >/dev/null || fail "review values $i"
  token="$(jq -er '.review_token' <<<"$review")"
  api "$i" POST /api/payment-approve "$(jq -nc --arg vault "$vault" --arg attempt "$attempt" --arg review_token "$token" '{vault:$vault,attempt:$attempt,review_token:$review_token}')" | jq -e '.phase == "signing"' >/dev/null || fail "approve $i"
done
ready=false
for _ in {1..40}; do
  listed="$(api 1 GET "/api/payments?vault=$vault")" || fail payments
  jq -e --arg attempt "$attempt" 'any(.payments[]; .attempt == $attempt and .ready_to_send)' <<<"$listed" >/dev/null && { ready=true; break; }
  sleep 1
done
[[ "$ready" == true ]] || fail 'signers did not start'
finished="$(api 1 POST /api/payment-finish "$(jq -nc --arg vault "$vault" --arg attempt "$attempt" '{vault:$vault,attempt:$attempt}')")" || fail finish
txid="$(jq -er '.txid' <<<"$finished")" || fail txid
echo "broadcast txid: $txid"
verified="$(api 1 POST /api/payment-verify "$(jq -nc --arg vault "$vault" --arg attempt "$attempt" --arg txid "$txid" '{vault:$vault,attempt:$attempt,txid:$txid}')")" || fail verify
jq -e '.phase == "broadcast" or .phase == "confirmed"' <<<"$verified" >/dev/null || fail "verify result: $verified"
echo "PASS: Testnet payment broadcast; current phase $(jq -r '.phase' <<<"$verified")"
