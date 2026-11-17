#!/usr/bin/env bash
# Testnet end to end: an open payment request signed by the first approvers and broadcast.
#
# By default this starts three members and creates a new 2-of-3 vault. With VAULT and
# TOKEN_DIR it reuses three running members on BASE_PORT+1..3 that are already in that
# active vault; TOKEN_DIR holds each member's API token as <i>.token.
set -euo pipefail

cd "$(dirname "$0")/.."
: "${AMOUNT_ZAT:?set AMOUNT_ZAT to the amount in zat}"

bin="${LOKI_MEMBER_APP_BIN:-$PWD/target/debug/loki_member_app}"
frostd="${FROSTD_URL:-http://127.0.0.1:2744}"
base_port="${BASE_PORT:-3300}"
funding_timeout="${FUNDING_TIMEOUT:-3600}"
vault="${VAULT:-}"
if [[ -n "$vault" ]]; then
  : "${TOKEN_DIR:?set TOKEN_DIR to the directory with the <i>.token file of each running member}"
  tmp="$TOKEN_DIR"
else
  : "${LIGHTWALLETD_URL:?set LIGHTWALLETD_URL to a Testnet lightwalletd endpoint}"
  tmp="$(mktemp -d)"
fi
pids=()
cleanup() {
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  wait 2>/dev/null || true
  [[ -n "${VAULT:-}" ]] || echo "member data preserved: $tmp"
}
trap cleanup EXIT
fail() {
  echo "FAIL: $1" >&2
  for i in 1 2 3; do tail -20 "$tmp/$i.log" 2>/dev/null || true; done
  exit 1
}
command -v jq >/dev/null || fail 'jq is required'
api() {
  local i="$1" method="$2" path="$3" body="${4:-}" token
  token="$(cat "$tmp/$i.token")"
  if [[ "$method" == POST ]]; then
    curl --fail-with-body -sS -m 600 -X POST "http://127.0.0.1:$((base_port+i))$path" \
      -H "X-Loki-Token: $token" -H 'Content-Type: application/json' -d "$body"
  else
    curl --fail-with-body -sS -m 600 "http://127.0.0.1:$((base_port+i))$path" -H "X-Loki-Token: $token"
  fi
}
passphrase() { printf 'testnet payment member %s' "$1"; }
pair() { jq -nc --arg vault "$vault" --arg attempt "$1" '{vault:$vault,attempt:$attempt}'; }

if [[ -n "$vault" ]]; then
  for i in 1 2 3; do
    if [[ "$(api "$i" GET /api/status | jq -r '.phase')" == locked ]]; then
      api "$i" POST /api/unlock "$(jq -nc --arg passphrase "$(passphrase "$i")" '{passphrase:$passphrase}')" | jq -e '.unlocked' >/dev/null || fail "unlock $i"
    fi
    api "$i" GET "/api/status?vault=$vault" | jq -e '.phase == "active"' >/dev/null || fail "member $i is not active in vault $vault"
  done
else
[[ -x "$bin" ]] || fail "missing $bin; build loki_member_app first"
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
for i in 1 2 3; do
  api "$i" POST /api/profile-create "$(jq -nc --arg name "Member $i" --arg passphrase "$(passphrase "$i")" '{name:$name,passphrase:$passphrase}')" | jq -e '.name' >/dev/null || fail "profile $i"
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
echo "Back up all three member directories before funding: $tmp"
fi
address="$(api 1 GET "/api/address?vault=$vault" | jq -er '.address')" || fail address
# Without RECIPIENT the vault pays itself, so the test spends nothing but fees.
recipient="${RECIPIENT:-$address}"
echo "vault $vault"
echo "Fund this vault with an Ironwood note worth more than amount plus fee: $address"
ready=false
for ((n=0; n<funding_timeout; n+=30)); do
  balance="$(api 1 POST /api/balance "$(jq -nc --arg vault "$vault" '{vault:$vault}')")" || fail "balance: $balance"
  if (( $(jq -r '.balance_zat // 0' <<<"$balance") > AMOUNT_ZAT + 100000 )); then ready=true; break; fi
  sleep 30
done
[[ "$ready" == true ]] || fail "funding not scanned within $funding_timeout seconds"
echo "balance: $(jq -r '.balance_zat' <<<"$balance") zat"

draft() {
  api 1 POST /api/payment-draft "$(jq -nc --arg vault "$vault" --arg recipient "$recipient" --arg amount_zat "$AMOUNT_ZAT" --arg memo "$1" '{vault:$vault,recipient:$recipient,amount_zat:$amount_zat,memo:$memo}')"
}
# A received note becomes spendable only after enough confirmations; retry until it is.
draft_when_spendable() {
  local out=''
  for ((n=0; n<funding_timeout; n+=30)); do
    out="$(draft "$1")" && { echo "$out"; return; }
    echo "no spendable note yet: $out" >&2
    sleep 30
  done
  fail "draft: $out"
}
publish() {
  api 1 POST /api/payment-publish "$(pair "$1")" | jq -e '.phase == "signing"' >/dev/null || fail "publish $1"
}
approve() {
  local i="$1" attempt="$2" review token
  review="$(api "$i" POST /api/payment-review "$(pair "$attempt")")" || fail "review $i: $review"
  jq -e --arg recipient "$recipient" --arg amount "$AMOUNT_ZAT" '.recipient == $recipient and .amount_zat == $amount' <<<"$review" >/dev/null || fail "review values $i"
  token="$(jq -er '.review_token' <<<"$review")"
  api "$i" POST /api/payment-approve "$(jq -nc --arg vault "$vault" --arg attempt "$attempt" --arg review_token "$token" '{vault:$vault,attempt:$attempt,review_token:$review_token}')" | jq -e '.phase == "signing"' >/dev/null || fail "approve $i"
  echo "member $i approved"
}
phase() { api "$1" GET "/api/payment-status?vault=$vault&attempt=$2" | jq -r '.phase'; }
has_phase() { [[ "$(phase "$1" "$2")" == "$3" ]]; }
pending() { api "$1" GET "/api/pending?vault=$vault" | jq -e --arg attempt "$2" 'any(.pending[]; .attempt == $attempt)' >/dev/null; }
# The proposer's view; listing also drains its control messages.
proposer_has() { api 1 GET "/api/payments?vault=$vault" | jq -e --arg attempt "$1" "any(.payments[]; .attempt == \$attempt and ($2))" >/dev/null; }
wait_for() {
  local what="$1" tries="$2"
  shift 2
  for ((n=0; n<tries; n++)); do "$@" && return; sleep 1; done
  fail "$what"
}
phases() { for i in 1 2 3; do echo "  member $i: $(phase "$i" "$1")"; done; }

echo "== open request: any member may approve; member 3 approves before member 2"
attempt="$(draft_when_spendable "${MEMO:-testnet payment}" | jq -er '.attempt')"
echo "attempt $attempt"
publish "$attempt"
for i in 2 3; do wait_for "member $i sees the request" 60 pending "$i" "$attempt"; done
phases "$attempt"
approve 3 "$attempt"
wait_for 'proposer records member 3' 60 proposer_has "$attempt" '.approvals == [3]'
approve 2 "$attempt"
wait_for 'proposer records member 2' 60 proposer_has "$attempt" '.approvals == [3,2]'
approve 1 "$attempt"
wait_for 'signing group [1,3]' 60 proposer_has "$attempt" '.signers == [1,3]'
wait_for 'member 2 is not selected' 300 has_phase 2 "$attempt" not_selected
! pending 2 "$attempt" || fail 'member 2 still lists the request'
echo "signing group [1,3]; member 2 not_selected and off its pending list"
wait_for 'signers did not finish' 600 proposer_has "$attempt" '.ready_to_send'
phases "$attempt"
finished="$(api 1 POST /api/payment-finish "$(pair "$attempt")")" || fail "finish: $finished"
txid="$(jq -er '.txid' <<<"$finished")" || fail txid
echo "broadcast txid: $txid"
verified="$(api 1 POST /api/payment-verify "$(jq -nc --arg vault "$vault" --arg attempt "$attempt" --arg txid "$txid" '{vault:$vault,attempt:$attempt,txid:$txid}')")" || fail "verify: $verified"
jq -e '.phase == "broadcast" or .phase == "confirmed"' <<<"$verified" >/dev/null || fail "verify result: $verified"
for i in 2 3; do wait_for "member $i hears the broadcast" 60 has_phase "$i" "$attempt" broadcast; done
phases "$attempt"
echo "PASS: Testnet payment $txid broadcast ($(jq -r '.phase' <<<"$verified"))"
