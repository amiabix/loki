#!/usr/bin/env bash
set -euo pipefail
umask 077

ROOT="$HOME/loki-frostd"
BIN="$ROOT/core/target/release/loki_member_app"
WEB="$ROOT/web/wallet"
DATA="$HOME/loki-demo-data"
FROSTD=http://127.0.0.1:2744
LWD=http://127.0.0.1:9067
THS=http://127.0.0.1:32805
RPC=http://127.0.0.1:18232
N=10 BASE=3600 THRESHOLD=2
PUBLIC="${PUBLIC_URL:?set PUBLIC_URL to the HTTPS address of the web wallet}"
[[ "$PUBLIC" == https://* ]] || { echo "PUBLIC_URL must use HTTPS" >&2; exit 1; }
[[ ! -e "$DATA" ]] || { echo "refusing to replace existing vault data: $DATA" >&2; exit 1; }
[[ -x "$BIN" ]] || { echo "missing member app binary: $BIN" >&2; exit 1; }

declare -a TOK SLUG

mine() { curl -s -u unused:unused -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"generate\",\"params\":[$1]}" "$RPC" >/dev/null 2>&1; }

api() {
  local i=$1 m=$2 p=$3 b=${4:-} port=$((BASE+$1))
  if [ "$m" = POST ]; then
    curl -fsS -m 300 -X POST "http://127.0.0.1:$port$p" \
      -H "X-Loki-Token: ${TOK[$i]}" -H 'Content-Type: application/json' -d "$b"
  else
    curl -fsS -m 300 "http://127.0.0.1:$port$p" -H "X-Loki-Token: ${TOK[$i]}"
  fi
}

echo "[1/6] starting $N member coordinators"
mkdir -p "$DATA"
peers=""; for i in $(seq 1 $N); do peers="$peers --peer $i=http://127.0.0.1:$((BASE+i))"; done
for i in $(seq 1 $N); do
  setsid "$BIN" --data "$DATA/$i" --port $((BASE+i)) --network regtest \
    --lightwalletd-url "$LWD" --frostd-url "$FROSTD" $peers >"$DATA/$i.log" 2>&1 &
done
sleep 6
for i in $(seq 1 $N); do
  TOK[$i]=$(sed -n 's|.*/#||p' "$DATA/$i.log" | head -1)
  [ -z "${TOK[$i]}" ] && { echo "member $i did not print a token:"; tail -3 "$DATA/$i.log"; exit 1; }
done

echo "[2/6] profiles + vault ($THRESHOLD-of-$N)"
for i in $(seq 1 $N); do
  pass=$(openssl rand -hex 32)
  printf 'Member %s %s\n' "$i" "$pass" >> "$DATA/passphrases.txt"
  api $i POST /api/profile-create "{\"name\":\"Member $i\",\"passphrase\":\"$pass\"}" >/dev/null
done
C=$(api 1 POST /api/create "{\"name\":\"Loki Test Vault\",\"members\":$N,\"threshold\":$THRESHOLD}")
V=$(echo "$C" | jq -r .vault)
[ "$V" = null ] && { echo "create failed: $C"; exit 1; }
echo "      vault=$V"
for i in $(seq 2 $N); do
  code=$(echo "$C" | jq -r --argjson s $i '.invites[]|select(.slot==$s).code')
  api $i POST /api/join "{\"invite\":\"$code\"}" >/dev/null
done

echo "[3/6] waiting for roster agreement"
FP=""
for n in $(seq 1 120); do
  s=$(api 1 GET "/api/status?vault=$V")
  [ "$(echo "$s" | jq -r .phase)" = compare_roster ] && { FP=$(echo "$s" | jq -r .fingerprint); CODE=$(echo "$s" | jq -r .roster_code); break; }
  sleep 1
done
[ -z "$FP" ] && { echo "never reached compare_roster"; exit 1; }
echo "      fingerprint=$FP"
for i in $(seq 1 $N); do api $i POST /api/agree "{\"vault\":\"$V\",\"fingerprint\":\"$FP\",\"roster_code\":\"$CODE\"}" >/dev/null; done

echo "[4/6] running DKG to active (this takes a bit for 10 members)"
for i in $(seq 1 $N); do
  ok=""
  for n in $(seq 1 300); do
    [ "$(api $i GET "/api/status?vault=$V" | jq -r .phase)" = active ] && { ok=1; break; }
    sleep 1
  done
  [ -z "$ok" ] && { echo "member $i never reached active"; exit 1; }
done
ADDR=$(api 1 GET "/api/address?vault=$V" | jq -r .address)
echo "      active, address=$ADDR"

echo "[5/6] funding the vault"
curl -fsS -X POST "$THS/api/v1/faucet/address" -H 'Content-Type: application/json' \
  -d "{\"address\":\"$ADDR\",\"amount_zatoshi\":500000000}" >/dev/null
mine 12

echo "[6/6] writing access map + serving the web wallet"
acc="{}"
for i in $(seq 1 $N); do
  slug=$(openssl rand -hex 16); SLUG[$i]=$slug
  acc=$(echo "$acc" | jq --arg s "$slug" --argjson id $i --argjson port $((BASE+i)) --arg tok "${TOK[$i]}" \
    '. + {($s): {id:$id, port:$port, token:$tok}}')
done
echo "{\"access\": $acc}" | jq . > "$WEB/.access.json"
: > "$DATA/links.txt"
for i in $(seq 1 $N); do echo "Member $i  $PUBLIC/#${SLUG[$i]}" >> "$DATA/links.txt"; done

cd "$WEB"
[ -d node_modules/@webgpu/types ] || npm install --no-audit --no-fund --silent
npm run build >"$DATA/web-build.log" 2>&1 || { echo "web build failed; see $DATA/web-build.log"; tail -20 "$DATA/web-build.log"; exit 1; }
setsid npx next start -p 3001 >"$DATA/web.log" 2>&1 &
sleep 4

echo
echo "=== DEPLOYED. Access links: $DATA/links.txt ==="
echo "=== vault $V funded; web wallet on :3001 ==="
