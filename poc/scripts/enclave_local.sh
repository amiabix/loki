#!/usr/bin/env bash
# S4a co-located development stack. The web publishes a public roster; N separately
# launched member processes own local unlock files, device keys and browser pairing links.
# Same-machine demo only: the OS account still controls all processes (not independent users).
# bash poc/scripts/enclave_local.sh [member-count, default 2]
# Fresh member state lives under ~/loki-enclave-<network>/members; old hosted data is untouched.
set -euo pipefail
umask 077

POC="$(cd "$(dirname "$0")/.." && pwd)"
APP="$POC/signer-app/out/LokiSigner.app/Contents/MacOS/LokiSigner"
WEB="$POC/../web/wallet"
NETWORK="${NETWORK:-regtest}"
DATA="$HOME/loki-enclave-$NETWORK"
LOG="$DATA/logs"
OMARCHY="${OMARCHY:-omarchy}"      # ssh host: its lightwalletd (:9067) and frostd (:2744)
OMARCHY_IP="${OMARCHY_IP:-100.83.113.38}"
FROSTD="http://$OMARCHY_IP:2744"   # omarchy's frostd, reachable over Tailscale
# regtest syncs omarchy's tunnelled lightwalletd; testnet uses the public one directly.
if [[ "$NETWORK" == regtest ]]; then LWD="${LWD:-http://127.0.0.1:9067}"; else LWD="${LWD:-https://testnet.zec.rocks:443}"; fi

[[ -x "$APP" ]] || { echo "build the signer app first: bash $POC/signer-app/build.sh" >&2; exit 1; }
mkdir -p "$LOG"

echo "[1/4] local nonce witnesses"
if [[ -z "${LOKI_NONCE_WITNESSES:-}" ]]; then
  LOKI_NONCE_WITNESSES="$(bash "$POC/scripts/nonce_witnesses.sh")"
fi
[[ -r "$LOKI_NONCE_WITNESSES" ]] || { echo "Cannot read nonce witnesses: $LOKI_NONCE_WITNESSES" >&2; exit 1; }
export LOKI_NONCE_WITNESSES

echo "[2/4] relay reachability + (regtest) chain tunnel"
nc -z -G3 "$OMARCHY_IP" 2744 || { echo "omarchy frostd unreachable at $FROSTD"; exit 1; }
if [[ "$NETWORK" == regtest ]]; then
  pkill -f "ssh -N -L 9067" 2>/dev/null || true
  sleep 1
  # 9067 lightwalletd (balance sync) + 32805 faucet + 18232 node RPC (the UI fund button + manual funding)
  nohup ssh -N -L 9067:127.0.0.1:9067 -L 32805:127.0.0.1:32805 -L 18232:127.0.0.1:18232 "$OMARCHY" >"$LOG/tunnel.log" 2>&1 & disown
  sleep 4
  nc -z -G3 127.0.0.1 9067 || echo "  warning: lightwalletd tunnel down — ceremony still works, funding won't"
else
  echo "  $NETWORK: lightwalletd = $LWD (public, no tunnel); frostd over Tailscale"
fi

echo "[3/4] keyless web wallet (localhost:3001)"
MEMBERS="${1:-2}"
[[ "$MEMBERS" =~ ^[1-9][0-9]*$ && "$MEMBERS" -le 16 ]] || { echo 'member count must be 1..16' >&2; exit 1; }
[[ -w /dev/tty ]] || { echo 'run in a terminal so recovery words and pairing links stay out of logs' >&2; exit 1; }
REG="$DATA/public-roster.json"
[[ -e "$REG" ]] || printf '{"access":[]}\n' > "$REG"
cd "$WEB"
[[ -d node_modules/next ]] || { echo 'install the existing wallet dependencies first' >&2; exit 1; }
# No signer binary, data root, unlock credential or capability is configured in Next.
if ! nc -z -G1 127.0.0.1 3001; then
  LOKI_REGISTRY="$REG" LOKI_DEV_FAUCET=1 nohup npx next dev --hostname localhost -p 3001 >"$LOG/web.log" 2>&1 &
  echo "$!" > "$LOG/web.pid"
fi
for ((i=0; i<60; i++)); do
  if curl -fsS --max-time 2 http://localhost:3001/api/members >/dev/null; then break; fi
  sleep 1
done
curl -fsS --max-time 5 http://localhost:3001/api/members >/dev/null

echo "[4/4] $MEMBERS member-owned signer processes"
for ((slot=1; slot<=MEMBERS; slot++)); do
  if nc -z -G1 127.0.0.1 "$((3600 + slot))"; then
    echo "Member port $((3600 + slot)) is already in use; leaving that process alone."
    continue
  fi
  # stdout goes only to the member terminal: recovery words must not land in coordinator logs.
  (
    trap '' HUP
    export NETWORK FROSTD_URL="$FROSTD" LWD LOKI_MEMBER_APP_BIN="$APP"
    export LOKI_MEMBER_DATA="$DATA/members" LOKI_COORDINATOR=http://localhost:3001
    exec bash "$POC/scripts/member_local.sh" "$slot"
  ) >/dev/tty 2>"$LOG/member-$slot.log" &
  echo "$!" > "$LOG/member-$slot.pid"
done
cat <<EOF

Open http://localhost:3001 in one tab per member. Wait for each member's local pairing link
(and Enclave consent prompt), save its recovery words privately, then paste its link into its tab.
Create a vault in one tab; join using the invite in the other. DKG, approvals and signing
run on the member processes, talking to frostd directly. Never paste a link into a URL bar.
After logout: stop that member process and rerun member_local.sh with the same data/config.
Existing hosted registry/data was not migrated or deleted. Public roster: $REG
Member errors: $LOG/member-<slot>.log; web log: $LOG/web.log
EOF
