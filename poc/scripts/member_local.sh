#!/usr/bin/env bash
# S4a local member launcher. Run as the member, in a terminal; the web never invokes this.
# bash poc/scripts/member_local.sh 1 [-- software development: LOKI_SECURE_ELEMENT=software]
set -euo pipefail
umask 077
POC="$(cd "$(dirname "$0")/.." && pwd)"
SLOT="${1:?usage: member_local.sh <public-slot>}"
[[ "$SLOT" =~ ^[1-9][0-9]*$ && "$SLOT" -le 1000 ]] || { echo 'local slot must be 1..1000' >&2; exit 1; }
NETWORK="${NETWORK:-regtest}"
MEMBER_ROOT="${LOKI_MEMBER_DATA:-$HOME/loki-enclave-$NETWORK/members}"
DIR="$MEMBER_ROOT/$SLOT"
PORT="$((3600 + SLOT))"
BACKEND="${LOKI_SECURE_ELEMENT:-apple}"
COORDINATOR="${LOKI_COORDINATOR:-http://localhost:3001}"
if [[ "$BACKEND" == apple ]]; then
  APP="${LOKI_MEMBER_APP_BIN:-$POC/signer-app/out/LokiSigner.app/Contents/MacOS/LokiSigner}"
  COMMAND=("$APP" serve)
else
  APP="${LOKI_MEMBER_APP_BIN:-$POC/target/debug/loki_member_app}"
  COMMAND=("$APP")
fi
[[ -x "$APP" ]] || { echo "missing signer executable: $APP" >&2; exit 1; }
[[ -r "${LOKI_NONCE_WITNESSES:-}" ]] || { echo 'set LOKI_NONCE_WITNESSES to the two pinned witness routes' >&2; exit 1; }
mkdir -p "$DIR"
# shortcut: throwaway dev unlock files; real member-owned unlock UI is S4b.
PASSFILE="${LOKI_LOCAL_PASSPHRASE_FILE:-$DIR/local.passphrase}"
if [[ ! -e "$PASSFILE" ]]; then
  printf 'loki-local-member-%s-%s\n' "$SLOT" "$(openssl rand -hex 16)" > "$PASSFILE"
  chmod 600 "$PASSFILE"
fi
if [[ "$NETWORK" == regtest ]]; then
  LWD="${LWD:-http://127.0.0.1:9067}"
else
  LWD="${LWD:-${LIGHTWALLETD_URL:-https://testnet.zec.rocks:443}}"
fi
exec "${COMMAND[@]}" --data "$DIR" --port "$PORT" --advertise-url "http://127.0.0.1:$PORT" \
  --network "$NETWORK" --secure-element "$BACKEND" --allow-loopback-peers \
  --lightwalletd-url "$LWD" --frostd-url "${FROSTD_URL:-http://127.0.0.1:2744}" \
  --nonce-witnesses "$LOKI_NONCE_WITNESSES" --development-http \
  --coordinator-url "$COORDINATOR" --registration-slot "$SLOT" \
  --local-passphrase-file "$PASSFILE" --profile-name "Member $SLOT"
