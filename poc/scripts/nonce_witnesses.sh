#!/usr/bin/env bash
# Persistent, local-demo witnesses. Never delete/restore these ledgers with signer profiles.
# Production needs independently operated relays in separate rollback domains.
# Prints only the witnesses.json path to stdout; safe for command substitution.
set -euo pipefail
umask 077

POC="$(cd "$(dirname "$0")/.." && pwd)"
DATA="${1:-$HOME/loki-nonce-witnesses}"
mkdir -p "$DATA"
DATA="$(cd "$DATA" && pwd)"
RELAY="$POC/../communication/target/debug/loki-relay-server"
PROVISION="$POC/target/debug/examples/provision_nonce_witnesses"

cargo build --manifest-path "$POC/../communication/Cargo.toml" \
  --target-dir "$POC/../communication/target" --bin loki-relay-server >&2
cargo build --manifest-path "$POC/Cargo.toml" --target-dir "$POC/target" \
  --features relay-communication --example provision_nonce_witnesses >&2

for i in 1 2; do
  root="$DATA/relay-$i"
  port="3910$i"
  if [[ ! -d "$root" ]]; then
    if [[ -e "$DATA/witnesses.json" || -e "$DATA/witnesses.json.pending" ]]; then
      echo "Missing $root for saved witnesses; refusing to replace a relay identity" >&2
      exit 1
    fi
    capability="$DATA/provision-$i.secret"
    dd if=/dev/urandom of="$capability" bs=32 count=1 2>/dev/null
    "$RELAY" init --root "$root" --provision-capability-file "$capability" \
      --listen "127.0.0.1:$port" --total-bytes 67108864 --mailbox-bytes 67108864 --mailbox-count 1
    rm "$capability"
  fi
  if ! curl --noproxy '*' -fsS --max-time 1 "http://127.0.0.1:$port/health" >/dev/null 2>&1; then
    nohup "$RELAY" serve --root "$root" --listen "127.0.0.1:$port" \
      >>"$DATA/relay-$i.log" 2>&1 </dev/null &
    echo "$!" >"$DATA/relay-$i.pid"
  fi
  ready=0
  for attempt in {1..50}; do
    if curl --noproxy '*' -fsS --max-time 1 "http://127.0.0.1:$port/health" >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 0.1
  done
  [[ "$ready" == 1 ]] || { echo "Witness relay $i did not start; see $DATA/relay-$i.log" >&2; exit 1; }
done

# The helper authenticates both keys/run IDs, including when a port was already listening.
"$PROVISION" --development-http --relay-root "$DATA/relay-1" --relay-root "$DATA/relay-2" \
  --out "$DATA/witnesses.json"
