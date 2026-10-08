#!/usr/bin/env bash
# Run the payment flow against a running THS instance without managing its lifecycle.
set -euo pipefail
cd "$(dirname "$0")"
args=(--name "${LOKI_THS_INSTANCE:-loki}")
if [ -n "${LOKI_STATE:-}" ]; then args+=(--state "$LOKI_STATE"); fi
exec python3 run-ths.py "${args[@]}"
