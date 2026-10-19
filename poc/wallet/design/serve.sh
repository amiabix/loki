#!/usr/bin/env bash
# Serve the design prototype locally. Roots at poc/wallet so both /design/ and
# /fonts/ (referenced as ../fonts/) resolve. No deps beyond python3.
set -euo pipefail
PORT="${1:-8080}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"   # poc/wallet
echo "Serving $ROOT on http://localhost:$PORT/design/"
exec python3 -m http.server "$PORT" --directory "$ROOT"
