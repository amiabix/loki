#!/usr/bin/env bash
# G3 standalone nonce safety prototype, across browser engines.
#
# Standalone means standalone: no FROST, no PCZTs, no chain, no G1 state. The subject is
# the nonce store and what a browser can and cannot promise about it.
#
#   ./run-g3.sh                 chromium full suite, then the portable suite on
#                               webkit and firefox, then a per-engine table
#   ./run-g3.sh <drill>         that one drill, on $G3_ENGINE (default chromium)
#   G3_ENGINE=webkit ./run-g3.sh --full     the full suite on one engine
#
# Playwright's WebKit is a WebKit build shipped by Playwright. It is NOT Safari, and
# nothing here is a Safari result. Native Safari is not automated; see G3-RESULTS.md for
# why and for the exact commands that would be required.
set -uo pipefail
cd "$(dirname "$0")"

PORTS="${RELAY_PORT:-18765} ${RELAY_PORT_B:-18766} ${RELAY_PORT_C:-18767} ${G3_WEB_PORT:-18764}"
for P in $PORTS; do
  if lsof -nP -iTCP:"$P" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "port $P is in use; set RELAY_PORT / RELAY_PORT_B / RELAY_PORT_C / G3_WEB_PORT" >&2
    exit 1
  fi
done

[ -d node_modules ] || npm install --silent

# Browsers are installed on demand. Each engine is attempted even if install fails, so the
# failure is recorded per engine rather than aborting the run.
if [ ! -d "$HOME/Library/Caches/ms-playwright" ] || [ -n "${G3_INSTALL:-}" ]; then
  node node_modules/playwright-core/cli.js install chromium webkit firefox || true
fi

G3_TMP="${G3_TMP:-/tmp/loki-g3}"
export G3_TMP
mkdir -p "$G3_TMP"

# One named drill, or one engine's full suite.
if [ $# -gt 0 ] && [ "$1" != "--full" ]; then
  exec node drills.mjs "$1"
fi
if [ "${1:-}" = "--full" ]; then
  G3_SUITE=full exec node drills.mjs
fi

rm -f "$G3_TMP"/summary-*.json
RC=0

echo "========================================================================"
echo " chromium: FULL suite"
echo "========================================================================"
G3_ENGINE=chromium G3_SUITE=full node drills.mjs || RC=1

for E in webkit firefox; do
  echo
  echo "========================================================================"
  echo " $E: PORTABLE suite (receipt gate, two-tab race, crash recovery,"
  echo "     profile restore, strict durability)"
  echo "========================================================================"
  G3_ENGINE="$E" G3_SUITE=portable node drills.mjs || RC=1
done

echo
echo "========================================================================"
echo " per-engine summary"
echo "========================================================================"
node summarise.mjs "$G3_TMP" || RC=1

echo
echo "G3 PARTIAL: real device crash tests and the platform restore matrix are not run."
echo "            See the 'Device cases: NOT TESTED' section of G3-RESULTS.md."
exit $RC
