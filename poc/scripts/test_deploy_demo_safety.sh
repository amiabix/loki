#!/usr/bin/env bash
set -euo pipefail

script="$(cd "$(dirname "$0")" && pwd)/deploy_demo.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$tmp/home/loki-demo-data" "$tmp/bin"
touch "$tmp/home/loki-demo-data/keep"
printf '#!/usr/bin/env bash\nexit 0\n' > "$tmp/bin/pkill"
printf '#!/usr/bin/env bash\nexit 0\n' > "$tmp/bin/sleep"
chmod +x "$tmp/bin/pkill" "$tmp/bin/sleep"

if HOME="$tmp/home" PATH="$tmp/bin:$PATH" PUBLIC_URL=https://example.test bash "$script" >"$tmp/out" 2>&1; then
  echo "deploy unexpectedly accepted an existing vault directory" >&2
  exit 1
fi
if [[ ! -e "$tmp/home/loki-demo-data/keep" ]]; then
  echo "deploy removed existing vault data" >&2
  exit 1
fi
