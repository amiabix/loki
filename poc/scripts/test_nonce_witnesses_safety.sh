#!/usr/bin/env bash
set -euo pipefail

script="$(cd "$(dirname "$0")" && pwd)/nonce_witnesses.sh"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
mkdir "$tmp/bin"
printf '#!/usr/bin/env bash\nexit 0\n' > "$tmp/bin/cargo"
chmod +x "$tmp/bin/cargo"

for saved in witnesses.json witnesses.json.pending; do
  data="$tmp/$saved-state"
  mkdir "$data"
  printf 'saved witness state\n' > "$data/$saved"
  cp "$data/$saved" "$tmp/expected"
  if PATH="$tmp/bin:$PATH" bash "$script" "$data" >"$tmp/out" 2>"$tmp/err"; then
    echo "witness setup unexpectedly replaced a missing relay identity" >&2
    exit 1
  fi
  cmp "$tmp/expected" "$data/$saved"
  [[ ! -e "$data/relay-1" && ! -e "$data/relay-2" ]]
  [[ "$(cat "$tmp/err")" == *"refusing to replace a relay identity"* ]]
done
echo "PASS: saved and pending witnesses refuse replacement relay identities"
