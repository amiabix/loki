#!/usr/bin/env bash
set -euo pipefail

count="${1:-}"
if ! [[ "$count" =~ ^[1-9][0-9]?$ ]]; then
  echo "usage: $0 <number of members, 1-16>" >&2
  exit 2
fi
app="${APP:-/Applications/LokiSigner.app}"
if [[ ! -d "$app" ]]; then
  echo "LokiSigner app not found at $app (set APP=...)" >&2
  exit 1
fi
support="$HOME/Library/Application Support"

open -n -a "$app"
for ((member = 2; member <= count; member++)); do
  open -n -a "$app" --args --data "$support/LokiSigner-member$member"
done
