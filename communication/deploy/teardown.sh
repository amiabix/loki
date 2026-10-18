#!/usr/bin/env bash
set -euo pipefail
if [[ $# != 1 || ! -f $1/pids ]]; then
  echo 'usage: teardown.sh /absolute/bringup/root' >&2
  exit 2
fi
root=$(cd "$1" && pwd -P)
while read -r pid; do
  [[ $pid =~ ^[0-9]+$ ]] || { echo 'invalid pid file' >&2; exit 1; }
  command=$(ps -p "$pid" -o command= 2>/dev/null || true)
  if [[ $command == *"$root"* ]]; then kill -INT "$pid" 2>/dev/null || true; fi
done < "$root/pids"
for _ in {1..100}; do
  alive=0
  while read -r pid; do
    command=$(ps -p "$pid" -o command= 2>/dev/null || true)
    [[ $command == *"$root"* ]] && alive=1
  done < "$root/pids"
  [[ $alive == 0 ]] && break
  sleep 0.1
done
[[ $alive == 0 ]] || { echo 'some services did not stop' >&2; exit 1; }
rm "$root/pids"
echo 'owned TEST stack stopped'
