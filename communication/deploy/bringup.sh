#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 1 || $1 != /* || -e $1 ]]; then
  echo 'usage: bringup.sh /absolute/new/root' >&2
  exit 2
fi
root=$1
deploy=$(cd "$(dirname "$0")" && pwd -P)
workspace=$(cd "$deploy/.." && pwd -P)
if [[ $(cd "$(dirname "$root")" && pwd -P) != "$(dirname "$root")" ]]; then
  echo 'root parent must be canonical' >&2
  exit 2
fi

cargo build --release --locked --manifest-path "$workspace/Cargo.toml" \
  -p loki-relay-server -p loki-setup-admission
bin="$workspace/target/release"
"$bin/loki-owned-test-inputs" init "$root" "$bin/loki-relay-server"

printf -v quoted_bin '%q' "$bin/loki-owned-test-inputs"
printf -v quoted_root '%q' "$root"
printf '#!/usr/bin/env bash\nexec %s grant %s "$@"\n' "$quoted_bin" "$quoted_root" > "$root/issue-enrollment"
chmod 700 "$root/issue-enrollment"

pids=()
cleanup() {
  if [[ -f $root/pids ]]; then
    while read -r pid; do kill -INT "$pid" 2>/dev/null || true; done < "$root/pids"
  fi
}
trap cleanup EXIT
trap 'exit 1' INT TERM
python3 - "$root" "$bin" > "$root/pids" <<'PY'
import subprocess
import sys
from pathlib import Path

root, binaries = map(Path, sys.argv[1:])
commands = [
    ([str(binaries / 'loki-relay-server'), 'serve', '--root', str(root / f'relay-{slot}'),
      '--listen', f'127.0.0.1:{39100 + slot}'], root / f'relay-{slot}.log')
    for slot in (1, 2, 3)
]
commands.append(([
    str(binaries / 'loki-setup-admission'), 'serve', '--root', str(root / 'admission'),
    '--bundle-file', str(root / 'inputs/bundle'),
    '--config-key-file', str(root / 'inputs/config-key'),
    '--signing-key-file', str(root / 'admission/signing-key'),
    '--issuer-key-file', str(root / 'inputs/issuer-public-key'),
    *[part for slot in (1, 2, 3) for part in
      (f'--relay-{slot}-provision-file', str(root / f'inputs/relay-{slot}-provision'))],
    '--listen', '127.0.0.1:39104', '--development',
], root / 'admission.log'))
for command, log in commands:
    with log.open('w') as output:
        child = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=output,
                                 stderr=subprocess.STDOUT, start_new_session=True)
    print(child.pid, flush=True)
PY
while read -r pid; do pids+=("$pid"); done < "$root/pids"
for port in 39101 39102 39103 39104; do
  ready=0
  for _ in {1..100}; do
    for pid in "${pids[@]}"; do kill -0 "$pid" 2>/dev/null || { echo "service exited; see $root/*.log" >&2; exit 1; }; done
    if curl --silent --fail --max-time 1 "http://127.0.0.1:$port/health" > /dev/null; then
      ready=1
      break
    fi
    sleep 0.1
  done
  [[ $ready == 1 ]] || { echo "health check failed on $port; see $root/*.log" >&2; exit 1; }
  echo "127.0.0.1:$port health OK"
done
trap - EXIT INT TERM
echo "owned TEST stack ready at $root"
