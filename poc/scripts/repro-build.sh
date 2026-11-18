#!/usr/bin/env bash
# Reproducible build of the two signers, then SHA-256 of every artifact:
#   - native: loki_member_app (relay-communication), the packaged member binary
#     (communication/deploy/run-member.sh MEMBER_BIN)
#   - browser: the loki-signer-wasm wasm-pack bundle (web/wallet/scripts/copy-signer.mjs)
#
#   poc/scripts/repro-build.sh [target-dir]      (default: poc/target/repro)
#
# Same OS + arch + toolchain => same hashes, whatever the checkout path or target dir.
# See docs/product/AUDIT_SCOPE.md §3. Needs: rustup with 1.95.0 (+ wasm32-unknown-unknown),
# wasm-pack 0.15.1.
set -euo pipefail
poc=$(cd "$(dirname "$0")/.." && pwd)
root=$(dirname "$poc")
target=${1:-$poc/target/repro}
mkdir -p "$target"
target=$(cd "$target" && pwd)

export RUSTUP_TOOLCHAIN=1.95.0 CARGO_TARGET_DIR=$target
export SOURCE_DATE_EPOCH=1700000000 CARGO_INCREMENTAL=0
# rustc: the last matching --remap-path-prefix wins, so the most specific prefix goes last.
remap="--remap-path-prefix=$HOME=/home --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo"
remap+=" --remap-path-prefix=$root=/loki --remap-path-prefix=$target=/target"
# codegen-units=1: without it two clean builds alternated between two hashes (AUDIT_SCOPE §3).
flags="$remap -C codegen-units=1"

cd "$poc"
RUSTFLAGS="$flags" cargo build --release --locked --features relay-communication --bin loki_member_app
# --no-opt: skip wasm-opt, a separately downloaded binaryen this build does not pin.
RUSTFLAGS="$flags --cfg getrandom_backend=\"wasm_js\"" \
  wasm-pack build loki-signer-wasm --release --no-opt --target web --out-dir "$target/wasm-pkg" -- --locked

cd "$target"
find release/loki_member_app wasm-pkg -type f | LC_ALL=C sort | xargs shasum -a 256
