#!/usr/bin/env bash
# Clean reproducible build of the two signers from the committed HEAD; prints SHA-256 of
# every artifact on stdout (build logs go to stderr):
#   - native: loki_member_app (relay-communication), the packaged member binary
#     (communication/deploy/run-member.sh MEMBER_BIN)
#   - browser: the loki-signer-wasm wasm-pack bundle (web/wallet/scripts/copy-signer.mjs)
#
#   poc/scripts/repro-build.sh > SHA256SUMS
#
# Same OS + arch + toolchain => same hashes, whatever the checkout path or user. See
# docs/product/AUDIT_SCOPE.md §3. Needs: rustup with 1.95.0 (+ wasm32-unknown-unknown),
# wasm-pack 0.15.1, network (crates.io, wasm-bindgen download). Uncommitted changes are
# not built.
set -euo pipefail
exec 3>&1 1>&2
checkout=$(cd "$(dirname "$0")/../.." && pwd)
# Every path that reaches the build is fixed under one root, so RUSTFLAGS and cargo's
# metadata hashes are identical on every builder. Measured: the checkout path changed the
# binary even with --remap-path-prefix, and vendored OpenSSL bakes its OUT_DIR install
# prefix into the binary as ENGINESDIR/MODULESDIR strings.
build=/tmp/loki-repro
rm -rf "$build"
mkdir -p "$build/src"
git -C "$checkout" archive HEAD | tar -x -C "$build/src"

export RUSTUP_TOOLCHAIN=1.95.0 CARGO_HOME=$build/cargo CARGO_TARGET_DIR=$build/target
export SOURCE_DATE_EPOCH=1700000000 CARGO_INCREMENTAL=0
# codegen-units=1: without it two clean builds alternated between two hashes (AUDIT_SCOPE §3).
flags="--remap-path-prefix=$build=/build -C codegen-units=1"

cd "$build/src/poc"
RUSTFLAGS="$flags" cargo build --release --locked --features relay-communication --bin loki_member_app
# --no-opt: skip wasm-opt, a separately downloaded binaryen this build does not pin.
RUSTFLAGS="$flags --cfg getrandom_backend=\"wasm_js\"" \
  wasm-pack build loki-signer-wasm --release --no-opt --target web --out-dir "$build/wasm-pkg" -- --locked

cd "$build"
find target/release/loki_member_app wasm-pkg -type f | LC_ALL=C sort | xargs shasum -a 256 >&3
