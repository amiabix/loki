#!/usr/bin/env bash
set -euo pipefail
exec 3>&1 1>&2
checkout=$(cd "$(dirname "$0")/../.." && pwd)
build=/tmp/loki-repro
rm -rf "$build"
mkdir -p "$build/src"
git -C "$checkout" archive HEAD | tar -x -C "$build/src"

export RUSTUP_TOOLCHAIN=1.95.0 CARGO_HOME=$build/cargo CARGO_TARGET_DIR=$build/target
export SOURCE_DATE_EPOCH=1700000000 CARGO_INCREMENTAL=0
flags="--remap-path-prefix=$build=/build -C codegen-units=1"

cd "$build/src/core"
RUSTFLAGS="$flags" cargo build --release --locked --features relay-communication --bin loki_member_app
for crate in loki-signer-wasm wasm-transport; do
  RUSTFLAGS="$flags --cfg getrandom_backend=\"wasm_js\"" \
    wasm-pack build "$crate" --release --no-opt --target web -- --locked
  pkg="$build/src/core/$crate/pkg"
  module=${crate//-/_}
  if [[ $crate == wasm-transport ]]; then module=loki_wasm_transport; fi
  raw="$CARGO_TARGET_DIR/wasm32-unknown-unknown/release/$module.wasm"
  first_raw=$(shasum -a 256 "$raw")
  printf '%s\n' "$first_raw" >> "$build/raw.manifest"
  find "$pkg" -type f ! -name .gitignore -print0 | sort -z | xargs -0 shasum -a 256 > "$build/$crate.first"

  RUSTFLAGS="$flags --cfg getrandom_backend=\"wasm_js\"" \
    wasm-pack build "$crate" --release --no-opt --target web -- --locked
  if [[ $(shasum -a 256 "$raw") != "$first_raw" ]]; then
    echo "$crate: raw rustc wasm changed during the repeated wasm-pack invocation" >&2
    exit 1
  fi
  find "$pkg" -type f ! -name .gitignore -print0 | sort -z | xargs -0 shasum -a 256 > "$build/$crate.second"
  if ! diff -u "$build/$crate.first" "$build/$crate.second"; then
    echo "$crate: identical raw rustc wasm produced different wasm-pack output" >&2
    exit 1
  fi
done

cd "$build"
shasum -a 256 target/release/loki_member_app >&3
cat raw.manifest >&3
node src/core/loki-signer-wasm/serve.mjs --hash >&3
