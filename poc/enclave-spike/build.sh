#!/usr/bin/env bash
# Reproduce the Secure Enclave spikes on an Apple-silicon Mac (has a Secure Enclave).
# No cargo / no crates.io: the Rust side is built with rustc directly so it works even
# when the registry is unreachable. Run from this directory.
set -euo pipefail
cd "$(dirname "$0")"

echo "== 1. wrap/unwrap spike (unsigned) =="
swiftc enclave_spike.swift -o /tmp/enclave_spike_bin -framework Security -framework Foundation
/tmp/enclave_spike_bin

echo "== 2. Rust -> Swift -> Enclave FFI demo (ephemeral; rustc, offline) =="
swiftc -emit-library -o libse_bridge.dylib se_bridge.swift -framework Security -framework Foundation
rustc --edition 2021 ffi_demo.rs -L "$PWD" -lse_bridge -C link-arg=-Wl,-rpath,"$PWD" -o /tmp/ffi_demo_bin
/tmp/ffi_demo_bin

echo "== 3. persistent-key spike (REQUIRES a signing identity) =="
echo "   Unsigned this fails with errSecMissingEntitlement (-34018)."
echo "   With a free Apple ID personal team in Xcode, sign the built binary with that"
echo "   identity (codesign -s 'Apple Development: <you>' ...) and it passes."
swiftc persist_spike.swift -o /tmp/persist_spike_bin -framework Security -framework Foundation
/tmp/persist_spike_bin || echo "   (expected to fail until signed with a real Team ID)"
