#!/usr/bin/env bash
# Reproduce the Secure Enclave spikes on an Apple-silicon Mac (has a Secure Enclave).
# No cargo / no crates.io: the Rust side is built with rustc directly so it works even
# when the registry is unreachable. Run from this directory.
set -euo pipefail
cd "$(dirname "$0")"

if [[ ${1:-} == --test-backend ]]; then
    out=$(mktemp -d "${TMPDIR:-/tmp}/loki-se-tests.XXXXXX")
    trap 'rm -rf "$out"' EXIT
    swiftc -D SE_TESTS se_backend.swift se_backend_tests.swift -o "$out/swift-tests"
    "$out/swift-tests"
    swiftc -emit-library -o "$out/libse_backend.dylib" \
        -Xlinker -install_name -Xlinker "@rpath/libse_backend.dylib" se_backend.swift
    rustc --edition 2021 --crate-type rlib zeroize_shim.rs -o "$out/libzeroize.rlib"
    rustc --edition 2021 --test apple_ffi_verify.rs --extern "zeroize=$out/libzeroize.rlib" \
        -L "$out" -lse_backend -C "link-arg=-Wl,-rpath,$out" -o "$out/rust-tests"
    "$out/rust-tests" enclave_failures_have_fixed_member_messages
    exit
fi

echo "== 1. wrap/unwrap spike (unsigned) =="
swiftc enclave_spike.swift -o /tmp/enclave_spike_bin -framework Security -framework Foundation
/tmp/enclave_spike_bin

echo "== 2. Rust -> Swift -> Enclave FFI demo (ephemeral; rustc, offline) =="
swiftc -emit-library -o libse_bridge.dylib se_bridge.swift -framework Security -framework Foundation
rustc --edition 2021 ffi_demo.rs -L "$PWD" -lse_bridge -C link-arg=-Wl,-rpath,"$PWD" -o /tmp/ffi_demo_bin
/tmp/ffi_demo_bin

echo "== 3. real AppleSecureElement backend FFI round-trip (ephemeral; rustc, offline) =="
echo "   Builds the SHIPPED module poc/src/signer/secure_element_apple.rs against the"
echo "   Swift C-ABI backend and round-trips a signer DEK through the Secure Enclave."
swiftc -emit-library -o libse_backend.dylib \
    -Xlinker -install_name -Xlinker "@rpath/libse_backend.dylib" \
    se_backend.swift -framework Security -framework Foundation
rustc --edition 2021 --crate-type rlib zeroize_shim.rs -o libzeroize.rlib
rustc --edition 2021 apple_ffi_verify.rs --extern zeroize=libzeroize.rlib \
    -L "$PWD" -lse_backend -C link-arg=-Wl,-rpath,"$PWD" -o /tmp/apple_ffi_verify
/tmp/apple_ffi_verify

echo "== 4. persistent-key spike (REQUIRES a signing identity) =="
echo "   Unsigned this fails with errSecMissingEntitlement (-34018)."
echo "   With a free Apple ID personal team in Xcode, sign the built binary with that"
echo "   identity (codesign -s 'Apple Development: <you>' ...) and it passes."
swiftc persist_spike.swift -o /tmp/persist_spike_bin -framework Security -framework Foundation
/tmp/persist_spike_bin || echo "   (expected to fail until signed with a real Team ID)"
