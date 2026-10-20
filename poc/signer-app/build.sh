#!/usr/bin/env bash
# Build the real native signer: Rust signer static lib + Swift Enclave backend + the app,
# then run the selftest (seals a FROST share under the persistent Secure Enclave key).
# Needs: Xcode, an Apple ID in Xcode Accounts (team provisions on first GUI Run), the Apple
# WWDR intermediate installed, and crates.io reachable.
set -euo pipefail
cd "$(dirname "$0")"
POC="$(cd .. && pwd)"

echo "== 1. Rust signer static lib (+ Enclave backend) =="
( cd "$POC" && cargo build --features apple-enclave )

echo "== 2. stage libs =="
mkdir -p libs
cp "$POC/target/debug/libloki_poc.a" libs/
cp "$(find "$POC/target/debug/build" -name libse_backend.dylib | head -1)" libs/

echo "== 3. generate + build the app (arm64) =="
ruby gen.rb
rm -rf out
xcodebuild -project LokiSigner.xcodeproj -target LokiSigner -configuration Debug \
  -allowProvisioningUpdates ARCHS=arm64 ONLY_ACTIVE_ARCH=YES CONFIGURATION_BUILD_DIR="$PWD/out" build

echo "== 4. run the real signer Enclave selftest =="
./out/LokiSigner.app/Contents/MacOS/LokiSigner rust
