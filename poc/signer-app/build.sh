#!/usr/bin/env bash
# Build the real native signer: Rust signer static lib + Swift Enclave backend + the app,
# then run the selftest (seals a FROST share under the persistent Secure Enclave key).
# Needs: Xcode, an Apple ID in Xcode Accounts (team provisions on first GUI Run), the Apple
# WWDR intermediate installed, and crates.io reachable.
set -euo pipefail
cd "$(dirname "$0")"
POC="$(cd .. && pwd)"

echo "== 1. Rust signer static lib (+ Enclave backend + live member-app serve) =="
( cd "$POC" && cargo build --lib --features apple-enclave,relay-communication )

echo "== 2. stage libs =="
mkdir -p libs
cp "$POC/target/debug/libloki_poc.a" libs/
cp "$(find "$POC/target/debug/build" -name libse_backend.dylib | head -1)" libs/

echo "== 3. generate + build the app (arm64) =="
ruby gen.rb
xcodebuild -project LokiSigner.xcodeproj -scheme LokiSigner -configuration Debug -derivedDataPath "$PWD/build" \
  -allowProvisioningUpdates ARCHS=arm64 ONLY_ACTIVE_ARCH=YES CONFIGURATION_BUILD_DIR="$PWD/out" build
codesign --verify --deep --strict out/LokiSigner.app

echo "== 4. run the real signer Enclave selftest =="
./out/LokiSigner.app/Contents/MacOS/LokiSigner rust
