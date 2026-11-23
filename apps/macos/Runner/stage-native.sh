#!/bin/bash
set -euo pipefail

export PATH="$HOME/.cargo/bin:$PATH"
if [[ "${ARCHS}" != arm64 || "$(rustc -vV | sed -n 's/^host: //p')" != aarch64-apple-darwin ]]; then
    echo 'error: building LokiSigner requires the arm64 Xcode architecture and Apple Silicon Rust toolchain' >&2
    exit 1
fi

core="$SRCROOT/../../core"
stage="$DERIVED_FILE_DIR/LokiNative"
mkdir -p "$stage"
if [[ "$CONFIGURATION" == Debug ]]; then profile=dev; else profile=release; fi

if ! cargo build --manifest-path "$core/Cargo.toml" --locked -p loki-poc --lib --profile "$profile" \
    --features apple-enclave,relay-communication --message-format=json-render-diagnostics > "$stage/cargo.jsonl"; then
    python3 -c 'import json, sys; [sys.stderr.write(m["message"].get("rendered") or "") for m in map(json.loads, sys.stdin) if m["reason"] == "compiler-message"]' < "$stage/cargo.jsonl"
    exit 1
fi
python3 - "$stage" "$core" <<'PY'
import json
import pathlib
import shutil
import sys

stage, core = map(pathlib.Path, sys.argv[1:])
manifest = core.resolve() / 'Cargo.toml'
messages = [json.loads(line) for line in (stage / 'cargo.jsonl').read_text().splitlines()]
artifact, = [m for m in messages if m['reason'] == 'compiler-artifact'
             and pathlib.Path(m['manifest_path']).resolve() == manifest
             and 'staticlib' in m['target']['crate_types']]
lib, = [p for p in artifact['filenames'] if p.endswith('/libloki_poc.a')]
backend, = [m['out_dir'] for m in messages if m['reason'] == 'build-script-executed'
            and m['package_id'] == artifact['package_id']]
for source in (pathlib.Path(lib), pathlib.Path(backend) / 'libse_backend.dylib'):
    dest = stage / source.name
    if not dest.exists() or source.stat().st_mtime_ns != dest.stat().st_mtime_ns:
        shutil.copy2(source, dest)
PY
xcrun lipo "$stage/libloki_poc.a" -verify_arch arm64
xcrun lipo "$stage/libse_backend.dylib" -verify_arch arm64
