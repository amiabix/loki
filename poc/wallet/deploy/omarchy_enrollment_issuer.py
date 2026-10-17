#!/usr/bin/env python3
import argparse
import hashlib
import os
import re
import subprocess
import sys
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--device-key", required=True)
    parser.add_argument("--operator-bundle", type=Path, required=True)
    parser.add_argument("--policy", choices=("2-of-3", "2-of-4", "3-of-4"), required=True)
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{64}", args.device_key):
        parser.error("Invalid device key")
    bundle = args.operator_bundle.read_bytes()
    if not 1 <= len(bundle) <= 16384:
        parser.error("Invalid operator bundle")
    target = os.environ.get("LOKI_ISSUER_SSH_TARGET", "omarchy")
    command = (
        "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", target,
        "/home/abix/loki-deployment-session/src/communication/target/release/loki-owned-testnet-config",
        "grant", "/home/abix/.local/share/loki-hosted-testnet", args.device_key,
        args.policy, hashlib.sha256(bundle).hexdigest(),
    )
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20)
    if result.returncode or not 1 <= len(result.stdout) <= 4096:
        raise SystemExit("Enrollment is unavailable")
    sys.stdout.buffer.write(result.stdout)


if __name__ == "__main__":
    main()
