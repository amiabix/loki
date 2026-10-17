#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


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
    digest = hashlib.sha256(bundle).hexdigest()
    public_url = os.environ.get("LOKI_PUBLIC_ISSUER_URL")
    if public_url:
        url = urlsplit(public_url)
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment or url.path != "/grant":
            parser.error("Invalid public issuer URL")
        token_path = os.environ.get("LOKI_PUBLIC_ISSUER_TOKEN_FILE")
        if not token_path:
            parser.error("Set LOKI_PUBLIC_ISSUER_TOKEN_FILE")
        token_file = Path(token_path)
        if stat.S_IMODE(token_file.stat().st_mode) != 0o600:
            parser.error("Issuer access token must have mode 0600")
        token = token_file.read_text().strip()
        if not re.fullmatch(r"[0-9a-f]{64}", token):
            parser.error("Invalid issuer access token")
        payload = json.dumps({"device_key": args.device_key, "policy": args.policy,
                              "bundle_sha256": digest}).encode()
        request = Request(public_url, data=payload,
                          headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
                          method="POST")

        class NoRedirect(HTTPRedirectHandler):
            def redirect_request(self, *_):
                return None

        try:
            with build_opener(NoRedirect()).open(request, timeout=15) as response:
                if response.status != 200 or response.headers.get_content_type() != "application/cbor":
                    raise ValueError("Invalid issuer response")
                raw = response.read(4097)
        except (OSError, ValueError):
            raise SystemExit("Enrollment is unavailable") from None
    else:
        target = os.environ.get("LOKI_ISSUER_SSH_TARGET", "omarchy")
        command = (
            "ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", target,
            "/home/abix/loki-deployment-session/src/communication/target/release/loki-owned-testnet-config",
            "grant", "/home/abix/.local/share/loki-hosted-testnet", args.device_key,
            args.policy, digest,
        )
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20)
        raw = result.stdout if result.returncode == 0 else b""
    if not 1 <= len(raw) <= 4096:
        raise SystemExit("Enrollment is unavailable")
    sys.stdout.buffer.write(raw)


if __name__ == "__main__":
    main()
