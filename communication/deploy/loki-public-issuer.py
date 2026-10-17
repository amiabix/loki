#!/usr/bin/env python3
import argparse
import hmac
import json
import re
import stat
import subprocess
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


def make_server(root, port):
    token_file = root / "issuer-access-token"
    if stat.S_IMODE(token_file.stat().st_mode) != 0o600:
        raise ValueError("Issuer token must have mode 0600")
    token = token_file.read_text().strip()
    if not re.fullmatch(r"[0-9a-f]{64}", token):
        raise ValueError("Invalid issuer token")
    binary = Path(__file__).resolve().parents[1] / "target/release/loki-owned-testnet-config"
    # shortcut: the 20-grant limit is process-local; use durable enrollment for permanent hosting.
    issued = {}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):
            pass

        def reply(self, status, body=b""):
            self.send_response(status)
            self.send_header("Content-Type", "application/cbor" if status == 200 else "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            if self.path != "/grant" or self.headers.get("Content-Type") != "application/json":
                return self.reply(400)
            auth = self.headers.get("Authorization", "")
            if len(auth) != 71 or not hmac.compare_digest(auth, "Bearer " + token):
                return self.reply(403)
            length = self.headers.get("Content-Length", "")
            if not 1 <= len(length) <= 3 or not length.isascii() or not length.isdecimal() or not 1 <= int(length) <= 512:
                return self.reply(400)
            try:
                request = json.loads(self.rfile.read(int(length)))
            except (ValueError, UnicodeDecodeError):
                return self.reply(400)
            if not isinstance(request, dict) or set(request) != {"device_key", "policy", "bundle_sha256"}:
                return self.reply(400)
            device, policy, digest = (request[k] for k in ("device_key", "policy", "bundle_sha256"))
            if not isinstance(device, str) or not re.fullmatch(r"[0-9a-f]{64}", device):
                return self.reply(400)
            if policy not in ("2-of-3", "2-of-4", "3-of-4"):
                return self.reply(400)
            if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
                return self.reply(400)
            key = (device, policy, digest)
            cached = issued.get(key)
            if cached and cached[0] > time.time():
                return self.reply(200, cached[1])
            if key not in issued and len(issued) >= 20:
                return self.reply(429)
            try:
                result = subprocess.run(
                    (str(binary), "grant", str(root), device, policy, digest),
                    capture_output=True, timeout=5,
                )
            except (OSError, subprocess.TimeoutExpired):
                return self.reply(503)
            if result.returncode or not 1 <= len(result.stdout) <= 4096:
                return self.reply(400)
            issued[key] = (time.time() + 3500, result.stdout)
            self.reply(200, result.stdout)

    class Server(HTTPServer):
        def get_request(self):
            connection, address = super().get_request()
            connection.settimeout(5)
            return connection, address

    return Server(("127.0.0.1", port), Handler)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--port", type=int, default=39106)
    args = parser.parse_args()
    make_server(args.root.resolve(), args.port).serve_forever()
