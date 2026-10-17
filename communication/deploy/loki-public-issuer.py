#!/usr/bin/env python3
import argparse
import hmac
import json
import re
import stat
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

MAX_REQUESTS = 16


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
    issued_lock = threading.Lock()

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
            with issued_lock:
                cached = issued.get(key)
                if cached and cached[0] > time.time():
                    status, body = 200, cached[1]
                elif key not in issued and len(issued) >= 20:
                    status, body = 429, b""
                else:
                    try:
                        result = subprocess.run(
                            (str(binary), "grant", str(root), device, policy, digest),
                            capture_output=True, timeout=5,
                        )
                    except (OSError, subprocess.TimeoutExpired):
                        status, body = 503, b""
                    else:
                        if result.returncode or not 1 <= len(result.stdout) <= 4096:
                            status, body = 400, b""
                        else:
                            status, body = 200, result.stdout
                            issued[key] = (time.time() + 3500, body)
            self.reply(status, body)

    class Server(ThreadingHTTPServer):
        daemon_threads = True

        def __init__(self, address, handler):
            self.slots = threading.BoundedSemaphore(MAX_REQUESTS)
            super().__init__(address, handler)

        def get_request(self):
            connection, address = super().get_request()
            connection.settimeout(5)
            return connection, address

        def process_request(self, request, client_address):
            if not self.slots.acquire(blocking=False):
                self.close_request(request)
                return
            try:
                super().process_request(request, client_address)
            except BaseException:
                self.slots.release()
                raise

        def process_request_thread(self, request, client_address):
            try:
                super().process_request_thread(request, client_address)
            finally:
                self.slots.release()

    return Server(("127.0.0.1", port), Handler)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--port", type=int, default=39106)
    args = parser.parse_args()
    make_server(args.root.resolve(), args.port).serve_forever()
