#!/usr/bin/env python3
"""Joining a vault from a separate app process, over the network courier.

Every app here is its own operating system process with its own private data
root and its own courier directory. No directory is shared between them, so the
only way a setup file reaches another member is the creator's HTTP courier.

What these tests do not establish: a join from a separate physical device. The
HTTPS case proves the transport and the joiner's certificate check on one host;
reaching that endpoint from another device is a deployment question this suite
cannot answer.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from member_app import SETUP, Wallet, decoded, encoded

HERE = Path(__file__).resolve().parent


def free_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class Refused(Exception):
    """What the app told the caller, in the words the UI would show."""


class App:
    """One member's signer app, in its own process with its own roots."""

    def __init__(self, root, invite_port=None, invite_origin=None, env=None):
        self.root = Path(root)
        self.data = self.root / "data"
        self.exchange = self.root / "exchange"
        self.port = free_port()
        argv = [sys.executable, str(HERE / "member_app.py"),
                "--data", str(self.data), "--exchange", str(self.exchange),
                "--port", str(self.port)]
        if invite_port:
            argv += ["--invite-port", str(invite_port)]
        if invite_origin:
            argv += ["--invite-origin", invite_origin]
        self.process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                        text=True, env={**os.environ, **(env or {})})
        self.token = None
        while True:
            line = self.process.stdout.readline()
            if not line:
                raise AssertionError(f"app exited: {self.process.stderr.read()}")
            if line.startswith("Signer:"):
                self.token = line.strip().split("#", 1)[1]
                return

    def api(self, path, body=None):
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/api/{path}",
            data=None if body is None else json.dumps(body).encode(),
            headers={"X-Loki-Token": self.token, "Content-Type": "application/json"},
            method="GET" if body is None else "POST")
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                return json.loads(response.read())
        except urllib.error.HTTPError as error:
            with error:
                raise Refused(json.loads(error.read())["error"]) from None

    def status(self, vault=None):
        return self.api(f"status?vault={vault}" if vault else "status")

    def until(self, vault, check, limit=120, what="state"):
        deadline = time.time() + limit
        while time.time() < deadline:
            state = self.status(vault)
            if check(state):
                return state
            time.sleep(0.5)
        raise AssertionError(f"member {self.port} never reached {what}: {self.status(vault)}")

    def stop(self):
        self.process.terminate()
        for pipe in (self.process.stdout, self.process.stderr):
            pipe.close()
        try:
            self.process.wait(timeout=20)
        except subprocess.TimeoutExpired:
            self.process.kill()


def tls_front(port, target, certificate, key):
    """A TLS front for the loopback courier: the deployment this build expects
    for any address outside this machine. It terminates TLS and forwards bytes;
    it is the test's stand-in for a reverse proxy, not part of the app."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(8)

    def pump(source, sink):
        try:
            while True:
                chunk = source.recv(65536)
                if not chunk:
                    break
                sink.sendall(chunk)
        except OSError:
            pass
        finally:
            for side in (source, sink):
                try:
                    side.close()
                except OSError:
                    pass

    def serve():
        while True:
            try:
                raw, _ = listener.accept()
            except OSError:
                return
            try:
                client = context.wrap_socket(raw, server_side=True)
                upstream = socket.create_connection(target, timeout=15)
            except (OSError, ssl.SSLError):
                raw.close()
                continue
            threading.Thread(target=pump, args=(client, upstream), daemon=True).start()
            threading.Thread(target=pump, args=(upstream, client), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    return listener


def dropping_front(port, target, drops=1):
    """A courier address that swallows its first answer.

    The creator's app receives the claim and commits it; the joining app sees
    the connection close with nothing on it. This is the failure where an
    invitation could be spent without anyone being able to use it."""
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", port))
    listener.listen(8)
    left = [drops]

    def forward(source, sink):
        try:
            while True:
                chunk = source.recv(65536)
                if not chunk:
                    return
                sink.sendall(chunk)
        except OSError:
            return

    def handle(client):
        try:
            upstream = socket.create_connection(target, timeout=15)
            first = client.recv(65536)
        except OSError:
            client.close()
            return
        if not first:
            client.close()
            upstream.close()
            return
        upstream.sendall(first)
        # Only the claim's answer is dropped, and only once. Counting
        # connections instead would make this depend on who dialled first.
        swallow = b"/claim" in first and left[0] > 0
        if swallow:
            left[0] -= 1
        threading.Thread(target=forward, args=(client, upstream), daemon=True).start()
        if swallow:
            upstream.recv(65536)      # the answer the joining app never sees
        else:
            forward(upstream, client)
        client.close()
        upstream.close()

    def serve():
        while True:
            try:
                client, _ = listener.accept()
            except OSError:
                return
            threading.Thread(target=handle, args=(client,), daemon=True).start()

    threading.Thread(target=serve, daemon=True).start()
    return listener


def make_certificates(folder):
    """A private CA and a localhost certificate signed by it. The joiner trusts
    exactly this CA and nothing else; verification stays on."""
    ca, ca_key = folder / "ca.pem", folder / "ca.key"
    leaf, leaf_key, csr = folder / "leaf.pem", folder / "leaf.key", folder / "leaf.csr"
    extensions = folder / "leaf.ext"
    extensions.write_text("subjectAltName=DNS:localhost\n")
    run = lambda *argv: subprocess.run(argv, check=True, capture_output=True)
    run("openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(ca_key),
        "-out", str(ca), "-days", "1", "-subj", "/CN=Loki setup test CA",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    run("openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(leaf_key),
        "-out", str(csr), "-subj", "/CN=localhost")
    run("openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca), "-CAkey", str(ca_key),
        "-out", str(leaf), "-days", "1", "-extfile", str(extensions))
    return ca, leaf, leaf_key


def hostile_courier(files):
    """A courier that answers with whatever it likes. The joining member's app
    has no reason to believe any of it: the creator's address came from an
    invite, and the files are only bytes until their own checks pass."""
    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *_args):
            pass

        def do_GET(self):
            if not self.path.endswith("/files"):
                body = files.get(self.path.rsplit("/", 1)[-1], ("", b""))[1]
            elif isinstance(files, dict):
                body = json.dumps({"files": {name: digest for name, (digest, _) in files.items()}}).encode()
            else:
                body = json.dumps({"files": files}).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


class CourierAnswerTest(unittest.TestCase):
    """What one member's app accepts from the other side of the courier."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="loki-courier-answers-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.vault = "b" * 64
        self.wallet = Wallet(self.root / "data", self.root / "exchange")
        self.addCleanup(self.wallet.close)
        (self.root / "exchange" / self.vault).mkdir(mode=0o700, parents=True)

    def sync(self, files):
        server = hostile_courier(files)
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        origin = f"http://127.0.0.1:{server.server_address[1]}"
        self.wallet.sync_once(self.vault, origin, "x" * 40, 2)

    def digest(self, body):
        return hashlib.sha256(body).hexdigest()

    def test_a_listed_name_outside_this_vault_is_refused(self):
        body = b"{}"
        for name in ("../../escape.json", "/etc/passwd", "join-9.json", "draft.json.bak",
                     f"{'c' * 64}-r1-2.bin"):
            with self.subTest(name=name):
                with self.assertRaisesRegex(ValueError, "cannot have"):
                    self.sync({name: (self.digest(body), body)})
        self.assertEqual(sorted(path.name for path in (self.root / "exchange" / self.vault).iterdir()),
                         [])
        self.assertEqual(sorted(path.name for path in self.root.iterdir()), ["data", "exchange"])

    def test_a_body_that_is_not_the_listed_file_is_refused(self):
        with self.assertRaisesRegex(ValueError, "not the file it listed"):
            self.sync({"join-2.json": (self.digest(b"what was promised"), b"what arrived")})
        self.assertFalse((self.root / "exchange" / self.vault / "join-2.json").exists())

    def test_a_file_this_app_published_is_never_replaced(self):
        folder = self.root / "exchange" / self.vault
        (folder / "join-2.json").write_bytes(b"mine")
        other = b"theirs"
        with self.assertRaisesRegex(ValueError, "different join-2.json"):
            self.sync({"join-2.json": (self.digest(other), other)})
        self.assertEqual((folder / "join-2.json").read_bytes(), b"mine")

    def test_a_listing_that_is_not_a_listing_is_refused(self):
        with self.assertRaisesRegex(ValueError, "did not answer with this vault"):
            self.sync(["join-2.json"])


class RemoteJoinTest(unittest.TestCase):
    def setUp(self):
        if not SETUP.is_file():
            self.skipTest("build loki_setup_member first: cd poc && cargo build --locked --bins")
        self.temp = tempfile.TemporaryDirectory(prefix="loki-remote-join-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def app(self, name, **options):
        app = App(self.root / name, **options)
        self.addCleanup(app.stop)
        return app

    def member(self, name, **options):
        app = self.app(name, **options)
        app.api("profile-create", {"name": name, "passphrase": f"passphrase for {name} only"})
        return app

    def test_three_apps_certify_a_vault_with_no_shared_directory(self):
        """The whole setup, end to end, with the courier as the only channel."""
        invite_port = free_port()
        creator = self.member("creator", invite_port=invite_port)
        created = creator.api("create", {"name": "Group treasury", "members": 3})
        vault, invites = created["vault"], created["invites"]
        second = self.member("second")
        third = self.member("third")

        self.assertEqual(second.api("join", {"invite": invites[0]}), {"vault": vault, "joined": True})
        self.assertEqual(third.api("join", {"invite": invites[1]}), {"vault": vault, "joined": True})

        # the creator's rows, from real state: both other members published an
        # identity, and the page can say "Joined" because of that and nothing else
        state = creator.until(vault, lambda s: all(row["joined"] for row in s.get("invites", [{}])),
                              what="both members joined")
        self.assertEqual([row["slot"] for row in state["invites"]], [2, 3])
        self.assertEqual([row["origin"] for row in state["invites"]],
                         [f"http://127.0.0.1:{invite_port}"] * 2)
        self.assertGreater(state["invites_expire_at"], time.time())

        apps = [creator, second, third]
        fingerprints = [app.until(vault, lambda s: s["fingerprint"], what="a roster fingerprint")
                        ["fingerprint"] for app in apps]
        self.assertEqual(len(set(fingerprints)), 1)
        for app in apps:
            self.assertEqual(app.status(vault)["phase"], "compare_roster")
            self.assertIsNone(app.status(vault)["transport_error"])

        # no directory is shared, and each app holds its own copy of the courier
        self.assertEqual(len({app.exchange.resolve() for app in apps}), 3)
        for app in apps:
            self.assertTrue((app.exchange / vault / "draft.json").is_file())

        for app in apps:
            self.assertEqual(app.api("agree", {"vault": vault, "fingerprint": fingerprints[0]}),
                             {"started": True})
        for app in apps:
            app.until(vault, lambda s: s["phase"] != "creating_keys", what="finished key creation")
            self.assertEqual(app.status(vault)["phase"], "back_up")

        saved = []
        for app in apps:
            words = app.api("backup", {"vault": vault})["words"]
            saved.append(words)
            self.assertEqual(app.api("verify", {"vault": vault, "words": words}),
                             {"verified": True})
        for app in apps:
            # every member's signed backup check has to arrive over the courier
            # before any of them can move to the final card
            deadline = time.time() + 120
            while len(list((app.exchange / vault).glob(f"{vault}-backup-*.bin"))) < 3:
                self.assertLess(time.time(), deadline, "backup checks never arrived")
                time.sleep(0.5)
            app.api("activate", {"vault": vault})
        addresses = []
        for app, words in zip(apps, saved):
            app.api("finalize-backup", {"vault": vault, "words": words})
            card = app.api(f"final-card?vault={vault}")["card"]
            self.assertEqual(app.api("verify-final-backup",
                                     {"vault": vault, "words": words, "card": card}),
                             {"verified": True})
            addresses.append(app.api("address", {"vault": vault})["address"])
        self.assertEqual(len(set(addresses)), 1)
        self.assertTrue(addresses[0].startswith("uregtest1"))

    def test_invite_refusals_and_courier_limits(self):
        invite_port = free_port()
        origin = f"http://127.0.0.1:{invite_port}"
        creator = self.member("creator", invite_port=invite_port)
        created = creator.api("create", {"name": "Refusals", "members": 3})
        vault, invites = created["vault"], created["invites"]
        draft_path = creator.exchange / vault / "draft.json"
        draft = json.loads(draft_path.read_text())

        # an invite whose slot was swapped for another member's secret
        wrong_slot = encoded({"vault": vault, "slot": 3,
                              "secret": decoded(invites[0])["secret"], "url": origin})
        with self.assertRaisesRegex(Refused, "does not match this vault"):
            self.member("wrong-slot").api("join", {"invite": wrong_slot})

        # the same invite, after its 24 hours
        draft_path.write_text(json.dumps({**draft, "expires_at": int(time.time()) - 1}))
        with self.assertRaisesRegex(Refused, "expired"):
            self.member("late").api("join", {"invite": invites[0]})
        draft_path.write_text(json.dumps(draft))

        # one use only: a copied code is spent by the first app to redeem it
        second = self.member("second")
        self.assertEqual(second.api("join", {"invite": invites[0]}), {"vault": vault, "joined": True})
        with self.assertRaisesRegex(Refused, "already used"):
            self.member("duplicate").api("join", {"invite": invites[0]})

        token = json.loads((second.data / "vaults" / vault / "transport.json").read_text())["token"]

        def courier(method, path, token=None, body=None):
            request = urllib.request.Request(f"{origin}{path}", data=body, method=method,
                                             headers={"X-Loki-Setup": token} if token else {})
            try:
                with urllib.request.urlopen(request, timeout=15) as response:
                    return response.status, response.read()
            except urllib.error.HTTPError as error:
                with error:
                    return error.code, error.read()

        # the signer app, the dashboard and every private route are absent here
        for path in ("/", "/app.js", "/app.css", "/api/status", "/api/card",
                     f"/api/status?vault={vault}", "/dashboard.js", f"/setup/{vault}"):
            status, _ = courier("GET", path)
            self.assertEqual(status, 404, path)
        for path in ("/api/unlock", "/api/agree", "/api/backup"):
            status, _ = courier("POST", path, body=b"{}")
            self.assertEqual(status, 404, path)

        # reading the courier needs a claimed token
        self.assertEqual(courier("GET", f"/setup/{vault}/files")[0], 400)
        self.assertIn(b"Claim your invite first", courier("GET", f"/setup/{vault}/files")[1])
        status, body = courier("GET", f"/setup/{vault}/files", token)
        self.assertEqual(status, 200)
        self.assertIn("join-2.json", json.loads(body)["files"])

        # a member's token publishes that member's files and no one else's
        self.assertEqual(courier("PUT", f"/setup/{vault}/files/join-3.json", token, b"{}")[0], 400)
        self.assertIn(b"cannot publish",
                      courier("PUT", f"/setup/{vault}/files/join-3.json", token, b"{}")[1])
        self.assertEqual(courier("PUT", f"/setup/{vault}/files/join-2.json", token, b"{}")[0], 400)
        self.assertIn(b"already published",
                      courier("PUT", f"/setup/{vault}/files/join-2.json", token, b"{}")[1])
        # and nothing outside the named setup files crosses at all
        self.assertEqual(courier("PUT", f"/setup/{vault}/files/membership.json", token, b"{}")[0], 400)
        self.assertEqual(courier("GET", f"/setup/{vault}/files/../draft.json", token)[0], 404)

    def test_a_lost_claim_answer_costs_a_retry_and_not_the_invitation(self):
        invite_port, front_port = free_port(), free_port()
        origin = f"http://127.0.0.1:{front_port}"
        creator = self.member("creator", invite_port=invite_port, invite_origin=origin)
        front = dropping_front(front_port, ("127.0.0.1", invite_port))
        self.addCleanup(front.close)
        created = creator.api("create", {"name": "Lost answer", "members": 3})
        vault, invites = created["vault"], created["invites"]

        second = self.member("second")
        with self.assertRaisesRegex(Refused, "Cannot reach the vault creator's app"):
            second.api("join", {"invite": invites[0]})
        # the creator has already spent that slot, and nobody knows it yet
        claims = json.loads((creator.data / "vaults" / vault / "claims.json").read_text())
        self.assertEqual(list(claims), ["2"])

        # that saved token belongs to the invite it was made for: the member 3
        # invite pasted into the same app cannot ride on it
        with self.assertRaisesRegex(Refused, "already claimed the member 2 invite"):
            second.api("join", {"invite": invites[1]})
        self.assertEqual(list(json.loads(
            (creator.data / "vaults" / vault / "claims.json").read_text())), ["2"])

        # and the 24 hours gate the first claim of a slot, not the retry of one
        # the creator's app already recorded
        draft_path = creator.exchange / vault / "draft.json"
        draft = json.loads(draft_path.read_text())
        draft_path.write_text(json.dumps({**draft, "expires_at": int(time.time()) - 1}))
        self.assertEqual(second.api("join", {"invite": invites[0]}), {"vault": vault, "joined": True})
        with self.assertRaisesRegex(Refused, "expired"):
            self.member("late").api("join", {"invite": invites[1]})
        draft_path.write_text(json.dumps(draft))
        creator.until(vault, lambda s: s["invites"][0]["joined"], what="member 2 joined after a retry")

        # a copy of the same code on another app is still refused
        with self.assertRaisesRegex(Refused, "already used by another app"):
            self.member("thief").api("join", {"invite": invites[0]})

    def test_join_over_https_the_joiner_verifies(self):
        """The only channel this build offers beyond this machine: HTTPS with a
        certificate the joining device already trusts."""
        if not shutil.which("openssl"):
            self.skipTest("openssl is needed to make the test certificate")
        ca, leaf, leaf_key = make_certificates(self.root)
        invite_port, front_port = free_port(), free_port()
        origin = f"https://localhost:{front_port}"
        creator = self.member("creator", invite_port=invite_port, invite_origin=origin)
        front = tls_front(front_port, ("127.0.0.1", invite_port), leaf, leaf_key)
        self.addCleanup(front.close)
        created = creator.api("create", {"name": "Over TLS", "members": 3})
        vault, invites = created["vault"], created["invites"]
        self.assertTrue(all(decoded(code)["url"] == origin for code in invites))

        # an app that does not trust this certificate cannot join: the check is on
        stranger = self.member("stranger")
        with self.assertRaisesRegex(Refused, "Cannot reach the vault creator's app"):
            stranger.api("join", {"invite": invites[0]})

        second = self.member("second", env={"SSL_CERT_FILE": str(ca)})
        self.assertEqual(second.api("join", {"invite": invites[1]}), {"vault": vault, "joined": True})
        state = creator.until(vault, lambda s: s["invites"][1]["joined"],
                              what="the member that joined over HTTPS")
        self.assertFalse(state["invites"][0]["joined"])
        self.assertEqual(state["invites"][1]["origin"], origin)
        self.assertIsNone(second.status(vault)["transport_error"])

    def test_lan_http_invite_origin_is_refused(self):
        """A plain http address off this machine would carry the invite token in
        the clear, so the app refuses to advertise one at all."""
        port = free_port()
        result = subprocess.run(
            [sys.executable, str(HERE / "member_app.py"), "--data", str(self.root / "lan" / "data"),
             "--exchange", str(self.root / "lan" / "exchange"), "--port", str(free_port()),
             "--invite-port", str(port), "--invite-origin", "http://192.168.1.5:8787"],
            capture_output=True, text=True, timeout=60)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Use https", result.stderr)


if __name__ == "__main__":
    unittest.main()
