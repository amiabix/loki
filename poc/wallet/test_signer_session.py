import unittest
import sys
import json
import tempfile
import threading
import http.client
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from member_app import SignerSessions, Wallet, make_signer_server, make_dashboard_server


class SessionTests(unittest.TestCase):
    def test_approval_is_scoped_and_can_be_disconnected(self):
        sessions = SignerSessions("http://127.0.0.1:18802")
        request = sessions.request("http://127.0.0.1:18802")
        self.assertEqual(sessions.poll(request), "pending")
        self.assertEqual(sessions.pending()[0]["origin"], "http://127.0.0.1:18802")
        self.assertFalse(sessions.valid(request, "http://127.0.0.1:18802"))
        sessions.approve(request)
        self.assertEqual(sessions.poll(request), "approved")
        self.assertTrue(sessions.valid(request, "http://127.0.0.1:18802"))
        self.assertFalse(sessions.valid(request, "http://127.0.0.1:18803"))
        sessions.disconnect(request, "http://127.0.0.1:18802")
        self.assertFalse(sessions.valid(request, "http://127.0.0.1:18802"))

    def test_wrong_origin_rejection_and_expiry(self):
        sessions = SignerSessions("http://127.0.0.1:18802", now=lambda: 1000)
        with self.assertRaisesRegex(ValueError, "dashboard origin"):
            sessions.request("http://evil.example")
        request = sessions.request("http://127.0.0.1:18802")
        sessions.reject(request)
        self.assertEqual(sessions.poll(request), "rejected")
        newer = sessions.request("http://127.0.0.1:18802")
        sessions.now = lambda: 2000
        with self.assertRaisesRegex(ValueError, "expired"):
            sessions.approve(newer)
        self.assertFalse(sessions.valid(newer, "http://127.0.0.1:18802"))

    def test_clear_removes_approved_sessions(self):
        sessions = SignerSessions("http://127.0.0.1:18802")
        request = sessions.request("http://127.0.0.1:18802")
        sessions.approve(request)
        sessions.clear()
        self.assertFalse(sessions.valid(request, "http://127.0.0.1:18802"))

    def test_expired_requests_do_not_exhaust_capacity(self):
        sessions = SignerSessions("http://127.0.0.1:18802", now=lambda: 1000)
        for _ in range(16):
            sessions.request("http://127.0.0.1:18802")
        sessions.now = lambda: 2000
        self.assertTrue(sessions.request("http://127.0.0.1:18802"))


class SessionHttpTests(unittest.TestCase):
    def test_dashboard_is_separate_static_origin(self):
        server = make_dashboard_server(18801, 0)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        port = server.server_address[1]
        conn = http.client.HTTPConnection("127.0.0.1", port)
        conn.request("GET", "/")
        page = conn.getresponse().read().decode()
        conn.close()
        self.assertIn('data-signer-origin="http://127.0.0.1:18801"', page)
        self.assertNotIn("X-Loki-Token", page)
        conn = http.client.HTTPConnection("127.0.0.1", port)
        conn.request("GET", "/api/status")
        self.assertEqual(conn.getresponse().status, 404)
        conn.close()

    def test_pairing_allows_only_read_only_vault_discovery(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            wallet = Wallet(root / "member", root / "exchange")
            wallet.profile_data = {"id": "private-profile-id", "name": "Alice"}
            wallet.vaults = lambda: [{"vault": "abc", "name": "Treasury", "slot": 2,
                                      "profile": "private-profile-id", "invites": ["secret"]}]
            wallet.status = lambda vault=None: {"phase": "active", "words": "secret"}
            created = []
            wallet.create = lambda name, members: created.append((name, members)) or {"vault": "new-vault", "invites": ["private-invite"]}
            server, private_token = make_signer_server(wallet, 0, 18802)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(server.shutdown)
            self.addCleanup(server.server_close)
            self.addCleanup(wallet.close)
            port = server.server_address[1]
            origin = "http://127.0.0.1:18802"

            def call(method, path, payload=None, headers=None):
                conn = http.client.HTTPConnection("127.0.0.1", port)
                body = json.dumps(payload).encode() if payload is not None else None
                conn.request(method, path, body=body, headers=headers or {})
                response = conn.getresponse()
                result = response.read()
                headers_out = dict(response.getheaders())
                conn.close()
                return response.status, json.loads(result) if result else None, headers_out

            status, _, _ = call("POST", "/api/session/request", {}, {"Origin": "http://evil.example"})
            self.assertEqual(status, 403)
            status, request, headers = call("POST", "/api/session/request", {}, {"Origin": origin})
            self.assertEqual(status, 200)
            self.assertEqual(headers.get("Access-Control-Allow-Origin"), origin)
            key = request["request"]
            self.assertEqual(call("GET", "/api/session/vaults", headers={"Origin": origin,
                              "X-Loki-Session": key})[0], 403)
            status, pending, _ = call("GET", "/api/session/pending",
                                      headers={"X-Loki-Token": private_token})
            self.assertEqual(status, 200)
            self.assertEqual(pending["requests"][0]["origin"], origin)
            self.assertEqual(call("POST", "/api/session/approve", {"request": key},
                                  {"X-Loki-Token": private_token})[0], 200)
            status, result, _ = call("GET", "/api/session/vaults", headers={"Origin": origin,
                                      "X-Loki-Session": key})
            self.assertEqual(status, 200)
            self.assertEqual(result, {"profile": "Alice", "vaults": [{"vault": "abc",
                              "name": "Treasury", "slot": 2, "phase": "active"}]})
            self.assertEqual(call("POST", "/api/session/action", {"kind": "create", "name": "Bad"},
                                  {"Origin": "http://evil.example", "X-Loki-Session": key})[0], 403)
            self.assertEqual(call("POST", "/api/session/action", {"kind": "create", "name": " "},
                                  {"Origin": origin, "X-Loki-Session": key})[0], 400)
            action = call("POST", "/api/session/action", {"kind": "create", "name": "New team", "members": 4},
                          {"Origin": origin, "X-Loki-Session": key})[1]["action"]
            self.assertEqual(created, [])
            pending_action = call("GET", "/api/session/actions",
                                  headers={"X-Loki-Token": private_token})[1]["actions"]
            self.assertEqual(pending_action[0]["name"], "New team")
            self.assertEqual(pending_action[0]["members"], 4)
            self.assertEqual(call("POST", "/api/session/action-approve", {"action": action},
                                  {"X-Loki-Token": private_token})[0], 200)
            self.assertEqual(created, [("New team", 4)])
            self.assertEqual(call("POST", "/api/session/action-approve", {"action": action},
                                  {"X-Loki-Token": private_token})[0], 400)
            self.assertEqual(call("POST", "/api/session/action-poll", {"action": action},
                                  {"Origin": origin, "X-Loki-Session": key})[1],
                             {"state": "done", "result": {"vault": "new-vault"}})
            self.assertEqual(call("POST", "/api/create", {"name": "Bad"},
                                  {"Origin": origin, "X-Loki-Session": key})[0], 403)
            self.assertEqual(call("POST", "/api/payment-approve", {
                "vault": "abc", "attempt": "a" * 64, "review_token": "b" * 64},
                {"Origin": origin, "X-Loki-Session": key})[0], 403)
            self.assertEqual(call("POST", "/api/payment-resend", {
                "vault": "abc", "attempt": "a" * 64},
                {"Origin": origin, "X-Loki-Session": key})[0], 403)
            self.assertEqual(call("POST", "/api/session/disconnect", {},
                                  {"Origin": origin, "X-Loki-Session": key})[0], 200)
            self.assertEqual(call("GET", "/api/session/vaults", headers={"Origin": origin,
                              "X-Loki-Session": key})[0], 403)
            next_key = call("POST", "/api/session/request", {}, {"Origin": origin})[1]["request"]
            self.assertEqual(call("POST", "/api/session/approve", {"request": next_key},
                                  {"X-Loki-Token": private_token})[0], 200)
            self.assertEqual(call("POST", "/api/lock", {}, {"X-Loki-Token": private_token})[0], 200)
            self.assertEqual(call("GET", "/api/session/vaults", headers={"Origin": origin,
                              "X-Loki-Session": next_key})[0], 403)

if __name__ == "__main__":
    unittest.main()
