"""The wired redesign UI (ui.html + ui.js) is served over the real signer
server and drives real /api/* commands. This proves the first functional slice
end to end without native binaries: the token-authed routes the UI fetches
(vault list via /api/status, create via /api/create) answer over HTTP, and the
new /ui assets are served alongside the shipping app.
"""

import http.client
import json
import sys
import tempfile
import threading
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent))
import member_app
from member_app import Wallet, make_signer_server


def make_vault(temp, name="Treasury Reserve", slot=1, threshold=2, members=3):
    """A real on-disk membership, the same shape /api/create writes."""
    vault = "a" * 64
    wallet = Wallet(Path(temp) / "member", Path(temp) / "exchange")
    wallet.profile_data = {"id": "member", "name": "Alice"}
    wallet.passphrase = "member long test passphrase"
    (wallet.data / "profile").mkdir(parents=True, exist_ok=True)
    (wallet.data / "profile" / "profile.sealed").write_bytes(b"sealed")
    member = wallet.data / "vaults" / vault
    member.mkdir(parents=True)
    (member / "membership.json").write_text(json.dumps({
        "vault": vault, "slot": slot, "name": name, "profile": "member",
        "threshold": threshold, "members": members, "network": "regtest"}))
    (member / "roster.json").write_text("{}")
    return wallet, vault


def serve(test, wallet):
    server, token = make_signer_server(wallet, 0)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    test.addCleanup(server.server_close)
    test.addCleanup(server.shutdown)
    port = server.server_address[1]

    def request(method, path, body=None, headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        head = {"Host": f"127.0.0.1:{port}"}
        if body is not None:
            head["Content-Type"] = "application/json"
        head.update(headers or {})
        conn.request(method, path, json.dumps(body) if body is not None else None, head)
        response = conn.getresponse()
        data = response.read()
        conn.close()
        return response.status, data

    return token, request


import unittest


class WiredUiTest(unittest.TestCase):
    def test_ui_assets_are_served_alongside_the_shipping_app(self):
        with tempfile.TemporaryDirectory(prefix="loki-ui-assets-") as temp:
            wallet, _ = make_vault(temp)
            self.addCleanup(wallet.close)
            _, request = serve(self, wallet)

            status, body = request("GET", "/ui")
            self.assertEqual(status, 200)
            self.assertIn(b"Connect your Loki signer", body)
            self.assertIn(b'src="/ui.js"', body)

            status, body = request("GET", "/ui.js")
            self.assertEqual(status, 200)
            self.assertIn(b"payment-review", body)

            # The design CSS loads unchanged; its fonts resolve to /fonts/*.
            for asset in ("/ui/tokens.css", "/ui/app.css"):
                status, body = request("GET", asset)
                self.assertEqual(status, 200, asset)
                self.assertTrue(body)

    def test_vault_list_screen_calls_real_status_route(self):
        """The 02 Vaults screen fetches /api/status, then one
        /api/status?vault=<id> per vault — exactly what ui.js:loadVaults does."""
        with tempfile.TemporaryDirectory(prefix="loki-ui-vaults-") as temp:
            wallet, vault = make_vault(temp, name="Treasury Reserve")
            self.addCleanup(wallet.close)
            token, request = serve(self, wallet)
            auth = {"X-Loki-Token": token}

            status, body = request("GET", "/api/status", headers=auth)
            self.assertEqual(status, 200)
            home = json.loads(body)
            self.assertEqual(home["phase"], "home")
            self.assertEqual([v["vault"] for v in home["vaults"]], [vault])
            self.assertEqual(home["vaults"][0]["name"], "Treasury Reserve")
            self.assertEqual(home["vaults"][0]["threshold"], 2)
            self.assertEqual(home["vaults"][0]["members"], 3)

            # Per-vault phase: the screen fetches /api/status?vault=<id>. A
            # draft-only fixture has no setup-exchange files, so the real route
            # answers a clean JSON error — ui.js:vaultPhase catches it and shows
            # "unavailable" rather than breaking the list.
            status, body = request("GET", f"/api/status?vault={vault}", headers=auth)
            self.assertEqual(status, 400)
            self.assertIn("error", json.loads(body))

            # No token → the route the screen uses is refused.
            status, _ = request("GET", "/api/status", headers={"X-Loki-Token": "wrong"})
            self.assertEqual(status, 403)

    def test_create_vault_screen_calls_real_create_route(self):
        """The 03 Create screen posts /api/create with {name, members, threshold}.
        Native keygen is stubbed; the route, body shape and token auth are real."""
        with tempfile.TemporaryDirectory(prefix="loki-ui-create-") as temp:
            wallet, _ = make_vault(temp)
            self.addCleanup(wallet.close)
            token, request = serve(self, wallet)

            seen = {}

            def fake_create(name, members=3, threshold=2):
                seen.update(name=name, members=members, threshold=threshold)
                return {"vault": "c" * 64, "invites": ["loki/invite:x", "loki/invite:y"]}

            with patch.object(wallet, "create", side_effect=fake_create):
                status, body = request("POST", "/api/create",
                                       {"name": "Ops Float", "members": 4, "threshold": 3},
                                       {"X-Loki-Token": token})
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(body)["vault"], "c" * 64)
            self.assertEqual(seen, {"name": "Ops Float", "members": 4, "threshold": 3})

            # The same POST without the private token is refused.
            status, _ = request("POST", "/api/create",
                                {"name": "x", "members": 3, "threshold": 2},
                                {"X-Loki-Token": "wrong"})
            self.assertEqual(status, 403)


if __name__ == "__main__":
    unittest.main()
