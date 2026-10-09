"""The demo uses the current binary and rejects cross-origin run requests."""

import os
import tempfile
import unittest
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import runner
import server


class BinaryLookupTest(unittest.TestCase):
    def test_default_prefers_repo_build_over_legacy_tmp_binary(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary = root / "target" / "debug" / "loki"
            binary.parent.mkdir(parents=True)
            binary.write_text("test executable")
            binary.chmod(0o755)
            with patch.object(runner, "POC", root), patch.dict(os.environ, {}, clear=True):
                self.assertEqual(runner.loki_bin(), binary)

    def test_explicit_cargo_target_takes_precedence(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary = root / "custom" / "debug" / "loki"
            binary.parent.mkdir(parents=True)
            binary.write_text("test executable")
            binary.chmod(0o755)
            with patch.object(runner, "POC", root), patch.dict(os.environ, {"CARGO_TARGET_DIR": str(root / "custom")}):
                self.assertEqual(runner.loki_bin(), binary)


class RunEndpointTest(unittest.TestCase):
    def request(self, origin, content_type):
        handler = server.Handler.__new__(server.Handler)
        handler.path = "/api/run"
        handler.headers = {"Origin": origin, "Content-Type": content_type, "Content-Length": "16"}
        handler.server = SimpleNamespace(server_port=8787)
        handler.rfile = BytesIO(b'{"step":"reset"}')
        handler._json = Mock()
        with patch.object(server.RUNNER, "start") as start:
            handler.do_POST()
            return handler._json.call_args.args[0], start.call_count

    def test_foreign_page_cannot_start_a_step(self):
        self.assertEqual(self.request("https://example.org", "application/json"), (403, 0))

    def test_simple_form_content_type_cannot_start_a_step(self):
        self.assertEqual(self.request("http://127.0.0.1:8787", "text/plain"), (415, 0))

    def test_same_origin_json_can_start_a_step(self):
        self.assertEqual(self.request("http://127.0.0.1:8787", "application/json"), (200, 1))


if __name__ == "__main__":
    unittest.main()
