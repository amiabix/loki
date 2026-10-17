import importlib.util
import json
import tempfile
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen


class PublicIssuerTest(unittest.TestCase):
    def test_authorization_and_retry(self):
        path = Path(__file__).with_name("loki-public-issuer.py")
        spec = importlib.util.spec_from_file_location("loki_public_issuer", path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            token = "a" * 64
            secret = root / "issuer-access-token"
            secret.write_text(token)
            secret.chmod(0o600)
            server = module.make_server(root, 0)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                url = f"http://127.0.0.1:{server.server_port}/grant"
                payload = json.dumps({"device_key": "b" * 64, "policy": "2-of-3",
                                      "bundle_sha256": "c" * 64}).encode()

                def post(auth, data=payload):
                    request = Request(url, data=data, headers={"Content-Type": "application/json",
                                                                 "Authorization": auth}, method="POST")
                    try:
                        with urlopen(request, timeout=2) as response:
                            return response.status, response.read()
                    except HTTPError as error:
                        try:
                            return error.code, error.read()
                        finally:
                            error.close()

                with patch.object(module.subprocess, "run", return_value=SimpleNamespace(
                    returncode=0, stdout=b"signed-grant")) as issue:
                    self.assertEqual(post("Bearer wrong")[0], 403)
                    self.assertEqual(post("Bearer " + token, b"{}")[0], 400)
                    self.assertEqual(post("Bearer " + token), (200, b"signed-grant"))
                    self.assertEqual(post("Bearer " + token), (200, b"signed-grant"))
                    self.assertEqual(issue.call_count, 1)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
