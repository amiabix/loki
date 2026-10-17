import importlib.util
import json
import socket
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from urllib.error import HTTPError
from urllib.request import Request, urlopen


class PublicIssuerTest(unittest.TestCase):
    def test_incomplete_clients_cannot_create_unbounded_workers(self):
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
            with patch.object(module, "MAX_REQUESTS", 1, create=True):
                server = module.make_server(root, 0)
            occupied = threading.Event()
            original_process_request = server.process_request

            def process_request(*args):
                original_process_request(*args)
                occupied.set()

            server.process_request = process_request
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            stalled = socket.create_connection(("127.0.0.1", server.server_port))
            try:
                stalled.sendall(b"POST /grant HTTP/1.1\r\nHost: localhost\r\n")
                self.assertTrue(occupied.wait(1))
                payload = json.dumps({"device_key": "b" * 64, "policy": "2-of-3",
                                      "bundle_sha256": "c" * 64}).encode()
                request = Request(f"http://127.0.0.1:{server.server_port}/grant", data=payload,
                                  headers={"Content-Type": "application/json",
                                           "Authorization": "Bearer " + token}, method="POST")
                with patch.object(module.subprocess, "run", return_value=SimpleNamespace(
                    returncode=0, stdout=b"signed-grant")) as issue:
                    try:
                        with urlopen(request, timeout=1) as response:
                            status = response.status
                    except OSError:
                        status = None
                    self.assertIsNone(status)
                    issue.assert_not_called()
            finally:
                stalled.close()
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_concurrent_retries_share_one_grant(self):
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
                payload = json.dumps({"device_key": "b" * 64, "policy": "2-of-3",
                                      "bundle_sha256": "c" * 64}).encode()
                url = f"http://127.0.0.1:{server.server_port}/grant"

                def post():
                    request = Request(url, data=payload, headers={"Content-Type": "application/json",
                                                                 "Authorization": "Bearer " + token}, method="POST")
                    with urlopen(request, timeout=3) as response:
                        return response.status, response.read()

                second_issue = threading.Event()

                def issue_grant(*_args, **_kwargs):
                    number = issue.call_count
                    if number == 1:
                        second_issue.wait(1)
                    else:
                        second_issue.set()
                    return SimpleNamespace(returncode=0, stdout=f"grant-{number}".encode())

                with patch.object(module.subprocess, "run", side_effect=issue_grant) as issue:
                    with ThreadPoolExecutor(max_workers=2) as pool:
                        first = pool.submit(post)
                        second = pool.submit(post)
                        self.assertEqual(first.result(timeout=3), (200, b"grant-1"))
                        self.assertEqual(second.result(timeout=3), (200, b"grant-1"))
                    self.assertEqual(issue.call_count, 1)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

    def test_incomplete_client_does_not_block_enrollment(self):
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
            accepted = threading.Event()
            original_get_request = server.get_request

            def get_request():
                connection = original_get_request()
                accepted.set()
                return connection

            server.get_request = get_request
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            stalled = socket.create_connection(("127.0.0.1", server.server_port))
            try:
                stalled.sendall(b"POST /grant HTTP/1.1\r\nHost: localhost\r\n")
                self.assertTrue(accepted.wait(1))
                payload = json.dumps({"device_key": "b" * 64, "policy": "2-of-3",
                                      "bundle_sha256": "c" * 64}).encode()
                request = Request(f"http://127.0.0.1:{server.server_port}/grant", data=payload,
                                  headers={"Content-Type": "application/json",
                                           "Authorization": "Bearer " + token}, method="POST")
                with patch.object(module.subprocess, "run", return_value=SimpleNamespace(
                    returncode=0, stdout=b"signed-grant")):
                    try:
                        with urlopen(request, timeout=1) as response:
                            result = (response.status, response.read())
                    except TimeoutError:
                        result = None
                self.assertEqual(result, (200, b"signed-grant"))
            finally:
                stalled.close()
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

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
