"""Loopback-only access to a developer-owned THS regtest instance."""

import hashlib
import json
import os
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request


def post(url, body, timeout=300):
    request = urllib.request.Request(url, json.dumps(body).encode(), {"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        raise RuntimeError(f"HTTP {error.code}: {error.read().decode()}") from error


def loopback_url(value):
    parsed = urllib.parse.urlparse(value)
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or not parsed.port
            or parsed.username or parsed.password or parsed.query or parsed.fragment
            or parsed.path not in ("", "/")):
        raise RuntimeError(f"expected a loopback HTTP endpoint, got {value!r}")
    return value.rstrip("/")


class THS:
    def __init__(self, name=None):
        self.name = name or os.environ.get("LOKI_THS_INSTANCE", "loki")
        try:
            result = subprocess.run(
                ["ths", "--name", self.name, "endpoints", "--json"],
                check=True, text=True, capture_output=True, timeout=30,
            )
        except subprocess.CalledProcessError as error:
            raise RuntimeError(error.stderr.strip() or "THS endpoint discovery failed") from error
        self.endpoints = json.loads(result.stdout)
        if self.endpoints.get("network") != "regtest":
            raise RuntimeError("THS instance is not regtest")
        self.rpc_url = loopback_url(self.endpoints["rpc"])
        self.app_url = loopback_url(self.endpoints["dashboard"])
        self.rpc_address = urllib.parse.urlparse(self.rpc_url).netloc

    def rpc(self, method, params=None, timeout=300):
        response = post(self.rpc_url, {"jsonrpc": "2.0", "id": 1,
                        "method": method, "params": params or []}, timeout)
        if response.get("error"):
            raise RuntimeError(f"{method}: {response['error']}")
        return response["result"]

    def check(self):
        info = self.rpc("getblockchaininfo", timeout=10)
        if (info.get("chain") != "test"
                or info.get("upgrades", {}).get("37a5165b", {}).get("status") != "active"
                or info.get("consensus", {}).get("nextblock") != "37a5165b"):
            raise RuntimeError("expected THS regtest with the pinned NU6.3 branch active")
        return info

    def env(self):
        env = dict(os.environ, LOKI_RPC=self.rpc_address)
        env.pop("LOKI_ROUND", None)
        return env

    def fund(self, address, count=1):
        results = []
        digest = hashlib.sha256(address.encode()).hexdigest()[:32]
        for index in range(count):
            result = post(self.app_url + "/api/v1/faucet/address", {
                "address": address, "amount_zatoshi": 100_000_000,
                "idempotency_key": f"loki-{digest}-fund-{index}",
            })
            if result.get("status") != "confirmed" or not result.get("block_hash"):
                raise RuntimeError(f"funding not confirmed; retry the same vault: {result}")
            results.append(result)
        return results

    def mine(self, blocks=3):
        return subprocess.run(["ths", "--name", self.name, "mine", str(blocks), "--json"],
                              check=True, text=True, timeout=600)


if __name__ == "__main__":
    chain = THS()
    command = sys.argv[1]
    if command == "address":
        chain.check()
        print(chain.rpc_address)
    elif command == "rpc":
        print(json.dumps({"result": chain.rpc(sys.argv[2], json.loads(sys.argv[3]))}))
    elif command == "fund":
        print(json.dumps(chain.fund(sys.argv[2], int(sys.argv[3]))))
    elif command == "mine":
        chain.mine(int(sys.argv[2]))
    else:
        raise SystemExit(f"unknown THS helper command: {command}")
