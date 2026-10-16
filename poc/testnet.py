"""Read-only preflight for a locally reachable public Zcash Testnet node."""

import argparse
import http.client
import json
import re
from urllib.parse import urlsplit


GENESIS = "05a60a92d99d85997cce3b87616c089f6124d7342af37106edc76126334a2c38"
NU7_HEIGHT = 4_465_026
NU7_BRANCH = "77190ad9"


def preflight(call):
    if str(call("getblockhash", [0])).lower() != GENESIS:
        raise ValueError("RPC genesis is not the public Zcash Testnet genesis")
    info = call("getblockchaininfo", [])
    if info.get("chain") != "test":
        raise ValueError("RPC chain is not Testnet")
    height, headers = info.get("blocks"), info.get("headers")
    if not isinstance(height, int) or height < NU7_HEIGHT:
        raise ValueError("node has not reached Testnet NU7 activation")
    if not isinstance(headers, int) or headers < height or headers - height > 3:
        raise ValueError("node is behind its known Testnet headers")
    if info.get("initial_block_download_complete") is False:
        raise ValueError("node is still in initial block download")
    branch = str(info.get("consensus", {}).get("nextblock", "")).lower().removeprefix("0x")
    if branch != NU7_BRANCH:
        raise ValueError("node does not report the Testnet NU7 branch for the next block")
    tree = call("z_gettreestate", [str(height)])
    commitments = tree.get("ironwood", {}).get("commitments", {})
    root = commitments.get("finalRoot")
    state = commitments.get("finalState")
    if not ((isinstance(root, str) and re.fullmatch(r"[0-9a-fA-F]{64}", root))
            or (isinstance(state, str) and re.fullmatch(r"(?:[0-9a-fA-F]{2})+", state))):
        raise ValueError("node did not provide the Ironwood tree state")
    return {"network": "testnet", "height": height, "next_branch": branch,
            "ironwood_tree_available": True}


def local_rpc(url):
    endpoint = urlsplit(url)
    if (endpoint.scheme != "http" or endpoint.hostname != "127.0.0.1"
            or endpoint.username or endpoint.password or endpoint.path not in ("", "/")
            or endpoint.query or endpoint.fragment or endpoint.port is None):
        raise ValueError("pass a loopback node URL, such as http://127.0.0.1:18232")

    def call(method, params):
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method,
                           "params": params}).encode()
        connection = http.client.HTTPConnection("127.0.0.1", endpoint.port, timeout=10)
        try:
            connection.request("POST", "/", body, {"Content-Type": "application/json"})
            response = connection.getresponse()
            raw = response.read(1_000_001)
            if response.status != 200 or len(raw) > 1_000_000:
                raise ValueError(f"RPC {method} returned HTTP {response.status} or an oversized response")
            result = json.loads(raw)
            if result.get("error") is not None:
                raise ValueError(f"RPC {method} failed: {result['error']}")
            return result["result"]
        finally:
            connection.close()

    return call


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rpc", required=True, help="local Testnet node or local SSH tunnel URL")
    args = parser.parse_args()
    try:
        print(json.dumps(preflight(local_rpc(args.rpc)), sort_keys=True))
    except (ValueError, OSError, KeyError, json.JSONDecodeError) as error:
        parser.exit(1, f"Testnet preflight failed: {error}\n")


if __name__ == "__main__":
    main()
