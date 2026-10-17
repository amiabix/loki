"""Opt-in native call timing: `LOKI_TIMING_LOG=<path>` appends one JSON line per call.

Lines carry only the operation name, an 8-character vault prefix, the duration and
the exit code; never arguments, paths or stderr."""
import json
import os
import re
import threading
import time

_lock = threading.Lock()
_VAULT = re.compile(r"(?:^|/)vaults/(\.hosted-)?([0-9a-f]{8})")


def vault_prefix(*paths):
    for path in paths:
        match = _VAULT.search(str(path))
        if match:
            return ("pending-" if match.group(1) else "") + match.group(2)
    return None


_KDF = re.compile(rb"kdf_derivations=(\d+)")


def record(op, started, rc, *paths, stderr=None):
    target = os.environ.get("LOKI_TIMING_LOG")
    if not target:
        return
    row = {"t": time.time(), "op": op, "vault_prefix": vault_prefix(*paths),
           "ms": round((time.monotonic() - started) * 1000, 1), "rc": rc}
    if stderr:
        found = _KDF.search(stderr if isinstance(stderr, bytes) else stderr.encode(errors="replace"))
        if found:
            row["kdf"] = int(found.group(1))
    line = json.dumps(row)
    with _lock, open(target, "a") as output:
        output.write(line + "\n")
