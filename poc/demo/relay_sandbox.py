"""macOS seatbelt for one payment member. The profile is the restriction, not a hint."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path


def write_member_profile(path: Path, denied: list[Path]) -> Path:
    rules = ["(version 1)", "(allow default)"]
    for item in denied:
        resolved = str(Path(item).resolve())
        rules.append(
            "(deny file-read* file-write* (subpath " + json.dumps(resolved) + "))")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(rules) + "\n")
    path.chmod(0o600)
    return path


def _sandbox_cat(profile: Path, target: Path) -> subprocess.CompletedProcess:
    if sys.platform != "darwin" or not Path("/usr/bin/sandbox-exec").is_file():
        raise RuntimeError("macOS sandbox-exec is required")
    return subprocess.run(
        ["/usr/bin/sandbox-exec", "-f", str(profile), "/bin/cat", str(target)],
        capture_output=True, timeout=10, check=False)


def sandbox_allows(profile: Path, target: Path) -> bool:
    result = _sandbox_cat(profile, target)
    return result.returncode == 0 and result.stdout == Path(target).read_bytes()


def sandbox_denies(profile: Path, target: Path) -> bool:
    result = _sandbox_cat(profile, target)
    return result.returncode != 0 and result.stdout == b""


def denial_canary(root: Path) -> dict:
    """Prove mailbox, peer-root, and relay-store denial, then remove that tree."""
    root = Path(root).resolve()
    own = root / "run" / "source" / "member-1"
    peer = root / "run" / "source" / "member-2"
    mailbox = root / "run" / "payment" / "mailbox"
    relay = root / "relay" / "private"
    try:
        for path in (own, peer, mailbox, relay):
            path.mkdir(parents=True, exist_ok=True)
            (path / "canary").write_text(path.name + "\n")
        profile = write_member_profile(
            root / "profiles" / "canary.sb", [peer, mailbox, relay])
        allowed = sandbox_allows(profile, own / "canary")
        denied_peer = sandbox_denies(profile, peer / "canary")
        denied_mailbox = sandbox_denies(profile, mailbox / "canary")
        denied_relay = sandbox_denies(profile, relay / "canary")
        if not (allowed and denied_peer and denied_mailbox and denied_relay):
            raise RuntimeError("member sandbox canary failed")
        return {
            "mailbox_denial": True,
            "peer_denial": True,
            "relay_denial": True,
            "own_read": True,
        }
    finally:
        shutil.rmtree(root / "run", ignore_errors=True)
        shutil.rmtree(root / "relay", ignore_errors=True)
        canary = root / "profiles" / "canary.sb"
        if canary.exists():
            canary.unlink()
