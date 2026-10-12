"""Cached public relay evidence. Browser handlers read this and do not open a member store."""

from __future__ import annotations

import copy
import json
import threading
import time
from pathlib import Path

MAX_EVENTS = 10000
MAX_BYTES = 8 * 1024 * 1024
MAX_EVENT_BYTES = 16 * 1024
PAGE_LIMIT = 100
FRESH_SECONDS = 10

NATIVE_TYPES = {
    "request_start", "request_end", "receipt_validated", "receipt_persisted",
    "receipt_rejected", "original_authenticated", "original_committed",
    "received_linked", "retry_due", "route_failure", "quarantine",
    "session_envelope_authenticated", "application_accepted", "application_rejected",
    "approved",
}
LIFECYCLE_TYPES = {"relay_standby", "relay_failed", "relay_stopped", "member_paused", "member_offline"}
FIELDS = {
    "version", "run_id", "producer_id", "producer_sequence", "observed_at", "event_type",
    "actor_member", "authenticated_sender", "recipient_member", "relay_pin", "relay_run",
    "mailbox_id", "message_id", "message_digest", "object_hash", "object_ordinal",
    "wire_bytes", "request_id", "http_status", "duration_ms", "result_code", "receipt_digest",
    "gap_count", "kind", "envelope_hash", "vault_id", "payment_id", "attempt_id", "origin",
    "sequence", "relay",
}
SECTIONS = {
    "logical", "recipients", "objects", "receipts", "incoming",
    "acknowledgements", "rejections", "application",
}
ROLES = {"admin": None, "alice": 1, "bob": 2, "carol": 3}


class Rejected(ValueError):
    """The event or snapshot page is not public evidence."""


class Forbidden(PermissionError):
    """This role cannot see the requested object copies."""


class Missing(LookupError):
    """The authorized message is not in the cached inventory."""


def _token(value) -> bool:
    return isinstance(value, str) and 0 < len(value) <= 64 and all(
        character.isalnum() or character in "-_" for character in value)


def _public(value) -> bool:
    if value is None or isinstance(value, (bool, int, float)):
        return True
    if isinstance(value, str):
        return len(value) <= 128 and all(32 <= ord(character) <= 126 for character in value)
    return False


class RelayProjection:
    """One run of public events and snapshot evidence. Responses are copies."""

    def __init__(self, run_id: str, cache_dir=None):
        if not _token(run_id):
            raise Rejected("run_id")
        self.run_id = run_id
        self.cache_dir = Path(cache_dir) if cache_dir is not None else None
        self._lock = threading.Lock()
        self._events = []
        self._bytes = 0
        self._next = 1
        self._seen = set()
        self._producers = {}
        self._gap = False
        self._objects = {}
        self._logical_committed = 0
        self._counts = {
            "saved": 0, "stored": 0, "received": 0,
            "application_accepted": 0, "approved": 0,
        }
        self._relays = {str(index): {"status": "standby"} for index in (1, 2, 3)}
        self._members = {str(index): {"status": "idle"} for index in (1, 2, 3)}
        self.fresh_at = None

    def ingest(self, event: dict) -> None:
        if (isinstance(event, dict) and self.run_id == "pending"
                and _token(str(event.get("run_id", "")))):
            with self._lock:
                if self.run_id == "pending" and not self._events:
                    self.run_id = event["run_id"]
        encoded = self._validate_native(event)
        with self._lock:
            key = (event["producer_id"], event["producer_sequence"])
            if key in self._seen:
                return
            seen = self._producers.setdefault(event["producer_id"], set())
            expected = (max(seen) + 1) if seen else 1
            if event["producer_sequence"] != expected:
                self._gap = True
            seen.add(event["producer_sequence"])
            self._seen.add(key)
            self._append(self._native_record(event), encoded)
            self._count(event["event_type"])
            self.fresh_at = time.monotonic()

    def note_lifecycle(self, event_type: str, **fields) -> None:
        if event_type not in LIFECYCLE_TYPES:
            raise Rejected("event_type")
        record = {
            "version": 1, "run_id": self.run_id, "producer_id": "controller",
            "producer_sequence": 0, "observed_at": "", "event_type": event_type,
            "origin": "controller",
        }
        record.update(fields)
        if not all(_public(value) for value in fields.values()):
            raise Rejected("event_field")
        encoded = len(json.dumps(record).encode())
        if encoded > MAX_EVENT_BYTES:
            raise Rejected("event_bounds")
        with self._lock:
            record["producer_sequence"] = self._next
            self._append(record, encoded)
            relay = fields.get("relay")
            member = fields.get("member")
            if event_type == "relay_standby" and relay in (1, 2, 3):
                self._relays[str(relay)]["status"] = "standby"
            elif event_type == "relay_stopped" and relay in (1, 2, 3):
                self._relays[str(relay)]["status"] = "stopped"
            elif event_type == "relay_failed" and relay in (1, 2, 3):
                self._relays[str(relay)]["status"] = "failed"
            elif event_type == "member_paused" and member in (1, 2, 3):
                self._members[str(member)]["status"] = "paused"
            elif event_type == "member_offline" and member in (1, 2, 3):
                self._members[str(member)]["status"] = "offline"
            self.fresh_at = time.monotonic()

    def apply_snapshot(self, pages: list) -> None:
        if not isinstance(pages, list) or not pages:
            raise Rejected("snapshot")
        checked = [self._validate_page(page) for page in pages]
        identity = (checked[0]["snapshot_id"], checked[0]["run_id"],
                    checked[0]["config_revision"], checked[0]["member"])
        if any((page["snapshot_id"], page["run_id"], page["config_revision"], page["member"]) != identity
               for page in checked):
            raise Rejected("snapshot_identity")
        with self._lock:
            objects = dict(self._objects)
            logical = self._logical_committed
            for page in checked:
                if page["section"] == "objects":
                    for row in page["rows"]:
                        message = row.get("message_id")
                        if not isinstance(message, str) or len(message) != 64:
                            raise Rejected("message_id")
                        objects.setdefault(message, [])
                        if row not in objects[message]:
                            objects[message].append(copy.deepcopy(row))
                elif page["section"] == "logical":
                    logical = sum(1 for row in page["rows"] if row.get("state") == "committed")
            self._objects = objects
            self._logical_committed = logical
            self._write_objects()
            self.fresh_at = time.monotonic()

    def state(self, role: str) -> dict:
        member = self._role(role)
        with self._lock:
            messages = []
            for message, rows in self._objects.items():
                visible = [row for row in rows if member is None or row.get("recipient_member") == member
                           or row.get("actor_member") == member]
                if visible:
                    messages.append(message)
            freshness = "unknown"
            if self.fresh_at is not None:
                freshness = "stale" if time.monotonic() - self.fresh_at > FRESH_SECONDS else "live"
            return {
                "run_id": self.run_id,
                "freshness": freshness,
                "gap": self._gap,
                "saved": self._counts["saved"],
                "stored": self._counts["stored"],
                "received": self._counts["received"],
                "application_accepted": self._counts["application_accepted"],
                "approved": self._counts["approved"],
                "logical_committed": self._logical_committed,
                "relays": copy.deepcopy(self._relays),
                "members": copy.deepcopy(self._members),
                "messages": messages,
            }

    def events(self, role: str, after: int) -> dict:
        if type(after) is not int or after < 0:
            raise Rejected("cursor")
        member = self._role(role)
        with self._lock:
            gap = self._gap or (bool(self._events) and after < self._events[0]["sequence"] - 1 and after != 0)
            if self._events and after != 0 and after < self._events[0]["sequence"]:
                gap = True
            visible = []
            examined = after
            for event in self._events:
                if event["sequence"] <= after:
                    continue
                examined = event["sequence"]
                if self._visible(event, member):
                    visible.append(copy.deepcopy(event))
                if len(visible) == PAGE_LIMIT:
                    break
            return {"events": visible, "next": examined, "gap": gap}

    def objects(self, role: str, message_id: str, after: int, limit: int) -> dict:
        if not isinstance(message_id, str) or len(message_id) != 64 or any(
                character not in "0123456789abcdef" for character in message_id):
            raise Rejected("message_id")
        if type(after) is not int or after < 0 or type(limit) is not int or not 1 <= limit <= PAGE_LIMIT:
            raise Rejected("page")
        member = self._role(role)
        with self._lock:
            if message_id not in self._objects:
                raise Missing(message_id)
            rows = [row for row in self._objects[message_id]
                    if member is None or row.get("recipient_member") == member
                    or row.get("actor_member") == member]
            if member is not None and not rows:
                raise Forbidden(message_id)
            page = rows[after:after + limit]
            return {
                "message_id": message_id, "after": after, "next": after + len(page),
                "complete": after + len(page) >= len(rows), "rows": copy.deepcopy(page),
            }

    def _role(self, role: str):
        if role not in ROLES:
            raise Forbidden(role)
        return ROLES[role]

    def _visible(self, event: dict, member) -> bool:
        if member is None or event.get("origin") == "controller":
            return True
        return event.get("actor_member") == member or event.get("recipient_member") == member

    def _count(self, event_type: str) -> None:
        if event_type == "original_authenticated":
            self._counts["saved"] += 1
        elif event_type == "receipt_persisted":
            self._counts["stored"] += 1
        elif event_type == "received_linked":
            self._counts["received"] += 1
        elif event_type == "application_accepted":
            self._counts["application_accepted"] += 1
        elif event_type == "approved":
            self._counts["approved"] += 1

    def _append(self, record: dict, encoded: int) -> None:
        record = copy.deepcopy(record)
        record["sequence"] = self._next
        self._next += 1
        self._events.append(record)
        self._bytes += encoded
        while len(self._events) > MAX_EVENTS or self._bytes > MAX_BYTES:
            dropped = self._events.pop(0)
            self._bytes -= len(json.dumps(dropped).encode())
            self._gap = True

    def _native_record(self, event: dict) -> dict:
        record = copy.deepcopy(event)
        record["origin"] = "native"
        return record

    def _validate_native(self, event: dict) -> int:
        if not isinstance(event, dict):
            raise Rejected("event")
        encoded = json.dumps(event).encode()
        if len(encoded) > MAX_EVENT_BYTES:
            raise Rejected("event_bounds")
        if event.get("version") != 1 or event.get("run_id") != self.run_id:
            raise Rejected("event_identity")
        if event.get("event_type") not in NATIVE_TYPES or not _token(event.get("producer_id")):
            raise Rejected("event_type")
        sequence = event.get("producer_sequence")
        if type(sequence) is not int or sequence < 1:
            raise Rejected("producer_sequence")
        observed = event.get("observed_at")
        if not isinstance(observed, str) or len(observed) > 40:
            raise Rejected("observed_at")
        for name, value in event.items():
            if name not in FIELDS or not _public(value):
                raise Rejected("event_field")
        return len(encoded)

    def _validate_page(self, page: dict) -> dict:
        if not isinstance(page, dict):
            raise Rejected("snapshot")
        if page.get("version") != 1 or page.get("run_id") != self.run_id:
            raise Rejected("snapshot_identity")
        if not _token(str(page.get("snapshot_id", ""))) or page.get("section") not in SECTIONS:
            raise Rejected("snapshot")
        if page.get("member") not in (1, 2, 3) or page.get("owner") != page.get("member"):
            raise Rejected("snapshot")
        if type(page.get("config_revision")) is not int:
            raise Rejected("snapshot")
        if not isinstance(page.get("rows"), list):
            raise Rejected("snapshot")
        for row in page["rows"]:
            if not isinstance(row, dict) or any(not _public(value) for value in row.values()):
                raise Rejected("snapshot_row")
        return page

    def _write_objects(self) -> None:
        if self.cache_dir is None:
            return
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self._objects).encode()
        if len(payload) > MAX_BYTES:
            raise Rejected("cache")
        path = self.cache_dir / "objects.json"
        path.write_bytes(payload)
        path.chmod(0o644)
