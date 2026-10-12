"""Public relay projection. Schema fixtures are not live delivery evidence."""

import json
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import relay_observation


MESSAGE = "ab" * 32
OTHER = "cd" * 32


class ProjectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.projection = relay_observation.RelayProjection(
            "demo-1", cache_dir=Path(self.temp.name))

    def event(self, sequence, event_type, **fields):
        event = {
            "version": 1,
            "run_id": "demo-1",
            "producer_id": "member-1",
            "producer_sequence": sequence,
            "observed_at": "2026-10-11T00:00:00Z",
            "event_type": event_type,
        }
        event.update(fields)
        return event

    def committed_snapshot(self):
        return [{
            "version": 1, "snapshot_id": "generation-1", "member": 1, "owner": 1,
            "section": "logical", "after": "0", "next": "1", "complete": True,
            "run_id": "demo-1", "config_revision": 3, "config_hash": "ef" * 32,
            "gap_count": 0, "rows": [{
                "message_id": MESSAGE, "state": "committed", "count": 2,
            }],
        }]

    def test_snapshot_does_not_fill_missing_request_history(self):
        self.projection.ingest(self.event(1, "request_start"))
        self.projection.ingest(self.event(3, "original_committed"))
        self.projection.apply_snapshot(self.committed_snapshot())
        result = self.projection.events("admin", 0)
        self.assertTrue(result["gap"])
        self.assertFalse(any(event["event_type"] == "request_end" for event in result["events"]))
        again = self.projection.events("admin", 0)
        self.assertEqual([event["event_type"] for event in again["events"]],
                         ["request_start", "original_committed"])

    def test_receipt_commit_is_distinct_from_request_response(self):
        self.projection.ingest(self.event(1, "request_end", http_status=200))
        self.projection.ingest(self.event(2, "receipt_validated", receipt_digest="aa" * 32))
        self.assertEqual(self.projection.state("admin")["stored"], 0)
        self.projection.ingest(self.event(3, "receipt_persisted", receipt_digest="bb" * 32))
        self.assertEqual(self.projection.state("admin")["stored"], 1)
        self.assertEqual(self.projection.state("admin")["application_accepted"], 0)

    def test_transport_milestones_stay_distinct_from_approval(self):
        self.projection.ingest(self.event(1, "original_authenticated", message_id=MESSAGE))
        self.projection.ingest(self.event(2, "received_linked", message_id=MESSAGE))
        state = self.projection.state("admin")
        self.assertEqual(state["saved"], 1)
        self.assertEqual(state["received"], 1)
        self.assertEqual(state["approved"], 0)
        self.projection.ingest(self.event(3, "application_accepted", message_id=MESSAGE, kind=4))
        self.projection.ingest(self.event(4, "approved", message_id=MESSAGE, kind=4))
        state = self.projection.state("admin")
        self.assertEqual(state["application_accepted"], 1)
        self.assertEqual(state["approved"], 1)
        self.assertEqual(state["saved"], 1)

    def test_standby_relay_is_not_a_failed_relay(self):
        self.projection.note_lifecycle("relay_standby", relay=3)
        self.projection.note_lifecycle("relay_failed", relay=1)
        state = self.projection.state("admin")
        self.assertEqual(state["relays"]["3"]["status"], "standby")
        self.assertEqual(state["relays"]["1"]["status"], "failed")
        native = [event for event in self.projection.events("admin", 0)["events"]
                  if event["origin"] == "native"]
        self.assertEqual(native, [])
        self.assertTrue(all(event["origin"] == "controller"
                            for event in self.projection.events("admin", 0)["events"]))

    def test_gap_recovery_restores_status_without_fake_traffic(self):
        self.projection.ingest(self.event(1, "request_start", message_id=MESSAGE))
        before = len(self.projection.events("admin", 0)["events"])
        self.projection.apply_snapshot(self.committed_snapshot())
        self.assertEqual(len(self.projection.events("admin", 0)["events"]), before)
        self.assertEqual(self.projection.state("admin")["logical_committed"], 1)

    def test_duplicate_producer_sequence_is_ignored(self):
        self.projection.ingest(self.event(1, "request_start", request_id=7))
        self.projection.ingest(self.event(1, "request_end", request_id=8))
        result = self.projection.events("admin", 0)
        self.assertEqual(len(result["events"]), 1)
        self.assertEqual(result["events"][0]["event_type"], "request_start")

    def test_role_filter_uses_a_global_cursor(self):
        self.projection.ingest(self.event(1, "request_start", actor_member=2, recipient_member=2))
        self.projection.ingest(self.event(2, "request_start", actor_member=1, recipient_member=1))
        alice = self.projection.events("alice", 0)
        self.assertEqual(len(alice["events"]), 1)
        self.assertEqual(alice["events"][0]["actor_member"], 1)
        self.assertGreaterEqual(alice["next"], 2)
        self.assertEqual(self.projection.events("alice", alice["next"])["events"], [])
        admin = self.projection.events("admin", 0)
        self.assertEqual(len(admin["events"]), 2)

    def test_carol_sees_its_native_events_and_public_lifecycle(self):
        self.projection.ingest(self.event(1, "request_start", actor_member=1, recipient_member=2))
        self.projection.ingest(self.event(2, "request_start", actor_member=3, recipient_member=2))
        self.projection.note_lifecycle("relay_stopped", relay=1)
        carol = self.projection.events("carol", 0)
        self.assertEqual([event["event_type"] for event in carol["events"]],
                         ["request_start", "relay_stopped"])
        self.assertEqual(carol["events"][0]["actor_member"], 3)
        self.assertEqual(self.projection.state("carol")["relays"]["1"]["status"], "stopped")

    def test_alice_objects_hide_bob_copies(self):
        pages = [{
            "version": 1, "snapshot_id": "generation-1", "member": 1, "owner": 1,
            "section": "objects", "after": "0", "next": "2", "complete": True,
            "run_id": "demo-1", "config_revision": 3, "config_hash": "ef" * 32,
            "gap_count": 0, "rows": [
                {"message_id": MESSAGE, "recipient_member": 1, "object_hash": "11" * 32,
                 "object_ordinal": 1, "wire_bytes": 4},
                {"message_id": MESSAGE, "recipient_member": 2, "object_hash": "22" * 32,
                 "object_ordinal": 1, "wire_bytes": 4},
                {"message_id": OTHER, "recipient_member": 1, "object_hash": "33" * 32,
                 "object_ordinal": 1, "wire_bytes": 4},
            ],
        }]
        self.projection.apply_snapshot(pages)
        alice = self.projection.objects("alice", MESSAGE, 0, 100)
        self.assertEqual([row["recipient_member"] for row in alice["rows"]], [1])
        self.assertNotIn("22" * 32, json.dumps(alice))
        bob = self.projection.objects("bob", MESSAGE, 0, 100)
        self.assertEqual([row["recipient_member"] for row in bob["rows"]], [2])
        with self.assertRaises(relay_observation.Forbidden):
            self.projection.objects("bob", OTHER, 0, 100)
        with self.assertRaises(relay_observation.Missing):
            self.projection.objects("admin", "ee" * 32, 0, 100)

    def test_oversized_event_is_rejected(self):
        huge = self.event(1, "request_start", message_id="m" * 20000)
        with self.assertRaises(relay_observation.Rejected):
            self.projection.ingest(huge)

    def test_evidence_is_stale_after_ten_seconds(self):
        self.projection.ingest(self.event(1, "request_start"))
        self.assertEqual(self.projection.state("admin")["freshness"], "live")
        self.projection.fresh_at = time.monotonic() - 11
        self.assertEqual(self.projection.state("admin")["freshness"], "stale")

    def test_responses_are_copies(self):
        self.projection.ingest(self.event(1, "request_start", actor_member=1))
        first = self.projection.events("admin", 0)
        first["events"][0]["actor_member"] = 9
        second = self.projection.events("admin", 0)
        self.assertEqual(second["events"][0]["actor_member"], 1)


class CachedApiTests(unittest.TestCase):
    def flow(self):
        import member_demo
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        with patch.object(member_demo, "ROOT", root), patch.object(member_demo, "RUN", root / "run"):
            flow = member_demo.Flow()
        flow.relay.projection = relay_observation.RelayProjection("demo-1", cache_dir=root)
        flow.relay.projection.ingest({
            "version": 1, "run_id": "demo-1", "producer_id": "member-1",
            "producer_sequence": 1, "observed_at": "2026-10-11T00:00:00Z",
            "event_type": "request_start", "actor_member": 1, "recipient_member": 1,
            "message_id": MESSAGE,
        })
        return flow, member_demo

    def get(self, flow, member_demo, path, token):
        from types import SimpleNamespace
        handler = member_demo.Handler.__new__(member_demo.Handler)
        handler.path = path
        handler.headers = {"X-Loki-Token": token}
        handler.server = SimpleNamespace(server_port=8790)
        captured = {}

        def send(code, data, ctype):
            del ctype
            captured["code"] = code
            captured["body"] = json.loads(data)

        handler.send = send
        with patch.object(member_demo, "FLOW", flow):
            handler.do_GET()
        return captured

    def test_get_reads_the_cache_and_starts_no_subprocess(self):
        import subprocess
        flow, member_demo = self.flow()
        spawned = []
        with patch.object(subprocess, "Popen", side_effect=lambda *args, **kwargs: spawned.append(args)):
            state = self.get(flow, member_demo, "/api/relay/state", flow.tokens["carol"])
            events = self.get(flow, member_demo, "/api/relay/events?after=0", flow.tokens["alice"])
            missing = self.get(flow, member_demo, f"/api/relay/messages/{OTHER}/objects?after=0&limit=100",
                               flow.tokens["carol"])
            invalid = self.get(flow, member_demo, "/api/relay/events?after=nope", flow.tokens["carol"])
        self.assertEqual(spawned, [])
        self.assertEqual(state["code"], 200)
        self.assertEqual(events["code"], 200)
        self.assertEqual(len(events["body"]["events"]), 1)
        self.assertEqual(missing["code"], 404)
        self.assertEqual(invalid["code"], 400)
        hidden = self.get(flow, member_demo, "/api/relay/state", flow.tokens["bob"])
        self.assertEqual(hidden["code"], 200)
        self.assertNotIn(MESSAGE, json.dumps(hidden["body"]))

    def post(self, flow, member_demo, path, token, body):
        from io import BytesIO
        from types import SimpleNamespace
        handler = member_demo.Handler.__new__(member_demo.Handler)
        payload = json.dumps(body).encode()
        handler.path = path
        handler.headers = {
            "Origin": "http://127.0.0.1:8790", "Content-Type": "application/json",
            "Content-Length": str(len(payload)), "X-Loki-Token": token,
        }
        handler.rfile = BytesIO(payload)
        handler.server = SimpleNamespace(server_port=8790)
        captured = {}

        def send(code, data, ctype):
            del ctype
            captured["code"] = code
            captured["body"] = json.loads(data)

        handler.json = lambda code, value: captured.update(code=code, body=value)
        handler.send = send
        with patch.object(member_demo, "FLOW", flow):
            handler.do_POST()
        return captured

    def test_creator_actions_are_fixed_and_pause_of_a_signer_is_busy(self):
        from types import SimpleNamespace
        flow, member_demo = self.flow()
        flow.creator = "carol"
        flow.leases.reserve(1, "sign")
        busy = self.post(flow, member_demo, "/api/relay/member", flow.tokens["carol"],
                         {"member": 1, "action": "pause"})
        self.assertEqual(busy["code"], 400)
        self.assertIn("busy", busy["body"]["error"])
        denied = self.post(flow, member_demo, "/api/relay/restart", flow.tokens["alice"],
                           {"relay": 1})
        self.assertEqual(denied["code"], 403)
        child = SimpleNamespace(stopped=False)

        def stop(process, timeout=2.0):
            del timeout
            process.stopped = True

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        flow.relay.owner = SimpleNamespace(
            root=Path(temporary.name), _children=[], stop=stop, close=lambda: None)
        flow.relay.context = SimpleNamespace(relays=[
            SimpleNamespace(child=None, run_id="run-1"),
            SimpleNamespace(child=child, run_id="run-2"),
            SimpleNamespace(child=None, run_id="run-3"),
        ])
        restarted = []
        with patch.object(member_demo.run, "restart_relay",
                          lambda owner, relay, server, deadline: restarted.append(relay.run_id)):
            accepted = self.post(flow, member_demo, "/api/relay/restart", flow.tokens["carol"],
                                 {"relay": 2})
        self.assertEqual(accepted["code"], 200)
        self.assertEqual(restarted, ["run-2"])
        stopped = self.post(flow, member_demo, "/api/relay/stop", flow.tokens["carol"], {"relay": 2})
        self.assertEqual(stopped["code"], 200)
        self.assertTrue(child.stopped)
        self.assertEqual(flow.chain_start_calls if hasattr(flow, "chain_start_calls") else 0, 0)
        self.assertEqual(flow.relay.chain_start_calls, 0)


if __name__ == "__main__":
    unittest.main()
