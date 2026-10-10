import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
import sys
from types import SimpleNamespace


class ExistingVaultTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.source = self.base / 'source'
        self.source.mkdir()
        members = []
        for member_id in (1, 2, 3):
            root = self.source / 'members' / str(member_id)
            (root / 'secrets').mkdir(parents=True)
            for name in ('identity.sealed', 'vault.sealed'):
                (root / 'secrets' / name).write_bytes(bytes([member_id]) * 100)
            (root / 'passphrase').write_bytes(b'fixture passphrase\n')
            members.append({'id': member_id, 'signing': f'{member_id:02x}' * 32,
                            'encryption': f'{member_id + 3:02x}' * 32})
        (self.source / 'roster.json').write_text(json.dumps({'vault': '07' * 32,
                                                           'members': members}))

    def harness(self):
        spec = importlib.util.find_spec('three_members')
        self.assertIsNotNone(spec, 'Existing-vault three-environment harness is missing')
        import three_members
        return three_members

    def test_copy_preserves_existing_identity_and_excludes_transport(self):
        harness = self.harness()
        old_transport = self.source / 'members/1/transport'
        old_transport.mkdir()
        (old_transport / 'old').write_bytes(b'old transport')
        destination = self.base / 'new'
        destination.mkdir()
        members, roster, hashes = harness.copy_vault(self.source, destination)
        self.assertEqual([member.member_id for member in members], [1, 2, 3])
        self.assertEqual(json.loads(roster.read_text())['vault'], '07' * 32)
        self.assertEqual(len(hashes), 10)
        for member in members:
            self.assertEqual((member.root / 'secrets/vault.sealed').read_bytes(),
                             bytes([member.member_id]) * 100)
            self.assertFalse((member.root / 'transport').exists())
            self.assertEqual(member.passphrase_file.stat().st_mode & 0o777, 0o600)
            self.assertEqual(member.root.stat().st_mode & 0o777, 0o700)
        harness.verify_source(hashes)
        (self.source / 'members/1/secrets/vault.sealed').write_bytes(b'changed')
        with self.assertRaises(harness.run.OwnershipError):
            harness.verify_source(hashes)

    def test_symlinked_member_secret_is_refused(self):
        harness = self.harness()
        secret = self.source / 'members/2/secrets/vault.sealed'
        secret.unlink()
        secret.symlink_to(self.source / 'members/1/secrets/vault.sealed')
        destination = self.base / 'new'
        destination.mkdir()
        with self.assertRaises(harness.run.OwnershipError):
            harness.copy_vault(self.source, destination)

    def test_overlapping_source_is_refused(self):
        harness = self.harness()
        with self.assertRaises(harness.run.OwnershipError):
            harness.copy_vault(self.source, self.source / 'new')

    def test_duplicate_member_identity_is_refused(self):
        harness = self.harness()
        path = self.source / 'roster.json'
        roster = json.loads(path.read_text())
        roster['members'][1]['signing'] = roster['members'][0]['signing']
        path.write_text(json.dumps(roster))
        destination = self.base / 'new'
        destination.mkdir()
        with self.assertRaises(harness.run.OwnershipError):
            harness.copy_vault(self.source, destination)

    def test_large_status_capture_remains_bounded(self):
        harness = self.harness()
        owner = harness.MemberEnvironments.create(self.base / 'capture')
        self.addCleanup(owner.close)
        ordinary = harness.run.OwnedRun.create(self.base / 'ordinary-capture')
        self.addCleanup(ordinary.close)
        with self.assertRaises(harness.run.OwnershipError):
            ordinary.capture([sys.executable, '-c', 'print("x" * 70000)'],
                             cwd=ordinary.root, timeout=5, output_limit=65536)
        output = owner.capture([sys.executable, '-c', 'print("x" * 70000)'],
                               cwd=owner.root, timeout=5, output_limit=262144)
        self.assertEqual(len(output.stdout), 70001)
        with self.assertRaises(harness.run.OwnershipError):
            owner.capture([sys.executable, '-c', 'print("x" * 270000)'],
                          cwd=owner.root, timeout=5, output_limit=262144)


class CompletionEvidenceTests(unittest.TestCase):
    def setUp(self):
        import three_members
        self.harness = three_members
        self.context = SimpleNamespace(members=[SimpleNamespace(member_id=i) for i in (1, 2, 3)])
        self.originals = [{'sender': sender, 'id': f'{sender}-{number}',
                           'digest': f'digest-{sender}-{number}', 'session': '-', 'kind': 'test'}
                          for sender in (1, 2, 3) for number in (1, 2)]
        self.snapshots = {i: {'messages': [], 'incoming': [], 'acks': [], 'pending_transfers': 0}
                          for i in (1, 2, 3)}
        self.acknowledgements = []
        for original in self.originals:
            sender = original['sender']
            self.snapshots[sender]['messages'].append({
                **original, 'readiness': 'ready', 'received_whole': 1, 'received_author': 1,
                'received_members': {1: int(sender != 1), 2: int(sender != 2), 3: int(sender != 3)}})
            for peer in (1, 2, 3):
                if peer == sender:
                    continue
                self.snapshots[peer]['incoming'].append({**original, 'readiness': 'ready'})
                ack_id = f"ack-{original['id']}-{peer}"
                self.snapshots[peer]['acks'].append({**original, 'author': peer, 'ack_message': ack_id})
                self.acknowledgements.append({'author': peer, 'ack_message': ack_id,
                                             'original_id': original['id'],
                                             'received_digest': 'received-' + ack_id})
                self.snapshots[sender]['incoming'].append({'id': ack_id, 'sender': peer,
                                                           'digest': 'received-' + ack_id,
                                                           'kind': 'received'})

    def check(self):
        self.harness.require_complete(self.context, self.snapshots, self.originals, self.acknowledgements)

    def test_six_originals_require_twelve_peer_acknowledgements(self):
        self.check()
        self.snapshots[2]['acks'].pop()
        with self.assertRaises(self.harness.run.OwnershipError):
            self.check()

    def test_self_acknowledgement_cannot_replace_peer_acknowledgement(self):
        self.snapshots[2]['acks'][0]['author'] = 1
        with self.assertRaises(self.harness.run.OwnershipError):
            self.check()

    def test_duplicate_original_cannot_replace_missing_original(self):
        self.originals[5] = self.originals[4]
        with self.assertRaises(self.harness.run.OwnershipError):
            self.check()

    def test_missing_received_return_path_is_not_success(self):
        self.snapshots[1]['incoming'] = [row for row in self.snapshots[1]['incoming']
                                         if row['kind'] != 'received']
        with self.assertRaises(self.harness.run.OwnershipError):
            self.check()

    def test_pending_peer_original_is_not_success(self):
        self.snapshots[2]['incoming'][0]['readiness'] = 'pending'
        with self.assertRaises(self.harness.run.OwnershipError):
            self.check()

    def test_wrong_acknowledged_body_is_not_success(self):
        self.snapshots[2]['acks'][0]['digest'] = 'wrong-body'
        with self.assertRaises(self.harness.run.OwnershipError):
            self.check()

    def test_pending_outgoing_bookkeeping_does_not_override_received_evidence(self):
        for current in self.snapshots.values():
            current['pending_transfers'] = 18
        self.check()


if __name__ == '__main__':
    unittest.main()
