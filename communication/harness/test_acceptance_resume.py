from pathlib import Path
import json
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import acceptance_resume as resume


class AcceptanceResumeTests(unittest.TestCase):
    def test_certified_consent_skips_agreement_and_dkg(self):
        for phase in resume.CERTIFIED:
            state = {'phase': phase, 'agreed_fingerprint': 'a' * 64}
            self.assertFalse(resume.agreement_needed(state, 'a' * 64))
            self.assertEqual(resume.backup_actions(state, words=True, final_card=False), ('finalize',))
            self.assertEqual(resume.backup_actions(state, words=False, final_card=True), ())

    def test_changed_or_missing_consent_and_terminal_states_stop(self):
        for state in ({'phase': 'certified', 'agreed_fingerprint': 'b' * 64},
                      {'phase': 'certified', 'agreed_fingerprint': None},
                      {'phase': 'checkpoint_conflict', 'agreed_fingerprint': 'a' * 64}):
            with self.assertRaises(RuntimeError):
                resume.agreement_needed(state, 'a' * 64)
        self.assertTrue(resume.agreement_needed({'phase': 'roster_proposed'}, 'a' * 64))

    def test_backup_resume_requires_saved_words_and_complete_final_card(self):
        state = {'phase': 'awaiting_backups'}
        self.assertEqual(resume.backup_actions(state, words=False, final_card=False), ('create', 'verify'))
        self.assertEqual(resume.backup_actions(state, words=True, final_card=False), ('verify',))
        with self.assertRaises(RuntimeError):
            resume.backup_actions({'phase': 'certified'}, words=False, final_card=False)
        with self.assertRaises(RuntimeError):
            resume.backup_actions(state, words=True, final_card=True)

    def test_restart_reuses_completed_action_and_preserves_uncertainty(self):
        with tempfile.TemporaryDirectory() as temporary:
            actions = resume.Actions(temporary)
            identity = ['original-attempt', 'original-manifest']
            calls = []
            result = actions.run('broadcast', identity, lambda: calls.append(1) or b'original-txid')
            restarted = resume.Actions(temporary)
            self.assertEqual(restarted.run('broadcast', identity, lambda: calls.append(2)), result)
            self.assertEqual(calls, [1])
            def timeout():
                raise subprocess.TimeoutExpired('finish', 1)
            with self.assertRaises(subprocess.TimeoutExpired):
                actions.run('uncertain-broadcast', identity, timeout)
            with self.assertRaisesRegex(RuntimeError, 'Uncertain'):
                restarted.run('uncertain-broadcast', identity, lambda: calls.append(3))
            self.assertEqual(calls, [1])
            restarted.reconcile('uncertain-broadcast', identity, b'chain-reconciled-txid')
            self.assertEqual(restarted.run('uncertain-broadcast', identity, lambda: b'new-txid'), b'chain-reconciled-txid')
            for path in Path(temporary).iterdir():
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_funding_retry_retains_same_idempotency_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            actions = resume.Actions(temporary)
            identity = ['owned-chain', 'vault-address', 3]
            with self.assertRaises(RuntimeError):
                actions.run('fund', identity, lambda: (_ for _ in ()).throw(RuntimeError('lost response')), idempotent=True)
            result = actions.run('fund', identity, lambda: b'confirmed-same-keys', idempotent=True)
            self.assertEqual(result, b'confirmed-same-keys')
            intent, _ = actions.paths('fund', identity)
            self.assertEqual(json.loads(intent.read_text())['identity'], identity)

    def test_two_controllers_cannot_own_the_same_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            with resume.controller_lock(temporary):
                with self.assertRaises(BlockingIOError):
                    with resume.controller_lock(temporary):
                        self.fail('duplicate controller acquired ownership')
            with resume.controller_lock(temporary):
                pass

    def test_tunnel_reconnects_dead_child_and_reaps_only_owned_process(self):
        with tempfile.TemporaryDirectory() as temporary:
            processes = []
            class Process:
                def __init__(self, argv, **kwargs):
                    self.argv, self.dead, self.terminated = argv, False, False
                    processes.append(self)
                def poll(self): return 0 if self.dead else None
                def terminate(self): self.terminated = True; self.dead = True
                def wait(self, **kwargs): return 0
            with patch.object(resume.subprocess, 'Popen', Process):
                tunnel = resume.RpcTunnel('root@owned', lambda: True, temporary)
                tunnel.ensure()
                processes[0].dead = True
                tunnel.ensure()
                self.assertEqual(len(processes), 2)
                self.assertIn('127.0.0.1:47052:127.0.0.1:18452', processes[-1].argv)
                self.assertIn('ExitOnForwardFailure=yes', processes[-1].argv)
                self.assertIn('ServerAliveInterval=15', processes[-1].argv)
                tunnel.stop()
                self.assertTrue(processes[-1].terminated)

    def test_tunnel_readiness_failure_is_bounded(self):
        with tempfile.TemporaryDirectory() as temporary:
            class Process:
                def poll(self): return 1
            with patch.object(resume.subprocess, 'Popen', return_value=Process()) as popen, \
                    patch.object(resume.time, 'sleep'):
                tunnel = resume.RpcTunnel('root@owned', lambda: False, temporary, attempts=2)
                with self.assertRaisesRegex(RuntimeError, 'unavailable'):
                    tunnel.ensure()
                self.assertEqual(popen.call_count, 2)
                self.assertIsNone(tunnel.process)

    def test_saved_certified_policy_finishes_only_pending_cards(self):
        import importlib.util
        import os
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            root.chmod(0o700)
            (root / 'owner.json').write_text(json.dumps({'purpose': 'native separate-host HTTPS acceptance', 'source_commit': 'source'}))
            (root / 'public-operator.json').write_text(json.dumps({'trusted_key': 'key', 'configuration_sha256': 'digest'}))
            binary = root / 'native-binary'
            binary.write_bytes(b'preserved artifact')
            local = root / 'member-4-1'
            (local / 'secrets').mkdir(parents=True)
            for name in ('identity.sealed', 'hosted-context.sealed'):
                (local / 'secrets' / name).touch()
            env = {'LOKI_ACCEPTANCE_ROOT': str(root), 'LOKI_SETUP_BIN': str(binary), 'LOKI_SOURCE_TREE': 'tree'}
            with patch.dict(os.environ, env):
                spec = importlib.util.spec_from_file_location('native_resume_test', Path(__file__).with_name('native_hosted.py'))
                native = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(native)
            calls = []
            cards = {2}
            class Member(native.Member):
                def exists(self, name):
                    return self.slot in cards if name == 'final-card/vault.card' else True
                def command(self, command, *args, **kwargs):
                    calls.append((self.slot, command))
                    if command in ('setup-invite', 'setup-agree', 'setup-backup-create', 'setup-backup-verify'):
                        raise AssertionError('replayed an earlier phase')
                    if command == 'setup-backup-finalize':
                        cards.add(self.slot)
                        return {'final_card': 'checked'}
                    if command == 'setup-info':
                        return {'fingerprint': 'a' * 64}
                    if command == 'setup-evidence':
                        return {'policy': '2-of-4', 'vault': 'vault', 'fingerprint': 'a' * 64,
                                'address': 'address', 'group_ak': 'group', 'configuration_digest': 'digest',
                                'relays': [], 'handoff': 'ready', 'development': False, 'own_slot': self.slot}
                    if command in ('setup-step', 'setup-status'):
                        active = len(cards) == 4
                        return {'phase': 'active' if active else 'certified', 'handoff': 'ready' if active else 'pending',
                                'agreed_fingerprint': 'a' * 64}
                    raise AssertionError(command)
            def ssh(command, **kwargs):
                if command.startswith('cat '):
                    return json.dumps({'files': {'loki_setup_member': {'sha256': 'hash'}}, 'compiler': 'pinned'}).encode()
                return b'other-host'
            with patch.object(native, 'Member', Member), patch.object(native, 'ssh', ssh):
                report = native.policy(4)
                self.assertEqual(report['result'], 'native_separate_host_signed_handoff_accepted')
                self.assertEqual([slot for slot, command in calls if command == 'setup-backup-finalize'], [1, 3, 4])
                before = list(calls)
                self.assertEqual(native.policy(4), report)
                self.assertEqual(calls, before)

    def test_interrupted_receipt_publication_never_looks_complete(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            receipt = root / 'receipt.done'
            def interrupt(source, target):
                self.assertEqual(Path(source).read_bytes(), b'complete-result')
                self.assertFalse(receipt.exists())
                raise InterruptedError('process interrupted before publication')
            with patch.object(resume.os, 'link', side_effect=interrupt):
                with self.assertRaises(InterruptedError):
                    resume.write_new(receipt, b'complete-result')
            self.assertFalse(receipt.exists())
            resume.write_new(receipt, b'complete-result')
            with self.assertRaises(FileExistsError):
                resume.write_new(receipt, b'replacement')
            self.assertEqual(receipt.read_bytes(), b'complete-result')

    def test_empty_payment_directory_restores_original_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            work = root / 'original-attempt'
            work.mkdir()
            manifest = work / 'payment.json'
            resume.ensure_manifest(manifest, b'original-manifest')
            self.assertEqual(manifest.read_bytes(), b'original-manifest')
            resume.ensure_manifest(manifest, b'original-manifest')
            with self.assertRaises(RuntimeError):
                resume.ensure_manifest(manifest, b'changed-manifest')
            self.assertEqual(manifest.read_bytes(), b'original-manifest')
