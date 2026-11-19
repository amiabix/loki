#!/usr/bin/env python3
"""Exercise an existing vault through three relays in three macOS member sandboxes."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sqlite3
import sys
import time

import run


def read_source(path, cap):
    path = Path(path).absolute()
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise run.OwnershipError('Source vault contains a symlink')
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > cap:
            raise run.OwnershipError('Source vault file exceeds its bound')
        with os.fdopen(descriptor, 'rb', closefd=False) as source:
            data = source.read(cap + 1)
        if len(data) > cap:
            raise run.OwnershipError('Source vault file exceeds its bound')
        return data
    finally:
        os.close(descriptor)


def copy_vault(source, destination, preserve_configuration=False):
    """Copy only certified sealed state; never reuse the source transport journal."""
    source = Path(source).absolute()
    destination = Path(destination).absolute()
    if source == destination or source in destination.parents or destination in source.parents:
        raise run.OwnershipError('Source vault overlaps the selected run')
    raw = read_source(source / 'roster.json', 65536)
    roster = json.loads(raw)
    publics = roster.get('members', [])
    if (run._HEX64.fullmatch(str(roster.get('vault'))) is None
            or len(publics) not in (3, 4) or [item.get('id') for item in publics] != list(range(1, len(publics) + 1))):
        raise run.OwnershipError('Source roster must certify consecutive members for a supported policy')
    for field in ('signing', 'encryption'):
        values = [item.get(field) for item in publics]
        if any(not isinstance(value, str) or run._HEX64.fullmatch(value) is None
               for value in values) or len(set(values)) != len(publics):
            raise run.OwnershipError('Source member identities are not distinct')
    hashes = {source / 'roster.json': hashlib.sha256(raw).hexdigest()}
    target_roster = destination / 'roster.json'
    run._write_new(target_roster, raw, 0o644)
    run._mkdir(destination / 'members')
    members = []
    for public in publics:
        member_id = public['id']
        root = destination / 'members' / str(member_id)
        run._mkdir(root)
        run._mkdir(root / 'secrets')
        run._mkdir(root / 'home')
        run._mkdir(root / 'tmp')
        source_member = (source / 'members' / str(member_id)
                         if (source / 'members' / str(member_id)).is_dir()
                         else source / f'member-{member_id}')
        pass_name = 'passphrase' if (source_member / 'passphrase').is_file() else 'pass.txt'
        files = [('secrets/identity.sealed', 'secrets/identity.sealed', 65536),
                 ('secrets/vault.sealed', 'secrets/vault.sealed', 4 * 1024 * 1024),
                 (pass_name, 'passphrase', 65536)]
        if (source_member / 'secrets/activation.sealed').is_file():
            files.append(('secrets/activation.sealed', 'secrets/activation.sealed', 65536))
        for source_name, destination_name, cap in files:
            path = source_member / source_name
            data = read_source(path, cap)
            hashes[path] = hashlib.sha256(data).hexdigest()
            run._write_new(root / destination_name, data, 0o600)
        if preserve_configuration:
            database = source_member / 'transport/client.sqlite3'
            run._mkdir(root / 'transport')
            with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as original:
                reference = original.execute('SELECT revision,hash FROM config_versions WHERE singleton=1').fetchone()
                if reference is None or reference[0] != 1 or len(reference[1]) != 32:
                    raise run.OwnershipError('Hosted source has no exact installed initial configuration')
                with sqlite3.connect(root / 'transport/client.sqlite3') as target:
                    original.backup(target)
            os.chmod(root / 'transport/client.sqlite3', 0o600)
            name = f'secrets/relay-config-{reference[0]:016}.sealed'
            raw = read_source(source_member / name, 4 * 1024 * 1024)
            hashes[source_member / name] = hashlib.sha256(raw).hexdigest()
            run._write_new(root / name, raw, 0o600)
        member = run.CertifiedMember(member_id, root, root / 'passphrase',
                                     public['signing'], public['encryption'])
        if preserve_configuration:
            member.config_revision, member.config_hash = reference[0], reference[1].hex()
        members.append(member)
    return tuple(members), target_roster, hashes


def verify_source(hashes):
    for path, expected in hashes.items():
        if hashlib.sha256(read_source(path, 4 * 1024 * 1024)).hexdigest() != expected:
            raise run.OwnershipError('Source vault changed during the test')


class MemberEnvironments(run.OwnedRun):
    """Apply filesystem denial and a private HOME/TMPDIR to every member invocation."""

    CAPTURE_OUTPUT_LIMIT = 1048576

    def capture_group(self, jobs, *, timeout, output_limit=16384):
        if any(argv[:2] == [getattr(self, 'member_binary', None), 'status']
               for argv, _cwd in jobs):
            output_limit = self.CAPTURE_OUTPUT_LIMIT
        results = super().capture_group(jobs, timeout=timeout, output_limit=output_limit)
        for result in results:
            if result.returncode and result.stderr:
                index = len(list(self.root.glob('command-failure-*.private')))
                run._write_new(self.root / f'command-failure-{index}.private', result.stderr, 0o600)
        return results

    def configure(self, members, source, member_binary, extra_denied=()):
        self.members = members
        self.member_binary = str(member_binary)
        self.profiles = {}
        profile_root = self.root / 'profiles'
        run._mkdir(profile_root)
        for member in members:
            denied = [other.root for other in members if other is not member]
            denied += [self.root / 'relays', source, *extra_denied]
            denied += [self.root / 'descriptors' / str(other.member_id)
                       for other in members if other is not member]
            rules = ['(version 1)', '(allow default)']
            for path in denied:
                rules.append('(deny file-read* file-write* (subpath ' +
                             json.dumps(str(path.resolve())) + '))')
            for path in (self.root / 'public-manifests', self.root / 'capabilities',
                         self.root / 'roster.json', profile_root):
                rules.append('(deny file-write* (subpath ' +
                             json.dumps(str(path.resolve())) + '))')
            for provisioning in (False, True):
                profile = profile_root / f'{member.member_id}-{int(provisioning)}.sb'
                selected = list(rules)
                if not provisioning:
                    selected.append('(deny file-read* (subpath ' +
                                    json.dumps(str(self.root / 'capabilities')) + '))')
                run._write_new(profile, ('\n'.join(selected) + '\n').encode(), 0o600)
                self.profiles[member.member_id, provisioning] = profile

    def sandbox_command(self, member, argv, provisioning=False):
        return ['/usr/bin/sandbox-exec', '-f',
                str(self.profiles[member.member_id, provisioning]), '/usr/bin/env', '-i',
                'PATH=/usr/bin:/bin', 'HOME=' + str(member.root / 'home'),
                'TMPDIR=' + str(member.root / 'tmp'), *argv]

    def _command(self, argv, cwd):
        argv, cwd = super()._command(argv, cwd)
        if argv[0] == getattr(self, 'member_binary', None):
            root = Path(argv[argv.index('--member-root') + 1])
            member = next((item for item in self.members if item.root == root), None)
            if member is None:
                raise run.OwnershipError('Member root is outside the selected environments')
            run._reject_foreign(argv, [item.root for item in self.members if item is not member]
                                + [self.root / 'relays'])
            argv = self.sandbox_command(member, argv, argv[1] == 'provision')
        return argv, cwd


def check_isolation(owner, source, deadline):
    for member in owner.members:
        environment = owner.capture(owner.sandbox_command(member, [
            '/bin/sh', '-c', 'printf "%s\\n%s\\n" "$HOME" "$TMPDIR"']),
            cwd=member.root, timeout=run._remaining(deadline))
        expected = f'{member.root}/home\n{member.root}/tmp\n'.encode()
        if environment.returncode != 0 or environment.stdout != expected:
            raise run.OwnershipError('Member environment did not receive its private HOME and TMPDIR')
        run._write_new(member.root / 'isolation-canary', b'member canary\n', 0o600)
    relay_canary = owner.root / 'relays' / 'isolation-canary'
    run._write_new(relay_canary, b'relay canary\n', 0o600)
    evidence = []
    for member in owner.members:
        own = owner.capture(owner.sandbox_command(member, ['/bin/cat', str(member.root / 'isolation-canary')]),
                            cwd=member.root, timeout=run._remaining(deadline))
        if own.returncode != 0 or own.stdout != b'member canary\n':
            raise run.OwnershipError('Member sandbox could not read its own state')
        denied = [other.root / 'isolation-canary' for other in owner.members if other is not member]
        source_member = (source / 'members' / str(member.member_id)
                         if (source / 'members' / str(member.member_id)).is_dir()
                         else source / f'member-{member.member_id}')
        denied += [relay_canary, source_member / 'secrets/vault.sealed']
        for path in denied:
            result = owner.capture(owner.sandbox_command(member, ['/bin/cat', str(path)]),
                                   cwd=member.root, timeout=run._remaining(deadline))
            if result.returncode != 1 or result.stdout:
                raise run.OwnershipError('Member sandbox allowed foreign state access')
        evidence.append({'member': member.member_id, 'own_read': True,
                         'peer_reads_denied': len(owner.members) - 1, 'relay_read_denied': True,
                         'source_read_denied': True, 'private_home_and_tmp': True})
    relay_canary.unlink()
    return evidence


def prepare_existing(owner, source, ports, communication, poc, deadline):
    server = run.find_binary('loki-relay-server', workspace=communication)
    member_bin = run.find_binary('loki_relay_member', workspace=core)
    setup_bin = run.find_binary('loki_setup_member', workspace=core)
    run.preflight_ports(ports)
    members, roster, hashes = copy_vault(source, owner.root)
    owner.configure(members, source, member_bin)
    fingerprint = run._fingerprint_text(run._command_text(
        owner, [str(setup_bin), 'fingerprint', str(roster)], owner.root, deadline))
    vault = json.loads(roster.read_text())['vault']
    for name in ('relays', 'public-manifests', 'capabilities', 'capability-staging',
                 'courier-export', 'descriptors'):
        run._mkdir(owner.root / name)
    isolation = check_isolation(owner, source, deadline)
    relays = tuple(run._init_relay(owner, index, port, server, deadline, 1048576, 8388608)
                   for index, port in enumerate(ports, 1))
    if len({relay.receipt_key for relay in relays}) != 3 or len({relay.run_id for relay in relays}) != 3:
        raise run.OwnershipError('Relay identities are not distinct')
    run._rmdir(owner.root / 'capability-staging', 'Capability staging was not retired')
    for relay in relays:
        relay.child = owner.start([str(server), 'serve', '--root', str(relay.root),
                                   '--listen', run._listen(relay.endpoint)], cwd=relay.root)
        run._wait_listen(relay.child, run._listen(relay.endpoint), deadline)
    context = run.provision_members(owner, relays, members, roster, vault, fingerprint,
                                    member_bin, deadline, 1048576, 8388608)
    capability = owner.root / 'capabilities' / relays[0].receipt_key
    for member in members:
        result = owner.capture(owner.sandbox_command(member, ['/bin/cat', str(capability)]),
                               cwd=member.root, timeout=run._remaining(deadline))
        if result.returncode != 1 or result.stdout:
            raise run.OwnershipError('Runtime member could read the provisioning capability')
        isolation[member.member_id - 1]['runtime_provisioning_read_denied'] = True
    return context, hashes, isolation, server, member_bin


def prepare_hosted_existing(owner, source, runtime, communication, poc, deadline, offline_relay=None, signing_attempt=None):
    server = run.find_binary('loki-relay-server', workspace=communication)
    member_bin = run.find_binary('loki_relay_member', workspace=core)
    setup_bin = run.find_binary('loki_setup_member', workspace=core)
    members, roster, hashes = copy_vault(source, owner.root, preserve_configuration=True)
    owner.configure(members, source, member_bin, extra_denied=(runtime,))
    run._mkdir(owner.root / 'relays')
    isolation = check_isolation(owner, source, deadline)
    fingerprint = run._fingerprint_text(run._command_text(owner, [str(setup_bin), 'fingerprint', str(roster)], owner.root, deadline))
    relays = []
    for index in range(1, 4):
        root = runtime / f'relay-{index}'
        fields = read_source(root / 'manifest', 4096).decode().splitlines()
        if len(fields) != 3 or any(re.fullmatch(r'[0-9a-f]{64}', pin) is None for pin in fields[1:]):
            raise run.OwnershipError('Saved hosted relay manifest is invalid')
        endpoint, run_id, receipt_key = fields
        listen = run._listen(endpoint)
        child = None
        if index != offline_relay:
            child = owner.start([str(server), 'serve', '--root', str(root), '--listen', listen], cwd=root)
            run._wait_listen(child, listen, deadline)
        relays.append(run.RelayBinding(endpoint, run_id, receipt_key, root, child))
    if len({relay.receipt_key for relay in relays}) != 3 or len({relay.run_id for relay in relays}) != 3:
        raise run.OwnershipError('Hosted relay identities are not independent pins')
    context = run.SetupContext(owner, json.loads(roster.read_text())['vault'], fingerprint,
                               0, 0, tuple(relays), members, roster, (), ())
    context.signing_attempt = signing_attempt
    inboxes = []
    expected_routes = {(relay.receipt_key, relay.run_id, relay.endpoint) for relay in relays}
    expected_failures = (relays[offline_relay - 1].receipt_key,) if offline_relay is not None else ()
    for member in members:
        parsed = run._parse_status(run._member_text(context, member_bin, member, deadline,
            'status', ['--verify-relays', *(['--attempt', signing_attempt] if signing_attempt is not None else [])]), member.member_id, True,
            expected_route_failures=expected_failures, member_count=len(members))
        found_routes = {(item['pin'], item['run'], item['endpoint']) for item in parsed['inboxes']}
        if found_routes != expected_routes or any(item['append_revision'] != 1 for item in parsed['inboxes']) \
                or (parsed['config_revision'], parsed['config_hash']) != (member.config_revision, member.config_hash):
            raise run.OwnershipError('Installed hosted configuration differs from its saved relay pins or reference')
        inboxes.extend(parsed['inboxes'])
        capability = runtime / 'relay-1.secret'
        denied = owner.capture(owner.sandbox_command(member, ['/bin/cat', str(capability)]), cwd=member.root, timeout=run._remaining(deadline))
        if denied.returncode != 1 or denied.stdout:
            raise run.OwnershipError('Hosted member could read operator provisioning capability')
        isolation[member.member_id - 1]['runtime_provisioning_read_denied'] = True
    if len(inboxes) != 3 * len(members) or len({item['mailbox'] for item in inboxes}) != len(inboxes):
        raise run.OwnershipError('Installed hosted inboxes are not distinct for every member')
    context.inboxes = tuple(inboxes)
    return context, hashes, isolation, server, member_bin

def status(context, binary, member, deadline, verify=False):
    return run._member_status(context, binary, member, deadline, verify=verify)


def poll(context, binary, member, deadline):
    for _ in range(32):
        try:
            text = run._member_text(context, binary, member, deadline, 'poll', ['--once'])
        except run.OwnedCommandError as error:
            if not error.capacity:
                raise
            run._member_text(context, binary, member, deadline, 'upload', [], allow_empty=True)
            continue
        if text != 'poll=ok\n':
            raise run.OwnershipError('Member poll did not complete')
        return
    raise run.OwnershipError('Member inbox backpressure did not clear within the bounded retry')


def send_pair(context, binary, member, deadline):
    payload_dir = member.root / 'payloads'
    run._mkdir(payload_dir)
    sent = []
    for name, size in (('ordinary', 64), ('chunked', 65537)):
        path = payload_dir / name
        run._write_new(path, secrets.token_bytes(size), 0o600)
        request_id = secrets.token_hex(32)
        args = ['--payload-file', str(path), '--request-id', request_id]
        first = run._member_text(context, binary, member, deadline, 'send', args)
        message_id, digest = run._parse_send(first, request_id)
        repeated = run._member_text(context, binary, member, deadline, 'send', args)
        if run._parse_send(repeated, request_id) != (message_id, digest):
            raise run.OwnershipError('Repeated request created a different message')
        sent.append({'name': name, 'payload_length': size, 'request_id': request_id,
                     'id': message_id, 'digest': digest})
    for _ in range(12):
        run._parse_upload_progress(run._member_text(
            context, binary, member, deadline, 'upload', [], allow_empty=True))
        current = status(context, binary, member, deadline)
        originals = run._bind_originals(current, sent)
        messages = [run._only_message(current, item['id']) for item in sent]
        if all(message['readiness'] == 'ready' and message['stored_whole'] == '1'
               and message['needs_route'] == 0 for message in messages):
            pair = run._shared_pair(context, originals)
            if any(run._copies_on_pair(message, pair) is None for message in messages):
                raise run.OwnershipError('Original copies are incomplete')
            return originals, pair
    raise run.OwnershipError('Original messages did not reach Stored')


def receive_pair(context, binary, member, originals, pair, deadline):
    original_ids = {item['id'] for item in originals}
    for _ in range(12):
        poll(context, binary, member, deadline)
        run._parse_upload_progress(run._member_text(
            context, binary, member, deadline, 'upload', [], allow_empty=True))
        current = status(context, binary, member, deadline)
        selected = dict(current)
        selected['acks'] = [ack for ack in current['acks'] if ack['id'] in original_ids]
        ack_ids = {ack['ack_message'] for ack in selected['acks']}
        selected['messages'] = [message for message in current['messages'] if message['id'] in ack_ids]
        received = run._received_stored(selected, member.member_id, originals, pair)
        if run._incoming_bound(current, originals) and received is not None:
            if any(row['readiness'] != 'ready' for row in current['incoming'] if row['id'] in original_ids):
                raise run.OwnershipError('Received original is not authenticated and ready')
            return received
    raise run.OwnershipError('Offline recipient did not receive and acknowledge both messages')


def require_complete(context, snapshots, originals, acknowledgements):
    ids = tuple(member.member_id for member in context.members)
    original_count = 2 * len(ids)
    acknowledgement_count = original_count * (len(ids) - 1)
    if len(originals) != original_count or len({item['id'] for item in originals}) != original_count:
        raise run.OwnershipError('Expected six distinct original messages')
    expected_links = {(item['sender'], item['id'], peer)
                      for item in originals for peer in ids if peer != item['sender']}
    observed_links = []
    for member in context.members:
        current = snapshots[member.member_id]
        tests = [message for message in current['messages'] if message['kind'] == 'test']
        incoming = [message for message in current['incoming'] if message['kind'] == 'test']
        if len(tests) != 2 or len(incoming) != 2 * (len(ids) - 1) or len(current['acks']) != 2 * (len(ids) - 1):
            raise run.OwnershipError('Member counts differ from two self and four peer originals')
        if any(row['readiness'] != 'ready' for row in incoming):
            raise run.OwnershipError('Peer original is not authenticated and ready')
        peer_originals = [item for item in originals if item['sender'] != member.member_id]
        if not run._incoming_bound(current, peer_originals):
            raise run.OwnershipError('Peer originals are missing or incomplete')
        for item in originals:
            if item['sender'] != member.member_id:
                continue
            message = run._only_message(current, item['id'])
            expected_received = {peer: int(peer != member.member_id) for peer in ids}
            if (message['digest'] != item['digest'] or message['readiness'] != 'ready'
                    or message['received_whole'] != 1 or message['received_author'] != 1
                    or message['received_members'] != expected_received):
                raise run.OwnershipError('Author lacks both authenticated peer acknowledgements')
        for ack in current['acks']:
            target = next((item for item in originals if item['id'] == ack['id']
                           and item['sender'] == ack['sender']), None)
            if target is None or ack['digest'] != target['digest']:
                raise run.OwnershipError('Acknowledgement names a different original body')
            observed_links.append((ack['sender'], ack['id'], ack['author']))
    if len(observed_links) != acknowledgement_count or set(observed_links) != expected_links:
        raise run.OwnershipError('Acknowledgements include a duplicate, missing peer or self acknowledgement')
    if len(acknowledgements) != acknowledgement_count or len({ack['ack_message'] for ack in acknowledgements}) != acknowledgement_count:
        raise run.OwnershipError('Expected twelve distinct Received messages')
    for ack in acknowledgements:
        author = next(item['sender'] for item in originals if item['id'] == ack['original_id'])
        rows = [row for row in snapshots[author]['incoming']
                if row['kind'] == 'received' and row['id'] == ack['ack_message']
                and row['sender'] == ack['author'] and row['digest'] == ack['received_digest']]
        if len(rows) != 1:
            raise run.OwnershipError('Received message did not return to its original author')


def snapshot(context, binary, deadline):
    return {member.member_id: status(context, binary, member, deadline, verify=True)
            for member in context.members}


def exercise(context, binary, server, deadline):
    originals, acknowledgements = [], []
    shared_pair = None
    for sender in context.members:
        published, pair = send_pair(context, binary, sender, deadline)
        if shared_pair is not None and shared_pair != pair:
            raise run.OwnershipError('Members did not use the same complete relay pair')
        shared_pair = pair
        originals.extend(published)
        for recipient in context.members:
            if recipient is not sender:
                acknowledgements.extend(receive_pair(context, binary, recipient, published, pair, deadline))
        poll(context, binary, sender, deadline)
    for _ in range(2):
        for member in context.members:
            poll(context, binary, member, deadline)
            run._member_text(context, binary, member, deadline, 'upload', [], allow_empty=True)
    before = snapshot(context, binary, deadline)
    require_complete(context, before, originals, acknowledgements)
    for member in context.members:
        run._require_remote_retrieval(before[member.member_id], member.member_id)
        run._require_replica_ciphertext(before[member.member_id], originals, acknowledgements,
                                        shared_pair, member.member_id)
    run._require_distinct_ciphertext(before)
    for member in context.members:
        poll(context, binary, member, deadline)
        run._member_text(context, binary, member, deadline, 'upload', [], allow_empty=True)
    repeated = snapshot(context, binary, deadline)
    require_complete(context, repeated, originals, acknowledgements)
    run._compare_remote(before, repeated)
    run._restart_relays(context, server, deadline)
    for member in context.members:
        poll(context, binary, member, deadline)
    after = snapshot(context, binary, deadline)
    require_complete(context, after, originals, acknowledgements)
    run._compare_remote(before, after)
    return {'original_count': 6, 'acknowledgement_count': 12,
            'messages': originals, 'acknowledgements': acknowledgements,
            'remote_before': before, 'remote_after': after,
            'checks': {'offline_receipt': True, 'all_members_send': True,
                       'same_request_retry': True, 'no_duplicate_effects': True,
                       'same_relay_network': True, 'relay_restart': True,
                       'member_command_restart': True}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--vault-root', type=Path, required=True)
    parser.add_argument('--run-root', type=Path, required=True)
    parser.add_argument('--ports', type=run._cli_port, nargs=3, required=True)
    args = parser.parse_args(argv)
    if sys.platform != 'darwin' or not Path('/usr/bin/sandbox-exec').is_file():
        parser.error('This test requires macOS sandbox-exec; isolation is never silently disabled')
    source = args.vault_root.absolute()
    communication, core = run._default_workspaces()
    harness_hashes = {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
                      for path in (Path(__file__), Path(run.__file__))}
    owner = MemberEnvironments.create(args.run_root)
    deadline = time.monotonic() + 600
    phase = 'setup'
    try:
        context, hashes, isolation, server, binary = prepare_existing(
            owner, source, args.ports, communication, poc, deadline)
        phase = 'messages'
        report = exercise(context, binary, server, deadline)
        verify_source(hashes)
        report.update({'result': 'accepted', 'setup': context.public_report(),
                       'environments': isolation, 'source_unchanged': True,
                       'source_file_hashes': sorted(hashes.values()),
                       'isolation': 'macos_process_sandbox', 'separate_operators': False,
                       'harness_sha256': harness_hashes,
                       'binary_sha256': {name: hashlib.sha256(path.read_bytes()).hexdigest()
                                         for name, path in [('relay', server), ('member', binary)]}})
        owner.close()
        report['owned_processes_remaining'] = sum(child.poll() is None for child in owner._children)
        run._write_new(owner.root / 'three-members-report.json', run._json_bytes(report), 0o644)
        sys.stdout.write(run._json_bytes({key: report[key] for key in
                         ('result', 'original_count', 'acknowledgement_count', 'checks',
                          'environments', 'source_unchanged', 'owned_processes_remaining')}).decode())
        return 0
    except (run.OwnershipError, OSError, ValueError, KeyError, StopIteration) as error:
        owner.close()
        run._write_new(owner.root / 'three-members-failure.json',
                       run._json_bytes({'result': 'failed', 'phase': phase,
                                        'reason': str(error) if isinstance(error, run.OwnershipError)
                                        else type(error).__name__}), 0o644)
        print('three_member_test_failed; inspect the retained run', file=sys.stderr)
        return 1
    finally:
        owner.close()


if __name__ == '__main__':
    sys.exit(main())
