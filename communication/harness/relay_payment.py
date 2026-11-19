#!/usr/bin/env python3
"""Spend an already funded manual regtest vault through three private relay members.

First run core/run-member-payment.py --manual with a fresh --state directory.
This harness copies only sealed source state, keeps each payment mailbox private,
and uses relays for every signing envelope.
"""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

import run
import three_members


def payment_command(owner, member, binary, roster, work, rpc, action, *extra):
    argv = [str(binary), action, str(member.root), str(member.passphrase_file),
            str(roster), str(work), *map(str, extra)]
    command = owner.sandbox_command(member, argv)
    command.insert(command.index(str(binary)), 'LOKI_RPC=' + rpc)
    return command


def pump(context, relay_binary, payment_binary, works, attempt, sent, rpc, deadline):
    for member in context.members:
        mailbox = works[member.member_id] / 'mailbox'
        inventory = context.owner.capture(payment_command(context.owner, member, payment_binary,
            context.roster, works[member.member_id], rpc, 'local-wires'), cwd=member.root,
            timeout=run._remaining(deadline))
        if inventory.returncode != 0:
            raise run.OwnershipError('Member could not inspect its own signing messages')
        wires = json.loads(inventory.stdout)['wires']
        if not isinstance(wires, list) or any(not isinstance(wire, str) or
                re.fullmatch(r'[0-9a-f]{64}', wire) is None for wire in wires):
            raise run.OwnershipError('Signer returned an invalid wire inventory')
        for wire in wires:
            if wire in sent:
                continue
            run._member_text(context, relay_binary, member, deadline, 'send-signing',
                             ['--payload-file', str(mailbox / wire), '--attempt', attempt])
            sent.add(wire)
        run._member_text(context, relay_binary, member, deadline, 'upload', [], allow_empty=True)
    for member in context.members:
        three_members.poll(context, relay_binary, member, deadline)
        result = run._member_text(context, relay_binary, member, deadline, 'export-signing',
                                  ['--work-dir', str(works[member.member_id]), '--attempt', attempt])
        if re.fullmatch(r'exported_signing=\d+\n', result) is None:
            raise run.OwnershipError('Signing export returned an invalid count')


def await_action(owner, command, member, pump_once, deadline):
    while True:
        result = owner.capture(command, cwd=member.root, timeout=run._remaining(deadline))
        if result.returncode == 0:
            return result
        if re.fullmatch(rb'error: waiting for member [1-4] (Commitment|Package|Share); sync relay inbox and retry\n', result.stderr) is None:
            raise run.OwnershipError('Payment action failed authenticated readiness checks')
        pump_once()


def await_members(processes, deadline, owner):
    output = []
    for process in processes:
        try:
            stdout, stderr = process.communicate(timeout=run._remaining(deadline))
        except subprocess.TimeoutExpired as error:
            raise run.OwnershipError('Payment finishing timed out') from error
        if process.returncode != 0:
            index = len(list(owner.root.glob('finisher-failure-*.private')))
            run._write_new(owner.root / f'finisher-failure-{index}.private',
                           stderr[:run.OwnedRun.CAPTURE_OUTPUT_LIMIT], 0o600)
            raise run.OwnershipError('Payment member exited unsuccessfully')
        output.append(stdout.decode('utf-8', errors='replace'))
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--payment-root', type=Path, required=True)
    parser.add_argument('--run-root', type=Path, required=True)
    parser.add_argument('--name', required=True, help='running THS regtest instance')
    parser.add_argument('--ports', type=run._cli_port, nargs=3)
    parser.add_argument('--source', type=Path)
    parser.add_argument('--recipient-root', type=Path)
    parser.add_argument('--hosted-runtime', type=Path)
    parser.add_argument('--offline-relay', type=int, choices=(1, 2, 3))
    parser.add_argument('--finisher', type=int, choices=(1, 2, 3, 4), help='member who proves and sends; defaults to the non-signer')
    args = parser.parse_args(argv)
    if sys.platform != 'darwin' or not Path('/usr/bin/sandbox-exec').is_file():
        parser.error('The member isolation test requires macOS sandbox-exec')
    manual = args.payment_root.resolve()
    manifest = (manual / 'payment/payment.json').read_bytes()
    payment = json.loads(manifest)
    if any(re.fullmatch(r'[0-9a-f]{64}', payment.get(field, '')) is None
           for field in ('payment', 'attempt')):
        parser.error('Payment manifest has invalid identifiers')
    pair = payment.get('pair', [1, 2])
    source = args.source.resolve() if args.source else manual / 'source'
    roster = json.loads((source / 'roster.json').read_text())
    ids = [peer['id'] for peer in roster['members']]
    if ids not in ([1, 2, 3], [1, 2, 3, 4]) or pair not in [[left, right] for left in ids for right in ids if left < right]:
        parser.error('Payment manifest has an invalid signing pair')
    communication, core = run._default_workspaces()
    sys.path.insert(0, str(core))
    from ths import THS
    chain = THS(args.name)
    chain.check()
    pay = run.find_binary('loki_member_payment', workspace=core)
    feature = subprocess.run([str(pay), 'features'], capture_output=True, timeout=5)
    if feature.returncode != 0 or feature.stdout != b'relay-backed-signing=1\n':
        parser.error('Build loki_member_payment with --features relay-communication')
    owner = three_members.MemberEnvironments.create(args.run_root)
    processes = []
    deadline = time.monotonic() + 900
    try:
        if args.hosted_runtime:
            context, hashes, _isolation, _server, relay = three_members.prepare_hosted_existing(
                owner, source, args.hosted_runtime.resolve(), communication, poc, deadline, args.offline_relay, payment['attempt'])
        else:
            if not args.ports or args.offline_relay:
                raise run.OwnershipError('Manual provisioning requires three explicit ports')
            context, hashes, _isolation, _server, relay = three_members.prepare_existing(
                owner, source, args.ports, communication, poc, deadline)
        works = {member.member_id: member.root / 'payments' / payment['attempt']
                 for member in context.members}
        proposer_id = int.from_bytes(bytes.fromhex(payment['proposer']), 'little')
        if proposer_id not in ids:
            raise run.OwnershipError('Payment proposer is outside the certified roster')
        proposer = context.members[proposer_id - 1]
        work = works[proposer_id]
        work.parent.mkdir(mode=0o700)
        work.mkdir(mode=0o700)
        run._write_new(work / 'payment.json', manifest, 0o600)
        run._member_text(context, relay, proposer, deadline, 'send-proposal',
                         ['--proposal-file', str(work / 'payment.json')])
        while time.monotonic() < deadline:
            run._member_text(context, relay, proposer, deadline, 'upload', [], allow_empty=True)
            for member in context.members:
                if member.member_id == proposer_id:
                    continue
                three_members.poll(context, relay, member, deadline)
                run._member_text(context, relay, member, deadline, 'import-proposals',
                                 ['--payments-dir', str(member.root / 'payments')])
                run._member_text(context, relay, member, deadline, 'upload', [], allow_empty=True)
            if all((path / 'payment.json').is_file() for path in works.values()):
                break
        else:
            raise run.OwnershipError('Proposal did not reach every private member store')
        if any((path / 'payment.json').read_bytes() != manifest for path in works.values()):
            raise run.OwnershipError('Imported payment differs from the proposed intent')
        if any((path / 'payment.json').stat().st_mode & 0o777 != 0o600 for path in works.values()):
            raise run.OwnershipError('Imported payment is not private')
        sent = set()
        pump_once = lambda: pump(context, relay, pay, works, payment['attempt'], sent,
                                 chain.rpc_address, deadline)
        for member in (context.members[number - 1] for number in pair):
            result = owner.capture(payment_command(owner, member, pay, context.roster,
                works[member.member_id], chain.rpc_address, 'commit'), cwd=member.root,
                timeout=run._remaining(deadline))
            if result.returncode != 0 or b'commitments published' not in result.stdout:
                raise run.OwnershipError('Member could not persist and publish commitments')
            pump_once()
        proposer = context.members[pair[0] - 1]
        result = await_action(owner, payment_command(owner, proposer, pay, context.roster,
            works[proposer.member_id], chain.rpc_address, 'package'), proposer, pump_once, deadline)
        if result.returncode != 0 or b'payment package published' not in result.stdout:
            raise run.OwnershipError('Proposer could not build the reviewed payment package')
        pump_once()
        for member in (context.members[number - 1] for number in pair):
            before = {item['id'] for item in three_members.status(context, relay, member, deadline)['messages']}
            review = await_action(owner, payment_command(owner, member, pay, context.roster,
                works[member.member_id], chain.rpc_address, 'review'), member, pump_once, deadline)
            if review.returncode != 0:
                raise run.OwnershipError('Member could not review the exact candidate')
            displayed = json.loads(review.stdout)
            expected = {key: payment[key] for key in ('vault', 'payment', 'attempt', 'pair',
                'amount_zat', 'memo', 'fee_zat', 'change_zat', 'expiry_height', 'input_nullifiers')}
            expected['memo_hex'] = expected.pop('memo')
            if any(displayed.get(key) != value for key, value in expected.items()) or \
                    displayed.get('authorization_required') is not True:
                raise run.OwnershipError('Signer review differs from the proposed payment')
            result = owner.capture(payment_command(owner, member, pay, context.roster,
                works[member.member_id], chain.rpc_address, 'approve-reviewed',
                displayed['review_token']), cwd=member.root,
                timeout=run._remaining(deadline))
            if result.returncode != 0 or b'signed locally; approval delivery pending relay storage' not in result.stdout:
                raise run.OwnershipError('Member could not verify and witness its approval')
            pump_once()
            delivered = [item for item in three_members.status(context, relay, member, deadline)['messages']
                         if item['id'] not in before and item['kind'] == 'test']
            if len(delivered) != len(ids) - 1 or any(item['stored_whole'] != '1' for item in delivered):
                raise run.OwnershipError('Approval is not yet durably stored by relays')
        observers = [member for member in context.members if member.member_id not in pair]
        aggregate_results = []
        for observer in observers:
            checked = await_action(owner, payment_command(owner, observer, pay, context.roster,
                works[observer.member_id], chain.rpc_address, 'finish-check'), observer, pump_once, deadline)
            if checked.returncode != 0 or b'aggregate verified' not in checked.stdout:
                raise run.OwnershipError('Independent finisher could not verify both saved shares')
            aggregate_results.append(checked.stdout)
        if len(set(aggregate_results)) != 1:
            raise run.OwnershipError('Independent finishers disagree on the approved signature hash')
        finisher_id = args.finisher or next(number for number in ids if number not in pair)
        if finisher_id not in ids:
            raise run.OwnershipError('Finisher is outside the certified roster')
        finisher = context.members[finisher_id - 1]
        processes.append(subprocess.Popen(
            payment_command(owner, finisher, pay, context.roster, works[finisher.member_id],
                            chain.rpc_address, 'finish'),
            cwd=finisher.root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE))
        finished = await_members(processes, deadline, owner)[0]
        match = re.search(r'txid=([0-9a-f]{64})', finished)
        if match is None:
            raise run.OwnershipError('Finisher returned no transaction ID')
        txid = match.group(1)
        chain.mine(3)
        verified = owner.capture(payment_command(owner, finisher, pay, context.roster,
                                works[finisher.member_id], chain.rpc_address, 'verify', txid),
                                 cwd=finisher.root, timeout=run._remaining(deadline))
        if verified.returncode != 0 or b'verified' not in verified.stdout:
            raise run.OwnershipError('Mined payment did not match the approved candidate')
        recipient = args.recipient_root.resolve() if args.recipient_root else manual / 'recipient'
        received = subprocess.run([str(pay), 'receive', str(recipient / 'member-1'),
                                   str(recipient / 'member-1/pass.txt'),
                                   str(recipient / 'roster.json'), str(manual / 'payment'), txid],
                                  env=chain.env(), capture_output=True, timeout=120)
        if received.returncode != 0 or b'independently decrypted' not in received.stdout:
            raise run.OwnershipError('Independent recipient could not decrypt the payment')
        three_members.verify_source(hashes)
        report = {'result': 'accepted', 'payment': payment['payment'], 'txid': txid,
                  'signers': pair, 'finisher': finisher.member_id, 'relay_envelopes': len(sent),
                  'recipient_decrypted': True, 'members': len(ids), 'hosted_configuration': bool(args.hosted_runtime), 'offline_relay': args.offline_relay, 'isolation': _isolation, 'independent_finishers': [member.member_id for member in observers]}
        run._write_new(owner.root / 'relay-payment-report.json', run._json_bytes(report), 0o644)
        print(run._json_bytes(report).decode(), end='')
        return 0
    finally:
        for process in processes:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
        owner.close()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (run.OwnershipError, OSError, ValueError, KeyError, subprocess.TimeoutExpired) as error:
        print('relay_payment_failed: ' + str(error), file=sys.stderr)
        sys.exit(1)
