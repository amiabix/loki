#!/usr/bin/env python3
"""Spend an already funded manual regtest vault through three private relay members.

First run poc/run-member-payment.py --manual with a fresh --state directory.
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


def pump(context, relay_binary, works, attempt, sent, deadline):
    for member in context.members:
        mailbox = works[member.member_id] / 'mailbox'
        if mailbox.is_dir():
            for wire in mailbox.iterdir():
                if re.fullmatch(r'[0-9a-f]{64}', wire.name) is None or wire.name in sent:
                    continue
                run._member_text(context, relay_binary, member, deadline, 'send-signing',
                                 ['--payload-file', str(wire), '--attempt', attempt])
                sent.add(wire.name)
        run._member_text(context, relay_binary, member, deadline, 'upload', [], allow_empty=True)
    for member in context.members:
        three_members.poll(context, relay_binary, member, deadline)
        result = run._member_text(context, relay_binary, member, deadline, 'export-signing',
                                  ['--work-dir', str(works[member.member_id]), '--attempt', attempt])
        if re.fullmatch(r'exported_signing=\d+\n', result) is None:
            raise run.OwnershipError('Signing export returned an invalid count')


def await_members(processes, pump_once, deadline):
    while any(process.poll() is None for process in processes):
        if time.monotonic() >= deadline:
            raise run.OwnershipError('Payment signing timed out')
        pump_once()
        time.sleep(0.1)
    pump_once()
    output = []
    for process in processes:
        stdout, _stderr = process.communicate(timeout=2)
        if process.returncode != 0:
            raise run.OwnershipError('Payment member exited unsuccessfully')
        output.append(stdout.decode('utf-8', errors='replace'))
    return output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--payment-root', type=Path, required=True)
    parser.add_argument('--run-root', type=Path, required=True)
    parser.add_argument('--name', required=True, help='running THS regtest instance')
    parser.add_argument('--ports', type=run._cli_port, nargs=3, required=True)
    parser.add_argument('--finisher', type=int, choices=(1, 2, 3), help='member who proves and sends; defaults to the non-signer')
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
    if pair not in ([1, 2], [1, 3], [2, 3]):
        parser.error('Payment manifest has an invalid signing pair')
    communication, poc = run._default_workspaces()
    sys.path.insert(0, str(poc))
    from ths import THS
    chain = THS(args.name)
    chain.check()
    pay = run.find_binary('loki_member_payment', workspace=poc)
    owner = three_members.MemberEnvironments.create(args.run_root)
    processes = []
    deadline = time.monotonic() + 900
    try:
        context, hashes, _isolation, _server, relay = three_members.prepare_existing(
            owner, manual / 'source', args.ports, communication, poc, deadline)
        works = {}
        for member in context.members:
            work = member.root / 'payment' / payment['attempt']
            work.parent.mkdir(mode=0o700)
            work.mkdir(mode=0o700)
            run._write_new(work / 'payment.json', manifest, 0o600)
            works[member.member_id] = work
        sent = set()
        pump_once = lambda: pump(context, relay, works, payment['attempt'], sent, deadline)
        approval = ('APPROVE ' + payment['payment'] + '\n').encode('ascii')
        for member in (context.members[number - 1] for number in pair):
            processes.append(subprocess.Popen(
                payment_command(owner, member, pay, context.roster, works[member.member_id],
                                chain.rpc_address, 'sign'),
                cwd=member.root, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE))
            processes[-1].stdin.write(approval)
            processes[-1].stdin.close()
            processes[-1].stdin = None
        signatures = await_members(processes, pump_once, deadline)
        if not all('approved payment ' + payment['payment'] in result for result in signatures):
            raise run.OwnershipError('Both signers did not approve the named payment')
        finisher_id = args.finisher or next(number for number in (1, 2, 3) if number not in pair)
        finisher = context.members[finisher_id - 1]
        processes.append(subprocess.Popen(
            payment_command(owner, finisher, pay, context.roster, works[finisher.member_id],
                            chain.rpc_address, 'finish'),
            cwd=finisher.root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE))
        finished = await_members(processes[2:], pump_once, deadline)[0]
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
        recipient = manual / 'recipient'
        received = subprocess.run([str(pay), 'receive', str(recipient / 'member-1'),
                                   str(recipient / 'member-1/pass.txt'),
                                   str(recipient / 'roster.json'), str(manual / 'payment'), txid],
                                  env=chain.env(), capture_output=True, timeout=120)
        if received.returncode != 0 or b'independently decrypted' not in received.stdout:
            raise run.OwnershipError('Independent recipient could not decrypt the payment')
        three_members.verify_source(hashes)
        report = {'result': 'accepted', 'payment': payment['payment'], 'txid': txid,
                  'signers': pair, 'finisher': finisher.member_id, 'relay_envelopes': len(sent),
                  'recipient_decrypted': True}
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
