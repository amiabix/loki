# Member setup app

This is the first member-owned regtest path. Run one app process per person, each
with its own `--data` directory. The shared `--exchange` directory carries only
public join records and the existing signed or encrypted setup messages. Each
process calls `loki_setup_member` for its own identity, DKG and backup. It has
no route that creates another member's identity or unlocks another share.

```sh
cd poc
cargo build --locked --bin loki_setup_member
python3 wallet/member_app.py --data /tmp/loki-member-1 --exchange /tmp/loki-setup-exchange --port 8801
```

Start two more processes with different private data directories and ports 8802
and 8803, using the same exchange directory. Open each printed private URL in a
separate browser window. Member 1 creates a vault and copies each invite code to
the intended member. Each joiner pastes their own code. All three compare the
roster fingerprint through a trusted channel and confirm it. They must start
key creation within the setup CLI's two-minute wait per round. Each member
downloads their backup card, records their 24 words separately, and loads both
back to check them. The receive address appears after all three backup checks.

The server binds to loopback and uses a private URL token; the passphrase is sent
to that local process for each action and is not stored in the member directory.
The app is passphrase-only today. Its local file courier and time-limited,
non-resumable DKG are development controls, not the planned relay transport.
Separate directories under one OS account do not isolate a compromised account.
There is no payment, chain sync or passkey UI in this app yet; use the existing
separate-member CLI and harness for transaction testing. Do not use real funds.

Verify the member flow:

```sh
python3 -m unittest -v wallet/test_member_app.py
```
