# Member setup app

This is the first member-owned regtest path. Run one app process per person, each
with its own `--data` directory. The shared `--exchange` directory carries only
public join records and the existing signed or encrypted setup messages. Each
process calls `loki_setup_member` for its own identity, DKG and backup. It has
no route that creates another member's identity or unlocks another share.

```sh
cd poc
cargo build --locked --bins
python3 wallet/member_app.py --data /tmp/loki-member-1 --exchange /tmp/loki-setup-exchange --port 8801
```

Start two more processes with different private data directories and ports 8802
and 8803, using the same exchange directory. Open each printed private URL in a
separate browser window. Each person creates a local profile and unlocks it. A
profile can create or join more than one vault; every vault has its own transport
identity and sealed FROST share under `vaults/<vault-id>/`. The creator copies each invite code to
the intended member. Each joiner pastes their own code. All three compare the
roster fingerprint through a trusted channel and confirm it. They must start
key creation within the setup CLI's two-minute wait per round. Each member
downloads their backup card, records their 24 words separately, and loads both
back to check them. The receive address appears after all three backup checks.
If the page closes before that check, **Show backup words** returns the same
words and card after unlock. The temporary sealed word copy is removed when
the member checks the saved artifacts.
An active vault can scan the regtest chain for its unspent balance at a named
block height. Set `LOKI_RPC=host:port` when starting each app if the local node
is not on the default `127.0.0.1:18232`; the app does not fund or mine blocks.

The server binds to loopback and uses a private URL token. The passphrase unlocks
the sealed profile and stays in this process's memory until Lock or shutdown; it
is not saved as plaintext in the member directory. The profile ID is local and
does not appear in the vault roster or on chain. A membership links that profile
ID to the vault ID locally; the certified roster binds that membership's separate
public identity to its FROST share.
The app is passphrase-only today. Its local file courier and time-limited,
non-resumable DKG are development controls, not the planned relay transport.
Data roots created by the previous one-vault app are left untouched and need an
explicit migration before this version can open them; use a fresh root to test it.
Separate directories under one OS account do not isolate a compromised account.
There is no persistent chain cache, payment or passkey UI in this app yet; use the existing
separate-member CLI and harness for transaction testing. Do not use real funds.

Verify the member flow:

```sh
python3 -m unittest -v wallet/test_member_app.py
```
