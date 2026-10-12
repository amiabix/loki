# Member setup app

This is the first member-owned regtest path. Run one app process per person, each
with its own `--data` directory. The shared `--exchange` directory carries only
public join records and the existing signed or encrypted setup messages. Each
process calls `loki_setup_member` for its own identity, DKG and backup. It has
no route that creates another member's identity or unlocks another share.

Before agreeing to the roster, each member connects the reference regtest
wallet. Click **Create connection challenge**, download its JSON, and run the
wallet command in a separate terminal:

```sh
chmod 600 /path/to/your-24-word-seed-file
./target/debug/loki_seed_wallet prove /path/to/your-24-word-seed-file loki-account-challenge.json
```

Paste the JSON proof into the member app. The command derives account 0 using
ZIP 32's regtest coin type, signs the fresh vault-and-member challenge with its
Orchard spend authorization key, and exits. Loki verifies that signature and
seals the account link. The profile uses the same account key across its vaults,
while each vault still gets a separate FROST identity and share. The seed file
never goes to the Loki app or the setup courier. This adapter supports only the
reference command; existing Zcash wallets do not automatically expose this
signing API. Use a **regtest-only seed**. An address QR is not a proof of control.

```sh
cd poc
cargo build --locked --bins
python3 wallet/member_app.py --data /tmp/loki-member-1 --exchange /tmp/loki-setup-exchange --port 8801
```

For the separate dashboard and signer flow, start the same member app with a
second loopback port:

```sh
python3 wallet/member_app.py --data /tmp/loki-member-1 --exchange /tmp/loki-setup-exchange --port 8801 --dashboard-port 8901
```

Open the printed **Signer** URL in one window, create or unlock the local
profile there, and open the printed **Dashboard** URL in another. Click
**Connect signer** on the dashboard. The signer window shows the requesting
origin, regtest network, and requested access; approve there. The dashboard
then shows only that profile's vault names, member slots and setup status.
**Create vault** in the dashboard sends a separate request that names the vault;
it creates nothing until the signer window approves it. Join, compare the
roster, and back up in the signer window; the dashboard updates its vault list.
**Disconnect** removes the dashboard grant without removing membership.
Locking the signer also revokes it. Grants are in memory and expire after one
hour. They permit status reads and action requests, never silent vault creation
or signing. Do not share the signer's private URL.
The dashboard cannot approve or sign payments; that needs a signer-side
transaction review request and the relay-backed inbox.

Start two or three more processes with different private data directories and ports,
using the same exchange directory. Open each printed private URL in a
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
The account-control proof is verified locally and kept in the member's sealed
store. It is not part of the group certificate, so other members do not learn a
reusable account key. The ordinary wallet seed does not recover a Loki FROST
share; the Loki 24 words and backup card are still required.
The app can create 2-of-3 or 2-of-4 regtest vaults. The policy is included in
the new roster fingerprint; old 2-of-3 roster files retain their original
fingerprint. A four-member source vault completed a mined payment with members
3 and 4 signing and member 2 finishing through `run-member-payment.py
--members 4 --pair CD --finisher 2`. This is the local courier test path; the
relay adapter and payment UI remain three-member-only or absent, respectively.

The app is passphrase-only today. Its local file courier and time-limited,
non-resumable DKG are development controls, not the planned relay transport.
Data roots created by the previous one-vault app are left untouched and need an
explicit migration before this version can open them; use a fresh root to test it.
Separate directories under one OS account do not isolate a compromised account.
There is no persistent chain cache, payment or passkey UI in this app yet; use the existing
separate-member CLI and harness for transaction testing. Do not use real funds.

Verify the member flow:

```sh
python3 -m unittest -v wallet/test_account_link.py wallet/test_member_app.py
python3 -m unittest -v wallet/test_signer_session.py
```
