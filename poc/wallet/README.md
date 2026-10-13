# Member setup app

This is the first member-owned regtest path. Run one app process per person, each
with its own `--data` directory. The shared `--exchange` directory carries only
public join records and the existing signed or encrypted setup messages. Each
process calls `loki_setup_member` for its own identity, DKG and backup. It has
no route that creates another member's identity or unlocks another share.

Vault creation needs only each member's Loki signer. A personal Zcash wallet is
not required. An optional regtest account link can be added before or after
setup: open **Optional: link a reference Zcash account**, create a challenge,
download its JSON, and run the wallet command separately:

```sh
chmod 600 /path/to/your-24-word-seed-file
./target/debug/loki_seed_wallet prove /path/to/your-24-word-seed-file loki-account-challenge.json
```

Paste the JSON proof into the member app. The command derives account 0 using
ZIP 32's regtest coin type, signs the fresh vault-and-member challenge with its
Orchard spend authorization key, and exits. Loki verifies that signature and
seals the account link. The profile uses the same account key across its vaults,
while each vault still gets a separate FROST identity and share. Linking does
not change or recover that share. The seed file never goes to the Loki app or
the setup courier. This adapter supports only the
reference command; existing Zcash wallets do not automatically expose this
signing API. Use a **regtest-only seed**. An address QR is not a proof of control.

```sh
cd poc
cargo build --locked --bins --features relay-communication
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
the intended member. Each joiner pastes their own code. All members compare the
roster fingerprint through a trusted channel and confirm it. They must start
key creation within the setup CLI's two-minute wait per round. Each member
records their 24 words and enters them to check the app's local provisional
card. Once every member has checked their words, each app creates a final
recovery card. The member downloads that card and loads the saved file with
their words to check it. Only then does their app show the receive address.
If the page closes during setup, **Show 24 words** returns the same words after
unlock. The temporary word copy stays sealed under the member's unlock
passphrase until the final card is generated, then is removed.

## Inviting a member whose app is not on this filesystem

`--invite-port` serves the creator's own setup courier on loopback, and each
invite then carries the address an invited app should reach it on. The files
that cross are the same opaque ones the shared `--exchange` directory carried:
the vault draft, each member's public identity, each app's roster answer, and
the signed, recipient-encrypted DKG and backup wires. An invited app checks
every name against the ones this vault can have and every body against the
digest the courier advertised, refuses a second version of a published wire,
and may publish only its own slot's files. The roster fingerprint is still
compared out of band, so the courier remains untrusted.
After a member reloads and checks the final card, their app publishes a signed
status receipt. The status list verifies those signatures against the certified
roster; it cannot prove anyone still retains their card. Remote reports arrive
while the creator's courier and joining apps remain online.

```sh
python3 wallet/member_app.py --data /tmp/loki-member-1 --exchange /tmp/loki-setup-1 --port 8801 --invite-port 8787
```

An invitation spends one slot for one app. The joining app saves its courier
token before it asks, so an answer that never arrives costs a retry and not the
invitation; the same code in a second app is refused. The 24 hours gate the
first claim of a slot, not that retry. There is no reissue: an invitation that
is spent, expired, or claimed by an app that then lost its data root cannot be
replaced without a new vault.

### What this does not do yet

* **A separate device needs HTTPS.** `--invite-origin` accepts plain `http`
  only for a loopback address. Any other address must be `https` with a
  certificate the joining device already trusts, because the invite's token
  travels on every request; a LAN `http://` address is refused when the invite
  is made. Reaching the courier from another device therefore means putting a
  TLS front with such a certificate ahead of the loopback `--invite-port`. That
  deployment is not part of this app, and a join from a second physical device
  has not been verified here.
* **Members cannot finish at their own times, and the creator cannot be
  offline.** The courier is served by the creator's app, so it must be open and
  reachable for the whole join, DKG and backup round. A durable independent
  relay would fix the creator's availability but not the rest: `loki_setup_member
  run` publishes its round-one package and then waits for each peer's file with
  a 120 second deadline, so the ceremony itself still needs every member present
  at the same time. Asynchronous setup needs a resumable ceremony, not only a
  different transport.
* **The `communication/` relay is not used for this.** It is durable and
  encrypted, but a mailbox's append and read capabilities are distributed in
  descriptors derived from an already certified roster, which is exactly what
  setup does not have yet.

On a new device, create and unlock a local profile, then use **Restore your
membership** with that member's final recovery card and 24 words. The app asks
the Rust restore command to verify the card's roster and signed backup checks,
then saves that member's signing material and the shared viewing secret under the new profile. It rejects
the internal provisional card, restores the same receive address, and needs neither
the setup courier nor a relay. The old device remains capable of signing;
restoring is not revocation.
An active vault can scan the regtest chain for its unspent balance at a named
block height. Set `LOKI_RPC=host:port` when starting each app if the local node
is not on the default `127.0.0.1:18232`; the app does not fund or mine blocks.

The server binds to loopback and uses a private URL token. The passphrase unlocks
the sealed profile and stays in this process's memory until Lock or shutdown; it
is not saved as plaintext in the member directory. The profile ID is local and
does not appear in the vault roster or on chain. A membership links that profile
ID to the vault ID locally; the certified roster binds that membership's separate
public identity to its FROST share.
If used, the account-control proof is verified locally and kept in the member's sealed
store. It is not part of the group certificate, so other members do not learn a
reusable account key. The ordinary wallet seed does not recover a Loki FROST
share; the Loki 24 words and backup card are still required.
The app can create 2-of-3 or 2-of-4 regtest vaults. The policy is included in
the new roster fingerprint; old 2-of-3 roster files retain their original
fingerprint. A four-member source vault completed a mined payment with members
3 and 4 signing and member 2 finishing through `run-member-payment.py
--members 4 --pair CD --finisher 2`. This is the local courier test path; the
relay adapter remains three-member-only. The 2-of-4 vault can show its balance
when funded through the CLI test path, but the app hides its receive address
and payment controls to avoid deposits it cannot spend. For a 2-of-3 vault, the private member
app has controls for a fixed signing pair: create a local payment draft, send
the proposal, publish commitments, build the package, review the transaction,
approve that exact review, prove and broadcast, then verify it on chain. The
review panel uses the Rust signer's verified transaction fields, not the
proposal's annotation. Each member runs these controls in their own private
signer window. **Refresh payments** uploads queued proposals and this member's
authenticated signing messages, polls the relays, and imports messages for this
member. The separate dashboard has no payment approval route. A local approval
remains pending delivery until every saved signing message has relay storage; confirmation is checked again against this member's
chain view whenever the payment list is shown. If a signer closed after saving
an approval, **Retry saved signing messages** republishes the same sealed share;
it never creates another signature share.

Relay setup is still an external prerequisite. Each member must provision their
vault directory with three operator-issued relay manifests and capability files
using `loki_relay_member provision`, run `export-config`, deliver only the
recipient-encrypted courier files to the named peers, and run `import-config`
on the files addressed to them. Check each member with
`loki_relay_member status --verify-relays` before using payment controls. The app
does not collect capabilities or automate this ceremony. The independent
three-relay setup in `communication/harness/three_members.py` tests transport;
it does not configure an app vault. Relay keys are checked as distinct, but
operator independence is a deployment condition that the app cannot verify.
If signing stops after consuming a nonce and before saving the share, that
attempt cannot be resumed; create a new payment attempt with fresh nonces.

For a funded separate-member vault, `communication/harness/relay_payment.py`
now delivers the proposal to each member through the relays, carries only each
member's own signing messages, uses the exact signer review token, then proves,
mines, and checks receipt in an independent recipient vault. This validates the
Rust payment path; it is not a browser end-to-end test.

The app is passphrase-only today. Its local file courier and time-limited,
non-resumable DKG are development controls, not the planned relay transport.
Data roots created by the previous one-vault app are left untouched and need an
explicit migration before this version can open them; use a fresh root to test it.
Separate directories under one OS account do not isolate a compromised account.
There is no persistent chain cache or passkey UI in this app yet; use the existing
separate-member CLI and harness for transaction testing. Do not use real funds.

Verify the member flow:

```sh
python3 -m unittest -v wallet/test_account_link.py wallet/test_member_app.py
python3 -m unittest -v wallet/test_signer_session.py
```
