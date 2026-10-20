# Member app

## Wired redesign UI (first functional slice)

The redesign prototype in `design/` is wired to the real member command host.
It runs alongside the shipping app on the **same** server and token — no extra
process, no build step, no framework. Start the app as usual, then open the
printed signer link with `/ui` before the `#token`:

```sh
python3 wallet/member_app.py --network regtest \
  --data /path/to/member-1 --exchange /path/to/setup-courier --port 8801
# printed:  Signer: http://127.0.0.1:8801/#<token>
# wired UI: http://127.0.0.1:8801/ui#<token>   ← same token, redesign look
```

Eight screens are wired to real commands: connect (`/api/status`), vault list
(`/api/status`), create vault (`/api/create`, general t-of-n), setup & backup
(`/api/status` steps + roster short-code + confirmations, then `/api/agree`,
`/api/backup`, `/api/verify`, `/api/activate`), vault overview (`/api/status`
roster/members, `/api/balance`, `/api/address`, `/api/payments`), propose payment
(`/api/payment-draft` + `payment-publish`), signer approval / WYSIWYS
(`/api/payment-review` → `payment-approve`), and history (`/api/payments`, status
pills Preparing → approved → broadcast → confirmed, with the reorg recheck shown).
No new endpoints were added — every screen reads routes the app already exposes.
The page serves `design/tokens.css` and `design/app.css` at `/ui/tokens.css` and
`/ui/app.css`; fonts resolve to the app's existing `/fonts/*`. The share never
enters the page — approval releases it only for the exact reviewed package.
`index.html`/`app.js` are untouched.

Acceptance tests (no native binaries, mock/regtest data) prove the vault-list,
create-vault, setup-status, overview-balance and history screens hit real routes
end to end (served 200 with the shape each screen reads, 403 without the token):

```sh
cd poc/wallet
python3 -m unittest test_member_app test_wired_ui
```

## Public Testnet UI

The same member app can create a Testnet vault, check backups, receive, review,
approve, and send. Start one process per installation, with a separate private
data directory and browser window. Balance and payment actions need a synced NU7
Zcash Testnet node on loopback. Local courier creation also requires that node
to choose the vault's birth block; hosted creation uses the fixed NU7 activation
block. The node's RPC cookie must be an owner-only file.

```sh
cd poc
cargo build --locked --bins --features relay-communication
export LOKI_TESTNET_RPC=127.0.0.1:18232
export LOKI_TESTNET_COOKIE_FILE=/path/to/your/testnet-rpc.cookie
python3 wallet/member_app.py --network testnet \
  --data /path/to/member-1 --exchange /path/to/setup-courier --port 8801
```

Open the private signer URL printed by the app. Create or unlock your profile,
create a vault, and share each member's invite. Every member compares the roster
fingerprint out of band and checks their final recovery card before anyone
deposits. Use a Testnet wallet able to send to the Ironwood pool for funding;
there is no Testnet faucet button. Each member connects the payment relays in
their own app before proposing or approving. A dashboard is optional: pass
`--dashboard-port 8901` to this same command if you want one. It does not sign.

The Accounts section can create another profile with its own key store and
vaults, then switch between accounts. The existing `--data` profile remains the
**Existing account**; new accounts live in `--data/accounts/<id>/`. Switching
locks the previous profile, so unlock an account to use its vaults. All accounts
in one app use the app's selected network. Renaming, deleting, and moving
accounts between networks are not available yet.

For members on separate machines, each app needs its own local Testnet node or
loopback RPC tunnel. The local setup courier needs a verified HTTPS front and
`--invite-port` plus `--invite-origin` on the creator's app, as described below.
Hosted setup also accepts `--network testnet` with the signed operator bundle
and enrollment issuer described below. Its certified roster uses the NU7
activation block (4,465,026) as the scan start for every member. This is safe
for deposits but can make the first scan slow. A hosted Testnet payment through
the browser has not yet been mined end to end; use disposable test funds.

## Local regtest

This is the first member-owned regtest path. Run one app process per device, each
with its own `--data` directory. The shared `--exchange` directory carries only
public join records and the existing signed or encrypted setup messages. Each
account calls `loki_setup_member` for its own identity, DKG and backup. The
setup courier exposes no profile, passphrase, or key material.

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
cargo build --release --locked --bins --features relay-communication
cargo build --locked --manifest-path ../communication/Cargo.toml -p loki-relay-server
python3 wallet/member_app.py --data /tmp/loki-member-1 --exchange /tmp/loki-setup-exchange --port 8801
```

The app uses the release binaries when all four are built and otherwise falls back
to `target/debug` with a startup warning. Select one explicitly with
`--bin-profile release|debug` or `LOKI_POC_BIN_PROFILE`; `CARGO_TARGET_DIR` is
honored. Debug builds are for development and the setup fault-injection drills;
their dependencies are optimized, but Loki's own code is not.

With hosted transport, an unlocked profile runs its setup commands in one
`loki_member_service` child (built with the other binaries). It receives the
passphrase once over its stdin and keeps it, and the Argon2id keys it derives,
only in memory; Lock stops it within 5 s. A missing service binary, or
`LOKI_MEMBER_SERVICE=0`, keeps one `loki_setup_member` process per command.

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
hour. They permit status reads, local relay setup, local test funding, and action
requests, never silent vault creation or signing. Do not share the signer's private URL.
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
  deployment is not part of this app. `test_remote_join.py` completes joining,
  DKG, and backup across verified HTTPS with separate app roots on one host;
  a second physical device has not been verified here.
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
block height. Set `LOKI_RPC=host:port` when starting each app if the local node is not
on THS's default `127.0.0.1:18232`; the app then uses the lightwalletd THS runs beside
that node unless `LOKI_LIGHTWALLETD=http://host:port` names another. **Refresh balance** only scans the chain;
the local **Fund Vault** action uses the separate THS faucet described below.

## Emergency recovery and exit (regtest beta)

Two members who each saved a **final** `loki-vault.card` and their 24 words can
spend without the old devices, old unlock passphrases, setup courier, or payment
relays. Use one trusted recovery computer together. Each member enters their
own words and chooses a new local unlock passphrase; each checks the full
transaction review and types the payment ID to approve it. Both recovered
shares and both approvals are handled on this one computer, so this emergency
path concentrates the threshold there. Run it only on a computer both members
trust. The tool removes its temporary restored stores when it exits normally.

To replace a departing member, first create a **new** 2-of-3 vault in the
member app with the continuing members, complete its backup checks, and copy
its receive address. Then run:

```sh
cd poc
cargo build --locked --bins
./target/debug/loki_recover --rpc 127.0.0.1:18232
```

Enter each member's final card **file** and 24 words when prompted, then the
new vault's receive address. The tool restores both members, scans the regtest
chain, creates a sweep of all currently unspent source notes, displays the
Rust signer's exact review to each member, and broadcasts only after both
approve. Check the transaction ID and the new vault's balance after it is
mined. A relay outage does not affect this path; a reachable regtest node is
still required. No old passphrase is needed.
The new vault must have a different address. Compare the displayed recipient
with the new vault's address before either member approves.

The native CLI passes backup words and passphrases through anonymous pipes,
without writing them to named files. Its private temporary directory holds
copied final cards, sealed restored state, the public roster, and payment work;
it is removed on normal exit. Treat the cards and temporary directory as
sensitive. A funded, mined end-to-end recovery sweep still needs
live regtest verification before this beta path is release ready.

The current payment manifest supports at most eight source notes. If the
source vault has more, the tool stops before signing. See
[Step 4 status](../../STEP4-STATUS.md) for the live regtest evidence still
needed before this is considered a verified release journey.

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
The app offers 2-of-3, 2-of-4, and 3-of-4 vaults. The selected policy is
included in the roster fingerprint; an existing vault's policy does not change.
The payment form selects the exact members who will sign this attempt. A different
signer set requires a new attempt and new signing nonces. A 3-of-4 local regtest
payment was mined with members 1, 2, and 3 signing and member 4 finishing;
the recipient independently decrypted it. Member 1 restored from the final card
and words before signing. The separate member app relay journey also mined a
3-of-4 payment and checked that restored old nonce state could not approve again.
The private member app can create a local payment draft, send
the proposal, publish commitments, build the package, review the transaction,
approve that exact review, prove and broadcast, then verify it on chain. The
review panel uses the Rust signer's verified transaction fields, not the
proposal's annotation. Each member runs these controls in their own private
signer window. While the profile is unlocked, the app's payment worker does every
step that needs no decision, whether or not a page is open: it delivers queued
proposals and this member's authenticated signing messages, polls the relays,
imports messages for this member, commits nonces, builds the package, retries
saved approvals and checks the chain, in one relay process per pass (every 2 s
while a payment is in flight, every 3 s otherwise). It can never review, approve
or send; those stay buttons in the signer window, and a frozen allowlist refuses
them on the worker thread. Lock stops the worker within 5 s. The page only reads
the saved payment list; **Check for updates** asks the worker for one pass now.
The separate dashboard has no payment approval route. A local approval
remains pending delivery until every saved signing message has relay storage; confirmation is checked again against this member's
chain view at most every 10 s: one block-hash lookup confirms the block it was
mined in is still on the chain, and the full verify runs again only after a reorg. If a signer closed after saving
an approval, **Retry saved signing messages** republishes the same sealed share;
it never creates another signature share.

The dashboard offers **Fund Vault** beside each eligible local regtest vault. Each new
click requests exactly 5 local test ZEC from the THS address faucet, then waits
for a confirmed transaction. Dashboard access includes this incoming test-fund
action; it cannot authorize spending from the vault. Set `LOKI_THS_INSTANCE` to
the local THS instance name before starting the member app (default: `loki`).
The faucet must use regtest and the same RPC endpoint as `LOKI_RPC`.

Funding is disabled until the final backup is checked. Progress and confirmation
appear beside the selected vault. Failed or interrupted requests reuse their
saved request ID through **Retry funding**, including after app restart. A
request with an unknown outcome must be resolved before starting another.
Confirmed funding allows a new 5 ZEC request. Open the vault in its signer and
click **Refresh balance** to scan the updated balance.

For apps sharing the same local `--exchange` directory, click **Set up relays**
once in the dashboard's **Payment relays** section with the signer unlocked and
connected. Setup runs directly through that dashboard session. The private
signer's vault-list page also offers the same single setup control. This starts
one saved network of three loopback test
relays and enables automatic connection for all existing and future eligible
vaults in that local environment.

Each running member app automatically provisions its own inboxes and exchanges
recipient-encrypted configurations through the shared courier. Locked apps
wait until their owners unlock them; no additional relay setup click is needed.
A vault connects after its final backup is checked, and each vault row shows
connection progress. Shared-courier 2-of-3, 2-of-4, and 3-of-4 vaults use this development flow.
Payment review and approval still happen separately in each private signer.

Saved relay roots, identities, operator access files, and encrypted couriers live
under `--exchange/.payment-relays/network/` by default. A single saved network
with capacity for more vaults is reused in its existing directory. Automatic
connection settings are saved in `--exchange/.payment-relays/settings.json`. Keep this directory with the
local test environment. **Retry connections** restarts the same relay network
if needed and retries failed attachments. The services continue across signer
restarts. Previously provisioned per-vault networks retain their saved identities
and configuration; networks originally limited to one vault continue serving
that vault. New connections use the shared network. These processes run on one machine; hosted HTTPS relays and
remote onboarding are not implemented by this local test flow.

For an operator-provided network, relay operators issue three independent manifest and capability sets
to each member. Put each member's sets in a local kit with `manifests/` and
`capabilities/` directories. In that member's private app, **Connect operator-provided relays**
provisions from the kit path for either supported policy, downloads one recipient-encrypted config file per peer,
and imports the encrypted files received from the other members. Send each
download only to its named member. **Check relay connection** requires all
peer configs and a response from this member's inbox on at least two relays;
delivery to other members is checked when sending. The app does
not issue operator credentials or deliver the encrypted files between members.
Hosted vaults attach automatically and do not expose these manual kit controls.
Operator independence is a deployment condition it cannot verify. The independent
three-relay setup in `communication/harness/three_members.py` tests transport;
it does not configure an app vault.
If signing stops after consuming a nonce and before saving the share, that
attempt cannot be resumed; create a new payment attempt with fresh nonces.

For a funded separate-member vault, `communication/harness/relay_payment.py`
now delivers the proposal to each member through the relays, carries only each
member's own signing messages, uses the exact signer review token, then proves,
mines, and checks receipt in an independent recipient vault. This validates the
Rust payment path; it is not a browser end-to-end test.

The opt-in member-app test joins those paths on a disposable THS network. It
creates and backs up a vault in three separate app processes, provisions three
real relay processes through the app routes, funds the vault, checks two signer
reviews, has the third member broadcast, and checks confirmation, the recipient
balance and all three member balance views:

```sh
cargo build --manifest-path communication/Cargo.toml --locked -p loki-relay-server
cargo build --manifest-path poc/Cargo.toml --locked --bins --features relay-communication
ths --name loki-app-flow start --no-open --port-offset 280  # keep this running
LOKI_THS_INSTANCE=loki-app-flow python3 poc/wallet/test_relay_payment_flow.py -v
```

For the same journey through three real Chromium windows, run the opt-in browser
test with the same THS instance after installing `poc/g3`'s Playwright packages:

```sh
npm ci --prefix poc/g3
LOKI_THS_INSTANCE=loki-app-flow python3 poc/wallet/test_real_browser_flow.py -v
```

Each browser controls a different private app process. The setup courier uses
verified HTTPS; the companion HTTPS join test checks wrong-hostname refusal.
The browser test checks the backup gate, relay connection, both transaction
review panels, two approvals, the third member's Send action, and confirmation
in all three windows. Members
discover the mined txid from its input nullifiers and then verify its exact
approved effects; confirmation does not depend on the finisher announcing a txid.
Each member keeps the same encrypted wallet database on regtest as on Testnet
(`wallet.sqlite`), synced before every chain read from the lightwalletd THS runs beside
`LOKI_RPC` (THS shifts both ports by the same offset), or from `LOKI_LIGHTWALLETD`. The
wallet library chooses a payment's notes, so one payment can combine up to 64 notes;
received notes become spendable after 10 confirmations and the vault's own change after 3,
so **Fund Vault** mines the extra blocks a funded note needs.

These tests run three private processes on one host and three relays under one
test operator. They do not prove physical-device operation or independent relay
operators. For a physical-device acceptance run, use a trusted HTTPS setup
courier, three independently operated HTTPS relays with a separate kit on each
device, and a shared regtest chain connection. Record only public evidence:
matching roster fingerprints, each member's final-card check and relay status,
the funding and payment txids, both verified review summaries, confirmation
height, recipient receipt and each member's post-payment balance. Do not copy
passphrases, cards, capabilities or signing wires into the report.

The app is passphrase-only today. Its local file courier and time-limited,
non-resumable DKG are development controls, not the planned relay transport.
Data roots created by the previous one-vault app are left untouched and need an
explicit migration before this version can open them; use a fresh root to test it.
Separate directories under one OS account do not isolate a compromised account.
There is no passkey UI in this app yet; use the existing
separate-member CLI and harness for transaction testing. Do not use real funds.

Verify the member flow:

```sh
python3 -m unittest -v wallet/test_account_link.py wallet/test_member_app.py
python3 -m unittest -v wallet/test_signer_session.py
python3 -m unittest -v wallet/test_local_relays.py
python3 -m unittest -v wallet/test_local_funding.py
node wallet/test-relay-dashboard-browser.js
node wallet/test-payment-poll-browser.js
```

The browser checks use Playwright from `g3/node_modules`. Set
`LOKI_BROWSER_EXECUTABLE` if you need to select an installed Chromium executable.


## feat(wallet): hosted setup rollout

Select hosted transport explicitly when starting the signer:

```sh
python3 wallet/member_app.py --data /PRIVATE/NEW/MEMBER --exchange /PRIVATE/LOCAL/PLACEHOLDER --port 18801 --transport hosted --operator-bundle /PRIVATE/operators.cbor --operator-key TRUSTED_CONFIG_SIGNING_KEY_HEX --enrollment-issuer /PRIVATE/configured-issuer
```

Add `--network testnet` for a hosted Testnet vault, and use it on every member's
app. Each member still supplies their own loopback Testnet RPC settings for
balance and payment actions. A wrong-network invitation is refused before the
member's identity or claim is saved.

The exchange placeholder is retained for compatibility with local startup arguments; hosted vault creation and payment handoff do not use a shared courier. Supply a scoped `--enrollment-grant` only when it belongs to the saved pending creator identity. A configured issuer receives the public creator key, selected policy and operator bundle path and returns the signed bounded grant on stdout. The product's production authentication/enrollment provider remains a deployment decision. Operator capabilities and issuer private keys stay off the signer. Development loopback requires explicit `--development-http`; production verifies HTTPS and the signed bundle.

All three supported policies use invitations delivered privately to the respective members, explicit fingerprint comparison and backup checks. Start every member with the same network; a mismatched invitation is refused. While unlocked, the native worker resumes the saved setup, registers scoped inboxes, installs all certified peer configurations and reconciles every signed activation vote. There is no additional per-vault relay approval. Lock stops the worker, terminates its native command and revokes dashboard sessions. A retry keeps the saved identity, exact requests, encrypted DKG state and payment descriptors. Creating again with the same pending name and policy reopens that setup; choose a distinct name for another vault.

Pending member slots appear beside the vault, separately from connection failures. Receiving and payment controls remain gated on checked backups and native payment activation. The dashboard receives public progress only and cannot retrieve keys, DKG packages, recovery words or capabilities. Hosted mode hides local relay-server setup and the local 5-ZEC faucet. Existing local vaults and their saved data retain the local path; there is no automatic migration or relay rotation.

The combined branch still requires consolidated validation of these paths and all six four-member signing pairs before acceptance. Same-host owned fixtures are not distinct-device HTTPS or mainnet custody approval.
