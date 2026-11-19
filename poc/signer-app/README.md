# LokiSigner — member-owned native signer

The native app claims a `loki://pair` link, opens the existing persistent Secure Enclave
P-256 device key, and runs S4a self-registration. The coordinator receives public enrollment
and a challenge signature. Profile passphrases, local session capabilities and FROST shares
stay on the member device. The FROST share is encrypted with an Enclave-wrapped key; it is
opened in signer memory for signing.

## Build and pair

```sh
LOKI_DEV_TEAM=B399KAT22M bash poc/signer-app/build.sh
open poc/signer-app/out/LokiSigner.app
```

On the wallet's sign-in screen open **Use a native member app instead**. It has two steps.

1. **Pair a new native signer**: choose **Get a pairing link**. The wallet shows the reserved
   slot, the time left on the link, an **Open LokiSigner** button and **Copy link** (to open
   it on the member's Mac yourself). LokiSigner then asks, in this order:
   - On first launch, choose **Pair a new signer** (or see restore below if this is a replacement Mac).
   - "Pair this device with slot N?" with the coordinator origin. Choose **Continue** only if
     it is the wallet's address.
   - "Pair this device with slot N?" again, with the network and endpoints that coordinator
     chose (see below). Enter a local profile passphrase and choose **Pair**. Approve the
     Enclave prompt if macOS shows one.
   - For a new profile, "Save your recovery words privately". Write them down, then choose
     **I saved these words**.
   - "LokiSigner is running". Choose **Done**.

   While the link is out the wallet watches the public roster. Once the slot appears there,
   the wallet says so and you can continue to step 2. The roster alone cannot tell you whose
   app registered the slot. Compare the code on your own Mac before allowing the tab. When the two
   minutes run out first, the link and copy button go away; **Get a new link** asks for the
   same slot again. A lapsed slot can go to another member: the wallet then says the slot was
   taken, and the next link uses another slot. The wallet never asks for a new link by itself,
   because each one reserves a slot.
2. **Connect this wallet tab**: on **that same Mac**, unlock LokiSigner, select its slot in
   the wallet, and choose **Connect LokiSigner**. If the app is still registering, the tab
   retries for up to a minute, then offers **Try again**. When LokiSigner asks, check the
   wallet origin and match the six-digit code in the app to the one in the tab, then choose
   **Allow**. If they do not match, choose **Refuse**. Nothing is copied. Allow local network
   access if your browser asks.

The app stays running for ceremony, payment review and signing using the existing device
consent and nonce-witness paths. Connect separately in each new tab and after a relaunch. In
the **LokiSigner** menu, **Disconnect all wallet tabs** withdraws existing grants without
quitting or locking the app. Wallet logout locks the profile and revokes all wallet-tab grants.
Quit also invalidates every grant; launch again to unlock and register with the saved public
coordinator/slot, without reusing the claim.

With saved settings, you can unlock and use local features such as **Vault addresses…** and
**Restore a vault…** while the coordinator is offline. If registration fails or is refused,
LokiSigner shows a warning, stays unlocked and keeps trying in the background. A launch with
a new pairing link waits for the registration result before reporting success.

If you cancel, enter the wrong passphrase, or LokiSigner cannot start, choose **Try again**
or **Quit**. If the coordinator refuses a pairing, retry the saved pairing or get a new link
from the wallet. When the existing profile has no vault data, **Start over…** lets you set it
aside before pairing or restoring. LokiSigner moves the whole data folder to a dated sibling;
it deletes neither the folder nor the old device key in the Keychain. New native profiles save
a random key scope and use a different device login key, even at the same path. That key stays
with its profile if the folder is moved. Existing vault share key tags do not change.

**Update the coordinator and wallet before updating LokiSigner.**

| Coordinator and wallet | LokiSigner | What the member sees |
| --- | --- | --- |
| Old | Old | Paste the private link displayed by LokiSigner. |
| New | Old | The wallet still offers the paste flow for an older app. |
| Old | New | First pairing shows a refusal; a saved profile opens with a registration warning and retries. The old wallet offers only paste, and the new app has no link to paste. |
| New | New | Select the member slot, choose **Connect LokiSigner**, and compare the code before allowing. |

`loki_member_app` and `LokiSigner serve` still use their printed pairing link. Once a new
LokiSigner has registered, **do not roll back the coordinator** without removing the roster
rows containing `lokisigner_url`. The old coordinator rejects those rows as an “unexpected
registration field,” breaking `/api/members` for everyone, not just those slots.

The signed `lokisigner_url` roster field tells everyone who can read `/api/members` that the
slot uses LokiSigner and which local port it currently listens on. The field is separate
from the peer endpoint and contains no tab token. A website the member visits can use that
port and the member API's open ceremony routes to learn that LokiSigner is running, subject
to the browser's local network permission. Only the pinned coordinator origin can ask to
connect from a browser. Grants are stored in `sessionStorage`: duplicating a tab can copy its
grant without another **Allow**. The coordinator serves the page but never receives the token
in registration. Safari may block the wallet's request to loopback; this has not been verified.

## Back up and restore a vault

After your vault is active, choose **Download encrypted backup** in the wallet's **Recovery**
card. The ciphertext is stored in your LokiSigner profile on this Mac, not by the coordinator.
**Keep the downloaded JSON somewhere other than this Mac.** If you lose the Mac and the file,
the 24 words alone cannot recover the vault. Export one file per vault and store your words
privately, separately from the files. Together the words and a file can recover your share.

On a new Mac, open LokiSigner without a pairing link. Choose **Restore from recovery words**,
enter the original coordinator's HTTPS origin, confirm it, and review the signer configuration.
Choose one backup file in LokiSigner, enter the 24 words, and set a new local profile passphrase.
LokiSigner opens the file locally and checks that both recovered public identity keys identify
exactly one slot in the coordinator's roster. It saves the recovered vault and identity together,
then registers the new Mac in that slot without reserving a new one. If the connection fails
after saving, keep LokiSigner running or reopen and unlock it to retry. If the coordinator
refuses the slot before the first successful registration, LokiSigner checks the member list
again and uses a different slot only when exactly one entry matches both public identity keys.
You won't need the words again to reconnect. Use **Connect LokiSigner** to connect each
wallet tab on the new Mac.

Restore can reuse an absent or empty data folder, or one with only recognized leftovers: empty
`profile/` or `device-auth/` directories, the public `native-key-scope` file, incomplete
pairing or signer-settings `.tmp` files, and an empty `vaults/` directory or one holding only
generated restore staging directories. Restore preserves these leftovers in a dated sibling.
Anything unrecognized requires you to confirm **Start over…** before it is moved. Any other
entry in `vaults/`, a `vaults` file, a legacy `card` entry, or top-level `vault.card`,
`vault.sealed`, or `share.sealed` protects the profile from being set aside. LokiSigner tries
to clear expired `.loki-restore-<UUID>` directories at startup, both in `vaults/` and beside
the data folder. Symlinks to the data folder still work; set-aside keeps the link pointing to
the newly emptied location and archives the old contents beside its target.

If you already paired a different member by mistake, choose **Start over…** from the retry
dialog or when **Restore a vault…** says the backup does not match the running profile. Confirm
**Set aside and start over**, then choose **Restore from recovery words**. LokiSigner will not
set aside a profile with vault data. To restore a different member in that case, use another Mac
or macOS account.

Restore each additional backup from **LokiSigner → Restore a vault…** in the unlocked app.
It must belong to the same member and recovery words. It will not replace an existing vault.
After the replacement registers, the coordinator's device binding and advertised endpoint
point to the new Mac; the member slot and identity keys stay the same. This does not erase or
revoke the old Mac's local share. Quit and retire the old signer if you still have it: a Mac
that still holds the identity can register another device binding again.

LokiSigner refuses HTTP recovery setup and restore. It continues serving recovery status and
the encrypted backup. The headless `loki_member_app` and `LokiSigner serve` **do** keep HTTP
setup and restore for automation; their authenticated callers handle the words directly.
The native restore field is masked, with spell checking and autocorrection off. LokiSigner
clears the field and Rust wipes the writable FFI buffer after copying it. Swift/AppKit do not
guarantee that transient string or text-editor copies are wiped from process memory. Do not
copy your words into the system clipboard or type them into the wallet.

## Verify a receive address

In the **LokiSigner** menu, open **Vault addresses…**. Each active vault shows its network,
your member slot, and the full receive address with a **Copy address** button. macOS may ask
for Touch ID when LokiSigner first opens a vault's signer store. Use **Refresh** if you finish
setting up a vault while the window is open.

Give senders the address copied from LokiSigner, or compare the full addresses before sharing
the one on the wallet page. A page served by the coordinator could substitute a different
address and redirect deposits. LokiSigner derives the address from the device-bound signer's
group viewing key and checks it against the local public metadata. If it cannot verify a
vault's address, it shows an error and offers nothing to copy. Vault names are creator-supplied
labels, not instructions from LokiSigner.

## Roster code

Before key generation every member compares the vault's 24-digit roster code with the others,
so a coordinator cannot swap a member in. For a LokiSigner member the wallet page cannot agree
to a roster by itself. When the member chooses **Compare in LokiSigner** on the wallet's
**Verify members** step, LokiSigner shows "Do the roster codes match?" with the threshold,
the member count, the member's slot, the network and the code. Rust derives the code from the
same setup document the signer checks in `dkg_begin`. The vault name comes from the creator's
invite. It follows the same rule as in **Vault addresses…**: it is shown as written, in its own
one-line box, or replaced whole by "Name hidden (unsupported characters)" when it is longer
than 80 characters or holds a control, format, default-ignorable or line-breaking character
or a run of more than three combining marks.

- **Codes match** records the agreement and tells the creator.
- **Codes differ** records nothing, and LokiSigner refuses that vault until it restarts, so a
  page cannot reopen the dialog until the member gives in.
- Neither button answers to Return, Space or any other key. The dialog takes focus when a page
  asks, possibly while the member is typing elsewhere, so the member must click.
- Closing the dialog or leaving it unanswered for 10 minutes records nothing; the member can
  ask again.

LokiSigner shows one roster dialog at a time. While it is open the member's other requests
continue, and when the roster or the setup changed in the meantime the answer is refused.

The roster dialog and the payment dialog are both modal on the app's main thread. A payment
request that arrives while the roster dialog is open waits until the member answers it or it
times out, and only then shows its own dialog. Ten minutes may be longer than the
coordinator waits for this member's approval, so answer the roster dialog before approving
payments.

The headless member (`loki_member_app`, `LokiSigner serve`) has no screen. It keeps the earlier
behaviour: `POST /api/agree` with the right code agrees, so it trusts whoever holds its session
token to have compared the code with the other members.

## Signer configuration

LokiSigner needs no terminal or flags. Its network, frostd relay, lightwalletd and the two
nonce witnesses are chosen by **the coordinator whose origin the member confirmed** in the
pairing dialog. That coordinator serves them at `GET <origin>/api/signer-config`. They are the
values its signer origin gives the browser signer (`LOKI_NETWORK`, `LOKI_FROSTD_URL`,
`LOKI_LIGHTWALLETD_URL` and `LOKI_NONCE_WITNESSES` in `poc/loki-signer-wasm/serve.mjs`).

- **Coordinator first.** Opening a pairing link first shows only the coordinator origin and
  slot, read from the link by Rust without any network request. LokiSigner contacts that
  coordinator only after the member confirms it is the one they intended.
- **Shown before saved.** It then fetches the configuration and shows the network and every
  endpoint beside the coordinator origin, with the passphrase field. LokiSigner runs with
  exactly the values shown, without fetching again.
- **Checked locally.** LokiSigner treats the reply as untrusted. It refuses unknown fields,
  mainnet, remote endpoints without TLS (loopback HTTP only with `--development-http`),
  endpoints containing whitespace, control or non-ASCII characters, and witnesses that hosted
  signing would refuse. The request follows no redirect and times out. The app shows a fixed
  message on failure, not the coordinator’s reply or HTTP status.
- **Saved once unlocked, and pinned.** The configuration is saved only after the local profile
  unlocks, owner-only (0600) in the data directory: `signer-config.json` with the coordinator
  origin it came from, and the witnesses in `nonce-witnesses.json`, the `--nonce-witnesses`
  format. A wrong passphrase saves nothing. A configuration from any coordinator other than the
  paired one is refused and the saved one is left as it was. A new pairing link for the same
  coordinator and slot refreshes it once the member confirms and unlocks.
- **Unlock.** A plain launch shows and uses the saved configuration. A profile paired before
  configurations were saved fetches it once from its paired coordinator.
- **Flags.** An explicit `--network`, `--frostd-url`, `--lightwalletd-url` or
  `--nonce-witnesses` overrides the value for that field **for this launch only**. When a flag
  overrides a fetched value, nothing is saved, because the member was shown the flag's value
  and not the coordinator's.
- **Nothing to run with.** When a launch still lacks the network, frostd, lightwalletd (on
  testnet) or the witnesses, LokiSigner reports that it couldn’t load settings. It never
  falls back to regtest defaults.
- **Regtest deployments.** The signer origin's `LOKI_NETWORK` defaults to `testnet`. A regtest
  stack must set `LOKI_NETWORK=regtest` on the signer origin, or LokiSigner is told testnet.

This applies only to the native app's pairing and unlock. `LokiSigner serve` and the headless
`loki_member_app` keep their flags and defaults.

Pairing reserves a slot for 120 seconds. Both claim and registration are consumed once,
including failed proofs; claiming does not extend the deadline. If it expires while saving
recovery words, choose **Get a new link** in the wallet, which asks for the same slot (or,
if another member took it meanwhile, a new one). After
a lost response, choose **Try again** and unlock; an outstanding reservation may need to expire before
retry. Public device bindings prevent a different identity or slot from reusing the enrolled
key.

The default data directory is `~/Library/Application Support/LokiSigner`; default listener
is a dynamically chosen loopback port. Production coordinator links require HTTPS. Local
HTTP coordinators need an explicit development launch:

```sh
poc/signer-app/out/LokiSigner.app/Contents/MacOS/LokiSigner native --development-http
# Or launch with a link and member configuration:
poc/signer-app/out/LokiSigner.app/Contents/MacOS/LokiSigner pair 'loki://pair?...' \
  --data /path/to/member --port 3601 --development-http \
  --frostd-url http://127.0.0.1:2744 --nonce-witnesses /path/to/witnesses.json
```

Other member flags are the existing `loki_member_app` flags: network, lightwalletd, relay,
nonce witnesses, and peer allowlist. Each overrides the coordinator's value for its field,
for that launch only. For members on separate Macs, configure a reachable
HTTPS `--advertise-url` (forwarded to the member service) and the allowed `--peer` origins.
The private browser session still uses loopback; it is never sent to that public endpoint.
The link contains only origin, slot and a random claim, never runtime configuration or keys;
the configuration comes from that origin, as described above.
The native passphrase is passed to Rust in memory and the Swift byte buffer is immediately
zeroed. `serve` retains S4a's local-file unlock for development automation only.

## Verification

With a built wallet (`cd web/wallet && npm run build`) and Rust member binary:

```sh
node poc/scripts/test_self_registration.mjs --pairing
# Exercise the signed app instead; approve the local Enclave prompts:
LOKI_NATIVE_SIGNER=1 \
LOKI_MEMBER_APP_BIN="$PWD/poc/signer-app/out/LokiSigner.app/Contents/MacOS/LokiSigner" \
node poc/scripts/test_self_registration.mjs --pairing
```

For a complete real paired signing/payment run, use a running web coordinator, frostd,
lightwalletd, nonce witnesses, and the existing funded testnet fixture. This test **broadcasts
a testnet payment**, keeps member state in the printed private temporary directory, and
requires native consent/Touch ID:

```sh
LOKI_NATIVE_SIGNER=1 \
LOKI_MEMBER_APP_BIN="$PWD/poc/signer-app/out/LokiSigner.app/Contents/MacOS/LokiSigner" \
LOKI_COORDINATOR=http://localhost:3001 \
LOKI_NONCE_WITNESSES=/path/to/witnesses.json \
FROSTD_URL=http://127.0.0.1:2744 \
LIGHTWALLETD_URL=https://testnet.zec.rocks:443 \
RECIPIENT='<testnet Orchard address>' AMOUNT_ZAT=100000 \
bash poc/scripts/test_payment.sh
```

## One-time setup (done)
- Apple ID in Xcode → Settings → Accounts.
- **Apple WWDR intermediate** installed (otherwise the Dev cert is "invalid"):
  `curl -O https://www.apple.com/certificateauthority/AppleWWDRCAG3.cer && security import AppleWWDRCAG3.cer -k ~/Library/Keychains/login.keychain-db`
- Team: `B399KAT22M`. Touch ID present (biometric mode works).

## Build + run (the one GUI step that provisions a free-team profile)
```sh
cd poc/signer-app && ruby gen.rb        # regenerates LokiSigner.xcodeproj (needs the xcodeproj gem)
open LokiSigner.xcodeproj               # in Xcode: select the LokiSigner scheme, Product → Run (⌘R)
```
The first GUI **Run** registers this Mac as a dev device and generates the provisioning
profile (free teams can't do this headlessly). The console prints:
```
SIGNER-APP ENCLAVE PASS: persistent wrap/unwrap of a signer DEK
```
After that first run the profile exists; subsequent `xcodebuild … -allowProvisioningUpdates`
builds work headlessly.

- `LokiSigner persist`   — create + reload a persistent SE key, wrap/unwrap (no biometric).
- `LokiSigner biometric` — same, gated by **Touch ID** on unwrap (interactive).

## Native signer: the real Rust signer seals its share in the Enclave

`./build.sh` builds the Rust signer as a static lib (`libloki_poc.a`, `--features
apple-enclave`), links it + the Swift Enclave backend into the app, and runs:

```
RUST SIGNER ENCLAVE PASS: FROST share sealed + reloaded under the persistent Secure Enclave key
```

The app calls `loki_signer_enclave_selftest()` (`poc/src/enclave_ffi.rs`), which runs the
actual signer path — `SealedShare::seal` under `AppleSecureElement::persistent` — so the
member's FROST share is held in a persistent, device-bound, biometric-capable Secure Enclave
key, **inside the provisioned app**. Built entirely on the Mac (crates.io + Enclave + Xcode).
Arch must be `arm64` (matches the Rust lib). `libs/` is regenerated by `build.sh`, not committed.
