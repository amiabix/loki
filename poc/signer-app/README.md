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
   - "Pair this device with slot N?" with the coordinator origin. Choose **Continue** only if
     it is the wallet's address.
   - "Pair this device with slot N?" again, with the network and endpoints that coordinator
     chose (see below). Enter a local profile passphrase and choose **Pair**. Approve the
     Enclave prompt if macOS shows one.
   - For a new profile, "Save your recovery words privately". Write them down, then choose
     **I saved these words**.
   - "Signer paired and running". Choose **Copy private link**.

   While the link is out the wallet watches the public roster. Once the slot appears there,
   the wallet says so and moves to step 2. It cannot tell whose identity registered the slot,
   so trust LokiSigner's "Signer paired and running", not the roster alone. When the two
   minutes run out first, the link and copy button go away; **Get a new link** asks for the
   same slot again. A lapsed slot can go to another member: the wallet then says the slot was
   taken, and the next link uses another slot. The wallet never asks for a new link by itself,
   because each one reserves a slot.
2. **Paste LokiSigner's private link**: paste the private session link into the wallet tab on
   **that same Mac** and choose **Pair this tab**. A member whose app is already paired starts
   here after unlocking it.

The app stays running for ceremony, payment review and signing using the existing device
consent and nonce-witness paths. Quit locks the process; launch again to unlock and register
with the saved public coordinator/slot, without reusing the claim.

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
invite, so it appears in its own box as one line, with control, invisible and line-breaking
characters replaced.

- **Codes match** records the agreement and tells the creator.
- **Codes differ** records nothing, and LokiSigner refuses that vault until it restarts, so a
  page cannot reopen the dialog until the member gives in.
- Neither button answers to Return, Space or any other key. The dialog takes focus when a page
  asks, possibly while the member is typing elsewhere, so the member must click.
- Closing the dialog or leaving it unanswered for 10 minutes records nothing; the member can
  ask again.

LokiSigner shows one roster dialog at a time. While it is open the member's other requests
continue, and when the roster or the setup changed in the meantime the answer is refused.

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
  signing would refuse. The request follows no redirect and times out. Its errors name only
  the origin and the HTTP status; nothing the coordinator sends is shown.
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
  testnet) or the witnesses, LokiSigner names what is missing and does not start. It never
  falls back to regtest defaults.
- **Regtest deployments.** The signer origin's `LOKI_NETWORK` defaults to `testnet`. A regtest
  stack must set `LOKI_NETWORK=regtest` on the signer origin, or LokiSigner is told testnet.

This applies only to the native app's pairing and unlock. `LokiSigner serve` and the headless
`loki_member_app` keep their flags and defaults.

Pairing reserves a slot for 120 seconds. Both claim and registration are consumed once,
including failed proofs; claiming does not extend the deadline. If it expires while saving
recovery words, choose **Get a new link** in the wallet, which asks for the same slot (or,
if another member took it meanwhile, a new one). After
a lost response, restart and unlock; an outstanding reservation may need to expire before
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
