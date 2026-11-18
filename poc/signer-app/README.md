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

In the web wallet choose **Pair a new native signer**, then **Open LokiSigner** (or copy the
link to the member's Mac). Confirm the coordinator shown in the native dialog. Enter a local
profile passphrase, save the recovery words privately, and approve the Enclave prompt. The
app displays a private local session link: paste it into the wallet tab on **that same Mac**.
The app stays running for ceremony, payment review and signing using the existing device
consent and nonce-witness paths. Quit locks the process; launch again to unlock and register
with the saved public coordinator/slot, without reusing the claim.

## Signer configuration

LokiSigner needs no terminal or flags. Its network, frostd relay, lightwalletd and the two
nonce witnesses are chosen by **the coordinator whose origin the member confirmed** in the
pairing dialog. That coordinator serves them at `GET <origin>/api/signer-config`. They are the
values its signer origin gives the browser signer (`LOKI_NETWORK`, `LOKI_FROSTD_URL`,
`LOKI_LIGHTWALLETD_URL` and `LOKI_NONCE_WITNESSES` in `poc/loki-signer-wasm/serve.mjs`).

- **Shown before saved.** Opening a pairing link fetches the configuration and shows the
  network and every endpoint beside the coordinator origin. Nothing is saved until the member
  continues, and LokiSigner runs with exactly the values shown, without fetching again.
- **Checked locally.** LokiSigner treats the reply as untrusted. It refuses unknown fields,
  mainnet, remote endpoints without TLS (loopback HTTP only with `--development-http`), and
  witnesses that hosted signing would refuse. The request follows no redirect and times out.
- **Saved and pinned.** The configuration is saved owner-only (0600) in the data directory:
  `signer-config.json` with the coordinator origin it came from, and the witnesses in
  `nonce-witnesses.json`, the `--nonce-witnesses` format. A configuration from any coordinator
  other than the paired one is refused and the saved one is left as it was. A new pairing link
  for the same coordinator and slot refreshes it once the member confirms.
- **Unlock.** A plain launch shows and uses the saved configuration. A profile paired before
  configurations were saved fetches it once from its paired coordinator.
- **Flags.** An explicit `--network`, `--frostd-url`, `--lightwalletd-url` or
  `--nonce-witnesses` overrides the saved value for that field only.
- **Nothing to run with.** When a launch still lacks the network, frostd, lightwalletd (on
  testnet) or the witnesses, LokiSigner names what is missing and does not start. It never
  falls back to regtest defaults.

This applies only to the native app's pairing and unlock. `LokiSigner serve` and the headless
`loki_member_app` keep their flags and defaults.

Pairing reserves a slot for 120 seconds. Both claim and registration are consumed once,
including failed proofs; claiming does not extend the deadline. If it expires while saving
recovery words, request a fresh link for the same slot. After a lost response, restart and
unlock; an outstanding reservation may need to expire before retry. Public device bindings
prevent a different identity or slot from reusing the enrolled key.

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
nonce witnesses, and peer allowlist. Each overrides the coordinator's value for its field. For members on separate Macs, configure a reachable
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
