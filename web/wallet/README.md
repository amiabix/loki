# S4a keyless coordinator

Next publishes a **public roster** and the UI. It does not start signers, unlock profiles,
store member capabilities, proxy device calls, or perform signing. `poc/src/host/payment.rs`
runs in each **member-owned process**, including share loading and S1 consent. DKG and
payment relay traffic still goes directly from those processes to frostd; S2 share storage,
S3 nonce state and the two Gap-C witnesses are unchanged.

## Co-located development

Use `bash poc/scripts/enclave_local.sh 2` from the repository root, after building the existing
Enclave signer (`bash poc/signer-app/build.sh`) and installing the existing wallet dependencies.
The script starts the web and two member processes with separate data directories and local
unlock files. Signer stdout goes to the terminal, not web logs. Save each member's recovery
words privately when shown. The script uses a new `public-roster.json`; old hosted data is
left intact. It will not restart processes already occupying the ports.

Alternatively, start Next in this directory:

```sh
LOKI_REGISTRY=/absolute/path/public-roster.json npx next dev --hostname localhost -p 3001
```

Then, in **each member's terminal**, with the two witness routes configured:

```sh
export LOKI_NONCE_WITNESSES=/absolute/path/witnesses.json
bash poc/scripts/member_local.sh 1
# In another terminal, with the same witness config:
bash poc/scripts/member_local.sh 2
```

Paths above are from the repository root. `member_local.sh` defaults to the existing Enclave
app. `LOKI_SECURE_ELEMENT=software` selects the explicitly insecure development backend and
`poc/target/debug/loki_member_app`. `NETWORK`, `LWD`, `FROSTD_URL`, `LOKI_MEMBER_DATA`,
`LOKI_COORDINATOR`, and `LOKI_LOCAL_PASSPHRASE_FILE` override the member-local configuration.
For an existing member, point `LOKI_MEMBER_DATA/<slot>` at its existing data and supply its
original local unlock file; no shares or recovery identity are migrated automatically.

The member process creates/unlocks its profile **locally**, then authorizes its P-256 device
key with its existing Ed25519 identity. It requests a one-use challenge and signs a transcript
binding the coordinator origin, requested slot, identity keys, advertised endpoint and nonce.
The Node verifier uses the same Ed25519 enrollment / P-256 SHA-256 verification protocol as
`signer/device_auth.rs` and `host/device.rs`; the Rust client reuses the enrollment verifier.
This proves key possession, **not hardware attestation**. The software development backend
and an Enclave key produce the same wire proofs.

Open `http://localhost:3001`. Paste the member's printed **local pairing link into the pairing
field**, never into the address bar or a message to an operator. Each tab stores its own
device capability in session storage and calls that manually selected loopback endpoint
with `X-Loki-Token`; no capability is sent to Next. The device allows only the exact configured
browser origin, and pairing checks the device's public identity against the roster. A roster
update cannot silently retarget an existing paired tab. Create/join, review/approve, and
co-signing use the existing typed device API. Logout locks the device; restart that member
locally with its unlock file and pair with its new link. A web restart does not restart members.

A LokiSigner member compares the roster code in LokiSigner, not on this page: **Compare in
LokiSigner** opens LokiSigner's dialog, and only its **Codes match** records the agreement
(see `poc/signer-app/README.md`). The page knows LokiSigner asks because the member's vault
status reports `roster_dialog`. A headless member paired with this tab (`loki_member_app`,
`LokiSigner serve`) does not, so the page shows it the code to compare, as it always did. After confirming the roster, a member stays on **Verify
members** until the creator has all confirmations and publishes the relay session. Waiting
for people has no key-generation timeout. A creator lock or temporary disconnect can be retried before key generation starts;
an unlocked member restarted during that wait retains its confirmation. Once key generation
has started, an interruption requires **Create a new vault**, new invitations, and a new code
comparison by every member. The failed vault and its diagnostic error remain available.

`LOKI_DEV_FAUCET=1` enables the optional local-origin regtest faucet; it receives only a public
regtest address. It is off by default, and the supplied launcher binds Next to localhost.

## In-browser signer: enroll → discover → DKG

An in-browser signer (`src/lib/signer.ts`, the wasm core in `poc/loki-signer-wasm`) has no
local HTTP server, so it enrolls as a **frostd-only member with no `advertise_url`** — peer
traffic goes over the frostd relay (peer-over-frostd), and the roster stores `advertise_url: ""`
for it. Native members still advertise their loopback origin and enroll exactly as before; both
coexist in one roster. A browser member has completed a real **2-of-3 DKG** over the live relay.

**Serving the signer.** `scripts/copy-signer.mjs` (wired to `predev`/`prebuild`) stages the built
`poc/loki-signer-wasm/{pkg,signer-worker.js,signer-client.js}` and `poc/wasm-transport/pkg` into
`public/signer/` (gitignored), keeping the worker's relative `./pkg/...` + OPFS-snippet imports
intact. `signer.ts` then defaults to the served worker at `/signer/signer-worker.js`: a HEAD
probe confirms the asset before binding the `Worker`, so `browserSigner` is the default whenever
the bundles are present and a build without them degrades cleanly to the in-memory mock. Build
the bundles first — `RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack build --dev --target
web` in `poc/loki-signer-wasm`, and `wasm-pack build --target web` in `poc/wasm-transport`.

1. **Create / unlock** the signer (passkey or passphrase). The device `Identity` is held in the
   Worker.
2. **Enroll** — `enroll(coordinatorOrigin?)` (default: same origin):
   - the Worker returns `enrollMaterial()` → `{signing_pubkey, relay_pubkey}` (the relay key is
     the frostd-login pubkey);
   - the browser generates a non-extractable **WebCrypto P-256 device key** (persisted in
     IndexedDB, reused on re-enroll) and the Worker's `authorizeDevice()` signs it with the
     member identity — the same Ed25519/P-256 proof as `poc/src/host/registration.rs`;
   - `POST /api/members/challenge` → the browser signs the registration transcript
     (`advertise_url` is `""`) with the device key (ECDSA P-256 / SHA-256, IEEE-P1363) →
     `POST /api/members` returns the allocated member and `slot`.
3. **Discover** the ceremony params. The public coordinator (this Next app) owns only the roster;
   the DKG session is run by the vault **creator** (slot 1), which serves `vaultHex`, the setup
   doc (`rosterHex`, `setup_version: 2`), the frostd `sessionId` and `coordinatorPeer` from its
   ceremony endpoints (`/api/roster`, `/api/session`, see `poc/src/host/ceremony.rs`). The UI/parent
   supplies these to the signer. **Not built here:** a browser-reachable discovery surface for the
   creator's session (CORS/TLS + invite delivery, or a vault-announcement endpoint in this app) —
   see the handoff below.
4. **DKG** — `request("dkg", {vaultHex, slot, label, network, rosterHex, coordinatorPeer,
   sessionId})` drives `driveDkg()` to an active vault + address. `signer.ts` folds `frostdUrl`
   and `transportUrl` into every ceremony/payment call from **deployment config**: set the TLS
   relay with `NEXT_PUBLIC_FROSTD_URL`, and `transportUrl` defaults to the served
   `/signer/wasm-transport/pkg/loki_wasm_transport.js` (override with
   `NEXT_PUBLIC_SIGNER_TRANSPORT_URL`). The frostd endpoint must be reachable over **https/wss
   with CORS** — a browser cannot use a loopback-plaintext relay.

Onboarding (create/unlock → Home) works standalone; the full ceremony above needs that live
coordinator + frostd. Payment review/approve are wired through `request()` the same way.

## Registry and limits

`.access.json` (or `LOKI_REGISTRY`) contains only `{access: [{slot, signing_pubkey, relay_pubkey,
advertise_url, lokisigner_url?}]}`. The optional signed `lokisigner_url` field tells everyone
reading `/api/members` that the slot uses LokiSigner and which loopback port it currently
listens on. It is not a capability. Deploy this coordinator and wallet before updating
LokiSigner; an older coordinator rejects registration containing the field. Headless and
older apps without that field still use the pasted local link. Old hosted registry formats
fail closed; retire those files privately and self-register existing devices into a fresh
public roster. Never copy old access records into
it. The adjacent `.challenges` file contains only short-lived public enrollment proofs and
nonces; consumption persists across Next workers and restarts. At most 256 live challenges
are accepted, each expires after two minutes. If a worker crashes while holding `.lock`, stop
all web workers before removing that lock. The roster is discovery, not authority to spend.

LokiSigner sends a tab its device session only after the member allows that tab's code in
the native app. The coordinator-served JavaScript can still read a grant held by its own tab;
device-side consent remains required for signing. Co-location under one OS account is not
independent custody against that OS operator.

## Checks

```sh
node --experimental-strip-types --test tests/*.test.mjs scripts/wallet-ui.test.mjs
npx tsc --noEmit
npx next build
```

The end-to-end local registration/restart smoke test is in
`poc/scripts/test_self_registration.mjs` (starts isolated member processes explicitly, outside
Next). Run it after building `loki_member_app` with `relay-communication` and the web bundle.

The confirmation regression starts three disposable testnet member processes against a live
`frostd`, delays the remaining confirmations for 22 seconds, locks and restarts the creator,
restarts the waiting member, then checks that all three activate the same vault. From the
repository root, after building `loki_member_app`:

```sh
FROSTD_URL=http://127.0.0.1:2744 node --test poc/scripts/test_confirmation_wait.mjs
```

## Payment approval and recovery

Publishing creates separate encrypted control and signing relay sessions. Each selected member’s
approval inbox discovers pending requests over the control session without a copied attempt ID.
Review the full recipient, amount and fee, then approve on each selected member. Waiting for people
does not start a signing timeout or create a nonce. After quorum, the proposer prepares wallet inputs
and starts the bounded signing round automatically. A saved signed PCZT is required for **Ready to
send**; the proposer can then use **Review & send** and **Confirm and send**. A delayed final send
does not require another signing round. Peer status notices do not establish chain confirmation;
each wallet verifies that locally.

Consent waiting can resume after a member restart. A started signing round cannot restart under
the same attempt ID. Failed attempts retain their diagnostic state and nonce journal. The proposer
can **Discard failed payment** only when no signature share was released and no signed or raw
transaction exists. Discard closes relay sessions, saves a cancellation record, and releases that
attempt’s reserved input; the next payment gets a fresh ID. Ambiguous signed outcomes stay reserved
for recovery. Broadcast retries reuse the saved raw transaction and move input reservations atomically.

The payment regressions use disposable testnet identities and synthetic notes with the live relay;
they never broadcast a transaction:

```sh
FROSTD_URL=http://127.0.0.1:2744 cargo test --manifest-path poc/Cargo.toml --locked --offline --features relay-communication --lib host::payment::tests
```

## Browser signer (separate signer origin)

The in-browser signer runs on its **own origin**, not the wallet's. `poc/loki-signer-wasm/serve.mjs`
serves the signer page, Worker, wasm and transport. The wallet embeds that page in an iframe and
exchanges only public data with it over postMessage. The passkey PRF ceremony, the passphrase,
the roster-code comparison and every payment approval happen on the signer page. The share
stays in that origin's OPFS.

Local development uses two ports. Build the wasm once (both pkgs are gitignored):

```sh
# in poc/loki-signer-wasm
RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack build --dev --target web
# in poc/wasm-transport
wasm-pack build --target web
```

Then, in web/wallet:

```sh
LOKI_FROSTD_URL=http://127.0.0.1:2744 npm run signer   # signer origin  → http://localhost:3002
npm run dev                                           # wallet         → http://localhost:3001
```

`next dev` points at `http://localhost:3002` by default. A production build **must** set
`NEXT_PUBLIC_SIGNER_ORIGIN`. Without it, every signer call fails. There is no mock fallback in a
browser.

What a deploy must provide on the signer server (`serve.mjs` env):

| variable | meaning |
|---|---|
| `LOKI_WALLET_ORIGIN` | the one wallet origin allowed to frame and message the signer (`frame-ancestors`, postMessage check) |
| `LOKI_FROSTD_URL` | the frostd relay the signer logs in to. It is shown to the member and not settable from the wallet page. One relay only. |
| `LOKI_RP_ID` | WebAuthn rpId. It **must stay the same across deploys** or passkeys stop unlocking. |
| `LOKI_NONCE_WITNESSES` | the two nonce-witness relays every signature is claimed at (the native `--nonce-witnesses` file). Each mailbox `read` capability is served publicly in `config.json`. |
| `LOKI_NETWORK` | `testnet` (default) or `regtest`; mainnet is refused at startup. A regtest stack **must** set `regtest`, or LokiSigner is told testnet. |
| `LOKI_LIGHTWALLETD_URL` | the lightwalletd native members sync from |
| `LOKI_SIGNER_PORT` | listen port (default 3002) |

The coordinator (this app) serves the same values to the native signer at
`GET /api/signer-config`: network, frostd, lightwalletd and the witnesses, read from
`${NEXT_PUBLIC_SIGNER_ORIGIN}/config.json` on each request (the origin is inlined at build time,
as for the browser signer). Nothing is copied into the wallet's own configuration. The route answers 502 with an error when the signer origin is unset,
unreachable, redirects, or serves a configuration it cannot validate, and it never serves
mainnet. LokiSigner shows these values when it pairs and saves them (see
`poc/signer-app/README.md`).

The signer origin itself must be **stable**. The share (OPFS), the device-login key (IndexedDB)
and the passkey (rpId) are all bound to it. A new hostname per run (for example a fresh
trycloudflare URL) gives an empty signer that cannot open the old share. Only one tab per browser
profile may run the signer: a Web Lock guards the Worker, its share and its nonce store. Other
tabs refuse signer operations until the first one closes.

The signer origin sends a strict CSP: only its own scripts, `wasm-unsafe-eval` for wasm, and connections only to itself, the relay and `LOKI_CEREMONY_ORIGINS`. It answers only from the snapshot it read at startup. `node poc/loki-signer-wasm/serve.mjs --hash` prints the published build hash (per-file SHA-256 plus one bundle hash), and a running signer serves the same thing at `/build-hash.json`. Publish the bundle hash with each release so the deployed signer can be compared against it.
