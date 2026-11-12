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

`LOKI_DEV_FAUCET=1` enables the optional local-origin regtest faucet; it receives only a public
regtest address. It is off by default, and the supplied launcher binds Next to localhost.

## Registry and limits

`.access.json` (or `LOKI_REGISTRY`) contains only `{access: [{slot, signing_pubkey, relay_pubkey,
advertise_url}]}`. Old hosted registry formats fail closed; retire those files privately and
self-register existing devices into a fresh public roster. Never copy old access records into
it. The adjacent `.challenges` file contains only short-lived public enrollment proofs and
nonces; consumption persists across Next workers and restarts. At most 256 live challenges
are accepted, each expires after two minutes. If a worker crashes while holding `.lock`, stop
all web workers before removing that lock. The roster is discovery, not authority to spend.

This is a **development-only pairing seam**: the coordinator-served JavaScript is trusted
with that tab's device session. A malicious web bundle can steal that session; device-side
consent remains required for signing. Co-location under one OS account is not independent
custody against that OS operator. Real cross-device QR pairing and the native signed app
client are S4b. No QR or production device trust UX is implemented here. The existing Enclave
binary is reused; no Swift changes are required.

## Checks

```sh
node --experimental-strip-types --test tests/*.test.mjs scripts/wallet-ui.test.mjs
npx tsc --noEmit
npx next build
```

The end-to-end local registration/restart smoke test is in
`poc/scripts/test_self_registration.mjs` (starts isolated member processes explicitly, outside
Next). Run it after building `loki_member_app` with `relay-communication` and the web bundle.
