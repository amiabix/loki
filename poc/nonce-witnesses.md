# Hosted nonce witnesses

Hosted signing requires `--nonce-witnesses /path/to/witnesses.json`. The file is a
JSON array of exactly two objects. Each object contains `endpoint` (an HTTPS
origin), and `key`, `run`, `mailbox`, `read` (each a JSON array of 32 byte values).
`key` and `run` pin the relay identity; `mailbox` identifies an already provisioned
mailbox; `read` is its owner read capability. Keep the file private. The existing
relay provisioning tools supply these values; the signer does not provision or
replace witnesses automatically. `--development-http` permits loopback HTTP for
local tests, using the existing relay client's endpoint rules.

Use independently operated relays whose durable nonce ledgers are outside the
profile's backup/rollback domain. Both must return fresh, signed, challenge-bound
first-write receipts before a share is computed. Claims are keyed by the FROST
public key, signer identifier and nonce commitment, so changing an attempt name
or restoring the signing journal cannot obtain a second claim. The claim record
contains the signing package and randomizer seed sealed by the existing secure
element; the relays do not receive the plaintext package.

The original relay keys, run IDs and mailboxes are sealed alongside each nonce
before its commitment is published. Changing any of them refuses the saved nonce.
A duplicate claim, an unavailable witness, or a crash after claiming but before
saving a share requires a fresh signing attempt with fresh nonces. A locally saved
share can still be resent. Pre-upgrade nonces lack the witness binding and are
refused; start a fresh attempt. Do not reset a witness ledger while old nonce
snapshots may exist.

## Device-owned nonce storage

Hosted payments keep nonces in `<data>/vaults/<vault>/signer/nonces`, beside the
device's share and secure element, using that share's element and current epoch.
The nonce directory is mode 0700 (files 0600); symlinked nonce directories are
refused. In the co-located demo, `<data>` belongs to that member's signer process.
These permissions do not isolate processes running as the same OS user. Software
SE storage retains its existing reduced guarantee: the KEK is passphrase-sealed.

Recovery artifacts contain share material, never nonce or burn files. Exclude
`signer/nonces` from coordinator profile archives; do not restore it with profile
state. External witnesses remain mandatory even for device-local nonces, including
when an entire device filesystem snapshot is restored.

The old `<data>/vaults/<vault>/signer-nonces` directory is no longer read or written.
Before upgrading, stop or abandon in-flight signing attempts. Start fresh attempts
after upgrading, then remove the retired directory, including its separate KEK,
nonce and burn files. Do not copy its files into `signer/nonces` or replace the
share's KEK. Keep the existing witness configuration and ledgers intact.

## Local Enclave demo

Nonce witnesses use the Loki relay (`communication/relay`), whose `/v1/mailboxes`
and signed nonce receipts are separate from frostd's session API. Two mailboxes on
one relay do not satisfy the distinct key/run checks. The demo starts two Loki
relay processes on `127.0.0.1:39101` and `127.0.0.1:39102`; frostd remains the
existing message transport. No SSH or remote service is needed for the witnesses.

From the repository root:

```bash
cd /Users/abix/Work/Zcash/Projects/loki-zcash-frost-worktrees/speedmaster
# Builds the existing relay and provisioning example, starts both relays,
# provisions one mailbox each, and prints the absolute witnesses.json path.
LOKI_NONCE_WITNESSES="$(bash poc/scripts/nonce_witnesses.sh)" && export LOKI_NONCE_WITNESSES

# Rebuild if the signed app predates the nonce-witness fix (requires Xcode signing).
bash poc/signer-app/build.sh
bash poc/scripts/enclave_local.sh
open http://localhost:3001
```

Alternatively, `bash poc/scripts/enclave_local.sh` runs witness setup itself when
`LOKI_NONCE_WITNESSES` is unset. An explicitly supplied path must already be
provisioned with both relays running. Signup and restart forward
`--nonce-witnesses "$LOKI_NONCE_WITNESSES" --development-http` to each signer;
other launchers leave signer arguments unchanged when the variable is unset.
The existing stack still needs its frostd and chain services.

State lives in `~/loki-nonce-witnesses`, outside the signer profile directory.
Pass a different persistent directory as the script's first argument if needed.
Each `relay-{1,2}` root has its own key, run ID and random provisioning capability.
The script initializes each with `--listen 127.0.0.1:39101` (or `39102`),
`--total-bytes 67108864 --mailbox-bytes 67108864 --mailbox-count 1`, then uses
`serve --root <root> --listen <address>`. Logs and PID files are beside the roots.
It reuses running listeners only after the helper verifies the expected pins.

To rerun just provisioning/verification after the relays are running:

```bash
cargo run --manifest-path poc/Cargo.toml --features relay-communication \
  --example provision_nonce_witnesses -- --development-http \
  --relay-root "$HOME/loki-nonce-witnesses/relay-1" \
  --relay-root "$HOME/loki-nonce-witnesses/relay-2" \
  --out "$HOME/loki-nonce-witnesses/witnesses.json"
```

The helper uses each root's existing `manifest` and raw 32-byte `provision.secret`,
authenticates both relay identities, and writes the shared `WitnessConfig` schema
with mode 0600. Interrupted provisioning resumes identical requests from
`witnesses.json.pending`. Successful reruns validate and reuse the existing file
and mailboxes. Keep this state private and persistent; do not delete, regenerate,
or restore its ledgers with signer backups. A full 64 MiB ledger fails closed.
Start a fresh signing attempt for pre-upgrade or already-claimed nonces.

This is a local demo: both relays share the Mac's failure/rollback domain.
Production requires two independently operated relays with separate durable
storage outside the signer backup domain, accessed over HTTPS.
