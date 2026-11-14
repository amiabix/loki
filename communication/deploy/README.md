# feat(setup): hosted operator deployment

## Single-host loopback TEST bringup

This toolkit runs three owned relays and one admission service on one host at
`127.0.0.1:39101`–`39104`. Use a new absolute directory each time; it contains
private operator capabilities and the test enrollment issuer seed. Bash, Cargo,
Python 3, and curl are required.

```sh
communication/deploy/bringup.sh /absolute/new/test-stack
communication/deploy/teardown.sh /absolute/new/test-stack
```

Bringup builds the release binaries with `--locked`, generates random TEST keys,
initializes three separate relay roots and the admission root, signs a canonical
development bundle, starts all four services, and checks each `/health` endpoint.
It refuses an existing root. Teardown sends the services SIGINT and preserves the
roots, logs, and operator inputs for inspection. The admission executable in this
checkout has `serve` only: input generation creates its root and signing key.
Each relay's `init` creates its signing key and run identity. Relay provision
files are numbered in **bundle signing-key order**, which admission requires;
the relay roots remain numbered by listener port.

The generated paths are:

| Path under the root | Use |
| --- | --- |
| `inputs/bundle`, `inputs/config-key` | Member operator bundle and trusted 32-byte configuration public key |
| `inputs/config-signing-key` | Private TEST configuration seed; keep on operator host |
| `inputs/issuer-public-key`, `inputs/issuer-signing-key` | Admission enrollment verifier and private TEST issuer seed |
| `inputs/relay-{1,2,3}-provision` | Private relay capabilities for admission, in bundle order |
| `relay-{1,2,3}/`, `admission/` | Persistent service roots |
| `issue-enrollment` | TEST issuer executable for a member app on this host |

## Single-host self-custody member stack (frostd)

The audited DKG/signing on `main` runs over **frostd** (`FrostdTransport`), not the
owned relays above. `selfcustody-testnet.sh` stands up the full self-custody stack on
one host — the public-roster web coordinator plus N `loki_member_app` processes that
self-register — then drives a t-of-n DKG to `active` and prints the shared address.
Bash, Cargo, Node, Python 3, curl, and openssl are required.

```sh
communication/deploy/selfcustody-testnet.sh /absolute/new/member-stack
kill $(cat /absolute/new/member-stack/pids)   # stop
```

It builds `loki_member_app` (`--features relay-communication`) and the web coordinator,
starts the coordinator on `:3001` with `LOKI_REGISTRY` pointed at the stack root, starts
N members (software device storage, self-registering to the coordinator), waits for the
roster to fill, then creates/joins/agrees the ceremony and reports the `utest1…` address.
Tunables are environment variables (`FROSTD_URL`, `LWD_URL`, `NETWORK`, `MEMBERS`,
`THRESHOLD`, `WEB_PORT`, `BASE_PORT`); defaults are a testnet 2-of-3 against
`http://127.0.0.1:2744` and `https://testnet.zec.rocks:443`.

**frostd must be https off loopback** (`transport::require_tls_off_loopback`): a plaintext
dev relay (`frostd -n -p 2744`) is only accepted on loopback, so forward a remote one first
and keep the default `FROSTD_URL`:

```sh
ssh -N -L 2744:localhost:2744 your-frostd-host   # then run selfcustody-testnet.sh
```

One member app on its own:

```sh
poc/target/release/loki_member_app --data /absolute/member-1 --port 3601 \
  --network testnet --lightwalletd-url https://testnet.zec.rocks:443 \
  --frostd-url http://127.0.0.1:2744 --allow-loopback-peers \
  --secure-element software --development-http \
  --coordinator-url http://localhost:3001 \
  --local-passphrase-file /absolute/member-1.pass --registration-slot 1
```

`--allow-loopback-peers` is required on testnet when members are co-located on loopback
(the SSRF guard otherwise rejects loopback peer URLs). The local-passphrase file must be
mode 0600. This is a one-host TEST setup, not production HTTPS or independent operators.

### Owned-relay operator kit (above)

The `bringup.sh` relay/admission stack is the operator-side enrollment/admission toolkit
and is independent of the frostd DKG path. For a member app that uses it, pass the relay
kit (`--operator-bundle inputs/bundle`, `--operator-key $(xxd -p -c 256 inputs/config-key)`,
`--enrollment-issuer <root>/issue-enrollment`, `--development-http`). The bundle, key, and
issuer executable are the member's relay kit; never copy the private operator seeds or
provision files into a member root. A member app on another machine cannot use these
literal loopback origins.

`compose.hosted-test.yml` is an alternative runner for already initialized
roots. It requires `LOKI_OWNED_RELAY_IMAGE`, `LOKI_OWNED_RELAY_{1,2,3}_ROOT`,
`LOKI_OWNED_ADMISSION_IMAGE`, `LOKI_OWNED_ADMISSION_ROOT`, and
`LOKI_OWNED_OPERATOR_INPUTS`; the final variable names the generated `inputs/`
directory. The image variables need operator-built images containing the two
service binaries. The scripts above run the binaries directly and do not need
those environment variables.

Build the communication workspace with Rust 1.89 and the PoC signer with Rust 1.91. Enable `relay-communication` for the signer. `setup-fault-injection` is an opt-in debug acceptance feature; release compilation rejects it. Never deploy that acceptance build.

Each of the three relay stores has its own persistent root, signing key, run identifier and provisioning capability. Serve its private loopback listener through a TLS reverse proxy. Initialize with an immutable HTTPS public origin matching the proxy hostname; neither forwarded headers nor redirects change the trusted endpoint. Clients verify the platform certificate chain and hostname and the signed relay challenge against the operator bundle. Listen/private origin and signed/public origin are separate settings.

The admission service requires a signed operator bundle, its trusted configuration key, its own signing key and the three provisioning files. Keep operator capabilities exclusively on the service hosts, outside any member data root. Give them mode 0600 and their parent directories mode 0700. Admission provisioning records contain owner-generated verifiers; the service never creates member read/admin secrets. Store the admission SQLite database and its tombstones on durable encrypted storage. Back up the database coherently, including its WAL or a SQLite backup, and test recovery before operating it. Reusing an operation ID with changed bytes is refused.

Configure an enrollment verifier explicitly. Creation is denied when no issuer is configured. Production enrollment issuance is an integration with the chosen authentication and abuse-control system; this branch does not choose or deploy that provider. The signer supports a scoped grant for its saved creator identity or a configured issuer executable. The executable receives only the public device signing key, operator bundle path and policy and returns a signed grant on stdout. Do not put issuer private keys or operator capabilities in the signer. Issuance failure retains the pending identity, and native setup persists the exact successful grant before an admission request. Owned fixtures use test keys solely in private disposable roots.

Mailbox quotas, setup deadlines and invitation first-claim expiry come from signed configuration. A successful same-identity claim remains retrievable after invitation expiry. Admission terminal state does not erase certified payment mailboxes or nonce claims: setup inboxes retire separately, and existing payment retention remains unchanged. Activation requires every certified member's signed vote and two common physically provisioned relay identities. An admission outage leaves saved setup pending; it does not authorize payment readiness, replace the operator bundle or rerun DKG.

Renew TLS certificates without changing the signed hostname or relay key/run. Changes to relay identities, public origins, admission keys or configuration trust require an explicitly reviewed rotation. Existing ceremonies retain their recorded bundle and pins; retries never select replacement operators silently. Monitor quota pressure, provisioning retries, terminal retirement and admission backups without logging bearer capabilities, invitation secrets, recovery words, DKG packages or sealed-state plaintext.

The supplied compose file describes one owned loopback acceptance environment with three separately initialized persistent relay roots and one admission root. Set each `LOKI_OWNED_RELAY_1_ROOT`, `LOKI_OWNED_RELAY_2_ROOT` and `LOKI_OWNED_RELAY_3_ROOT` to a different new private root; initialize its own key/run and use ports 39101–39103 in the signed development bundle. It is not evidence of operator independence or separate-device HTTPS acceptance. Production deployment remains gated on operator/enrollment decisions, distinct-host TLS acceptance and independent review of invitation trust, checkpoint serialization, backup and payment handoff. Regtest acceptance does not approve mainnet custody.
