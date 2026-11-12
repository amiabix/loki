# test(harness): offline delivery and fault evidence

`run.py` uses selected built binaries, explicit argv lists, separate member/relay roots, process handles and bounded deadlines. It creates only new owned roots and stops only its children. Ordinary exits retain data. Symlink components, occupied ports, foreign/replaced roots, mismatched run IDs and unowned process handles are refused. Closing an owner after that same handle successfully deleted its run is harmless; a missing or foreign root does not acquire that exception.

The setup uses `loki_setup_member identity`, `fingerprint` and certified `run`, followed by member provisioning and six encrypted descriptor handoffs. Each member child receives its own root/passphrase and the public roster. The controller does not invoke address, backup, funding, scanning, signing, chain, Docker or wallet-server stages.

## test(harness): commands

On macOS `/tmp` is a symlink, so choose `/private/tmp` roots. Existing roots are retained; select another new path and free ports for another run. An explicit `CARGO_TARGET_DIR` is honored by both build workspaces and binary discovery. Default profile is `debug`; the harness does not build binaries.

```sh
python3 communication/harness/run.py acceptance --run-root /private/tmp/loki-relay-acceptance-new --ports 39101 39102 39103
python3 communication/harness/run.py faults --run-root /private/tmp/loki-relay-faults-new --ports 39111 39112 39113
python3 communication/harness/run.py faults --run-root /private/tmp/loki-relay-orphan-new --ports 39301 39302 39303 --scenario orphan_flood
python3 communication/harness/run.py delete --run-root /private/tmp/SELECTED_RUN --expected-run-id RUN_ID_HEX32
```

`acceptance` exits zero only after all offline, self-copy, acknowledgement, complete replica and restart assertions pass. `faults` runs all seventeen scenarios by default, or the explicitly selected names. Each scenario has a 300-second bound and the full campaign a 1,200-second bound. Captured stdout/stderr are bounded to 65,536 bytes; stderr and failure bodies are excluded from public reports. Rust fixture summaries must show a successful exit, at least one executed passing case, and matching test names. Cargo's launcher name is preserved for rustup multicall installations.

A selected subset leaves unrelated coverage rows `not_selected`. An inventory row passes only when every contributing scenario passes. Failure of any required observation prevents that row from passing. `completed` means all selected scenarios succeeded; consult all 26 inventory rows when assessing complete coverage.

## test(harness): existing vault across three member environments

`three_members.py` reuses a selected completed vault rather than creating new
member identities. The source must contain `roster.json` and
`members/{1,2,3}/secrets/{identity,vault}.sealed` plus each member's `passphrase`
file, as retained by `run.py acceptance`. It also accepts the activated
`source/` directory made by `poc/run-member-payment.py --manual`. Selection is explicit: the test never
silently chooses a different vault or starts a new setup ceremony.

On macOS, each Rust member invocation runs through `sandbox-exec` with a separate
member root, HOME and TMPDIR. Real read probes must deny both peer roots, relay
storage and the original vault, while allowing its own state. Runtime commands
also cannot read the provisioning capabilities. The controller copies the
selected sealed identity, sealed vault, passphrase and, when present, the sealed
activation record into each private test root, with fresh transport journals.
Source hashes must remain unchanged.
These are three process sandboxes on one host, not separate OS users, machines
or operators. Isolation fails closed when macOS sandboxing is unavailable.

Build the server and member binaries using the commands in
[`../README.md`](../README.md), then run with a new directory and three free ports:

```sh
python3 -m unittest discover -s communication/harness -p 'test*.py'
python3 communication/harness/three_members.py \
  --vault-root /private/tmp/loki-relay-acceptance-review-20261010-a \
  --run-root /private/tmp/loki-three-members-new --ports 39401 39402 39403
```

All members use the same three relay identities, with nine private inboxes and
six encrypted configuration handoffs. Each member sends one 64-byte message and
one 65,537-byte chunked message while the other member commands are offline.
After the sender exits, both peers poll and upload authenticated Received
acknowledgements. The final checks require six originals, twelve distinct peer
acknowledgements returned to the corresponding authors, four peer originals per
member, and two sender self-copies without self acknowledgements. Whole-vault
Stored must cover every recipient object on the same two distinct relay pins.
The CLI's `pending_transfers` counter includes outgoing bookkeeping without a
cached completion marker, so it can remain nonzero after quorum delivery. The
test uses authenticated readiness, complete replica receipts and peer Received
evidence as its completion criteria.

Repeated request IDs, uploads and polls must preserve message identity without
duplicate effects. Restarting the relays and reopening all member sessions must
preserve ciphertext, sequences and saved receipts. Every command is bounded;
the full test has a 600-second deadline. Status capture allows at most 256 KiB
for the larger six-message inventory; the existing harness keeps its 64 KiB cap.
The CLI reports authenticated IDs and digests, not decrypted payload text.

Success writes `three-members-report.json` with public setup, message, receipt,
isolation and restart evidence. Failure writes `three-members-failure.json`.
Owned children are stopped and all run data remains for inspection; the existing
run-ID deletion command can explicitly remove that test run later.

## Funded payment through private member relays

`relay_payment.py` connects the regtest signing fixture to the relay. Run it
against a fresh funded manual payment; each run consumes that payment's note.
It copies sealed source state into three sandboxed member roots, gives each
member its own payment mailbox, and moves encrypted signing envelopes through
three relays. The selected pair approves; any member can prove and send. The
finisher checks the mined effects and an independent recipient decrypts the output.

```sh
cargo build --manifest-path communication/Cargo.toml --locked -p loki-relay-server
cargo build --manifest-path poc/Cargo.toml --locked --bins --features relay-communication
python3 poc/run-member-payment.py --name loki-manual \
  --state /private/tmp/loki-fresh-payment --manual --pair BC
python3 communication/harness/relay_payment.py \
  --payment-root /private/tmp/loki-fresh-payment \
  --run-root /private/tmp/loki-fresh-relay-payment \
  --name loki-manual --ports 39561 39562 39563 --finisher 2
```

The THS regtest instance must already be running and `ths` must be on `PATH`.
Success writes `relay-payment-report.json` with the payment ID, txid and counts.
This is a regtest integration fixture: the pair is selected when the payment
is prepared, signing uses volatile nonces and a 120-second live wait, and
prints Approved before the relay has stored the share. The relay's kind 1
payload carries the encrypted inner signing envelope,
selected by the attempt ID; the signer authenticates the inner envelope and
verifies transaction effects before releasing a share. This run does not
establish browser custody, approval recovery after a crash, a relay nonce
witness or independent relay operators.

## test(harness): scenario evidence classes

| Scenario | Observation and injection |
| --- | --- |
| `outage` | Stops the third owned relay before publication, then stops one acknowledged relay. Stored was established on the other two; Bob authenticates both messages from the surviving acknowledged replica. New automatic Received entries are allowed while every original remains exact. |
| `quota` | The preferred two inboxes fill with the original and Bob's Received. They refuse a new message. The available third accepts its copies, but one complete replica leaves whole-vault Stored false. Retry attempts count failed schedules, so a successful first PUT can have zero attempts. Original/Received objects and reads remain intact. |
| `retained_restart` | Owned production relay stop/restart preserves key, run, ciphertext, sequences and receipt digests. |
| `append_rotation` | Real member rotation advances each append revision and the sealed reference without changing saved object/receipt identity. Exact retry and redistribution are also checked by `provisioning_retry`. |
| `offline_delivery` | Built production binaries perform ordinary/chunked offline delivery, self reconciliation, Received return and relay restart. |
| `missing_chunk` | Native complete-transfer, staged-authentication, partial-input/no-Received and same-pair union fixtures. Missing chunks/copies/manifests withhold completion. |
| `forged_inner_sender` | Real `RelayStore` accepts and retries an HPKE object using a valid append capability. The recipient rejects the inner signature and preserves encrypted rejection evidence without an original or Received, including after reopen. Public hash, pin, run, length and counts are emitted. |
| `invalid_receipt` | Scripted HTTP receipts exercise key/run/mailbox/hash/length/sequence/retention/signature binding and duplicate identity counting. |
| `missing_download` | Scripted HTTP 404, malformed receipt, omitted sequence, durable task/cursor recovery, bounded samples and later valid progress. |
| `crash_recovery` | Test-only preinsert/afterinsert rollback, simulated commit-error and lost reply, actual SQLite FULL, and actual SIGKILL before/after relay/client commit points. Outgoing and acknowledgement HTTP peers are signed fixtures. |
| `binding` | Ciphertext/context/sender tamper, canonical framing, complete manifest/chunk validation and exact bounds. |
| `ordering_conflict` | Reordered three-relay delivery, early Received, wrong target/session/digest/author and same-ID authenticated conflict preservation after reopen. |
| `provisioning_retry` | Real relay revision fixtures and PoC sealed-state partial rotation/uncertain-response retries. |
| `canonical_vectors` | Deterministic CBOR rejection, 64 KiB boundaries, the selected RFC suite's known-answer vectors and maximum 274-chunk transfer. |
| `orphan_flood` | Reduced test budget reaches real staging admission: accepted encrypted orphan chunks and a pre-existing pending download survive refusal and reopen. The refused hash, cursor and counts are public. This is budget admission, not a claim of hardware disk exhaustion. |
| `sealed_config` | Member CLI restart with missing referenced sealed configuration fails closed. |
| `capacity` | Real relay-store quotas retain duplicate receipts, reads and accepted objects after reopen. |

Native test-process scenarios set `simulation: true` to distinguish fixture execution from the production controller. The crash group explicitly labels its combination of real process kills, real engine FULL and simulated commit/response faults. `power_loss` is false throughout. Production CLIs expose no fault endpoint.

## docs(harness): retained validation

The real acceptance evidence is `/private/tmp/loki-relay-acceptance-20261010-a/acceptance-report.json`. It includes three public relay keys/run IDs, nine mailbox IDs, six descriptor digests, original/Received ciphertext hashes and receipt digests before/after restart. The final campaign is `/private/tmp/loki-relay-faults-20261010-c/fault-report.json`: all seventeen scenarios and all 26 coverage rows passed, with no failures or skipped rows. The [completed requirement audit](verification-2026-10-10.md) maps all 47 units and 26 rows to named evidence; its JSON companion records source/log/report hashes. The orphan supplement `/private/tmp/loki-relay-orphan-evidence-20261010/fault-report.json` records three accepted orphan chunks, one pending task, cursor four and the refused ciphertext hash. Earlier failed campaign roots remain retained as diagnostic evidence.

No capabilities, passphrases, payloads or decrypted member secrets belong in public reports. Tests verify redaction and process ownership. Local key separation does not establish separate operators. SIGKILL and synchronous FULL do not establish physical power-loss durability. The separate payment fixture above establishes only its named regtest payment and chain checks; it makes no browser or custody claim.

## fix(harness): resume retained native HTTPS acceptance

`native_hosted.py` and `native_hosted_payments.py` resume the owned 2026-10-14
separate-host fixtures. They keep member keys, operator state and payment work on
their original hosts. Remote paths and accounts match that fixture, so inventory
its owner markers and services before using these runners. No repository source
needs to be transferred to the remote host.

Set `LOKI_ACCEPTANCE_ROOT` to the retained private root containing `owner.json`
and `public-operator.json`, `LOKI_SETUP_BIN` and `LOKI_PAYMENT_BIN` to the existing
verified native artifacts, and `LOKI_SOURCE_TREE` to their recorded source tree.
For payments also set `LOKI_THS_INSTANCE` to the retained regtest instance and
`LOKI_ACCEPTANCE_RECIPIENT` to the retained independent recipient root. Run:

```sh
python3 communication/harness/native_hosted.py
python3 communication/harness/native_hosted_payments.py
```

Certified members retain their fingerprint consent and skip invitation,
agreement and DKG replay. Final card completion checks `final-card/vault.card`,
not the card directory. Funding retains THS's original address-derived
idempotency keys and stores its confirmed receipt. Payment actions store intent
before execution and results after success; resume reuses completed actions and
stops at uncertain signing or broadcast actions. Reconcile the original attempt
against saved local wires or the chain before marking such an action complete.
Never delete an intent to make a retry possible.

The payment runner supervises its own loopback reverse SSH forward from remote
`127.0.0.1:47052` to local `127.0.0.1:18452`, checks the pinned regtest branch,
and uses bounded SSH connection and keepalive limits. It terminates only its own
SSH child. Admission HTTPS must be healthy independently; an RPC tunnel does
not repair an unavailable admission service. Preserve diagnostics privately.
