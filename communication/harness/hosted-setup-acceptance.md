# test(setup): consolidated acceptance evidence

The implementation checkpoint reconciles updated main `d68d9b3` (mailbox-bound nonce witnesses and refusal to reprovision surviving nonces). Recorded passes below predate that merge; merged-source native validation is a separate pending gate. Existing payment runs continue against their recorded pre-merge binaries, with saved state preserved.

The required implementation batch includes scoped provisioning, all-peer certified configuration, signed automatic activation, both payment policies, signer/dashboard integration and the local faucet/relay checkpoint. Consolidated validation completed the communication workspace (1,127 passed, eight process-child fixtures ignored by discovery), the full native suite (249 passed, four process-child fixtures ignored by discovery), wallet regressions (46 passed), three browser scripts, source/dependency isolation and the 61-case harness. The final unfiltered native result uses current optimized artifacts and includes both policies' complete automatic handoff and every-member card restoration. Actual process-kill evidence is separate from simulated faults.

Required mined payment acceptance remains incomplete overall. Three-member AB, AC and BC have confirmed transactions and independently decrypted recipients. BC reused an existing approved broadcast that a timed-out harness left in the mempool; its saved aggregate and exact raw transaction were reverified, mined and checked against the original independent recipient without signing again. Four-member AB is also confirmed, with both independent finishers agreeing on the saved aggregate and the original recipient decrypting it while physical relay 1 was offline. Four-member AC is also confirmed with both independent finishers and recipient decryption. Four-member AD is confirmed as well. BC, BD and CD remain unconfirmed; their current run uses retained automatically activated vaults and source-bound settled journals. These runs do not repeat DKG. Debug payment attempts reached their existing deadlines, so the current acceptance selects optimized PoC binaries through `LOKI_POC_BIN_PROFILE=release`; guards and deadlines remain unchanged. Record compiler and binary hashes alongside the resulting reports. A running case or a selected pair does not establish complete policy acceptance.

The VPS TLS preflight established verified cross-host HTTPS and wrong-hostname rejection only. It did not execute native setup, certified configuration installation or signed activation over HTTPS. Automatic review rejected repository-source export; none was transferred. A local network-disabled x86_64 Linux build is preparing the narrower binary-only transfer path. Native separate-host acceptance remains outstanding. The user-selected independent agent review found no confirmed Critical or Important defect in invitation trust, DKG checkpoint serialization, enrollment, backup or payment handoff. Two Minor findings are deferred: duplicate relay run IDs can pass bundle validation but fail closed during nonce witness selection, and authenticated invitation expiry is omitted from UI status. The complete review is recorded in `hosted-setup-security-review.md`; it does not establish production or mainnet custody approval. The device comparator requires every certified member's report across at least two actual hosts, with exact policy, configuration, relay pins, address and activation agreement. Operator-collected host metadata is not hardware attestation.

Build the test artifacts and run the full communication and PoC suites as a consolidated gate; fix demonstrated failures within that validation phase. Run signer, dashboard, local faucet/relay and browser regressions in that phase. The owned harness reuses the real native integration fixture, retains private runtime roots and emits allowlisted public evidence. A successful selected scenario does not establish overall completion.

```sh
cargo +1.89.0 test --manifest-path communication/Cargo.toml --workspace --locked
cargo +1.91.0 test --manifest-path poc/Cargo.toml --features relay-communication --locked
python3 poc/scripts/verify_relay_source_isolation.py
python3 -m unittest discover -s poc/tests -p test_dependency_graph.py
python3 communication/harness/hosted_setup.py acceptance --run-root /private/tmp/loki-hosted-3-NEW --members 3
python3 communication/harness/hosted_setup.py acceptance --run-root /private/tmp/loki-hosted-4-NEW --members 4
python3 communication/harness/hosted_setup.py acceptance --run-root /private/tmp/loki-hosted-outage-4-NEW --members 4 --offline-relay 1
```

Actual process kills use `setup-fault-injection`, a debug-only opt-in feature. Build the `setup_relay` test artifact with that feature before selecting `faults`. The hook pauses only at the explicitly selected member root and phase, after the sealed generation and directory are durable. The owner kills the actual process, reopens it without the hook and verifies all earlier sealed checkpoint bytes remain identical. Killing Starting must retire that attempt; it must never run part1 a second time. All other saved phases are killed and resumed within one ceremony per policy, followed by the complete signed handoff. Starting is a separate abort case; the default campaign uses two ceremonies per policy rather than restarting a full ceremony for each checkpoint. Simulated reply-loss tests and actual kills are recorded separately.

```sh
cargo +1.91.0 test --manifest-path poc/Cargo.toml --features setup-fault-injection --test setup_relay --no-run --locked
python3 communication/harness/hosted_setup.py faults --run-root /private/tmp/loki-hosted-kills-3-NEW --members 3
python3 communication/harness/hosted_setup.py faults --run-root /private/tmp/loki-hosted-kills-4-NEW --members 4
```

A retained local fixture does not establish distinct-host HTTPS, independent operator/device isolation or mined payments from the automatically configured hosted vault. Four-member relay payment acceptance must exercise AB, AC, AD, BC, BD and CD, both observers' independent aggregate verification, exact share retry, nonce protection, mining and independent recipient decryption. These gates and independent security review must be recorded individually with compiler versions, binary/configuration digests, relay key/run pins, public message hashes, group key/address equality and transaction confirmation. Never include recovery words, passphrases, capabilities, invitations, DKG packages or sealed-state plaintext in evidence or a PR.


Retained setup runs can exercise real mined payments over their saved automatic configurations, without manually provisioning replacement inboxes. Select the exact retained owner's run ID from `.harness-owner.json`. These commands operate only on owned regtest roots and the selected THS instance. They create an independent recipient and run every required pair, checking both non-signers' independent aggregation and recipient decryption. `--offline-relay 1|2|3` omits one physical store while preserving all three recorded pins.

```sh
python3 communication/harness/hosted_setup.py payments --run-root /private/tmp/loki-hosted-payments-4-NEW --members 4 --source-run /private/tmp/loki-hosted-4-NEW --source-run-id EXACT_OWNED_RUN_ID --name OWNED_THS_INSTANCE
```

The payments command verifies and locks the retained source owner, copies only certified encrypted member/configuration state and SQLite snapshots, restarts the existing pinned relay roots and denies member sandbox access to source, peer and operator state. It does not run DKG again or use operator provisioning credentials. Payment reports distinguish manual provisioning from an installed hosted configuration.


On each physical device, complete the hosted signer flow against the same signed HTTPS operator configuration, then collect public native evidence in a new owned root. The native exporter re-verifies the complete installed configuration, exact saved checkpoint and every signed activation notice. It refuses unfinished handoff; the collector refuses development HTTP. Transfer only the public reports to the coordinator and compare all member slots, operator pins, certificate fingerprint, group key/address and recorded host IDs. Collect one report per member across at least two physical devices or distinct hosts, as required by the hosting gate; the comparison records the actual host count. Collector host metadata is operator evidence, not hardware attestation. Record negative certificate/hostname and changed-pin checks separately.

```sh
python3 communication/harness/hosted_setup.py device-evidence --run-root /PRIVATE/NEW/PUBLIC-EVIDENCE --member-root /PRIVATE/MEMBER --passphrase-file /PRIVATE/PASSFILE
python3 communication/harness/hosted_setup.py distinct-hosts --run-root /PRIVATE/NEW/COMPARISON --members 4 --device-reports /PUBLIC/device-1.json /PUBLIC/device-2.json /PUBLIC/device-3.json /PUBLIC/device-4.json
```

## fix(harness): recover saved handoff checkpoints

The acceptance fixture held the setup lock while spawning its address CLI. Releasing that lock before spawning fixes the deadlock. The `resume-handoff` command verifies and locks the exact retained owner and reuses its signed operator configuration, relay stores and sealed member checkpoints. It maps each sorted signed route to its saved relay manifest and preserves physical relay numbering. Completed fixtures are reaped before cleanup; bounded failure diagnostics remain private and are excluded from reports.

Finalization deleted the peer backup words as designed. The old failed fixture had retained them only in memory, so these recovered runs can check creator restoration using the existing private checked-words input, but cannot prove peer-card restoration. Reports record the actual restored member slots. The planned full fault campaigns must still establish restoration for every member; recovered handoff evidence cannot substitute for that gate. No recovery command repeats DKG or rotates saved relay configuration.

```sh
python3 communication/harness/hosted_setup.py resume-handoff --run-root /private/tmp/NEW-RECOVERY-OWNER --members 4 --source-run /private/tmp/EXACT-RETAINED-OWNER --source-run-id EXACT_OWNED_RUN_ID --offline-relay 1
```

## test(setup): recovered policy readiness and regression gates

Both saved policy runs completed signed handoff for every member; the four-member case kept physical relay 1 offline. Recovery checked creator-card restoration, unchanged prior sealed bytes, repeated configuration installation and activated-state abort refusal. All-member card restoration remains part of the required complete crash campaigns. The complete wallet regression gate passed 46 cases; harness discovery passed 51 cases including stopped-WAL source preservation. These results do not establish mined payments or overall acceptance.

Actual crash acceptance keeps pause markers outside the strict sealed journal and drives the initial phases through the CLI, preserving the journal file allowlist. Payment acceptance copies a locked stopped source database and WAL into a private scratch directory, recovers it with SQLite and exports a closed DELETE-journal snapshot. It does not open the saved source for writing. Hosted inbox validation checks the native authenticated configuration reference and every recorded relay pin before using those inboxes as the expected payment inventory.

## fix(relays): bounded backlog and accurate checkpoint evidence

Consolidated payment validation exposed pending-transfer capacity that remained occupied after relay storage. Upload now invokes the SDK's existing release method, which reopens the committed message and verifies the complete recipient/object receipt intersection before writing the immutable completion marker. Crossed relay pairs release no capacity; a common verified pair releases capacity idempotently. The 128-transfer and storage limits remain unchanged. A capacity-blocked original no longer prevents later authenticated candidates from reconciling, and the owned runner retries only the exact capacity error after uploading saved outboxes. Failed attempts retain their private data and do not repeat DKG.

The complete harness suite passed 54 cases before the final report-only correction, and source/dependency verification passed after the bounded status and acknowledgement fixes. These results are separate from mined policy acceptance. Actual checkpoint kills cover phases 0,2,3,4,5,6,7,8 in both recovered policy runs, and separate Starting-phase cases establish phase1 kills and abort. Starting returns before a vault or backup exists; its earlier generated report incorrectly listed backup restoration slots. Those fields are invalid evidence and have been corrected in the exporter. Legacy recovered full handoffs prove creator restoration only; every-member restoration remains a native acceptance requirement.

The user authorized Tailscale SSH to `ssf-replica`, and access as root was verified. An isolated private acceptance root was created. No repository source has been uploaded: automatic approval review requires specific authorization for that transfer. Distinct-host HTTPS acceptance and the independent reviews remain incomplete.

## fix(payments): authenticate readiness before advancing signing phases

The final complete communication gate passed 1,127 tests with zero failures and eight existing ignores. Its new real-crypto regression covers both policies, caches70 original encrypted records with signed relay receipts, bounds polling admission to64 shared slots, commits the atomic Received copies and verifies that all original ciphertexts remain unchanged. The unrestricted store/authentication API retains the128-transfer safety contract; only polling schedules intake in smaller batches.

Actual payment runs then exposed a different harness error: one transport pump was treated as evidence that commitments or shares had arrived. Package construction correctly refused a missing commitment, and an independent finisher correctly refused missing shares. The owned runner now waits only on the exact native missing-message result and pumps transport within the original deadline. Package, review and both independent finisher checks use that wait; signature and every other failure stop immediately. Native finish-check reports pending authenticated prerequisites immediately, while actual proving/broadcast retains its prior wait and verification. Approval still requires the exact review token and nonce witness.

The complete corrected harness gate passed56 tests in83.099seconds, including malformed/wrong-member/signature-error refusal in the phase wait. These passes do not establish mined policy acceptance or distinct-host HTTPS. The existing full native ceremony has allseven participants active/ready, but its final required checks are still running. The remaining BC and all-six four-member mined payments are running with the phase-readiness correction. No DKG was repeated for a payment retry.

## fix(harness): preserve completed broadcasts and settled transport

After every independent finisher verifies the saved shares, proof and broadcast do not require another transport pump. Collect that native result directly under the original deadline. A failed finisher retains bounded mode-0600 diagnostics outside public reports. A retained `final.hex` is not acceptance by itself: compare it to the node transaction, reverify the approved aggregate and mined candidate, and decrypt with the original independent recipient.

For remaining distinct payment pairs, a new owned run can retain the completed transport journal rather than replaying historical traffic from an older setup snapshot. Supply `--transport-source-run` and `--transport-source-run-id` for the stopped private-member owner. The harness locks that exact owner and compares the roster, every sealed identity/vault/activation/configuration and passphrase to the original certified source before copying any journal. It changes only the new run's source copies; native configuration validation and all signing checks still apply. Keep the original setup owner and all signing data intact. Record separately confirmed pairs when selecting only the remaining pairs.
