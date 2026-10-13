# feat(setup): hosted vault review checkpoint

Draft review is appropriate. Required implementation is present for both policies: scoped provisioning, all-peer certified configuration installation, signed automatic payment activation, dashboard/private-signer integration, and the local faucet/relay checkpoint. Updated main `d68d9b33a79ecd372e18c9cb528cacfc46491cac` is reconciled, retaining mailbox-bound nonce witnesses, fail-closed legacy nonce records and the surviving-nonce reprovision guard. No saved vault, runtime or secret is part of this checkpoint.

The independent five-area source review found no confirmed Critical or Important implementation defect. See [complete review](hosted-setup-security-review.md). Two deferred Minor findings remain: signed bundles can contain duplicate relay run IDs and later fail closed at nonce witness selection; UI invitation status omits the authenticated expiry enforced by the backend. The [base-update assessment](hosted-setup-security-review-base-update.md) found no must-fix regression. Merged-source native artifacts compiled successfully; the complete native suite is now running in the isolated build root. Agent review is not production or mainnet custody approval.

Mandatory acceptance gaps at checkpoint creation: four-member BC, BD and CD; actual native setup, certified configuration and signed activation across two hosts over verified HTTPS; merged-source consolidated native validation. Four-member AB, AC and AD and all three three-member pairs have confirmed transactions and independent recipient decryption. Both four-member independent finishers agreed, with relay 1 offline. Existing payment acceptance is isolated and continues against its recorded pre-merge binary manifest; it cannot establish merged-source acceptance. TLS preflight proves only connectivity and hostname rejection, not native hosting acceptance. Unknown-CA and changed-pin negative cases must accompany the actual hosting gate.

Before the base update, the complete communication suite passed 1,127 cases, native suite 249, wallet 46 and harness 61, with three browser scripts and source/dependency verification passing. Eight communication and four native process-child fixtures are ignored by discovery; actual process-kill evidence is separate. These are recorded passes, not overall completion or a substitute for merged-source validation.

## test(setup): reproducible consolidated validation

Prerequisites: Rust 1.89 for communication, Rust 1.91 for PoC, Python 3, the pinned local THS/Zakura regtest stack for payment acceptance, and a Chromium-compatible browser. Run from repository root unless the command says otherwise. Use new private absolute runtime roots; on macOS `/private/tmp` avoids the `/tmp` symlink. Do not reuse another owner's roots or change existing THS instances. Fetch locked dependencies if needed; recorded local commands used `--offline` after fetching. The payment harness requires macOS `sandbox-exec` and checks actual private-root isolation.

```sh
cargo +1.89.0 test --manifest-path communication/Cargo.toml --workspace --locked --offline
cargo +1.89.0 build --manifest-path communication/Cargo.toml --bins --locked --offline
cargo +1.91.0 test --release --manifest-path poc/Cargo.toml --features relay-communication --locked --offline -- --test-threads=1
cargo +1.91.0 build --release --manifest-path poc/Cargo.toml --features relay-communication --bins --locked --offline
python3 poc/scripts/verify_relay_source_isolation.py
python3 -m unittest discover -s poc/tests -p test_dependency_graph.py
python3 -m unittest discover -s communication/harness -p 'test*.py'
```

Run wallet tests from `poc/`:

```sh
python3 -m unittest -v wallet.test_hosted_setup wallet.test_member_app wallet.test_local_relays wallet.test_local_funding wallet.test_signer_session wallet.test_account_link wallet.test_remote_join
```

Install the browser harness dependency from `poc/g3/` with `npm ci`. From repository root, select the installed browser's absolute executable path in `LOKI_BROWSER_EXECUTABLE`, then run:

```sh
node poc/wallet/test-hosted-setup-browser.js
node poc/wallet/test-relay-dashboard-browser.js
node poc/wallet/test-payment-poll-browser.js
```

Build the debug-only actual-kill fixture once, then perform one complete crash campaign per policy. Release builds reject `setup-fault-injection`. Fault campaigns cover phases 0 and 2–8 within the same ceremony; Starting/phase 1 uses a separate abort case. Never run one full ceremony per small development change.

```sh
cargo +1.91.0 test --manifest-path poc/Cargo.toml --features setup-fault-injection --test setup_relay --no-run --locked --offline
python3 communication/harness/hosted_setup.py faults --run-root /private/tmp/loki-hosted-review-kills-3-NEW --members 3
python3 communication/harness/hosted_setup.py faults --run-root /private/tmp/loki-hosted-review-kills-4-NEW --members 4
```

For fresh payment reproduction, first complete one owned handoff for each policy. Start one new dedicated THS instance in a separate terminal (`ths --name loki-hosted-review-NEW start --no-open --port-offset 230`), choosing an unused name and free offset. Keep it running throughout acceptance. Replace each source ID below with that setup root's exact `.harness-owner.json` run ID. The default payment selection exercises all required pairs; do not supply a subset to establish overall policy acceptance. Native binaries use release while communication service binaries use debug.

```sh
python3 communication/harness/hosted_setup.py acceptance --run-root /private/tmp/loki-hosted-review-3-NEW --members 3
python3 communication/harness/hosted_setup.py acceptance --run-root /private/tmp/loki-hosted-review-4-NEW --members 4 --offline-relay 1
LOKI_POC_BIN_PROFILE=release python3 communication/harness/hosted_setup.py payments --run-root /private/tmp/loki-hosted-review-payments-3-NEW --members 3 --source-run /private/tmp/loki-hosted-review-3-NEW --source-run-id EXACT_THREE_MEMBER_OWNER_ID --name loki-hosted-review-NEW
LOKI_POC_BIN_PROFILE=release python3 communication/harness/hosted_setup.py payments --run-root /private/tmp/loki-hosted-review-payments-4-NEW --members 4 --source-run /private/tmp/loki-hosted-review-4-NEW --source-run-id EXACT_FOUR_MEMBER_OWNER_ID --offline-relay 1 --name loki-hosted-review-NEW
```

Separate-host acceptance must use a fresh signed HTTPS bundle and scoped enrollment grants, private identities created on each host, explicit signer fingerprint/backup verification, and native automatic activation for every member. The existing local fixture is not that test. Follow [operator deployment](../deploy/README.md), then collect `device-evidence` per member and compare all member reports with `distinct-hosts` as documented in [acceptance evidence](hosted-setup-acceptance.md). The documented compose file is loopback development only. Complete hosting/setup automation and its exact execution transcript are still pending; do not report those commands as executed native hosting acceptance.

## test(setup): retained local evidence

Evidence below is local to the coordinator workspace and must not be uploaded with private runtime directories. Public report paths are allowlisted; recovery words, capabilities, invitations and plaintext remain private.

- Native pre-merge: `/private/tmp/loki-hosted-consolidated-native-current-release.log`.
- Communication: `/private/tmp/loki-hosted-consolidated-communication-terminal-intake.log`.
- Wallet: `/private/tmp/loki-hosted-consolidated-wallet-complete.log`.
- Harness: `/private/tmp/loki-hosted-consolidated-harness-source-bound-final.log`.
- Browser: `/private/tmp/loki-hosted-consolidated-browser.log`, `/private/tmp/loki-hosted-consolidated-dashboard-browser.log`, `/private/tmp/loki-hosted-consolidated-payment-browser.log`.
- Isolation/dependency: `/private/tmp/loki-hosted-consolidated-isolation-current-release.log`, `/private/tmp/loki-hosted-consolidated-graph-current-release.log`.
- Three-member AB/AC: `/private/tmp/loki-hosted-consolidated-payments-3-v7/cases/{AB,AC}/private-members/relay-payment-report.json`.
- Three-member BC: `/private/tmp/loki-hosted-consolidated-BC-v7-final-confirmation/relay-payment-report.json`.
- Four-member AB: `/private/tmp/loki-hosted-consolidated-four-AB-v10-final-confirmation/relay-payment-report.json`.
- Four-member AC/AD: `/private/tmp/loki-hosted-consolidated-payments-4-v12/cases/{AC,AD}/private-members/relay-payment-report.json`. Remaining cases in this run are pending.
- Recorded pre-merge binary manifest: `/private/tmp/loki-hosted-release-acceptance-artifacts.json`.
- Independent review: `/private/tmp/loki-hosted-independent-security-review-20261014.md`, SHA-256 `f9fd9fb3ed8d93f24555437d079edf0028c6371ebb36730cec73497db0e7e210`.
- Isolated merged-source artifact build: `/private/tmp/loki-hosted-updated-base-native-artifact-build.log`; consolidated test log will be `/private/tmp/loki-hosted-updated-base-native-validation.log`.

The user owns draft PR creation against main. This checkpoint authorizes neither merging nor production deployment. Acceptance work and subsequent evidence stay isolated from the commit until their actual results are known.
