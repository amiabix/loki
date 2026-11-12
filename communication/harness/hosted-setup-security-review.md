# review(setup): independent security assessment of hosted vault setup

**Verdict:** The five reviewed areas are conditionally acceptable for the scoped hosted regtest implementation. I found no confirmed Critical or Important implementation defect in the paths examined. Two Minor findings remain. This review does **not** establish production readiness: complete four-member payment acceptance and actual native separate-host HTTPS acceptance were still outstanding at review time.

## Scope and method

I reviewed the authoritative worktree `/Users/megabyte/.codex/worktrees/1255/loki-zcash-frost`, branch `feat/hosted-relay-vault-setup`, at HEAD `5886a38a61d3c5a8f30f2442c66a54559be29658`, including tracked changes against base `3bc1c9f03c28cb15ba99ce6b36122375ae70f483` and the current untracked implementation.

I read the hosted setup specification and plan, inspected `git status --short` and the base diff/stat, and traced the principal security boundaries through protocol, admission, client transport, native ceremony, backup, handoff and signer/UI code. Untracked files explicitly examined included `setup_relay/activation.rs`, `wallet/hosted_setup.py`, `tests/setup_handoff.rs`, `harness/hosted_setup.py` and deployment/evidence documentation.

This was a read-only review. I did not modify files, execute tests, inspect private runtime state, access recovery words or capabilities, commit, contact external parties, or delegate further.

The reported native **249 passed / 0 failed**, communication **1,127 passed / 0 failed**, and harness **61 passed** results are supporting evidence supplied by the coordinator. They are not substitutes for the code review or the outstanding acceptance gates.

## 1. Invitation trust

**Scope:** Signed operator configuration, private invitation decoding, bootstrap context, claim ownership, roster proposal/acceptance, signer agreement and dashboard exposure.

**Checked invariants and evidence:**

- Operator bundles require a signature under the separately supplied trusted configuration key. Endpoint validation rejects non-HTTPS origins in production, credentials in URLs and redirect-oriented URL components. Configuration records bind three pinned relay identities and the admission identity: `communication/client/src/operator_config.rs:124`.
- Invitation verification checks the creator signature, secret hash, supported policy, assigned slot, expiry and trusted bundle digest before constructing bootstrap authority: `communication/client/src/setup.rs:405`.
- The native adapter obtains the initial creator identity from the invitation and verifies its signature: `poc/src/setup_relay.rs:86`. This authenticates possession of that identity’s signing key; human identity depends on receiving the invitation through the trusted channel described in the specification.
- Admission refuses a different identity claiming an occupied slot and rejects duplicate signing/encryption identities within a ceremony: `communication/admission/src/store.rs:581`.
- Accepted roster construction requires one signed, identical acceptance from every member, including capability/policy compatibility: `communication/client/src/setup.rs:609`.
- Subsequent setup authentication requires exact accepted-roster authors and the accepted digest: `communication/client/src/setup.rs:693`.
- Signer agreement takes an expected fingerprint, rather than silently approving the current proposal: `poc/src/setup_relay.rs:1743`.
- Dashboard vault responses are allowlisted and do not include invitation codes, recovery material or SDK credentials: `poc/wallet/member_app.py:1695`.

**Finding:** Minor M2 below: hosted invitation expiry is enforced cryptographically but omitted from its UI status.

**Verdict:** **Conditionally acceptable.** The admission identity is appropriately distinct from human roster identity. Invitation theft can still consume a slot and deny service; the mandatory trusted-channel comparison and all-member acceptance remain essential.

## 2. DKG checkpoint serialization and restart

**Scope:** Native secret-package serialization/restoration, snapshot validation, immutable journal writes, worker locking, remote checkpoint anchoring and the initial entropy boundary.

**Checked invariants and evidence:**

- Restoration bounds framing, validates phase/member count/member ID and rejects trailing bytes: `poc/src/distributed_setup.rs:230`.
- Round-one restoration verifies canonical round-trip serialization, member identifier, threshold, member count, commitment equality and coefficient-to-commitment consistency: `poc/src/distributed_setup.rs:315`.
- Round-two restoration verifies the corresponding secret-package bindings and verifies its secret share against the public commitment: `poc/src/distributed_setup.rs:385`.
- Ceremony snapshot restoration additionally checks authenticated round-one inputs, round-two contribution commitments, public package reconstruction, transcript, viewing-secret derivation, certificate bodies and all required backups: `poc/src/setup_ceremony/engine.rs:445`, `:524`.
- Journal generations bind context, member and generation in authenticated headers; encrypted plaintext contains predecessor and saved operation ID. Files are immutable, privately permissioned, synced and chained: `poc/src/setup_ceremony/journal.rs:348`, `:396`.
- A held worker lock and owner/file checks limit accidental concurrent workers and unsafe filesystem inputs: `poc/src/setup_ceremony/journal.rs:45`, `:221`.
- Publication requires successful synchronization of the exact saved checkpoint. Only the immediate predecessor can advance admission state; conflicting or stale state stops the ceremony: `poc/src/setup_ceremony/engine.rs:378`, `poc/src/setup_ceremony/admission_checkpoint.rs:48`.
- A durable `Starting` phase precedes `part1`. Reopening that phase refuses regeneration; the live process permits only one entropy-consuming invocation: `poc/src/setup_ceremony/engine.rs:725`.

**Findings:** No Critical, Important or Minor defect identified in these examined checkpoint paths.

**Verdict:** **Conditionally acceptable for intact-store crash recovery and device-only rollback detection.** A coordinated rollback of both device journal and authoritative admission database remains outside the demonstrated guarantee, as the specification explicitly acknowledges. Library serialization and secret-erasure behavior were not independently cryptographically audited.

## 3. Enrollment and scoped provisioning

**Scope:** Grant verification, device/config binding, transactional budgets, idempotency, claims, provisioning intents, relay authentication, expiry and terminal tombstones.

**Checked invariants and evidence:**

- An absent issuer denies enrollment; grant signatures, expiry, device key, configuration digest and bounded budgets are checked: `communication/admission/src/lib.rs:131`.
- Creation consumes grant budgets within an immediate transaction, records the creator claim and stores invitation hashes: `communication/admission/src/store.rs:454`.
- Reusing an operation ID with different signed request bytes conflicts. Successful saved requests replay their original signed response: `communication/admission/src/store.rs:279`.
- Mailbox/checkpoint/state slots must match the requesting device ID at canonical request validation: `communication/protocol/src/admission.rs:171`, `:211`.
- Mailbox requests carry capability **verifiers**, not owner read/admin secrets, and are bounded by per-grant mailbox budgets and setup storage reservations: `communication/admission/src/store.rs:627`.
- Provisioning is driven from persisted intents. The provisioner authenticates the pinned relay before presenting operator authority and retries the saved creation bytes: `communication/admission/src/provision.rs:46`.
- Terminal/expired setup namespaces are retired separately; payment namespace retention is not converted into setup TTL: `communication/admission/src/store.rs:362`, `communication/relay/src/store.rs:1733`.
- The admission HTTP surface bounds request bodies and concurrency, validates signed request route/method correspondence, and carries credentials in Authorization headers: `communication/admission/src/http.rs:58`, `:83`.

**Finding:** Minor M1 below concerns rejecting incompatible relay run IDs earlier.

**Verdict:** **Conditionally acceptable.** Production issuer integration, operator-key custody, durable authoritative admission backups and tombstone retention remain deployment obligations. The configurable issuer executable is a trusted signer-side integration receiving public inputs; its own authentication/abuse-control implementation was not reviewed.

## 4. Backup and restoration

**Scope:** Provisional/final card creation, recovery-word checks, durable word deletion, all-member backup receipts, native restore and signer readiness controls.

**Checked invariants and evidence:**

- Backup creation preserves saved words and exact existing card contents, refusing conflicting replacement state: `poc/src/setup_backup.rs:54`.
- Finalization verifies the provisional card against the expected state, verifies saved words where present, writes/verifies final evidence, then removes pending words and syncs the secret directory: `poc/src/setup_backup.rs:130`.
- Local backup verification produces the native receipt through the ceremony engine and checkpoint anchoring: `poc/src/setup_relay.rs:2501`.
- Final recovery evidence includes certified state, the complete roster and all signed member backup receipts: `poc/src/setup_relay.rs:2534`.
- Native restoration verifies roster consistency and each member’s receipt against the expected backup body before installing spendable activation state: `poc/src/bin/loki_setup_member.rs:373`, `:697`.
- Restore can recover keys/address from final evidence without contacting setup admission: `poc/src/bin/loki_setup_member.rs:690`.
- Signer receive controls require final backup verification, and hosted controls additionally require native activation state: `poc/wallet/member_app.py:1108`.

**Findings:** No Critical, Important or Minor defect identified in these examined backup paths.

**Verdict:** **Conditionally acceptable for the existing version-2 card contract.** Recovery of signing authority is distinct from restoring existing payment inbox credentials: the final card contains certified state/roster/receipts, rather than the entire hosted transport configuration. This review does not certify mnemonic custody, storage hardware, or mainnet recovery operations.

## 5. Certified payment handoff and signer boundaries

**Scope:** Owner payment intents, descriptor exchange, complete configuration installation, common relay receipts, all-member activation proofs, abort protection and four-member approval fanout.

**Checked invariants and evidence:**

- Payment handoff requires all verified backup receipts before generating its saved owner intent: `poc/src/setup_relay/payment.rs:478`.
- Every member descriptor is authenticated and checked against the certified owner, revision and recorded operator routes: `poc/src/setup_relay/payment.rs:563`.
- Scoped configuration installation requires three owner routes and every certified peer descriptor/courier. Reinstallation accepts only the exact saved configuration: `poc/src/relay_member/config.rs:661`.
- Setup delivery readiness intersects receipt pins across every required recipient/object copy; different per-recipient relay pairs cannot satisfy common durability: `communication/client/src/setup_network.rs:597`.
- Admission activation requires all member votes and two relays provisioned for every payment owner: `communication/admission/src/store.rs:762`.
- Native activation independently requires all incoming member activation records, complete verified storage, all member signed admission notices and exact equality between those notices and the received requests before installing activated state: `poc/src/setup_relay/activation.rs:320`, `:392`.
- Activated native checkpoints refuse user abort; admission refuses mutations after its active terminal state: `poc/src/setup_relay.rs:3226`, `communication/admission/src/store.rs:569`.
- Four-member approval computes each share once, creates copies for both non-signers and persists them before publication: `poc/src/signing_session.rs:1141`, `:1257`.
- Dashboard creation requests require signer action approval. Fingerprint and backup review remain private-signer actions: `poc/wallet/member_app.py:1789`.

**Finding:** Minor M1 below concerns witness selection for misconfigured duplicate run IDs.

**Verdict:** **Conditionally acceptable at the examined native/CLI boundary.** The public `publish_approved_secured_to_roster` API checks roster shape, own/peer identities and FROST identifiers, but relies on its native caller to supply certified non-signer communication keys. The CLI supplies its validated member roster. I found no dashboard-controlled path substituting these keys; future SDK callers must preserve that precondition.

## Findings

### Critical

None confirmed.

### Important

None confirmed in the reviewed implementation. Outstanding mandatory acceptance evidence is listed separately below.

### Minor M1: Reject incompatible relay run IDs before creating a vault

**References:** `communication/client/src/operator_config.rs:164`; `poc/src/bin/loki_member_payment.rs:696`.

Operator configuration rejects repeated signing keys but permits repeated relay run IDs. Payment nonce selection takes the first two reachable routes, then rejects equal run IDs at `loki_member_payment.rs:710`.

**Failure scenario:** A signed operator bundle with distinct keys but equal runs can pass configuration validation and setup, yet signing fails closed. If only the first two reachable routes share a run, selection fails even when the third provides a usable distinct witness.

**Recommended fix:** Reject repeated run IDs when verifying the trusted operator bundle, aligning provisioning with nonce-witness requirements. Alternatively, select a distinct key/run pair across all reachable routes. This is an availability/configuration problem; it does not bypass nonce safety.

### Minor M2: Hosted invitation status omits its enforced expiry

**References:** `poc/wallet/hosted_setup.py:274`; `poc/wallet/hosted_setup.py:292`; `poc/wallet/app.js:538`.

Hosted status returns invitation codes without `invites_expire_at`. The UI uses that field to label expired invitations and display their deadline.

**Failure scenario:** After the first-claim deadline, previously exported codes can remain displayed as waiting/shareable even though a new join correctly fails expiry validation.

**Recommended fix:** Expose the authenticated saved claim deadline as public invitation status and use the existing expiry UI. Already claimed identities should remain resumable according to the existing admission rule.

## Remaining limitations and required gates

- Actual **native setup, complete certified configuration and signed activation over separate-host HTTPS** were not established by this review. TLS preflight alone does not establish that gate.
- At review time the coordinator reported four-member AC accepted, with AD/BC/BD/CD still running. Complete six-pair confirmation, both independent finishers and recipient decryption must be recorded before declaring four-member payment acceptance complete.
- I inspected representative security tests and integration assertions but did not rerun them. Existing reported passing suites do not prove unexamined adversarial cases.
- This was one independent source review across a large change set, with focused tracing of the five requested areas rather than exhaustive verification of every changed line.
- Operator/device independence, admission backup operations, coordinated rollback resistance, issuer-service security and production configuration/key rotation require their own operational evidence.
- **Ready for scoped implementation review: yes, with the stated nonblocking findings and limitations. Ready for production deployment or mainnet custody approval: not established.**
