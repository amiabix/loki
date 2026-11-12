# review(setup): incremental assessment after the nonce-mailbox base update

**Assessment:** No must-fix security regression or semantic merge conflict identified in the inspected integration. The hosted 2-of-4 approval fanout retains the upstream mailbox-bound nonce protections. Two test tuple fixtures required mechanical adaptation at review time; the coordinator had already identified and was fixing them. Post-merge build/test validation remains necessary and was not performed by this reviewer.

## Reviewed snapshot

Authoritative worktree: `/Users/megabyte/.codex/worktrees/1255/loki-zcash-frost`.

Implementation HEAD: `e815247d637d10539cd31b504bba9e882b3dddac`.

Incoming base: `origin/main` at `d68d9b33a79ecd372e18c9cb528cacfc46491cac` (`fix: bind signing nonces to relay mailboxes`). The clean `--no-commit --no-ff` merge was pending its final checkpoint during review. Five files carried staged upstream changes; no unresolved merge paths appeared. The coordinator was concurrently adapting the new hosted signing test fixtures.

This is an incremental read-only review of the merge integration, not a replacement for the original five-area review at `/private/tmp/loki-hosted-independent-security-review-20261014.md`. I inspected diffs and relevant source without running tests, modifying repository files, accessing private runtime data, or spawning agents. The only write was this explicitly authorized report artifact.

## Checked integration invariants

- `WitnessPins` now binds each witness's relay key, run ID and mailbox ID; it requires nonzero fields and distinct witnesses: `poc/src/signing_session.rs:773`.
- The CLI derives those triples from the actual selected authenticated owner inbox routes: `poc/src/bin/loki_member_payment.rs:656`. Hosted relay outage selection still picks reachable configured routes; it does not invent or rotate a mailbox.
- New persisted nonce records write version 2 and both complete witness triples. Reading checks the 195-byte minimum header, version, field offsets, distinct pins, bounded nonce count, individual lengths and trailing bytes: `poc/src/signing_session.rs:1488`, `:1513`.
- Version-1 nonce records are deliberately refused rather than upgraded with guessed mailbox identities. This is a fail-closed compatibility change: an unfinished old attempt requires a fresh attempt and fresh nonces; preserving its sealed file does not authorize reopening it.
- Hosted three- and four-member roster-aware approval still funnels into `publish_approved_secured_to_finishers`. That helper compares the complete saved witness triples against the current witness before any nonce claim, decision marker or signing: `poc/src/signing_session.rs:1184`.
- Share computation remains once per approved attempt, followed by sealing and saving every peer/non-signer copy. Mailbox binding does not cause the four-member path to invoke signing twice: `poc/src/signing_session.rs:1246`.
- Fresh owner provisioning refuses surviving `nonces.sealed` files when no current owner configuration is available: `poc/src/relay_member/config.rs:615`, `:2718`. Existing exact configuration reuse returns without provisioning replacement inboxes.
- Hosted scoped handoff installation continues to compare the complete saved configuration and recover only that exact sealed revision: `poc/src/relay_member/config.rs:687`. Its saved owner intent contains the original inbox IDs; it therefore does not defeat the new guard by replacing mailbox IDs beneath surviving nonces.
- Incoming fault tests cover changed mailboxes under the same relay keys/runs, refusal before decision/share creation, and version-1 refusal. The incoming reprovision test covers transport-state loss with surviving signing nonces. These assertions were inspected, not executed.

## Findings and compatibility

**Critical:** None confirmed.

**Important security regressions:** None confirmed in the examined integration.

**Known build compatibility work:** At inspection, `poc/tests/signing_session.rs:69` and `:153` still constructed two-field witness tuples. They must use matching nonzero, distinct mailbox triples for the new `WitnessPins` type. The coordinator was already adapting these fixtures. This report does not claim the pending snapshot compiles.

**Nonblocking prior findings:** The original review's duplicate-run validation/witness selection and missing invitation-expiry UI findings remain unchanged by this upstream update. They are not new merge regressions.

## Verdict and limits

**Acceptable source integration, conditional on completing the known fixture adaptation and post-merge validation.** The inspected merge strengthens nonce rollback protection without weakening hosted 2-of-4 fanout or exact handoff restoration.

Pre-update passing suites and mined payments cannot establish that the new merged binaries pass. Record current source/binary hashes and rerun the affected required gates through the coordinator's validation process. This incremental review does not establish actual native separate-host HTTPS acceptance, all-six-pair post-merge payment acceptance, coordinated device-and-service rollback resistance, or production/mainnet custody approval.
