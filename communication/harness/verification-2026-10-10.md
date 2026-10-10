# test(relay): completed requirement audit — 2026-10-10

All 47 plan units and all 26 acceptance/fault rows are verified against the current native tree. The evidence is in [verification-2026-10-10.json](verification-2026-10-10.json). The Rust checks, Python checks, production acceptance and fault campaign are distinct evidence sources; fixture execution is identified in the campaign.

| Unit | Requirement | Passing evidence |
| --- | --- | --- |
| 1.1 | Workspace and server dependency boundary | `server_excludes_wallet_and_client_dependencies` |
| 1.2 | Bounded deterministic CBOR codec | `canonical_subset` |
| 1.3 | Roster and logical-message schemas | `message_schema` |
| 1.4 | Public envelope framing and padding boundaries | `wire_boundary` |
| 1.5 | Receipt and HTTP metadata schemas | `metadata_schema` |
| 2.1 | Serialized identity import | `identity_import` |
| 2.2 | Single-use HPKE record sealing and opening | `hpke_binding` |
| 2.3 | Signed common logical messages | `inner_signature` |
| 2.4 | Complete recipient object preparation | `recipient_set` |
| 2.5 | Complete transfer assembly and authentication | `transfer_complete` |
| 2.6 | Selected-suite RFC vectors | `selected_suite_vectors` |
| 3.1 | Persistent relay root and exclusive identity | `root_identity` |
| 3.2 | Capabilities and idempotent mailbox creation | `create_mailbox` |
| 3.3 | Immutable object transaction and signed receipts | `immutable_put` |
| 3.4 | Monotonic append rotation | `rotation_monotonic` |
| 3.5 | Quota and checked-counter boundaries | `capacity_preserves` |
| 3.6 | Relay commit and restart faults | `relay_commit_fault` |
| 4.1 | Bounded dedicated database writer | `writer_boundary` |
| 4.2 | Authenticated object HTTP routes | `object_routes` |
| 4.3 | Provisioning and rotation HTTP routes | `control_routes` |
| 4.4 | Snapshot pagination and cursor route | `snapshot_page` |
| 4.5 | HTTP admission limits and loopback binary | `http_limits` |
| 5.1 | Certified sealed member loader | `certified_member` |
| 5.2 | Signed encrypted descriptors | `descriptor_binding` |
| 5.3 | Client configuration reference database | `config_reference` |
| 5.4 | Immutable sealed configuration and courier files | `sealed_revision` |
| 5.5 | Provisioning request persistence and client HTTP | `owner_provision` |
| 5.6 | Partial rotation and descriptor redistribution | `partial_rotation` |
| 6.1 | Outbox schema and recovery queries | `outbox_schema` |
| 6.2 | Atomic complete outbox commit | `outbox_atomic` |
| 6.3 | Bounded download/upload HTTP and receipt validation | `receipt_binding` |
| 6.4 | Exact upload retries and current credentials | `upload_retry` |
| 6.5 | Whole-vault same-pair Stored calculation | `stored_pair` |
| 6.6 | Outgoing process crash and replay evidence | `outbox_crash` |
| 7.1 | Incoming recovery schema and query boundaries | `incoming_schema` |
| 7.2 | Atomic page capture and durable missing downloads | `capture_atomic` |
| 7.3 | Pending download recovery and bounded quarantine | `download_recovery` |
| 7.4 | Staged complete authentication and prerequisite classification | `staged_auth` |
| 7.5 | Atomic original persistence and complete Received outbox | `received_atomic` |
| 7.6 | Received reference reconciliation and no loops | `received_reference` |
| 7.7 | Incoming and acknowledgement crash matrix | `incoming_crash` |
| 8.1 | Owned process and run-root controller | `HarnessOwnership` |
| 8.2 | Communication CLI command wiring | `communication_cli` |
| 8.3 | Separate certified setup and nine inboxes | `HarnessSetup` |
| 8.4 | Offline whole-vault communication scenario | `OfflineDelivery` |
| 8.5 | Fault scenarios and sanitized evidence | `HarnessFaultEvidence` |
| 8.6 | Final integration gate and coverage report | `integration_gate` |

| Case | Passing scenarios | Evidence class |
| --- | --- | --- |
| spec10-01 | `offline_delivery` | production owned processes |
| spec10-02 | `offline_delivery` | production owned processes |
| spec10-03 | `offline_delivery`, `ordering_conflict` | native fixtures; mixed fault classes where identified |
| spec10-04 | `crash_recovery` | native fixtures; mixed fault classes where identified |
| spec10-05 | `retained_restart`, `crash_recovery` | native fixtures; mixed fault classes where identified |
| spec10-06 | `crash_recovery`, `missing_download` | native fixtures; mixed fault classes where identified |
| spec10-07 | `outage` | production owned processes |
| spec10-08 | `missing_chunk` | native fixtures; mixed fault classes where identified |
| spec10-09 | `binding` | native fixtures; mixed fault classes where identified |
| spec10-10 | `forged_inner_sender` | native fixtures; mixed fault classes where identified |
| spec10-11 | `ordering_conflict` | native fixtures; mixed fault classes where identified |
| spec10-12 | `ordering_conflict` | native fixtures; mixed fault classes where identified |
| spec10-13 | `invalid_receipt` | native fixtures; mixed fault classes where identified |
| spec10-14 | `quota`, `capacity` | native fixtures; mixed fault classes where identified |
| spec10-15 | `missing_download` | native fixtures; mixed fault classes where identified |
| spec10-16 | `provisioning_retry` | native fixtures; mixed fault classes where identified |
| spec10-17 | `canonical_vectors`, `binding` | native fixtures; mixed fault classes where identified |
| plan-duplicate-download-order | `ordering_conflict` | native fixtures; mixed fault classes where identified |
| plan-omitted-intermediate-sequence | `missing_download` | native fixtures; mixed fault classes where identified |
| plan-sqlite-full | `crash_recovery` | native fixtures; mixed fault classes where identified |
| plan-client-disk-full | `missing_download`, `crash_recovery` | native fixtures; mixed fault classes where identified |
| plan-orphan-chunk-flood | `orphan_flood` | native fixtures; mixed fault classes where identified |
| plan-early-received-wrong-target | `ordering_conflict` | native fixtures; mixed fault classes where identified |
| plan-authenticated-conflict | `ordering_conflict` | native fixtures; mixed fault classes where identified |
| plan-restart-after-receipt | `retained_restart` | production owned processes |
| plan-missing-sealed-config | `sealed_config` | native fixtures; mixed fault classes where identified |

The final campaign contains 17 passing scenarios, 26 passing coverage rows, zero failed rows and zero skipped rows. All owned run lifecycles are stopped. Public report scans found no passphrases or provisioning capabilities in raw, hex or base64url representations. Source isolation checks separately verify published vendor bytes and both locked dependency graphs.

Process kills, simulated failures, real SQLite FULL and reduced-budget staging admission are separate observations. They do not establish hardware power-loss durability, independent operators, browser/WASM behavior or payment/nonce safety. Earlier failed campaign roots remain retained. No commit, push or payment action was performed.
