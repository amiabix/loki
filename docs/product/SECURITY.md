# Loki security brief — research stage

**Status: regtest and Testnet research only; not for custody or mainnet funds.**
This describes the code on the current development line, including the newer
`Signer` interface and the separate-member CLI and local app. It is a pre-audit
inventory, not an external security review. The [research README](../../poc/README.md)
records the live transaction evidence. Workstream documents in this directory
describe target designs; their acceptance criteria are not all complete.

## The paths and their boundaries

| Path | What has been exercised | Security boundary that remains |
|---|---|---|
| Separate-member CLI / local app | A 3-of-4 regtest payment has been mined. Setup, backup, and payment screens exist for Testnet, but a public Testnet browser payment has not yet been mined end to end ([research results](../../poc/README.md), [app runbook](../../poc/wallet/README.md)). | Separate processes and data roots can belong to the same host. The Python app holds the unlock passphrase while unlocked and writes a short-lived `.unlock-*` file for some commands ([app](../../poc/wallet/member_app.py), [service](../../poc/wallet/member_service.py)). This is not an independent hardware signer. |
| New `Signer` seam and coordinator loop | Signer-side DKG encrypts round-two packages to the accepted roster and seals the final share. The coordination test drives signers to an aggregated, signed PCZT ([local signer](../../poc/src/signer/local.rs), [loop](../../poc/src/signer/coordination.rs)). | The loop stops before proof, broadcast, and confirmation. The type guard and source deny-list cover named return types and limited source files, not process isolation or opaque-byte contents ([seam](../../poc/src/signer/mod.rs), [guard](../../poc/src/coordinator_boundary.rs)). |
| `frostd` adapter | A live relay test completed 2-of-3 DKG and signature exchange ([adoption record](ADOPTION.md)). | This is transport evidence, not a confirmed payment through the new signer seam. The relay sees participants, session IDs, timing, and message sizes even when message bodies are sealed ([adapter](../../poc/src/transport.rs)). |
| macOS signer app | Persistent Secure Enclave key wrapping and Rust share sealing are exercised inside a provisioned app ([self-test](../../poc/signer-app/README.md)). | The app is a self-test, not a released signer with payment display, approval, and independent delivery. |

The `Signer` API returns public commitments, signature shares, and encrypted DKG
messages; the DKG share and signing nonce are intended to stay in the signer.
`LocalSigner` is currently an **in-process** implementation. Its software key
wrapper keeps the wrapping key in process memory, and payment approval is an
application-supplied callback ([key wrapper](../../poc/src/signer/secure_element.rs),
[approval](../../poc/src/signer/local.rs)). The signer app's Secure Enclave self-test
does not change these boundaries for the CLI or local browser app.

### Viewing-key privacy is currently broken on the new seam

The new coordinator asks a signer to select a note and build the candidate, so
it need not hold a viewing key **as an input**. However, the candidate builder
places the vault full viewing key into Orchard spend data and returns the
serialized PCZT to the coordinator ([builder](../../poc/src/candidate.rs),
[serialized spend field](../../poc/vendor/zakura-orchard/src/pczt.rs)). Anyone who
receives that PCZT can obtain viewing authority over the vault. A viewing key
cannot sign a spend, but it exposes wallet activity. **Do not claim viewing-key
privacy for this path until the outgoing PCZT is redacted and the signer still
verifies the exact transaction it approves.** Treat coordinator-visible PCZTs
as private wallet data in the meantime. The coordinator also legitimately sees
payment intent and transaction effects; the relay sees routing metadata.

The separate Testnet `loki_split_payment` binary is an integration harness. It
opens two members' state in one process and supplies an always-approve callback
([source](../../poc/src/bin/loki_split_payment.rs)). Its successful spend would
not demonstrate independent devices or human consent.

## Controls exercised in code, with limits

- `sign_approve` derives a payment view from the PCZT, asks the approval callback,
  recomputes the sighash, and refuses a mismatched signing package before opening
  the share ([implementation](../../poc/src/signer/local.rs)). This binds the
  package to bytes; it does not prove that a person saw and approved a complete,
  correct display.
- The nonce store persists commitments and burns a nonce before releasing a share;
  crash and reuse tests exercise that local state machine ([implementation](../../poc/src/signer/nonce.rs)). Physical device power loss and rollback still need drills.
- `LocalSigner` requires an accepted ceremony roster and encrypts DKG round-two
  packages to its members ([implementation](../../poc/src/signer/local.rs)). A
  member must still compare the roster fingerprint and peer identities through
  an independent channel.
- The signer backup module tests restoration on a clean data root with a bumped
  nonce epoch ([implementation](../../poc/src/signer/backup.rs)). This is not a
  complete live recovery-spend or device replacement exercise.

These are narrow unit and integration claims. The FROST arithmetic uses pinned
upstream crates, while Loki's PCZT building, validation, key derivation, backup,
transport integration, and approval flow remain in the audit scope.

## Work required before custody use

1. **Stop viewing-key disclosure.** Redact private spend data before a PCZT crosses
   to the coordinator, then prove through serialization tests that the key and
   other private fields are absent while each signer can still validate and sign.
   Review other PCZT paths for the same exposure.
2. **Harden signer review of hostile transactions.** Reject unsupported pools,
   unexpected transaction fields, and unreadable memos before approval. Exercise
   malformed serialized PCZTs, fee/value substitution, and a malicious coordinator
   end to end ([payment view](../../poc/src/signer/wysiwys.rs)). The current
   display can turn a memo-recovery failure into an empty memo.
3. **Enforce independent approval.** Deliver a signer process/app that holds one
   member's key, displays all signed effects, and requires the member's own unlock
   and confirmation. Remove the software key wrapper and automatic callback from
   any custody path; verify that the coordinator/browser cannot read signer data.
4. **Complete live drills.** Confirm a public Testnet payment through separate
   devices and the intended relay; test crash, reorg, restore, and recovery spend
   on fresh devices. The existing regtest and same-host tests are insufficient.
5. **Obtain independent review and reproducible delivery.** Review the complete
   signer and coordinator boundary, serialized PCZTs, nonce and backup formats,
   local ZIP-2005 `use_qsk` viewing-key derivation (ZF frost #1094), and release
   artifacts. The repo contains vectors and a regtest payment for the derivation,
   but no recorded independent upstream review ([adoption notes](ADOPTION.md),
   [research results](../../poc/README.md)). Establish a pinned, reproducible,
   independently delivered signer build before relying on separate devices.

No mainnet signer network is exposed by the new `Signer::Network` enum, which
currently has `Regtest` and `Testnet` only ([definition](../../poc/src/signer/mod.rs)).
That is not a reviewed release gate. Adding mainnet support requires an explicit
refusal gate and sign-off on the work above.
