# Signing session library milestone

`signing_session` implements an offline 2-of-3 Ironwood signing attempt. A payment
intent has a stable proposal ID; each attempt has a fresh random ID, one selected
pair, fresh per-spend FROST commitments, and library-generated randomizer seeds.
Each member checks the whole exact candidate, claimed note ownership, value
commitments, seed-derived randomizers and `rk`, and locally derived sighash before
releasing any share. The caller must give each member its own locally approved
`Intent` and show the returned `ReviewSummary` for explicit confirmation before
calling `publish_approved`.

The append-only local mailbox carries padded, authenticated encrypted envelopes.
It is a courier for this test flow, not a deployed relay protocol: callers preselect
the mailbox directory, and no opaque network routing address or availability
service has been specified. The envelope hides the vault, payment, attempt,
membership, candidate, and seeds from a reader of the wire. The package publisher
saves its own encrypted package copies and delivers copies to the other members.
Each signer saves its exact encrypted share copies before delivery; an identical
retry or restart resends those bytes. FROST nonce secrets stay in RAM and are
consumed at signing. A crash before saving the share abandons that attempt and
requires a new attempt with fresh commitments, seeds, candidate, and review.

`aggregate_and_apply` lets a member with the encrypted package and both shares
verify and assemble a signed PCZT without the approvers' nonce secrets. The
offline test exercises Carol finishing from her inbox and Alice finishing after
restart from her sealed outbound package and share. It stops at the signed PCZT:
chain witness reconstruction, proving, broadcast, and confirmation are separate.
No `Signed` or `Confirmed` payment status is recorded from a relay receipt.

Run `cd poc && cargo test --locked --test signing_session --test signing_faults
--test signing_flow_faults` for the flow and fault tests. This module is not wired
to the legacy CLI or certified real-vault state. Its sealed file store reuses the
prototype `MemberDir` and has no rollback or live-process snapshot defense; it
is not a production nonce or custody boundary. Aborting is allowed only before
a share is released. A released share cannot be revoked, so later attempts must
remain associated with the same payment effects and notes.
