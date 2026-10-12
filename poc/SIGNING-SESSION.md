# Signing session library milestone

`signing_session` implements an offline 2-of-3 Ironwood signing attempt. A payment
intent has a stable proposal ID; each attempt has a fresh random ID, one selected
pair, fresh per-spend FROST commitments, and library-generated randomizer seeds.
Each member checks the whole exact candidate, claimed note ownership, value
commitments, seed-derived randomizers and `rk`, and locally derived sighash before
releasing any share. The caller must give each member its own locally approved
`Intent` and show the returned `ReviewSummary` for explicit confirmation before
calling the approval method.

The append-only local mailbox carries padded, authenticated encrypted envelopes.
It is a courier for this test flow, not a deployed relay protocol: callers preselect
the mailbox directory, and no opaque network routing address or availability
service has been specified. The envelope hides the vault, payment, attempt,
membership, candidate, and seeds from a reader of the wire. The package publisher
saves its own encrypted package copies and delivers copies to the other members.
Each signer saves its exact encrypted share copies before delivery; an identical
retry or restart resends those bytes. The old `sign` command is a simultaneous,
RAM-only regtest fixture. The relay-backed path uses `commit`, `package`, and
`approve` as separate invocations. `commit` seals nonce secrets before publishing
commitments. `approve` reopens them, verifies the candidate, and obtains a fresh,
challenge-bound first-write receipt for each nonce from two pinned relays. It then
fsyncs a consumed decision, removes the sealed nonce file, computes shares, and
saves exact encrypted share copies. A crash after a relay claim but before saving
shares burns the attempt; a new attempt needs fresh nonces. A restored old profile
cannot reclaim a CID at an honest, reachable relay in the pinned pair.

`aggregate_and_apply` lets a member with the encrypted package and both shares
verify and assemble a signed PCZT without the approvers' nonce secrets. The
offline test exercises Carol finishing from her inbox and Alice finishing after
restart from her sealed outbound package and share. That test stops at the signed
PCZT. `loki_member_payment` now connects separately created and backup-activated
member vaults to this path on THS regtest. Member 3 scans the chain independently,
installs the witness and anchor, proves, broadcasts, and verifies a mined payment.
The verifier decrypts vault change and compares the mined sighash to a fully checked
candidate. For an external recipient it cannot independently decrypt the payment
output, so it reports `candidate-opening-and-mined-sighash` as the recipient evidence.
The `approve` command reports local signing as delivery pending. The relay payment
harness checks that both share envelopes are durably stored before treating that
member's approval as delivered. Chain confirmation still comes from the node.

Run `cd poc && cargo test --locked --test signing_session --test signing_faults
--test signing_flow_faults` for the flow and fault tests. For a live regtest run,
start a disposable THS instance, then run `cargo build --locked --bins` and
`python3 run-member-payment.py --name <instance> --state <new-private-directory>`.
Add `--manual` to stop after setup and print the two concurrent signer commands,
then the finish, mine, and verification commands. Each signer displays the
recipient unified address and exact payment before accepting typed approval.
The script creates three member processes, checks provisional backups, finalizes
their one-file recovery cards, funds the vault, then restores one selected signer
from its final card and 24 words into a new data root. It supplies both approval
strings after each signer verifies the candidate. This
is scripted approval, not a test of independent human review. It creates a second
vault as the independent recipient; that vault decrypts the mined payment while the
source vault verifies the checked candidate, mined sighash, fee and change. The
driver selects one covering note and keeps its
intent manifest in a local directory; it is a regtest bridge, not a wallet inbox.
After a crash before the share was saved, start a new private work directory and
prepare a fresh attempt. If a share was saved, `loki_member_payment resend` republishes
only its original encrypted bytes.

The relay-backed path uses a process lock and two pinned relay identities. It
depends on at least one honest, reachable relay in that pair retaining its
first-write index. These runs do not establish physical power-loss durability,
independent relay operators, browser storage safety, or custody readiness.
Aborting is allowed only before a share is released; a released share cannot be
revoked.
