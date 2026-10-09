# refactor(signing): adopt the recommended FROST seed flow

Issue: https://github.com/amiabix/loki-zcash-frost/issues/3
Base: `origin/main`, `e66f97ce894e3784efa53e5625919a0b8abce9e4`, fetched 2026-10-09.

For each real spend of each AB, AC and BC candidate, generate parameters with
`frost_rerandomized::RandomizedParams::new_from_commitments(group_key,
&commitments, rand_core::OsRng)`. Feed the returned randomizer through the existing
canonical scalar conversion into the patched builder before calculating the sighash.
Persist the returned seed; never derive it from the proposal, pair or index.

Store a versioned seed record per candidate and real-spend index, using the existing
index-zero filename convention. Bind its metadata to the proposal ID, candidate pair,
spend index, input nullifier and exact serialized signer commitments. Validate record
length, hex encoding, version and association. A changed seed or commitment against
a fixed candidate must fail the reconstructed alpha/rk checks. A missing record,
including a legacy proposal, must fail explicitly, without a fallback generator.

Restart means reading the original seed and candidate bytes. Re-running proposal
construction with unchanged commitments must not create a new message for the same
nonces: either return the already persisted complete session unchanged or refuse
without altering it. A fresh honest session uses fresh nonce commitments and new
library-generated seeds. Refuse incomplete or mixed saved sessions without emitting
shares. Existing plain-file storage still provides no crash-safe consumed-nonce
ledger or rollback protection.

Signers independently review the payment and locally compute its sighash. They
reconstruct parameters with `RandomizedParams::regenerate_from_seed_and_commitments`,
check canonical alpha and rk against the known vault key, and sign using
`sign_with_randomizer_seed`. Complete validation for all relevant candidates and
spends precedes signature-share output. Finishers use the same saved record and
commitments, check the candidate association and reconstructed alpha/rk, and aggregate
using those reconstructed parameters. Map real spends by intent nullifier, never
assume shuffled action order equals input order.

Second-device replicas carry seed records for every real spend in the selected
candidate. Seeds need a confidential handoff according to the library API; the
prototype uses protected local directories and does not implement or claim an
authenticated encrypted network relay. Remove claims that every replica artifact is
public. Key packages, signer nonce secrets and approver scan state remain withheld.

Preserve independent recipient, amount, memo, fee, change, input, expiry and pool
checks; nullifier equality across candidates; signatures before anchor, witnesses
and proof; and sighash invariance when those are subsequently installed. Cover AB,
AC and BC and more than one input in regression tests. Update the rollback drill to
save seeds/commitments and distinguish a fixed-candidate refusal from a deliberately
rebuilt consistent candidate under rolled-back nonces. A fresh seed does not repair
nonce reuse. Do not turn this into a rollback-prevention project.

Keep pinned dependencies and caller-alpha vendor patches. Zakura migration and ZIP
2005 implementation are separate work; latest main already contains experimental
ZIP 2005 changes, which this branch must preserve. Avoid replacing the current vault
implementation or reviving outdated claims from earlier main revisions.

Using the recommended API removes the custom-seed assumption. It does not let
signers prove the coordinator used a random seed, establish a security proof, or
expand NCC's published audit scope to rerandomized FROST. Keep regtest-only claims.

Validation: Rust build, full default-feature tests, formatting and all-target clippy;
regtest, independent second-device, tamper and nonce-reuse harnesses. Inspect all
state paths and node processes first; use isolated temporary state and loopback
services. Tests for refusals assert the specific reason and zero share output.
Report skipped or failed checks separately from passes. No UI change is required.
