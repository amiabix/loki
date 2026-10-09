# Zakura dependency migration — 9 October 2026

Issue #4 moves Loki's production transaction, signing, scanning, witness, PCZT, and
proving graph to Zakura. This is regtest evidence for the existing G1-TX prototype.
There is no intended approval-policy change, custody claim, or new ZIP 2005 claim.

## Before replacing the graph

The isolated branch started at `3f66967`, with plan commit `4fa9f0d`. The old graph
used local `orchard 0.16.0` (Zcash `616a669df8c9a59c33d47064d3ce04b25d026b2e`),
`zcash_primitives 0.31.0-pre.0`, `pczt 0.10.0-pre.0`, FROST `reddsa 0.5.2`,
transaction `reddsa 0.6.1`, and Pasta 0.5.2/0.6.0. FROST core/rerandomized were
3.0.0. Both old vendor alpha patches were retained and rebased onto the published
Zakura builders. Exact new provenance/checksums are in [vendor/README.md](vendor/README.md).

Baseline `cargo test --locked` passed 64 tests: 53 library, 2 CLI, and 9 integration
cases, including the offline two-input sign/anchor/prove/extract test. Baseline
`cargo build --locked` and `cargo clippy --locked --all-targets` passed without
warnings. Baseline `cargo fmt --check` reported pre-existing formatting differences;
this worktree was formatted before final validation. Host `rustc` is
`1.98.0 (88d9e12ae 2026-08-18)` on macOS aarch64.

Before any dependency edit, temporary capture code generated synthetic 2-of-3
FROST shares with `ChaCha20Rng::from_seed([42; 32])` and a candidate with
transaction `StdRng::from_seed([43; 32])`. The committed public fixture records:

- Three identifiers and BLAKE3 hashes of serialized key packages, never private packages.
- Exact serialized public-key-package and group-key bytes.
- A randomized signature, its public message, and canonical alpha.
- Exact redacted unproved PCZT bytes and the BLAKE3 hash of the complete unredacted
  PCZT. Redaction removes bundle bsk, spend FVK/rho/rseed/value/recipient/witness/
  alpha/dummy keys, output recipient/value/rseed/ock, and action rcv. Public
  commitments, nullifiers, rk, ciphertexts and ephemeral keys remain.

The three initial compatibility regressions passed on the old graph, then passed
unchanged on Zakura. The migrated tests regenerate private keys/full PCZT only at
runtime and match the old key-package digests and complete candidate hash exactly.
Public packages, identifiers, signatures, and redacted PCZT also round trip byte
for byte; the old signature verifies under the expected randomized key.

An independent `chacha20poly1305 0.11.0` oracle supplied the old sealed public
payload fixture. Plaintext is `public legacy seal compatibility payload`, passphrase
is `public migration fixture passphrase`, salt is `[0x21; 16]`, nonce is `[0x43; 24]`,
and the existing LOKISEAL header is the AAD. `MemberDir::read_sealed` under 0.10.1
opens these exact bytes without rewriting the file; wrong-passphrase authentication
still fails. This fixture encrypts no key material. The resolver reason for 0.10.1
is documented in [DEPENDENCIES.md](DEPENDENCIES.md).

Actual CLI tests reject malformed/truncated saved key packages through both
`commit` and `review-sign`. Corrupt-magic, unknown-version and truncated saved
PCZTs fail through `review-sign` with the expected parse refusal. Complete filesystem
snapshots show zero share files and unchanged keys, nonces, commitments and proposal
files after each refusal. No migration fallback, key recreation, or nonce reset exists.

## Offline verification

Final validation commands, from `poc/`, excluding the intentionally failing
`probe-zip2005` feature:

```sh
cargo build --locked
cargo test --locked
cargo fmt --check
cargo clippy --locked --all-targets
cargo test --locked --manifest-path vendor/zakura-orchard/Cargo.toml --lib loki_b2
python3 -m unittest discover -s tests -p 'test_*.py'
cargo metadata --locked --format-version 1
cargo tree --locked --edges normal,build
```

Before integrating later main changes, all commands passed: 72 Rust tests
(54 library, 2 CLI, 16 integration), three vendor alpha tests, and 16 Python tests.
Final build/clippy produced no warnings and fmt reported no differences. Both patch
files apply cleanly to pristine archives and reproduce the edited files exactly.
The production graph assertion confirms 20 Zakura packages, all Common at 2.2.0,
PCZT at 0.1.0-rc4, and FROST core/rerandomized exactly 3.0.0. Published manifests
compose without a PCZT patch, using note-encryption 0.4.2 and Merkle-tree 0.8.2.

Current `origin/main` advanced to `754445a` during implementation. After the verified
migration commits, that main was merged locally. Both test-fixture conflicts retain
upstream’s proposed ZIP 2005 derivation, and the separate-member real-PCZT signing
test is retained with rc4’s no-argument IO-finalizer call. Upstream’s one-pager removal
and documentation changes are preserved. Production payment/key derivation and the
custom seed flow are unchanged. On the merged tree, build, all 72 Rust tests, fmt,
clippy and all 16 Python tests passed without Rust warnings. The existing required
live gates above exercised the same production code; fresh merged-tree AB local and
BC independent payments additionally mined and passed effects verification.

The deterministic two-input regression builds 16 shuffled candidates, matches each
real spend by its original note nullifier, checks the original alpha and derived rk,
and requires observing reversed real-spend order. Existing mismatch-alpha-count,
distinct-rk, DKG, share-verification, coordinator, refresh, and approval tests remain.
The full offline two-input test signs each real spend, installs witnesses/anchor
after signing, proves/extracts, and verifies unchanged effects sighash and exact fee.

## Live THS evidence

Root started and owns the dedicated `loki-zakura-issue4` instance. THS is 0.3.0,
Docker is 29.8.1, and inspected runtime images are:

- App: `ghcr.io/zcashlabs/thus-spoke-zakura-app:0.3.0`
- Node: `zakuracore/zakura:1.6.0`
- Lightwalletd: `ghcr.io/zcashlabs/thus-spoke-zakura-lightwalletd:0.3.0`

Endpoints are loopback: RPC `http://127.0.0.1:18302`, dashboard
`http://127.0.0.1:32875`, lightwalletd `http://127.0.0.1:9137`, P2P
`127.0.0.1:18303`. Every harness checks regtest with active NU6.3 branch `37a5165b`.
Every run used new temporary state outside tracked files. Root retains responsibility
for stopping only this instance after independent validation.

The baseline CLI hardcoded AC in all finishing/handoff paths. Meeting the three-pair
acceptance gate required adding backward-compatible `--pair AB|AC|BC` to `finish`,
`post-final`, and `replicate`, retaining their historical AC default. Replicas store
public `pair.txt`; old replicas without it retain AC interpretation. Invalid pair
metadata fails explicitly. `finish-second` and effects verification use that selected
pair's candidate and inputs. The harness defaults to AB, signs only the requested
members, requires exactly that pair to be finishable, checks the actual finished pair,
and verifies independent modes against their replica's artifacts. CLI handoff tests
inspect actual copied pair files and exclude private packages/nonces. Python behavior
coverage exercises all nine pair/finisher combinations, beyond parser mapping.

Independent harness runs move every member directory out of reach during
`finish-second`. Withholding uses persistent storage; each moved member is restored
individually. Failed moves/restores retain remaining keys and report their path,
never auto-delete them. Injected failure tests verify this behavior.

| Harness / pair | Path | Inputs | Txid | Mined height | Confirmations |
| --- | --- | --- | --- | --- | --- |
| `run-regtest.sh`, AB | local | 1 | `2ac8c1c8e41270c5a660c3d082d99e5416cf06b48270165258610a8a12b8ce13` | 107 | 3 |
| AB | independent re-prove | 1 | `ac71451f56f662d5772ebd8e9a42971afa3c8fdbcba9cc9f1c2c3bc51f4e7dbc` | 115 | 3 |
| AC | independent re-prove | 1 | `58a677945a67fa7a3c332d1ea63b6137e9a8e2f5b0a48eb9b5b069061a33a35d` | 119 | 3 |
| BC | independent re-prove | 1 | `538f0a81fc4938452d8712c060300a44adaddbfaaaf5211a0261a5776a6462ab` | 123 | 3 |
| second-device p1, AC | posted A | 1 | `aebb4c2f9be23de8382702a6ce315d30b3d3ab659eafa94444ae0c82e3b1eaa7` | 129 | 3 |
| second-device p2, AC | re-prove B | 1 | `84a7270c3c5bd27443dd05806f3fb1093500b7d73f21122cb40c4d55d8f8faf5` | 132 | 3 |
| second-device p3, AC | re-prove B | 2 | `c45d6bd4eae195b8ac56f13597adcdb750080ce53109b17061c975f9824e04e8` | 135 | 3 |
| second-device p4, AC | posted A | 2 | `cc959a79a95c1e9f84ecdf2cb971d6159a245b140e97039940b19f6647220b20` | 138 | 3 |
| BC | local | 1 | `326c714e94f1d35718b844c8996c605597dade4bb0e65ae7ea87530576883004` | 145 | 3 |
| AB | independent posted | 1 | `9479c598d287afc1f52a84378ccc0fb75f8621430aae54106e6848beda1b29e1` | 149 | 3 |
| BC | independent posted | 1 | `dc0b86b70945e2e6c5bd37489a9660ffc0b06630249a273b23e1afef35c27894` | 154 | 3 |
| AB, final persistent withholding helper | independent re-prove | 1 | `53acb4b34ce6a938aaf3ab37b8f52afd0e9e4e6e83f5054adec75a0b8c39b860` | 158 | 3 |
| After main integration, AB | local | 1 | `810f72ce5e6f29df22585b92e2c9ac46d4ae8df9ffd77b164f78ca5009909f78` | 162 | 3 |
| After main integration, BC | independent re-prove | 1 | `a1ebb49a79464557da78f954a6511299a16a68397829e2553f7f988444c41511` | 166 | 3 |

All completed payments verify input nullifiers, recipient, amount, memo, change and
10,000-zat fee against mined chain bytes. Re-proving logs record signature application
before anchor/witness/proof and unchanged effects sighash after installation. Posted
finishing validates exact effects sighash and inputs before broadcast. Second-device
finishing moves the entire approver state aside and passed all five failure cases:
approver scan file present, missing share, malformed posted transaction, posted
transaction for another intent, and repeat broadcast.

`tamper-tests.sh`: nine adversarial mutations refused for the expected reason with
zero shares, honest control accepted, zero failures. Fee-only mutation remains
unconstructible (`ChangeRequired(ZatBalance(1000))`), explicitly not a passed attack
case. `nonce-reuse-drill.sh` used a newly funded, unspent vault: stage A refused with
no AC share; stage B signed honestly, restored the same Alice nonce files, re-committed
Carol and rebuilt the candidate, then emitted a second **different** share. This
records the existing rollback reuse limitation, not a protection claim. Its observed
stage B output was inspected; exit code alone was not treated as evidence.

Early pair-routing failures were diagnosed and corrected before these successful
runs. No failed run is counted as a pass. No required live gate is skipped or blocked.

## Coordination and limits

Issue #3 was rechecked open with no open PRs after validation. The custom deterministic
seed flow and existing signing API remain intact; generated randomizer seeds belong
to the concurrently coordinated #3 work. No unrelated checkout was edited. Full G1,
physical devices, authenticated remote relays, crash-safe nonce consumption, custody,
and independent audit coverage remain outside the established claims. Review and
push/PR creation are owned by the coordinating root agent.
