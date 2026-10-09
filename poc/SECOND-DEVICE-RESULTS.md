# Second-device finishing on the G1-TX path

> Historical experiment record. Node build/configuration details below describe the
> original run. Current local-chain setup uses THS; see [harness/README.md](harness/README.md)
> for current local-chain instructions.

## Both paths mined and verified. This is not full G1, not G3, and not custody readiness.

Date 2026-10-03. Regtest, NU6.3 (Ironwood). One 2-of-3 FROST vault, two payments, two
finishing paths, one finisher that holds none of the approvers' files.

```
p1  path A  txid a5f79ca7a3f41efd33dde6336bb07219251a35bfa0b2aa03042f1cf8bf9dc3d1
p2  path B  txid 5621135c5fd82699fa2a797627e9b7be1b2712c64d9c1bd780873d0062a57d1d
```

## The key construction is TEST-ONLY, and nothing here changes that

The vault FVK is a documented splice of the DKG group `ak` into `ak || nk || rivk`
(`src/vault.rs::test_only_fvk`). It is **not** the ZIP 2005 `qsk → qk → rivk_ext`
derivation, which is implemented in no crate (`DEPENDENCIES.md` finding B1, and the ZIP is
`Status: Proposed`). The finisher prints this at the point of use, every run, before it does
anything:

```
second device: vault FVK rebuilt from the replicated group ak
               TEST-ONLY construction (ak || nk || rivk), not ZIP 2005
```

**Full G1 remains BLOCKED (ZIP 2005).** This work does not advance it.

Also not claimed: **G3** (the nonce store here is plain files with no rollback guarantee;
`g3/` is where that is prototyped, and it is PARTIAL), independent recovery, and custody
readiness. This is one regtest flow on one machine.

## Run

```
cd poc && ./run-second-device.sh
```

The current script runs the two historical one-note payments, then two new two-note
payments (paths B and A). It exits nonzero if any payment fails to mine, if the mined
effects do not match the approved intent, or if any failure case is not refused. It
attaches to the developer-started THS instance selected by `LOKI_THS_INSTANCE` and
requests two confirmed 1-ZEC faucet notes. The two-note payments use 1 and 1.1 ZEC
to stay within that funding. Approver state, replicas, and results remain under the
printed temporary directory for inspection. The script does not stop the THS instance.

The historical run below used fixed `/tmp` paths. The current driver runs the same stages
under its printed temporary directory and adds the two two-note payments.

Stage by stage, the commands the historical script ran:

```sh
loki setup    /tmp/loki-2dev                    # 2-of-3 DKG, three member directories
loki address  /tmp/loki-2dev                    # the vault's regtest unified address
loki scan     /tmp/loki-2dev                    # the approvers' own funding scan

# per payment, with LOKI_ROUND=p1 or p2 so the second cannot overwrite the first
LOKI_ROUND=p1 loki commit      /tmp/loki-2dev alice   # and bob, and carol
LOKI_ROUND=p1 loki propose     /tmp/loki-2dev funded_note.txt
LOKI_ROUND=p1 loki review-sign /tmp/loki-2dev alice   # separate process
LOKI_ROUND=p1 loki review-sign /tmp/loki-2dev carol   # separate process
LOKI_ROUND=p1 loki post-final  /tmp/loki-2dev         # path A only: prove, post, no broadcast
LOKI_ROUND=p1 loki replicate   /tmp/loki-2dev /tmp/loki-2dev-bob/replica_p1 --with-final

mv /tmp/loki-2dev /tmp/loki-2dev-attic/state_p1       # both approver apps close

loki finish-second  /tmp/loki-2dev-bob/replica_p1 /tmp/loki-2dev-bob/work_p1
loki verify-effects /tmp/loki-2dev-bob/replica_p1 <txid>
```

Payment 2 is identical except `LOKI_ROUND=p2`, `funded_note_alt.txt`, no `post-final`, and
`replicate` without `--with-final`.

## What the finisher is given, and what it is not

`replicate` writes only public, relay-carried artifacts, and writes a manifest naming what
it withheld. The replica for path B, verbatim from the run:

```
candidate_AC.pczt.hex    commitment_AC_alice.hex   commitment_AC_carol.hex
group_ak.hex             identifier_alice.hex      identifier_carol.hex
intent.txt               public_package.hex        share_AC_alice.hex
share_AC_carol.hex       MANIFEST.txt
```

Path A's replica is the same plus `final_tx.hex`.

Withheld, and named as withheld in `MANIFEST.txt`:

| not replicated | why it would have invalidated the test |
|---|---|
| `alice/key_package.hex`, `carol/key_package.hex` | the approvers' secret shares |
| `bob/key_package.hex` | the finisher's own share is not used either; finishing needs no secret |
| `*/nonces_*.hex` | every member's nonce secrets |
| `funded_note.txt`, `funded_note_alt.txt` | an approver's scan output: note, rho, rseed, position |
| `cmxs.hex` | an approver's commitment stream |
| `anchor.txt` | an approver's anchor |

**The approver state is moved, not just ignored.** After `replicate`, the script runs
`mv /tmp/loki-2dev /tmp/loki-2dev-attic/state_pN` and asserts the path no longer exists.
The finisher cannot read what is not there.

`finish-second` also refuses structurally rather than relying on the script's discipline:
it errors if `alice/`, `bob/` or `carol/` exists under either directory, and if the replica
contains `funded_note.txt`, `cmxs.hex` or `anchor.txt`. One of the failure cases below
exercises that.

## The finisher's own chain scan

The note position, the commitment stream and the anchor all come from
`scan::scan_chain`, run by the finisher against the node. Nothing is read from an approver
file:

```
p1   own scan: 29 blocks, 29 vault notes, input note at position 0
p2   own scan: 33 blocks, 35 vault notes, input note at position 1
```

The input note is located by matching the intent's `input_nullifier` against notes the
finisher decrypted itself, and the witness is checked against the node's own anchor before
it is used (`witness::witness_for` fails loudly if the rebuilt root differs).

**A bug found and fixed here.** `scan_block` originally tried only the external incoming
viewing key. Coinbase funding and payments to a diversified address are external, so the
funding scan worked, but **change goes to the internal address and was invisible**. It
surfaced as `no change output to the vault could be decrypted` on the first effects check.
`scan::vault_ivks` now returns both scopes and both scan paths try both; p2's scan seeing
35 notes against p1's 29 is the change notes becoming visible.

## Path A: broadcast an already posted final transaction

Alice aggregated, proved, extracted and **posted** the final transaction without
broadcasting (`post-final` writes `final_tx.hex` and prints `broadcast=no`). Then both
approver apps closed.

```
AC  aggregated two shares; verifies under ak+alpha
AC  anchor and witness installed after signing
AC  effects sighash unchanged by anchor/witness installation
AC  extracted v6 transaction a5f79ca7… (9166 bytes)
AC  final transaction POSTED, not broadcast: a5f79ca7…

path A  posted final transaction parsed: a5f79ca7…
path A  it spends the nullifier the intent names
path A  broadcast: "a5f79ca7a3f41efd33dde6336bb07219251a35bfa0b2aa03042f1cf8bf9dc3d1"
```

The finisher does not broadcast blindly. It parses the posted bytes, reads the Ironwood
bundle, and requires an action whose nullifier is the one the intent names. Two failure
cases below show that check firing.

## Path B: re-prove the signed candidate, no final transaction posted

No `post-final` ran, so `final_tx.hex` is absent and the manifest records it as
`deliberately absent: this is path B`. The finisher does the whole second half itself:

```
path B  no final transaction posted; re-proving the signed candidate
path B  aggregated two shares; verifies under ak+alpha
path B  anchor and witness installed after signing
path B  effects sighash unchanged by anchor/witness installation
path B  building the proving key...
path B  proof created
path B  extracted v6 transaction 5621135c… (9166 bytes)
path B  broadcast: "5621135c5fd82699fa2a797627e9b7be1b2712c64d9c1bd780873d0062a57d1d"
```

It computes the effects sighash from the candidate bytes itself, recomputes α from the
proposal id and the published commitments rather than accepting one, verifies the
aggregated signature under `ak + [α]G` before any node sees it, and only then installs the
anchor and witness from its own scan. The sighash is re-checked after installation and is
byte-identical, which is the claim the whole deferred-anchor path rests on.

## Effects verified against the chain

`verify-effects` fetches the mined transaction by txid, trial-decrypts its Ironwood actions
with the vault's own viewing keys in both scopes, and compares every field the intent
names. It also compares the mined effects sighash with the replicated approved candidate.

| | p1, path A | p2, path B |
|---|---|---|
| mined at height | 32, 2 confirmations | 41, 1 confirmation |
| nullifier spent | `aad0fdc8624da54b…` | `d85ff2d16ba83257…` |
| paid | 40000000 zat to `778f6f5b…` | 40000000 zat to `778f6f5b…` |
| memo | `"loki g1-tx"` | `"loki g1-tx"` |
| change | 584990000 zat, vault internal address | 584990000 zat, vault internal address |
| implied fee | 10000 zat | 10000 zat |

The memo is compared over the whole 512-byte field: the prefix must equal the approved memo
and every remaining byte must be zero, so a trailing payload cannot hide in the padding.
Any output to an address the intent does not name is a hard failure, not a warning.

## 8 October extension awaiting a live regtest run

The CLI now carries per-spend commitments and shares through `replicate`, aggregates and
witnesses every input in `post-final` and `finish-second`, and compares every action's
nullifier and the full effects sighash before broadcasting a posted transaction. The mined
fee is read from the consensus Ironwood value balance. An offline two-note candidate test
signs and aggregates both spends, rejects a share copied between them, installs both
witnesses, creates the Halo 2 proof, and extracts a v6 transaction. The extracted bytes
parse back with the signed effects hash and expected fee. This is local proof and
extraction; the two-note second-device transaction has **not** yet been mined, so the
historical transaction results above remain single-note chain evidence. The
`scan` stage now uses the same spent-note filter as the second-device scanner, so the
new rounds cannot reselect the already mined inputs.

## Failure cases

All five are asserted, and three of them assert **which layer refused**. A local validation
failure that only the node caught would mean the finisher shipped unchecked bytes, so
`check_local` fails the case if `sendrawtransaction` appears in the output at all.

```
replica carries an approver scan file   refused: the replica contains funded_note.txt,
                                        which is an approver's scan output
replica missing carol's share           refused: share_AC_carol.hex: No such file or directory
posted final tx does not parse          refused locally: the posted final transaction does
                                        not parse: failed to fill whole buffer
posted final tx is for another intent   refused locally: the posted transaction does not
                                        spend the note the intent names
payment 1 broadcast a second time       refused: sendrawtransaction: {"code":-1,"message":
                                        "any transaction with the same effects will be rejected"}
```

**Two of these were weak and were corrected.** The first version of the corrupted-final
case flipped one byte in the proof of payment 1's already-mined transaction. It "passed",
but the node had rejected it as a double spend, so the case proved nothing about the
finisher's checking. It is now two cases that both refuse locally: a truncated transaction
that cannot parse, and payment 2's real mined transaction substituted into payment 1's
replica, which parses perfectly and is caught by the nullifier check. The double-spend case
is kept separately, where the node is the correct layer to refuse.

An earlier version of the driver also piped every stage through `sed`, which discarded exit
codes; four stages failed in sequence and the script carried on. Stages now run through a
`step` helper that aborts the payment on a nonzero exit.

## What this does NOT establish

- **Not full G1.** The test-only FVK stands in for ZIP 2005 derivation, which exists
  nowhere. **G1 BLOCKED (ZIP 2005)** is unchanged.
- **Not G3.** Member state is plain files with no rollback or crash guarantee; a nonce is
  deleted after use, which is not a crash-safe consumed-nonce ledger. `g3/G3-RESULTS.md`
  is where that is measured and it is PARTIAL.
- **Not a real second device.** It is a second *process* with a separate directory on the
  same machine, reading a replica built by a local `cp`. There is no relay, no transport,
  no authentication of the replicated records, and no second piece of hardware.
- **The replica is trusted for authenticity.** `replicate` copies files; nothing signs the
  proposal, the commitments or the shares in transit. The finisher does verify everything
  cryptographically after reading it (α recomputed, signature checked under `ak + [α]G`,
  posted transaction checked against the intent), so a corrupted replica cannot produce a
  wrong payment, but a *substituted* intent would be finished faithfully. Binding the
  replica to an authenticated group record, so a substituted proposal could be detected,
  is design work that is not done here.
- **No concurrent finishers.** One finisher at a time. Two devices racing to finish the
  same candidate is not tested; the node's double-spend rejection is the only thing that
  would stop the second, and that is after the fact.
- **AB and BC were signed but never finished.** Both payments produced three candidates and
  the approvers signed the two they were in, so shares for AB and BC exist on disk. Nothing
  here tests that finishing AC makes them unusable beyond the node's own double-spend
  rejection, which is what the final failure case shows.
- **Chain scan cost is not addressed.** The finisher rescans every block from genesis on
  every run, and rebuilds the whole commitment tree. Correct on a 40-block regtest chain and
  useless on mainnet; a real finisher needs an incremental tree.
- **One note per payment, one input, one recipient.** No multi-input spends, no multiple
  recipients, no Orchard pool, no transparent pool.
- **No custody readiness.** Two regtest payments on a documented test-only key prove a code
  path works. They say nothing about operational safety.

## Files changed

```
src/scan.rs            scan_chain, chain_anchor, try_decrypt_with_memo, vault_ivks;
                       scan_block now takes a slice of viewing keys and tries both scopes
src/bin/loki.rs        new stages post-final, replicate, finish-second, verify-effects;
                       aggregate_and_apply and prove_and_extract factored out of finish;
                       shared_name() so two payments can run against one vault
run-second-device.sh   the driver: four payments, two paths, five failure cases
```
