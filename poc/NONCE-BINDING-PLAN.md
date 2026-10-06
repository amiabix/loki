# Can package-bound nonces remove the storage-rollback hole?

G3 left one hole open: a browser profile can be rolled back, the device re-uses a nonce
for a different message, and the signing share leaks. The 2-of-3 relay receipt gate
mitigates it but does not close it, and two colluding relays defeat it entirely.

G3's own conclusion named one relay-free fix: **bind each nonce to the exact package at
publication, so replaying it can only ever reproduce the identical share.** That paragraph
has never been tested. This is the plan to test it.

## The tension that makes this worth doing

The design's headline feature is *prepared-subset mode*: publish nonce commitments in
advance, build one candidate per signing pair, approve once, walk away, and let any two
members complete it later. That requires nonces generated **before** the message exists.

Binding a nonce to a package requires knowing the package **when the nonce is generated**.
Those two requirements are in direct conflict. So the real question is not "does binding
work" but:

> Is there a binding granularity that removes the reuse hole **and** keeps approve-once?

A negative answer is worth as much as a positive one, and would be worth knowing before
any more relay machinery is built.

## Why this is a Rust question, not a browser one

The G3 prototype signs with a Schnorr stand-in: `s = k + e·x`. Real FROST has a **binding
factor** `ρ = H(id, msg, commitment_set)` that the stand-in does not model, and the whole
difficulty lives there. Two shares over the same nonce leak the key whenever **anything
that feeds ρ or the challenge differs** — not only the message.

That matters because `ρ` covers the **commitment set**, which includes the other signer's
commitment. So a nonce bound only to the package digest can still be replayed into a
different `ρ` if a co-signer re-commits. Testing this in the JS stand-in would produce a
confident, wrong answer.

So: cryptography first, in Rust against real `reddsa` FROST. Storage second, in the browser
harness, and only for a scheme that survives.

## Phase A — does the leak exist, and does binding stop it?

Each step is a test in `src/nonce_binding.rs` that either extracts a key or fails to.

- **A.1 Extraction oracle.** Given two signature shares produced from the same nonce pair,
  recover the signer's secret share. Pure scalar arithmetic over the Pallas scalar field.
  Everything below is scored by this and nothing else.
- **A.2 Baseline: prove the leak is real.** Classic reuse, one nonce pair and two different
  messages, with real `frost_rerandomized::sign`. **The oracle must recover the key.** If it
  does not, no later result means anything, exactly as the honest control works in G3.
- **A.3 Scheme 1, package-bound nonces.** `nonce = SigningNonces::new(share, ChaCha(seed ‖
  package_digest))`. Replay the *same* package: the nonce, the commitment and the share must
  all be byte-identical, and the oracle must find nothing.
- **A.4 Scheme 1 under a different package.** Replay with a different package digest: the
  nonce must differ, so there is no reuse to exploit. Oracle finds nothing.
- **A.5 Scheme 1 under a re-committing co-signer.** Same package digest, but the other
  signer publishes a fresh commitment, so `ρ` changes while our nonce does not.
  **Predicted to leak.** This is the step that decides whether Scheme 1 is sufficient.
- **A.6 Scheme 2, if A.5 leaks.** Extend the binding to cover the full commitment set. This
  is circular on its face, since the set contains our own commitment. Test whether a commit
  ordering breaks the circle, and record precisely why if it does not.

## Phase B — what does a surviving scheme cost?

Only runs if something survives A.

- **B.1 Granularity.** Can one nonce bind to a candidate *family*, all pairs of one
  proposal, rather than a single candidate? Loki already uses a separate nonce per pair, so
  the question is whether the family digest is known early enough.
- **B.2 Approve-once.** Does the surviving scheme still let a member approve once, offline,
  with any two completing later? State plainly if it does not.
- **B.3 Round cost.** If preprocessing is lost, measure what replaces it: one extra round
  trip, or a second human visit. Those are different products.

## Phase C — storage, only if a scheme survives

- **C.1** Re-run the G3 restore drills with the surviving scheme and **zero relays
  configured**. Target: `restore-all-acknowledgers-lying` stops recovering a key.
- **C.2** If it holds, the relay apparatus (three operators, Ed25519 receipts, pinning, the
  2-of-3 gate) can be deleted. Measure what is left.

## Rules for this work

- A claim of "no leak" is only valid when the extraction oracle has first been shown to
  work on a known-bad case in the same test file.
- No scheme is reported as safe on the strength of an argument. It has to survive A.5.
- A negative result ends the line and is written up as such.

## Phase A result: Scheme 1 does not work, and the reason generalises

`cargo test --lib nonce_binding` — 5 tests, all passing. Passing here means "the asserted
behaviour was observed", including for the two tests whose assertion is that a scheme
fails.

| test | asserts | outcome |
|---|---|---|
| `a2_baseline_reuse_is_detectable` | one nonce, two messages, shares differ | the oracle fires on a known-bad case |
| `a3_same_package_replay_is_byte_identical` | replaying one package reproduces the share byte for byte | **binding works for the simple rollback** |
| `a4_a_different_package_changes_the_nonce` | a different package gives a different nonce | no reuse to exploit |
| `a5_a_recommitting_cosigner_defeats_package_binding` | same nonce, two shares, message unchanged | **Scheme 1 insufficient** |
| `a6_ordered_binding_protects_only_the_second_signer` | ordering moves the hole, does not close it | **Scheme 2 insufficient** |

### What A.5 showed

Binding the nonce to the package digest handles exactly the case G3 described: a device
rolls back, replays the identical publication, and produces a byte-identical share. Nothing
new leaks.

It does not handle the case G3 never modelled. `rho` covers the **whole commitment set**, so
a co-signer who simply commits a second time moves the binding factor while our bound nonce
stays fixed. Same nonce, two different shares, and **the message never changed**. That is
the precondition G3's `extractOnReuse` turns into a recovered key. Re-committing is cheap,
public, and needs no privilege.

### What A.6 showed

The obvious repair is to bind to the co-signer's commitment too. Symmetrically that is
circular: each party's nonce would depend on the other's commitment, which depends on
theirs. A fixed commit order looks like a way out, and it half works: the signer who commits
second is genuinely protected, because a re-commitment upstream moves its nonce rather than
only its binding factor.

The signer who commits **first** is not protected, and cannot be. It binds to the package
alone because nothing else exists yet. Ordering relocates the vulnerability; it does not
remove it.

### The general statement

> A nonce cannot be bound to everything its own binding factor depends on, because the
> binding factor depends on the commitment set, which contains the nonce's own commitment.

Any scheme that tries to close this by including the set is circular. Any scheme that
breaks the circle by ordering leaves whoever goes first exposed. The only remaining way to
pin the commitment set before nonce generation is an extra round, and an extra round is
precisely what preprocessing exists to avoid.

**Conclusion: the state requirement cannot be removed by binding.** A signer must remember
that a nonce was used. The question is not how to avoid that memory but how to make it
survive rollback.

## What this means for the product

Phase B is moot in its original form: there is no surviving scheme whose cost needs
measuring. The prepared-subset feature is not in tension with a fix, because there is no
relay-free fix to be in tension with.

Phase C is also moot: there is nothing to re-run the restore drills against.

The open problem returns to where G3 left it, now with one more option eliminated and the
reason recorded:

1. **Hardware-backed, non-exportable, non-backed-up nonce storage.** What the design
   already calls for on mobile, and what a browser does not have.
2. **A non-rollback counter the device cannot forge**, held by something the user carries.
3. ~~Bind the commitment to the package~~ — **eliminated here.**

That leaves the honest reading: a pure web wallet cannot hold nonce state safely against
rollback, and the relay gate from G3 is a mitigation rather than a fix. Either the product
accepts a hardware dependency for the signing device, or it accepts that two colluding
relays can cause a key loss.

### Worth noting about the relay gate

A.5 also sharpens what the G3 relays are actually for. They are not only detecting
rollback; an honest relay that refuses a second commitment for one `(package, signer)` is
preventing the A.5 attack directly. That is a stronger argument for the relay design than
the one G3 made, and it should be tested on its own.

## Phase A applied to Loki itself: `./nonce-reuse-drill.sh`

A.5 is about bare FROST. Loki is not bare FROST: it derives the per-pair randomiser from
the proposal AND the published commitment set, and every signer recomputes it rather than
accepting one. So the question became whether that already defends the real signing path.
`nonce-reuse-drill.sh` runs it against the live prototype, in two stages.

**Stage A, the naive attack: defended.** Carol re-commits, the candidate is left alone.
Alice refuses with `rk does not match recomputed alpha`, and writes no share. The
derivation is doing real work; this is not an accident of the test.

**Stage B, the composed attack: not defended.**

```
1. alice signs honestly, nonce consumed
2. nonce files restored, shares dropped: the device believes it never signed
3. carol re-committed; candidate rebuilt so rk matches the new alpha
4. alice signed again, and the share DIFFERS

   share 1 5c3c603f906019c0cbb6e875ae99cfba598325b8...
   share 2 bfbff0c400d23e31804ce22b07162c1f670b6eaa...
```

Same nonce, two different shares. Once the attacker rebuilds the candidate to match the
moved commitment set, **nothing is inconsistent for the signer to notice**. The `rk` check
is satisfied, the effects check is satisfied, and the only thing that had been preventing
reuse was that the nonce file had been deleted.

### What that pins down

> Nonce safety in this prototype rests on deletion surviving. It does not rest on the `rk`
> check, which cannot see this attack at all.

This is not a bug in the signer, and nothing in `review_sign` needs fixing: there is no
information available to it that would distinguish stage B from an honest first signing.
It is the measured boundary of what the randomiser derivation can do, and it puts the whole
weight back on nonce-store durability, which is G3's open problem.

It also raises the cost of the G3 relay gate failing. Two colluding relays do not merely
hide a rollback; combined with a rebuilt candidate they produce a recoverable key.

## Status

Phase A complete, negative. Phases B and C do not apply.
Applied to the real signing path: stage A defended, stage B not. Drill kept as
`nonce-reuse-drill.sh`.
