# Who has to be malicious, and what do they get?

This chapter records the earlier local seed-flow and rollback drill. The staged
relay-backed signing path now uses first-write nonce claims from two pinned
relays; its conditional rollback boundary is in [Signing sessions](SIGNING-SESSION.md).

Two questions that turned out to be one. `nonce-reuse-drill.sh` showed a signing share can
be leaked by a rollback **paired with a rebuilt candidate**, and the party that rebuilds the
candidate is the coordinator. So the cost of a leak and the power of the coordinator have to
be answered together.

The original boundary was demonstrated by coordinator tests and the historical
`nonce-reuse-drill.sh`. Current seed-flow validation and the updated live drill outcome
are recorded separately in [FROST-RANDOMIZER-RESULTS.md](FROST-RANDOMIZER-RESULTS.md).

## What the coordinator cannot do

| | |
|---|---|
| **Equivocate**: show Alice one payment and Carol another, then combine | **CO.1** shares made under different signing packages do not aggregate, under either package |
| **Reach the threshold alone** | **CO.2** one share is not a signature in a 2-of-3 group |
| **Forge a missing share** | **CO.4** `aggregate` checks each share against that member's verifying share, rejects the forgery and names the culprit |
| **Change what a signer agreed to** | independent payment review and local sighash; historical tamper cases refused with no share written, current seed refusals also check zero new shares |
| **Change a fixed candidate's seed or commitments unnoticed** | record association and reconstructed canonical α/`rk` checks refuse inconsistent data against the known vault key |

## docs(signing): seed generation and handoff boundaries

Production calls `RandomizedParams::new_from_commitments` with `OsRng` before each
real spend is built, saves the returned seed with its exact proposal/pair/index/
nullifier/commitments association, and reconstructs it during review and aggregation.
Signers independently check the canonical proposal, payment effects and local sighash;
all checks and share computations precede any share output or nonce deletion. This
removes the custom seed derivation assumption. It does not prove that a hostile
coordinator used random seeds, provide a security proof, or extend NCC's published
audit to rerandomized FROST.

Seeds require confidential handoff. The prototype uses a local replica directory
protected as 0700 and seed records as 0600 on Unix; it implements no encrypted or
authenticated relay. It withholds approver key packages, nonce secrets and scan state.
The replica still needs an authenticated association with the intended account/payment.

Ordinary reproposal refuses any existing intent/candidate/seed/alpha/share files
unchanged. An honest new session needs a fresh `LOKI_ROUND` and fresh commitments.
Neither this guard nor batch checking makes writes and nonce consumption crash-atomic
or provides a consumed-nonce ledger or rollback protection.

## What the coordinator can do

**Supply a chosen seed.** Reconstructed α/`rk` checks detect inconsistency with the fixed
candidate, but cannot prove seed randomness.

**Cause a nonce leak, given a rollback.** `nonce-reuse-drill.sh` stage B. Moving the
commitment set or saved seed against a fixed candidate is caught by association or
α/`rk` checks (stage A). Deliberately rebuilding a consistent candidate and association
under restored, already-used nonce secrets (stage B) is not caught, because at that
point **nothing is inconsistent for the signer to notice**. The only thing that had prevented reuse was the deleted nonce file.

A fresh seed does not repair nonce reuse. Ordinary reproposal refuses a saved round;
the adversarial rebuild in the drill is a test-only path. No information available to
`review_sign` distinguishes that case from an honest first signing.

## What a leaked share is worth

| attacker holds | outcome |
|---|---|
| one share | **nothing spendable.** CO.2: one share is not a signature |
| two shares | **total loss.** CO.3 produces a valid group signature with no cooperation from either owner, and it verifies under the group key |

## The line that matters

> **One** rolled-back member is survivable. **Two** is total loss. A malicious co-signer
> counts as one of the two for free.

That reframes the urgency. The dangerous adversary is not an outsider who can roll back one
device: they get one share, which signs nothing. It is

* an outsider who can roll back **two** members, or
* **one malicious member** who can roll back **one** other.

The second is much cheaper to achieve than the first, and it is the case to design against.

## What this does not cover

- **Liveness.** A coordinator that withholds or stalls is not modelled here. It cannot steal,
  but it can stop the account working.
- **Share refresh.** `frost_core::keys::refresh` is public and generic over the ciphersuite,
  so it is reachable with `PallasBlake2b512` even though `reddsa` does not re-export it.
  Nothing in the prototype calls it yet, so there is currently **no response to a suspected
  leak**: a leaked share stays valid for the life of the group.
- **Identifying which member leaked.** Not attempted.
- **Real relays.** The G3 operators are local processes; three on one machine are not three
  operators.
