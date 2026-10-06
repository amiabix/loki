# Who has to be malicious, and what do they get?

Two questions that turned out to be one. `nonce-reuse-drill.sh` showed a signing share can
be leaked by a rollback **paired with a rebuilt candidate**, and the party that rebuilds the
candidate is the coordinator. So the cost of a leak and the power of the coordinator have to
be answered together.

Established by `cargo test --lib coordinator` (4 tests) and `./nonce-reuse-drill.sh`.

## What the coordinator cannot do

| | |
|---|---|
| **Equivocate**: show Alice one payment and Carol another, then combine | **CO.1** shares made under different signing packages do not aggregate, under either package |
| **Reach the threshold alone** | **CO.2** one share is not a signature in a 2-of-3 group |
| **Forge a missing share** | **CO.4** `aggregate` checks each share against that member's verifying share, rejects the forgery and names the culprit |
| **Change what a signer agreed to** | `verify.rs` + `tamper-tests.sh`: 10 adversarial cases, each refused with no share written |
| **Choose the randomiser** | every signer recomputes α from the proposal and the published commitments and checks `rk` against it |

## What the coordinator can do

**Cause a nonce leak, given a rollback.** `nonce-reuse-drill.sh` stage B. Moving the
commitment set alone is caught by the `rk` check (stage A). Rebuilding the candidate so `rk`
matches the moved set is not caught, because at that point **nothing is inconsistent for the
signer to notice**. The only thing that had prevented reuse was the deleted nonce file.

This is not a flaw in `review_sign`. No information available to it distinguishes that case
from an honest first signing.

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
