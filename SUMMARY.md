# Shielded Threshold — Zcash FROST Multisig

**Research + technical design summary**
First pass: 2026-09-29 · Second pass: 2026-09-30

- First-pass page: https://claude.ai/code/artifact/2936d384-253c-4827-b51e-7e5a72b17af5
- **The book** (21 chapters, ground up): https://claude.ai/code/artifact/268c9f60-4d26-49eb-bab2-3969a2f7a3bf
- Konclave + zigner teardown: https://claude.ai/code/artifact/64152e67-1766-4ea3-9f55-ed68f802ee81
- **Test suite:** `scratchpad/frost-spike` · 20 tests, 1,074 lines, all passing

> **The second pass ran code.** Everything §0.5 marks as corrected was previously an
> estimate or an inference and is now either measured or executed. Where the two
> passes disagree, §0.5 wins.

---

## 0. TL;DR

- Zcash multisig **already exists** and works. Four active projects, two on mainnet.
- The thing **nobody has shipped is recovery** — what happens when a member loses their device.
- Recovery is **two** primitives, not one: `keys::repairable` rebuilds the lost share, then
  `keys::refresh` invalidates the old copy. Both unused by every Zcash project.
- Neither is audited. The NCC review covered frost-core **0.6.0**, which contains no refresh
  code at all, and explicitly excludes rerandomized FROST — the variant Zcash uses.
- That gap is the product. A signing + recovery **layer**, not another wallet.
- Two grant applications for "an SDK wrapping frost-core" were rejected this year. Don't pitch that.

---

## 0.5 Corrections and additions — second pass, 2026-09-30

Everything here was checked by reading the crate source or by running a test. Items
marked **CORRECTION** contradict the first pass; items marked **NEW** were not known.

### Recovery

**CORRECTION — refresh alone cannot recover anything.** §9 described `keys::refresh` as
the recovery mechanism. It is not. Refresh computes `sᵢ′ = sᵢ + z(i)` where `z` is a
sharing of zero. If `sᵢ` is gone there is nothing to add the correction to. **Refresh
rotates a seat; it cannot issue one.**

The primitive that issues one is `frost-core::keys::repairable` — the repairable
threshold scheme, three parts, in the same crate and equally unused. A threshold of
survivors send blinded values to the new device, which reassembles the lost share
without any of them learning the group key.

So recovery is **repair, then refresh**, and skipping either is a different kind of wrong:

| Skip | Consequence |
|---|---|
| repair | nothing to refresh; the seat stays dead |
| refresh | the share is restored **identical**, so a recovered device is still a live seat |

*Verified:* `lose_a_device_and_recover_without_moving_funds` runs the whole flow on
RedPallas — 2-of-3 signs under a fixed α, a device is destroyed, survivors repair it,
everyone refreshes, and the destroyed share is then rejected with `Invalid signature
share`. Two controls guard the ending.

**NEW — refresh needs no dealer and only one round.** `compute_refreshing_shares` takes
only the *public* key package. No secret goes in, so any member can compute the
refreshing shares, and retaining them grants nothing that a threshold of new shares
would not already give. A dishonest helper can stall the run but cannot steal.
That makes everyday refresh **one round, not the three a DKG costs.**

**CORRECTION — "audited" is wrong.** §8 lists `frost-core 2.2.0` as "NCC-audited". The
ZcashFoundation/frost README states the audit covered release **0.6.0** and that it
*"does not include frost-secp256k1-tr and rerandomized FROST"*. Release 0.6.0 contains
**zero occurrences of the string `refresh`** — checked. So the refresh path is outside
the audit, and so is the rerandomized variant ZIP 312 specifies. Do not describe any of
this as audited without that scope attached.

### The Zcash side, which the first pass skipped

**NEW — how a group key becomes an address.** An Orchard viewing key is
`ak || nk || rivk`. Replace `ak` with the FROST group verifying key and everything
downstream — address, note detection, balance — works unchanged, because none of it ever
needed `ask`. This is not theory: zkool does exactly this at
`frost/dkg/exec.rs:269-279`, splicing the serialized group key over the first 32 bytes
of a full viewing key.

**NEW — Orchard requires `ak` to have an even y coordinate**, and the parser enforces it:

```rust
// orchard/src/keys.rs — SpendValidatingKey::from_bytes
// - The sign of the y-coordinate must be positive.
if b != [0; 32] && b[31] & 0x80 == 0 { … } else { None }
```

A group key with odd y is a perfectly good public key that Zcash refuses to parse, so
the group has no address at all. Who fixes it depends on the version:

| Library | Even-y handling |
|---|---|
| `reddsa` 0.5.2 | **Automatic.** Implements the `post_generate` / `post_dkg` ciphersuite hooks and calls `into_even_y` |
| `reddsa` 0.5.1 | **None.** No `EvenY` in the crate at all — the caller must do it |
| `frost-core` | Knows nothing about Orchard by design; the hooks exist from 2.2.0 |

zkool is on a 0.5.1 git rev and calls `into_even_y` by hand (`dkg/exec.rs:270`).
Konclave is on 0.5.2 and gets it free.

> *This began as a wrong guess.* I predicted half of all groups would need correcting and
> wrote a test to show it. It found 0 of 64, against a measured 50/50 split for raw curve
> points, which is what led to the hooks above. Measuring beat reasoning.

### Versions

**CORRECTION — target frost-core 3.0.0, not 2.2.0.** Konclave already ships 3.0.0. The
refresh constraints hold there: `min_signers` must match, the verifying key is copied
verbatim, the construction is still a sharing of zero.

**NEW — every Zcash implementation is pinned to a deprecated call.**
`frost-rerandomized` 3.0 deprecated the explicit-randomizer `sign` in favour of a
coordinator-generated seed. Zcash structurally cannot use the seed path, because α is
fixed by the transaction before any signer sees it. `Randomizer::from_scalar` and
`::deserialize` are *not* deprecated, so the approach survives, but the call around it is
on notice. Worth raising upstream rather than each project pinning around it quietly.

### zkool, measured rather than estimated

**CORRECTION — the group caps at t=3, not "t=4–5".** Z4 called the ceiling arithmetic and
unverified. Measured by serializing real signing packages on the real ciphersuite:

| t | signing package | + zkool's envelope | of 512 |
|---|---|---|---|
| 2 | 241 | 392 | fits |
| 3 | 342 | **493** | fits, by 19 bytes |
| 4 | 443 | 594 | **over** |
| 5 | 544 | 695 | over |

The package grows **101 bytes per signer**. At t=4 the package alone is 443 and the
fields it must sit beside are another 134, so it is over the wall before a single byte of
framing. **No encoding choice rescues it.** The interface offers up to 5.

**NEW — the share is broadcast before it is recorded.** Phase 3 opens a DB transaction,
writes the share, *then* publishes the Zcash transaction carrying it, and commits last
(`frost/sign.rs:549, :605-627`). The stated intent is that a failed send must not leave a
stored share: the correct worry pointed the wrong way. A crash between broadcast and
commit leaves the share on chain with no local record. The nonce column is `NOT NULL` and
never cleared (`:333`), and the row's signing package is overwritable (`:416, :492`).

**NEW — message authentication is bypassed by omitting it.** `verify_message` returns
`true` when the signature field is absent, for backward compatibility
(`frost/sign.rs:148-151`). The field is `Option` in the wire struct, so an attacker does
not defeat the signature: they delete it.

**NEW — the transport's confidentiality rests on a list of addresses.** Every wallet
derives the shared broadcast account from
`BLAKE2b("Zcash__FROST_DKG", sorted mailbox addresses)` → BIP-39 mnemonic
(`frost/protocol.rs:594-606`). Anyone who learns all the mailbox addresses derives the
same wallet and reads the group's entire protocol traffic. Those addresses are swapped by
hand, and a Zcash address is not normally handled as a secret.

**NEGATIVE RESULT — zkool does not build on this host.** Four attempts. Two were corrupted
crates in the local cargo registry. The real blocker is that `rustc 1.95.0`, the version
zkool pins and the only stable installed here, emits a `sqlx-macros` proc-macro dylib that
macOS 27's loader rejects with *mis-aligned LINKEDIT string pool*. Forcing the classic
linker did not help; Flutter is not installed. **Untried:** zkool ships a `flake.nix`, and
there is a Docker binary here with the daemon stopped. Recorded so it is not retried the
same way.

### The two risks, resolved

**R1 — Konclave is ahead: NO.** Zero hits for `keys::refresh`, `refresh_dkg`,
`refresh_share` across their whole repo, and nothing on the roadmap. What they call
recovery is re-importing an encrypted export the member still holds, whose precondition is
that the member kept it. Their own `docs/CLAIMS.md:118` concedes member-recovery and
inheritance are unshipped. Worse for them: `helper::derive_identity` is
**non-deterministic**, so a full threshold of shares mints a *new* address — full recovery
needs a server-side `registration.json` backed up out of band.

**R2 — zigner owns the air gap: CONFIRMED, and further along than assumed.** They already
ship the durable nonce ledger — sled-backed, fingerprinted, consumed *before* signing,
with a comment naming the force-quit replay attack (`signer/src/frost_multisig.rs:17-77`).
That was our gating milestone 2.

Two findings from their source worth sending upstream:

- **iOS and Android disagree about one nonce per action.** Android generates a fresh nonce
  per α (`FrostSignScreen.kt:393-414`); iOS generates one and reuses it across every α via
  `frost_spend_sign_actions` (`FrostSignView.swift:146-163`, `frost_multisig.rs:217-247`).
  Not the textbook key leak — the binding factor is computed over the *randomized*
  verifying key, so ρ differs per action, checked in frost-core 2.2.0 `round2.rs` — but
  outside the one-commitment-one-session assumption FROST is proved under.
- **iOS does no on-device verification.** Android recomputes the sighash from the PCZT and
  hard-fails on mismatch (`FrostSignScreen.kt:348-390`); the iOS FROST screens contain no
  PCZT reference at all. zigner's *solo* path does verify, so this is specific to FROST on
  one platform.

### Threat model

**CONFIRMED BY TEST, not inference.** §10 row "holder of `t` old shares" was right and is
now demonstrated. `t_old_shares_still_spend_after_a_refresh` refreshes a 2-of-3 twice, then
signs with two shares captured before either refresh, and the signature verifies under the
**current** group key. Refresh removes a seat from the group; it does not remove the money
from someone who already had enough seats. The security is entirely conditional on erasure,
which is an operations problem, not a cryptographic one.

**NEW — the coordinator, stated in frost-core's own words:**

> The coordinator can be one of the participants or a semi-trusted third party (who is
> trusted to not perform denial of service attacks, but does not learn any secret
> information).

It cannot spend, forge, or recover a share. It **can** stall forever, choose the signer
subset, and learn who signed what and when. On Zcash that last one is the product risk: a
group can shield its transactions from the world and remain fully legible to whoever runs
its sessions. Never say trustless. Say *the coordinator cannot spend your money.*

Also easy to miss: `frost-core` requires in capitals that you **MUST NOT** send the
identifier alongside a signature share — the coordinator must learn the sender from the
channel it arrived on. A transport that lets a share declare its own sender destroys
cheater detection.

### What this changes in the build order

| # | Was | Now |
|---|---|---|
| 1 | Session blob + state machine | unchanged |
| 2 | Nonce ledger — gates everything, novel | **narrowed.** zigner shipped a deny-list; ours is take-and-erase. Passing the replay test is table stakes, not a differentiator |
| 3 | Refresh and recovery | **two primitives, and the spike already passes.** Add a funded review: the surface is unaudited |
| 4 | QR transport | **be zigner's coordinator, do not rebuild its signer.** Send them the two iOS findings |
| 5 | DKG over the same transport | unchanged |
| 6 | ZIP 2005 joint `sk` | still unclaimed by every project read |

---

## 1. What FROST is

**F**lexible **R**ound-**O**ptimized **S**chnorr **T**hreshold signatures. RFC 9591.

One private key, cut into shares. No one ever holds the whole thing. Any `t` of `n` holders
cooperate to produce **a single signature** indistinguishable from a solo signer's.

The chain sees an ordinary transaction. It never learns a group exists.

### vs. script multisig (Bitcoin P2SH)

Script multisig publishes the policy, the keys, and every signature. On a transparent ledger
that's fine. On Zcash it hands an observer exactly the fingerprint the shielded pool exists to
destroy: this is a treasury, it has three officers, the same two signed last month.

Zcash *does* standardise transparent multisig — [ZIP 48](https://zips.z.cash/zip-0048) — but it's
Draft, [Zallet has no implementation](https://github.com/zcash/zallet/issues/872) (spending
explicitly out of scope), and it only ever works on t-addresses.

### vs. Safe (Ethereum)

**One line: Safe enforces the rule in a contract. FROST enforces it in the key.**

Safe is a smart contract wallet. Owners and threshold live on-chain; owners sign an EIP-712 hash
off-chain, signatures collect in Safe's Transaction Service, then anyone submits `execTransaction`
and **the contract verifies them**.

| | Safe | FROST |
|---|---|---|
| Where the rule lives | On-chain, in a contract | Nowhere — in how the key was split |
| Public sees | Owners, threshold, every signature, every config change | One signature. No sign a group exists |
| Cost of more owners | More gas per signature verified | Zero. Same transaction either way |
| Change the threshold | Yes, `changeThreshold` | **Never.** 2-of-3 is 2-of-3 forever |
| Add/remove a member | On-chain tx, public | Off-chain protocol run, private |
| Spending limits, timelocks, guards | Yes, programmable | None. A signature can't have logic |
| Lose too many keys | Recoverable via modules | Funds gone permanently |

Safe is better at almost everything — programmable, easier recovery, mutable rules, visible state.
All of that comes from being public. FROST trades every one of those for the single property Safe
cannot have: nobody knows it's a multisig.

**Practical reason it's FROST on Zcash: Zcash has no smart contracts.** There's nowhere to put a
Safe. Key-level is the only level available.

---

## 2. How it works, in numbers

### Splitting

A line needs two points. Draw one whose **y-intercept is the secret key**, hand each person a point.

```
secret key = 7                 line: y = 7 + 3x   (slope is random)

Alice   f(1) = 10
Bob     f(2) = 13
Carol   f(3) = 16
```

Any two determine the line and read off `7`. Any one holds a number consistent with a secret of
7, or 2, or four million.

A share is **not** a third of the key. Each is full-size; nobody holds "some of the digits".
Want 3-of-5? Use a parabola — needs three points. **The threshold is the degree of the curve.**

### Signing without ever reassembling

Recovering the secret is a *weighted sum*:

```
λ₁ = 2   λ₂ = −1        (Lagrange coefficients for positions {1,2})
2·10 + (−1)·13 = 7  ✓
```

Those coefficients depend only on *which positions signed*, so anyone can compute them. Because
`s = λ₁s₁ + λ₂s₂` is linear, it pushes through the signature equation `z = r + c·s`:

```
z = r + c·(λ₁s₁ + λ₂s₂)
  = (r₁ + c·λ₁s₁) + (r₂ + c·λ₂s₂)
     └── Alice ──┘   └─── Bob ───┘
```

With `r₁ = 5`, `r₂ = 9`, `c = 3`:

```
Alice:  z₁ = 5 + 3·2·10    =  65
Bob:    z₂ = 9 + 3·(−1)·13 = −30
                              ────
                       z   =   35

Check, if anyone HAD the key:  r + c·s = 14 + 3·7 = 35  ✓
```

Alice never learned 7. Bob never learned 7. Neither learned the combined nonce 14. The verifier
checks `g^z = R · PK^c` and passes — the number 35 doesn't remember how it was assembled.

This is also why the signer set must be **fixed before anyone signs**: `λ₁=2, λ₂=−1` is correct
*for positions 1 and 2*. Substitute Carol mid-protocol and the brackets sum to nothing.

### DKG — building the key with no dealer

Each participant invents their own secret and their own line, with no coordination:

```
Alice   f_A(x) = 4 + 1x       contribution: 4
Bob     f_B(x) = 2 + 5x       contribution: 2
Carol   f_C(x) = 1 + 2x       contribution: 1
```

Everyone evaluates their line at everyone's position and sends each person their point:

```
              → Alice(1)   → Bob(2)   → Carol(3)
Alice's line       5           6           7
Bob's line         7          12          17
Carol's line       3           5           7
                 ────        ────        ────
sum down:         15          23          31      ← the shares
```

Adding lines gives a line:

```
F(x) = (4+2+1) + (1+5+2)x = 7 + 8x

F(1)=15 ✓   F(2)=23 ✓   F(3)=31 ✓     group key = F(0) = 7
```

Recover it the usual way: `2·15 + (−1)·23 = 7` ✓ — but nobody ever does.

**Alice knows her own 4 and her share 15. Neither reveals 7.** She'd need Bob's 2 and Carol's 1.
The number 7 was never computed by any participant, on any machine, at any moment.

The slope `8 = 1+5+2` is three independent random choices, so no participant can predict or
steer the key.

**Two things the numbers leave out** (and why DKG is three rounds, not one):

1. **Coefficient commitments** — each broadcasts `g⁴`, `g¹` etc. so recipients can verify the
   point they got lies on the advertised line. The "verifiable" in VSS.
2. **Schnorr proof of knowledge** of one's own constant term. Without it, Carol could wait, read
   the others' commitments, and pick her contribution as a function of theirs to control the
   final key. That's the **rogue-key attack**.

---

## 3. Three properties that dictate any architecture

**P1 — Two nonces, not one.** The obvious one-nonce design is broken: an adversary controlling
`t−1` participants opens concurrent sessions, harvests commitments, and solves the ROS problem
via Wagner's generalised birthday attack. Earlier schemes patched it by banning concurrency.
FROST's fix is the **binding factor** `ρᵢ = H1(PK, msg, commitment_list, i)`, which welds each
response to one session. Two independent commitments give `ρ` something to entangle with.

**P2 — Nonce reuse is total key recovery.** Sign two messages with the same `(dᵢ, eᵢ)` and anyone
seeing both signatures recovers `sᵢ` by subtraction. RFC 9591 is blunt about it.
→ *"Resume after crash" and "retry, it timed out" are both, naively implemented, instructions to
replay round 1.* This must be structurally impossible, not discouraged by a comment.

**P3 — `t` is not "whoever shows up".** `λᵢ` is computed over the *specific* chosen subset. If a
selected signer drops out you don't fail over — you restart with fresh nonces. ZF docs: all
selected participants must produce their share even if more than `t` are available.

**Non-property:** the coordinator is untrusted for key material but fully trusted for *liveness*
and, on Zcash, for *privacy*. It learns who signed what. ZIP 312 says the role cannot be
eliminated. **Never say "trustless".** Say "the coordinator cannot spend your money" — that's true.

---

## 4. Zcash-specific constraints

### C1 — Re-randomization, and where α really comes from

Reusing one verifying key would link every transaction. [ZIP 312](https://zips.z.cash/zip-0312)
specifies **Re-Randomized FROST**: sign under `PK + g^α` with `sᵢ + α`. Works because `Σλᵢ = 1`.

Ciphersuites: `FROST(Pallas, BLAKE2b-512)` for Orchard/Ironwood, `FROST(Jubjub, BLAKE2b-512)`
for Sapling.

**The trap:** read the ZIP casually and you conclude the coordinator generates α at random. In an
isolated deployment it does. **In Zcash it doesn't get to.** The transaction builder already
committed to `rk = ak + [α]G` inside the shielded action, and consensus checks against *that*.
α is extracted from the half-built transaction and obeyed.

→ Use `Randomizer::from_scalar(alpha)`, **never** `Randomizer::new()`. Getting this wrong produces
a perfectly valid Schnorr signature that consensus rejects, because it verifies under the wrong key.

### C2 — One signature per action

Every action spending a note carries its own spend-auth signature over its own `rk` with its own α.
Spending four notes = **four independent FROST sessions in one transaction**. Every size and
latency number multiplies by a note count the user never chose and cannot see.

### C3 — Ironwood moved the target (28 July 2026)

Ironwood (NU6.3) activated, **sealing the Orchard pool** (~3.66M ZEC) and opening a new shielded
pool from zero with a turnstile. Trigger was an undisclosed bug in Orchard's proof circuit that
could have allowed undetectable counterfeiting. ~$80M crossed in on day one.

**Orchard is exit-only. Build Ironwood-first.** `pczt` 0.9 exposes `sign_ironwood`,
`apply_ironwood_signature`, `create_ironwood_proof` as first-class.

Good news: Ironwood keeps RedPallas spend-auth signatures, so ZIP 312 and every FROST crate apply
unchanged. [ZIP 2005](https://zips.z.cash/zip-2005) is explicit that RedDSA is *not* upgraded.

### C4 — Ironwood created an unsolved ceremony

ZIP 2005 introduces a quantum spending key `qsk`. Recovery-protocol spends need both a RedDSA
signature on `ak` **and** a proof of knowledge of `qsk`/`sk`. For threshold groups the ZIP states
participants **MUST privately agree on a value `sk`** and use it with `use_qsk = true` to derive
`nk`, `qsk`, `qk`, `rivk_ext`.

So an Ironwood FROST group needs a shared secret agreed **outside** standard FROST DKG.
**No implementation exists anywhere.** Zkool has no reference to `qsk` (grepped across rust/src).
Genuinely unclaimed territory.

---

## 5. Zkool teardown (the incumbent)

[hhanh00/zkool2](https://github.com/hhanh00/zkool2) — successor to Ywallet. Flutter + Rust, DKG
and signing built in, Ledger, Tor, Ironwood. **First mainnet FROST transaction on Zcash** was
signed with it at a Zcash Brasil workshop, June 2025.

Read at v6.31.0, commit `4552fe9`. Source read, not run.

### The defining decision: the blockchain IS the message bus

Every FROST package is an encrypted memo inside a real shielded transaction.

1. **Mailboxes** — each wallet derives a hidden account for protocol messages only
   (`protocol.rs:499`). Participants swap mailbox addresses by hand. The one manual step.
2. **Shared address from nothing** — every wallet computes
   `BLAKE2b("Zcash__FROST_DKG", mailbox addresses)` (`protocol.rs:594`). Same input, same output,
   so everyone lands on the same address with no server and no registry.
3. **DKG, one block at a time** — three rounds. Each builds a real transaction whose zero-value
   outputs carry the package in their memos (`protocol.rs:439`). Everyone waits for the block,
   syncs, decrypts. Driven by a `new_block` handler (`graphql/frost.rs:54`).
4. **Signing, same pattern** — three more rounds, three more transactions, three more blocks.

**Why it's clever:** note encryption already gives encryption, authentication and delivery. No
relay to run, nothing to censor, nobody to trust with metadata. Most Zcash-native answer possible.

**Why it hurts:** every round is now a transaction.

### Five consequences

| ID | Finding | Evidence |
|----|---------|----------|
| **Z1** | ~6 on-chain transactions per person per signature. Rounds serialise on *change confirmation* — round k+1 can't be funded until round k's change is mined. | `dkg/plan.rs:28`; `dkg/step.rs` `waiting_for_funds` |
| **Z2** | **You must already own ZEC to join a multisig.** Every message is a fee-paying tx. Excludes exactly the cosigners you want — auditor, counsel, the relative holding a recovery share. | architecture |
| **Z3** | Every round waits for all `n`, never `t`. Correct for DKG, but makes setup a synchronous scheduled ceremony. | `dkg/plan.rs:33` |
| **Z4** | Memos are 512 bytes with **no chunking** — oversized payloads hard-fail. **MEASURED (§0.5): the ceiling is `t=3`**, which clears 512 by 19 bytes; `t=4` needs 594. UI caps at 5. | `pay/plan.rs:1275`, measured |
| **Z5** | Authentication is optional — verifier returns `true` when no signature present, for backward compat. | `sign.rs:148–151` |

At a 75-second block target, the workshop announcement literally scheduled an AMA to fill the
"downtime waiting for block confirmations".

### Two things that aren't there

- **No share refresh, recovery or rotation.** Grepping the FROST module for
  `refresh|recover|rotate` returns one hit — a comment about crash recovery in the DKG planner.
- **No ZIP 2005 quantum key agreement.**

### Verdict

Zkool proved the cryptography works in a consumer app, on mainnet, with real users. That's the
hard part and it's done — don't redo it, and say so publicly.

What's unsolved is the product: setup is a scheduled ceremony, signing is a multi-block wait,
joining requires holding the asset, and losing a device means losing the group. The first three
fall out of changing one arrow. **The fourth is worth building a company around.**

---

## 6. The field

| Project | Shape | Transport | Proven | Recovery? |
|---|---|---|---|---|
| **Zkool** (hhanh00) | Consumer wallet, Flutter+Rust | On-chain memos | Mainnet | ❌ None — zero grep hits |
| **Konclave** (deegalabs) | Browser treasury, Tauri | Loopback + blind relay | Mainnet, 19 tx | ❌ Listed *in progress* |
| **Quorum** (Fatihmaull) | Org custody, Next.js+Postgres | `frostd` relay | Ironwood testnet | ❌ Not mentioned |
| **zigner** (rotkonetworks) | Air-gapped phone signer | Animated UR QR | Released | ❌ Encrypted backups only |
| **zec-multisig** (zyn-io) | Rust library | n/a | Mainnet (README) | ❌ Dormant repo |
| **ZF frost-tools** | Reference CLI + relay | HTTPS relay | Audited | ⚠️ Primitive only, no UI |

**Read the last column.** Every project has solved key generation and signing. Not one has
shipped recovery. Konclave knows it's the gap — validation, and a clock.

### Rejected grant applications — the pattern matters

| Application | Ask | Outcome | Stated reason |
|---|---|---|---|
| TSSK — Creatives Onchain | $25,000 | Declined 2025-11-24 | ZF frost-tools already covered it; no wallet outreach plan |
| FROST Multi-Sig SDK — mahmudsudo | $22,000 | Declined 2026-07-21 | Same shape: SDK wrapping frost-core, no users attached |
| Zcash SeedSigner — Biglup Labs | $65,000 | Declined | DIY air-gapped PCZT signer; contained no FROST at all |

**"A Rust SDK wrapping frost-core" is a dead proposal.** Lead with what a person can do, never
with what the library exposes.

---

## 7. The product

> **A signing session is a file. Move it however you want — and make losing a device a
> ten-second recovery, not a migration.**

### Two decisions, everything follows

**D1 — Transport off the chain.** The session travels as one sealed blob over whatever channel the
group already has: QR, AirDrop, Signal, email, or an optional relay that sees only ciphertext.
The chain is for settlement, not coordination. Turns a multi-block wait costing a fee per
participant into two QR scans costing nothing, and removes the need to hold ZEC to cosign.

**D2 — Recovery as a first-class flow.** `frost-core` 2.2.0 shipped `keys::refresh` in Aug 2025.
Audited, and unused by every Zcash wallet for over a year.

### Who it's for

1. **Small treasuries** — company, DAO working group, grant recipient. Need 2-of-3, need an
   auditor who can cosign without holding funds, and they turn over staff.
2. **Families / inheritance** — where a share holder genuinely *will* become unavailable.
3. **Individuals splitting their own key** — phone + laptop + a share at a relative's. Here a lost
   device is a certainty, not a risk.

### Acceptance test — one continuous take, four minutes

```
1.  Three laptops. Create a 2-of-3 group.          < 3 min, nobody holds ZEC
2.  Fund the group address.                        one ordinary send
3.  Sign a spend: two people scan, done.           < 60 s
4.  Put laptop #3 in a drawer. It is gone.         ← nobody else can film this
5.  Remaining two recover onto a new device.       same address, funds never moved
6.  Sign again using the recovered share.          proves the new share is real
7.  Block explorer: every spend looks exactly      the privacy claim,
    like a single-signer transaction.              demonstrated not asserted
```

---

## 8. Architecture

**Governing rule: we write zero cryptography.** Every audited primitive exists in a crate. We
write state, transport and interface. The discipline is noticing when something we're about to
write is really crypto in disguise.

### Dependencies (versions verified against Zkool's Cargo.lock)

| Layer | Crate | Why |
|---|---|---|
| Threshold core | `frost-core 3.0.0` | RFC 9591. Ships `keys::dkg`, `keys::refresh`, `keys::repairable`. **Not audited** — see §0.5 |
| Re-randomization | `frost-rerandomized 3.0.0` | ZIP 312. `Randomizer::from_scalar` — the one we need. Note the `sign` deprecation, §0.5 |
| Ciphersuite | `reddsa 0.5.2` (feature `frost`) | RedPallas / `PallasBlake2b512`. **0.5.2, not 0.5.1** — it enforces Orchard's even-y constraint for you (§0.5) |
| Transaction | `pczt 0.9.2` | Models multi-party construction. Ironwood-aware. `SpendAuthSignature` |
| Chain access | `librustzcash` + lightwalletd | **Coordinator only.** Signers never touch it |
| Blob sealing | XChaCha20-Poly1305 + Argon2id | Boring and correct |
| Peer auth | ed25519-dalek | Mandatory on every message. No unsigned path |
| QR | Animated UR, fountain-coded | zigner + PCZT hardware ecosystem already speak it |

**The gift in pczt 0.9:** `pczt::roles::signer::SpendAuthSignature` exists for exactly our shape —
its own docs say it "can be used by external signers that return signatures separately from a
PCZT", tagged with `value_pool` and `action_index`. We're using the designed path, not fighting
the format.

### Components

```
Coordinator  ──blob──▶  Transport  ──blob──▶  Signers (t of n)
  builds + redacts PCZT   QR / file / relay     run pczt Verifier, read α
  fixes the signer subset ciphertext only       show the human sentence
  aggregates·proves·sends                       hold one KeyPackage each
  HOLDS NO KEY SHARE                            NEED ZERO ZEC, never touch chain
       │
       ▼  finished transaction only
  Zcash (Ironwood)
```

### PCZT role pipeline — who runs what, in order

| Roles | Who |
|---|---|
| `Creator → Constructor → IoFinalizer → Redactor` | coordinator |
| `Verifier → low_level_signer` (read α only) | each signer — **never mutates** |
| `Signer::apply_ironwood_signature` × k | coordinator, after aggregation |
| `Prover → SpendFinalizer → TransactionExtractor` | coordinator |

Signers never call a mutating role. The only bytes they return are 64-byte signature shares.

### Durable state

```rust
Group {                              // long-lived
  group_id:       [u8; 32],          // hash of the PublicKeyPackage
  key_package:    KeyPackage<P>,     // OUR share. sealed at rest.
  public_package: PublicKeyPackage<P>,
  identifier:     Identifier<P>,
  min_signers:    u16,               // immutable — see recovery
  members:        Vec<MemberRecord>, // id, label, ed25519 verifying key
  epoch:          u32,               // incremented by every refresh
  address:        UnifiedAddress,    // Ironwood receiver only
}

NonceRecord { session_id, action_idx, state: NonceState }   // safety-critical
SessionRecord { session_id, group_id, epoch, state, signer_set, transcript }
```

`epoch` is load-bearing: a refresh bumps it, every message carries it, and a stale-epoch blob is
rejected rather than silently mixed with post-refresh shares.

### Session blob (the wire format)

```rust
SessionBlob {
  version:    u8,
  group_id:   [u8; 32],
  epoch:      u32,                  // must equal our Group.epoch
  session_id: [u8; 32],             // random; binds the whole run
  round:      Round,                // Commit | Sign | Shares
  pczt:       Vec<u8>,              // redacted for signers
  signer_set: Vec<Identifier>,      // immutable after round 1
  actions: Vec<ActionSlot> {        // k parallel sub-sessions — C2
    action_index: u32,
    value_pool:   ValuePool,        // Ironwood | Orchard
    alpha:        [u8; 32],         // read from the PCZT, never invented
    commitments:  BTreeMap<Identifier, SigningCommitments>,
    signing_pkg:  Option<SigningPackage>,
    shares:       BTreeMap<Identifier, SignatureShare>,
  },
  transcript: [u8; 32],             // chains every prior message
  from:       Identifier,
  signature:  [u8; 64],             // ed25519. ALWAYS verified.
}
```

**Resumable** — the blob is the state, so any participant can be handed it and continue.
**Transport-agnostic** — QR, file, relay and email are one code path.
The `transcript` is a rolling BLAKE2b that each party checks extends the one it holds — stops a
malicious coordinator showing different signers different histories of the same session.

### State machine

```
Draft → Committing → Signing → Aggregating → Proving → Sent
             │           │
             │           └─ durable: nonce → Consumed, BYTES ERASED
             │                       (same txn as producing the share)
             └───────────── durable: nonce → Unconsumed
                                     (BEFORE the commitment leaves)

  ↓ dropout · timeout · bad signature · wrong epoch
Aborted   ← terminal. Consumed nonces stay consumed.
            Retry = NEW session_id, fresh nonces.
```

**There is deliberately no edge from `Aborted` back into the protocol.**

### The nonce ledger (P2 defence)

```rust
enum NonceState { Unconsumed(SigningNonces<P>), Consumed }

// The ONLY accessor. Takes nonces by value out of the store and writes
// Consumed in the same database transaction, so a second call has nothing
// to return — the bytes are gone, not merely flagged.
fn take_for_signing(&mut self, session: SessionId, action: u32)
    -> Result<SigningNonces<P>, TakeError>

enum TakeError {
    AlreadyConsumed,   // → abort the session, do not sign
    NotFound,          // → we never committed; abort
}
```

Ordering is the whole thing. `Unconsumed` is written **before** the round-1 commitment reaches the
transport, so a crash between write and send is safe. `Consumed` is written **in the same
transaction** that produces the share, so a crash after signing cannot resurrect the nonce.

> **Test that gates every other milestone:** drive a full session, kill the process after round 1,
> restart, replay the same blob. It passes only if the second run **refuses**. If it signs, we
> have shipped the key-recovery bug and nothing else matters.

### Signing path, end to end

```rust
// ── coordinator: build and dispatch ──────────────────────────────
// 1. Build with librustzcash → PCZT.  Creator → Constructor → IoFinalizer.

// 2. Enumerate what needs signing.
let sighash = Signer::new(pczt.clone())?.shielded_sighash();

// 3. Read α per action WITHOUT mutating the PCZT.
let alphas = LowLevelSigner::new(pczt.clone())
    .sign_ironwood_with(|_pczt, bundle, _| {
        // bundle.actions()[i].spend().alpha()  → one scalar per action
        Ok::<_, OrchardParseError>(())
    })?;

// 4. Redact before it goes near a signer.
let for_signers = Redactor::new(pczt.clone())
    .redact_global_with(|r| r.clear_proprietary())
    .finish();

// ── signer: round 2 ──────────────────────────────────────────────
// MANDATORY FIRST. The low_level_signer docs state callers relying on wire
// `fvk` bytes MUST have run full Verifier checks over the identical PCZT
// bytes. The signing parse skips FVK derivation and hands you `fvk: None`.
// Skipping this is signing a transaction you have not read.
Verifier::new(pczt.clone()).check_all()?;

let nonces     = ledger.take_for_signing(session_id, action_idx)?;
let randomizer = Randomizer::<P>::from_scalar(alpha);   // NOT ::new()
let share      = frost_rerandomized::sign(
    &signing_package, &nonces, &group.key_package, randomizer,
)?;

// ── coordinator: aggregate and finish ────────────────────────────
let params = RandomizedParams::from_randomizer(
    group.public_package.verifying_key(), randomizer,
);
let sig = frost_rerandomized::aggregate(
    &signing_package, &shares, &group.public_package, &params,
)?;
signer.apply_ironwood_signature(action_index, sig.serialize().try_into()?)?;
// Prover → SpendFinalizer → TransactionExtractor → broadcast.
```

**Two ways to get this wrong:**
1. Calling `Randomizer::new()` — generates a fresh random scalar. Right for isolated FROST,
   consensus-invalid here.
2. Skipping the `Verifier` on the signer — the signing parse deliberately skips FVK derivation
   and hands the closure `fvk: None`. A signer trusting unverified PCZT bytes is approving a
   transaction it hasn't checked, which defeats the point of being a cosigner.

---

## 9. Recovery — how `refresh` actually works

> **Read §0.5 first.** Refresh is only half of recovery. It rotates a seat; it cannot
> issue one. `keys::repairable` rebuilds a lost share, and must run before this.
> The rest of this section, on what refresh itself does, is correct.

**Read from `frost-core/src/keys/refresh.rs`, not inferred.**

Refresh does not build a new polynomial from the secret. It generates a sharing of **zero** —
`SigningKey { scalar: Field::zero() }` with fresh random coefficients — and adds those shares to
the existing ones. Since the added polynomial evaluates to 0 at the origin, the group secret is
unchanged, and the code copies the verifying key across verbatim in **both** the dealer and DKG
paths:

```rust
let refreshing_key = SigningKey { scalar: Field::zero() };
// ... shares of zero are generated and added to the old shares ...
let refreshed_pub_key_package = PublicKeyPackage {
    verifying_shares: refreshed_verifying_shares,
    verifying_key: pub_key_package.verifying_key,     // ← UNCHANGED
};
```

```
BEFORE (epoch n)          add a sharing of ZERO        AFTER (epoch n+1)
polynomial f              z(0) = 0                     A: s₁′
A: s₁ = f(1)              sᵢ′ = sᵢ + z(i)              B: s₂′
B: s₂ = f(2)              so (f+z)(0) = ask still      D: s₃′  ← new device
C: s₃ = f(3) ← lost       no chain interaction         old s₃ no longer combines
f(0) = ask

Unchanged: group key PK · group address · every note · every balance. ZERO transactions.
```

### Three constraints verified in the source

- ✅ `max_signers` **MAY shrink** → removing a member is supported.
- ❌ `min_signers` **MUST equal the original** → **the threshold can NEVER change.**
  2-of-3 stays 2-of-3 for the life of the group.
- ⚠️ **Refresh gives no security unless old shares are destroyed.** `t` surviving *old* shares
  still reconstruct `ask` after any number of refreshes. ZF documents that refreshing "does not
  restore full security" and that removed participants colluding with current ones using old
  shares remain a threat.

### The API, in order

| Step | Call | Who |
|---|---|---|
| 1 | `refresh_dkg_part_1(identifier, max_signers, min_signers, rng)` | each surviving member |
| 2 | `refresh_dkg_part2(secret_pkg, round1_packages)` | each surviving member |
| 3 | `refresh_dkg_shares(round2_secret, r1_pkgs, r2_pkgs, old_pub_pkg, old_key_pkg)` | each surviving member |
| 4 | **overwrite `Group.key_package`, ERASE the old one, bump `epoch`** | each surviving member |

Step 4 is ours and it is not bookkeeping. Overwrite in place, never keep a pre-refresh backup —
and that decision must survive every future request for "undo".

### Two flows, never one button

| | Device lost | Share compromised |
|---|---|---|
| Threat | Nobody has the old share | Someone might, or does |
| Action | Refresh in place | Refresh **and** migrate to a new group |
| Address | ✅ Unchanged | ❌ New — funds must move on-chain |
| Cost | ✅ Zero, no transaction | ❌ One shielded tx + fee |
| Honest because | Attacker with 1 old share and 0 new is below threshold | Attacker with 1 old share needs only one more old share, ever |

The recovery screen asks one question first: *was the device lost, or could someone else have it?*
**Competitors shipping a single "recover" button will be quietly wrong for half their users.**

---

## 10. Threat model

| Adversary | Can | Cannot | Mitigation |
|---|---|---|---|
| Coordinator | Stall; choose the signer subset; learn who signed what | Spend; forge; recover a share | Accepted + documented. Any member can coordinate |
| Relay | Drop/delay; see blob sizes and timing | Read contents; forge | Sealed blobs; mandatory ed25519; relay optional |
| Network observer | See a shielded tx exists | Distinguish from a solo spend | Inherent to FROST + ZIP 312 |
| `t−1` members | Open concurrent sessions; refuse to sign | Forge a signature | FROST binding factor (P1) |
| `t` members | **Spend everything** | — | None possible. That's the threshold |
| Holder of `t` **old** shares | **Reconstruct `ask` after any number of refreshes** | — | Mandatory erasure on refresh; compromised-flow migration |
| Stolen signer device | Read one share if storage unsealed | Sign alone | Argon2id + XChaCha20-Poly1305; OS keystore |

## 11. Failure handling

| Failure | Response |
|---|---|
| Signer drops out mid-session | `Aborted`. New session, new id, fresh nonces, possibly different subset (P3) |
| Blob arrives twice | Idempotent by `(session_id, round, from)`. Identical bytes = no-op; differing bytes = abort |
| Blob from an old epoch | Rejected before parsing. Prevents mixing pre-/post-refresh shares |
| Bad or missing ed25519 signature | Rejected. No compatibility path — the mistake in Z5 |
| Transcript doesn't extend ours | Abort and surface. The equivocating-coordinator case |
| Aggregate fails to verify | Coordinator checks against `rk` **before** proving. Bad share identified, not broadcast |
| Crash after round 1 | Resume reads `Consumed`, refuses, aborts. Costs one wasted round; cannot leak a key |
| Broadcast fails after signing | Transaction is complete and retryable as bytes. No re-signing, so no new nonces |

## 12. Deliberate simplifications

- **Trusted dealer before DKG.** DKG is three more rounds of transport. Dealer mode is a supported
  `frost-core` path; ships first. The recovery story is identical either way.
- **Ironwood only.** No Sapling, no transparent, Orchard read-only at most.
- **One session at a time per group.** FROST is safe concurrently (P1), but serialising removes a
  class of state bug for zero user-visible cost at these group sizes.
- **No blob compression.** Only matters for QR payload size; revisit when measured as too slow.

---

## 13. Build order

| # | Deliverable | Done when |
|---|---|---|
| 1 | Session blob + state machine. 2-of-3 Ironwood spend passing files between three processes, trusted-dealer keys, no relay, no on-chain messages | Testnet spend confirmed. Wall-clock recorded against the same spend in Zkool |
| 2 | **Nonce ledger** (§8) | Kill-after-round-1 replay test **refuses** to sign. Gates everything downstream |
| 3 | **Refresh and recovery.** Both flows, mandatory old-share erasure | Destroy a share, refresh, spend again with the replacement. Same address, funds never moved, old share proven not to combine |
| 4 | QR / UR transport + signing screen on a phone | Air-gapped phone signs using only camera and screen |
| 5 | DKG over the same transport | Three devices in a room, group in under five minutes, nobody holding ZEC |
| 6 | ZIP 2005 joint `sk` agreement (C4) | A threshold group with working Ironwood quantum recoverability |

Milestone 2 sits ahead of everything user-visible on purpose — it's the one bug class that ends
the project, and far cheaper to design in than retrofit.

Ship 1–3 and we have something no Zcash wallet has. Ship 4–5 and it's usable outside the forum.
Milestone 6 is research — highest risk, only genuinely unclaimed item.

---

## 14. Risks

**R1 — RESOLVED, they are not ahead (§0.5).** *Original text below, kept for the record.*

**R1 — Konclave is ahead and knows about the gap.** 19 mainnet transactions, released Tauri app,
browser-WASM DKG, social recovery on their roadmap. Milestone 1 is a better version of something
they have working; milestone 3 is a race against a head start.
*Mitigation:* read their repo before writing a line. If their recovery is close, build the piece
they aren't — the lost-vs-compromised distinction, or C4.

**R2 — CONFIRMED and stronger than assumed (§0.5): they already shipped the nonce ledger.**
*Original text below, kept for the record.*

**R2 — zigner owns the air gap.** QR FROST DKG and signing on an offline phone, no relay in the
crypto path, actively released. Milestone 4 overlaps almost exactly.
*Mitigation:* don't compete. Speak their UR encoding and let zigner be a supported signer. More
compatible signers is strictly better; a second signer app is strictly redundant.

**R3 — A better transport is a pull request, not a moat.** hhanh00 ships fast and Zkool has users.
If off-chain transport were the whole idea, it lands in Zkool and we built a feature.
*Mitigation:* exactly why recovery leads and transport follows.

**R4 — The market might be smaller than the engineering.** Nobody has published how many Zcash
threshold groups exist. Could be dozens, and serious infrastructure for dozens is a hobby.
*Mitigation:* find out before milestone 4. Ask the forum, ask ZF, ask the Zkool workshop
attendees. A negative answer is a real answer and much cheaper now.

### Open decision

**Standalone wallet, or a signing-and-recovery layer that plugs into Zkool, Konclave and Zashi?**

Recommendation: **the layer.** The architecture is already built for it — the signer never touches
the chain, never syncs, never manages notes. A standalone wallet means building all of that: 90%
of the work, 0% of the novelty, and a feature race with a wallet two years ahead. A layer competes
with nobody, and every wallet becomes a distribution channel.

---

## 15. Verification notes

*Updated after the second pass, 2026-09-30.*

### Ran, and passed
- **20 tests, 1,074 lines** (`scratchpad/frost-spike`) against `orchard 0.15.5`,
  `frost-core 3.0.0`, `frost-rerandomized 3.0.0`, `reddsa 0.5.2`, on Pallas — the curve
  Zcash spend-authorization signatures actually live on.
- Both attacks are **carried out**, not described: nonce reuse recovers the exact private
  key; the rogue-key attack hijacks the group key and the proof of knowledge blocks it.
- The memo ceiling is **measured** by serializing real signing packages at each threshold.
- The old-shares threat is **demonstrated**: two pre-refresh shares sign, and the result
  verifies under the current group key.
- A FROST group key is **built into a real Orchard viewing key** and an address derived
  from it; flipping the sign bit makes the same key unparseable.

### Read directly at the source
- `frost-core` 0.6.0, 2.2.0 and 3.0.0; `frost-rerandomized` 3.0.0; `reddsa` 0.5.1 and
  0.5.2; `orchard` 0.15.5; `pczt`. Downloaded from crates.io and read.
- zkool2 at commit `4552fe9`, Konclave at `afca23bc`, zigner at `5fdb768c`. Every
  `file:line` citation in this document was opened.
- The audit scope was fetched from the ZcashFoundation/frost README, not quoted from
  another project's summary of it.
- RFC 9591, ZIP 312, ZIP 2005, ZIP 48.

### NOT done
- **No transaction was signed on any network.** No testnet spend, nothing timed. Every
  latency figure is structural, derived from round count × block target, not a stopwatch.
- **zkool was never launched.** Four build attempts failed on host toolchain defects and
  none reached zkool's own code (§0.5). Flutter is not installed.
- The spike signs a stand-in message, **not a real shielded sighash from a PCZT**. Wiring
  it to `pczt` is milestone 1, and is where the argument lists will shift.
- The ROS/Wagner attack is stated, not executed. The binding factor's mechanism is
  demonstrated; the attack it defends against is not.
- zkool's broadcast-before-commit window is read from source, with **no crash staged** to
  open it.
- **R4 is still open.** Nobody has been asked how many Zcash threshold groups exist.

### Superseded
The first pass's §15 said "nothing was run" and left the 512-byte ceiling, the recovery
flow and the audit scope unverified. All three are now settled and appear in §0.5.

### Correction carried forward
An earlier pass repeated the Zcash Foundation's May 2025 statement that no wallets integrate FROST.
True when written, **false now** — Zkool shipped it, Konclave is on mainnet, two more are close.
**Treat any research on this topic dated before mid-2025 as describing a different landscape.**

---

## 16. Sources

**Protocol**
- [RFC 9591 — FROST](https://www.rfc-editor.org/rfc/rfc9591.html)
- [Komlo & Goldberg, FROST (ePrint 2020/852)](https://eprint.iacr.org/2020/852.pdf)
- [The ZF FROST Book](https://frost.zfnd.org/frost.html)

**ZIPs**
- [ZIP 312 — FROST for Spend Authorization](https://zips.z.cash/zip-0312)
- [ZIP 2005 — Ironwood Quantum Recoverability](https://zips.z.cash/zip-2005)
- [ZIP 48 — Transparent Multisig Wallets](https://zips.z.cash/zip-0048)
- [zips #693 — offline shielded transactions (PCZT)](https://github.com/zcash/zips/issues/693)

**Crates / docs**
- [ZcashFoundation/frost](https://github.com/ZcashFoundation/frost)
- [frost-core keys::refresh](https://docs.rs/frost-core/latest/frost_core/keys/refresh/index.html)
- [frost-core keys::dkg](https://docs.rs/frost-core/latest/frost_core/keys/dkg/index.html)
- [pczt](https://docs.rs/pczt/latest/pczt/)

**Projects**
- [hhanh00/zkool2](https://github.com/hhanh00/zkool2)
- [deegalabs/konclave](https://github.com/deegalabs/konclave)
- [Fatihmaull/zcash-multisig (Quorum)](https://github.com/Fatihmaull/zcash-multisig)
- [rotkonetworks/zigner](https://github.com/rotkonetworks/zigner)
- [zyn-io/zec-multisig](https://github.com/zyn-io/zec-multisig)
- [zallet #872 — ZIP 48 accounts](https://github.com/zcash/zallet/issues/872)

**Ecosystem**
- [ZF — The State of FROST for Zcash](https://zfnd.org/the-state-of-frost-for-zcash/)
- [FROST support in zcash-devtool](https://forum.zcashcommunity.com/t/hackmas-frost-support-in-zcash-devtool/54586)
- [Zkool multisig workshop](https://forum.zcashcommunity.com/t/multisig-with-zkool-workshop/51323)
- [Ywallet FROST demo](https://frost.zfnd.org/zcash/ywallet-demo.html)
- [TSSK grant (declined)](https://forum.zcashcommunity.com/t/threshold-shielded-signing-kit-tssk-frost-powered-multisig-for-zcash/52937)
- [FROST SDK grant (declined)](https://forum.zcashcommunity.com/t/frost-shielded-multi-sig-sdk-easy-threshold-custody-for-zcash-wallets-grant-application/56608)
- [Zcash SeedSigner grant (declined)](https://github.com/ZcashCommunityGrants/zcashcommunitygrants/issues/411)
