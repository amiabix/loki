# Loki Security Brief — Demo Stage

Status: **DEMO / TEST-NETWORK ONLY. NOT FOR REAL FUNDS.**
Audience: a decision-maker who is not a cryptographer and needs to know what is
proven, what is still dangerous, and exactly what to arrange before any mainnet
money is at risk.

Scope of this brief: the round-2 signer work (`poc/src/signer/` +
`poc/src/coordinator_boundary.rs`), audited against the threat model
(`00-architecture.md` §5) and invariants (§7), `ws1-signer.md`, and
`ws6-standards-and-audit.md`. The companion `pr2/coordinator-demo` branch exists,
but its end-to-end coordination loop has not been reviewed here.

Verification note: this review reproduced a plaintext DKG share leak in the signer
test, then reran the test and the library suite after moving round-two sealing
inside the signer. These tests do not establish production custody safety.

---

## 1. What the demo proves

The demo separates the secret-holding signer from the coordinator. The DKG
round-two boundary required a fix: it previously returned plaintext share packages.

- **No spend key in the coordinator.** The coordinator (the part that would be a web
  app) talks to a member only through one narrow trait, `Signer`
  (`poc/src/signer/mod.rs`). Round one is signed, and round two is encrypted to its
  intended member before the coordinator sees it (`local.rs`). The type guard
  (`known_signer_return_types_are_public_artifacts`) checks named return types but
  cannot inspect `Vec<u8>` contents or detect an unlisted new trait method. The
  coordinator source deny-list checks one file, not the whole process.
- **Audited FROST crypto.** The threshold math is the ZF `frost-rerandomized` /
  `reddsa` RedPallas stack (`ADOPTION.md` §1–2, 4); Loki writes the signer shell, not
  new threshold crypto. The partial signature is produced by
  `frost_rerandomized::sign_with_randomizer_seed` (`poc/src/signer/nonce.rs`).
- **Each member approves the real transaction on their own signer.** Before any share
  is touched, the signer independently parses the PCZT, renders what it actually pays,
  and recomputes the exact bytes being signed (`poc/src/signer/local.rs`
  `sign_approve`; `poc/src/signer/wysiwys.rs` `describe_pczt` + `sighash_of_pczt`).

---

## 2. Safe by design — invariants genuinely upheld, with evidence

| Invariant (§7) | Upheld? | Evidence |
|---|---|---|
| #1 No key in the browser/coordinator | **Partial** | `LocalSigner::dkg_step` now signs round one and encrypts round-two shares to a preapproved roster. The opaque-byte trait and one-file deny-list do not prove the whole coordinator stays keyless. |
| #3 Confirm on the signer (WYSIWYS) | **Yes — the round-1 BLOCKER is closed** | `sign_approve` recomputes the sighash from the same bytes it rendered and **refuses with `SighashMismatch` before the nonce/share is touched** if `pkg.message()` differs. Test `sign_approve_binds_package_message_to_rendered_sighash` proves a tampered package is refused *and* the nonce stays `Committed`. |
| #4 Only public data crosses the boundary | **Partial** | The coordinator receives encrypted DKG shares and a viewing key. The viewing key does not authorize spends, but reveals wallet activity and needs a separate privacy review. |
| #5 Audited crypto only | **Yes** | FROST math is `frost-rerandomized`/`reddsa`; `nonce.rs` calls the audited signer, no bespoke threshold code. |
| Nonce single-use + crash-safety | **Yes (in `nonce.rs`)** | Persist-before-emit (round 1), atomic burn-before-nonce-removal with fsync (round 2), reuse-for-different-message hard-refused. Tests `crash_after_burn_leaves_no_stranded_or_duplicated_nonce` and `reuse_for_a_different_message_is_hard_refused` (`nonce.rs`). |
| Share born in the signer (DKG) | **Partially** | `dkg_step` seals the resulting share and encrypts each outbound round-two package inside the signer. The signer now requires a signed `AcceptedCeremonyRoster` and checks its vault, policy, network, and own identity. Human roster review, backup/restore, and epoch reset still need work. |

The signer rejects a signing package whose message differs from its recomputed
transaction hash. The simulated approval callback and unreviewed coordinator loop
limit what this demo establishes about a malicious coordinator.

---

## 3. NOT safe for real funds yet — each gap and why it is dangerous

- **Software KEK (share-at-rest).** `SoftwareSecureElement` holds the wrapping key in
  process memory and even exposes `from_kek` to reconstruct it
  (`poc/src/signer/secure_element.rs`). A stolen/imaged device yields the share — the
  at-rest protection is only as strong as file permissions until a real Secure Enclave
  / StrongBox / TPM backend replaces it. This defeats threat **A3 (stolen device)**.
- **No biometric / no human unlock gate.** Approval is a code callback
  (`ApprovalPolicy = FnMut(&PaymentView) -> bool`) and `connect` takes no biometric
  (`local.rs`). The "member approves on device" step is simulated; there is no actual
  Face/Touch-ID or passphrase gating a real unlock. Anyone with the running process can
  auto-approve.
- **WYSIWYS fee binding has an untested negative path.** The fee is only marked
  `fee_verified` when every action's declared value binds to its `cv_net` commitment
  (`wysiwys.rs`). By the author's own honest caveat, the `fee_verified == false` branch
  is **not reachable through the public builder** (every built action carries `rcv`, and
  the spend value/`rcv` fields are crate-private), so a forged-fee PCZT cannot be
  exercised end-to-end from a test. The guard is defensive but **unproven against a real
  adversarial PCZT**. Dangerous: a fee/value substitution path could exist that the test
  suite cannot currently reach.
- **Human DKG roster review is not proven.** `for_dkg` now requires the signed
  `AcceptedCeremonyRoster` and rejects mismatched vault or signer metadata. The
  setup agreement proves the listed keys voted; a trusted signer-side workflow must
  still show the fingerprint and bind each peer key to its intended person. A member
  who approves attacker-controlled peer keys can send decryptable shares to them.
- **DKG: no backup/restore, no epoch reset proven.** `dkg_step` generates and seals the
  share, but this round does not demonstrate backup, restore-to-new-device, or the
  nonce-epoch reset on restore that `ws1-signer.md` §8 requires. A real custody flow must
  recover a share without replaying an old nonce; that is not shown here.
- **No end-to-end coordination / broadcast proven.** The `pr2/coordinator-demo` branch
  exists but has not been reviewed here; there is no reviewed 2-of-3 testnet payment
  that aggregates partials, applies them to a PCZT, and broadcasts (ws1 §11
  acceptance #6). The signer half is proven in isolation only.
- **No external security audit yet.** All assurances above are self-review + Loki's own
  tests. The highest-value target (the signer shell) has not been looked at by an
  independent auditor (`ws6` §3).
- **No reproducible / independently delivered builds.** A targeted malicious signer build
  is currently undetectable (threat **A5, supply chain**). `ws6` §4 requires reproducible
  builds, published hashes, and per-pair independent delivery — none exist yet.
- **Test-network only, and there is no mainnet-refuse *guard*, there is simply no mainnet
  path.** The `Network` enum has only `Regtest` and `Testnet` (`mod.rs`); `connect`
  rejects a network mismatch. That is honest (no mainnet can be selected) but it is the
  *absence* of a feature, not an audited refuse-guard. Before any mainnet variant is
  added, an explicit, tested refuse-until-all-checks-pass guard must exist (§4).
- **#1094 FVK derivation is unreviewed upstream.** The vault viewing key uses
  `zip2005.rs` (`use_qsk`), which is cross-checked against vectors but **not yet reviewed
  by ZF** (`ADOPTION.md` §3, `ws6` §2). An error here corrupts which address the vault
  controls.

---

## 4. Pre-custody checklist (ordered; do all before any mainnet funds)

Each item is tagged with who must do it: **loki-eng** (Loki engineering),
**user** (the custody decision-maker / operator), **external-auditor**.

1. **Replace the software KEK with a real secure element** — Secure Enclave (iOS/macOS),
   StrongBox/Keystore (Android), TPM/OS-keyring (desktop, with the reduced-guarantee
   disclosure), implementing the same `SecureElement` trait. KEK must be non-exportable;
   unlock must require biometric/passphrase. — **loki-eng**
2. **Wire a real human approval + biometric gate** into `connect`/`sign_approve` so the
   `ApprovalPolicy` callback becomes an actual on-device confirmation, not a code path. —
   **loki-eng**
3. **Prove the WYSIWYS fee/value binding against an adversarial PCZT** — add a harness that
   can inject a forged value / missing `rcv` and assert `fee_verified == false` and a
   refusal, closing the currently-unreachable negative branch. — **loki-eng**
4. **Backup + restore + reorg/crash device drills** — independent recovery-spend from a
   restored share on a fresh device, nonce-epoch reset proven (no old-nonce replay), and
   crash/reorg handling exercised on real device state. — **loki-eng** builds, **user**
   runs/witnesses the recovery drill.
5. **End-to-end split-architecture payment** — a 2-of-3 testnet payment signed via two
   isolated signers + a keyless coordinator, aggregated, applied, broadcast, confirmed;
   print the txid (ws1 §11 #6). Verify each signer approved the actual peer roster
   independently of the coordinator. Requires review of the coordinator loop. — **loki-eng**
6. **External security audit** with this explicit scope: the **signer shell** (at-rest
   sealing / KEK wrapping / nonce single-use + crash-safety), the **WYSIWYS→sighash
   binding** (`sign_approve` + `wysiwys::sighash_of_pczt`), the **keyless coordinator
   boundary** (including DKG roster binding and round-two encryption), and
   **ZIP-2005 FVK derivation #1094** (`zip2005.rs`). — **external-auditor** (scoped by **loki-eng**,
   commissioned by **user**).
7. **ZIP-2005 #1094 upstream review** — drive the vector-matched `use_qsk` derivation
   through ZF `frost#1094` and either land it reviewed or switch to an audited derivation.
   — **loki-eng** engages; **external-auditor** / ZF reviews.
8. **Reproducible builds + independent delivery** — reproducible signer build that two
   machines reproduce to the same hash, published hashes, signed releases, and delivery of
   signer binaries to a quorum through independent channels (app stores / reproducible
   artifacts), counting every device each member uses. — **loki-eng** builds the recipe;
   **user** arranges the independent delivery channels and device inventory.
9. **Mainnet-refuse guard** — before a `Mainnet` network variant is ever added, implement
   and test an explicit guard that refuses mainnet funds until items 1–8 are all signed
   off. The build must show its network plainly (invariant #6). — **loki-eng**; sign-off
   by **user** + **external-auditor**.

Do not touch mainnet until **every** item above is closed.

---

## 5. What the user must arrange (vs what Loki eng builds)

**Loki engineering builds:** the real secure-element backends (#1), the biometric/approval
gate (#2), the adversarial fee-binding harness (#3), backup/restore + crash/reorg handling
(#4, code), the coordinator loop and e2e payment (#5), the reproducible-build recipe (#8,
recipe), the mainnet-refuse guard (#9), and the #1094 upstream engagement (#7).

**The user must arrange (cannot be delegated to Loki eng):**
- **Commission and pay for the external security audit** (#6) and agree the scope above
  with the auditor. Loki eng can scope it; only the user can engage an independent firm.
- **Run / witness the recovery-spend and device drills** (#4) as the custody operator —
  the point is that recovery works for *you*, independently of the people who wrote it.
- **Set up independent delivery channels and the device inventory** (#8) — decide through
  which independent channels each member in a quorum receives their signer, and account for
  every device each member uses. A single mutable origin for all members defeats the
  supply-chain protection regardless of what the code does.
- **Give the final mainnet go-live sign-off** (#9) jointly with the external auditor.

The tests in §1–2 cover specific signer behavior; they do not prove the entire
coordinator boundary. Every gap in §3 is a reason real money would be at risk today.
The §4 checklist, with §5 ownership, is the path from demo to custody.
