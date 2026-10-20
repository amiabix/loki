# WS1 — The Signer

> Safety-critical. This is the component that solves "keys in the browser." If any
> other workstream conflicts with a requirement here, this one wins.

Parent: `00-architecture.md`. Upholds invariants 1–4, 6.

---

## 1. Goal

A native, per-member application that **generates, stores, and uses exactly one FROST
share**, runs the ZF participant role in DKG and signing, and **independently confirms
the real transaction on the member's own device** before releasing any signature.
The share is wrapped by the platform secure element and gated by biometrics; it never
enters a browser, a coordinator, a relay, or any Loki service.

## 2. Scope

- Key generation (DKG participant), backup, and restore of **one** share.
- At-rest protection: share sealed by a data key wrapped by the secure element.
- Biometric/passphrase unlock gating every use of the share.
- FROST round 1 (commitments) and round 2 (partial signature), rerandomized.
- **Independent PCZT parse + human-readable render + explicit approval** ("what you
  see is what you sign").
- Single-use nonce handling with crash-safe persistence.
- A narrow, auditable **signer API** the coordinator calls (local IPC or `frostd`),
  exposing only public artifacts.

## 3. Non-goals

- Building transactions, scanning the chain, computing balances, or broadcasting —
  those are WS2 (coordinator). The signer may *parse* a PCZT to display it but does
  not *construct* spends.
- Holding more than one member's share. Multi-membership = multiple sealed stores,
  each independently unlocked; the signing module operates on one at a time.
- Being a web page or a web worker. (Explicitly forbidden: invariant 1.)
- New threshold crypto. All FROST math is the ZF stack (WS4).

## 4. Platforms & secure-element mapping

| Platform | Wrapping key home | Unlock | Notes |
|---|---|---|---|
| iOS / iPadOS | Secure Enclave (P-256 wrapping key) | Face ID / Touch ID | Keychain item, `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`, access control `.biometryCurrentSet`. |
| macOS | Secure Enclave (Apple silicon) / Keychain | Touch ID / password | Same Keychain API; fall back to login keychain on Intel w/o SE. |
| Android | StrongBox Keymaster if present, else TEE Keystore | BiometricPrompt | `setUserAuthenticationRequired(true)`, `setIsStrongBoxBacked(true)` best-effort. |
| Desktop (Linux/Win) | TPM 2.0 via OS keystore, else OS keyring | OS auth / passphrase | Document reduced guarantee when no TPM; still never browser. |

**Hard constraint (why the element only wraps):** secure elements operate **P-256**
keys only; FROST-Zcash is **Pallas**. The element therefore holds a **wrapping/KEK**
that encrypts the share's data-encryption key; the Pallas share math runs in app
memory after unlock, then the plaintext is zeroed. See `00-architecture.md` §2.4.

### Hardware path (future, keep open)
A FROST-capable hardware wallet (Keystone / Frostsnap) that speaks Pallas can host the
share and run the rounds on-device, with the native signer acting as its host/UI. The
signer API (§7) and the "confirm on device" rule are defined so that swapping the
in-app Enclave-wrapped store for a hardware participant is an **implementation change
behind the same interface**, not a redesign. PCZT is the interchange format (vizor
already proves PCZT hardware signing for single-sig shielded).

## 5. At-rest key hierarchy

```
Biometric/passphrase unlock
        │ releases
   KEK  ──(secure element: Enclave/StrongBox/TPM, non-exportable)
        │ unwraps
   DEK  ──(random, per-membership)
        │ decrypts
  Sealed share blob  ──(FROST share + group info + nonce-state epoch)
```

- One **DEK per vault membership**; one **KEK** per device (or per membership) in the
  secure element, non-exportable.
- Sealed blob format is versioned; includes an AEAD tag and the backup epoch so a
  restored or rolled-back store is detectable (ties to crash-safe nonces, §8).
- Switching the active membership locks the previous one (zeroizes its DEK + plaintext
  share), matching the existing "switching accounts locks the previous profile"
  behavior in `README.md`.

## 6. FROST responsibilities (ZF participant role)

The signer wraps `frost-client`'s participant functionality (WS4) and performs:
1. **DKG** (v2, shared core `poc/src/dkg_core.rs`, any 2 ≤ t < n ≤ 16): round 1/2/3
   as a participant; outputs this member's `KeyPackage` (the share) + the shared
   `PublicKeyPackage` (group verifying key) + the vault secret `vs`.
   - Before anything is generated, the roster passes the shared gate (vault, policy,
     network, distinct non-weak keys, own identity, `setup_version` 2) and the member
     compares a 24-digit roster code on the device. Nothing is saved on a mismatch,
     cancel or timeout.
   - Round one is signed and carries a commitment to the member's contribution and a
     one-setup fresh X25519 key. Round two is sealed per recipient in a v2 envelope
     under the two fresh keys and bound to the round-one transcript, so FROST
     round-one equivocation is caught. The fresh key is erased once the certificate
     state is saved; the group key is normalized to even Y.
   - Every outgoing message is saved before release and resent byte-identically after
     a restart. Before the share exists any mismatch is final: the setup is wiped
     and never retried. Once the share exists a bad message is only refused, so one
     faulty or malicious member cannot destroy the shares the others already hold.
   - The share is sealed before the certificate is released. The vault is ready only
     after every member's backup receipt.
2. **Signing round 1**: generate single-use `SigningNonces`, emit `SigningCommitments`
   (public). Persist nonce state crash-safely **before** emitting (§8).
3. **Signing round 2 (rerandomized)**: given the coordinator's `SigningPackage` +
   the **randomizer** (transaction `alpha`), verify the package binds the intent this
   member approved, then produce the partial `SignatureShare`. Consume (burn) the
   nonce atomically with producing the share.

The signer **never aggregates**; aggregation + final signature application is WS2 via
`zcash-sign` (combine partials → apply to PCZT).

## 7. Signer API (the only surface the coordinator sees)

Transport: local IPC (Unix socket / platform channel) when co-located, or `frostd`
when remote (WS3). All payloads are **public**. The API is intentionally tiny and is
the primary audit surface for the coordinator boundary.

```
connect(origin, network, challenge) -> session            # shows origin+network, biometric, returns session + member identity (public)
listVaults(session)                 -> [VaultRef]          # names, slots, setup status (public metadata only)
dkgBegin(session, roster)           -> VaultRef            # roster gate, then the on-device roster code; saves the confirmed roster
dkgStep(session, vaultRef, inMsgs)  -> [DkgWire]           # sender-tagged inputs; returns every saved setup message (rounds, certificate, receipts)
backup(session)                     -> [DkgWire]           # saves and reloads the backup on the device; returns only the signed receipt
releaseAddress(session)             -> ReleasedAddress     # once ready, over a session the member approved on-device; address only
signCommit(session, candidateRef)   -> SigningCommitments  # round 1; after on-device "prepare" ack
signApprove(session, candidateRef, pczt, signingPackage, randomizer)
                                    -> SignatureShare | REFUSED
                                                           # round 2; BLOCKS on in-signer parse+render+biometric approval
disconnect(session)
```

Rules enforced inside `signApprove`, not by the caller:
- Re-parse `pczt`; render recipient/amount/fee/change/memo **from the bytes**; require
  explicit member approval + biometric unlock (invariant 3 / threat §5.4).
- Verify `signingPackage` + `randomizer` correspond to the parsed, approved PCZT and
  to a candidate using **this** member's share; refuse otherwise.
- One share released for the **exact** approved package under single-use nonce rules.
- A refusal is a member decision, not a protocol veto (`WALLET_BUILD.md` §8).

The API exposes **no** method that returns a share, a nonce, a viewing key, or a
spend authorization. Its return types are pinned by the type guard
(`known_signer_return_types_are_public_artifacts`): `DkgWire`, `ReleasedAddress` and
`CandidatePczt` can be made only inside the crate. There is no "export key" path except the member's own guarded
backup flow.

## 8. Nonce safety (crash-safe approval)

This is called out in `WALLET_BUILD.md` as unsolved ("a crash between nonce
consumption and saved-share persistence can strand an approval").

Requirements:
- Nonces are **single-use**. The commitment and its secret nonce are persisted (DEK-
  sealed, fsync'd) **before** the commitment is emitted in round 1.
- Round 2 consumes the nonce **atomically** with emitting the partial signature:
  persist "nonce burned + partial emitted" in one durable, fsync'd transaction; a
  crash either leaves the nonce unused (safe to retry) or burned-and-emitted (safe to
  resend the same partial) — never "burned but lost."
- Reused nonce detection: if a stored nonce epoch is seen again for a different
  message, **hard refuse** (nonce reuse breaks FROST security).
- Restore from backup resets to a fresh nonce epoch and must not replay an old one.

Acceptance includes a crash-injection test at the nonce/persist boundary (§11).

## 9. UX requirements

- **Connect**: show coordinator origin, network (regtest/testnet/mainnet), requested
  access, and a short-lived challenge; member approves on the signer (Safe's
  "connect a signer wallet" contract, already described in `WALLET_BUILD.md`).
- **Approve payment**: full-screen, signer-rendered summary — **To / Amount / Fee /
  Change / Memo / Network** — parsed from the PCZT, with a clear "this is what you are
  signing" framing and the biometric prompt. No coordinator-supplied text is trusted
  for these fields.
- **Network banner**: non-mainnet builds display test-network status plainly and
  refuse mainnet funds (release boundary, `WALLET_BUILD.md`).
- **Backup**: force the member to save and prove-load their recovery artifact before
  the vault can activate.

## 10. Dependencies

- WS4 ZF stack (`frost-client` participant lib, `reddsa`/`frost-rerandomized`).
- WS5 FVK derivation choice (affects what the DKG outputs / how backup recovers the
  group viewing key).
- WS3 transport only for the remote-signer deployment; local IPC otherwise.
- Reuses Loki's existing `distributed_setup`, `member_state` sealed loading,
  `signing_session` nonce/approval rules as the starting point to be re-homed onto the
  ZF participant role (`WALLET_BUILD.md` "Existing code and required changes").

## 11. Acceptance criteria (run; paste output — no claim without passing tests)

1. **Isolation**: on three separate OS users/devices, three signers each generate and
   hold only their own share; a cross-store read attempt fails. (Mirrors
   `WALLET_BUILD.md` ownership test.)
2. **No-browser proof**: static check + runtime assertion that the share-holding module
   is never loaded in a web/worker context; coordinator API surface contains no
   share/nonce/vk return.
3. **At-rest**: with the app locked, the on-disk share blob is AEAD ciphertext; the KEK
   is non-exportable from the secure element (platform attestation where available);
   unlock requires biometric.
4. **WYSIWYS**: a deliberately malicious coordinator that sends a PCZT paying a
   different recipient than it *claims* is caught — the signer renders the true
   recipient and the member can refuse. Automated with a tampered-coordinator harness.
5. **Nonce crash-safety**: crash-injection at the round-2 persist boundary leaves no
   stranded/duplicated nonce; reuse is hard-refused.
6. **End-to-end**: 2-of-3 testnet payment signed via two isolated signers + keyless
   coordinator, broadcast and confirmed; print txid. (Extends the existing confirmed
   testnet payment to the split architecture.)
7. **Hardware-ready**: the signer store is swappable behind the §7 API (demonstrate
   with a mock hardware participant that satisfies the same interface).

## 12. Open questions (resolve during build, not before)

- Desktop without TPM: ship with OS-keyring + strong passphrase and a clear reduced-
  guarantee disclosure, or require a hardware token? (Lean: ship with disclosure; WS6.)
- Single installed app (coordinator + signer in one native binary, logically split) vs
  two separate installs for v1? (Lean: one native app, logical split, so the web
  coordinator is an *option* layered later — smallest path to the safety property.)
- Which biometric fallback policy (passphrase-only devices)?
</content>
