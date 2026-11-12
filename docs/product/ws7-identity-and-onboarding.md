# WS7 — Identity, Membership & Onboarding

> How a person becomes a signer, how a signer is uniquely and recoverably bound to its
> owner, and how vault membership is assigned. Replaces the demo's "claim a slot from a
> pool of 30" screen, which is a deployment artifact, not the product.

Parent: `00-architecture.md` (LOCKED). Builds on `ws1-signer.md` (the signer),
`ws2-coordinator.md` (keyless coordinator), and the recovery/device code already in
`poc/src/signer/{recovery,device_auth,secure_element_apple}.rs`. Upholds invariants
1–4, 6.

---

## 1. The problem this fixes

The hosted demo pre-spawns **30 `loki_member_app` processes** on one box (ports
3601–3630) and the web login makes the user **"claim slot N"**, then unlocks it with a
**passphrase** (`SoftwareSecureElement`, Argon2id — `host/ceremony.rs` `run_background`
seals the share with `SoftwareSecureElement::persistent`). Two consequences, both wrong
for the product:

1. **Signer identity = a typed passphrase.** Anyone who knows member N's passphrase can
   act as that member from any machine. There is no device binding, nothing unique or
   non-replayable. (This is the gap caught in review.)
2. **"Member" is a user-facing slot you pick from a shared pool.** Users should never
   see or choose a "member number"; a slot is an internal FROST index inside one vault.

Both are demo shortcuts to fake multi-party on a single host. They contradict the locked
architecture (`00-architecture.md` §1: *"Signing always requires the member's own
device"*). WS7 specifies the real model.

## 2. Prior art (and what Loki takes from each)

- **Vizor** (Keplr/Chainapsis Zcash wallet): keyless app; the **key lives on a hardware
  device** (Keystone / Ledger) that confirms signing; **PCZT** is the app↔device
  interchange. Single-sig only — no multisig. *Takeaway:* the signing identity is a
  device, not a secret the app holds; PCZT is the confirm-on-device format. Loki already
  keeps the FROST-hardware upgrade path open on this exact interface (`ws1` §Hardware).
- **zkool** (hhanh00): native app, each member runs their own, each device holds **only
  that member's share**; the app *is* the signer. *Takeaway:* one signer per person, one
  share per device, no shared pool.
- **Device-share MPC wallets** (Vultisig-style): no single seed phrase; each device is a
  share-holder, and the "account" is the group. *Takeaway:* "your device = a key share"
  is a proven UX; Loki differs by giving each **member** (not the group) a recoverable
  seed identity, so a lost device is restorable without re-keying the whole vault.

Loki = **keyless web/native coordinator + one device-bound FROST signer per person**,
threshold across people (what Vizor lacks), with per-member seed recovery (what pure
device-share MPC lacks).

## 3. The identity model — "account = wallet × machine"

An **account** is the user's single, durable signer identity. It is two things bound
together:

```
        ACCOUNT (one per user, reused across every vault)
        │
        ├─ IDENTITY ROOT  — a BIP-39 24-word seed              (the "wallet")
        │     recovery.rs: RecoveryKey::generate() → 24 words → BIP-39 seed (64B)
        │     → RFC 9180 DeriveKeyPair → X25519 recovery key (HPKE) + Ed25519
        │       device-authorization key. The words are shown ONCE; only PUBLIC
        │       keys are persisted. This is the portable root of the account.
        │
        └─ DEVICE KEY  — a non-extractable key in THIS machine  (the "machine")
              secure_element_apple.rs: AppleSecureElement::persistent — Secure
              Enclave P-256 key, kSecAttrIsPermanent, access control
              .biometryCurrentSet | .privateKeyUsage (Face/Touch ID, this device
              only). Authorized by the identity root (recovery.rs::authorize_device)
              and recognized by challenge/response (device_auth.rs::DeviceRegistry).
```

- The **device key is the live credential**: every use of a share is gated by this
  machine's biometric, and the key cannot leave the Enclave. So you **cannot act as this
  account from another machine by typing a secret** — exactly the uniqueness the review
  asked for.
- The **seed is the recovery root**, not a day-to-day login. It (a) HPKE-seals each
  vault share as a backup (`recovery.rs::seal_backup`) and (b) authorizes device keys.
  Lose the machine → restore the seed on a new machine → it re-authorizes the new device
  and reopens the share. Dead laptop ≠ lost funds.
- **A "member" of a vault is this account.** In each vault the account holds exactly one
  FROST share (`ws1` §2), born in that vault's DKG on the account's device, sealed by the
  device key. One account, many vaults, one share each.

### 3.1 Why both halves are needed

| Threat | Stopped by |
|---|---|
| Malicious web bundle reads a key | Share never leaves the signer / Enclave (`00-arch` §2.1) |
| Attacker types a stolen passphrase from their laptop | No passphrase login — needs **this device** + biometric |
| User's machine is lost/stolen | Seed words restore on a new device; old device **revoked** (`device_auth.rs::revoke`) |
| Attacker steals the seed words | Can restore, but the group can **re-key / repair** that member's share (`ws1`; `signer/repair.rs`), and device revocation limits a stolen live device |

Seed-portability and device-binding are **complementary**, not in tension: the device
key is what's live and unique; the seed is what's portable and recoverable.

## 4. Membership & slots — assigned, never chosen

- A **slot** (FROST identifier `1..n`) is an **internal, per-vault** index. It is never
  shown to or chosen by the user, and there is no global "member pool."
- **Creating** a vault makes you slot 1 automatically. **Joining** via an invite assigns
  you the next free slot automatically. Your *account* is the same across all of them;
  only the per-vault slot differs, behind the scenes.
- The current "pick member N / claim a slot" login screen is **deleted** (see §6).

## 5. Onboarding & lifecycle flows

### 5.1 First run — create your account (once per device/person)
1. App generates the **identity root**: 24 words shown once ("write these down — they
   restore your account on a new device"). Only public keys persisted (`recovery.rs`).
2. App creates the **device key** in the Secure Enclave, biometric-gated, and
   self-authorizes it with the identity root (`authorize_device` → enrolled in the
   local `DeviceRegistry`).
3. Done. No vault yet. There is no "choose member 2."

### 5.2 Create a vault
1. Pick policy (t-of-n). You become **slot 1** automatically.
2. App emits **invite links** (one per remaining slot) — an invite carries the vault id,
   the slot's one-time token, the policy, and the creator's reachable address
   (constrained to configured peers; the SSRF guard in `host/ceremony.rs::join` applies).
3. Share links out-of-band. Status shows who's joined.

### 5.3 Join a vault (invitee)
1. Open the invite link in your app (already have an account from §5.1).
2. App enrolls your account's identity under the next free slot — **no slot picking,
   no new account**.
3. Compare the roster code on-device (`ws1` §6), agree, run DKG. Your share is born on
   your device and sealed by your device key.

### 5.4 Sign a payment
Unchanged from `ws1`/`ws2`: coordinator proposes a PCZT; your signer **parses + renders
+ requires biometric approval** on your device; emits commitment then partial signature;
never aggregates. The approval is device-bound — the thing a co-signer must physically do.

### 5.5 Add a second device to the same account
1. On the new device, "restore account" → enter your 24 words.
2. The identity root authorizes the new device's Enclave key; it enrolls in the
   `DeviceRegistry`. Vault shares are re-opened from their HPKE backups (`recovery.rs`).
3. Both devices can now act for the account. *(Open decision §8.1: allow N live devices,
   or one-active-at-a-time.)*

### 5.6 Lose a device / rotate
1. Restore on a replacement device (§5.5).
2. **Revoke** the lost device key (`device_auth.rs::revoke`) so its challenges fail.
3. If the seed itself may be compromised: the group runs **share repair / re-key** for
   that member (`signer/repair.rs`, RTS) — the vault keeps its address; only the member's
   share rotates.

## 6. What changes vs the current demo

| Area | Demo today | WS7 target |
|---|---|---|
| Signer process | 30 pre-spawned on one box | **One signer per user/device** (native app, or one-per-browser-profile for a web pilot) |
| Login | pick slot N + passphrase | **No slot picking.** Open app → your account (device biometric); restore via seed on a new device |
| Custody | `SoftwareSecureElement` (Argon2id passphrase) | `AppleSecureElement` / platform SE (non-extractable, biometric) — `ws1` §4 table |
| Membership | claim from a pool | created (slot 1) or joined via **invite link**, slot auto-assigned |
| Coordinator | already keyless | unchanged (keyless; holds only public data) |

The **coordinator and FROST/DKG/payment layers do not change** — they already take any
`SecureElement` and any roster. WS7 is an **identity + onboarding + packaging** change,
plus swapping the software SE for the platform SE in the real signer.

## 7. Gap analysis — built vs missing

**Already built (reuse as-is):**
- BIP-39 identity root + HPKE share backups — `recovery.rs` (proven: restore test, and
  live recovery on the hosted apps this cycle).
- Device-authorization + challenge/response + revoke — `device_auth.rs`.
- Non-extractable biometric device key — `secure_element_apple.rs` (proven on M4 Pro).
- DKG, rerandomized FROST signing, on-device PCZT review — `ws1`, signer modules.
- Share repair (RTS) — `signer/repair.rs` (library-level).

**Missing (the WS7 work):**
1. **One-signer-per-user packaging** — drop the 30-process pool; ship the native signer
   (macOS first; it exists in `poc/signer-app`) as *the* identity, or one isolated signer
   per browser profile for a web-only pilot.
2. **Account onboarding UI** — first-run seed generation + device enrollment; "restore on
   new device"; delete the claim-a-slot screen.
3. **Wire the platform SecureElement into the member app** — today `host/ceremony.rs` /
   `host/payment.rs` use `SoftwareSecureElement`; make the SE pluggable so the native
   build uses `AppleSecureElement`.
4. **Invite-link join in the product UI** — the backend exists (`host/ceremony.rs`
   create/join/enroll); surface it as links + auto slot assignment, no numbers.
5. **Repair wired into the coordinator** — add the host endpoints so §5.6 re-key works in
   the app, not just the library.

## 8. Open decisions (need a call)

### 8.1 One active device, or several, per account?
- **One-active-at-a-time** (simplest; matches today's "switching accounts locks the
  previous"): the account lives on one device; moving = restore + revoke old. Clean
  security story, slightly more friction for multi-device users.
- **Several live devices** (phone + laptop both authorized): more convenient; the
  `DeviceRegistry` already supports multiple enrolled keys. Needs a rule for which device
  participates in a given signing round (the signer only runs one share at a time).
- *Recommendation:* ship **one-active** first; the registry keeps multi-device open.

### 8.2 Seed custody UX
24 raw words (current) vs. an encrypted seed export / optional passkey-wrapped cloud
backup. Raw words are the safe default; any cloud/export path must never let the
coordinator or a web origin see the seed. *Recommendation:* words only for v1.

### 8.3 Web-pilot signer vs native-only
Pure native (zkool's path) is the safest. If a web pilot is wanted before native ships,
the "one isolated signer per browser profile" must still **never put a Pallas spend key
in the page** — it would be a local companion process the page talks to, not WASM in the
origin (`00-arch` §2.1 forbids keys in the page). *Recommendation:* native signer is the
real answer; treat any web-signer as a throwaway demo clearly labeled non-custodial-only.

## 9. Invariants upheld

1. No spend key ever in a web page — share stays in the signer/Enclave.
2. Key born in DKG on the device, decrypted to memory only at signing, then zeroed.
3. Real transaction confirmed on the member's own device (biometric).
4. Coordinator handles only public data.
6. General t-of-n (2 ≤ t < n ≤ 16), no hardcoding.

WS7 does not touch the crypto; it makes *who a signer is* unique, device-bound, and
recoverable, and makes *becoming one* an account + invite flow instead of claiming a
pooled slot.
