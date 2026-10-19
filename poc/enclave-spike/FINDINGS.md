# Secure Enclave spike — findings

Feasibility spike for the Apple backend of loki's `SecureElement` trait
(`poc/src/signer/secure_element.rs`), which seals the FROST share at rest. The Enclave
only does **P-256**, not Pallas — so it **wraps the share's data key (DEK)**, it does not
hold the share. The trait is exactly two methods, `wrap_dek` / `unwrap_dek`; an
`AppleSecureElement` implements them via the Swift Security.framework.

Run on an **Apple M4 Pro** (has a Secure Enclave), macOS, Xcode CLI (`swiftc 6.4`,
`rustc 1.95`). Reproduce with `./build.sh`.

## Results (measured)

| What | File | Result |
|---|---|---|
| Create non-exportable P-256 key **in the Secure Enclave** | `enclave_spike.swift` | PASS, **unsigned** |
| Private key non-exportable (`SecKeyCopyExternalRepresentation` refused) | `enclave_spike.swift` | PASS |
| `wrap_dek` — ECIES-encrypt a 32-byte DEK to the Enclave key | `enclave_spike.swift` | PASS, 113-byte ciphertext |
| `unwrap_dek` — decrypt inside the Enclave, round-trip | `enclave_spike.swift` | PASS, byte-for-byte |
| **Rust → Swift → Enclave FFI** (the real backend shape, ephemeral key) | `ffi_demo.rs` + `se_bridge.swift` | PASS, built offline with `rustc` |
| **Persistent** key (create at init, reload next launch) | `persist_spike.swift` | FAILS until signed — see below |

## The one gate: a signing identity (free, not a paid account)

A usable wallet needs the Enclave KEK to **persist** across launches. That path requires
the binary signed with an Apple **Team ID**:
- unsigned → `errSecMissingEntitlement` (-34018)
- ad-hoc signed (`codesign -s -`) with a made-up `keychain-access-groups` → process
  **SIGKILLed** (exit 137), because `TeamIdentifier=not set`.

A **free Apple ID** added in **Xcode → Settings → Accounts** creates a "personal team"
+ a free *Apple Development* certificate + a Team ID, which is enough to sign and run on
your own device. No paid ($99/yr) membership is needed for local Enclave development
(free-team limits — 7-day app expiry, no distribution — don't affect it).

## What's proven vs. remaining

- Proven: the Enclave wrap/unwrap crypto and the Rust↔Swift↔Enclave FFI wiring work on
  this machine. The ephemeral `ffi_demo` is the exact shape of `AppleSecureElement`.
- Remaining (once a signing cert exists): persist the key (`persist_spike` path, signed),
  add `.biometryCurrentSet` to the access control for the Face/Touch-ID gate on
  `unwrap_dek`, and swap `AppleSecureElement` in behind the trait in
  `poc/src/signer/secure_element.rs` (plus the Rust FFI build path for the main crate).

The proper `AppleSecureElement` backend (real trait impl + C-ABI + offline round-trip) now
lives alongside this spike — see **`BACKEND.md`**. The persistent/biometric code and both
remaining gates (signing cert, crates.io/vendored crate build) are documented there.
