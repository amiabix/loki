# Apple Secure Enclave backend — status

Extends the feasibility spike (`FINDINGS.md`) into a **proper `AppleSecureElement`** that
implements loki's `SecureElement` trait (`poc/src/signer/secure_element.rs`). The Enclave
is P-256 only, so it holds the **KEK** and wraps/unwraps the per-share **DEK** via ECIES;
the FROST share itself never enters the Enclave. Nothing above the trait changes versus
`SoftwareSecureElement` — it is a drop-in KEK backend.

Built and run on an Apple-silicon Mac (has a Secure Enclave), `swiftc 6.4`, `rustc 1.95`,
fully offline. Reproduce with `./build.sh`.

## Files

| File | Role |
|---|---|
| `se_backend.swift` | C-ABI Secure Enclave backend: `se_open_ephemeral`, `se_open_persistent`, `se_wrap`, `se_unwrap`, `se_close`. Handle table so one process can hold several elements. |
| `poc/loki-signer-core/src/signer/secure_element_apple.rs` | **Shipped** Rust `AppleSecureElement` — `impl SecureElement` (`wrap_dek`/`unwrap_dek`), `ephemeral()`, `open_persistent(tag)` and `create_persistent(tag)`, `Drop` closes the handle. |
| `apple_ffi_verify.rs` | Offline `rustc` verifier that **includes the shipped module** and round-trips a DEK through the real Enclave. |
| `zeroize_shim.rs` | Std-only `zeroize::Zeroizing` stand-in so the shipped module compiles under `rustc` without cargo. Verifier-only. |

## Verified on this Mac (real output, stage 3 of `build.sh`)

```
[rust] ephemeral AppleSecureElement opened via FFI
[rust] wrap_dek -> 113 bytes (ECIES to the Enclave key)
[rust] unwrap_dek -> DEK recovered byte-for-byte
[rust] tampered ciphertext correctly rejected
[rust] persistent path gated as expected (unsigned): se_open_persistent failed (code -5) ...
APPLE FFI VERIFY PASS: real AppleSecureElement ephemeral wrap/unwrap round-trips a signer DEK
```

The code exercised there is byte-for-byte the shipped module (the verifier `#[path]`-includes
it); only the crate-side `SecureElement`/`WrappedDek` types and the `zeroize` crate are stubbed.
The FFI, the Swift backend, and the wrap/unwrap body are the real thing.

## What is present but NOT verified here (honest ceiling)

Two independent gates remain. Neither is a crypto problem; both are environment.

### Gate 1 — persistence + biometrics need a signed binary (no cert on this Mac)

`se_open_persistent` only creates a key for a creating caller after `errSecItemNotFound`.
The key uses `kSecAttrIsPermanent=true` + `kSecAttrApplicationTag` with
access control `[.biometryCurrentSet, .privateKeyUsage]` — the persistent, Face/Touch-ID-gated
KEK a real wallet needs. **Unsigned, Keychain operations can fail with
`errSecMissingEntitlement`**; members see a fixed message, not the OS status.
Run the Swift entry-point and signer-core error-copy tests without a Secure Enclave or signing
identity. The script links the shipped Rust module against the dylib, even when a direct Cargo
test of the leaf crate cannot link it:

```sh
bash poc/enclave-spike/build.sh --test-backend
```

Unblock: add a free Apple ID in Xcode → Settings → Accounts → Manage Certificates (creates a
"personal team" + free *Apple Development* cert + Team ID; no paid membership needed), then
`codesign -s 'Apple Development: <you>' <binary>` with a `keychain-access-groups` entitlement.
The biometric prompt fires inside `se_unwrap` → `SecKeyCreateDecryptedData`.

### Gate 2 — the integrated loki crate build needs crates.io or vendoring

`secure_element_apple.rs` lives in the crate but is **not yet wired into the crate build**:
it needs a `#[cfg(target_os = "macos")]`/feature gate in `signer/mod.rs` and a link directive
(build.rs or `#[link]`) for `libse_backend`. More fundamentally, `cargo build --offline` on this
Mac fails to resolve dependencies (e.g. `xeddsa` not found — crates.io unreachable, deps not
vendored), so the full crate cannot compile here at all. That is why the backend is verified
standalone with `rustc`.

Unblock: build on a host with crates.io reachable, or `cargo vendor` the dependency tree, then
add the module gate + link directive and move the round-trip into `secure_element.rs`'s
`#[cfg(test)]` block.

## Summary

- Proven on this Mac: the real `AppleSecureElement` ephemeral path round-trips a signer DEK
  through the Secure Enclave over the Rust↔Swift↔Enclave FFI, and rejects tampered ciphertext.
- Not proven (gated, documented): persistent + biometric key (needs a signing cert), and the
  integrated loki-crate build (needs crates.io or a vendored tree). Neither is fabricated as
  working.
