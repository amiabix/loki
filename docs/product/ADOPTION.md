# ADOPTION — ZF FROST stack (WS4) + FVK derivation (WS5)

Parent: `00-architecture.md` (invariant 5, audited crypto only). Resolves the WS4
Mode-A/B decision gate and the WS5 recoverable-vs-not determination. Every claim below
is backed by code read on the build host and a passing test; see `poc/tests/zf_spine.rs`.

Evidence snapshot (the build host, 2026-10-18):
- `ZcashFoundation/frost-tools` @ `53df99c` (contains `frost-client`, `frostd`, `zcash-sign`)
- `ZcashFoundation/frost` @ `0966bd1` (issue #1094 repo)
- orchard fork used by `zcash-sign`: `conradoplg/orchard` rev `42015f1` (v0.15.5, `unstable-frost`)

---

## 1. WS4 Mode gate — Mode A (library)

**Decision: Mode A.** `frost-client` already exposes a usable Rust library surface; we
do not need the Mode-B hand-rolled frostd driver.

Evidence (`frost-tools/frost-client/src/lib.rs`):

```
pub mod api;      pub mod cipher;  pub mod cli;     pub mod client;
pub mod coordinator; pub mod dkg;  pub mod participant; pub mod session;
pub mod trusted_dealer;
pub use reddsa;
```

- Participant entry point: `participant::cli::participant<C: RandomizedCiphersuite>(...)`
  (`src/participant/cli.rs:75`), plus `generate_signature(...)` (`:23`).
- Coordinator entry point: `coordinator::cli::coordinator<C>(...)` (`src/coordinator/cli.rs:23`).
- `Client` struct with the full frostd wire API — `challenge`, `login`, `create_new_session`,
  `send`, `receive`, `close_session` (`src/client.rs:19-115`).
- DKG and trusted-dealer are public modules (`dkg`, `trusted_dealer`).

The HEAD commit is literally `#579 "refactor participant to make it easier to use as a
library"`, confirming the library trajectory the WS4 spec anticipated. Loki embeds the
participant side in WS1 and the coordinator side in WS2 via these entry points.

Mode B (drive frostd directly with `frost-core`/`frost-rerandomized`/`reddsa`) stays as
the documented fallback only if a future `frost-client` release regresses the library
surface. Not needed now.

## 2. Pinned crate versions

The crypto math and the relay are the audited crates; Loki writes orchestration + UX.

| Crate | Loki `poc` pin (what we ship) | `frost-tools@53df99c` pin | Role |
|---|---|---|---|
| `frost-core` | `=3.0.0` (feat `serialization`) | `2.2.0` | FROST primitives |
| `frost-rerandomized` | `=3.0.0` (feat `serialization`) | `2.1.0` | rerandomized signing (`alpha`) |
| RedPallas (`reddsa`) | `zakura-reddsa =2.2.0` (feat `frost`) | `reddsa 0.5.1` | Pallas sig scheme |
| `orchard` | `zakura-orchard =2.2.0` (feat `unstable-frost`) | `conradoplg/orchard 0.15.5 @42015f1` | FVK/address |
| `pasta_curves` | `zakura-pasta-curves =2.2.0` | `0.5.2` | curves |
| `frost-client` | (Mode A dep, not yet vendored) | `0.1.0 @53df99c` | participant+coordinator lib |
| `zcash-sign` | (WS5 reference, not a dep) | `0.1.0 @53df99c` | `generate` / `sign` tooling |
| `frostd` | (WS3 transport) | `@53df99c` | JSON-HTTPS relay |

**Skew to track (WS6):** Loki is on `frost-core`/`frost-rerandomized` **3.0.0** via the
`zakura-*` vendor set, whereas `frost-tools@53df99c` is still on **2.x**. Embedding
`frost-client` as a Mode-A dependency requires either bumping `frost-client` to 3.0.0 or
aligning Loki to 2.x. Pin alignment is a WS4→WS6 follow-up, not a blocker for the
decision.

## 3. WS5 FVK determination — `zcash-sign generate` is NOT quantum-recoverable

**Determination: Option B (`zcash-sign generate`) uses the NON-recoverable
constructor.** Therefore, per WS5 §5 recommendation, if quantum-recoverability is a
required product property Loki keeps Option A (`zip2005.rs`, `use_qsk`) and drives ZF
issue #1094 to get it reviewed upstream.

### 3.1 What `generate` does (source)

`frost-tools/zcash-sign/src/generate.rs`:

```rust
pub fn generate(rng: &mut impl RngCore, ak: &SpendValidatingKey) -> FullViewingKey {
    let sk = /* random bytes -> SpendingKey */;
    // "keep this non-quantum-recoverable constructor for now (frost-tools#591)"
    FullViewingKey::from_sk_ak_incompatible_with_quantum_recoverability_and_will_be_removed(
        &sk, ak.clone(),
    )
}
```

Two decisive facts:
1. It calls `from_sk_ak_incompatible_with_quantum_recoverability_and_will_be_removed`.
   In `conradoplg/orchard@42015f1` (`src/keys.rs:379`) that constructor is literally
   `FullViewingKey { ak, nk: sk.into(), rivk: sk.into() }` — the plain Orchard
   derivation, **no `use_qsk` / `qk` / blake3 step**. No quantum-recoverable branch
   exists in that orchard at all.
2. `sk` is drawn **randomly** per call, so `generate` cannot even reproduce a fixed FVK
   for a fixed group key; it is not a deterministic FROST-group derivation.

Contrast — Loki `poc/src/zip2005.rs` (`use_qsk`, `VERSION = zip2005-use-qsk-2026.8.0`):
`nk = expand(sk,0x07)`, `qsk = expand(sk,0x0c)[:32]`,
`qk = blake3::derive_key("Zcash ZIP 2005 qk-derivation v1", qsk)`,
`rivk = expand(qk,0x0d, ak‖nk)`, `FVK = ak‖nk‖rivk`.

### 3.2 Byte proof (fixed group_ak + fixed sk, `poc/tests/zf_spine.rs`)

Loki's orchard (`zakura-orchard 2.2.0`) does not export the FROST-only ctor, but its
`From<&SpendingKey>` uses the identical `nk: sk.into(), rivk: sk.into()` derivation
(`keys.rs:325-328`), so the test reproduces `generate`'s output exactly by building the
standard FVK from the same `sk` and splicing `group_ak` into the `ak` slot — bit-for-bit
what the non-recoverable constructor does.

```
group_ak      = 30dff446d05ea6547b8ecb567feee4f1cb144611b256a58156232cbd174f5302
sk            = 2a2a2a2a...2a2a (32 bytes of 0x2a)
zip2005  FVK  = 30dff446…174f5302 18c5cd0d…4dde5e37 3c37610dfe6d33458a578eb660c9195889e221c4576afcb5106e053713366a36
zcash-sign FVK= 30dff446…174f5302 18c5cd0d…4dde5e37 a6feea9b9b33dfa7468c597ea4edcf93f2fd2ec1498c9547ff1f4b637234f21b
```

| FVK segment | zip2005 (use_qsk) | zcash-sign (non-recoverable) | Match |
|---|---|---|---|
| ak   [0..32]  | `30dff446…174f5302` | `30dff446…174f5302` | **=** |
| nk   [32..64] | `18c5cd0d…4dde5e37` | `18c5cd0d…4dde5e37` | **=** |
| rivk [64..96] | `3c37610d…3366a36`  | `a6feea9b…7234f21b`  | **≠** |

`nk` matches (zip2005's `expand(sk,0x07)` equals orchard's `sk.into()` nullifier
derivation — also asserted by the pre-existing `poc/tests/zip2005_keys.rs`). `rivk`
differs: zip2005 routes it through the `qsk→qk→expand` `use_qsk` path; `zcash-sign` uses
plain `sk.into()`. Different `rivk` ⇒ different `ivk` ⇒ **different vault address**. The
two paths are not interchangeable.

### 3.3 Consequence for the lock

- `zip2005.rs` remains cross-checked 8/8 against `frost-tools#610` vectors (the two
  vectors live in `poc/tests/zip2005_keys.rs` and pass).
- Option B does not provide quantum-recoverability and its FVK won't match a zip2005
  vault, so it cannot silently replace Option A.
- **Locked:** keep Option A (`zip2005.rs`, `use_qsk`) for the recoverable property;
  pursue ZF `frost#1094` review with the matched vectors (WS6). Revisit Option B only if
  `zcash-sign generate` moves to a deterministic `use_qsk` derivation upstream.

## 4. Verification run (the build host, cargo 1.98.0)

`cargo test --locked --test zf_spine --test zip2005_keys -- --nocapture`:

```
running 2 tests  (tests/zf_spine.rs)
[WS4] 2-of-3 rerandomized FROST (reddsa RedPallas) aggregate+verify OK
test ws5_zcash_sign_generate_is_not_quantum_recoverable ... ok
test zf_crates_sign_2_of_3_rerandomized_and_verify ... ok
test result: ok. 2 passed; 0 failed

running 2 tests  (tests/zip2005_keys.rs)
test frost_viewing_key_matches_second_independent_vector ... ok
test frost_viewing_key_keeps_the_zip2005_nullifier_key_but_changes_rivk ... ok
test result: ok. 2 passed; 0 failed
```

The 2-of-3 rerandomized roundtrip (trusted-dealer keygen → round1 commit → randomizer →
round2 partial sigs → aggregate → verify) runs on the audited
`frost-core`/`frost-rerandomized`/`reddsa` RedPallas crates inside Loki's own tree,
upholding invariant 5.

**Pre-existing blocker (not WS4/WS5):** `poc/src/bin/loki_member_payment.rs:1079` calls
`Frontier::root()` with no args, but `incrementalmerkletree 0.8.2` changed it to
`root(Option<Level>)`. This breaks `cargo test` at the package level (it builds all
bins). The one-line fix is `root(None)`; it is unrelated to this workstream and is left
for the owner of that bin. The ZF tests above were run with the lib + the two test
targets.

## 5. WS3 transport — `frostd` adopted (the build host, 2026-10-18)

**Decision:** route the public protocol messages through the audited ZF `frostd` relay;
the bespoke Loki relay stack is marked for retirement.

### 5.1 frostd bring-up
`ZcashFoundation/frost-tools @ 53df99c`, `cargo build -p frostd` (cargo 1.98.0), then:

```
./target/debug/frostd --no-tls-very-insecure -p 2744   # frostd 0.1.0
INFO frostd: server running
WARN frostd: starting an INSECURE HTTP server at 0.0.0.0:2744   # local test only; TLS in prod (ws3 §6)
```

The relay is a pure store-and-forward of opaque bytes: `send { session_id, recipients,
msg }` queues `Msg { sender, msg }`; `receive { session_id, as_coordinator }` drains it.
It never inspects `msg` (`frostd/src/functions.rs`). Login is XEdDSA over a server
challenge (`functions.rs::login`, `xeddsa`), with the member's X25519 key as its address.

### 5.2 Mode-A at the transport layer (not the full `frost-client` crate)
`poc` speaks the eight frostd JSON endpoints directly from `poc/src/transport.rs`
(`Transport` trait per ws3 §5 + `FrostdTransport`), reusing the audited relay binary and
its wire contract. It does **not** take `frost-client` as a crate dependency: that crate
is on `frost-core`/`reddsa` 2.x while `poc` is on 3.0.0 (§2 skew), so embedding it would
pull a conflicting second copy of the crypto crates. The FROST math stays on `poc`'s
audited `reddsa_frost`/`frost-core`; only the thin client orchestration is local. (If the
§2 pin-alignment lands in WS6, the full `frost-client` participant/coordinator API can
replace this orchestration behind the same `Transport` seam.)

### 5.3 Live acceptance (ws3 §7.1 / §7.3)
`FROSTD_URL=http://127.0.0.1:2744 cargo test --test frostd_transport -- --nocapture` — a
2-of-3 **dealerless DKG** (`frost::keys::dkg` part1/2/3) **and** a rerandomized signing
round-trip, every message carried over the running frostd:

```
[WS3] 3 members + coordinator authenticated to frostd at http://127.0.0.1:2744
[WS3] session 9d6c5953-711f-4931-b904-c4ab3df8a9fc created; members joined
[WS3] DKG complete over frostd — group verifying key = 9eef7a2c5bebbf935ae50eff3ae49d487b8d02df68e62db76db2a7436f368131
[WS3] 2-of-3 rerandomized signature over frostd VERIFIES
[WS3] audited 15 relayed payloads; none equals a share or key package (invariant 4 holds)
test two_of_three_dkg_and_sign_over_real_frostd ... ok
```

The test records every byte string frostd actually carried and asserts none equals a DKG
secret package, a FROST share / `KeyPackage`, or a signing nonce — invariant 4 ("only
public data crosses") proven directly, not asserted. Without `FROSTD_URL` the test
self-skips so `cargo test` stays green offline.

### 5.4 Retirement
Loki's bespoke relay stack — `relay_member`, `setup_relay`, `member_service`, and the
`setup_backup`/`setup_retry` helpers — is already behind the off-by-default
`relay-communication` feature and is now annotated in `poc/src/lib.rs` as retiring in
favor of `transport::FrostdTransport`. It still compiles; no new callers should be added.
What stays is the thin roster/admission layer frostd does not provide (ws3 §4):
`setup_ceremony` (invitations, `AdmissionCheckpointAuthority`, the `VaultCertificate`,
network/birth-height tagging). frostd replaces message *passing*, not *who is in a vault*.
