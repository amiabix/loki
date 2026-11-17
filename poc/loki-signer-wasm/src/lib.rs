//! wasm-bindgen bindings for the in-browser FROST signer.
//!
//! Phase 3 slice: the trust-critical, persistence-free custody primitive, proven to run
//! in the browser — seal/open a FROST share under a WebAuthn-PRF-derived KEK (W2's
//! [`WebAuthnSecureElement`]). This is the piece the onboarding UX needs first: the share
//! is wrapped under the passkey's PRF secret (released by Touch/Face ID / security key /
//! phone) and persisted sealed; a reload re-derives the same KEK and reopens it.
//!
//! The full stateful `SignerModule` (web/wallet/src/lib/signer.ts) — `createSigner` →
//! sealed share in OPFS, DKG/signing over the frostd transport, `request(path, body)` —
//! builds on top of this once the synchronous OPFS store seam replaces `store.rs`'s
//! `std::fs` (the core stays synchronous; the signer runs in a Web Worker where OPFS
//! `createSyncAccessHandle` gives synchronous file I/O). See the Phase 3 report.

use loki_signer_core::setup_transport::{Identity, PublicIdentity};
use loki_signer_core::signer::backup::BackupArtifact;
use loki_signer_core::signer::local::{
    BackupDevice, DevicePrompts, LocalSigner, RosterDecision, SignerError,
};
use loki_signer_core::signer::secure_element::{
    fresh_kek_salt, SealedShare, SoftwareSecureElement,
};
use loki_signer_core::signer::secure_element_webauthn::{prf_kek, WebAuthnSecureElement};
use loki_signer_core::signer::{
    opfs_exists, opfs_get, opfs_put, CandidateRef, Network, Session, Signer as SignerTrait,
    VaultRef,
};
use loki_signer_core::signer::wysiwys::{describe_pczt, sighash_of_pczt};
use loki_signer_core::signer::DkgInput;
use loki_signer_core::signing_session::{AttemptId, SessionContext};
use loki_signer_core::frost;
use std::time::Duration;
use wasm_bindgen::prelude::*;
use zeroize::Zeroizing;

// secp256k1 is pulled into this crate transitively (bip32 <- zakura-transparent, and pczt's
// `signer` feature forces `transparent`). The Orchard FROST signer performs no secp256k1
// CRYPTO, but `pczt::roles::signer::Signer` OWNS a `secp256k1::Secp256k1<All>` context, so the
// payment review/sighash path still CONSTRUCTS and DROPS one. Its C preallocated-context
// functions are left as `env` module imports by the wasm build (no WASI C toolchain compiles
// the C here), and a browser can't resolve a bare `env` specifier. Define them in-module so
// the linker is satisfied AND the context's construct→drop lifecycle is memory-safe: `size`
// and `clone_size` return the SAME non-zero value and `create` returns its own buffer, so
// secp256k1's `alloc(size)` / `dealloc(ctx, clone_size)` is a balanced round-trip. Earlier
// these returned size 0 / a null ctx, so `Drop` ran `dealloc(null, 0)` — a wasm "memory access
// out of bounds" the moment a candidate was reviewed. The context is never used for crypto
// (no secp256k1 op runs for our shielded-only candidates); a transparent-input tx would still
// need a real context, out of scope here.
#[cfg(target_arch = "wasm32")]
mod secp256k1_link_stub {
    use core::ffi::{c_uint, c_void};
    // Arbitrary non-zero, aligned buffer size; only alloc/dealloc balance matters since the
    // context bytes are never read by a real secp256k1 operation.
    const CTX_SIZE: usize = 256;
    #[no_mangle]
    pub extern "C" fn rustsecp256k1_v0_10_0_context_preallocated_size(_flags: c_uint) -> usize {
        CTX_SIZE
    }
    #[no_mangle]
    pub extern "C" fn rustsecp256k1_v0_10_0_context_preallocated_create(
        prealloc: *mut c_void,
        _flags: c_uint,
    ) -> *mut c_void {
        prealloc
    }
    #[no_mangle]
    pub extern "C" fn rustsecp256k1_v0_10_0_context_preallocated_destroy(_ctx: *mut c_void) {}
    #[no_mangle]
    pub extern "C" fn rustsecp256k1_v0_10_0_context_preallocated_clone_size(_ctx: *const c_void) -> usize {
        CTX_SIZE
    }

    // secp256k1-sys's `sanity_checks_for_wasm()` (types.rs) runs when a context is constructed
    // — which the pczt transparent Signer/Verifier role does even for our shielded-only
    // candidate — and asserts each C ABI size/align against these `extern "C"` statics. The C
    // that defines them is not compiled here (see the note above), so without definitions they
    // read as garbage and the assert aborts with a bare "unreachable". Define them with the
    // real wasm32 ABI values (int/uint/size_t/ptr = 4 bytes, uchar = 1), so the check passes;
    // the context itself is still the never-operated-on null from the stubs above.
    #[no_mangle]
    pub static WASM32_INT_SIZE: u8 = 4;
    #[no_mangle]
    pub static WASM32_INT_ALIGN: u8 = 4;
    #[no_mangle]
    pub static WASM32_UNSIGNED_INT_SIZE: u8 = 4;
    #[no_mangle]
    pub static WASM32_UNSIGNED_INT_ALIGN: u8 = 4;
    #[no_mangle]
    pub static WASM32_SIZE_T_SIZE: u8 = 4;
    #[no_mangle]
    pub static WASM32_SIZE_T_ALIGN: u8 = 4;
    #[no_mangle]
    pub static WASM32_UNSIGNED_CHAR_SIZE: u8 = 1;
    #[no_mangle]
    pub static WASM32_UNSIGNED_CHAR_ALIGN: u8 = 1;
    #[no_mangle]
    pub static WASM32_PTR_SIZE: u8 = 4;
    #[no_mangle]
    pub static WASM32_PTR_ALIGN: u8 = 4;
}

// Runs once when the worker instantiates the module (wasm-bindgen `start`), so any later
// panic in a synchronous core call prints its real message + Rust location to the Worker
// console instead of a bare "unreachable" trap. console_error_panic_hook logs via
// `console.error`, which exists in a Web Worker.
#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

fn prf32(prf_secret: &[u8]) -> Result<[u8; 32], String> {
    prf_secret
        .try_into()
        .map_err(|_| "WebAuthn PRF secret must be exactly 32 bytes".to_string())
}

// Inner impls return String so the native `wasm-bindgen-test` can assert on them; the
// exported wrappers map the error to a JS exception.
fn seal_impl(prf_secret: &[u8], epoch: u64, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let se = WebAuthnSecureElement::from_prf_secret(&prf32(prf_secret)?);
    Ok(SealedShare::seal(&se, epoch, plaintext)?.to_bytes())
}

fn open_impl(prf_secret: &[u8], sealed: &[u8]) -> Result<Vec<u8>, String> {
    let se = WebAuthnSecureElement::from_prf_secret(&prf32(prf_secret)?);
    Ok(SealedShare::from_bytes(sealed)?.open(&se)?.to_vec())
}

/// Seal a FROST share under a passkey: KEK = HKDF(PRF secret), then the proven
/// XChaCha20-Poly1305 share seal. Returns the sealed bytes the browser persists.
/// `epoch` is the share's backup epoch.
#[wasm_bindgen(js_name = sealShareUnderPasskey)]
pub fn seal_share_under_passkey(
    prf_secret: &[u8],
    epoch: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, JsError> {
    seal_impl(prf_secret, epoch, plaintext).map_err(|e| JsError::new(&e))
}

/// Reopen a share sealed by [`seal_share_under_passkey`] with the same passkey's PRF
/// secret. Fails if the secret is wrong, the bytes are corrupt, or they were sealed under
/// a different element.
#[wasm_bindgen(js_name = openShareWithPasskey)]
pub fn open_share_with_passkey(prf_secret: &[u8], sealed: &[u8]) -> Result<Vec<u8>, JsError> {
    open_impl(prf_secret, sealed).map_err(|e| JsError::new(&e))
}

/// Browser OPFS-store seam self-test: write bytes at `path` and read them back through
/// the signer's synchronous `durable` backend (OPFS sync handles in this Worker). The
/// Worker must `opfsPreopenWrite(path)` first. Proves wasm↔OPFS before the full store.
#[wasm_bindgen(js_name = opfsSelftest)]
pub fn opfs_selftest(path: &str, bytes: &[u8]) -> Result<Vec<u8>, JsError> {
    loki_signer_core::signer::opfs_selftest(path, bytes).map_err(|e| JsError::new(&e))
}

// ─── Phase A: the stateful profile-lifecycle signer ──────────────────────────
//
// `Signer` is a stateful wasm-bindgen object: it holds the unlocked device `Identity` in
// memory between `unlock` and `lock`, and persists ONLY its sealed form to OPFS. The
// device identity is `Identity::new(1)` — slot 1 as a placeholder; it is re-stamped to the
// real vault slot later when the signer joins a vault (DKG, Phase B). The at-rest files are
// a fixed, deterministic set under `loki/device/`, so the Worker can pre-open exactly the
// paths each op touches before the synchronous call (OPFS sync handles are acquired async):
//
//   createSigner  writes: identity.sealed, profile.json, (passphrase) kek.salt
//   hasSigner     reads:  identity.sealed
//   unlock        reads:  identity.sealed, profile.json, (passphrase) kek.salt
//   lock          no I/O
//
// `request()` (DKG/payment) is NOT here — it stays `SignerPending` in the TS layer (Phase B/C).

/// Sealed device identity: `SealedShare(identity.to_secret_bytes())` under the selected SE.
pub const IDENTITY_PATH: &str = "loki/device/identity.sealed";
/// Public profile metadata (the display name). Non-secret, plaintext JSON.
pub const PROFILE_PATH: &str = "loki/device/profile.json";
/// Argon2id salt for the passphrase KEK (passphrase custody only).
pub const SALT_PATH: &str = "loki/device/kek.salt";

/// The device file set the Worker pre-opens, as a JSON array, so the pre-open protocol has a
/// single source of truth shared with `signer-worker.js` instead of drifting constants.
#[wasm_bindgen(js_name = devicePaths)]
pub fn device_paths() -> String {
    serde_json::json!({
        "identity": IDENTITY_PATH,
        "profile": PROFILE_PATH,
        "salt": SALT_PATH,
    })
    .to_string()
}

/// Re-derive the custody KEK. `create` draws and persists a fresh passphrase salt (first
/// create); otherwise the salt is read back. Passkey tiers take the JS-released PRF secret.
///
/// Both tiers reduce to the identical 32-byte KEK that backs [`SoftwareSecureElement`]
/// (`WebAuthnSecureElement` is `from_kek(prf_kek(..))`, passphrase is `from_kek(derive(..))`),
/// so the stateful signer holds the KEK and seals every file — the device identity AND the
/// per-vault DKG files — under `SoftwareSecureElement::from_kek`, byte-identical to the
/// original custody element. Holding the KEK (not the raw passphrase/PRF) is what lets the
/// vault signer re-seal its share after the custody secret has been dropped.
fn custody_kek(
    method: &str,
    passphrase: Option<String>,
    prf_secret: Option<Vec<u8>>,
    create: bool,
) -> Result<[u8; 32], String> {
    match method {
        "passphrase" => {
            let pass = passphrase.ok_or("passphrase required for passphrase custody")?;
            let salt = if create {
                let s = fresh_kek_salt();
                opfs_put(SALT_PATH, &s, false)?; // fresh salt on every create
                s.to_vec()
            } else {
                opfs_get(SALT_PATH)?.ok_or("no KEK salt — this signer is not passphrase-backed")?
            };
            Ok(*loki_signer_core::seal_kdf::derive(&pass, &salt)
                .map_err(|_| "passphrase KEK derivation failed (salt too short?)".to_string())?)
        }
        "platform" | "roaming" => {
            let prf = prf_secret.ok_or("WebAuthn PRF secret required for passkey custody")?;
            Ok(prf_kek(&prf32(&prf)?))
        }
        other => Err(format!("unknown custody method: {other}")),
    }
}

fn profile_json(identity: &Identity, name: &str) -> String {
    serde_json::json!({
        "id": hex::encode(identity.public().signing),
        "name": name,
    })
    .to_string()
}

/// Stateful in-browser signer. Holds the unlocked device identity (and the custody KEK that
/// seals every file) only while unlocked, plus the active vault's DKG signer once joined.
#[wasm_bindgen]
pub struct Signer {
    identity: Option<Identity>,
    kek: Option<[u8; 32]>,
    vault: Option<VaultState>,
}

impl Default for Signer {
    fn default() -> Self {
        Self {
            identity: None,
            kek: None,
            vault: None,
        }
    }
}

#[wasm_bindgen]
impl Signer {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Signer {
        Signer::default()
    }

    /// True once a device identity is sealed in this browser → Unlock, not Create.
    /// The Worker must `opfsPreopenRead(IDENTITY_PATH)` first.
    #[wasm_bindgen(js_name = hasSigner)]
    pub fn has_signer(&self) -> bool {
        opfs_exists(IDENTITY_PATH)
    }

    /// Generate `Identity::new(1)`, seal it under the chosen custody element, and persist the
    /// sealed identity + profile (+ salt for passphrase) to OPFS. Returns the profile JSON
    /// `{id,name}`. The Worker must pre-open identity.sealed, profile.json (+ kek.salt) for
    /// write first. Refuses if a signer already exists here.
    #[wasm_bindgen(js_name = createSigner)]
    pub fn create_signer(
        &mut self,
        method: &str,
        name: &str,
        passphrase: Option<String>,
        prf_secret: Option<Vec<u8>>,
    ) -> Result<String, JsError> {
        self.create_impl(method, name, passphrase, prf_secret)
            .map_err(|e| JsError::new(&e))
    }

    /// Re-derive the custody element, open the sealed identity, and hold it in the session.
    /// Returns the profile JSON `{id,name}`. The Worker must pre-open the same paths for read.
    #[wasm_bindgen(js_name = unlock)]
    pub fn unlock(
        &mut self,
        method: &str,
        passphrase: Option<String>,
        prf_secret: Option<Vec<u8>>,
    ) -> Result<String, JsError> {
        self.unlock_impl(method, passphrase, prf_secret)
            .map_err(|e| JsError::new(&e))
    }

    /// Drop the in-memory identity, custody KEK and any active vault signer; the session
    /// ends. The sealed files stay on disk.
    #[wasm_bindgen(js_name = lock)]
    pub fn lock(&mut self) {
        self.identity = None;
        self.kek = None;
        self.vault = None;
    }

    /// Whether an identity is currently held unlocked in memory.
    #[wasm_bindgen(js_name = isUnlocked)]
    pub fn is_unlocked(&self) -> bool {
        self.identity.is_some()
    }

    // ─── Phase B: join-a-vault + DKG ─────────────────────────────────────────
    //
    // The audited DKG core (`Signer::dkg_begin/dkg_step/backup/release_address`) is
    // SYNCHRONOUS and message-in/out: it never owns a transport. These wasm methods drive a
    // real OPFS-backed `LocalSigner` through those four primitives; the async pump — frostd
    // fetch and the coordinator's roster HTTP — lives in the Worker (`signer-worker.js`),
    // which loops `vaultStep([])` ↔ frostd until `vaultReady()`. The device identity is
    // re-stamped to the vault slot on join (slot bytes overwritten, keys unchanged), exactly
    // like the native hosted `ceremony::identity` fix.

    /// The X25519 frostd login key for this device (secret + public, hex). The Worker builds
    /// the browser frostd transport from it; the public half is this member's relay address
    /// and must equal the `encryption` key the coordinator enrolled for the slot.
    #[wasm_bindgen(js_name = frostdLogin)]
    pub fn frostd_login(&self) -> Result<String, JsError> {
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| JsError::new("unlock the signer first"))?;
        let secret = identity.to_secret_bytes();
        Ok(serde_json::json!({
            "secret": hex::encode(&secret[34..66]),
            "pubkey": hex::encode(identity.public().encryption),
        })
        .to_string())
    }

    /// This member's public enrollment identity for the coordinator's public roster:
    /// `signing_pubkey` (the Ed25519 member identity) and `relay_pubkey` (= the X25519 frostd
    /// login pubkey, this member's relay address). Hex JSON. The browser POSTs these, plus a
    /// browser device key, to the coordinator's `/api/members` — a frostd-only member with no
    /// `advertise_url`. Unlock the signer first.
    #[wasm_bindgen(js_name = enrollMaterial)]
    pub fn enroll_material(&self) -> Result<String, JsError> {
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| JsError::new("unlock the signer first"))?;
        Ok(serde_json::json!({
            "signing_pubkey": hex::encode(identity.public().signing),
            "relay_pubkey": hex::encode(identity.public().encryption),
        })
        .to_string())
    }

    /// Authorize a browser device-login key (P-256 SEC1 uncompressed bytes, hex) with this
    /// member identity, using the same Ed25519 enrollment proof as the native self-registration
    /// (`Identity::authorize_device`). Returns the authorization signature (hex) the coordinator
    /// verifies before the device key's own signature over the registration transcript.
    #[wasm_bindgen(js_name = authorizeDevice)]
    pub fn authorize_device(&self, device_pub_hex: &str) -> Result<String, JsError> {
        let identity = self
            .identity
            .as_ref()
            .ok_or_else(|| JsError::new("unlock the signer first"))?;
        let device_pub = hex::decode(device_pub_hex).map_err(|e| JsError::new(&e.to_string()))?;
        Ok(hex::encode(identity.authorize_device(&device_pub)))
    }

    /// Create-or-reopen this member's vault signer, confirm the coordinator's roster, and
    /// begin DKG. Returns the `VaultRef` JSON. The Worker must pre-open `vaultPaths(vaultHex)`
    /// for write first. `roster` is the coordinator's setup document (`setup_version: 2`).
    #[wasm_bindgen(js_name = vaultJoin)]
    pub fn vault_join(
        &mut self,
        vault_hex: &str,
        slot: u16,
        label: &str,
        network: &str,
        roster: &[u8],
    ) -> Result<String, JsError> {
        self.vault_join_impl(vault_hex, slot, label, network, roster)
            .map_err(|e| JsError::new(&e))
    }

    /// Reopen this browser's signer for an existing vault, with no network input. Returns
    /// `{vault_id, slot, threshold, network, ready, members: [{id, signing, encryption}]}`
    /// from the roster this member confirmed at setup. The Worker must pre-open
    /// `vaultPaths(vaultHex)` first.
    #[wasm_bindgen(js_name = vaultOpen)]
    pub fn vault_open(&mut self, vault_hex: &str) -> Result<String, JsError> {
        self.vault_open_impl(vault_hex).map_err(|e| JsError::new(&e))
    }

    /// One DKG pass: feed the relayed peer wires (each hex `DkgWire` bytes the coordinator
    /// forwarded) into `dkg_step` and return this member's outgoing wires (hex), which the
    /// Worker sends to the coordinator. Call with `[]` on every poll tick to advance phases
    /// and re-emit saved outgoing bytes idempotently.
    #[wasm_bindgen(js_name = vaultStep)]
    pub fn vault_step(&mut self, in_wires: Vec<String>) -> Result<Vec<String>, JsError> {
        let vs = self
            .vault
            .as_mut()
            .ok_or_else(|| JsError::new("no active vault — call vaultJoin first"))?;
        let inputs: Vec<DkgInput> = in_wires
            .iter()
            .filter_map(|h| hex::decode(h).ok())
            .filter_map(|b| DkgInput::from_relay(b).ok())
            .collect();
        let wires = vs
            .signer
            .dkg_step(&vs.session, &vs.vref, &inputs)
            .map_err(|e| JsError::new(&format!("dkg_step: {e}")))?;
        Ok(wires.iter().map(|w| hex::encode(w.as_bytes())).collect())
    }

    /// Run the on-device backup once every certificate has matched, and return this member's
    /// signed backup receipt wires (hex) for the coordinator. `[]` means the vault is not yet
    /// ready for backup — the Worker retries on the next tick.
    #[wasm_bindgen(js_name = vaultBackup)]
    pub fn vault_backup(&mut self) -> Result<Vec<String>, JsError> {
        let vs = self
            .vault
            .as_mut()
            .ok_or_else(|| JsError::new("no active vault — call vaultJoin first"))?;
        match vs.signer.backup(&vs.session) {
            Ok(wires) => Ok(wires.iter().map(|w| hex::encode(w.as_bytes())).collect()),
            Err(SignerError::NotReady) => Ok(Vec::new()),
            Err(e) => Err(JsError::new(&format!("backup: {e}"))),
        }
    }

    /// True once every member's backup receipt has arrived and the vault is active.
    #[wasm_bindgen(js_name = vaultReady)]
    pub fn vault_ready(&self) -> Result<bool, JsError> {
        let vs = self
            .vault
            .as_ref()
            .ok_or_else(|| JsError::new("no active vault — call vaultJoin first"))?;
        let vaults = vs
            .signer
            .list_vaults(&vs.session)
            .map_err(|e| JsError::new(&format!("list_vaults: {e}")))?;
        Ok(vaults.first().map(|v| v.ready).unwrap_or(false))
    }

    /// The vault's receive address, once the vault is ready. Proves DKG completed: every
    /// member derives the identical address, which must match the coordinator's.
    #[wasm_bindgen(js_name = vaultAddress)]
    pub fn vault_address(&mut self) -> Result<String, JsError> {
        let vs = self
            .vault
            .as_mut()
            .ok_or_else(|| JsError::new("no active vault — call vaultJoin first"))?;
        Ok(vs
            .signer
            .release_address(&vs.session)
            .map_err(|e| JsError::new(&format!("release_address: {e}")))?
            .address)
    }

    // ─── Phase C: review + approve a payment (NON-proposer signer) ───────────────
    //
    // The audited payment seam (`Signer::sign_commit/sign_approve`, `wysiwys::describe_pczt/
    // sighash_of_pczt`) is SYNCHRONOUS and message-in/out: it never owns a transport. These
    // wasm methods drive the active vault's `LocalSigner` through them; the async frostd pump
    // (`drivePayment` in signer-worker.js) carries the signing-round messages. The browser
    // member REVIEWS + APPROVES only — the proposer/builder assembles and seals the candidate
    // (out of scope here). WYSIWYS is enforced inside `signApprove`: it re-renders the
    // candidate, recomputes the sighash, and REFUSES unless the signing package commits to
    // that exact sighash, BEFORE the nonce/share is touched.

    /// WYSIWYS render of a candidate PCZT (hex): the facts this member would sign, derived
    /// from the bytes with the vault viewing key, plus the independently recomputed sighash.
    /// Releases NO secret and touches no nonce. Returns JSON
    /// `{recipient, amount_zat, fee_zat, change_zat, memo, network_branch_id, fee_verified,
    /// sighash}` (recipient/memo/sighash hex; amounts decimal strings). Reopen the vault
    /// (`vaultJoin`) first. Errors on an unparseable/invalid candidate.
    #[wasm_bindgen(js_name = paymentReview)]
    pub fn payment_review(&self, candidate_hex: &str) -> Result<String, JsError> {
        self.payment_review_impl(candidate_hex).map_err(|e| JsError::new(&e))
    }

    /// Round 1: the PUBLIC signing commitment for `attempt_hex` (hex). The secret nonce is
    /// persisted crash-safe to OPFS and never returned. The Worker must pre-open this attempt's
    /// `nonces/<id>.nonce` + `.burn` paths first. Reopen the vault first.
    #[wasm_bindgen(js_name = signCommit)]
    pub fn sign_commit(&mut self, attempt_hex: &str) -> Result<String, JsError> {
        self.sign_commit_impl(attempt_hex).map_err(|e| JsError::new(&e))
    }

    /// Open a candidate the `proposer` signer sealed to this member over frostd for this
    /// attempt. Returns the unsigned candidate PCZT (hex) to review + approve. `signers_csv`
    /// is the comma-separated slot list the proposer sealed under (sorted internally to match).
    /// No share is released here. Reopen the vault first.
    #[wasm_bindgen(js_name = openCandidate)]
    pub fn open_candidate(
        &self,
        proposer_signing_hex: &str,
        proposer_enc_hex: &str,
        proposer_id: u16,
        signers_csv: &str,
        attempt_hex: &str,
        wire_hex: &str,
    ) -> Result<String, JsError> {
        self.open_candidate_impl(
            proposer_signing_hex,
            proposer_enc_hex,
            proposer_id,
            signers_csv,
            attempt_hex,
            wire_hex,
        )
        .map_err(|e| JsError::new(&e))
    }

    /// Open a message a vault member sealed to this one on a payment's frostd control session
    /// (`session_id`, a UUID). `from_hex` is the frostd sender; the sender's identity comes from
    /// the roster this member confirmed at setup, so a non-member's message is refused.
    /// Returns `{from, body}`: the sender's member id and the message body (JSON text).
    #[wasm_bindgen(js_name = openControl)]
    pub fn open_control(&self, session_id: &str, from_hex: &str, wire_hex: &str) -> Result<String, JsError> {
        self.open_control_impl(session_id, from_hex, wire_hex)
            .map_err(|e| JsError::new(&e))
    }

    /// Seal a control message (`body_json`) from this member to member `to` on the payment
    /// control session `session_id`, under the roster confirmed at setup. Returns the wire (hex)
    /// to send to that member's relay key.
    #[wasm_bindgen(js_name = sealControl)]
    pub fn seal_control(&self, session_id: &str, to: u16, body_json: &str) -> Result<String, JsError> {
        self.seal_control_impl(session_id, to, body_json)
            .map_err(|e| JsError::new(&e))
    }

    /// Round 2: the PUBLIC signature share for `attempt_hex` (hex). INDEPENDENTLY re-renders
    /// the candidate, recomputes its sighash, and REFUSES unless `package_hex` commits to that
    /// exact sighash — before the nonce/share is touched (WYSIWYS). `candidate_hex` is the
    /// opened candidate, `seed_hex` the 32-byte rerandomizer seed. Reopen the vault first.
    #[wasm_bindgen(js_name = signApprove)]
    pub fn sign_approve(
        &mut self,
        attempt_hex: &str,
        candidate_hex: &str,
        package_hex: &str,
        seed_hex: &str,
    ) -> Result<String, JsError> {
        self.sign_approve_impl(attempt_hex, candidate_hex, package_hex, seed_hex)
            .map_err(|e| JsError::new(&e))
    }
}

/// The active vault's DKG signer, held while a join/DKG is in flight (and after, until lock).
struct VaultState {
    signer: LocalSigner<SoftwareSecureElement>,
    session: Session,
    vref: VaultRef,
}

/// The vault signer's data directory in OPFS. The `LocalSigner` store owns
/// `signer.meta`/`identity`/`roster`/`setup`/`share.sealed` + `nonces/` here; `OpfsBackup`
/// owns `backup.sealed` beside them.
fn vault_dir(vault_hex: &str) -> String {
    format!("loki/vaults/{vault_hex}/signer")
}

/// The deterministic file set the Worker pre-opens (for write) before a DKG call, mirroring
/// `devicePaths()`. Write handles are read-capable too, so one set covers reads and writes.
#[wasm_bindgen(js_name = vaultPaths)]
pub fn vault_paths(vault_hex: &str) -> String {
    let dir = vault_dir(vault_hex);
    serde_json::json!([
        format!("{dir}/signer.meta"),
        format!("{dir}/identity.sealed"),
        format!("{dir}/roster.sealed"),
        format!("{dir}/setup.sealed"),
        format!("{dir}/share.sealed"),
        format!("{dir}/backup.sealed"),
    ])
    .to_string()
}

/// OPFS-backed [`BackupDevice`]: the in-ceremony backup `LocalSigner::backup` saves and
/// re-loads to prove it persisted. It is sealed under a KEK-derived passphrase; the separate
/// HPKE-to-recovery-words backup (lost-device restore) is a later phase.
struct OpfsBackup {
    path: String,
    pass: Zeroizing<String>,
}

impl BackupDevice for OpfsBackup {
    fn passphrase(&mut self) -> Option<Zeroizing<String>> {
        Some(self.pass.clone())
    }
    fn save(&mut self, artifact: &BackupArtifact) -> Result<(), String> {
        if opfs_exists(&self.path) {
            return Ok(());
        }
        opfs_put(&self.path, &artifact.0, true)
    }
    fn load(&mut self) -> Result<BackupArtifact, String> {
        Ok(BackupArtifact(
            opfs_get(&self.path)?.ok_or("no stored backup")?,
        ))
    }
}

/// The browser signer's device prompts for the vault in `dir`.
fn browser_prompts(dir: &str, kek: [u8; 32]) -> DevicePrompts {
    DevicePrompts {
        connect: Box::new(|_origin, _net| true),
        // The web coordinator already drove this member's roster agreement.
        roster: Box::new(|_code| RosterDecision::Match),
        roster_deadline: Duration::from_secs(60),
        backup: Box::new(OpfsBackup {
            path: format!("{dir}/backup.sealed"),
            pass: Zeroizing::new(hex::encode(kek)),
        }),
        approval: Box::new(|_request| true),
    }
}

fn parse_network(s: &str) -> Result<Network, String> {
    match s {
        "regtest" => Ok(Network::Regtest),
        "testnet" => Ok(Network::Testnet),
        other => Err(format!("unknown network: {other}")),
    }
}

/// Re-stamp a device identity to a vault slot: overwrite the 2 id bytes, keep the keys.
fn restamp(identity: &Identity, slot: u16) -> Result<Identity, String> {
    let mut secret = identity.to_secret_bytes();
    secret[..2].copy_from_slice(&slot.to_be_bytes());
    Identity::from_secret_bytes(&secret)
}

fn vault_ref_json(v: &VaultRef) -> String {
    serde_json::json!({
        "vault_id": hex::encode(v.vault_id),
        "label": v.label,
        "threshold": v.threshold,
        "members": v.members,
        "ready": v.ready,
    })
    .to_string()
}

fn hex32(s: &str) -> Result<[u8; 32], String> {
    hex::decode(s)
        .map_err(|e| e.to_string())?
        .try_into()
        .map_err(|_| "expected 32 bytes of hex".to_string())
}

impl Signer {
    /// This payment's candidate reference. The native host uses `payment_id == attempt_id ==
    /// attempt`, which also fixes the crash-safe nonce file name; mirror it.
    fn candidate_ref(&self, attempt_hex: &str) -> Result<(CandidateRef, [u8; 32]), String> {
        let vs = self.vault.as_ref().ok_or("no active vault — call vaultJoin first")?;
        let attempt = hex32(attempt_hex)?;
        Ok((
            CandidateRef {
                vault_id: vs.vref.vault_id,
                payment_id: attempt,
                attempt_id: attempt,
            },
            vs.vref.vault_id,
        ))
    }

    fn payment_review_impl(&self, candidate_hex: &str) -> Result<String, String> {
        let vs = self.vault.as_ref().ok_or("no active vault — call vaultJoin first")?;
        let (_, fvk) = vs.signer.hosted_metadata().map_err(|e| e.to_string())?;
        let bytes = hex::decode(candidate_hex).map_err(|e| e.to_string())?;
        let view = describe_pczt(&bytes, &fvk)?;
        let sighash = sighash_of_pczt(&bytes, &fvk)?;
        Ok(serde_json::json!({
            "recipient": hex::encode(view.to),
            "amount_zat": view.amount_zat.to_string(),
            "fee_zat": view.fee_zat.to_string(),
            "change_zat": view.change_zat.to_string(),
            "memo": hex::encode(view.memo),
            "network_branch_id": view.network_branch_id,
            "fee_verified": view.fee_verified,
            "sighash": hex::encode(sighash),
        })
        .to_string())
    }

    fn sign_commit_impl(&mut self, attempt_hex: &str) -> Result<String, String> {
        let (cand, _) = self.candidate_ref(attempt_hex)?;
        let vs = self.vault.as_mut().ok_or("no active vault — call vaultJoin first")?;
        let commit = vs.signer.sign_commit(&vs.session, &cand).map_err(|e| e.to_string())?;
        commit.serialize().map(hex::encode).map_err(|e| e.to_string())
    }

    fn open_candidate_impl(
        &self,
        proposer_signing_hex: &str,
        proposer_enc_hex: &str,
        proposer_id: u16,
        signers_csv: &str,
        attempt_hex: &str,
        wire_hex: &str,
    ) -> Result<String, String> {
        let vs = self.vault.as_ref().ok_or("no active vault — call vaultJoin first")?;
        let proposer = PublicIdentity {
            id: proposer_id,
            signing: hex32(proposer_signing_hex)?,
            encryption: hex32(proposer_enc_hex)?,
        };
        let mut signers: Vec<u16> = signers_csv
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| s.parse::<u16>().map_err(|e| e.to_string()))
            .collect::<Result<_, _>>()?;
        signers.sort_unstable();
        let attempt = hex32(attempt_hex)?;
        let context = SessionContext {
            vault: vs.vref.vault_id,
            payment: attempt,
            attempt: AttemptId(attempt),
            signers,
        };
        let wire = hex::decode(wire_hex).map_err(|e| e.to_string())?;
        let bytes = vs
            .signer
            .open_candidate(&proposer, &context, &wire)
            .map_err(|e| e.to_string())?;
        Ok(hex::encode(bytes))
    }

    fn open_control_impl(&self, session_id: &str, from_hex: &str, wire_hex: &str) -> Result<String, String> {
        let vs = self.vault.as_ref().ok_or("no active vault — call vaultOpen first")?;
        let session = uuid::Uuid::parse_str(session_id).map_err(|e| e.to_string())?;
        let wire = hex::decode(wire_hex).map_err(|e| e.to_string())?;
        let (from, body) = vs
            .signer
            .open_control(session, &hex32(from_hex)?, &wire)
            .map_err(|e| e.to_string())?;
        let body = String::from_utf8(body).map_err(|e| e.to_string())?;
        Ok(serde_json::json!({ "from": from, "body": body }).to_string())
    }

    fn seal_control_impl(&self, session_id: &str, to: u16, body_json: &str) -> Result<String, String> {
        let vs = self.vault.as_ref().ok_or("no active vault — call vaultOpen first")?;
        let session = uuid::Uuid::parse_str(session_id).map_err(|e| e.to_string())?;
        let sealed = vs
            .signer
            .seal_control(session, to, body_json.as_bytes())
            .map_err(|e| e.to_string())?;
        Ok(hex::encode(sealed))
    }

    fn sign_approve_impl(
        &mut self,
        attempt_hex: &str,
        candidate_hex: &str,
        package_hex: &str,
        seed_hex: &str,
    ) -> Result<String, String> {
        let (cand, _) = self.candidate_ref(attempt_hex)?;
        let candidate = hex::decode(candidate_hex).map_err(|e| e.to_string())?;
        let package = frost::SigningPackage::deserialize(
            &hex::decode(package_hex).map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let seed = hex32(seed_hex)?;
        let vs = self.vault.as_mut().ok_or("no active vault — call vaultJoin first")?;
        let share = vs
            .signer
            .sign_approve(&vs.session, &cand, &candidate, &package, &seed)
            .map_err(|e| e.to_string())?;
        Ok(hex::encode(share.serialize()))
    }

    fn vault_open_impl(&mut self, vault_hex: &str) -> Result<String, String> {
        let kek = self.kek.ok_or("unlock the signer first")?;
        let me = self.identity.as_ref().ok_or("unlock the signer first")?.public().encryption;
        let dir = vault_dir(vault_hex);
        if !opfs_exists(&format!("{dir}/signer.meta")) {
            return Err("this browser holds no signer for that vault".into());
        }
        let mut signer = LocalSigner::open(
            std::path::Path::new(&dir),
            SoftwareSecureElement::from_kek(kek),
            "vault".into(),
            browser_prompts(&dir, kek),
        )
        .map_err(|e| e.to_string())?;
        let net = signer.network();
        let session = signer
            .connect("https://coordinator", net, b"browser vault")
            .map_err(|e| e.to_string())?
            .session;
        let vref = signer
            .list_vaults(&session)
            .map_err(|e| e.to_string())?
            .into_iter()
            .next()
            .ok_or("this vault's setup has not started")?;
        let roster = signer.confirmed_roster().ok_or("this vault has no confirmed roster")?;
        let slot = roster
            .members
            .values()
            .find(|m| m.encryption == me)
            .ok_or("this signer is not a member of that vault")?
            .id;
        let members: Vec<_> = roster
            .members
            .values()
            .map(|m| {
                serde_json::json!({
                    "id": m.id,
                    "signing": hex::encode(m.signing),
                    "encryption": hex::encode(m.encryption),
                })
            })
            .collect();
        let out = serde_json::json!({
            "vault_id": hex::encode(vref.vault_id),
            "slot": slot,
            "threshold": roster.threshold,
            "network": roster.network.label(),
            "ready": vref.ready,
            "members": members,
        })
        .to_string();
        self.vault = Some(VaultState { signer, session, vref });
        Ok(out)
    }

    fn vault_join_impl(
        &mut self,
        vault_hex: &str,
        slot: u16,
        label: &str,
        network: &str,
        roster: &[u8],
    ) -> Result<String, String> {
        let kek = self.kek.ok_or("unlock the signer first")?;
        let identity = self.identity.as_ref().ok_or("unlock the signer first")?;
        let vault_id: [u8; 32] = hex::decode(vault_hex)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "vault id must be 32 bytes of hex".to_string())?;
        let net = parse_network(network)?;
        let stamped = restamp(identity, slot)?;
        let dir = vault_dir(vault_hex);
        let se = SoftwareSecureElement::from_kek(kek);
        let prompts = browser_prompts(&dir, kek);
        let path = std::path::Path::new(&dir);
        let mut signer = if opfs_exists(&format!("{dir}/signer.meta")) {
            LocalSigner::open(path, se, label.to_string(), prompts)
        } else {
            LocalSigner::create_with_identity(
                path,
                se,
                net,
                vault_id,
                slot,
                label.to_string(),
                prompts,
                stamped,
            )
        }
        .map_err(|e| e.to_string())?;
        let connection = signer
            .connect("https://coordinator", net, b"browser dkg")
            .map_err(|e| e.to_string())?;
        let session = connection.session;
        let existing = signer.list_vaults(&session).map_err(|e| e.to_string())?;
        let vref = if existing.is_empty() {
            signer
                .dkg_begin(&session, roster)
                .map_err(|e| e.to_string())?
        } else {
            existing.into_iter().next().expect("non-empty")
        };
        let out = vault_ref_json(&vref);
        self.vault = Some(VaultState {
            signer,
            session,
            vref,
        });
        Ok(out)
    }

    fn create_impl(
        &mut self,
        method: &str,
        name: &str,
        passphrase: Option<String>,
        prf_secret: Option<Vec<u8>>,
    ) -> Result<String, String> {
        if opfs_exists(IDENTITY_PATH) {
            return Err("a signer already exists in this browser".into());
        }
        let kek = custody_kek(method, passphrase, prf_secret, true)?;
        let se = SoftwareSecureElement::from_kek(kek);
        let identity = Identity::new(1);
        let secret = identity.to_secret_bytes();
        let sealed = SealedShare::seal(&se, 0, &secret)?;
        opfs_put(IDENTITY_PATH, &sealed.to_bytes(), true)?; // write-once
        opfs_put(PROFILE_PATH, profile_json(&identity, name).as_bytes(), false)?;
        let out = profile_json(&identity, name);
        self.kek = Some(kek);
        self.identity = Some(identity);
        Ok(out)
    }

    fn unlock_impl(
        &mut self,
        method: &str,
        passphrase: Option<String>,
        prf_secret: Option<Vec<u8>>,
    ) -> Result<String, String> {
        let kek = custody_kek(method, passphrase, prf_secret, false)?;
        let se = SoftwareSecureElement::from_kek(kek);
        let raw = opfs_get(IDENTITY_PATH)?.ok_or("no signer in this browser — create one first")?;
        let secret = SealedShare::from_bytes(&raw)?.open(&se)?;
        let identity = Identity::from_secret_bytes(&secret)?;
        self.kek = Some(kek);
        let name = opfs_get(PROFILE_PATH)?
            .and_then(|b| serde_json::from_slice::<serde_json::Value>(&b).ok())
            .and_then(|v| v.get("name").and_then(|n| n.as_str()).map(|s| s.to_string()))
            .unwrap_or_else(|| "You".to_string());
        let out = profile_json(&identity, &name);
        self.identity = Some(identity);
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    // Repro of the browser approver's post-message signing path that panicked live: render +
    // recompute-sighash of a real candidate PCZT. Fixture dumped from a native dealer vault.
    const CANDIDATE_HEX: &str = "50435a54020000000698ed92c40ddbac94bd0301008009010000000100000000010000000000000000000000000000000000000000000000000000000000000000000102015c2b08f6b99c91e8e05bc36d9331c4b2e1bb76aba2c320e46274a826c09ab83b018183dc4afdfa1e06f2b949edf3c02bb83d546168327ea5d0f6a66ae20906a3220181ae52a0c6e38631987a4b019191de61179929706c0aa8a8754580563cd57e0d0001b4859a5cd871081c2e1f900b7602861cf689ec0e0e0dfa429228cbc14a221f3b6ed8d0c0c94b3a0a21959a01c0fc82aa02010101010101010101010101010101010101010101010101010101010101010101010202020202020202020202020202020202020202020202020202020202020202016f5b47426a1736e8b211c04c923c7f87698a403412b9e7e6e3cca56035b4973f18c5cd0dcf61488eec0ce2981deaa3343f36606137da78739171664d4dde5e37ca728c87a618c1082ca7f43989c8a4c4260d212f706886e30f120b588018463a0001dd5eacc8e21a886a41ff31d2ba73f188c827f47fff093e51373b97a6390eb209000000016aaac0b071c902f81ad053322535a7394d44839a353c342d9ce33501815ef1089b723e9d7fb3102378fdde39f8e0ec5118f299f30d4c8ee707364eefc706fa8400c4049eb46b7f7866a1c6532ce4e464d08e278c78e3a127daa3e603ad5bb0f73a274361d6a6b0403947e78a6134679c1bddd987b808489f383639acd9fe10ddda8c9089b9c14a5aad080fbcf82e5b5334e393779ece9e4c90b39f67d16b44f4e1cf4ff1fecb224dda4bdd44b92d8b9cb4a40cdb37d237470d86e4724bec4b92788e1747634eaaf33370f658af7b99446d7489c0b9cd374b9978c7c8da9a890e89e5b05564106b142d6ad0b9f3cdb8b2bd34daa107a7bb5bbe70b8776f09b8fe22a4ada3b0781b246ade2992649513e8a93743a6fa741241b248a77c56f8f5d8967ab17db34a4ca070f84fde75730082429e2bb8c180538295b5b9b845edfa219c0e34fe2401fc716a47406fff539381a11890ae39e0fa71e725ed616487408adcbf90f8730536716e55ee07d801ac61857adcafd96671b8729a74dd8643cba69d5af927275bf67a58e3ae249c58011436a7ea1c55e789518bc88808e0b438263a58c0cc276868c8a13bb060123fcb08ed723ef7aca8cba056abe8ee8f7ab69e4728b892c69ba15607e2840a21da6770092d7375e757ac36ae238bd7f609d8b023983a5305e0eb18532b585e03917aadbc1ecc12ac5baf9263c517587d69783863a8b282e5012015f168a7f4b79c4ae3324b76ae755b3e73d7c2d40e77b32df2edb1c9829f67110c125f0cfb54318b07f51b821465f6941fb531e92314a1771e48d40ae4b0e517da53883f9d9cfa3d28ed350a2abc7b73ae14f846dfd27e8087d2faaa6998b23db2abb39542c4faa981e59bb357396b293964d9c6d047640524ab262ca9fce8c35001d57d337509d84dd3db799ad3d4c632407c94e6fcefced0eed856f7719e3e712847bf40c9391c22b47907cdc000a0443a178443e469806dcf34d4558109b0c93b7627de1919ec060b486938c568554a0132452ece66910908921f4a55e35dcb88d16257cbbd86d7a4ca3e554aad8afa84670a3a1cafc5638a89beb001b0faf896020117088f6c65a962f897a82129712a98a295a646adb533af9d3efc75cf70af2c3c0000000001cb5ead2f0b21c1e5afa6257ffd47594ea1d93569b07c81cc40645d9addb2ca2001af34cabeea8ef9c8a7d2b5bed819923163bc40f1378af8ab62ea2f91c048d73401dfb51768c5a344e46b7509e27dc9e3363913dbfb1993e3aebe5c7dd55088d00001cc81f56467d96b3bebf8aa8491c17a0677cd92ca7c1ba45cbb2c274e15ded08d01527a16cd43084f245f66b54642532ac4415dd70614b30d558dd66ab6716cd98fe945fbf14fb086466ca75daff959fa5771b633c70fb01ddc39688e422f28b9140110a413bf94a727fe6eb7b3595cf1cf58bc1316229e8ab0bda996dec4233f98f0a2e3ba849098f9915bd124010001a76e2245b2668050ef16f541cacb4fe415c7cacedcfdec7a4d7de5966173403701d12324a9a342980013e2e704c7ef18d69939dc885d94a6558af06b89a85839d8016685f198a38ba86b8ed39aabe8ae8e7cb6c5721eea72108bede1c6a6401c733c68868b870439da5569c46a6c1317e73948edf61d53319371bc018ed2d426e62b81d6c08cd18fa46f09673ec059a6df1b5bdb88946e12015234dd3eec4d549a3401e1d3b1cb05aac213a5554247f930ad7cf035cff899d20c7444d7914dba50534c19eaa06d1097622ce7d229a2c29404fcbc79d29a0f4557f58807d29458535c9ed5cf74e13faa91bde886412f6ff81049fd0fbca55868d777539b6cc04ce3bff39889be28234d6f245eb852f5e97286f06e881677f8de6cbd7e2a6654bbb1420f5112b5ac0e0e6c58b8500ba776754b561b3530f47f3dfbad30d5f6dbcf06d2fc97d31ea8221f01d8f48c69c6de2506fdf07c57ed04f3be543ae18173a66dad07c026a792043f87c235275ef14821e5592a8aa3d7825f9641cef63e59249199f7cef880570848e5391b72cc1763ea7a171754b95edeae02971e4365a7ab6e19cd7103f2aa3c99747eea7890376fdd40df7e359ccda78829898c2ffa35919be4476aedb2a82a11fd1e4f79dc39a6ba909716164b498e4b674586e8dc5a8ba9edfc3459e0ef0ea70959085d5d0738641e5f25fecbac293fead8b05e75680f1b0e510e3008471fa0b43d2efb24495c0d30f6309f0943be5e4c97079078b57a19040c82ff98e5252fdb13294a1d9b30a63298123882e999d0995303880622659557d523ea980f12c09e4fe24562baf552c9781979fc0ab16bb301772bc7aa6afa923279bf520f24bd8292e1192e1bde41e780e8310a2909171e487d182e1178eed42f7d8b2f9c267bf170839b58b900455f41ccca87f65c912eeba6d562aaaaaa2059569e53be09e5d607cd2ac28fbaa837368df67c4eaeb603bce36a5f30381b4c5aad0b98a407e0fbe00347c08b07d3e61a72aeaed2723d44afbf35d070f2ef49105fdbd73c3afd03943bf23d3d80ac52d1f1439eef01bde21295a13fb600f00481c8cba1eb0718a1ca9a66958f2f44628744b3dfb0e9e222b4ce8e3193235602b0b139c637187af8e972637da0c82a374e46eb6bf5a9176c3dbb2ac482d0d2eeef0d186f243cdfd8d14aae595048d2f2df335156981ff30a0594a74c71f7df21cbc79b574912f092498340ae1ee0f8315873c0f335f358879d95de92153db82679d6dbd5941368b431ee71297347f6f684fd9d2b8e34af348858f0ec2067b3849011b3c36f1db7e15d4e3c3652a452dc2db10b87e489287943efe67da12ab6510ddd6ef11a3d6c16d049c6539b53f05ef6840188f239dc1e5f2865e295e77af4033416ec930221016b89167d7f780e151b0995f3d742d348e3d6bdb566f6eb7ec9358e4df801ddd832eaf606e448188f6bee47ed37823306f2bb6319520d044d51f1effaa20bf465d19332e094facb71a9097fe9c8b9f45cd1bdc0ff1aac76c49c55590c591844dfd3d1ae94ddd0693138f92d89ed7baef6b01d973fae0404e2aa1b518e2f23c72ffcb8055713487417419e8af75e16ee70695943434fba69522bcc2af7bc3c19f1e2207ea5068ac7e1b9fdad92d2c18bf5553cab1990e9a9fea9e95788220e01f9f637460dc2859c171b9ccbf2e9d49744465174404441bc34af2449372c3f0600000001d85682fb8c88d5f6ae464fd5acc37c74a1d64960bcf6186201886adc98b1ea1c14841398177f00fb3278d90b0fe6b97ff1ff0df90ce22869240432d4c605120700c404ce98a0a8bfa21346d6ba9d4efa56d8763ba000ebe48b32110f8844b91a0113f4f35ca4059e5ee14a1a2e12b6522e9f291465a86cc596ae8e9438325d2b75d4e1cd04d20ebac9db3823541ac36baf0733e07c10c2860661bbdc7e65908820b94972688648db283b7044f1c1c49577801527f6dffed053095c7ddfe291168d80228c3aeb45598384cde6ebc6cd0d9fdbc31de34052e514dcaf2ca2668c9e323597064dae0a5ac2f8a86df62e48f52f475e3852315947386a2cb80abf66d281ee18c0dfb426093ace6a97b1b53de57489b84c777f52ef064bedfdc341ce5e7807a38022526e1881e384291eb1635674189f95404c3055a51341159bcc30ed6248befa852ef3d32e517b3df38a83801a854754dbc2f64882762ff66b449279f9d402cdb04776378bbbc197a33de4138c50704f0f2be738162185177335c17a21ac2baf31455566d81cc1793e022362408f13f3e4b10311db2e175a7cd082a213922d9e3868fb1c7293543e93aadd457792a8aa3a47d672e7593e6b0ff9d469c039b13569c6515878656e1dd7d6f259900f82d3fad904893f6f5c3d088351752458108d4242a5c6e8c046bf6dd7a9b3d1e259ffe7db7efb35e330a74e591274c8ef5f4b30921ce409ef889494dff5ade225f4cd80b617f1159635f9e375e489fa1b09602d47e614d778f09c75886997cc57e0ea4d208f7087e2eb04095d25023799bbebd7eb210405285913ab61d66244aecd3aea556b09ac7762abc86895458790f2450f4191322336071584f7de8c1deb873fca04646b55e9d1427caf16fbe04036dc36d15b506e6a998ad8510f92fe89ce68ae38e9a15d744ff1436375eddd4135e62810ee4c4b457916f5b9f5cf14d2ab940ec3f3bf141b80210aeac2b5ed6dd466519167eda9f0bf976e108492cc9ada2f4c3210c201e2d15cb4e254a54a1fa7eff6f7cded3b3aaefdade66050a6b340a25b611e1cf27a47fc4c608738eb2d70390180b489130131fb120b23f891b76f36c712463434f498487485c756d054bc13d7ef3d3e240600000000014db58c86ea90a5c93ecf5877654ab27ae0cf60bcd04165e422d2d94fec68e73307904e000001000117143ab6d4c61f2311cde9ec66f9c4a681a9962581bee6b0633637eac91bb214";
    const FVK_HEX: &str = "6f5b47426a1736e8b211c04c923c7f87698a403412b9e7e6e3cca56035b4973f18c5cd0dcf61488eec0ce2981deaa3343f36606137da78739171664d4dde5e37ca728c87a618c1082ca7f43989c8a4c4260d212f706886e30f120b588018463a";

    #[wasm_bindgen_test]
    fn repro_describe_and_sighash_candidate() {
        let cand = hex::decode(CANDIDATE_HEX).unwrap();
        let fvk_bytes: [u8; 96] = hex::decode(FVK_HEX).unwrap().try_into().unwrap();
        let fvk = orchard::keys::FullViewingKey::from_bytes(&fvk_bytes).unwrap();
        let _ = describe_pczt(&cand, &fvk).unwrap();
        let _ = sighash_of_pczt(&cand, &fvk).unwrap();
    }

    #[wasm_bindgen_test]
    fn prf_seal_open_round_trips_and_rejects_wrong_secret() {
        let prf = [7u8; 32];
        let share = b"a FROST signing share worth forging";

        let sealed = seal_impl(&prf, 2, share).unwrap();
        // Same passkey re-derives the KEK and reopens byte-identical.
        assert_eq!(open_impl(&prf, &sealed).unwrap(), share);
        // A different PRF secret cannot open it.
        assert!(open_impl(&[8u8; 32], &sealed).is_err());
        // A short secret is rejected before any crypto.
        assert!(seal_impl(&[0u8; 16], 0, share).is_err());
    }
}
