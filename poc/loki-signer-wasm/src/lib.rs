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
// `signer` feature forces `transparent`), but the Orchard FROST signer never calls it. Its
// C preallocated-context functions are left as `env` module imports by the wasm build (no
// WASI C toolchain compiles the C here), and a browser can't resolve a bare `env` specifier.
// Define the three dead symbols so the linker satisfies them in-module instead — no `env`
// import, no WASI toolchain, no fork of the vendored crypto. They are never called; if that
// ever changes, a null context makes the first real use fail loudly rather than silently.
#[cfg(target_arch = "wasm32")]
mod secp256k1_link_stub {
    use core::ffi::{c_uint, c_void};
    #[no_mangle]
    pub extern "C" fn rustsecp256k1_v0_10_0_context_preallocated_size(_flags: c_uint) -> usize {
        0
    }
    #[no_mangle]
    pub extern "C" fn rustsecp256k1_v0_10_0_context_preallocated_create(
        _prealloc: *mut c_void,
        _flags: c_uint,
    ) -> *mut c_void {
        core::ptr::null_mut()
    }
    #[no_mangle]
    pub extern "C" fn rustsecp256k1_v0_10_0_context_preallocated_destroy(_ctx: *mut c_void) {}
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
        let prompts = DevicePrompts {
            connect: Box::new(|_origin, _net| true),
            // The web coordinator already drove this member's roster agreement.
            roster: Box::new(|_code| RosterDecision::Match),
            roster_deadline: Duration::from_secs(60),
            backup: Box::new(OpfsBackup {
                path: format!("{dir}/backup.sealed"),
                pass: Zeroizing::new(hex::encode(kek)),
            }),
            approval: Box::new(|_request| true),
        };
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
