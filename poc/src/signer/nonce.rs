//! Crash-safe single-use nonce state machine (ws1-signer §8).
//!
//! Distilled from the live `signing_session` rules (persist-before-emit in round 1:
//! `begin_sealed` -> `save_nonces`; atomic burn+emit in round 2: `decide('R')` then
//! `remove_nonces` then `sign`). Here the same discipline is isolated to one FROST
//! nonce so the crash-injection and reuse tests have no relay/courier machinery around
//! them.
//!
//! On disk, per nonce id, at most these files exist, written with fsync + atomic rename:
//! - `<id>.nonce`  : the sealed secret nonce  (round 1, persisted BEFORE the commitment
//!                   is emitted)
//! - `<id>.burn`   : the burn+partial record  (round 2, the nonce file is removed in the
//!                   SAME durable step the partial is recorded)
//!
//! A crash leaves exactly one of three states:
//! - neither file            -> nonce never committed; nothing stranded.
//! - `.nonce` only           -> committed, not yet used; safe to reuse-for-the-same-msg
//!                              or abandon. Reuse for a DIFFERENT message is HARD-REFUSED.
//! - `.burn` only (or both)  -> burned+emitted; the recorded partial is resent verbatim,
//!                              the nonce is never reused.
//!
//! "burned but lost" is impossible: the partial is in `.burn` before `.nonce` is removed,
//! and `.burn` is fsync'd before the removal.
//!
//! Hosted signers additionally require two external nonce witnesses. Their pins are sealed
//! with the nonce before publication; a fresh claim is required before computing a share.
//! Restoring local nonce/burn/journal files cannot restore the witnesses' consumed claims.

use crate::signer::durable::write_durable;
use crate::signer::secure_element::{SealedShare, SecureElement};
use crate::signing_session::{NonceWitness, WitnessPins};
use reddsa_frost::frost::redpallas as frost;
use std::{
    fs, io,
    path::{Path, PathBuf},
    sync::Mutex,
};
use zeroize::Zeroizing;

/// Hard error distinguishing a benign retry from a security-fatal reuse.
#[derive(Debug, PartialEq, Eq)]
pub enum NonceError {
    /// The same nonce id was asked to sign a DIFFERENT message than it burned for.
    /// FROST security breaks on nonce reuse; this is never recoverable.
    Reuse,
    /// A nonce committed under an earlier backup/nonce epoch was presented after a
    /// restore bumped the epoch (ws1-signer §8: "restore resets to a fresh nonce
    /// epoch and must not replay an old one"). Never recoverable — the member must
    /// re-commit under the current epoch.
    StaleEpoch,
    Io(String),
    Other(String),
}

impl std::fmt::Display for NonceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NonceError::Reuse => write!(f, "HARD REFUSE: nonce reuse for a different message"),
            NonceError::StaleEpoch => write!(
                f,
                "HARD REFUSE: nonce from a pre-restore epoch (replay across restore)"
            ),
            NonceError::Io(e) => write!(f, "nonce io: {e}"),
            NonceError::Other(e) => write!(f, "{e}"),
        }
    }
}

impl From<io::Error> for NonceError {
    fn from(e: io::Error) -> Self {
        NonceError::Io(e.to_string())
    }
}

/// A crash-safe store for one signing attempt's single-use nonces, under `dir`.
/// The secret nonce is sealed by the secure element exactly like the share at rest.
///
/// `epoch` is the current backup/nonce epoch. Every nonce is stamped with it when
/// committed (into the sealed blob's `backup_epoch`). A restore reconstructs the store
/// at a HIGHER epoch (see [`NonceStore::open_at_epoch`]); any nonce stamped with an
/// older epoch is hard-refused, so a nonce committed before the restore can never be
/// replayed afterwards (ws1-signer §8).
pub struct NonceStore {
    dir: PathBuf,
    epoch: u64,
    witness: Option<(WitnessPins, Mutex<Box<dyn NonceWitness + Send>>)>,
}

impl NonceStore {
    /// Open at epoch 0 (a store that was never restored).
    pub fn open(dir: &Path) -> io::Result<Self> {
        Self::open_at_epoch(dir, 0)
    }

    /// Open at an explicit epoch. A restore bumps the share's `backup_epoch` and opens the
    /// (fresh) nonce dir at that same epoch, so nonces stamped with any lower epoch are
    /// refused by [`NonceStore::sign_and_burn`].
    pub fn open_at_epoch(dir: &Path, epoch: u64) -> io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
        }
        #[cfg(not(unix))]
        fs::create_dir_all(dir)?;
        if !fs::symlink_metadata(dir)?.is_dir() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "nonce directory must not be a symlink"));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self {
            dir: dir.to_path_buf(),
            epoch,
            witness: None,
        })
    }

    pub(super) fn require_witness(&mut self, witness: Box<dyn NonceWitness + Send>) -> Result<(), NonceError> {
        let pins = witness.pins();
        if !crate::signing_session::valid_witness_pins(pins) {
            return Err(NonceError::Other("two distinct nonzero nonce witnesses required".into()));
        }
        self.witness = Some((pins, Mutex::new(witness)));
        Ok(())
    }

    fn witness_binding(&self) -> Vec<u8> {
        self.witness.as_ref().map_or_else(Vec::new, |(pins, _)| {
            pins.iter().flat_map(|(key, run, mailbox)| [*key, *run, *mailbox]).flatten().collect()
        })
    }

    fn nonce_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.nonce"))
    }
    fn burn_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.burn"))
    }

    /// Round 1: generate a single-use nonce, PERSIST it (sealed + fsync'd), then return
    /// the public commitment. The persist happens before the caller may emit anything.
    pub fn commit(
        &self,
        id: &str,
        se: &impl SecureElement,
        signing_share: &frost::keys::SigningShare,
    ) -> Result<frost::round1::SigningCommitments, NonceError> {
        if self.burn_path(id).exists() {
            return Err(NonceError::Other("nonce id already burned".into()));
        }
        if self.nonce_path(id).exists() {
            // Already committed; recover the same public commitment, do not re-generate.
            let (_, commitment) = self.load(id, se)?;
            return Ok(commitment);
        }
        let (nonces, commitment) =
            frost::round1::commit(signing_share, &mut rand_core::OsRng);
        let mut serialized = Zeroizing::new(self.witness_binding());
        serialized.extend_from_slice(&Zeroizing::new(nonces.serialize()
            .map_err(|e| NonceError::Other(e.to_string()))?));
        // Seal the secret nonce with the same at-rest hierarchy as the share, STAMPED with
        // the current epoch so a restore (which bumps the epoch) refuses this nonce.
        let sealed = SealedShare::seal(se, self.epoch, &serialized).map_err(NonceError::Other)?;
        write_durable(&self.dir, &format!("{id}.nonce"), &sealed.to_bytes())?;
        Ok(commitment)
    }

    fn load(
        &self,
        id: &str,
        se: &impl SecureElement,
    ) -> Result<(frost::round1::SigningNonces, frost::round1::SigningCommitments), NonceError> {
        let raw = fs::read(self.nonce_path(id))?;
        let sealed = SealedShare::from_bytes(&raw).map_err(NonceError::Other)?;
        // A nonce stamped with an older epoch than this store survived across a restore
        // (the dir is normally fresh after restore, but a leftover/rolled-back file must
        // still be refused, not signed with). ws1-signer §8.
        if sealed.backup_epoch != self.epoch {
            return Err(NonceError::StaleEpoch);
        }
        let plain = sealed.open(se).map_err(NonceError::Other)?;
        let binding = self.witness_binding();
        if !plain.starts_with(&binding) {
            return Err(NonceError::Other("nonce witness pins changed".into()));
        }
        let nonces = frost::round1::SigningNonces::deserialize(&plain[binding.len()..])
            .map_err(|e| NonceError::Other(e.to_string()))?;
        let commitment = frost::round1::SigningCommitments::from(&nonces);
        Ok((nonces, commitment))
    }

    /// The 32-byte message a burn record was created for (used to detect reuse).
    fn burned_message(&self, id: &str) -> io::Result<Option<[u8; 32]>> {
        match fs::read(self.burn_path(id)) {
            Ok(raw) if raw.len() >= 32 => Ok(Some(raw[..32].try_into().unwrap())),
            Ok(_) => Ok(None),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Round 2: ATOMICALLY burn the nonce and emit the partial for `message`.
    ///
    /// The partial is written into `<id>.burn` (fsync'd) BEFORE `<id>.nonce` is removed.
    /// A crash mid-call therefore leaves the burn record present (safe: resent verbatim)
    /// or the nonce still present (safe: retried) — never a burned-and-lost nonce.
    ///
    /// `inject_crash_after_burn` returns `true` just after the burn record is durable but
    /// before the nonce file is removed, to exercise the crash boundary in a test.
    pub fn sign_and_burn(
        &self,
        id: &str,
        se: &impl SecureElement,
        signing_package: &frost::SigningPackage,
        key: &frost::keys::KeyPackage,
        seed: &[u8; 32],
        inject_crash_after_burn: &dyn Fn() -> bool,
    ) -> Result<frost::round2::SignatureShare, NonceError> {
        let message: [u8; 32] = signing_package
            .message()
            .as_slice()
            .try_into()
            .map_err(|_| NonceError::Other("signing package message is not 32 bytes".into()))?;

        // Idempotent resend: a prior burn for the SAME message replays its partial;
        // a burn for a DIFFERENT message is reuse and is hard-refused.
        if let Some(prev) = self.burned_message(id)? {
            if prev != message {
                return Err(NonceError::Reuse);
            }
            let raw = fs::read(self.burn_path(id))?;
            return frost::round2::SignatureShare::deserialize(&raw[32..])
                .map_err(|e| NonceError::Other(format!("recorded partial: {e}")));
        }

        let (nonces, commitment) = self.load(id, se)?;
        if signing_package.signing_commitments().get(key.identifier()) != Some(&commitment) {
            return Err(NonceError::Other("own nonce differs from signing package".into()));
        }
        if let Some((pins, witness)) = &self.witness {
            let mut witness = witness.lock().map_err(|e| NonceError::Other(e.to_string()))?;
            if witness.pins() != *pins {
                return Err(NonceError::Other("nonce witness pins changed".into()));
            }
            // The CID follows the commitment, never the rolled-back attempt id or journal.
            let mut hash = blake3::Hasher::new();
            hash.update(b"Loki_hosted_nonce_cid_v1\0");
            hash.update(&key.verifying_key().serialize().map_err(|e| NonceError::Other(e.to_string()))?);
            hash.update(&key.identifier().serialize());
            hash.update(&commitment.serialize().map_err(|e| NonceError::Other(e.to_string()))?);
            let cid = hash.finalize().into();
            let mut record = Zeroizing::new(signing_package.serialize().map_err(|e| NonceError::Other(e.to_string()))?);
            record.extend_from_slice(seed);
            let record = SealedShare::seal(se, self.epoch, &record).map_err(NonceError::Other)?;
            witness.claim(cid, &record.to_bytes()).map_err(NonceError::Other)?;
        }
        let share = frost_rerandomized::sign_with_randomizer_seed(signing_package, &nonces, key, seed)
            .map_err(|e| NonceError::Other(e.to_string()))?;

        // Durable burn record: message || partial. Written and fsync'd FIRST.
        let mut record = Vec::with_capacity(32 + 64);
        record.extend_from_slice(&message);
        record.extend_from_slice(&share.serialize());
        write_durable(&self.dir, &format!("{id}.burn"), &record)?;

        if inject_crash_after_burn() {
            // Simulate a power loss after the burn is durable but before the nonce file
            // is removed. The nonce file still exists; the burn file exists. Recovery
            // must treat this as burned (resend the partial), never reuse the nonce.
            return Err(NonceError::Other("crash injected after burn".into()));
        }

        // Only now remove the now-dead nonce; crash here is still safe (burn present).
        let _ = fs::remove_file(self.nonce_path(id));
        fs::File::open(&self.dir)?.sync_all()?;
        Ok(share)
    }

    /// State after a (possibly crashed) attempt, for tests and recovery.
    pub fn state(&self, id: &str) -> NonceState {
        let nonce = self.nonce_path(id).exists();
        let burn = self.burn_path(id).exists();
        match (nonce, burn) {
            (false, false) => NonceState::Fresh,
            (true, false) => NonceState::Committed,
            (_, true) => NonceState::Burned,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum NonceState {
    Fresh,
    Committed,
    Burned,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::secure_element::SoftwareSecureElement;
    use reddsa_frost::frost::redpallas as frost;
    use std::collections::BTreeMap;

    /// A 2-of-2 key set and a rerandomized signing package over `msg`, for one signer.
    fn fixture(
        msg: [u8; 32],
    ) -> (
        SoftwareSecureElement,
        frost::keys::KeyPackage,
        frost::round1::SigningNonces,
        frost::SigningPackage,
        [u8; 32],
    ) {
        let (shares, _pubkeys) = frost::keys::generate_with_dealer(
            2,
            2,
            frost::keys::IdentifierList::Default,
            &mut rand_core::OsRng,
        )
        .unwrap();
        let id1 = frost::Identifier::try_from(1u16).unwrap();
        let id2 = frost::Identifier::try_from(2u16).unwrap();
        let kp1 =
            frost::keys::KeyPackage::try_from(shares.get(&id1).unwrap().clone()).unwrap();
        let kp2 =
            frost::keys::KeyPackage::try_from(shares.get(&id2).unwrap().clone()).unwrap();
        // Peer's commitment, needed to form a well-populated signing package.
        let (_n2, c2) = frost::round1::commit(kp2.signing_share(), &mut rand_core::OsRng);
        let (n1, c1) = frost::round1::commit(kp1.signing_share(), &mut rand_core::OsRng);
        let mut commitments = BTreeMap::new();
        commitments.insert(id1, c1);
        commitments.insert(id2, c2);
        let pkg = frost::SigningPackage::new(commitments, &msg);
        let se = SoftwareSecureElement::generate();
        (se, kp1, n1, pkg, [9u8; 32])
    }

    fn pkg_for(
        se_share: &frost::keys::KeyPackage,
        committed: &frost::round1::SigningCommitments,
        peer: &frost::round1::SigningCommitments,
        msg: [u8; 32],
    ) -> frost::SigningPackage {
        let mut commitments = BTreeMap::new();
        commitments.insert(*se_share.identifier(), *committed);
        commitments.insert(frost::Identifier::try_from(2u16).unwrap(), *peer);
        frost::SigningPackage::new(commitments, &msg)
    }

    #[cfg(unix)]
    #[test]
    fn nonce_directory_is_owner_only_even_when_reopened() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempdir("permissions");
        let dir = root.join("nonces");
        NonceStore::open(&dir).unwrap();
        assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
        NonceStore::open(&dir).unwrap();
        assert_eq!(fs::metadata(&dir).unwrap().permissions().mode() & 0o777, 0o700);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn nonce_directory_cannot_redirect_to_host_storage() {
        let root = tempdir("symlink");
        let host = root.join("host");
        fs::create_dir_all(&host).unwrap();
        let dir = root.join("nonces");
        std::os::unix::fs::symlink(&host, &dir).unwrap();
        assert!(NonceStore::open(&dir).is_err());
        assert_eq!(fs::read_dir(&host).unwrap().count(), 0);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn crash_after_burn_leaves_no_stranded_or_duplicated_nonce() {
        let dir = tempdir("crash");
        let store = NonceStore::open(&dir).unwrap();
        let msg = [1u8; 32];
        let (se, kp, _n1, pkg, seed) = fixture(msg);
        let peer = *pkg
            .signing_commitments()
            .get(&frost::Identifier::try_from(2u16).unwrap())
            .unwrap();

        // Round 1: persist-before-emit.
        let committed = store.commit("c0", &se, kp.signing_share()).unwrap();
        assert_eq!(store.state("c0"), NonceState::Committed);
        let pkg = pkg_for(&kp, &committed, &peer, msg);

        // Round 2 with a crash injected right after the burn record is durable.
        let err = store
            .sign_and_burn("c0", &se, &pkg, &kp, &seed, &|| true)
            .unwrap_err();
        assert!(matches!(err, NonceError::Other(_)));
        // The burn record exists; the state reads as Burned despite the nonce file
        // still being on disk (burn wins).
        assert_eq!(store.state("c0"), NonceState::Burned);

        // Recovery: retrying for the SAME message resends the recorded partial and
        // NEVER re-signs with the nonce. The guarantee is that the recovered partial is
        // stable across repeated calls (idempotent) — a stranded or re-generated nonce
        // would either fail or differ.
        let resent1 = store
            .sign_and_burn("c0", &se, &pkg, &kp, &seed, &|| false)
            .unwrap();
        let resent2 = store
            .sign_and_burn("c0", &se, &pkg, &kp, &seed, &|| false)
            .unwrap();
        assert_eq!(resent1.serialize(), resent2.serialize());
    }

    #[test]
    fn persisted_nonce_refuses_a_replacement_witness_or_legacy_unwitnessed_state() {
        struct Pinned(WitnessPins);
        impl NonceWitness for Pinned {
            fn pins(&self) -> WitnessPins { self.0 }
            fn claim(&mut self, _: [u8; 32], _: &[u8]) -> Result<(), String> { panic!("must refuse before claiming") }
        }
        let dir = tempdir("witness-pins");
        let (se, key, _, _, _) = fixture([7; 32]);
        let pins = [([1; 32], [2; 32], [3; 32]), ([4; 32], [5; 32], [6; 32])];
        let mut store = NonceStore::open(&dir).unwrap();
        store.commit("legacy", &se, key.signing_share()).unwrap();
        store.require_witness(Box::new(Pinned(pins))).unwrap();
        assert!(store.commit("legacy", &se, key.signing_share()).is_err());
        store.commit("pinned", &se, key.signing_share()).unwrap();
        for changed in [
            [([7; 32], pins[0].1, pins[0].2), pins[1]],
            [(pins[0].0, [8; 32], pins[0].2), pins[1]],
            [(pins[0].0, pins[0].1, [9; 32]), pins[1]],
        ] {
            let mut reopened = NonceStore::open(&dir).unwrap();
            reopened.require_witness(Box::new(Pinned(changed))).unwrap();
            assert!(reopened.commit("pinned", &se, key.signing_share()).is_err());
        }
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn reuse_for_a_different_message_is_hard_refused() {
        let dir = tempdir("reuse");
        let store = NonceStore::open(&dir).unwrap();
        let msg_a = [7u8; 32];
        let (se, kp, _n1, pkg_a, seed) = fixture(msg_a);
        let peer = *pkg_a
            .signing_commitments()
            .get(&frost::Identifier::try_from(2u16).unwrap())
            .unwrap();
        let committed = store.commit("r0", &se, kp.signing_share()).unwrap();
        let pkg_a = pkg_for(&kp, &committed, &peer, msg_a);
        store
            .sign_and_burn("r0", &se, &pkg_a, &kp, &seed, &|| false)
            .unwrap();

        // A second signing request binding the SAME nonce id to a different message.
        let msg_b = [8u8; 32];
        let pkg_b = pkg_for(&kp, &committed, &peer, msg_b);
        let err = store
            .sign_and_burn("r0", &se, &pkg_b, &kp, &seed, &|| false)
            .unwrap_err();
        assert_eq!(err, NonceError::Reuse);
    }

    fn tempdir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "loki-nonce-{tag}-{}-{}",
            std::process::id(),
            rand_core::RngCore::next_u64(&mut rand_core::OsRng)
        ));
        let _ = fs::remove_dir_all(&p);
        p
    }
}
