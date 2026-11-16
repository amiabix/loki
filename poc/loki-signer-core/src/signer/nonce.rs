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

use crate::signer::durable::{
    create_dir_all, file_exists, read_file, remove_file, sync_dir, write_durable,
};
use crate::signer::secure_element::{SealedShare, SecureElement};
use reddsa_frost::frost::redpallas as frost;
use std::{
    io,
    path::{Path, PathBuf},
};

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
        create_dir_all(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            epoch,
        })
    }

    fn nonce_name(id: &str) -> String {
        format!("{id}.nonce")
    }
    fn burn_name(id: &str) -> String {
        format!("{id}.burn")
    }

    /// Round 1: generate a single-use nonce, PERSIST it (sealed + fsync'd), then return
    /// the public commitment. The persist happens before the caller may emit anything.
    pub fn commit(
        &self,
        id: &str,
        se: &impl SecureElement,
        signing_share: &frost::keys::SigningShare,
    ) -> Result<frost::round1::SigningCommitments, NonceError> {
        if file_exists(&self.dir, &Self::burn_name(id)) {
            return Err(NonceError::Other("nonce id already burned".into()));
        }
        if file_exists(&self.dir, &Self::nonce_name(id)) {
            // Already committed; recover the same public commitment, do not re-generate.
            let (_, commitment) = self.load(id, se)?;
            return Ok(commitment);
        }
        let (nonces, commitment) =
            frost::round1::commit(signing_share, &mut rand_core::OsRng);
        let serialized = nonces
            .serialize()
            .map_err(|e| NonceError::Other(e.to_string()))?;
        // Seal the secret nonce with the same at-rest hierarchy as the share, STAMPED with
        // the current epoch so a restore (which bumps the epoch) refuses this nonce.
        let sealed = SealedShare::seal(se, self.epoch, &serialized).map_err(NonceError::Other)?;
        write_durable(&self.dir, &Self::nonce_name(id), &sealed.to_bytes())?;
        Ok(commitment)
    }

    fn load(
        &self,
        id: &str,
        se: &impl SecureElement,
    ) -> Result<(frost::round1::SigningNonces, frost::round1::SigningCommitments), NonceError> {
        let raw = read_file(&self.dir, &Self::nonce_name(id))?;
        let sealed = SealedShare::from_bytes(&raw).map_err(NonceError::Other)?;
        // A nonce stamped with an older epoch than this store survived across a restore
        // (the dir is normally fresh after restore, but a leftover/rolled-back file must
        // still be refused, not signed with). ws1-signer §8.
        if sealed.backup_epoch != self.epoch {
            return Err(NonceError::StaleEpoch);
        }
        let plain = sealed.open(se).map_err(NonceError::Other)?;
        let nonces = frost::round1::SigningNonces::deserialize(&plain)
            .map_err(|e| NonceError::Other(e.to_string()))?;
        let commitment = frost::round1::SigningCommitments::from(&nonces);
        Ok((nonces, commitment))
    }

    /// The 32-byte message a burn record was created for (used to detect reuse).
    fn burned_message(&self, id: &str) -> io::Result<Option<[u8; 32]>> {
        match read_file(&self.dir, &Self::burn_name(id)) {
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
            let raw = read_file(&self.dir, &Self::burn_name(id))?;
            return frost::round2::SignatureShare::deserialize(&raw[32..])
                .map_err(|e| NonceError::Other(format!("recorded partial: {e}")));
        }

        let (nonces, _) = self.load(id, se)?;
        let share = frost_rerandomized::sign_with_randomizer_seed(signing_package, &nonces, key, seed)
            .map_err(|e| NonceError::Other(e.to_string()))?;

        // Durable burn record: message || partial. Written and fsync'd FIRST.
        let mut record = Vec::with_capacity(32 + 64);
        record.extend_from_slice(&message);
        record.extend_from_slice(&share.serialize());
        write_durable(&self.dir, &Self::burn_name(id), &record)?;

        if inject_crash_after_burn() {
            // Simulate a power loss after the burn is durable but before the nonce file
            // is removed. The nonce file still exists; the burn file exists. Recovery
            // must treat this as burned (resend the partial), never reuse the nonce.
            return Err(NonceError::Other("crash injected after burn".into()));
        }

        // Only now remove the now-dead nonce; crash here is still safe (burn present).
        let _ = remove_file(&self.dir, &Self::nonce_name(id));
        sync_dir(&self.dir)?;
        Ok(share)
    }

    /// State after a (possibly crashed) attempt, for tests and recovery.
    pub fn state(&self, id: &str) -> NonceState {
        let nonce = file_exists(&self.dir, &Self::nonce_name(id));
        let burn = file_exists(&self.dir, &Self::burn_name(id));
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
    use std::fs;

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
