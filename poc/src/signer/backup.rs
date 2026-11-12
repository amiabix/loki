//! Member share BACKUP / RESTORE (ws1-signer §2, §5, §8).
//!
//! A FROST share is NOT seed-derivable — it is one point of a dealerless DKG. The only
//! way a member recovers signing ability on a new device is to have backed up the sealed
//! material itself. This module produces a single portable artifact that carries exactly
//! what [`LocalSigner::with_sealed_share`] needs to sign again, and restores it onto a
//! fresh data root.
//!
//! Crypto reuse (no new primitives, ws1-signer §3): the artifact is sealed with the SAME
//! [`SealedShare`] / [`SecureElement`] hierarchy used at rest, except the KEK is derived
//! from the member's backup passphrase via the one project-wide Argon2id
//! ([`crate::seal_kdf`]) rather than a device-bound element — so the blob is portable to a
//! new device, which is the whole point of a backup. The on-disk/over-the-wire artifact is
//! therefore AEAD ciphertext under a passphrase-derived KEK; the plaintext share never
//! leaves memory unsealed.
//!
//! Nonce-epoch reset (ws1-signer §8): every artifact carries a `backup_epoch`. [`restore`]
//! reconstructs the signer at `backup_epoch + 1` and opens its (fresh) nonce store at that
//! bumped epoch, so any nonce committed before the restore is hard-refused afterwards
//! (see [`crate::signer::nonce`]).

use crate::seal_kdf;
use crate::signer::local::{ApprovalPolicy, LocalSigner, SignerError};
use crate::signer::nonce::NonceStore;
use crate::signer::secure_element::{SealedShare, SecureElement, SoftwareSecureElement};
use crate::signer::Network;
use crate::zip2005;
use std::path::PathBuf;
use zeroize::Zeroizing;

const BACKUP_MAGIC: &[u8; 8] = b"LOKIBAK2";
/// Magic for a recovery-sealed artifact: same plaintext as [`BACKUP_MAGIC`], but HPKE-sealed
/// to a words-derived recovery public key instead of a passphrase KEK.
const RECOVERY_BACKUP_MAGIC: &[u8; 8] = b"LOKIRCV1";

fn network_tag(n: Network) -> u8 {
    match n {
        Network::Regtest => 0,
        Network::Testnet => 1,
    }
}

fn network_from_tag(t: u8) -> Result<Network, String> {
    match t {
        0 => Ok(Network::Regtest),
        1 => Ok(Network::Testnet),
        _ => Err(format!("unknown network tag {t}")),
    }
}

fn put_bytes(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(&(b.len() as u32).to_be_bytes());
    out.extend_from_slice(b);
}

fn take_bytes<'a>(raw: &'a [u8], at: &mut usize) -> Result<&'a [u8], String> {
    if *at + 4 > raw.len() {
        return Err("truncated backup field length".into());
    }
    let len = u32::from_be_bytes(raw[*at..*at + 4].try_into().unwrap()) as usize;
    *at += 4;
    if *at + len > raw.len() {
        return Err("truncated backup field".into());
    }
    let slice = &raw[*at..*at + len];
    *at += len;
    Ok(slice)
}

/// Everything needed to rebuild a member's signer on a new device. The share plaintext
/// (`key_package`) lives here only transiently; the sealed artifact ([`BackupArtifact`])
/// is what crosses a disk/QR/cloud boundary.
pub struct BackupMaterial {
    pub member_id: u16,
    pub threshold: u16,
    pub members: u16,
    pub network: Network,
    pub vault_id: [u8; 32],
    pub label: String,
    /// The group's privately agreed ZIP-2005 viewing-key secret (`group_sk`), needed to
    /// re-derive the vault FVK on the new device. Public-to-the-group but vault-private.
    pub group_sk: [u8; 32],
    /// This member's FROST `KeyPackage`, serialized. The one non-seed-derivable secret.
    pub key_package: Zeroizing<Vec<u8>>,
    /// The group `PublicKeyPackage`, serialized. Public.
    pub public_package: Vec<u8>,
    /// The epoch this backup was taken at. [`restore`] bumps past it.
    pub backup_epoch: u64,
    /// The member's setup identity (`Identity::to_secret_bytes`), so a restored device
    /// holds an identity that is in its own roster. Empty for a bare-share backup.
    pub identity: Zeroizing<Vec<u8>>,
    /// The confirmed roster document. Empty for a bare-share backup.
    pub roster: Vec<u8>,
    /// Fingerprint of `roster`; all zero for a bare-share backup.
    pub roster_fingerprint: [u8; 32],
    /// The vault's birth height on Testnet.
    pub birth_height: Option<u32>,
}

impl BackupMaterial {
    /// The group verifying key (`ak`), read from the public package. The FVK is
    /// `frost_viewing_key(ak, group_sk)`.
    fn group_ak(&self) -> Result<[u8; 32], String> {
        let public = reddsa_frost::frost::redpallas::keys::PublicKeyPackage::deserialize(
            &self.public_package,
        )
        .map_err(|e| format!("public package: {e}"))?;
        public
            .verifying_key()
            .serialize()
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "group verifying key is not 32 bytes".to_string())
    }

    fn encode_plaintext(&self) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::new());
        out.extend_from_slice(&self.member_id.to_be_bytes());
        out.extend_from_slice(&self.threshold.to_be_bytes());
        out.extend_from_slice(&self.members.to_be_bytes());
        out.push(network_tag(self.network));
        out.extend_from_slice(&self.vault_id);
        out.extend_from_slice(&self.group_sk);
        out.extend_from_slice(&self.backup_epoch.to_be_bytes());
        put_bytes(&mut out, self.label.as_bytes());
        put_bytes(&mut out, &self.key_package);
        put_bytes(&mut out, &self.public_package);
        put_bytes(&mut out, &self.identity);
        put_bytes(&mut out, &self.roster);
        out.extend_from_slice(&self.roster_fingerprint);
        match self.birth_height {
            Some(height) => {
                out.push(1);
                out.extend_from_slice(&height.to_be_bytes());
            }
            None => out.push(0),
        }
        out
    }

    fn decode_plaintext(raw: &[u8]) -> Result<Self, String> {
        if raw.len() < 2 + 2 + 2 + 1 + 32 + 32 + 8 {
            return Err("truncated backup plaintext".into());
        }
        let member_id = u16::from_be_bytes(raw[0..2].try_into().unwrap());
        let threshold = u16::from_be_bytes(raw[2..4].try_into().unwrap());
        let members = u16::from_be_bytes(raw[4..6].try_into().unwrap());
        let network = network_from_tag(raw[6])?;
        let vault_id: [u8; 32] = raw[7..39].try_into().unwrap();
        let group_sk: [u8; 32] = raw[39..71].try_into().unwrap();
        let backup_epoch = u64::from_be_bytes(raw[71..79].try_into().unwrap());
        let mut at = 79;
        let label = String::from_utf8(take_bytes(raw, &mut at)?.to_vec())
            .map_err(|_| "backup label is not utf-8")?;
        let key_package = Zeroizing::new(take_bytes(raw, &mut at)?.to_vec());
        let public_package = take_bytes(raw, &mut at)?.to_vec();
        let identity = Zeroizing::new(take_bytes(raw, &mut at)?.to_vec());
        let roster = take_bytes(raw, &mut at)?.to_vec();
        let roster_fingerprint: [u8; 32] = raw
            .get(at..at + 32)
            .ok_or("truncated backup fingerprint")?
            .try_into()
            .unwrap();
        at += 32;
        let birth_height = match raw.get(at) {
            Some(0) if raw.len() == at + 1 => None,
            Some(1) if raw.len() == at + 5 => Some(u32::from_be_bytes(
                raw[at + 1..at + 5].try_into().unwrap(),
            )),
            _ => return Err("invalid backup birth height".into()),
        };
        Ok(Self {
            member_id,
            threshold,
            members,
            network,
            vault_id,
            label,
            group_sk,
            key_package,
            public_package,
            backup_epoch,
            identity,
            roster,
            roster_fingerprint,
            birth_height,
        })
    }
}

/// The sealed, portable backup. `magic || SealedShare(plaintext, passphrase-KEK)`.
/// The share plaintext is never in these bytes — only AEAD ciphertext.
pub struct BackupArtifact(pub Vec<u8>);

/// Argon2id salt for the backup KEK: the vault id (stable, non-secret, vault-scoped).
fn backup_salt(vault_id: &[u8; 32]) -> &[u8] {
    vault_id
}

fn backup_element(passphrase: &str, vault_id: &[u8; 32]) -> Result<SoftwareSecureElement, String> {
    let kek =
        seal_kdf::derive(passphrase, backup_salt(vault_id)).map_err(|_| "backup KDF failed")?;
    Ok(SoftwareSecureElement::from_kek(*kek))
}

/// BACKUP: seal `material` under a KEK derived from `passphrase`. The returned artifact
/// is AEAD ciphertext and is safe to write to disk / show as a QR / store in the member's
/// own cloud; only the same passphrase (and the vault id) can reopen it.
pub fn create(material: &BackupMaterial, passphrase: &str) -> Result<BackupArtifact, String> {
    let se = backup_element(passphrase, &material.vault_id)?;
    let sealed = SealedShare::seal(&se, material.backup_epoch, &material.encode_plaintext())?;
    let mut out = Vec::with_capacity(8 + sealed.to_bytes().len());
    out.extend_from_slice(BACKUP_MAGIC);
    out.extend_from_slice(&sealed.to_bytes());
    Ok(BackupArtifact(out))
}

/// VERIFY (ws1-signer §9: "force the member to save and prove-load their recovery
/// artifact"): reopen the artifact with the passphrase and recover the material. A member
/// runs this right after [`create`] to prove the backup is loadable before the vault
/// activates. Also round-trips through the FROST deserializers so a corrupt share is
/// caught here, not at first signature.
pub fn verify(
    artifact: &BackupArtifact,
    passphrase: &str,
    vault_id: &[u8; 32],
) -> Result<BackupMaterial, String> {
    if artifact.0.len() < 8 || &artifact.0[..8] != BACKUP_MAGIC {
        return Err("not a Loki backup artifact".into());
    }
    let se = backup_element(passphrase, vault_id)?;
    let sealed = SealedShare::from_bytes(&artifact.0[8..])?;
    let plain = sealed.open(&se)?;
    let material = BackupMaterial::decode_plaintext(&plain)?;
    validate_material(material, vault_id)
}

/// Shared post-decode checks for any backup artifact, however it was sealed: it is for this
/// vault, its share + public package parse and derive a valid FVK, and (when present) its
/// identity is the one its own roster names.
fn validate_material(material: BackupMaterial, vault_id: &[u8; 32]) -> Result<BackupMaterial, String> {
    if &material.vault_id != vault_id {
        return Err("backup is for a different vault".into());
    }
    // Prove the share and public package actually parse and derive a valid FVK.
    reddsa_frost::frost::redpallas::keys::KeyPackage::deserialize(&material.key_package)
        .map_err(|e| format!("backup share does not parse: {e}"))?;
    let ak = material.group_ak()?;
    zip2005::frost_viewing_key(&ak, &material.group_sk)
        .map_err(|e| format!("backup cannot derive the vault FVK: {e:?}"))?;
    if !material.roster.is_empty() {
        // The restored identity must be the one its own roster names.
        let roster = crate::member_state::Roster::from_bytes(&material.roster)?;
        let identity = crate::setup_transport::Identity::from_secret_bytes(&material.identity)?;
        if roster.fingerprint() != material.roster_fingerprint
            || roster.vault != material.vault_id
            || roster.birth_height != material.birth_height
            || roster.members.get(&material.member_id) != Some(&identity.public())
        {
            return Err("backup identity or roster does not match".into());
        }
    } else if !material.identity.is_empty() || material.roster_fingerprint != [0; 32] {
        return Err("backup identity without its roster".into());
    }
    Ok(material)
}

/// RESTORE to a fresh data root. Reconstructs a signing-ready [`LocalSigner`] from the
/// artifact, re-sealing the share under `se` (the NEW device's secure element) and opening
/// the nonce store at `backup_epoch + 1` — the fresh nonce epoch. Any nonce committed
/// before this restore is stamped with a lower epoch and is hard-refused (ws1-signer §8).
///
/// `nonce_dir` MUST be a fresh/empty directory on the new data root.
#[allow(clippy::too_many_arguments)]
pub fn restore<SE: SecureElement>(
    artifact: &BackupArtifact,
    passphrase: &str,
    vault_id: &[u8; 32],
    se: SE,
    nonce_dir: PathBuf,
    approval: ApprovalPolicy,
) -> Result<LocalSigner<SE>, SignerError> {
    let material = verify(artifact, passphrase, vault_id).map_err(SignerError::Other)?;
    rebuild_signer(material, se, nonce_dir, approval)
}

/// Reconstruct a signing-ready signer from already-validated material, re-sealing the share
/// under the NEW device's `se` and opening the nonce store at `backup_epoch + 1`. Shared by
/// the passphrase ([`restore`]) and recovery-words ([`restore_recovery`]) restore paths.
fn rebuild_signer<SE: SecureElement>(
    material: BackupMaterial,
    se: SE,
    nonce_dir: PathBuf,
    approval: ApprovalPolicy,
) -> Result<LocalSigner<SE>, SignerError> {
    let ak = material.group_ak().map_err(SignerError::Other)?;
    let fvk = zip2005::frost_viewing_key(&ak, &material.group_sk)
        .map_err(|e| SignerError::Other(format!("FVK derivation: {e:?}")))?;
    // Fresh nonce epoch: strictly greater than the backed-up epoch.
    let next_epoch = material.backup_epoch + 1;
    let nonces = NonceStore::open_at_epoch(&nonce_dir, next_epoch)
        .map_err(|e| SignerError::Other(e.to_string()))?;
    let identity = if material.identity.is_empty() {
        None
    } else {
        Some(
            crate::setup_transport::Identity::from_secret_bytes(&material.identity)
                .map_err(SignerError::Other)?,
        )
    };
    LocalSigner::from_restored(
        material.member_id,
        material.threshold,
        material.members,
        material.vault_id,
        material.label.clone(),
        material.network,
        se,
        &material.key_package,
        material.public_package.clone(),
        fvk,
        next_epoch,
        nonces,
        approval,
        identity,
    )
}

/// RECOVERY BACKUP: seal `material` to a words-derived recovery PUBLIC key (RFC 9180 HPKE),
/// vault-scoped. Needs only the public key, so the signer makes a fresh backup for every new
/// vault without re-entering its recovery words; only the matching recovery key (the 24 words)
/// can reopen it. The service may hold this artifact — it is opaque ciphertext to anyone but
/// the words-holder. See [`crate::signer::recovery`].
pub fn create_to_recovery(
    material: &BackupMaterial,
    recovery_pub: &[u8; 32],
) -> Result<BackupArtifact, String> {
    let blob = crate::signer::recovery::seal_backup(
        recovery_pub,
        &material.vault_id,
        &material.encode_plaintext(),
    )?;
    let mut out = Vec::with_capacity(8 + blob.len());
    out.extend_from_slice(RECOVERY_BACKUP_MAGIC);
    out.extend_from_slice(&blob);
    Ok(BackupArtifact(out))
}

/// VERIFY a recovery-sealed artifact with the words-derived recovery key (same validation as
/// the passphrase [`verify`]). Wrong words (different key) or a tampered blob -> `Err`.
pub fn verify_recovery(
    artifact: &BackupArtifact,
    recovery: &crate::signer::recovery::RecoveryKey,
    vault_id: &[u8; 32],
) -> Result<BackupMaterial, String> {
    if artifact.0.len() < 8 || &artifact.0[..8] != RECOVERY_BACKUP_MAGIC {
        return Err("not a Loki recovery backup artifact".into());
    }
    let plain = recovery.open_backup(vault_id, &artifact.0[8..])?;
    let material = BackupMaterial::decode_plaintext(&plain)?;
    validate_material(material, vault_id)
}

/// RESTORE from a recovery-sealed artifact onto a fresh data root (the new-phone path):
/// re-derive the recovery key from the 24 words, open the service-held backup, and rebuild a
/// signing-ready signer under this device's `se`. Mirrors [`restore`]; `nonce_dir` MUST be a
/// fresh/empty directory.
#[allow(clippy::too_many_arguments)]
pub fn restore_recovery<SE: SecureElement>(
    artifact: &BackupArtifact,
    recovery: &crate::signer::recovery::RecoveryKey,
    vault_id: &[u8; 32],
    se: SE,
    nonce_dir: PathBuf,
    approval: ApprovalPolicy,
) -> Result<LocalSigner<SE>, SignerError> {
    let material = verify_recovery(artifact, recovery, vault_id).map_err(SignerError::Other)?;
    rebuild_signer(material, se, nonce_dir, approval)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::nonce::NonceState;
    use crate::signer::secure_element::SoftwareSecureElement;
    use crate::signer::{CandidateRef, Signer};
    use reddsa_frost::frost::redpallas as frost;

    fn tempdir(tag: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "loki-backup-{tag}-{}-{}",
            std::process::id(),
            rand_core::RngCore::next_u64(&mut rand_core::OsRng)
        ));
        let _ = std::fs::remove_dir_all(&p);
        p
    }

    /// A 2-of-3 dealer vault: member-1 share + public package + a fresh group_sk.
    fn fixture() -> (BackupMaterial, frost::keys::PublicKeyPackage) {
        let (shares, public) = frost::keys::generate_with_dealer(
            3,
            2,
            frost::keys::IdentifierList::Default,
            &mut rand_core::OsRng,
        )
        .unwrap();
        let id1 = frost::Identifier::try_from(1u16).unwrap();
        let kp1 = frost::keys::KeyPackage::try_from(shares.get(&id1).unwrap().clone()).unwrap();
        let material = BackupMaterial {
            member_id: 1,
            threshold: 2,
            members: 3,
            network: Network::Regtest,
            vault_id: [7u8; 32],
            label: "backup vault".into(),
            group_sk: [42u8; 32],
            key_package: Zeroizing::new(kp1.serialize().unwrap()),
            public_package: public.serialize().unwrap(),
            backup_epoch: 3,
            identity: Zeroizing::new(Vec::new()),
            roster: Vec::new(),
            roster_fingerprint: [0; 32],
            birth_height: None,
        };
        (material, public)
    }

    #[test]
    fn recovery_artifact_restores_a_signing_share_from_the_words() {
        use crate::signer::recovery::RecoveryKey;
        let (material, public) = fixture();
        let vault_id = material.vault_id;

        // First launch: words + recovery key. Back up to the PUBLIC key only.
        let (words, key) = RecoveryKey::generate().unwrap();
        let art = create_to_recovery(&material, &key.public_bytes()).unwrap();
        drop(key);
        // The share plaintext never appears in the artifact bytes.
        assert!(!art
            .0
            .windows(material.key_package.len())
            .any(|w| w == material.key_package.as_slice()));

        // Wrong words cannot open it.
        let (other, _) = RecoveryKey::generate().unwrap();
        assert!(verify_recovery(&art, &RecoveryKey::from_words(&other).unwrap(), &vault_id).is_err());

        // New phone: re-derive from the SAME words, restore onto a clean root, and sign.
        let restored_key = RecoveryKey::from_words(&words).unwrap();
        let mut signer = restore_recovery(
            &art,
            &restored_key,
            &vault_id,
            SoftwareSecureElement::generate(),
            tempdir("recovery-nonces"),
            Box::new(|_v| true),
        )
        .unwrap();

        let ak: [u8; 32] = public.verifying_key().serialize().unwrap().try_into().unwrap();
        let fvk = zip2005::frost_viewing_key(&ak, &material.group_sk).unwrap();
        let key1 = frost::keys::KeyPackage::deserialize(&material.key_package).unwrap();
        let cand = CandidateRef {
            vault_id,
            payment_id: [3u8; 32],
            attempt_id: [4u8; 32],
        };
        let session = signer
            .connect("http://coordinator.test", Network::Regtest, b"c")
            .unwrap()
            .session;
        let own = signer.sign_commit(&session, &cand).unwrap();
        let key2 = {
            let (shares, _p) = frost::keys::generate_with_dealer(
                3,
                2,
                frost::keys::IdentifierList::Default,
                &mut rand_core::OsRng,
            )
            .unwrap();
            frost::keys::KeyPackage::try_from(
                shares.get(&frost::Identifier::try_from(2u16).unwrap()).unwrap().clone(),
            )
            .unwrap()
        };
        let (pczt, pkg, seed) = crate::signer::local::tests::candidate_and_package(
            &fvk,
            &key1,
            &public,
            *key2.identifier(),
            frost::round1::commit(key2.signing_share(), &mut rand_core::OsRng).1,
            own,
            true,
        );
        let share = signer
            .sign_approve(&session, &cand, &pczt, &pkg, &seed)
            .expect("the words-restored share must sign a candidate for its group key");
        assert_eq!(share.serialize().len(), 32);
    }

    #[test]
    fn artifact_is_ciphertext_and_verifies_only_with_the_passphrase() {
        let (material, _public) = fixture();
        let art = create(&material, "correct horse").unwrap();
        // The share plaintext never appears in the artifact bytes.
        assert!(!art
            .0
            .windows(material.key_package.len())
            .any(|w| w == material.key_package.as_slice()));
        // Wrong passphrase fails; right one recovers the material.
        assert!(verify(&art, "wrong", &material.vault_id).is_err());
        let back = verify(&art, "correct horse", &material.vault_id).unwrap();
        assert_eq!(back.member_id, 1);
        assert_eq!(back.backup_epoch, 3);
        assert_eq!(&*back.key_package, &*material.key_package);
        assert_eq!(back.group_sk, material.group_sk);
    }

    // Acceptance (a): backup -> restore on a CLEAN data root yields a share that signs a
    // candidate for its group key. (b): a nonce committed BEFORE restore is hard-refused
    // after restore.
    #[test]
    fn restore_on_clean_root_signs_and_refuses_pre_restore_nonce() {
        let (material, public) = fixture();
        let vault_id = material.vault_id;
        let ak: [u8; 32] = public
            .verifying_key()
            .serialize()
            .unwrap()
            .try_into()
            .unwrap();
        let fvk = zip2005::frost_viewing_key(&ak, &material.group_sk).unwrap();
        let key1 = frost::keys::KeyPackage::deserialize(&material.key_package).unwrap();

        // --- Pre-restore signer (epoch 3): commit a nonce, capturing its sealed file. ---
        let old_nonce_dir = tempdir("old-nonces");
        let pre = NonceStore::open_at_epoch(&old_nonce_dir, 3).unwrap();
        let cand = CandidateRef {
            vault_id,
            payment_id: [1u8; 32],
            attempt_id: [2u8; 32],
        };
        let nonce_id = {
            let mut s = String::new();
            for b in cand.payment_id.iter().chain(cand.attempt_id.iter()) {
                s.push_str(&format!("{b:02x}"));
            }
            s
        };
        let pre_se = SoftwareSecureElement::generate();
        pre.commit(&nonce_id, &pre_se, key1.signing_share())
            .unwrap();
        assert_eq!(pre.state(&nonce_id), NonceState::Committed);

        // --- BACKUP then RESTORE onto a CLEAN data root (fresh dir, new element). ---
        let art = create(&material, "pw").unwrap();
        let fresh_nonce_dir = tempdir("fresh-nonces");
        let mut signer = restore(
            &art,
            "pw",
            &vault_id,
            SoftwareSecureElement::generate(),
            fresh_nonce_dir.clone(),
            Box::new(|_v| true),
        )
        .unwrap();

        // The restored signer signs a candidate for the group key (clean-root happy path).
        let session = signer
            .connect("http://coordinator.test", Network::Regtest, b"c")
            .unwrap()
            .session;
        let own = signer.sign_commit(&session, &cand).unwrap();
        let key2 = {
            // A stand-in peer commitment from a second dealer share of the same vault.
            // (We only need a well-formed package over the pczt's real sighash.)
            let (shares, _p) = frost::keys::generate_with_dealer(
                3,
                2,
                frost::keys::IdentifierList::Default,
                &mut rand_core::OsRng,
            )
            .unwrap();
            frost::keys::KeyPackage::try_from(
                shares
                    .get(&frost::Identifier::try_from(2u16).unwrap())
                    .unwrap()
                    .clone(),
            )
            .unwrap()
        };
        let (pczt, pkg, seed) = crate::signer::local::tests::candidate_and_package(
            &fvk,
            &key1,
            &public,
            *key2.identifier(),
            frost::round1::commit(key2.signing_share(), &mut rand_core::OsRng).1,
            own,
            true,
        );
        let share = signer
            .sign_approve(&session, &cand, &pczt, &pkg, &seed)
            .expect("restored share must sign a candidate for its group key");
        assert_eq!(share.serialize().len(), 32);

        // --- (b) The pre-restore nonce file, dropped into the restored store, is refused. ---
        // Copy the stale (epoch-3) nonce file into the fresh (epoch-4) store, as a
        // rollback/replay attacker would, and confirm the restored signer never signs it.
        let stale = std::fs::read(old_nonce_dir.join(format!("{nonce_id}.nonce"))).unwrap();
        let cand2 = CandidateRef {
            vault_id,
            payment_id: [9u8; 32],
            attempt_id: [9u8; 32],
        };
        let nonce_id2 = {
            let mut s = String::new();
            for b in cand2.payment_id.iter().chain(cand2.attempt_id.iter()) {
                s.push_str(&format!("{b:02x}"));
            }
            s
        };
        std::fs::write(fresh_nonce_dir.join(format!("{nonce_id2}.nonce")), &stale).unwrap();
        let refused = signer.sign_approve(&session, &cand2, &pczt, &pkg, &seed);
        assert!(
            matches!(&refused, Err(SignerError::Other(m)) if m.contains("pre-restore epoch")),
            "a pre-restore-epoch nonce must be hard-refused after restore, got {refused:?}"
        );
    }
}
