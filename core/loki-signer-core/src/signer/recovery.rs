use bip39::{Language, Mnemonic};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, setup_receiver, setup_sender,
    Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
};
use zeroize::Zeroizing;

type Kem = X25519HkdfSha256;

const INFO: &[u8] = b"loki-recovery-share-backup-v1";

const DEVICE_AUTHZ_DOMAIN: &str = "loki-recovery-device-authz-v1";

pub struct RecoveryKey {
    private: <Kem as KemTrait>::PrivateKey,
    public: <Kem as KemTrait>::PublicKey,
    signing: SigningKey,
}

impl RecoveryKey {
    pub fn generate() -> Result<(Zeroizing<String>, Self), String> {
        let mut entropy = Zeroizing::new([0u8; 32]);
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut entropy[..]);
        let mnemonic =
            Mnemonic::from_entropy(&entropy[..]).map_err(|e| format!("generate recovery words: {e}"))?;
        let words = Zeroizing::new(mnemonic.to_string());
        let key = Self::from_mnemonic(&mnemonic);
        Ok((words, key))
    }

    pub fn from_words(words: &str) -> Result<Self, String> {
        let mnemonic = Mnemonic::parse_in(Language::English, words.trim())
            .map_err(|_| "invalid recovery words".to_string())?;
        if mnemonic.word_count() != 24 {
            return Err(format!(
                "recovery secret must be 24 words, got {}",
                mnemonic.word_count()
            ));
        }
        Ok(Self::from_mnemonic(&mnemonic))
    }

    fn from_mnemonic(mnemonic: &Mnemonic) -> Self {
        let seed = Zeroizing::new(mnemonic.to_seed(""));
        let (private, public) = <Kem as KemTrait>::derive_keypair(&seed[..]);
        let authz_seed = Zeroizing::new(mnemonic.to_seed(DEVICE_AUTHZ_DOMAIN));
        let signing = SigningKey::from_bytes(authz_seed[..32].try_into().unwrap());
        Self {
            private,
            public,
            signing,
        }
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        let serialized = self.public.to_bytes();
        let mut out = [0u8; 32];
        out.copy_from_slice(&serialized);
        out
    }

    pub fn signing_public(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    pub fn authorize_device(&self, device_pub: &[u8]) -> [u8; 64] {
        self.signing.sign(device_pub).to_bytes()
    }

    pub fn authorize_device_renewal(&self, device_pub: &[u8], generation: &[u8; 32]) -> [u8; 64] {
        self.signing.sign(&device_renewal_message(device_pub, generation)).to_bytes()
    }

    pub fn open_backup(&self, vault_id: &[u8; 32], blob: &[u8]) -> Result<Zeroizing<Vec<u8>>, String> {
        let enc_len = <<Kem as KemTrait>::EncappedKey as Serializable>::size();
        if blob.len() < enc_len {
            return Err("recovery backup is truncated".to_string());
        }
        let (enc_bytes, ciphertext) = blob.split_at(enc_len);
        let enc = <Kem as KemTrait>::EncappedKey::from_bytes(enc_bytes)
            .map_err(|e| format!("bad encapsulated key: {e:?}"))?;
        let mut receiver =
            setup_receiver::<ChaCha20Poly1305, HkdfSha256, Kem>(&OpModeR::Base, &self.private, &enc, INFO)
                .map_err(|e| format!("hpke setup_receiver: {e:?}"))?;
        let share = receiver
            .open(ciphertext, vault_id)
            .map_err(|_| "could not open recovery backup (wrong words or tampered backup)".to_string())?;
        Ok(Zeroizing::new(share))
    }
}

pub(crate) fn device_renewal_message(device_pub: &[u8], generation: &[u8; 32]) -> Vec<u8> {
    [b"loki-local-device-renewal-v1\0".as_slice(), generation, device_pub].concat()
}

pub fn verify_device_authorization(
    recovery_signing_pub: &[u8; 32],
    message: &[u8],
    sig: &[u8; 64],
) -> Result<(), String> {
    let vk = VerifyingKey::from_bytes(recovery_signing_pub)
        .map_err(|e| format!("bad recovery signing key: {e}"))?;
    vk.verify(message, &ed25519_dalek::Signature::from_bytes(sig))
        .map_err(|_| "device authorization signature does not verify".to_string())
}

pub fn seal_backup(recovery_pub: &[u8; 32], vault_id: &[u8; 32], share: &[u8]) -> Result<Vec<u8>, String> {
    let pk = <Kem as KemTrait>::PublicKey::from_bytes(recovery_pub)
        .map_err(|e| format!("bad recovery public key: {e:?}"))?;
    let (enc, mut sender) =
        setup_sender::<ChaCha20Poly1305, HkdfSha256, Kem>(&OpModeS::Base, &pk, INFO)
            .map_err(|e| format!("hpke setup_sender: {e:?}"))?;
    let ciphertext = sender
        .seal(share, vault_id)
        .map_err(|e| format!("hpke seal: {e:?}"))?;
    let mut blob = enc.to_bytes().to_vec();
    blob.extend_from_slice(&ciphertext);
    Ok(blob)
}

#[cfg(test)]
mod tests {
    use super::*;

    const WORDS_A: &str = "abandon abandon abandon abandon abandon abandon abandon abandon \
        abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon \
        abandon abandon abandon abandon abandon art";

    #[test]
    fn backup_round_trips_through_the_recovery_words() {
        let (words, key) = RecoveryKey::generate().unwrap();
        let pubkey = key.public_bytes();
        drop(key);

        let vault_id = [7u8; 32];
        let share = b"a 2-of-3 FROST key package, sealed for recovery".to_vec();
        let blob = seal_backup(&pubkey, &vault_id, &share).unwrap();
        assert!(blob.len() > share.len(), "ciphertext carries enc key + AEAD tag");

        let restored = RecoveryKey::from_words(&words).unwrap();
        let opened = restored.open_backup(&vault_id, &blob).unwrap();
        assert_eq!(opened.as_slice(), share.as_slice());
    }

    #[test]
    fn same_words_derive_the_same_public_key() {
        let a = RecoveryKey::from_words(WORDS_A).unwrap();
        let b = RecoveryKey::from_words(WORDS_A).unwrap();
        assert_eq!(a.public_bytes(), b.public_bytes(), "derivation is deterministic");
    }

    #[test]
    fn wrong_words_cannot_open_the_backup() {
        let right = RecoveryKey::from_words(WORDS_A).unwrap();
        let vault_id = [9u8; 32];
        let blob = seal_backup(&right.public_bytes(), &vault_id, b"share").unwrap();

        let (other_words, _) = RecoveryKey::generate().unwrap();
        let wrong = RecoveryKey::from_words(&other_words).unwrap();
        assert!(wrong.open_backup(&vault_id, &blob).is_err(), "a different key must not open it");
    }

    #[test]
    fn wrong_vault_id_and_tampering_are_rejected() {
        let key = RecoveryKey::from_words(WORDS_A).unwrap();
        let vault_id = [1u8; 32];
        let mut blob = seal_backup(&key.public_bytes(), &vault_id, b"share").unwrap();

        assert!(
            key.open_backup(&[2u8; 32], &blob).is_err(),
            "AAD binds the backup to its vault id"
        );
        *blob.last_mut().unwrap() ^= 0x01;
        assert!(key.open_backup(&vault_id, &blob).is_err(), "AEAD rejects a tampered blob");
    }

    #[test]
    fn non_24_word_secret_is_rejected() {
        let twelve = "abandon abandon abandon abandon abandon abandon \
            abandon abandon abandon abandon abandon about";
        assert!(RecoveryKey::from_words(twelve).is_err());
        assert!(RecoveryKey::from_words("not real words at all").is_err());
    }
}
