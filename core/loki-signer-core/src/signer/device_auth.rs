//! Device authentication: the daily-convenience half of the native-signer recovery flow.
//!
//! A device holds a P-256 signing key — in production the Secure Enclave login key, gated by
//! Face ID so every signature needs user presence; a software P-256 key stands in here and the
//! SAME verifier checks either (the Enclave is P-256-only). Loki recognises a device by
//! challenge/response: it issues a random nonce, the device signs it, Loki checks the signature
//! against the device's enrolled public key. Loki never sees a private key.
//!
//! A device is enrolled only once the recovery identity (the 24 words) has authorized it via
//! [`crate::signer::recovery::RecoveryKey::authorize_device`] — which is exactly how a NEW
//! phone registers: restore the words, sign the new device key, enroll. A compromised device is
//! [`revoke`](DeviceRegistry::revoke)d so its challenges fail; the group separately re-keys the
//! vault (new DKG) to retire that member's share, which this layer does not do.
//!
//! The Enclave signs with `ecdsaSignatureMessageX962SHA256` (ASN.1/DER ECDSA over SHA-256 of
//! the message), so [`DeviceRegistry::verify_login`] accepts DER first, then a fixed 64-byte
//! signature, and p256 verifies with SHA-256 — matching both the Enclave and the stand-in.

use crate::signer::recovery::verify_device_authorization;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

const LOGIN_TTL: Duration = Duration::from_secs(120);
const MAX_LOGIN_CHALLENGES: usize = 256;
const LOGIN_CHALLENGES_PER_GRANT: usize = 16;

pub fn device_id(device_pub: &[u8]) -> Result<Vec<u8>, String> {
    VerifyingKey::from_sec1_bytes(device_pub)
        .map(|key| key.to_encoded_point(true).as_bytes().to_vec())
        .map_err(|e| format!("bad device key: {e}"))
}

#[derive(Clone)]
pub struct DeviceRegistry {
    recovery_signing_pub: [u8; 32],
    devices: BTreeMap<Vec<u8>, bool>,
    challenges: BTreeMap<[u8; 32], (Instant, [u8; 32], bool)>,
}

impl DeviceRegistry {
    pub fn new(recovery_signing_pub: [u8; 32]) -> Self {
        Self {
            recovery_signing_pub,
            devices: BTreeMap::new(),
            challenges: BTreeMap::new(),
        }
    }

    pub fn enroll(&mut self, device_pub: &[u8], authorization: &[u8; 64]) -> Result<(), String> {
        let id = device_id(device_pub)?;
        if self.devices.get(&id) == Some(&false) {
            return Err("revoked device requires a recovery renewal authorization".into());
        }
        verify_device_authorization(&self.recovery_signing_pub, device_pub, authorization)?;
        self.devices.insert(id, true);
        Ok(())
    }

    pub fn enroll_renewal(
        &mut self,
        device_pub: &[u8],
        generation: &[u8; 32],
        authorization: &[u8; 64],
    ) -> Result<(), String> {
        let message = crate::signer::recovery::device_renewal_message(device_pub, generation);
        verify_device_authorization(&self.recovery_signing_pub, &message, authorization)?;
        self.devices.insert(device_id(device_pub)?, true);
        self.invalidate_challenges();
        Ok(())
    }

    pub fn issue_challenge(&mut self, grant: [u8; 32]) -> Option<[u8; 32]> {
        let now = Instant::now();
        self.challenges
            .retain(|_, (issued, _, _)| now.duration_since(*issued) < LOGIN_TTL);
        if self.challenges.len() >= MAX_LOGIN_CHALLENGES
            || self
                .challenges
                .values()
                .filter(|(_, owner, _)| grant == *owner)
                .count()
                >= LOGIN_CHALLENGES_PER_GRANT
        {
            return None;
        }
        let mut challenge = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut challenge);
        self.challenges.insert(challenge, (now, grant, false));
        Some(challenge)
    }

    pub fn verify_login(
        &mut self,
        device_pub: &[u8],
        challenge: &[u8; 32],
        signature: &[u8],
    ) -> Result<(), String> {
        if self.devices.get(&device_id(device_pub)?) != Some(&true) {
            return Err("device is not enrolled or has been revoked".into());
        }
        if let Some((issued, _, used)) = self.challenges.get_mut(challenge) {
            if !*used && issued.elapsed() < LOGIN_TTL {
                *used = true;
                return verify_device_signature(device_pub, challenge, signature);
            }
        }
        Err("unknown, expired or already-used login challenge".into())
    }

    fn invalidate_challenges(&mut self) {
        for (_, _, used) in self.challenges.values_mut() {
            *used = true;
        }
    }

    pub fn revoke(&mut self, device_pub: &[u8]) {
        if let Ok(id) = device_id(device_pub) {
            if let Some(active) = self.devices.get_mut(&id) {
                *active = false;
                self.invalidate_challenges();
            }
        }
    }
}

pub fn verify_device_signature(
    device_pub: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    let vk =
        VerifyingKey::from_sec1_bytes(device_pub).map_err(|e| format!("bad device key: {e}"))?;
    let sig = Signature::from_der(signature)
        .or_else(|_| Signature::from_slice(signature))
        .map_err(|e| format!("bad signature encoding: {e}"))?;
    vk.verify(message, &sig)
        .map_err(|_| "device signature does not verify".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::recovery::RecoveryKey;
    use p256::ecdsa::{signature::Signer, SigningKey};

    fn device() -> (SigningKey, Vec<u8>) {
        let sk = SigningKey::random(&mut rand_core::OsRng);
        let pubkey = sk
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        (sk, pubkey)
    }

    fn sign(sk: &SigningKey, challenge: &[u8; 32]) -> Vec<u8> {
        let sig: Signature = sk.sign(challenge);
        sig.to_der().as_bytes().to_vec()
    }

    #[test]
    fn device_signature_binds_the_registration_transcript() {
        let (sk, public) = device();
        let message = b"loki-member-registration-v1\ncoordinator\n1\nidentity\nrelay\nendpoint";
        let sig: Signature = sk.sign(message);
        assert!(verify_device_signature(&public, message, sig.to_der().as_bytes()).is_ok());
        assert!(
            verify_device_signature(&public, b"changed endpoint", sig.to_der().as_bytes()).is_err()
        );
        assert!(verify_device_signature(&device().1, message, sig.to_der().as_bytes()).is_err());
    }

    #[test]
    fn recovery_authorized_device_logs_in_and_cannot_replay() {
        let (_words, recovery) = RecoveryKey::generate().unwrap();
        let mut registry = DeviceRegistry::new(recovery.signing_public());
        let (sk, device_pub) = device();

        let authz = recovery.authorize_device(&device_pub);
        registry.enroll(&device_pub, &authz).unwrap();

        let challenge = registry.issue_challenge([0; 32]).unwrap();
        let sig = sign(&sk, &challenge);
        registry
            .verify_login(&device_pub, &challenge, &sig)
            .unwrap();

        assert!(registry
            .verify_login(&device_pub, &challenge, &sig)
            .is_err());
    }

    #[test]
    fn a_device_the_recovery_key_did_not_authorize_cannot_enroll() {
        let (_w, recovery) = RecoveryKey::generate().unwrap();
        let mut registry = DeviceRegistry::new(recovery.signing_public());
        let (_sk, device_pub) = device();

        let (_w2, other) = RecoveryKey::generate().unwrap();
        let forged = other.authorize_device(&device_pub);
        assert!(registry.enroll(&device_pub, &forged).is_err());
    }

    #[test]
    fn revoked_device_cannot_log_in() {
        let (_w, recovery) = RecoveryKey::generate().unwrap();
        let mut registry = DeviceRegistry::new(recovery.signing_public());
        let (sk, device_pub) = device();
        registry
            .enroll(&device_pub, &recovery.authorize_device(&device_pub))
            .unwrap();

        registry.revoke(&device_pub);
        let challenge = registry.issue_challenge([0; 32]).unwrap();
        let sig = sign(&sk, &challenge);
        assert!(registry
            .verify_login(&device_pub, &challenge, &sig)
            .is_err());
    }

    #[test]
    fn unknown_device_and_unissued_challenge_are_refused() {
        let (_w, recovery) = RecoveryKey::generate().unwrap();
        let mut registry = DeviceRegistry::new(recovery.signing_public());
        let (sk, device_pub) = device();
        registry
            .enroll(&device_pub, &recovery.authorize_device(&device_pub))
            .unwrap();

        let (sk2, other_pub) = device();
        let challenge = registry.issue_challenge([0; 32]).unwrap();
        assert!(registry
            .verify_login(&other_pub, &challenge, &sign(&sk2, &challenge))
            .is_err());

        let bogus = [9u8; 32];
        assert!(registry
            .verify_login(&device_pub, &bogus, &sign(&sk, &bogus))
            .is_err());
    }

    #[test]
    fn a_valid_signature_over_the_wrong_challenge_is_refused() {
        let (_w, recovery) = RecoveryKey::generate().unwrap();
        let mut registry = DeviceRegistry::new(recovery.signing_public());
        let (sk, device_pub) = device();
        registry
            .enroll(&device_pub, &recovery.authorize_device(&device_pub))
            .unwrap();

        let issued = registry.issue_challenge([0; 32]).unwrap();
        let sig = sign(&sk, &[1u8; 32]);
        assert!(registry.verify_login(&device_pub, &issued, &sig).is_err());
    }

    /// Hardware proof: a REAL ephemeral Secure Enclave P-256 key is the device login key. Its
    /// public point enrolls (recovery-authorized) and it signs a live challenge the registry
    /// accepts — the Enclave private key never leaves the chip. Ephemeral, so this runs
    /// unsigned from `cargo test`; the persistent, Face-ID-gated key is the same surface.
    #[cfg(all(feature = "apple-enclave", target_os = "macos"))]
    #[test]
    fn real_enclave_key_logs_in() {
        use crate::signer::secure_element_apple::AppleSecureElement;

        let device = AppleSecureElement::ephemeral().expect("open ephemeral Secure Enclave");
        let device_pub = device.public_key_sec1().expect("export Enclave public key");

        let (_words, recovery) = RecoveryKey::generate().unwrap();
        let mut registry = DeviceRegistry::new(recovery.signing_public());
        registry
            .enroll(&device_pub, &recovery.authorize_device(&device_pub))
            .expect("recovery authorizes the Enclave device key");

        let challenge = registry.issue_challenge([0; 32]).unwrap();
        let sig = device
            .sign(&challenge)
            .expect("Enclave signs the challenge");
        registry
            .verify_login(&device_pub, &challenge, &sig)
            .expect("the Secure Enclave's signature logs the device in");
    }
}
