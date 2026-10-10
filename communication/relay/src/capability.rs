use loki_relay_protocol::types::Id32;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Role {
    Read = 1,
    Append = 2,
    Admin = 3,
}

pub struct Capability(Zeroizing<[u8; 32]>);

impl Capability {
    pub fn new(secret: [u8; 32]) -> Self {
        Self(Zeroizing::new(secret))
    }

    pub fn verify(&self, role: Role, mailbox: Id32, expected: &Id32) -> bool {
        bool::from(verifier(role, mailbox, &self.0).ct_eq(expected))
    }

    pub fn verify_provision(&self, run: Id32, expected: &Id32) -> bool {
        bool::from(provisioning_verifier(run, &self.0).ct_eq(expected))
    }
}

pub fn provisioning_verifier(run: Id32, secret: &[u8; 32]) -> Id32 {
    let mut hash = Sha256::new();
    hash.update(b"Loki_Relay_Provision_v1\0");
    hash.update(run);
    hash.update(secret);
    hash.finalize().into()
}

pub fn verifier(role: Role, mailbox: Id32, secret: &[u8; 32]) -> Id32 {
    let mut hash = Sha256::new();
    hash.update(b"Loki_Relay_Capability_v1\0");
    hash.update([role as u8]);
    hash.update(mailbox);
    hash.update(secret);
    hash.finalize().into()
}
