//! Public vault membership and frostd addresses for FROST drivers.

use std::collections::BTreeMap;

use blake2b_simd::Params;
use reddsa_frost::frost::redpallas as frost;

use crate::setup_transport::PublicIdentity;
use crate::transport::Peer;

pub struct FrostRoster {
    pub vault_id: [u8; 32],
    pub threshold: u16,
    pub members: BTreeMap<frost::Identifier, PublicIdentity>,
}

impl FrostRoster {
    pub fn from_identities(
        vault_id: [u8; 32],
        threshold: u16,
        members: impl IntoIterator<Item = (frost::Identifier, PublicIdentity)>,
    ) -> Self {
        Self {
            vault_id,
            threshold,
            members: members.into_iter().collect(),
        }
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        let mut hash = Params::new()
            .hash_length(32)
            .personal(b"Loki_frostr_v1")
            .to_state();
        hash.update(&self.vault_id);
        hash.update(&self.threshold.to_be_bytes());
        hash.update(&(self.members.len() as u32).to_be_bytes());
        for (id, member) in &self.members {
            hash.update(&id.serialize());
            hash.update(&member.id.to_be_bytes());
            hash.update(&member.signing);
            hash.update(&member.encryption);
        }
        hash.finalize()
            .as_bytes()
            .try_into()
            .expect("32-byte fingerprint")
    }

    pub fn peer_of(&self, id: &frost::Identifier) -> Option<Peer> {
        self.members.get(id).map(|member| Peer(member.encryption))
    }

    pub fn peer_list(&self) -> Vec<Peer> {
        self.members
            .values()
            .map(|member| Peer(member.encryption))
            .collect()
    }
}
