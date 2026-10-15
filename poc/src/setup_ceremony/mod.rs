#[cfg(feature = "relay-communication")]
pub use admission_checkpoint::AdmissionCheckpointAuthority;
#[cfg(feature = "relay-communication")]
mod admission_checkpoint;
mod engine;
pub use engine::{
    CeremonyPhase, CeremonyRecord, CeremonyStep, CheckpointAuthority, CheckpointState,
    SavedCheckpoint, SetupCeremony,
};
pub(crate) mod journal;
use crate::{member_state::Roster, setup_transport::Identity};
use std::collections::{BTreeMap, BTreeSet};

pub struct AcceptedCeremonyRoster {
    roster: Roster,
    network: String,
    operator_digest: [u8; 32],
    transport_required: bool,
}
impl AcceptedCeremonyRoster {
    fn validate(roster: &Roster, network: &str, operator_digest: &[u8; 32]) -> Result<(), String> {
        if network != "regtest"
            || roster.vault == [0; 32]
            || *operator_digest == [0; 32]
            || roster.threshold != 2
            || !matches!(roster.members.len(), 3 | 4)
            || roster.members.keys().copied().collect::<Vec<_>>()
                != (1..=roster.members.len() as u16).collect::<Vec<_>>()
        {
            return Err("setup_policy".into());
        }
        let mut signing = BTreeSet::new();
        let mut encryption = BTreeSet::new();
        for (&id, member) in &roster.members {
            let key = ed25519_dalek::VerifyingKey::from_bytes(&member.signing)
                .map_err(|_| "setup_identity")?;
            let probe = x25519_dalek::StaticSecret::from([1; 32]);
            if member.id != id
                || key.is_weak()
                || !signing.insert(member.signing)
                || !encryption.insert(member.encryption)
                || !probe
                    .diffie_hellman(&x25519_dalek::PublicKey::from(member.encryption))
                    .was_contributory()
            {
                return Err("setup_identity".into());
            }
        }
        Ok(())
    }
    pub fn agreement_payload(
        roster: &Roster,
        network: &str,
        operator_digest: &[u8; 32],
    ) -> Result<Vec<u8>, String> {
        Self::validate(roster, network, operator_digest)?;
        let mut out = vec![1, network.len() as u8];
        out.extend_from_slice(network.as_bytes());
        out.extend_from_slice(&roster.threshold.to_be_bytes());
        out.extend_from_slice(&(roster.members.len() as u16).to_be_bytes());
        out.extend_from_slice(&roster.fingerprint());
        out.extend_from_slice(operator_digest);
        Ok(out)
    }
    pub fn verify(
        roster: Roster,
        network: &str,
        operator_digest: [u8; 32],
        own: &Identity,
        votes: &BTreeMap<u16, Vec<u8>>,
    ) -> Result<Self, String> {
        let payload = Self::agreement_payload(&roster, network, &operator_digest)?;
        if roster.members.get(&own.public().id) != Some(&own.public())
            || votes.keys().copied().collect::<Vec<_>>()
                != roster.members.keys().copied().collect::<Vec<_>>()
        {
            return Err("setup_agreement".into());
        }
        for (id, peer) in &roster.members {
            if own
                .verify_setup_agreement(peer, &roster.vault, &votes[id])
                .map_err(|_| "setup_agreement")?
                != payload
            {
                return Err("setup_agreement".into());
            }
        }
        Ok(Self {
            roster,
            network: network.to_owned(),
            operator_digest,
            transport_required: false,
        })
    }
    pub fn roster(&self) -> &Roster {
        &self.roster
    }
    pub fn network(&self) -> &str {
        &self.network
    }
    pub fn operator_digest(&self) -> &[u8; 32] {
        &self.operator_digest
    }
    pub fn context_digest(&self) -> [u8; 32] {
        Self::hash_context(
            Self::agreement_payload(&self.roster, &self.network, &self.operator_digest)
                .expect("verified ceremony policy"),
            self.transport_required,
        )
    }
    // This digest identifies an existing hosted journal; it grants no ceremony authority.
    pub(crate) fn hosted_context_digest(
        roster: &Roster,
        network: &str,
        operator_digest: &[u8; 32],
    ) -> Result<[u8; 32], String> {
        Ok(Self::hash_context(
            Self::agreement_payload(roster, network, operator_digest)?,
            true,
        ))
    }
    fn hash_context(mut payload: Vec<u8>, transport_required: bool) -> [u8; 32] {
        payload.push(u8::from(transport_required));
        blake2b_simd::Params::new()
            .hash_length(32)
            .personal(b"Loki_setup_ctx1")
            .hash(&payload)
            .as_bytes()
            .try_into()
            .expect("32-byte hash")
    }
    #[cfg(feature = "relay-communication")]
    pub fn from_transport(
        accepted: &loki_relay_client::AcceptedSetupRoster,
    ) -> Result<Self, String> {
        let policy = accepted.context().policy();
        let members = &accepted.roster().members;
        if accepted.roster().vault != policy.ceremony
            || policy.threshold != 2
            || members.len() != policy.member_count as usize
        {
            return Err("setup_agreement".into());
        }
        let document=serde_json::to_vec(&serde_json::json!({"vault":hex::encode(policy.ceremony),"threshold":policy.threshold,"members":members.iter().map(|m|serde_json::json!({"id":m.id,"signing":hex::encode(m.signing),"encryption":hex::encode(m.encryption)})).collect::<Vec<_>>()})).map_err(|_|"setup_agreement")?;
        let roster = Roster::from_bytes(&document).map_err(|_| "setup_agreement")?;
        Self::validate(&roster, &policy.network, &policy.config_digest)?;
        Ok(Self {
            roster,
            network: policy.network.clone(),
            operator_digest: policy.config_digest,
            transport_required: true,
        })
    }
}
