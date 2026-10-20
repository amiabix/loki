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
use crate::{
    member_state::{Roster, ValidatedRoster},
    setup_transport::Identity,
};
#[cfg(feature = "relay-communication")]
use crate::network::TESTNET_NU7_BIRTH;
use std::collections::BTreeMap;

/// Setup format version carried in the agreement payload (C9). A member on another
/// format computes a different payload, so agreement fails before any key generation.
pub const SETUP_VERSION: u8 = 2;

pub struct AcceptedCeremonyRoster {
    roster: ValidatedRoster,
    network: String,
    operator_digest: [u8; 32],
    transport_required: bool,
}
impl AcceptedCeremonyRoster {
    /// The shared roster gate plus the hosted-only checks: the network label and a
    /// non-zero operator digest.
    fn validate(
        roster: Roster,
        network: &str,
        operator_digest: &[u8; 32],
    ) -> Result<ValidatedRoster, String> {
        if network != roster.network.label() || *operator_digest == [0; 32] {
            return Err("setup_policy".into());
        }
        ValidatedRoster::new(roster).map_err(|e| e.to_string())
    }
    pub fn agreement_payload(
        roster: &Roster,
        network: &str,
        operator_digest: &[u8; 32],
    ) -> Result<Vec<u8>, String> {
        if network != roster.network.label() || *operator_digest == [0; 32] {
            return Err("setup_policy".into());
        }
        ValidatedRoster::check(roster).map_err(|e| e.to_string())?;
        let mut out = vec![SETUP_VERSION, network.len() as u8];
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
            roster: Self::validate(roster, network, &operator_digest)?,
            network: network.to_owned(),
            operator_digest,
            transport_required: false,
        })
    }
    pub fn roster(&self) -> &Roster {
        &self.roster
    }
    pub fn validated(&self) -> &ValidatedRoster {
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
    #[cfg(any(feature = "relay-communication", test))]
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
            || !crate::member_state::valid_policy(policy.threshold, usize::from(policy.member_count))
            || members.len() != policy.member_count as usize
        {
            return Err("setup_agreement".into());
        }
        let mut document = serde_json::json!({"vault":hex::encode(policy.ceremony),"threshold":policy.threshold,"members":members.iter().map(|m|serde_json::json!({"id":m.id,"signing":hex::encode(m.signing),"encryption":hex::encode(m.encryption)})).collect::<Vec<_>>()});
        if policy.network == "testnet" {
            document["network"] = serde_json::json!("testnet");
            document["birth_height"] = serde_json::json!(TESTNET_NU7_BIRTH);
        }
        let document = serde_json::to_vec(&document).map_err(|_| "setup_agreement")?;
        let roster = Roster::from_bytes(&document).map_err(|_| "setup_agreement")?;
        Ok(Self {
            roster: Self::validate(roster, &policy.network, &policy.config_digest)?,
            network: policy.network.clone(),
            operator_digest: policy.config_digest,
            transport_required: true,
        })
    }
}
