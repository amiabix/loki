//! Local roster agreement only. A signed vote is not a DKG checkpoint or courier authority.

use super::SETUP_VERSION;
use crate::{
    member_state::{Roster, ValidatedRoster},
    network::{VaultNetwork, TESTNET_NU7_BIRTH},
    setup_transport::Identity,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const ERROR: &str = "setup_agreement";
const DOMAIN: &[u8; 8] = b"LOKILOC1";
const MAX_VOTE: usize = 2048;

/// Generate a fresh context once per setup attempt and persist it before asking for votes.
pub fn generate_local_context() -> [u8; 32] {
    loop {
        let mut context = [0; 32];
        OsRng.fill_bytes(&mut context);
        if context != [0; 32] {
            return context;
        }
    }
}

/// One member's signed agreement with the exact local roster and setup context.
#[derive(Clone, Serialize, Deserialize)]
pub struct LocalRosterVote {
    pub slot: u16,
    pub wire: Vec<u8>,
}

/// Verified local votes. This cannot be used as hosted admission or a checkpoint authority.
pub struct LocalAcceptedRoster {
    roster: ValidatedRoster,
    transcript: Vec<u8>,
}

impl LocalAcceptedRoster {
    pub fn roster(&self) -> &Roster {
        &self.roster
    }

    pub fn validated(&self) -> &ValidatedRoster {
        &self.roster
    }

    /// Stable across restart when the roster and context are reopened unchanged.
    pub fn context_digest(&self) -> [u8; 32] {
        blake2b_simd::Params::new()
            .hash_length(32)
            .personal(b"Loki_local_ctx1")
            .hash(&self.transcript)
            .as_bytes()
            .try_into()
            .expect("32-byte digest")
    }

    pub fn transcript(&self) -> &[u8] {
        &self.transcript
    }
}

fn transcript(roster: &Roster, context: [u8; 32]) -> Result<Vec<u8>, String> {
    if context == [0; 32] || roster.setup_version != Some(u16::from(SETUP_VERSION)) {
        return Err(ERROR.into());
    }
    ValidatedRoster::check(roster).map_err(|error| error.to_string())?;
    match (roster.network, roster.birth_height) {
        (VaultNetwork::Regtest, None) => {}
        (VaultNetwork::Testnet, Some(height)) if height >= TESTNET_NU7_BIRTH => {}
        _ => return Err(ERROR.into()),
    }
    let mut out = Vec::with_capacity(128 + roster.members.len() * 66);
    out.extend_from_slice(DOMAIN);
    out.push(SETUP_VERSION);
    out.extend_from_slice(&roster.vault);
    let network = roster.network.label().as_bytes();
    out.push(network.len() as u8);
    out.extend_from_slice(network);
    out.extend_from_slice(&roster.birth_height.unwrap_or(0).to_be_bytes());
    out.extend_from_slice(&roster.threshold.to_be_bytes());
    out.extend_from_slice(&(roster.members.len() as u16).to_be_bytes());
    for member in roster.members.values() {
        out.extend_from_slice(&member.id.to_be_bytes());
        out.extend_from_slice(&member.signing);
        out.extend_from_slice(&member.encryption);
    }
    out.extend_from_slice(&roster.fingerprint());
    out.extend_from_slice(&context);
    Ok(out)
}

/// Sign the canonical local transcript after checking this identity's exact roster entry.
pub fn local_roster_vote(
    roster: &Roster,
    context: [u8; 32],
    identity: &Identity,
) -> Result<LocalRosterVote, String> {
    let payload = transcript(roster, context)?;
    let public = identity.public();
    if roster.members.get(&public.id) != Some(&public) {
        return Err(ERROR.into());
    }
    Ok(LocalRosterVote {
        slot: public.id,
        wire: identity.sign_setup_agreement(&roster.vault, &payload)?,
    })
}

/// Require exactly one valid signed vote from each roster member.
pub fn verify_local_roster(
    roster: Roster,
    context: [u8; 32],
    own: &Identity,
    votes: &[LocalRosterVote],
) -> Result<LocalAcceptedRoster, String> {
    let payload = transcript(&roster, context)?;
    let own_public = own.public();
    if roster.members.get(&own_public.id) != Some(&own_public)
        || votes.len() != roster.members.len()
    {
        return Err(ERROR.into());
    }
    let mut unique = BTreeMap::new();
    for vote in votes {
        if vote.wire.len() > MAX_VOTE || unique.insert(vote.slot, vote.wire.as_slice()).is_some() {
            return Err(ERROR.into());
        }
    }
    if unique.keys().copied().collect::<Vec<_>>()
        != roster.members.keys().copied().collect::<Vec<_>>()
    {
        return Err(ERROR.into());
    }
    for (slot, peer) in &roster.members {
        if own
            .verify_setup_agreement(peer, &roster.vault, unique[slot])
            .map_err(|_| ERROR)?
            != payload
        {
            return Err(ERROR.into());
        }
    }
    Ok(LocalAcceptedRoster {
        roster: ValidatedRoster::new(roster).map_err(|error| error.to_string())?,
        transcript: payload,
    })
}
