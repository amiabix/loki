use crate::vault::{ceremony_and_sign, Measurements};

/// Run full v2 DKG, check every member's group address, and sign with a quorum.
pub fn ceremony(members: u16, threshold: u16) -> Result<Measurements, String> {
    ceremony_and_sign(members, threshold)
}
