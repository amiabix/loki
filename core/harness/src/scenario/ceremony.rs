use crate::vault::{ceremony_and_sign, Measurements};

pub fn ceremony(members: u16, threshold: u16) -> Result<Measurements, String> {
    ceremony_and_sign(members, threshold)
}
