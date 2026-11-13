//! Share repair ceremony — the Repairable Threshold Scheme (RTS, <https://eprint.iacr.org/2017/1155>),
//! Loki's group-assisted recovery route.
//!
//! When a member permanently loses its FROST share (device AND recovery words both gone), any
//! `threshold` remaining members act as HELPERS and rebuild *exactly that member's* share. The
//! group secret is never reconstructed and no one else's share changes — the repaired member
//! ends up with the same share it was dealt at DKG.
//!
//! The three RTS steps, wrapped for Pallas with Loki's own check on the result:
//!   1. [`helper_part1`] — each helper, for the lost member, produces one `Delta` per helper.
//!   2. [`helper_part2`] — each helper sums the deltas addressed to it into one `Sigma`.
//!   3. [`repaired_part3`] — the member sums the helpers' sigmas into its share AND verifies
//!      the rebuilt share against the group's public verifying share, so a wrong or malicious
//!      repair is refused rather than trusted.
//!
//! SECURITY — the `Delta`s (helper→helper) and `Sigma`s (helper→member) are secret additive
//! shares of the lost share: they MUST travel over the encrypted member-to-member channel,
//! never through the keyless coordinator in clear (hence [`Delta`]/[`Sigma`] expose
//! `serialize`/`deserialize` for that channel). Repair rebuilds the SAME share, so it does NOT
//! retire a suspected-compromised share — that still requires a fresh vault / re-key. This
//! ceremony is implemented but UNAUDITED; do not expose it in product until reviewed.

use reddsa_frost::frost::redpallas as frost;
use frost::keys::repairable::{Delta, Sigma};
use frost::keys::{KeyPackage, PublicKeyPackage};
use frost::{Identifier, PallasBlake2b512};
use std::collections::BTreeMap;

/// Step 1, run by each helper. `helpers` is the full helper set (threshold-many identifiers,
/// including this helper itself); `lost` is the member being repaired. Returns one [`Delta`]
/// to deliver to each helper in the set.
pub fn helper_part1(
    helpers: &[Identifier],
    helper_key_package: &KeyPackage,
    lost: Identifier,
) -> Result<BTreeMap<Identifier, Delta>, String> {
    frost::keys::repairable::repair_share_part1::<PallasBlake2b512, _>(
        helpers,
        helper_key_package,
        &mut rand_core::OsRng,
        lost,
    )
    .map_err(|e| format!("repair part1: {e}"))
}

/// Step 2, run by each helper: sum the deltas it received — one from every helper, including
/// its own — into the single sigma it sends to the member being repaired.
pub fn helper_part2(deltas: &[Delta]) -> Sigma {
    frost::keys::repairable::repair_share_part2(deltas)
}

/// Step 3, run by the member being repaired: rebuild its [`KeyPackage`] from the helpers'
/// sigmas, then check the rebuilt signing share against the group's public verifying share for
/// this identifier. A share that does not match the public commitment is rejected, so a
/// member never trusts a botched or malicious repair.
pub fn repaired_part3(
    sigmas: &[Sigma],
    identifier: Identifier,
    public: &PublicKeyPackage,
) -> Result<KeyPackage, String> {
    let kp = frost::keys::repairable::repair_share_part3(sigmas, identifier, public)
        .map_err(|e| format!("repair part3: {e}"))?;
    let expected = public
        .verifying_shares()
        .get(&identifier)
        .ok_or("the group has no verifying share for this member")?;
    if kp.verifying_share() != expected {
        return Err("repaired share does not match the group's public verifying share".into());
    }
    Ok(kp)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deal a t-of-n vault, "lose" one member's share, and have `threshold` other members run
    /// the ceremony. The rebuilt share must equal the dealt one (so it signs for the group).
    fn repair(threshold: u16, members: u16, lost_id: u16) {
        let (shares, public) = frost::keys::generate_with_dealer(
            members,
            threshold,
            frost::keys::IdentifierList::Default,
            &mut rand_core::OsRng,
        )
        .expect("dealer keygen");
        let kps: BTreeMap<Identifier, KeyPackage> = shares
            .iter()
            .map(|(id, s)| (*id, KeyPackage::try_from(s.clone()).unwrap()))
            .collect();
        let lost = Identifier::try_from(lost_id).unwrap();

        // Helpers: the first `threshold` members other than the lost one.
        let helpers: Vec<Identifier> = kps
            .keys()
            .copied()
            .filter(|id| *id != lost)
            .take(threshold as usize)
            .collect();
        assert_eq!(helpers.len(), threshold as usize);

        // Part 1: each helper produces a delta for every helper (routed helper -> helper).
        let part1: BTreeMap<Identifier, BTreeMap<Identifier, Delta>> = helpers
            .iter()
            .map(|h| (*h, helper_part1(&helpers, &kps[h], lost).unwrap()))
            .collect();

        // Part 2: helper `l` collects the delta addressed to it from every helper `j`.
        let sigmas: Vec<Sigma> = helpers
            .iter()
            .map(|l| {
                let deltas: Vec<Delta> = helpers.iter().map(|j| part1[j][l]).collect();
                helper_part2(&deltas)
            })
            .collect();

        // Part 3: the lost member rebuilds + verifies, and the share matches the dealt one.
        let repaired = repaired_part3(&sigmas, lost, &public).unwrap();
        assert_eq!(
            repaired.signing_share(),
            kps[&lost].signing_share(),
            "repaired share must equal the originally dealt share"
        );
    }

    #[test]
    fn helpers_repair_a_lost_share_2_of_3() {
        repair(2, 3, 2);
    }

    #[test]
    fn helpers_repair_a_lost_share_3_of_5() {
        repair(3, 5, 4);
    }

    #[test]
    fn deltas_and_sigmas_survive_the_wire() {
        // The secret additive shares serialize for the encrypted member channel and reload
        // byte-identically.
        let (shares, _public) = frost::keys::generate_with_dealer(
            3,
            2,
            frost::keys::IdentifierList::Default,
            &mut rand_core::OsRng,
        )
        .unwrap();
        let kps: BTreeMap<Identifier, KeyPackage> = shares
            .iter()
            .map(|(id, s)| (*id, KeyPackage::try_from(s.clone()).unwrap()))
            .collect();
        let helpers: Vec<Identifier> = kps.keys().copied().take(2).collect();
        let lost = *kps.keys().last().unwrap();
        let deltas = helper_part1(&helpers, &kps[&helpers[0]], lost).unwrap();
        let one = deltas.values().next().unwrap();
        assert!(Delta::deserialize(&one.serialize()).unwrap() == *one, "delta round-trips");
        let sigma = helper_part2(&[*one]);
        assert!(Sigma::deserialize(&sigma.serialize()).unwrap() == sigma, "sigma round-trips");
    }

    #[test]
    fn repair_refuses_too_few_helpers_and_a_corrupted_sigma() {
        let (shares, public) = frost::keys::generate_with_dealer(
            3,
            2,
            frost::keys::IdentifierList::Default,
            &mut rand_core::OsRng,
        )
        .unwrap();
        let kps: BTreeMap<Identifier, KeyPackage> = shares
            .iter()
            .map(|(id, s)| (*id, KeyPackage::try_from(s.clone()).unwrap()))
            .collect();
        let lost = Identifier::try_from(3u16).unwrap();
        let h: Vec<Identifier> = kps.keys().copied().filter(|id| *id != lost).take(2).collect();

        // (a) A sub-threshold helper set is refused at step 1 — the ceremony cannot even start.
        assert!(
            helper_part1(&h[..1], &kps[&h[0]], lost).is_err(),
            "fewer than `threshold` helpers must be rejected at part 1"
        );

        // (b) Right helpers, but a CORRUPTED sigma (one helper omits the other's delta): part 3's
        // check against the public verifying share refuses the bad share instead of trusting it.
        let part1: BTreeMap<Identifier, BTreeMap<Identifier, Delta>> = h
            .iter()
            .map(|x| (*x, helper_part1(&h, &kps[x], lost).unwrap()))
            .collect();
        let mut sigmas: Vec<Sigma> = h
            .iter()
            .map(|l| helper_part2(&h.iter().map(|j| part1[j][l]).collect::<Vec<_>>()))
            .collect();
        sigmas[0] = helper_part2(&[part1[&h[0]][&h[0]]]); // only one of the two required deltas
        assert!(
            repaired_part3(&sigmas, lost, &public).is_err(),
            "a corrupted sigma must be caught by the public-verifying-share check"
        );
    }
}
