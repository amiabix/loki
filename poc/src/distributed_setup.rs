//! One member's dealerless DKG state. No process ever holds another member's secret package.
//!
//! The caller must authenticate each sender and encrypt every round-two package before
//! transport. This module does not make a vault active: a certificate exchange and the
//! ZIP 2005 viewing-key derivation are still required.

use std::collections::BTreeMap;

use blake2b_simd::Params;
use reddsa_frost::frost::redpallas as frost;

pub struct Member {
    number: u16,
    members: u16,
    secret: frost::keys::dkg::round1::SecretPackage,
    own_round1: Vec<u8>,
}

pub struct Round2Member {
    number: u16,
    members: u16,
    secret: frost::keys::dkg::round2::SecretPackage,
    peer_round1: BTreeMap<frost::Identifier, frost::keys::dkg::round1::Package>,
    own_round1: Vec<u8>,
    pub transcript: [u8; 32],
}

pub struct Completed {
    number: u16,
    members: u16,
    key_package: zeroize::Zeroizing<Vec<u8>>,
    public_package: Vec<u8>,
    group_ak: [u8; 32],
    transcript: [u8; 32],
}

pub struct Certified {
    pub key_package: Vec<u8>,
    pub public_package: Vec<u8>,
    pub group_ak: [u8; 32],
    pub transcript: [u8; 32],
}

fn expected_ids(members: u16) -> Vec<u16> {
    (1..=members).collect()
}

impl Member {
    pub fn start(id: u16) -> Result<(Self, Vec<u8>), String> {
        Self::start_with_policy(id, 2, 3)
    }

    pub fn start_with_policy(
        id: u16,
        threshold: u16,
        members: u16,
    ) -> Result<(Self, Vec<u8>), String> {
        if !matches!((threshold, members), (2, 3) | (2, 4) | (3, 4))
            || !expected_ids(members).contains(&id)
        {
            return Err("supported DKG policies are 2-of-3, 2-of-4, and 3-of-4".into());
        }
        let identifier = frost::Identifier::try_from(id).map_err(|e| e.to_string())?;
        let (secret, public) =
            frost::keys::dkg::part1(identifier, members, threshold, rand_core::OsRng)
                .map_err(|e| e.to_string())?;
        let bytes = public.serialize().map_err(|e| e.to_string())?;
        Ok((
            Self {
                number: id,
                members,
                secret,
                own_round1: bytes.clone(),
            },
            bytes,
        ))
    }

    pub fn advance(
        self,
        round1: &BTreeMap<u16, Vec<u8>>,
    ) -> Result<(Round2Member, BTreeMap<u16, Vec<u8>>), String> {
        if round1.keys().copied().collect::<Vec<_>>() != expected_ids(self.members) {
            return Err("round one needs exactly the certified members".into());
        }
        let own = self.number;
        if round1[&own] != self.own_round1 {
            return Err("own round-one package changed in transit".into());
        }
        let mut transcript_hasher = Params::new()
            .hash_length(32)
            .personal(b"Loki_dkg_r1_v1")
            .to_state();
        let mut peers = BTreeMap::new();
        for (&sender, bytes) in round1 {
            transcript_hasher.update(&sender.to_be_bytes());
            transcript_hasher.update(&(bytes.len() as u32).to_be_bytes());
            transcript_hasher.update(bytes);
            if sender != own {
                peers.insert(
                    frost::Identifier::try_from(sender).map_err(|e| e.to_string())?,
                    frost::keys::dkg::round1::Package::deserialize(bytes)
                        .map_err(|e| format!("member {sender} round one: {e}"))?,
                );
            }
        }
        let mut transcript = [0u8; 32];
        transcript.copy_from_slice(transcript_hasher.finalize().as_bytes());
        let (secret, outgoing) =
            frost::keys::dkg::part2(self.secret, &peers).map_err(|e| e.to_string())?;
        let mut wire = BTreeMap::new();
        for peer in expected_ids(self.members)
            .into_iter()
            .filter(|peer| *peer != own)
        {
            let id = frost::Identifier::try_from(peer).map_err(|e| e.to_string())?;
            let package = outgoing
                .get(&id)
                .ok_or("missing outgoing round-two package")?;
            wire.insert(peer, package.serialize().map_err(|e| e.to_string())?);
        }
        Ok((
            Round2Member {
                number: self.number,
                members: self.members,
                secret,
                peer_round1: peers,
                own_round1: self.own_round1,
                transcript,
            },
            wire,
        ))
    }
}

impl Round2Member {
    pub fn finish(&self, incoming: &BTreeMap<u16, Vec<u8>>) -> Result<Completed, String> {
        let own = self.number;
        if incoming.len() != usize::from(self.members - 1)
            || incoming
                .keys()
                .any(|id| !expected_ids(self.members).contains(id) || *id == own)
        {
            return Err("round two needs one authenticated package from each peer".into());
        }
        let mut packages = BTreeMap::new();
        for (&sender, bytes) in incoming {
            packages.insert(
                frost::Identifier::try_from(sender).map_err(|e| e.to_string())?,
                frost::keys::dkg::round2::Package::deserialize(bytes)
                    .map_err(|e| format!("member {sender} round two: {e}"))?,
            );
        }
        let (key_package, public_package) =
            frost::keys::dkg::part3(&self.secret, &self.peer_round1, &packages)
                .map_err(|e| e.to_string())?;
        let ak: [u8; 32] = public_package
            .verifying_key()
            .serialize()
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "group ak is not 32 bytes")?;
        Ok(Completed {
            number: self.number,
            members: self.members,
            key_package: zeroize::Zeroizing::new(
                key_package.serialize().map_err(|e| e.to_string())?,
            ),
            public_package: public_package.serialize().map_err(|e| e.to_string())?,
            group_ak: ak,
            transcript: self.transcript,
        })
    }
}

impl Completed {
    /// The caller must authenticate the sender of each digest before passing it here.
    pub fn certificate_digest(&self) -> [u8; 32] {
        let hash = Params::new()
            .hash_length(32)
            .personal(b"Loki_dkg_cert_v1")
            .to_state()
            .update(&self.transcript)
            .update(&self.group_ak)
            .update(&(self.public_package.len() as u32).to_be_bytes())
            .update(&self.public_package)
            .finalize();
        hash.as_bytes()
            .try_into()
            .expect("BLAKE2b output is 32 bytes")
    }

    pub fn certify(mut self, digests: &BTreeMap<u16, [u8; 32]>) -> Result<Certified, String> {
        if digests.keys().copied().collect::<Vec<_>>() != expected_ids(self.members) {
            return Err("certificates need exactly the certified members".into());
        }
        let own = self.certificate_digest();
        if digests.values().any(|digest| digest != &own) {
            return Err("members disagree on the DKG transcript or group key".into());
        }
        Ok(Certified {
            key_package: std::mem::take(&mut *self.key_package),
            public_package: self.public_package,
            group_ak: self.group_ak,
            transcript: self.transcript,
        })
    }
}

const CHECKPOINT_MAGIC: &[u8; 8] = b"LOKISNP1";
const CHECKPOINT_LIMIT: usize = 64 * 1024;
const CHECKPOINT_ERROR: &str = "invalid DKG checkpoint";

fn checkpoint_header(phase: u8, number: u16, members: u16) -> zeroize::Zeroizing<Vec<u8>> {
    let mut out = zeroize::Zeroizing::new(CHECKPOINT_MAGIC.to_vec());
    out.push(phase);
    out.extend_from_slice(&number.to_be_bytes());
    out.extend_from_slice(&members.to_be_bytes());
    out
}
fn checkpoint_field(out: &mut Vec<u8>, field: &[u8]) -> Result<(), String> {
    if field.len() > CHECKPOINT_LIMIT
        || out.len().saturating_add(field.len() + 4) > CHECKPOINT_LIMIT
    {
        return Err(CHECKPOINT_ERROR.into());
    }
    out.extend_from_slice(&(field.len() as u32).to_be_bytes());
    out.extend_from_slice(field);
    Ok(())
}
struct CheckpointReader<'a> {
    raw: &'a [u8],
    offset: usize,
}
impl<'a> CheckpointReader<'a> {
    fn new(raw: &'a [u8], phase: u8) -> Result<(Self, u16, u16), String> {
        if raw.len() < 13
            || raw.len() > CHECKPOINT_LIMIT
            || &raw[..8] != CHECKPOINT_MAGIC
            || raw[8] != phase
        {
            return Err(CHECKPOINT_ERROR.into());
        }
        let number = u16::from_be_bytes(raw[9..11].try_into().map_err(|_| CHECKPOINT_ERROR)?);
        let members = u16::from_be_bytes(raw[11..13].try_into().map_err(|_| CHECKPOINT_ERROR)?);
        if !matches!(members, 3 | 4) || !(1..=members).contains(&number) {
            return Err(CHECKPOINT_ERROR.into());
        }
        Ok((Self { raw, offset: 13 }, number, members))
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(n)
            .filter(|e| *e <= self.raw.len())
            .ok_or(CHECKPOINT_ERROR)?;
        let value = &self.raw[self.offset..end];
        self.offset = end;
        Ok(value)
    }
    fn field(&mut self) -> Result<&'a [u8], String> {
        let len =
            u32::from_be_bytes(self.take(4)?.try_into().map_err(|_| CHECKPOINT_ERROR)?) as usize;
        self.take(len)
    }
    fn finish(&self) -> Result<(), String> {
        if self.offset == self.raw.len() {
            Ok(())
        } else {
            Err(CHECKPOINT_ERROR.into())
        }
    }
}
fn checked_round1(
    number: u16,
    threshold: u16,
    raw: &[u8],
) -> Result<frost::keys::dkg::round1::Package, String> {
    let public =
        frost::keys::dkg::round1::Package::deserialize(raw).map_err(|_| CHECKPOINT_ERROR)?;
    if public.serialize().map_err(|_| CHECKPOINT_ERROR)? != raw
        || public
            .commitment()
            .serialize()
            .map_err(|_| CHECKPOINT_ERROR)?
            .len()
            != usize::from(threshold)
    {
        return Err(CHECKPOINT_ERROR.into());
    }
    frost_core::keys::dkg::verify_proof_of_knowledge(
        frost::Identifier::try_from(number).map_err(|_| CHECKPOINT_ERROR)?,
        public.commitment(),
        public.proof_of_knowledge(),
    )
    .map_err(|_| CHECKPOINT_ERROR)?;
    Ok(public)
}
struct SecretCoefficients(Vec<pasta_curves::pallas::Scalar>);
impl Drop for SecretCoefficients {
    fn drop(&mut self) {
        for scalar in &mut self.0 {
            // The vector owns each live scalar; volatile writes prevent removal of the wipe.
            unsafe {
                std::ptr::write_volatile(scalar, pasta_curves::pallas::Scalar::zero());
            }
        }
        std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
    }
}
impl Member {
    pub fn checkpoint(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
        let secret =
            zeroize::Zeroizing::new(self.secret.serialize().map_err(|_| CHECKPOINT_ERROR)?);
        let mut out = checkpoint_header(1, self.number, self.members);
        checkpoint_field(&mut out, &secret)?;
        checkpoint_field(&mut out, &self.own_round1)?;
        Ok(out)
    }
    pub fn restore_checkpoint(raw: &[u8]) -> Result<Self, String> {
        let (mut reader, number, members) = CheckpointReader::new(raw, 1)?;
        let encoded = reader.field()?;
        let secret = frost::keys::dkg::round1::SecretPackage::deserialize(encoded)
            .map_err(|_| CHECKPOINT_ERROR)?;
        let own_round1 = reader.field()?.to_vec();
        reader.finish()?;
        let threshold = *secret.min_signers();
        let public = checked_round1(number, threshold, &own_round1)?;
        let roundtrip = zeroize::Zeroizing::new(secret.serialize().map_err(|_| CHECKPOINT_ERROR)?);
        if *roundtrip != encoded
            || *secret.identifier()
                != frost::Identifier::try_from(number).map_err(|_| CHECKPOINT_ERROR)?
            || !matches!((threshold, members), (2, 3) | (2, 4) | (3, 4))
            || *secret.max_signers() != members
            || secret.commitment() != public.commitment()
        {
            return Err(CHECKPOINT_ERROR.into());
        }
        let coefficients = SecretCoefficients(secret.coefficients());
        let expected = public
            .commitment()
            .serialize()
            .map_err(|_| CHECKPOINT_ERROR)?;
        if coefficients.0.len() != expected.len() {
            return Err(CHECKPOINT_ERROR.into());
        }
        for (scalar, commitment) in coefficients.0.iter().zip(expected) {
            let point = <frost::PallasGroup as frost_core::Group>::generator() * scalar;
            if <frost::PallasGroup as frost_core::Group>::serialize(&point)
                .map_err(|_| CHECKPOINT_ERROR)?
                .as_ref()
                != commitment
            {
                return Err(CHECKPOINT_ERROR.into());
            }
        }
        Ok(Self {
            number,
            members,
            secret,
            own_round1,
        })
    }
}
impl Round2Member {
    pub fn checkpoint(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
        let secret =
            zeroize::Zeroizing::new(self.secret.serialize().map_err(|_| CHECKPOINT_ERROR)?);
        let mut out = checkpoint_header(2, self.number, self.members);
        checkpoint_field(&mut out, &secret)?;
        checkpoint_field(&mut out, &self.own_round1)?;
        checkpoint_field(&mut out, &self.transcript)?;
        for number in expected_ids(self.members)
            .into_iter()
            .filter(|n| *n != self.number)
        {
            out.extend_from_slice(&number.to_be_bytes());
            let identifier = frost::Identifier::try_from(number).map_err(|_| CHECKPOINT_ERROR)?;
            checkpoint_field(
                &mut out,
                &self
                    .peer_round1
                    .get(&identifier)
                    .ok_or(CHECKPOINT_ERROR)?
                    .serialize()
                    .map_err(|_| CHECKPOINT_ERROR)?,
            )?;
        }
        Ok(out)
    }
    pub fn restore_checkpoint(raw: &[u8]) -> Result<Self, String> {
        let (mut reader, number, members) = CheckpointReader::new(raw, 2)?;
        let encoded = reader.field()?;
        let secret = frost::keys::dkg::round2::SecretPackage::deserialize(encoded)
            .map_err(|_| CHECKPOINT_ERROR)?;
        let own_round1 = reader.field()?.to_vec();
        let threshold = *secret.min_signers();
        let public = checked_round1(number, threshold, &own_round1)?;
        let transcript: [u8; 32] = reader.field()?.try_into().map_err(|_| CHECKPOINT_ERROR)?;
        let identifier = frost::Identifier::try_from(number).map_err(|_| CHECKPOINT_ERROR)?;
        let roundtrip = zeroize::Zeroizing::new(secret.serialize().map_err(|_| CHECKPOINT_ERROR)?);
        if *roundtrip != encoded
            || *secret.identifier() != identifier
            || !matches!((threshold, members), (2, 3) | (2, 4) | (3, 4))
            || *secret.max_signers() != members
            || secret.commitment() != public.commitment()
        {
            return Err(CHECKPOINT_ERROR.into());
        }
        frost::keys::SecretShare::new(
            identifier,
            frost::keys::SigningShare::new(secret.secret_share()),
            secret.commitment().clone(),
        )
        .verify()
        .map_err(|_| CHECKPOINT_ERROR)?;
        let mut peer_round1 = BTreeMap::new();
        let mut transcript_hasher = Params::new()
            .hash_length(32)
            .personal(b"Loki_dkg_r1_v1")
            .to_state();
        for expected in expected_ids(members) {
            let bytes = if expected == number {
                own_round1.as_slice()
            } else {
                let peer =
                    u16::from_be_bytes(reader.take(2)?.try_into().map_err(|_| CHECKPOINT_ERROR)?);
                if peer != expected {
                    return Err(CHECKPOINT_ERROR.into());
                }
                let bytes = reader.field()?;
                peer_round1.insert(
                    frost::Identifier::try_from(peer).map_err(|_| CHECKPOINT_ERROR)?,
                    checked_round1(peer, threshold, bytes)?,
                );
                bytes
            };
            transcript_hasher.update(&expected.to_be_bytes());
            transcript_hasher.update(&(bytes.len() as u32).to_be_bytes());
            transcript_hasher.update(bytes);
        }
        reader.finish()?;
        if transcript_hasher.finalize().as_bytes() != transcript {
            return Err(CHECKPOINT_ERROR.into());
        }
        Ok(Self {
            number,
            members,
            secret,
            peer_round1,
            own_round1,
            transcript,
        })
    }
}

impl Completed {
    pub fn checkpoint(&self) -> Result<zeroize::Zeroizing<Vec<u8>>, String> {
        let mut out = checkpoint_header(3, self.number, self.members);
        checkpoint_field(&mut out, &self.key_package)?;
        checkpoint_field(&mut out, &self.public_package)?;
        checkpoint_field(&mut out, &self.group_ak)?;
        checkpoint_field(&mut out, &self.transcript)?;
        Ok(out)
    }
    pub fn restore_checkpoint(raw: &[u8]) -> Result<Self, String> {
        let (mut reader, number, members) = CheckpointReader::new(raw, 3)?;
        let key_package = zeroize::Zeroizing::new(reader.field()?.to_vec());
        let public_package = reader.field()?.to_vec();
        let group_ak: [u8; 32] = reader.field()?.try_into().map_err(|_| CHECKPOINT_ERROR)?;
        let transcript: [u8; 32] = reader.field()?.try_into().map_err(|_| CHECKPOINT_ERROR)?;
        reader.finish()?;
        let key =
            frost::keys::KeyPackage::deserialize(&key_package).map_err(|_| CHECKPOINT_ERROR)?;
        let public = frost::keys::PublicKeyPackage::deserialize(&public_package)
            .map_err(|_| CHECKPOINT_ERROR)?;
        let identifier = frost::Identifier::try_from(number).map_err(|_| CHECKPOINT_ERROR)?;
        let key_roundtrip = zeroize::Zeroizing::new(key.serialize().map_err(|_| CHECKPOINT_ERROR)?);
        let threshold = *key.min_signers();
        if *key_roundtrip != *key_package
            || public.serialize().map_err(|_| CHECKPOINT_ERROR)? != public_package
            || *key.identifier() != identifier
            || !matches!((threshold, members), (2, 3) | (2, 4) | (3, 4))
            || public.min_signers() != Some(threshold)
            || public
                .verifying_shares()
                .keys()
                .copied()
                .collect::<Vec<_>>()
                != expected_ids(members)
                    .into_iter()
                    .map(|id| frost::Identifier::try_from(id).map_err(|_| CHECKPOINT_ERROR))
                    .collect::<Result<Vec<_>, _>>()?
            || key.verifying_key() != public.verifying_key()
            || key
                .verifying_key()
                .serialize()
                .map_err(|_| CHECKPOINT_ERROR)?
                .as_slice()
                != group_ak
            || public.verifying_shares().get(&identifier) != Some(key.verifying_share())
            || frost::keys::VerifyingShare::from(*key.signing_share()) != *key.verifying_share()
        {
            return Err(CHECKPOINT_ERROR.into());
        }
        let basis: std::collections::BTreeSet<_> =
            public.verifying_shares().keys().take(usize::from(threshold)).copied().collect();
        for target in
            std::iter::once(None).chain(public.verifying_shares().keys().copied().map(Some))
        {
            let mut expected = <frost::PallasGroup as frost_core::Group>::identity();
            for id in &basis {
                let coefficient =
                    frost_core::compute_lagrange_coefficient::<frost::PallasBlake2b512>(
                        &basis, target, *id,
                    )
                    .map_err(|_| CHECKPOINT_ERROR)?;
                expected = expected + public.verifying_shares()[id].to_element() * coefficient;
            }
            let encoded = <frost::PallasGroup as frost_core::Group>::serialize(&expected)
                .map_err(|_| CHECKPOINT_ERROR)?;
            let actual = match target {
                None => group_ak.to_vec(),
                Some(id) => public.verifying_shares()[&id]
                    .serialize()
                    .map_err(|_| CHECKPOINT_ERROR)?,
            };
            if encoded.as_ref() != actual {
                return Err(CHECKPOINT_ERROR.into());
            }
        }
        Ok(Self {
            number,
            members,
            key_package,
            public_package,
            group_ak,
            transcript,
        })
    }
}

impl Member {
    pub(crate) fn own_round1(&self) -> &[u8] {
        &self.own_round1
    }
}
impl Round2Member {
    pub(crate) fn round1_packages(&self) -> Result<BTreeMap<u16, Vec<u8>>, String> {
        let mut packages = BTreeMap::new();
        for number in expected_ids(self.members) {
            let bytes = if number == self.number {
                self.own_round1.clone()
            } else {
                let identifier =
                    frost::Identifier::try_from(number).map_err(|_| CHECKPOINT_ERROR)?;
                self.peer_round1
                    .get(&identifier)
                    .ok_or(CHECKPOINT_ERROR)?
                    .serialize()
                    .map_err(|_| CHECKPOINT_ERROR)?
            };
            packages.insert(number, bytes);
        }
        Ok(packages)
    }
}
impl Completed {
    pub(crate) fn transcript(&self) -> &[u8; 32] {
        &self.transcript
    }
}

impl Completed {
    pub(crate) fn public_package(&self) -> &[u8] {
        &self.public_package
    }
}
