//! One member's 2-of-3 DKG state. No process ever holds another member's secret package.
//!
//! The caller must authenticate each sender and encrypt every round-two package before
//! transport. This module does not make a vault active: a certificate exchange and the
//! ZIP 2005 viewing-key derivation are still required.

use std::collections::BTreeMap;

use blake2b_simd::Params;
use reddsa_frost::frost::redpallas as frost;

pub struct Member {
    number: u16,
    secret: frost::keys::dkg::round1::SecretPackage,
    own_round1: Vec<u8>,
}

pub struct Round2Member {
    number: u16,
    secret: frost::keys::dkg::round2::SecretPackage,
    peer_round1: BTreeMap<frost::Identifier, frost::keys::dkg::round1::Package>,
    pub transcript: [u8; 32],
}

pub struct Completed {
    key_package: Vec<u8>,
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

fn expected_ids() -> [u16; 3] {
    [1, 2, 3]
}

impl Member {
    pub fn start(id: u16) -> Result<(Self, Vec<u8>), String> {
        if !expected_ids().contains(&id) {
            return Err("member id must be 1, 2 or 3".into());
        }
        let identifier = frost::Identifier::try_from(id).map_err(|e| e.to_string())?;
        let (secret, public) = frost::keys::dkg::part1(identifier, 3, 2, rand_core::OsRng)
            .map_err(|e| e.to_string())?;
        let bytes = public.serialize().map_err(|e| e.to_string())?;
        Ok((
            Self {
                number: id,
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
        if round1.len() != 3 || round1.keys().copied().collect::<Vec<_>>() != expected_ids() {
            return Err("round one needs exactly members 1, 2 and 3".into());
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
        for peer in expected_ids().into_iter().filter(|peer| *peer != own) {
            let id = frost::Identifier::try_from(peer).map_err(|e| e.to_string())?;
            let package = outgoing
                .get(&id)
                .ok_or("missing outgoing round-two package")?;
            wire.insert(peer, package.serialize().map_err(|e| e.to_string())?);
        }
        Ok((
            Round2Member {
                number: self.number,
                secret,
                peer_round1: peers,
                transcript,
            },
            wire,
        ))
    }
}

impl Round2Member {
    pub fn finish(&self, incoming: &BTreeMap<u16, Vec<u8>>) -> Result<Completed, String> {
        let own = self.number;
        if incoming.len() != 2
            || incoming
                .keys()
                .any(|id| !expected_ids().contains(id) || *id == own)
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
            key_package: key_package.serialize().map_err(|e| e.to_string())?,
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

    pub fn certify(self, digests: &BTreeMap<u16, [u8; 32]>) -> Result<Certified, String> {
        if digests.len() != 3 || digests.keys().copied().collect::<Vec<_>>() != expected_ids() {
            return Err("certificates need exactly members 1, 2 and 3".into());
        }
        let own = self.certificate_digest();
        if digests.values().any(|digest| digest != &own) {
            return Err("members disagree on the DKG transcript or group key".into());
        }
        Ok(Certified {
            key_package: self.key_package,
            public_package: self.public_package,
            group_ak: self.group_ak,
            transcript: self.transcript,
        })
    }
}
