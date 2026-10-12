//! Validated regtest state produced by the separate-member setup ceremony.

use std::{collections::BTreeMap, fs, path::Path};

use blake2b_simd::Params;
use orchard::keys::FullViewingKey;
use reddsa_frost::frost::redpallas as frost;
use zeroize::{Zeroize, Zeroizing};

use crate::{
    setup_transport::{Identity, PublicIdentity},
    state::MemberDir,
    vault, zip2005,
};

pub struct Roster {
    pub vault: [u8; 32],
    pub threshold: u16,
    pub members: BTreeMap<u16, PublicIdentity>,
    legacy: bool,
}

impl Roster {
    pub fn load(path: &Path) -> Result<Self, String> {
        Self::from_bytes(&fs::read(path).map_err(|e| e.to_string())?)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        let data: serde_json::Value = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
        let vault = hex32(&data, "vault")?;
        let entries = data["members"].as_array().ok_or("missing members")?;
        let mut members = BTreeMap::new();
        for entry in entries {
            let id: u16 = entry["id"]
                .as_u64()
                .ok_or("missing member id")?
                .try_into()
                .map_err(|_| "invalid member id")?;
            let signing = hex32(entry, "signing")?;
            let encryption = hex32(entry, "encryption")?;
            ed25519_dalek::VerifyingKey::from_bytes(&signing)
                .map_err(|_| "invalid signing public key")?;
            if members
                .insert(
                    id,
                    PublicIdentity {
                        id,
                        signing,
                        encryption,
                    },
                )
                .is_some()
            {
                return Err("duplicate member in roster".into());
            }
        }
        let legacy = data.get("threshold").is_none();
        let threshold: u16 = if legacy {
            2
        } else {
            data["threshold"]
                .as_u64()
                .ok_or("invalid roster threshold")?
                .try_into()
                .map_err(|_| "invalid roster threshold")?
        };
        let count = members.len();
        if !matches!((threshold, count), (2, 3) | (2, 4))
            || (legacy && count != 3)
            || members.keys().copied().collect::<Vec<_>>() != (1..=count as u16).collect::<Vec<_>>()
        {
            return Err(
                "supported rosters are 2-of-3 and 2-of-4 with consecutive member IDs".into(),
            );
        }
        Ok(Self {
            vault,
            threshold,
            members,
            legacy,
        })
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        let mut hash = Params::new()
            .hash_length(32)
            .personal(if self.legacy {
                b"Loki_roster_v1"
            } else {
                b"Loki_roster_v2"
            })
            .to_state();
        hash.update(&self.vault);
        if !self.legacy {
            hash.update(&self.threshold.to_be_bytes());
            hash.update(&(self.members.len() as u16).to_be_bytes());
        }
        for member in self.members.values() {
            hash.update(&member.id.to_be_bytes());
            hash.update(&member.signing);
            hash.update(&member.encryption);
        }
        hash.finalize().as_bytes().try_into().unwrap()
    }
}

pub struct MemberState {
    pub vault: [u8; 32],
    pub roster: Roster,
    pub identity: Identity,
    pub key: frost::keys::KeyPackage,
    pub public: frost::keys::PublicKeyPackage,
    pub fvk: FullViewingKey,
}

fn hex32(value: &serde_json::Value, field: &str) -> Result<[u8; 32], String> {
    hex::decode(
        value[field]
            .as_str()
            .ok_or_else(|| format!("missing {field}"))?,
    )
    .map_err(|e| e.to_string())?
    .try_into()
    .map_err(|_| format!("{field} is not 32 bytes"))
}

fn hex_bytes(value: &serde_json::Value, field: &str) -> Result<Vec<u8>, String> {
    hex::decode(
        value[field]
            .as_str()
            .ok_or_else(|| format!("missing {field}"))?,
    )
    .map_err(|e| format!("{field}: {e}"))
}

pub fn open(owner: &Path, pass_file: &Path, roster_file: &Path) -> Result<MemberState, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if fs::metadata(pass_file)
            .map_err(|e| e.to_string())?
            .permissions()
            .mode()
            & 0o077
            != 0
        {
            return Err("passphrase file must be owner-only (mode 0600)".into());
        }
    }
    let mut pass = fs::read_to_string(pass_file).map_err(|e| e.to_string())?;
    let trimmed = Zeroizing::new(pass.trim_end_matches(['\r', '\n']).to_string());
    pass.zeroize();
    if trimmed.is_empty() {
        return Err("empty passphrase".into());
    }
    let dir = MemberDir::open(owner, "secrets");
    let state: serde_json::Value = serde_json::from_slice(
        &dir.read_sealed("vault.sealed", &trimmed)
            .map_err(|e| e.to_string())?,
    )
    .map_err(|e| e.to_string())?;
    if state["version"] != 2
        || state["network"] != "regtest"
        || state["key_derivation"] != zip2005::VERSION
    {
        return Err("unsupported separate-member regtest vault state".into());
    }
    let vault = hex32(&state, "vault")?;
    let roster = Roster::load(roster_file)?;
    if roster.vault != vault || roster.fingerprint() != hex32(&state, "roster_fingerprint")? {
        return Err("roster differs from sealed vault certificate".into());
    }
    if state
        .get("threshold")
        .is_some_and(|value| value.as_u64() != Some(u64::from(roster.threshold)))
        || state
            .get("members")
            .is_some_and(|value| value.as_u64() != Some(roster.members.len() as u64))
    {
        return Err("sealed vault policy differs from certified roster".into());
    }
    let identity = Identity::from_secret_bytes(&hex_bytes(&state, "identity_secret")?)?;
    if roster.members.get(&identity.public().id) != Some(&identity.public())
        || dir
            .read_sealed("identity.sealed", &trimmed)
            .map_err(|e| e.to_string())?
            != identity.to_secret_bytes()
    {
        return Err("member identity differs from certified roster".into());
    }
    let ak = hex32(&state, "group_ak")?;
    let secret = hex32(&state, "vault_secret")?;
    let fvk = zip2005::frost_viewing_key(&ak, &secret)
        .map_err(|e| format!("ZIP 2005 derivation: {e:?}"))?;
    if state["address"].as_str() != Some(&vault::regtest_unified_address(&fvk)) {
        return Err("stored address differs from derived vault address".into());
    }
    let public = frost::keys::PublicKeyPackage::deserialize(&hex_bytes(&state, "public_package")?)
        .map_err(|e| format!("public package: {e}"))?;
    let key = frost::keys::KeyPackage::deserialize(&hex_bytes(&state, "key_package")?)
        .map_err(|e| format!("member share: {e}"))?;
    let id = frost::Identifier::try_from(identity.public().id).map_err(|e| e.to_string())?;
    if public
        .verifying_key()
        .serialize()
        .map_err(|e| e.to_string())?
        != ak
        || key.identifier() != &id
        || key.verifying_key() != public.verifying_key()
        || public.verifying_shares().get(&id) != Some(key.verifying_share())
        || *key.min_signers() != roster.threshold
        || public.min_signers() != Some(roster.threshold)
    {
        return Err("member share differs from certified vault policy".into());
    }
    let backup_version = state.get("backup_version").and_then(|v| v.as_u64());
    let personal = match backup_version {
        None => b"Loki_bkup_v1".as_slice(),
        Some(2) => b"Loki_bkup_v2".as_slice(),
        _ => return Err("unsupported backup receipt version".into()),
    };
    let mut backup = Params::new().hash_length(32).personal(personal).to_state();
    backup.update(&vault);
    backup.update(&roster.fingerprint());
    backup.update(&ak);
    backup.update(zip2005::VERSION.as_bytes());
    if backup_version == Some(2) {
        backup.update(&secret);
        backup.update(
            state["address"]
                .as_str()
                .ok_or("missing address")?
                .as_bytes(),
        );
    }
    if dir
        .read_sealed("activation.sealed", &trimmed)
        .map_err(|_| "vault needs all members' backup confirmations")?
        != backup.finalize().as_bytes()
    {
        return Err("activation belongs to a different vault".into());
    }
    Ok(MemberState {
        vault,
        roster,
        identity,
        key,
        public,
        fvk,
    })
}
