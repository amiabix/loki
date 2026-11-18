//! Hosted signing uses the same fresh, signed nonce claims as standalone signing.
//! The operator supplies two independently managed, pre-provisioned relay mailboxes.

use std::{io::Read, path::Path};
use loki_relay_client::{RelayHttp, Secret32};
use loki_relay_protocol::types::{RelayPin, RelayRoute};
use crate::signing_session::{NonceWitness, WitnessPins};
use zeroize::{Zeroize, Zeroizing};

#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WitnessConfig {
    pub endpoint: String,
    pub key: [u8; 32],
    pub run: [u8; 32],
    pub mailbox: [u8; 32],
    pub read: [u8; 32],
}

impl Drop for WitnessConfig {
    fn drop(&mut self) { self.read.zeroize(); }
}

pub(super) struct RelayWitness {
    routes: [(RelayRoute, Secret32); 2],
    http: RelayHttp,
    runtime: tokio::runtime::Runtime,
}

impl RelayWitness {
    pub(super) fn open(path: Option<&Path>, development: bool) -> Result<Self, String> {
        let path = path.ok_or("hosted signing requires --nonce-witnesses <file>")?;
        let mut raw = Zeroizing::new(Vec::new());
        std::fs::File::open(path).map_err(|e| format!("nonce witnesses: {e}"))?
            .take(16_385).read_to_end(&mut raw).map_err(|e| format!("nonce witnesses: {e}"))?;
        if raw.len() > 16_384 { return Err("nonce witness configuration too large".into()); }
        let config: [WitnessConfig; 2] = serde_json::from_slice(&raw)
            .map_err(|_| "invalid nonce witness configuration")?;
        let routes = config.map(|c| (RelayRoute {
            pin: RelayPin { key: c.key, run: c.run }, endpoint: c.endpoint.clone(),
            mailbox: c.mailbox, append_revision: 1,
        }, Secret32::from_bytes(c.read)));
        let witness = Self {
            routes,
            http: if development { RelayHttp::new() } else { RelayHttp::hosted() }
                .map_err(|e| e.to_string())?,
            runtime: tokio::runtime::Builder::new_current_thread().enable_all().build()
                .map_err(|e| e.to_string())?,
        };
        if !crate::signing_session::valid_witness_pins(witness.pins()) {
            return Err("two distinct nonzero nonce witnesses required".into());
        }
        for (route, _) in &witness.routes {
            loki_relay_client::validate_endpoint(&route.endpoint, development).map_err(|e| e.to_string())?;
        }
        Ok(witness)
    }
}

impl NonceWitness for RelayWitness {
    fn pins(&self) -> WitnessPins {
        std::array::from_fn(|i| {
            let route = &self.routes[i].0;
            (route.pin.key, route.pin.run, route.mailbox)
        })
    }

    fn claim(&mut self, cid: [u8; 32], record: &[u8]) -> Result<(), String> {
        for (route, read) in &self.routes {
            let created = self.runtime.block_on(self.http.claim_nonce(route, read, cid, record))
                .map_err(|e| format!("nonce witness claim: {e}"))?;
            if !created { return Err("nonce already claimed; start a new signing attempt".into()); }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosted_signing_requires_external_witness_configuration() {
        assert!(RelayWitness::open(None, false).err().unwrap().contains("--nonce-witnesses"));
    }

    #[test]
    fn provisioned_witness_json_round_trips_into_hosted_signing() {
        let config = [1, 5].map(|n| WitnessConfig {
            endpoint: "http://127.0.0.1:39101".into(), key: [n; 32],
            run: [n + 1; 32], mailbox: [n + 2; 32], read: [n + 3; 32],
        });
        let raw = Zeroizing::new(serde_json::to_vec_pretty(&config).unwrap());
        let json: serde_json::Value = serde_json::from_slice(&raw).unwrap();
        assert_eq!(json.as_array().unwrap().len(), 2);
        for (entry, n) in json.as_array().unwrap().iter().zip([1, 5]) {
            assert_eq!(entry.as_object().unwrap().len(), 5);
            for (field, value) in [("key", n), ("run", n + 1), ("mailbox", n + 2), ("read", n + 3)] {
                assert_eq!(entry[field], serde_json::json!(vec![value; 32]));
            }
        }
        let decoded: [WitnessConfig; 2] = serde_json::from_slice(&raw).unwrap();
        assert_eq!(decoded[0].read, [4; 32]);
        assert_eq!(decoded[1].read, [8; 32]);
        let path = std::env::temp_dir().join(format!("loki-witness-{}.json", uuid::Uuid::new_v4()));
        std::fs::write(&path, &*raw).unwrap();
        let witness = RelayWitness::open(Some(&path), true).unwrap();
        assert_eq!(witness.pins(), [([1; 32], [2; 32], [3; 32]), ([5; 32], [6; 32], [7; 32])]);
        assert_eq!(witness.routes[0].1.as_bytes(), &[4; 32]);
        assert_eq!(witness.routes[1].1.as_bytes(), &[8; 32]);
        assert!(RelayWitness::open(Some(&path), false).is_err());
        std::fs::remove_file(path).unwrap();
    }

    /// Live: two dev relays provisioned with `examples/provision_nonce_witnesses`, named by
    /// `LOKI_NONCE_WITNESSES`. A fresh claim is accepted by both; the same claim again is
    /// refused, which is what blocks a rolled-back nonce from signing twice.
    #[test]
    fn provisioned_relays_accept_a_claim_once_and_refuse_a_duplicate() {
        let Some(path) = std::env::var_os("LOKI_NONCE_WITNESSES") else { return };
        let mut witness = RelayWitness::open(Some(Path::new(&path)), true).unwrap();
        let mut cid = [0u8; 32];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut cid);
        witness.claim(cid, b"first use").unwrap();
        let again = witness.claim(cid, b"first use").unwrap_err();
        assert!(again.contains("already claimed"), "{again}");
        let other = witness.claim(cid, b"another use").unwrap_err();
        assert!(other.contains("already claimed") || other.contains("nonce witness claim"), "{other}");
    }

    #[test]
    fn witness_configuration_requires_two_distinct_identities() {
        let path = std::env::temp_dir().join(format!("loki-witness-{}.json", uuid::Uuid::new_v4()));
        let entry = |n: u8| serde_json::json!({
            "endpoint": "https://example.invalid", "key": ([n; 32].to_vec()),
            "run": ([n + 1; 32].to_vec()), "mailbox": ([n + 2; 32].to_vec()), "read": ([n + 3; 32].to_vec())
        });
        std::fs::write(&path, serde_json::to_vec(&[entry(1), entry(1)]).unwrap()).unwrap();
        assert!(RelayWitness::open(Some(&path), false).is_err());
        std::fs::write(&path, serde_json::to_vec(&[entry(1), entry(5)]).unwrap()).unwrap();
        let witness = RelayWitness::open(Some(&path), false).unwrap();
        assert_eq!(witness.pins(), [([1; 32], [2; 32], [3; 32]), ([5; 32], [6; 32], [7; 32])]);
        std::fs::remove_file(path).unwrap();
    }
}
