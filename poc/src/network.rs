use zcash_protocol::consensus::{
    BlockHeight, NetworkType, NetworkUpgrade, Parameters, TEST_NETWORK,
};

use crate::candidate::Regtest;

pub const TESTNET_NU7_BIRTH: u32 = 4_465_026;

/// The only chains on which this research wallet may create vaults.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VaultNetwork {
    Regtest,
    Testnet,
}

impl VaultNetwork {
    pub fn parse(value: &str) -> Result<Self, String> {
        let network = match value {
            "regtest" => Self::Regtest,
            "testnet" => Self::Testnet,
            _ => return Err("unsupported vault network".into()),
        };
        network.ensure_test_only()?;
        Ok(network)
    }

    /// The research-wallet network policy: only test chains, never mainnet, until the ZIP-2005
    /// derivation and the key/backup flow are independently reviewed (see `crate::zip2005`).
    /// The exhaustive match has no wildcard: adding any non-test variant fails to compile here,
    /// so the guard can never silently lapse.
    pub fn ensure_test_only(self) -> Result<(), String> {
        match self {
            Self::Regtest | Self::Testnet => Ok(()),
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Regtest => "regtest",
            Self::Testnet => "testnet",
        }
    }
}

impl Parameters for VaultNetwork {
    fn network_type(&self) -> NetworkType {
        match self {
            Self::Regtest => Regtest.network_type(),
            Self::Testnet => TEST_NETWORK.network_type(),
        }
    }

    fn activation_height(&self, nu: NetworkUpgrade) -> Option<BlockHeight> {
        match self {
            Self::Regtest => Regtest.activation_height(nu),
            Self::Testnet => TEST_NETWORK.activation_height(nu),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zcash_protocol::consensus::BranchId;

    #[test]
    fn public_testnet_uses_nu7_and_mainnet_is_refused() {
        assert_eq!(
            BranchId::for_height(&VaultNetwork::Testnet, BlockHeight::from_u32(4_465_026)),
            BranchId::Nu7
        );
        assert!(VaultNetwork::parse("mainnet").is_err());
        assert!(VaultNetwork::parse("main").is_err());
        // The two test chains pass the policy; parse admits only these.
        assert!(VaultNetwork::Regtest.ensure_test_only().is_ok());
        assert!(VaultNetwork::Testnet.ensure_test_only().is_ok());
    }
}
