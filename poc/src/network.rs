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
        match value {
            "regtest" => Ok(Self::Regtest),
            "testnet" => Ok(Self::Testnet),
            _ => Err("unsupported vault network".into()),
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
    }
}
