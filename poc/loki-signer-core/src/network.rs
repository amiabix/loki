use zcash_protocol::consensus::{
    BlockHeight, NetworkType, NetworkUpgrade, Parameters, TEST_NETWORK,
};

use crate::candidate::Regtest;

pub const TESTNET_NU7_BIRTH: u32 = 4_465_026;

const MAINNET_REFUSED: &str = "mainnet network is refused: Loki is Testnet-only";

/// The one gate for a raw address or consensus network type. No wildcard: a chain
/// `zcash_protocol` adds later must be decided here, not defaulted in.
pub fn refuse_mainnet(network: NetworkType) -> Result<NetworkType, String> {
    match network {
        NetworkType::Test | NetworkType::Regtest => Ok(network),
        NetworkType::Main => Err(MAINNET_REFUSED.into()),
    }
}

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
            "main" | "mainnet" => Err(MAINNET_REFUSED.into()),
            _ => Err("unsupported vault network".into()),
        }
    }

    /// Refuses any chain lightwalletd reports other than this vault's. lightwalletd names
    /// regtest "test" too, so the chains are told apart by Sapling activation.
    pub fn require_lightwalletd_chain(self, chain_name: &str, sapling_activation: u64) -> Result<(), String> {
        if chain_name != "test"
            || Some(sapling_activation) != self.activation_height(NetworkUpgrade::Sapling).map(u64::from)
        {
            return Err(format!(
                "lightwalletd serves another chain ({chain_name} with Sapling at {sapling_activation}), not this {} vault's",
                self.label()
            ));
        }
        Ok(())
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
        for name in ["mainnet", "main", "Mainnet", "MAIN"] {
            assert!(VaultNetwork::parse(name).is_err(), "{name}");
        }
    }

    #[test]
    fn no_vault_network_maps_to_mainnet() {
        for network in [VaultNetwork::Regtest, VaultNetwork::Testnet] {
            // A new variant fails to compile here; add it to this match and the list above.
            match network {
                VaultNetwork::Regtest | VaultNetwork::Testnet => {}
            }
            assert_eq!(refuse_mainnet(network.network_type()), Ok(network.network_type()));
            assert_eq!(VaultNetwork::parse(network.label()), Ok(network));
        }
        assert!(refuse_mainnet(NetworkType::Main).is_err());
    }

    #[test]
    fn a_mainnet_lightwalletd_is_refused() {
        // Mainnet lightwalletd reports chain "main" with Sapling at 419200.
        for network in [VaultNetwork::Regtest, VaultNetwork::Testnet] {
            assert!(network.require_lightwalletd_chain("main", 419_200).is_err());
            assert!(network.require_lightwalletd_chain("test", 419_200).is_err());
        }
        assert!(VaultNetwork::Testnet.require_lightwalletd_chain("test", 280_000).is_ok());
        assert!(VaultNetwork::Regtest.require_lightwalletd_chain("test", 1).is_ok());
        assert!(VaultNetwork::Regtest.require_lightwalletd_chain("test", 280_000).is_err());
    }
}
