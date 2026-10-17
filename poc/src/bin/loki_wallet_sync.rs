use std::{env, fs, path::Path, time::Duration};

use loki_poc::{member_state, network::VaultNetwork, wallet_store::VaultWallet};
use tonic::transport::Endpoint;
use zcash_client_backend::{
    data_api::AccountBirthday,
    proto::service::{compact_tx_streamer_client::CompactTxStreamerClient, BlockId, Empty},
};
use zcash_protocol::consensus::Network;
use zeroize::Zeroizing;

fn lightwalletd_endpoint(url: String) -> Result<Endpoint, String> {
    let endpoint = Endpoint::from_shared(url).map_err(|e| format!("lightwalletd URL: {e}"))?;
    let uri = endpoint.uri();
    if uri.scheme_str() != Some("https")
        && !(uri.scheme_str() == Some("http")
            && matches!(uri.host(), Some("localhost" | "127.0.0.1" | "[::1]")))
    {
        return Err("lightwalletd must use HTTPS, except on localhost".into());
    }
    Ok(endpoint)
}

async fn sync(args: &[String]) -> Result<(), String> {
    if args.len() != 4 {
        return Err("usage: loki_wallet_sync <member-dir> <passphrase-file> <roster.json> <lightwalletd-url>".into());
    }
    let member = member_state::open(
        Path::new(&args[0]),
        Path::new(&args[1]),
        Path::new(&args[2]),
    )?;
    if member.network != VaultNetwork::Testnet {
        return Err("persistent wallet sync currently supports Testnet vaults only".into());
    }
    let birth = member
        .birth_height
        .ok_or("Testnet vault has no birth height")?;
    let endpoint = lightwalletd_endpoint(args[3].clone())?;
    let channel = endpoint
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .connect()
        .await
        .map_err(|e| format!("connect to lightwalletd: {e}"))?;
    let mut client = CompactTxStreamerClient::new(channel);
    let info = client
        .get_lightd_info(Empty {})
        .await
        .map_err(|e| format!("lightwalletd info: {e}"))?
        .into_inner();
    if info.chain_name != "test" || info.block_height < u64::from(birth) {
        return Err(format!(
            "lightwalletd is not at this Testnet vault's birth height (chain {})",
            info.chain_name
        ));
    }
    let prior = client
        .get_tree_state(BlockId {
            height: u64::from(birth - 1),
            hash: vec![],
        })
        .await
        .map_err(|e| format!("birth tree state: {e}"))?
        .into_inner();
    if prior.height != u64::from(birth - 1) || prior.network != "test" {
        return Err("lightwalletd returned a different birth checkpoint".into());
    }
    let birthday = AccountBirthday::from_treestate(prior, None)
        .map_err(|e| format!("parse birth tree state: {e}"))?;
    let passphrase =
        Zeroizing::new(fs::read_to_string(&args[1]).map_err(|e| format!("read passphrase: {e}"))?);
    let mut wallet = VaultWallet::open(
        &Path::new(&args[0]).join("wallet.sqlite"),
        Network::TestNetwork,
        &member.fvk,
        &birthday,
        passphrase.trim_end_matches(['\r', '\n']),
    )?;
    wallet.sync_testnet(&mut client).await?;
    let height = wallet
        .scanned_height()?
        .ok_or("wallet did not scan any blocks")?;
    let balance = wallet.ironwood_balance_zat()?;
    println!(
        "{}",
        serde_json::json!({
            "vault": hex::encode(member.vault),
            "network": "testnet",
            "height": height,
            "balance_zat": balance,
        })
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::lightwalletd_endpoint;

    #[test]
    fn plaintext_is_only_allowed_on_loopback() {
        assert!(lightwalletd_endpoint("https://wallet.example".into()).is_ok());
        assert!(lightwalletd_endpoint("http://localhost:9067".into()).is_ok());
        assert!(lightwalletd_endpoint("http://127.0.0.1:9067".into()).is_ok());
        assert!(lightwalletd_endpoint("http://wallet.example".into()).is_err());
        assert!(lightwalletd_endpoint("http://127.0.0.1.evil.example".into()).is_err());
    }
}

fn main() {
    let args = env::args().skip(1).collect::<Vec<_>>();
    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("start wallet sync: {e}"))
        .and_then(|runtime| runtime.block_on(sync(&args)));
    if let Err(error) = result {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
