//! JSON-only native member-runtime migration slice; no setup or payment routes yet.

use loki_poc::{member_runtime, network::VaultNetwork};
use std::path::PathBuf;

#[tokio::main]
async fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    let result = (|| {
        let mut data = None;
        let mut port = None;
        let mut network = VaultNetwork::Regtest;
        let mut at = 1;
        while at < args.len() {
            let value = args.get(at + 1).ok_or(
                "usage: loki_member_runtime --data ROOT --port PORT [--network regtest|testnet]",
            )?;
            match args[at].as_str() {
                "--data" => data = Some(PathBuf::from(value)),
                "--port" => port = Some(value.parse::<u16>().map_err(|_| "Invalid port")?),
                "--network" => {
                    network = VaultNetwork::parse(value).map_err(|_| "Invalid network")?
                }
                _ => return Err("Unknown option"),
            }
            at += 2;
        }
        Ok::<_, &str>((
            data.ok_or("--data is required")?,
            port.ok_or("--port is required")?,
            network,
        ))
    })();
    let result = match result {
        Ok((data, port, network)) => member_runtime::serve(data, network, port).await,
        Err(error) => Err(error.to_owned()),
    };
    if let Err(error) = result {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
