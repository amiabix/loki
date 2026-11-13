//! The member-owned HTTP device. Local profile + vault ceremony + multi-party payment,
//! driving the audited library in-process (see `loki_poc::host`). Never launched by the web.
//!
//!   loki_member_app --data <dir> --port <n> [--network testnet] [--lightwalletd-url <url>]
//!       [--frostd-url <url>] [--peer <slot=baseurl>]...
//!       [--bind <IP>] [--advertise-url <url>]
//!       [--secure-element <software|apple>]
//!       [--coordinator-url <origin> --local-passphrase-file <path>
//!        --registration-slot <public-slot> --profile-name <name>]
//!       [--transport hosted --operator-bundle <cbor> --operator-key <hex>
//!        --enrollment-issuer <path> --development-http]

use loki_poc::host;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let config = match host::config_from_args(&args) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(2);
        }
    };
    if let Err(error) = config.validate_secure_element().and_then(|_| host::run(config)) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
