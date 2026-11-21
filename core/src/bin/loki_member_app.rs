//! The member-owned HTTP device. Local profile + vault ceremony + multi-party payment,
//! driving the audited library in-process (see `loki_poc::host`). Never launched by the web.
//!
//!   loki_member_app --data <dir> --port <n> [--network testnet] [--lightwalletd-url <url>]
//!       [--frostd-url <url>] [--peer <slot=baseurl>]...
//!       [--bind <IP>] [--advertise-url <url>] [--allow-loopback-peers]
//!       [--secure-element <software|apple>]
//!       [--coordinator-url <origin> --local-passphrase-file <path>
//!        --registration-slot <public-slot> --profile-name <name>]
//!       [--transport hosted --operator-bundle <cbor> --operator-key <hex>
//!        --enrollment-issuer <path> --development-http]
//!       [--nonce-witnesses <json>] [--approve-from <file>]
//!
//! Without `--approve-from` this process has no approval channel and refuses every payment;
//! members sign from the native app. `--approve-from` is for test harnesses only: see
//! `host::file_approval`.

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
    let approval = args
        .iter()
        .position(|a| a == "--approve-from")
        .and_then(|i| args.get(i + 1))
        .map(|file| host::file_approval(file.into(), std::time::Duration::from_secs(120)));
    if let Err(error) = config.validate_secure_element().and_then(|_| host::run_local(config, None, None, approval, None)) {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
}
