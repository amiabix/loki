//! Hosted setup commands for one unlocked profile, over stdin and stdout JSON lines.
//! See `loki_poc::member_service` for the protocol. Regtest only.

fn main() {
    let stdin = std::io::stdin();
    let result = loki_poc::member_service::serve(stdin.lock(), Box::new(std::io::stdout()));
    loki_poc::seal_kdf::report();
    if let Err(error) = result {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
    // Commands abandoned after the stop grace end with the process.
    std::process::exit(0);
}
