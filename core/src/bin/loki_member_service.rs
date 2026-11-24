fn main() {
    let stdin = std::io::stdin();
    let result = loki_poc::member_service::serve(stdin.lock(), Box::new(std::io::stdout()));
    loki_poc::seal_kdf::report();
    if let Err(error) = result {
        eprintln!("error: {error}");
        std::process::exit(1);
    }
    std::process::exit(0);
}
