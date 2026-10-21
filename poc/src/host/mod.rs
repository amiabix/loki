//! The per-member HTTP coordinator (axum). One process per member: it fronts the account
//! and hosted-vault ceremony (and, later, payment) for the web UI, driving the audited
//! library in-process. All library calls run on `spawn_blocking` because the hosted relay
//! stack blocks on its own runtime (see `setup_relay::shared_runtime`).

mod ceremony;
mod payment;
mod routes;
mod state;

pub use state::Config;

/// Build the axum app and serve on 127.0.0.1:<port> until the process is killed. Blocks.
pub fn run(config: Config) -> Result<(), String> {
    // rustls has no default provider; install one before any relay/lightwalletd TLS.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    for url in config.peers.values() {
        crate::transport::require_tls_off_loopback(url)?;
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("tokio runtime: {e}"))?;

    runtime.block_on(async move {
        let state: state::Shared = std::sync::Arc::new(state::AppState::new(config));
        let addr = format!("127.0.0.1:{}", state.config.port);
        let listener = tokio::net::TcpListener::bind(&addr)
            .await
            .map_err(|e| format!("bind {addr}: {e}"))?;
        // The web proxy injects X-Loki-Token; this line is what the launcher parses.
        println!("Signer: http://{addr}/#{}", state.config.token);
        axum::serve(listener, routes::router(state))
            .await
            .map_err(|e| format!("serve: {e}"))
    })
}
