# Remote Testnet operator pilot

This starts the shared setup admission service and three durable relays on one Linux server. Each member runs `poc/wallet/member_app.py` on their **own** machine; their signing share and recovery words never go on this server. The three relay processes on one server are one failure domain. Use this deployment to exercise remote Testnet setup and payments with disposable funds. A custody deployment requires independent relay operators and the release gates in `../README.md`.

The server needs public DNS names for `relay1`, `relay2`, `relay3`, and `admission`, ports 80 and 443 open, systemd, Caddy, and enough encrypted persistent disk for the relay and admission databases. Use a pinned Loki revision and build the `communication` workspace with Rust 1.89. Member machines also need the `poc` binaries built with Rust 1.91, a synced Testnet node reachable on loopback, and a Testnet lightwalletd endpoint. Do not expose a member signer URL, node RPC port, relay loopback port, or the private files below to the internet.

## 1. Build and initialize the server

Run from the repository root on the Linux server. Replace all four `example.org` names with your own DNS names **before** initialization; a signed relay origin cannot be changed by editing Caddy later.

```sh
cargo +1.89.0 build --release --locked --manifest-path communication/Cargo.toml \
  -p loki-relay-server -p loki-setup-admission
sudo useradd --system --home /var/lib/loki --shell /usr/sbin/nologin loki
sudo install -d -o loki -g loki -m 0700 /var/lib/loki /var/lib/loki/admission /etc/loki/operator
sudo install -d -m 0755 /opt/loki/bin
sudo install -m 0755 communication/target/release/loki-relay-server /opt/loki/bin/
sudo install -m 0755 communication/target/release/loki-setup-admission /opt/loki/bin/
sudo install -m 0755 communication/target/release/loki_operator_admin /opt/loki/bin/
sudo -u loki sh -c 'umask 077; openssl rand 32 > /etc/loki/operator/relay-1.cap; openssl rand 32 > /etc/loki/operator/relay-2.cap; openssl rand 32 > /etc/loki/operator/relay-3.cap; openssl rand 32 > /var/lib/loki/admission/signing-key'
```

Initialize each relay **once**. Keep the roots and capability files across restarts. The public origins must exactly match the DNS names Caddy will serve.

```sh
sudo -u loki /opt/loki/bin/loki-relay-server init --root /var/lib/loki/relay-1 --provision-capability-file /etc/loki/operator/relay-1.cap --total-bytes 67108864 --mailbox-bytes 1048576 --mailbox-count 1024 --listen 127.0.0.1:39101 --public-origin https://relay1.example.org
sudo -u loki /opt/loki/bin/loki-relay-server init --root /var/lib/loki/relay-2 --provision-capability-file /etc/loki/operator/relay-2.cap --total-bytes 67108864 --mailbox-bytes 1048576 --mailbox-count 1024 --listen 127.0.0.1:39102 --public-origin https://relay2.example.org
sudo -u loki /opt/loki/bin/loki-relay-server init --root /var/lib/loki/relay-3 --provision-capability-file /etc/loki/operator/relay-3.cap --total-bytes 67108864 --mailbox-bytes 1048576 --mailbox-count 1024 --listen 127.0.0.1:39103 --public-origin https://relay3.example.org
sudo -u loki /opt/loki/bin/loki_operator_admin pubkey /var/lib/loki/admission/signing-key /var/lib/loki/admission/public-key
```

## 2. Sign the public operator configuration

Do this on a trusted admin computer. Build `loki_operator_admin` there with the same pinned revision. Transfer only the three relay `manifest` files and `/var/lib/loki/admission/public-key` from the server to the admin computer. Keep the configuration and enrollment issuer seeds on the admin computer; **never** put either seed in the member app or the admission service.

```sh
umask 077
openssl rand 32 > config.seed
openssl rand 32 > issuer.seed
./loki_operator_admin pubkey issuer.seed issuer-key
./loki_operator_admin bundle config.seed admission-public-key https://admission.example.org \
  relay-1.manifest relay-2.manifest relay-3.manifest bundle config-key relay-order
```

The command checks each HTTPS origin, rejects repeated relay keys or run IDs, signs the exact bundle format clients verify, and refuses to overwrite output files. It also writes `relay-order`: the original physical relay slot for each route after the signed bundle's key ordering. Admission must use provisioning capabilities in that **signed route order**. Transfer `bundle`, `config-key`, `issuer-key`, and `relay-order` to the server. Install the first three under `/etc/loki/operator/` as files readable by `loki`, then create its service mapping:

```sh
awk '{print "LOKI_RELAY_CAP_" NR "=/etc/loki/operator/relay-" $1 ".cap"}' relay-order > relay-order.env
sudo install -o loki -g loki -m 0644 relay-order.env /etc/loki/operator/relay-order.env
```

Compare the trusted `config-key` bytes with the admin computer before distributing it to members. Do not regenerate these keys to restart a service: that is a new operator configuration and existing vaults keep their old pins.

## 3. Start TLS and services

Copy the two `.service` files in this directory to `/etc/systemd/system/`. Copy `Caddyfile.example` to `/etc/caddy/Caddyfile`, replacing its four names with the names signed above. Let Caddy obtain publicly trusted certificates. It forwards to loopback and must preserve paths and request headers.

```sh
sudo caddy validate --config /etc/caddy/Caddyfile
sudo systemctl daemon-reload
sudo systemctl enable --now loki-relay@1 loki-relay@2 loki-relay@3 loki-admission caddy
sudo systemctl is-active loki-relay@1 loki-relay@2 loki-relay@3 loki-admission caddy
curl --fail --silent --show-error -H "x-loki-challenge: $(openssl rand -hex 32)" https://relay1.example.org/v1/identity -o /dev/null
curl --fail --silent --show-error -H "x-loki-challenge: $(openssl rand -hex 32)" https://relay2.example.org/v1/identity -o /dev/null
curl --fail --silent --show-error -H "x-loki-challenge: $(openssl rand -hex 32)" https://relay3.example.org/v1/identity -o /dev/null
```

Use a member client with the pinned `bundle` and `config-key` to verify the signed relay challenges and make a hosted setup request. A successful `curl` checks reachability and TLS only; it does not validate the relay pin or the admission protocol. Before opening enrollment, restore an admission SQLite backup into a private test root and verify it opens. Back up all four state roots and their WAL files coherently; do not copy a live SQLite file by itself.

For the first closed pilot, run the vault **creator** on the trusted admin computer. Copy `issuer-local.example` to a private executable there, set the four paths it reads, and pass it as `--enrollment-issuer` when starting that creator's member app. It grants only that app's newly generated device key, for one creation and one hour. Do not distribute this executable or the issuer seed to the invited members.

```sh
install -m 0700 issuer-local.example issuer-local
export LOKI_OPERATOR_ADMIN=/absolute/path/to/loki_operator_admin
export LOKI_ISSUER_SEED=/absolute/path/to/issuer.seed
export LOKI_OPERATOR_BUNDLE=/absolute/path/to/bundle
export LOKI_CONFIG_KEY=/absolute/path/to/config-key
cd poc
cargo +1.91.0 build --locked --bins --features relay-communication
python3 wallet/member_app.py --network testnet --transport hosted \
  --operator-bundle "$LOKI_OPERATOR_BUNDLE" \
  --operator-key "$(xxd -p -c 256 "$LOKI_CONFIG_KEY")" \
  --enrollment-issuer /absolute/path/to/issuer-local \
  --lightwalletd-url https://your-testnet-lightwalletd.example \
  --data /private/member-1 --exchange /private/unused-hosted --port 8801
```

Set `LOKI_TESTNET_RPC` and `LOKI_TESTNET_COOKIE_FILE` to a synced Testnet node reachable on loopback before starting each member app. The member app and its browser must remain on the member's own machine. Give each invited member the public `bundle` and trusted `config-key`, but never the issuer seed or relay capabilities. They start their own app with the same `--network testnet --transport hosted` arguments and `--operator-bundle`/`--operator-key`, without `--enrollment-issuer`, then join from their private invitation. Each member compares the roster fingerprint and checks their own final backup card before funding.

The local issuer wrapper is a pilot shortcut: code on the creator computer can request grants while it can invoke that executable. A public signup or independently hosted creator needs an authenticated enrollment provider. The bundle and grant command also supports operator-issued grants for a known device key, but the current member UI has no self-service enrollment-request screen.

## Stop or roll back

Stop admission first, then relays: `sudo systemctl stop loki-admission loki-relay@1 loki-relay@2 loki-relay@3`. Keep `/var/lib/loki` and the signed configuration intact. To roll back binaries, restore the prior pinned binaries at `/opt/loki/bin`, restart, and repeat the relay challenge and client checks. Never initialize a second relay root over an existing one or replace the signed bundle silently. Member approvals cannot proceed with fewer than two reachable relays.

This bundle has been checked against the repository's protocol tests. Actual Linux service startup, public DNS/TLS, physical-device onboarding, a mined Testnet hosted payment, and separate relay operators still require deployment evidence.
