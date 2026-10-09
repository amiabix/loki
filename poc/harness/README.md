# THS regtest environment

Loki uses [Thus Spoke Zakura](https://github.com/zcashlabs/thus-spoke-zakura)
(`ths`) for its disposable local chain. Install THS using its upstream README,
install/start Docker, and run `ths doctor`. `ths pull` prepares the exact runtime
images selected by the installed launcher. There is no standalone node binary
or Loki-owned node configuration to build or copy.

## Browser demo

From `poc/`, build Loki and run `python3 demo/server.py`. Create the account and
click **Start the test network**; the browser runner starts and manages its own
THS instance. Stop network, Reset, and graceful server exit delete that environment
through `ths stop`. See [../demo/README.md](../demo/README.md).

## Start and select an instance for terminal harnesses

```sh
ths --name loki start --no-open --port-offset 10
```

Keep this foreground process running. Use a new instance name and free ports;
THS start creates a fresh environment. Its shutdown deletes that environment.
For an offset of 10, the expected loopback endpoints are dashboard `32815`,
node RPC `18242`, lightwalletd `9077`, and P2P `18243`. Discover actual endpoints:

```sh
ths --name loki endpoints --json
ths --name loki status --json
```

In the terminal running Loki:

```sh
cd poc
export LOKI_THS_INSTANCE=loki
cargo build
./run-regtest.sh
./tamper-tests.sh
./run-second-device.sh
```

The shared `ths.py` adapter validates endpoint metadata, requires HTTP on
`127.0.0.1`, and checks NU6.3/Ironwood branch `37a5165b` against the live node.
Loki passes the discovered endpoint as `LOKI_RPC`; the selected instance is
never derived from a browser request. THS owns node configuration, services,
wallet/treasury, and chain data. Loki owns DKG, trial decryption, FROST approval,
proof generation, and intent verification.

## Funding and confirmation

THS mines to its treasury. Loki funds its vault with 1 ZEC faucet transfers,
using `/api/v1/faucet/address` with a stable idempotency key. The tamper and
second-process tests request two equal-value notes. The app must report confirmed
funding with a block hash before Loki scans; retrying the same vault's request
uses the same key. The harness supplies the idempotency key directly through
the app API.

After Loki broadcasts, `ths --name loki mine 3` mines confirmations; Loki reads
back and decrypts the transaction to verify its approved effects. No continuous
internal miner is assumed. The second-process harness retains its five failure
checks and moves approver state aside before finishing each payment.

CLI state is created in fresh temporary directories and retained for inspection.
`LOKI_STATE`, `BOB_STATE`, and `ATTIC` overrides must name new, separate paths.
No terminal chain harness deletes caller-supplied state or stops THS. Stop its
THS foreground process when finished to delete that dedicated chain. The browser
demo manages and deletes a separate instance of its own. Account files contain disposable
secrets and must not be committed.

The historical Zebra run is recorded in `RESULTS.md` and `DEPENDENCIES.md`.
The prototype remains G1-TX only; full G1, physical-device safety, and custody
remain unproven.
