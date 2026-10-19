# Demo chain: broadcast + confirm

The demo needs a real Zcash chain so a signed FROST multisig tx can be
**broadcast** and **confirmed**, not just verified-valid. Two paths work on the
demo host (omarchy). Pick one.

Host access:

```
ssh -o HostKeyAlias=omarchy abix@100.83.113.38
```

---

## Recommended for the demo: public Testnet

No local node, no version skew with the Loki Python, and this is the path of
the earlier confirmed Testnet payment.

- **lightwalletd**: `https://testnet.zec.rocks:443` — reachable from omarchy
  (TLS connects, HTTP 200).
- **Broadcast**: `loki_member_payment finish` sends the raw tx to lightwalletd
  via gRPC `SendTransaction` (`poc/src/bin/loki_member_payment.rs:1095-1101`).
  The endpoint comes from `LOKI_LIGHTWALLETD`, else the default
  `https://testnet.zec.rocks:443` (`poc/src/bin/loki_wallet_sync.rs:71`,
  `poc/src/wallet_store.rs:202-213`).
- **Confirm**: scan the public chain back with `loki_wallet_sync` /
  `loki_member_payment verify` — no local mining; the public miners confirm.

Verify the binaries build and connect (no funds spent). Binaries already built
at `~/loki/poc/target/debug/`:

```
cd ~/loki/poc
cargo test --locked -p loki-poc --bin loki_wallet_sync -- \
  --ignored reaches_public_testnet_lightwalletd --nocapture
```

Passing output means the client connected over TLS, called `GetLightdInfo`,
and the server reported `chain_name == "test"` above NU7 height — i.e. the
broadcast/scan endpoint is live.

Do NOT run a real payment unless the vault is funded; broadcasting spends.

---

## Alternative: local THS regtest node

Self-contained, nothing to fund from a tap, instant blocks. The node matches
the contract `poc/demo/managed_ths.py` drives (RPC branch `37a5165b`,
`/api/v1/status`, `ths mine`, bundled lightwalletd).

### One-time setup (on omarchy)

The installed launcher under the old name `thus-spoke-zakura` is stale and
lacks `mine`/`faucet`. Build the current `ths` from the checkout and pull its
matching runtime images:

```
cd ~/Projects/thus-spoke-zakura
cargo build --release --bin ths
ln -sf ~/Projects/thus-spoke-zakura/target/release/ths ~/.local/bin/ths
ths pull            # fetches zakura 1.6.0 + matching app/lightwalletd images
```

### Bring up + verify

```
./infra/ths-regtest-up.sh        # copied to the host; starts env "loki" if down
```

This starts `ths --name loki start --no-open`, then asserts the chain reports
`nextblock 37a5165b` / NU6.3 active, the dashboard `/api/v1/status` wallet is
`ready`, and `ths mine` works.

### How the demo broadcasts + confirms on regtest

`poc/demo/managed_ths.py` owns the env:

- **start**: `ths --name <n> start --no-open --port-offset <k>` (`managed_ths.py:247`)
- **broadcast**: `loki_member_payment finish` → bundled lightwalletd
  `SendTransaction` (same code path as Testnet; `LOKI_LIGHTWALLETD` points at
  the THS lightwalletd, `wallet_store.rs:200-213`)
- **confirm**: `ths --name <n> mine 3 --json` (`managed_ths.py:342-346`), then
  `loki_member_payment verify <txid>`

### Known skew (regtest only)

The browser demo's *vault-funding* step `managed_ths.fund` (`managed_ths.py:325-331`)
POSTs `/api/v1/faucet/address` and requires `result["status"] == "confirmed"`
plus an `idempotency_key` it sends. The installed THS v0.3.0 image's
`faucet_address` dropped `status` and ignores `idempotency_key` — it is now
synchronous (broadcast + mine 1, always confirmed) and returns only
`{address, amount_zatoshi, txid, block_hash}`
(`~/Projects/thus-spoke-zakura/crates/ths-server/src/api.rs:548-590`). So the
browser demo's funding call errors on this image even though the faucet
itself confirms a real tx. The node, RPC, status probe, mining, and the actual
payment broadcast are unaffected. Fixing the one-field check lives in `poc/`
(owned elsewhere); until then prefer the Testnet path for the end-to-end
browser demo, or fund the regtest vault with `ths faucet <addr>` out of band.
