# G1-TX regtest harness

A local NU6.3 (Ironwood) network. No peers, no proof-of-work validation, ephemeral state:
every run starts from genesis.

## Node

`zebrad` built from source. There is no published image carrying NU6.3.

- Upstream: https://github.com/ZcashFoundation/zebra
- Pinned commit: `6d1e414d6f55e4180d0e47baaa934bf97d5b4fec` (2026-10-02)
- Version: `zebrad 7.0.0-rc.0`
- Built with `--release --features internal-miner` on `rustc 1.91.0` (zebra pins it)
- Build time: 2m26s

```
git clone https://github.com/ZcashFoundation/zebra.git
cd zebra && git checkout 6d1e414d6f55e4180d0e47baaa934bf97d5b4fec
cargo build --release --package zebrad --features internal-miner
```

The resulting binary is copied to `harness/zebrad` and is **not** in version control.

## Run

```
harness/zebrad -c harness/zebrad-regtest.toml start
```

RPC on `127.0.0.1:18232`, no cookie auth, loopback only. The internal miner produces
blocks continuously; the first appears within ~10s.

## Confirmed state

```
chain     : test   (Regtest)
NU6.3     : branch 37a5165b | activation height 1 | ACTIVE
consensus : chaintip 37a5165b, nextblock 37a5165b
```

Activation-height keys are serde-renamed in `zebra-chain`; the exact TOML key is
`"NU6.3"`, not `NU6_3`.

## Not yet done

No wallet is attached. Checkpoint 2 still needs a funded Ironwood V3 note at the vault
address, plus its nullifier, witness and anchor.
