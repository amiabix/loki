# Loki

Loki is being built as a shielded Zcash multisig wallet. The current code is a
**regtest research harness**, not a wallet people can use to hold funds. It has
demonstrated a mined Ironwood payment signed by two FROST members, separate
member setup and backup, independent transaction review, and finishing by a
third member. The local browser demo puts all member files and approval processes
behind one Python server. Separate browser windows do not give members separate
custody.

## Product direction

The setup app now starts with **one member, one app, one private key store**.
It lets three independently launched members create and join a vault, compare
their roster, run dealerless key creation, and check their own backups. See
[the setup app](poc/wallet/README.md) for how to run it and its limits. A member's
app must still create or restore only that member's share, review
the transaction itself, and release an approval only after that member acts.
Other members receive signed, encrypted messages; no coordinator or web server
can approve on their behalf. See [the implementation path](WALLET_BUILD.md)
for the sequence and its acceptance checks.

The existing Rust code is valuable input to that work. The older Python demo, scripted
funding, shared local mailbox and test-only key paths remain under [`poc/`](poc/README.md)
as regression tools. They are not the product architecture.

## Run the current regtest harness

With Rust, Python 3, Docker and [THS](https://github.com/zcashlabs/thus-spoke-zakura)
installed:

```sh
cd poc
cargo build --locked --bins
python3 demo/member_demo.py
```

Open the URL printed by the server. The [harness guide](poc/README.md) has its
tests and exact limits. Use only disposable regtest funds.
