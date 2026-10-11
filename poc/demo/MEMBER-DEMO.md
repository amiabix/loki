# Separate-member payment UI

This loopback-only regtest UI drives the relay-backed `loki_member_payment`
commands through three sandboxed member stores and three local relays. It is
separate from the older `/` account demo.

## Run

Install THS and Docker as in [the harness guide](../harness/README.md), then:

```sh
cd communication
cargo build --locked --bins
cd ../poc
cargo build --locked --bins --features relay-communication
python3 demo/member_demo.py
```

Open the **Coordinator** URL printed in the terminal. Create a payment to a
new independent recipient vault. The amount and memo come from the form; the
regtest source vault receives one faucet note. Setup, backup checks, funding and
proposal creation take a few minutes. Launch Alice and Bob in separate
browser profiles. Each page displays that member's verified CLI review and
requires an explicit **Confirm payment** action. An approval counts only after
its two encrypted share messages are stored by the relays; a failed delivery
can be retried without signing again. Carol's window can then prove and send.
The UI says **Confirmed** only
after the mined transaction passes both source and recipient checks.

For a repeatable browser check, start a second fresh demo on another port in
one terminal, then run the check from another:

```sh
LOKI_MEMBER_DEMO_ROOT=/private/tmp/loki-member-demo-browser-check python3 demo/member_demo.py --port 8791
```

```sh
npm ci --ignore-scripts --prefix g3
LOKI_DEMO_URL='http://127.0.0.1:8791/#<printed-token>' node demo/test-member-browser.js
```

The check creates a regtest payment, opens an Alice window, signs from separate
Alice and Bob browser profiles, and waits for Carol's history to show the mined
txid. It requires Playwright's Chromium browser installed locally and leaves the
confirmed demo instance running for inspection.

The server creates and owns one disposable THS instance and three local relays.
Reset or a clean server exit stops those owned services. A restart during
signing abandons the attempt; reset creates fresh vaults and signing material.
State under `demo/.member-sandbox` (or the named test root) includes keys,
backup words, passphrases and nonce state.
Do not copy it or use real funds.

The member CLI commands are sandboxed against each other's files, but one local
test server still controls every member store and all three relays. This does
not establish independent custody, independent relay operators, browser key
storage, or physical power-loss safety. The local ZIP 2005 derivation and
backup format remain unreviewed. Do not use real funds.
