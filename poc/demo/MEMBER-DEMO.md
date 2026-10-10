# Separate-member payment UI

This loopback-only regtest UI drives `loki_setup_member` and
`loki_member_payment`. It is separate from the older `/` account demo, which
still uses a test-only viewing key.

## Run

Install THS and Docker as in [the harness guide](../harness/README.md), then:

```sh
cd poc
cargo build --locked --bins
python3 demo/member_demo.py
```

Open the **Coordinator** URL printed in the terminal. Create a payment to a
new independent recipient vault. The amount and memo come from the form; the
regtest source vault receives one faucet note. Setup, backup checks, funding and
proposal creation take a few minutes. Launch Alice and Bob in separate
windows. Each page displays that member's verified CLI review and
requires an explicit **Confirm payment** action. After both shares are saved,
Carol's window can prove and send. The UI says **Confirmed** only
after the mined transaction passes both source and recipient checks.

For a repeatable browser check, start a second fresh demo on another port in
one terminal, then run the check from another:

```sh
python3 demo/member_demo.py --port 8791
```

```sh
npm ci --ignore-scripts --prefix g3
LOKI_DEMO_URL='http://127.0.0.1:8791/#<printed-token>' node demo/test-member-browser.js
```

The check creates a regtest payment, opens an Alice window, signs from separate
Alice and Bob browser profiles, and waits for Carol's history to show the mined
txid. It requires Playwright's Chromium browser installed locally and leaves the
confirmed demo instance running for inspection.

The server creates and owns one disposable THS instance. Reset or a clean server
exit stops only that instance. A restart during signing abandons the attempt;
reset creates fresh vaults and signing material. State under
`demo/.member-sandbox` includes keys, backup words, passphrases and nonce state.
Do not copy it or use real funds.

Separate windows make the review flow visible; separate browser profiles or
devices are needed to simulate independent member custody. One local server
still controls every member store. This is **not** independent custody, a relay,
or a browser signer. Its local file courier and nonce state have no rollback
protection. The local ZIP 2005 derivation and backup format remain unreviewed.
