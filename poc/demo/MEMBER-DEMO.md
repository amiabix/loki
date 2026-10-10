# Separate-member payment UI

This loopback-only regtest UI drives `loki_setup_member` and
`loki_member_payment`. It is separate from the older `/` account demo, which
still uses a test-only viewing key.

## Run

Install THS and Docker as in [the harness guide](../harness/README.md). Feature-build both workspaces, then start the coordinator:

```sh
cargo build --manifest-path communication/Cargo.toml --locked --offline --bin loki-relay-server
cargo build --manifest-path poc/Cargo.toml --features relay-communication --locked --offline --bins
python3 poc/demo/member_demo.py --port 8790
```

**Create a test payment** is the only preparation action. It starts THS, creates the vaults from `run/source/member-N`, and starts three relays. There is no second chain launch and no second DKG. The third relay stays on standby while two relays hold the copies. Relay stop or restart reuses that relay store and does not mine or reset THS. Reset abandons the attempt and creates fresh relay state. One attempt is active at a time.

Transport saved, stored, and received stay separate from application acceptance, approval, and chain confirmation. Alice and Bob see their own relay events. Carol sees the network. Replay does not call the backend. Closing a browser leaves the coordinator running.

The live gate is `python3 poc/demo/verify_relay_payment.py --port <free> --timeout 1800`. It owns that port. The public `relay-payment-demo-report.json` is under the selected run. It records source and binary identities, relay pins, carrier and receipt digests, the mailbox-denial canary, scenario results, and the mined txid. It does not record the coordinator token or secret paths.

Supplemental communication-harness checks are separate from this launch. The older `poc/demo/server.py` account UI is a different demo.

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
