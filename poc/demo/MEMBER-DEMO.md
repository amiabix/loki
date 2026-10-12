# Separate-member payment UI

This loopback-only regtest UI drives the relay-backed `loki_member_payment`
commands through three sandboxed member stores and three local relays. It is
separate from the older `/` account demo.

## Run

Install THS and Docker as in [the harness guide](../harness/README.md). Feature-build both workspaces, then start the coordinator:

```sh
cd communication
cargo build --locked --bins
cd ../poc
cargo build --locked --bins --features relay-communication
python3 demo/member_demo.py
```

The terminal prints separate **Alice**, **Bob**, and **Carol** URLs. Open each
in a separate browser profile. The fresh run starts with no vault or payment.
Any member can start the local 2-of-3 source vault and independent recipient
vault, then add one test ZEC. Any member can propose a payment, enter a
unified recipient address, and choose one pair to sign this attempt. The two
selected members each see their own verified CLI review and must explicitly
**Confirm payment**. An approval counts only after its exact encrypted share
carriers are stored by the relays and the approver process prints `stored` before
exiting successfully. A failed delivery can be retried using the saved share
without signing again. Any member can then prove and send. The UI says **Confirmed**
only after the mined transaction passes the source vault's chain check. When
the recipient is the generated local vault, that vault decrypts and checks it
too.

For a repeatable browser check, start a second fresh demo on another port in
one terminal, then run the check from another:

```sh
LOKI_MEMBER_DEMO_ROOT=/private/tmp/loki-member-demo-browser-check python3 demo/member_demo.py --port 8791
```

```sh
npm ci --ignore-scripts --prefix g3
LOKI_ALICE_URL='http://127.0.0.1:8791/#<Alice-token>' \
LOKI_BOB_URL='http://127.0.0.1:8791/#<Bob-token>' \
LOKI_CAROL_URL='http://127.0.0.1:8791/#<Carol-token>' \
node demo/test-member-browser.js
```

The check starts the vault and proposes from Bob's browser profile, signs
from separate Bob and Carol profiles, and finishes from Alice's profile. It
requires Playwright's Chromium browser and leaves the confirmed demo instance
running for inspection.

The **Relay network** view shows each member's public transport evidence,
application acceptance, approvals, and chain status separately. The vault creator
can stop or restart a relay, pause or resume a member, and resend a saved share
for any selected approver. Replay reads cached events without fetching new ones.

The live gate is `python3 demo/verify_relay_payment.py --port <free> --timeout
1800`. It owns that port and uses the same staged member actions. Its public
`relay-payment-demo-report.json` records binary identities, relay pins, carrier
and receipt digests, the mailbox-denial canary, scenario results, and the mined
txid without coordinator tokens or secret paths. Supplemental
communication-harness checks are separate from the mined payment.

The server creates and owns one disposable THS instance and three local relays.
Reset or a clean server exit stops those owned services. A restart during
signing abandons the attempt; reset creates fresh vaults and signing material.
State under `demo/.member-sandbox` (or the named test root) includes keys,
backup words, passphrases and nonce state.
Do not copy it or use real funds.

The member CLI commands are sandboxed against each other's files, but one local
test server still controls every member store and all three relays. This does
not establish independent custody, independent relay operators, browser key
storage, or physical power-loss safety. Setup remains a fixed 2-of-3 local
fixture, and a proposal picks one pair before signing: a third member cannot
join the same attempt if that pair stalls. The local ZIP 2005 derivation and
backup format remain unreviewed. Do not use real funds.
