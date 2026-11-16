# Browser-signed payment — handoff

Status of the in-browser WASM signer signing a real testnet payment, and exactly where
to pick it up. Everything below is on `main` at `e05be0f` unless noted.

## TL;DR

A browser member can **create a signer, join a vault, and complete a real 2-of-3 DKG**
over live `frostd` — proven. For **payments**, the browser now also drives the two-session
signing handshake and gets all the way through: it records its approval with the proposer
(`approvals=[1,3]`) and **receives the candidate + signing package**. It then **panics**
("unreachable") in the WASM signing core before emitting its share, so the proposer fails
the attempt with *"relay delivered 1 of 2 expected messages"*. **That panic is the only
thing between here and a broadcast.**

## What works (proven live this session)

- In-browser signer: create/unlock (passphrase proven end-to-end; passkey wired, see below),
  OPFS custody, share born in a Web Worker during DKG. OPFS holds
  `loki/vaults/<vault>/signer/share.sealed`.
- **2-of-3 browser DKG** with two native members over live TLS `frostd`; all three derived
  the same address.
- **Payment control-session approval**: the browser seals a `{kind:"approval"}` PeerReply and
  sends it on the control session; the proposer records it (`approvals=[1,3]`). Signing round
  starts and the browser receives the candidate + package.

## The one open bug

A **Rust panic** (surfaces as a bare `"unreachable"` wasm trap, not a graceful `JsError`) in
the signing-round core when run as a **remote approver** (slot 3, signers `[1,3]`, proposer
slot 1). It fires *after* the candidate + package arrive, in one of:
`open_candidate_impl` / `payment_review_impl` / `sign_approve_impl`
(`poc/loki-signer-wasm/src/lib.rs`; wrappers at 426-470 map `Result→JsError`, so a panic
inside an `_impl` bypasses the `Result` and traps).

Where to look first: a slot-vs-index assumption, the `signers_csv` ordering, or an identity/
key lookup that `unwrap()`s — anywhere a remote approver differs from a native non-proposer.

**First step: install `console_error_panic_hook`** (`set_once()` in the wasm `init`/start; it
is NOT currently installed) so the next run prints the real panic message + location instead
of `"unreachable"`. The worker's panic reaches the main thread as the rejected
`approvePayment` promise; worker `console.*` does **not** surface to the Chrome-extension
console reader, so either rely on the panic-hook message in the rejection or `postMessage`
diagnostics to the main thread. (A per-call `try/catch` wrapper in `drivePayment` that folds
the failing call + the observed `m.from` values into the thrown error was used this session to
localize it — re-add it if useful; it needs only a wallet rebuild, no wasm rebuild.)

## How to reproduce / validate (once fixed)

### 1. Bring up `frostd` + 2 native members + tunnels
- `frostd`: `~/frost-tools/target/release/frostd --no-tls-very-insecure -p 2744`
- CORS proxy for the browser (frostd sends no CORS): a ~20-line node http proxy
  `:2755 → 127.0.0.1:2744` setting `Access-Control-Allow-Origin: <wallet origin>` (OPTIONS 204
  + mirror on responses).
- Tunnels (quick `cloudflared tunnel --url http://localhost:<port>`): one for `:2755` (the
  browser's `frostd` URL), one for the creator member's `:3401` (the browser POSTs the
  ceremony + `/api/payment-session` endpoints there; member app CORS-opens them —
  `routes.rs:86-114`).
- Native members (binary `poc/target/debug/loki_member_app`, built with
  `cargo build --bin loki_member_app --features relay-communication`):
  ```
  loki_member_app --data <dir> --port 3401 --network testnet \
    --lightwalletd-url https://testnet.zec.rocks:443 --frostd-url http://127.0.0.1:2744 \
    --secure-element software --peer 1=<creator-HTTPS-tunnel>
  ```
  The creator (`--peer 1=<its own HTTPS tunnel>`) so the invite's `creator_base_url` is HTTPS
  and the browser can reach it. A second member needs no `--peer`.
- Native API (token from the printed `Signer: http://127.0.0.1:<port>/#<token>`, header
  `X-Loki-Token`): `profile-create` → `create {members,threshold}` → the other member and the
  browser `join` with the per-slot invite codes.

### 2. Browser joins + DKG
Serve the wallet in **production** (`next build` + `node server.js`, `NEXT_PUBLIC_FROSTD_URL`
= the `frostd` tunnel). `next dev` breaks on the signer assets' cache-control headers. In the
wallet: create/unlock a signer → **Join vault** → paste the slot-3 invite → DKG runs. Natives
need an explicit `/api/agree` (`{vault, fingerprint}` from `/api/status?vault=…`) once they hit
`compare_roster`; the browser agrees itself.

### 3. Payment
- Proposer (member 1), native API: `payment-draft {vault, recipient, amount_zat, memo,
  signers:[1,3]}` (the `signers` override — `payment.rs` — lets you force the browser, slot 3,
  into the signer set) → `payment-publish` → `payment-review` → `payment-approve {review_token}`.
  **Do not restart the member app after approve** — it orphans the signing worker and the
  attempt can only be recovered/failed, not resumed (`ensure_worker`, `payment.rs:847`).
- Browser signs (signer must be unlocked), via the console entry point:
  ```js
  await window.lokiApprovePayment({
    creatorBaseUrl: "<creator HTTPS tunnel>",
    vault: "<hex>", attempt: "<hex>"
  })
  ```
  It POSTs `/api/payment-session`, assembles the `drivePayment` params, sends the control
  approval, then drives the signing session. **This is where the panic fires today.**
- Watch `GET /api/payments?vault=…` for `ready_to_send: true`, then proposer
  `payment-finish {vault, attempt}` → broadcast → `payment-verify`.

### Gotchas learned
- An attempt can't be **re-driven** (the browser's first commitment makes the second a
  "duplicate commitment"); every drive needs a **fresh** attempt.
- Once **any** share is released, the spent input is **reserved for recovery** and the attempt
  is non-discardable — so a failed signing locks that note until expiry. Keep a spare funded
  note around while debugging.

## Passkey custody

Wired (`f3b2f71`): main-thread WebAuthn PRF (create credential → follow-up `get()` for the PRF
secret), credential id stored in `localStorage["loki_passkey_cred"]`, `prfSecret` threaded to
the worker. PRF salt `"loki/signer/share-kek/v1"`, `rp.id = window.location.hostname`, secure
context required. **Not yet tested on a real authenticator** (the automation host has none) —
test Touch/Face ID on a real device. Passphrase (Argon2id) is the proven path.

## Key files + commits

| Area | Where |
|---|---|
| In-browser signer core (wasm) + Worker | `poc/loki-signer-wasm/` (`src/lib.rs`, `signer-worker.js`) |
| Browser `frostd` transport (wasm) | `poc/wasm-transport/src/lib.rs` (`sendToPeer` for explicit-recipient sends) |
| Signer seam + `approvePayment` | `web/wallet/src/lib/signer.ts` |
| `/api/payment-session` (remote-signer params) + `signers` override | `poc/src/host/payment.rs`, route in `routes.rs` |
| Passkey | `web/wallet/src/lib/webauthn.ts` + `signer.ts` |

Commits on `main`: `f3b2f71` passkey · `756986f` payment-session + approvePayment · `13bb69c`
draft `signers` override · `e05be0f` control-session approval (the live-proven fix) · `3c4df7e`
README. **Open:** the signing-core panic fix (in progress when this was written).

## `/api/payment-session` response shape
```json
{ "session_id", "control_session_id", "control_hash", "intent", "intent_hash",
  "attempt", "signers", "proposer",
  "proposer_frostd_pubkey", "coordinator_frostd_pubkey",
  "members": [{"id","signing","encryption"}], "threshold", "network", "birth_height" }
```
`proposer_frostd_pubkey` = proposer's roster `encryption` (the `m.from` the candidate arrives
under). `coordinator_frostd_pubkey` = X25519 public of the per-payment one-shot coordinator
(`p.coordinator_secret`; package + seed arrive under it). The browser rebuilds the byte-exact
DKG setup doc (`{vault, threshold, setup_version:2, network, members, birth_height}`) for
`rosterHex`.
