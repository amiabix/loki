# THS issues observed during Loki integration

Date: 2026-10-08. These observations concern the local THS installation used for
the Loki regtest experiment. They are not claims about all THS releases.

## Artifacts

- Installed launcher: `ths 0.3.0`.
- Dedicated instance: `loki-poc-20261008`, port offset 10.
- Zakura: `zakuracore/zakura:1.6.0`, image ID
  `sha256:bf53c178e9549217fce7cfaa21efc85c478129ba6dc5307d55640514affeb0ac`.
- App: `ghcr.io/zcashlabs/thus-spoke-zakura-app:0.3.0`, image ID
  `sha256:0353489e7e1566cb55d5a788d4d081e10ee0746cd900e9b5dd9a4d99a79d173d`.
- lightwalletd: `ghcr.io/zcashlabs/thus-spoke-zakura-lightwalletd:0.3.0`, image ID
  `sha256:9022dd9a5849863c8e07cf3a15e7d5268db7e52aff0edc2c3293eb8743c36693`.

## Faucet command rejected by the app

Command:

```sh
ths --name loki-poc-20261008 faucet <loki-vault-address> --amount 1 --json
```

Observed result: exit 1, HTTP 400:

```text
idempotency_key must contain 8-128 characters
```

The installed CLI request does not satisfy the running app's idempotency-key
validation. The precise request body from that installed binary was not captured.
The neighboring THS source checkout explicitly sends an `idempotency_key` in
`Runtime::faucet`, but it is not evidence that the installed binary contains that
implementation. Matching version strings alone did not establish compatibility.

Workaround verified: POST to the same app's `/api/v1/faucet/address` with
`address`, `amount_zatoshi: 100000000`, and the stable key
`loki-ths-fund-91eRIl-01`. The app returned `status: confirmed`, a transaction ID,
and a block hash. Loki independently scanned the chain and found the 1 ZEC note.
This preserves idempotency validation rather than weakening it.

No THS source, installed launcher, or image was changed. A THS follow-up should
reproduce against the exact launcher and app artifacts above, verify the request
body, and align their API contract.
