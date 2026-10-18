# Loki Product Specs

Production specs for turning Loki from a regtest research harness into a usable,
non-custodial shielded Zcash FROST multisig wallet.

**Start here:** [`00-architecture.md`](00-architecture.md) — the locked decision record
and threat model. Everything else derives from it.

The shape, in one line: a **Safe-style keyless coordinator** (may be a web app) +
an **isolated native signer** that holds the member's FROST share, wrapped by the
device secure element and gated by biometrics. The key is **born in the signer, never
in the browser**, and the real transaction is **confirmed on the signer**. Crypto and
coordination come from the **audited ZF FROST stack**.

| Spec | Title |
|---|---|
| [00](00-architecture.md) | Architecture — decision record & threat model |
| [WS1](ws1-signer.md) | The Signer (safety-critical) |
| [WS2](ws2-coordinator.md) | Coordinator / Wallet (keyless) |
| [WS3](ws3-transport.md) | Transport (`frostd` / serverless memo) |
| [WS4](ws4-zf-stack-adoption.md) | ZF Stack Adoption |
| [WS5](ws5-fvk-derivation.md) | FVK Derivation (one decision to lock) |
| [WS6](ws6-standards-and-audit.md) | Standards, Trust & Audit |
| [07](07-roadmap.md) | Roadmap & Sequencing |

Context: these specs close the open "browser or native key-storage decision" and the
"app delivery is custody" warning in [`../../WALLET_BUILD.md`](../../WALLET_BUILD.md),
and build on its vault / member / roster / DKG / candidate / approval vocabulary.
</content>
