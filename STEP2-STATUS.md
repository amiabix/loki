# Wallet scan status

The Testnet member balance, payment preparation, candidate construction, and
finishing paths now read the encrypted `wallet.sqlite` index created by
`loki_wallet_sync`. Finishing obtains historical Ironwood witnesses from that
index, checks the node's tree root, and refuses a stored block hash that no
longer matches the node or has fallen behind it. The member app syncs before
payment construction, finishing, and confirmation. Testnet confirmation requires
the mined transaction and its block hash in that index. A store test covers
reopening a funded wallet and rewinding a confirmation after a reorg; the
removed note disappears from the balance, spendable input query, and indexed
transaction lookup.

Live-node checks still needed: fund a disposable Testnet vault, sync it with
lightwalletd, close and reopen the member app, then prepare, sign, finish,
broadcast, and resync through confirmation. Reorg that confirmation on a
controlled Testnet node and verify balance and spendability after resync. This
workspace has no configured Testnet RPC cookie or live node, so those checks
were not run here.

The fixed-key `loki` regtest research harness still uses its existing scanner;
the persistent Testnet member payment path is the beta wallet path.
An outgoing transaction affects indexed balance after it is mined and synced;
the index does not reserve a broadcast input while it is still unconfirmed.
