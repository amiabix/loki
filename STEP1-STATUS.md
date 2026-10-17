# Step 1 live-node checks

Offline tests cover 2-of-3, 2-of-4, and 3-of-4 key generation, ceremony checkpoint restore, signing after restore, and nonce rollback and mailbox refusal. Docker is available, but the `ths` CLI required by the regtest harness is not installed here.

Still requires a live THS regtest node:

- Create and fund a hosted vault for each UI policy, then mine a payment signed by exactly its displayed threshold.
- For 3-of-4, confirm that two members cannot produce a mined spend and that three can after a signer process is restarted mid-signing.
- Repeat a payment after restoring a member from its recovery card and confirm the live relay nonce claims remain bound to the original mailboxes.
