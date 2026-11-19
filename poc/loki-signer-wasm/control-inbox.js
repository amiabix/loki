// Control-session reads for the browser signer. frostd hands each message to its recipient
// once: a receive drains the inbox. A native member saves what it reads (payment.rs
// `sync_control`); the browser signer kept nothing, so a proposer's notice, sent once at
// publish, vanished after the first approval-inbox poll and review could no longer find it.
// This keeps every message opened on a session and returns the whole history on each read.
// ponytail: worker memory only, so a page reload forgets notices already drained; persist to
// OPFS if members reload between a proposal and their approval.
export function controlInbox() {
  const seen = new Map();
  return async (sessionId, drain) => {
    const all = seen.get(sessionId) ?? [];
    all.push(...await drain());
    seen.set(sessionId, all);
    return [...all];
  };
}
