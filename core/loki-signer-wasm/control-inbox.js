// Control-session reads for the browser signer. frostd hands each message to its recipient
// once: a receive drains the inbox. A native member saves what it reads (payment.rs
// `sync_control`); the browser signer must keep what it drained too, or a proposer's notice,
// sent once at publish, is gone after the first approval-inbox poll and after a page reload.
// This keeps every relay message of a session in `store` and returns the whole history on
// each read. The messages are kept as the relay delivered them, still sealed to this member
// (the caller opens them), so the store holds nothing the relay operator could not see.
export function controlInbox(store = memoryStore()) {
  const seen = new Map();
  return async (sessionId, drain) => {
    const all = seen.get(sessionId) ?? [...await store.get(sessionId)];
    const fresh = await drain();
    all.push(...fresh);
    seen.set(sessionId, all);
    if (fresh.length) await store.put(sessionId, all);
    return [...all];
  };
}

function memoryStore() {
  const m = new Map();
  return { get: async (k) => m.get(k) ?? [], put: async (k, v) => { m.set(k, v); } };
}

// The browser store: IndexedDB on the signer origin, one record per control session.
// ponytail: never pruned; drop sessions of settled payments if it grows.
export function idbStore(name = "loki_control") {
  const db = new Promise((resolve, reject) => {
    const req = indexedDB.open(name, 1);
    req.onupgradeneeded = () => req.result.createObjectStore("sessions");
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
  const run = async (mode, fn) => {
    const r = fn((await db).transaction("sessions", mode).objectStore("sessions"));
    return new Promise((resolve, reject) => { r.onsuccess = () => resolve(r.result); r.onerror = () => reject(r.error); });
  };
  return {
    get: async (k) => (await run("readonly", (s) => s.get(k))) ?? [],
    put: (k, v) => run("readwrite", (s) => s.put(v, k)),
  };
}

// Whether a proposer notice ends a request for this member (slot): cancelled, failed, already
// signed or sent, or a signing group that leaves this member out. Kept notices outlive the
// request, so the inbox must drop it on these, not only when the notices stop coming.
export function endsRequest(msg, slot) {
  if (["cancelled", "failed", "signed", "broadcast", "confirmed"].includes(msg.kind)) return true;
  return msg.kind === "start" && !!msg.intent?.signers?.length && !msg.intent.signers.includes(slot);
}
