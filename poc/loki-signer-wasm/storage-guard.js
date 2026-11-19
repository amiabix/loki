// The sealed share, the device-login key and the vault state live in this origin's OPFS and
// IndexedDB. A browser may evict an origin's storage under storage pressure unless the origin
// holds persistent storage, and eviction deletes the share without asking. Measured on
// Chromium 155: a quota eviction round removed a non-persistent signer's OPFS and IndexedDB.

const fail = (message, status) => Object.assign(new Error(message), { status });

export const SHARE_MISSING = "Your signer's share is missing from this browser: its storage was cleared. Restore it from your 24 recovery words and a vault's recovery backup file.";

// Refuse to seal a share where the browser may evict it. Chrome and Edge grant persist() by
// their own heuristics (bookmarked or installed site, notifications, engagement), Firefox asks.
export async function requirePersistentStorage(storage) {
  if (await storage?.persist?.().catch(() => false)) return;
  throw fail("This browser refused the Loki signer persistent storage, so it could delete your share under storage pressure. "
    + "Bookmark or install this wallet (Chrome, Edge), or allow storage when the browser asks (Firefox), then try again.", 412);
}

// `has` answers whether this browser still holds a sealed share.
export async function requireShare(has) {
  if (!await has()) throw fail(SHARE_MISSING, 404);
}
