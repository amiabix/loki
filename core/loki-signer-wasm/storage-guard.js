const fail = (message, status) => Object.assign(new Error(message), { status });

export const SHARE_MISSING = "Your signer's share is missing from this browser: its storage was cleared. Restore it from your 24 recovery words and a vault's recovery backup file.";

export async function requirePersistentStorage(storage) {
  if (await storage?.persist?.().catch(() => false)) return;
  throw fail("This browser refused the Loki signer persistent storage, so it could delete your share under storage pressure. "
    + "Bookmark or install this wallet (Chrome, Edge), or allow storage when the browser asks (Firefox), then try again.", 412);
}

export async function requireShare(has) {
  if (!await has()) throw fail(SHARE_MISSING, 404);
}
