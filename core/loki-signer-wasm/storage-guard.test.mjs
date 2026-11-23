import { test } from "node:test";
import assert from "node:assert/strict";
import { requirePersistentStorage, requireShare, SHARE_MISSING } from "./storage-guard.js";

test("a share is never created or restored where the browser may evict it", async () => {
  for (const storage of [{ persist: async () => false }, { persist: async () => { throw new Error("denied"); } }, {}, undefined]) {
    await assert.rejects(requirePersistentStorage(storage), (e) => e.status === 412 && /persistent storage/.test(e.message));
  }
  await requirePersistentStorage({ persist: async () => true });
});

test("unlocking a browser whose share is gone says to restore it", async () => {
  await assert.rejects(requireShare(async () => false), (e) => e.status === 404 && e.message === SHARE_MISSING);
  assert.match(SHARE_MISSING, /recovery words/);
  assert.match(SHARE_MISSING, /backup/);
  await requireShare(async () => true);
});
