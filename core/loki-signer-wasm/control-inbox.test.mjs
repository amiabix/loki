import { test } from "node:test";
import assert from "node:assert/strict";
import { controlInbox, endsRequest } from "./control-inbox.js";

const relayOnce = (...msgs) => { let left = msgs; return async () => { const out = left; left = []; return out; }; };

test("a notice read once is still there on the next read", async () => {
  const read = controlInbox();
  const drain = relayOnce({ from: 1, kind: "intent" });
  assert.deepEqual(await read("s1", drain), [{ from: 1, kind: "intent" }]);
  assert.deepEqual(await read("s1", drain), [{ from: 1, kind: "intent" }]);
});

test("later messages follow earlier ones, per session", async () => {
  const read = controlInbox();
  await read("s1", relayOnce({ from: 1, kind: "intent" }));
  await read("s2", relayOnce({ from: 2, kind: "intent" }));
  assert.deepEqual(await read("s1", relayOnce({ from: 1, kind: "start" })), [{ from: 1, kind: "intent" }, { from: 1, kind: "start" }]);
  assert.deepEqual(await read("s2", relayOnce()), [{ from: 2, kind: "intent" }]);
});

test("a request ends when it is cancelled, failed, signed, sent or leaves this member out", () => {
  for (const kind of ["cancelled", "failed", "signed", "broadcast", "confirmed"]) assert.equal(endsRequest({ kind, intent: {} }, 3), true, kind);
  assert.equal(endsRequest({ kind: "start", intent: { signers: [1, 2] } }, 3), true);
  assert.equal(endsRequest({ kind: "start", intent: { signers: [1, 3] } }, 3), false);
  assert.equal(endsRequest({ kind: "intent", intent: {} }, 3), false);
});

test("kept notices survive a new inbox over the same store", async () => {
  const saved = new Map();
  const store = { get: async (k) => saved.get(k) ?? [], put: async (k, v) => { saved.set(k, v); } };
  await controlInbox(store)("s1", relayOnce({ from: "aa", message: "sealed-1" }));
  const afterReload = controlInbox(store);
  assert.deepEqual(await afterReload("s1", relayOnce()), [{ from: "aa", message: "sealed-1" }]);
  assert.deepEqual(await afterReload("s1", relayOnce({ from: "aa", message: "sealed-2" })), [{ from: "aa", message: "sealed-1" }, { from: "aa", message: "sealed-2" }]);
});
