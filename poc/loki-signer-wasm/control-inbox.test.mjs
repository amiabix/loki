// node --test poc/loki-signer-wasm/control-inbox.test.mjs
import { test } from "node:test";
import assert from "node:assert/strict";
import { controlInbox } from "./control-inbox.js";

// frostd hands a message to a recipient once: every later receive is empty.
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
