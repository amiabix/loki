import assert from "node:assert/strict";
import { test } from "node:test";
import { invitePreview, paymentLabel, rememberedVaultSlot, rememberVaultSlot } from "../src/lib/wallet-ui.ts";

const invite = { vault: "a".repeat(64), name: "Friends’ vault", members: 3, threshold: 2, slot: 2 };
const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");

test("invite preview preserves Unicode and rejects malformed metadata", () => {
  assert.deepEqual(invitePreview(encode(invite)), invite);
  for (const change of [{ name: "" }, { vault: "bad" }, { members: 17 }, { threshold: 4 }, { slot: 1 }, { slot: 4 }, { threshold: "2" }]) {
    assert.equal(invitePreview(encode({ ...invite, ...change })), null);
  }
  for (const code of ["not an invite", "", encode(null), encode([])]) assert.equal(invitePreview(code), null);
});

test("pending payments never look sent and internal phase names stay hidden", () => {
  assert.equal(paymentLabel("signing", false, false), "Collecting approvals");
  assert.equal(paymentLabel("signing", true, false), "Ready to send");
  assert.equal(paymentLabel("signing", true, true), "Sending");
  assert.equal(paymentLabel("broadcast", false, true), "Awaiting confirmation");
  assert.equal(paymentLabel("confirmed", false, true), "Confirmed");
  assert.equal(paymentLabel("not_selected", false, false), "Other members are signing");
  assert.equal(paymentLabel("expired", true, true), "Expired");
  assert.equal(paymentLabel("unknown_internal_phase", false, false), "Status unavailable");
});

test("remembered vault slots are scoped to the authenticated profile and vault", () => {
  const values = new Map();
  globalThis.localStorage = { getItem: (key) => values.get(key) ?? null, setItem: (key, value) => values.set(key, value) };
  rememberVaultSlot("alice", "vault-a", 2);
  assert.equal(rememberedVaultSlot("alice", "vault-a"), 2);
  assert.equal(rememberedVaultSlot("bob", "vault-a"), null);
  assert.equal(rememberedVaultSlot("alice", "vault-b"), null);
  assert.equal(rememberedVaultSlot(undefined, "vault-a"), null);
  values.set("loki_slot:alice:vault-a", "99");
  assert.equal(rememberedVaultSlot("alice", "vault-a"), null);
  globalThis.localStorage = { getItem: () => { throw new Error("denied"); }, setItem: () => { throw new Error("denied"); } };
  assert.doesNotThrow(() => rememberVaultSlot("alice", "vault-a", 2));
  assert.equal(rememberedVaultSlot("alice", "vault-a"), null);
  delete globalThis.localStorage;
});
