import assert from "node:assert/strict";
import { test } from "node:test";
import { invitePreview, paymentLabel, rememberedVaultSlot, rememberVaultSlot, verifyPhrase } from "../src/lib/wallet-ui.ts";

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
  assert.equal(paymentLabel("failed", true, true), "Failed · create a new payment");
  assert.equal(paymentLabel("discarding", true, true), "Releasing reserved input");
  assert.equal(paymentLabel("cancelled", true, true), "Discarded");
  assert.equal(paymentLabel("expired", true, true), "Expired");
  assert.equal(paymentLabel("unknown_internal_phase", false, false), "Status unavailable");
});

test("verify phrase is deterministic, word+emoji, and rejects non-hex", () => {
  const fp = "a".repeat(64);
  const p = verifyPhrase(fp);
  assert.deepEqual(p, verifyPhrase(fp.toUpperCase())); // case-insensitive, deterministic
  assert.equal(p.words.length, 5);
  assert.equal(p.emoji.length, 4);
  assert.ok(p.words.every((w) => typeof w === "string" && w.length));
  // a flipped byte changes the rendering (so a swapped roster shows differently)
  assert.notDeepEqual(p, verifyPhrase("b" + "a".repeat(63)));
  for (const bad of [undefined, "", "xyz", "abc", "zz"]) assert.equal(verifyPhrase(bad), null);
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
