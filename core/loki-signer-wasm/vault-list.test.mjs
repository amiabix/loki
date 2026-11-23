import { test } from "node:test";
import assert from "node:assert/strict";
import { vaultSummary, saveVaultName, readVaultName } from "./vault-list.js";

const id = "6df7e10161f47641fc2502bee89786fc3ba6886bd3d9e5398c1146f4c3191111";
const vault = { vault_id: id, threshold: 2, members: [{}, {}, {}], ready: true };

function memoryDir() {
  const files = new Map();
  return {
    async getFileHandle(name, { create = false } = {}) {
      if (!files.has(name) && !create) throw new DOMException("missing", "NotFoundError");
      if (!files.has(name)) files.set(name, new Uint8Array());
      return {
        async getFile() { return new Blob([files.get(name)]); },
        async createSyncAccessHandle() {
          let data = files.get(name);
          return {
            truncate(n) { data = data.slice(0, n); },
            write(bytes, { at }) { const out = new Uint8Array(Math.max(data.length, at + bytes.length)); out.set(data); out.set(bytes, at); data = out; },
            flush() { files.set(name, data); },
            close() {},
          };
        },
      };
    },
  };
}

test("a joined vault is listed under the name it was joined with", async () => {
  const dir = memoryDir();
  await saveVaultName(dir, "UI2 mixed vault");
  assert.deepEqual(vaultSummary(vault, await readVaultName(dir)),
    { vault: id, name: "UI2 mixed vault", members: 3, threshold: 2, active: true });
});

test("saving a shorter name replaces the old one", async () => {
  const dir = memoryDir();
  await saveVaultName(dir, "a long first name");
  await saveVaultName(dir, "short");
  assert.equal(await readVaultName(dir), "short");
});

test("a vault saved without a name shows its id", async () => {
  assert.equal(vaultSummary(vault, await readVaultName(memoryDir())).name, "Vault 6df7e101");
});
