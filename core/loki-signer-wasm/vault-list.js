export function vaultSummary(v, name) {
  return { vault: v.vault_id, name: name || `Vault ${v.vault_id.slice(0, 8)}`, members: v.members.length, threshold: v.threshold, active: v.ready };
}

export async function saveVaultName(dir, name) {
  const file = await (await dir.getFileHandle("name", { create: true })).createSyncAccessHandle();
  try {
    file.truncate(0);
    file.write(new TextEncoder().encode(name), { at: 0 });
    file.flush();
  } finally { file.close(); }
}

export async function readVaultName(dir) {
  try { return await (await (await dir.getFileHandle("name")).getFile()).text(); }
  catch { return ""; }
}
