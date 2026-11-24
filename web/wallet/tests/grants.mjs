import { readFileSync, writeFileSync } from 'node:fs';

export function admitGrant(digest, slot = null) {
  const file = process.env.LOKI_REGISTRY;
  let registry;
  try { registry = JSON.parse(readFileSync(file, 'utf8')); } catch { registry = { access: [] }; }
  if (registry.version !== 1) {
    let legacy = [];
    try { legacy = JSON.parse(readFileSync(`${file}.devices`, 'utf8')); } catch {}
    const devices = legacy.map((d) => ({ ...d, generation: 1, retired: [] }));
    registry = { version: 1, access: registry.access ?? [], devices, challenges: [], grants: {}, retired: [] };
  }
  registry.onboarding = { ...registry.onboarding, [digest]: slot };
  writeFileSync(file, JSON.stringify(registry));
}
