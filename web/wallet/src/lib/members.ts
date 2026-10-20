import { readFileSync } from "node:fs";
import { join } from "node:path";

export type Member = { id: number; port: number; token: string };

/**
 * The three running member_app processes, written by poc/wallet/launch_testnet_demo.py.
 * Read fresh each call so restarting the stack (new tokens) is picked up without a rebuild.
 * Server-only — the token never reaches the browser; the proxy route injects it.
 */
export function members(): Member[] {
  const file = join(process.cwd(), ".members.json");
  return JSON.parse(readFileSync(file, "utf8")).members as Member[];
}

export function member(id: number): Member {
  const found = members().find((m) => m.id === id);
  if (!found) throw new Error(`no member ${id} in .members.json`);
  return found;
}
