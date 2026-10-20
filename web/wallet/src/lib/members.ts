import { readFileSync } from "node:fs";
import { join } from "node:path";

export type Member = { id: number; port: number; token: string };

/**
 * The access map written by the deploy launcher: an unguessable capability slug per member,
 * mapping to that member_app's local port and `X-Loki-Token`. Read fresh each call so
 * restarting the stack (new slugs/tokens) is picked up without a rebuild. Server-only — neither
 * the token nor the map ever reaches the browser; the proxy injects the token.
 */
type Access = Record<string, Member>;

function accessMap(): Access {
  const file = join(process.cwd(), ".access.json");
  return JSON.parse(readFileSync(file, "utf8")).access as Access;
}

/** Resolve a tester's capability slug to their single member, or throw if unknown. */
export function memberBySlug(slug: string): Member {
  const found = slug && accessMap()[slug];
  if (!found) throw new Error("unknown or missing access link");
  return found;
}
