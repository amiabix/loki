import { addOnboardingGrant, listOnboardingGrants, pruneOnboardingGrants, registerOnboardingGrant } from "../src/lib/members.ts";

const usage = "usage: LOKI_REGISTRY=/path/to/registry.json node scripts/grants.ts add [--slot N] [--origin https://wallet.example] | register <sha256 digest> [--slot N] | list | prune";
const [command, ...rest] = process.argv.slice(2);
if (!process.env.LOKI_REGISTRY || !command) throw new Error(usage);

const option = (name: string) => {
  const at = rest.indexOf(name);
  return at === -1 ? undefined : rest[at + 1];
};

if (command === "add") {
  const slot = option("--slot");
  const origin = option("--origin");
  const grant = await addOnboardingGrant(slot === undefined ? undefined : Number(slot));
  console.log(origin ? `${new URL(origin).origin}/#onboarding=${grant}` : grant);
} else if (command === "register") {
  const slot = option("--slot");
  await registerOnboardingGrant(rest[0] ?? "", slot === undefined ? undefined : Number(slot));
} else if (command === "list") {
  for (const row of await listOnboardingGrants()) {
    console.log(`${row.digest.slice(0, 12)}…  slot ${row.slot ?? "auto"}  ${row.state}`);
  }
} else if (command === "prune") {
  console.log(`removed ${await pruneOnboardingGrants()} used grant(s)`);
} else {
  throw new Error(usage);
}
