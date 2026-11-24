import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { setTimeout as delay } from "node:timers/promises";

export type RegistrationPool = "newcomer" | "member";

const POOLS: Record<RegistrationPool, { burst: number; refill: number; inFlight: number }> = {
  newcomer: { burst: 64, refill: 0.008, inFlight: 8 },
  member: { burst: 128, refill: 0.016, inFlight: 8 },
};

const shared = globalThis as typeof globalThis & {
  lokiRegistrationBudgets?: Record<RegistrationPool, { tokens: number; updated: number; inFlight: number }>;
};

export async function registrationLock(file: string, pool: RegistrationPool): Promise<() => void> {
  const now = performance.now();
  const budgets = shared.lokiRegistrationBudgets ??= {
    newcomer: { tokens: POOLS.newcomer.burst, updated: now, inFlight: 0 },
    member: { tokens: POOLS.member.burst, updated: now, inFlight: 0 },
  };
  const budget = budgets[pool];
  const limits = POOLS[pool];
  budget.tokens = Math.min(limits.burst, budget.tokens + (now - budget.updated) * limits.refill);
  budget.updated = now;
  if (budget.tokens < 1 || budget.inFlight >= limits.inFlight) throw new Error("registration is busy");
  budget.tokens--;
  budget.inFlight++;
  let lock: DatabaseSync | undefined;
  const unlock = () => {
    try { lock?.close(); } finally { budget.inFlight--; }
  };
  try {
    mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
    lock = new DatabaseSync(`${file}.mutex.sqlite`, { timeout: 0 });
    const deadline = performance.now() + 5000;
    for (;;) {
      try {
        lock.exec("BEGIN IMMEDIATE");
        return unlock;
      } catch (error) {
        if ((Number((error as { errcode?: number }).errcode) & 0xff) !== 5) throw error;
        if (performance.now() >= deadline) throw new Error("registration is busy");
        await delay(25);
      }
    }
  } catch (error) {
    unlock();
    throw error;
  }
}
