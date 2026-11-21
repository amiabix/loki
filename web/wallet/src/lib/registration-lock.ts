import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { setTimeout as delay } from "node:timers/promises";

export async function registrationLock(file: string): Promise<() => void> {
  mkdirSync(dirname(file), { recursive: true, mode: 0o700 });
  // Only the SQLite write lock is used here. The JSON snapshot remains authoritative.
  const lock = new DatabaseSync(`${file}.mutex.sqlite`);
  const deadline = Date.now() + 5000;
  try {
    for (;;) {
      try {
        lock.exec("BEGIN IMMEDIATE");
        return () => lock.close(); // Ends the transaction; never unlink the lock database.
      } catch (error) {
        if ((Number((error as { errcode?: number }).errcode) & 0xff) !== 5) throw error; // SQLITE_BUSY
        if (Date.now() >= deadline) throw new Error("registration is busy");
        await delay(25);
      }
    }
  } catch (error) {
    lock.close();
    throw error;
  }
}
