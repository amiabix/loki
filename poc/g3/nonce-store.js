// G3 nonce store. Runs in the page; IndexedDB is the only durable local state.
//
// Scope: this prototype is about the STORE, not about FROST. A "share" here is the scalar
// half of a Schnorr signature, s = k + e*x mod q, over the Pallas scalar field, and the
// commitment is stood in by a hash of k rather than a group element. That is deliberate
// and it is enough, because reusing k really is catastrophic: two shares over one k with
// different e give x = (s1 - s2) / (e1 - e2), and `extractOnReuse` below computes it.
// Nothing here is a signature scheme and none of it should be lifted into the wallet.

const Q = 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001n;
const DB = 'loki-g3';
const VER = 1;

const hex = (b) => [...b].map((x) => x.toString(16).padStart(2, '0')).join('');
const bytes = (h) => Uint8Array.from(h.match(/../g).map((x) => parseInt(x, 16)));
const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

function mod(a) { return ((a % Q) + Q) % Q; }

async function sha256(u8) { return new Uint8Array(await crypto.subtle.digest('SHA-256', u8)); }
async function h2s(...parts) {
  return BigInt('0x' + hex(await sha256(new TextEncoder().encode(parts.join('|'))))) % Q;
}
function inv(a) {                       // Fermat: a^(q-2) mod q
  let r = 1n, b = mod(a), e = Q - 2n;
  while (e > 0n) { if (e & 1n) r = (r * b) % Q; b = (b * b) % Q; e >>= 1n; }
  return r;
}

// ── durability ─────────────────────────────────────────────────────────────
//
// STRICT DURABILITY IS REQUESTED on every write. `durability: 'strict'` asks the browser
// to flush to the operating system before reporting `complete`, rather than the default
// `'relaxed'`, which may report success while the write is still buffered.
//
// What happens when an engine does not support it is a decision, not a detail. This store
// FAILS CLOSED: `spend` refuses with `durability_unsupported` and releases no share. An
// unsupported platform is therefore recorded as inconclusive, never as a pass, because
// every crash drill's conclusion rests on a committed transaction actually being on disk.
//
// What a page cannot do: VERIFY the flush. The request is an instruction to the browser,
// not evidence about the disk, so `granted` below is the browser's own word for it.

let DURABILITY = {
  requested: 'strict',
  optionsAccepted: null,   // did the engine accept the options bag at all
  reflected: null,         // what `transaction.durability` reads back
  attrPresent: null,       // is there a `durability` getter to read at all
  supported: null,         // accepted AND reflected as 'strict'
  policy: 'fail_closed',
  simulated: false,
};

/// Set by the drill to simulate an engine that rejects the options bag. A SIMULATION: it
/// exercises this store's fail-closed path and says nothing about any real browser.
let FORCE_UNSUPPORTED = false;
export function simulateNoStrictDurability(on) {
  FORCE_UNSUPPORTED = !!on;
  DURABILITY = {
    requested: 'strict', optionsAccepted: null, reflected: null, attrPresent: null,
    supported: null, policy: 'fail_closed', simulated: !!on,
  };
}

// ── storage ────────────────────────────────────────────────────────────────

function open() {
  return new Promise((res, rej) => {
    const r = indexedDB.open(DB, VER);
    r.onupgradeneeded = () => {
      const db = r.result;
      db.createObjectStore('meta', { keyPath: 'k' });
      db.createObjectStore('nonces', { keyPath: 'id' });
      db.createObjectStore('wal', { keyPath: 'rid' });
      db.createObjectStore('shares', { keyPath: 'rid' });
    };
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
}

/// Every durable step is one transaction, awaited to `complete`, so a crash always lands
/// on a transaction boundary.
function tx(db, stores, mode, fn) {
  return new Promise((res, rej) => {
    let t;
    if (mode === 'readwrite') {
      // After a successful probe, falling back could release a share after a relaxed WAL write.
      const wasSupported = DURABILITY.supported;
      DURABILITY.attrPresent = typeof IDBTransaction !== 'undefined'
        && 'durability' in IDBTransaction.prototype;
      try {
        if (FORCE_UNSUPPORTED) throw new TypeError('simulated: options bag rejected');
        t = db.transaction(stores, mode, { durability: 'strict' });
        DURABILITY.optionsAccepted = true;
        DURABILITY.reflected = DURABILITY.attrPresent ? (t.durability ?? null) : 'no-attribute';
        // An engine that ACCEPTS the options bag and then does not reflect `strict` has
        // silently ignored the request, which is the most dangerous of the three outcomes:
        // it looks like success. It is treated as unsupported.
        DURABILITY.supported = DURABILITY.reflected === 'strict';
      } catch (e) {
        DURABILITY.optionsAccepted = false;
        DURABILITY.reflected = `threw: ${e.name}`;
        DURABILITY.supported = false;
        if (wasSupported) return rej(e);
        t = db.transaction(stores, mode);
      }
      if (wasSupported && !DURABILITY.supported) {
        t.abort();
        return rej(new Error('strict durability lost'));
      }
    } else {
      t = db.transaction(stores, mode);
    }
    let out;
    t.oncomplete = () => res(out);
    t.onerror = () => rej(t.error || new Error('tx error'));
    t.onabort = () => rej(t.error || new Error('aborted'));
    out = fn(t);
  });
}

const get = (t, s, k) => new Promise((res, rej) => {
  const r = t.objectStore(s).get(k);
  r.onsuccess = () => res(r.result);
  r.onerror = () => rej(r.error);
});
const all = (t, s) => new Promise((res, rej) => {
  const r = t.objectStore(s).getAll();
  r.onsuccess = () => res(r.result);
  r.onerror = () => rej(r.error);
});

// ── receipts ───────────────────────────────────────────────────────────────

/// Rebuild the signed bytes in the relay's key order. Both sides construct the object
/// identically; that is the canonicalization, adequate for a prototype and not for a
/// wallet.
const receiptBytes = (r) => new TextEncoder().encode(JSON.stringify({
  relay_id: r.relay_id,
  epoch_id: r.epoch_id,
  commitment_id: r.commitment_id,
  rid: r.rid,
  package_hash: r.package_hash,
  seq: r.seq,
}));

async function importPinned(pinned) {
  const keys = new Map();
  for (const { relay_id, spki } of pinned) {
    keys.set(relay_id, await crypto.subtle.importKey(
      'spki', b64(spki), { name: 'Ed25519' }, false, ['verify'],
    ));
  }
  return keys;
}

// ── the store ──────────────────────────────────────────────────────────────

export class NonceStore {
  /// `relays` is a list of { relay_id, base }: three SIMULATED operators in these drills.
  /// `pinnedKeys` is built from the keys pinned at vault setup; a relay whose id is not
  /// pinned is never trusted, no matter what it signs. `requiredReceipts` is the
  /// threshold, 2 of 3 in these drills.
  constructor(db, relays, pinnedKeys, requiredReceipts) {
    this.db = db; this.relays = relays; this.keys = pinnedKeys; this.log = [];
    this.required = requiredReceipts ?? 2;
  }

  static async create(relays, pinned, requiredReceipts) {
    const db = await open();
    const s = new NonceStore(db, relays, await importPinned(pinned), requiredReceipts);
    // Probe durability before anything depends on it. An empty readwrite transaction is
    // enough to learn whether the engine accepts the options bag.
    await tx(db, ['meta'], 'readwrite', () => {});
    return s;
  }

  note(event, detail) { const e = { event, ...detail }; this.log.push(e); return e; }

  durabilityReport() { return { ...DURABILITY }; }

  epoch() { return tx(this.db, ['meta'], 'readonly', (t) => get(t, 'meta', 'epoch')); }
  states() {
    return tx(this.db, ['nonces'], 'readonly', (t) => all(t, 'nonces'))
      .then((r) => r.map(({ id, state, secret }) => ({ id, state, has_secret: !!secret })));
  }
  sharesOut() { return tx(this.db, ['shares'], 'readonly', (t) => all(t, 'shares')); }
  walOut() { return tx(this.db, ['wal'], 'readonly', (t) => all(t, 'wal')); }

  // ── relay calls ──────────────────────────────────────────────────────────

  async call(relay, op, body) {
    const r = await fetch(`${relay.base}/${op}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(body),
    });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) { const e = new Error(j.error || `relay ${op}: ${r.status}`); e.payload = j; throw e; }
    return j;
  }

  /// Ask one relay for a signed write-ahead receipt, and accept it only if it is
  /// genuinely a receipt for THIS record.
  ///
  /// Four checks, each with its own drill:
  ///   1. the claimed relay_id is pinned        -> gate-relay-not-pinned
  ///   2. the signature verifies under THAT key -> forged-signature-rejected,
  ///                                               impersonated-receipt-counts-once
  ///   3. commitment, epoch and package digest all equal what was asked for
  ///                                            -> receipt-binds-commitment / -epoch
  ///                                               / -package
  ///   4. `rid` matches, so a receipt cannot be moved between records
  async receiptFrom(relay, want) {
    const j = await this.call(relay, 'receipt', want);
    const claimed = j.receipt?.relay_id;
    const key = this.keys.get(claimed);
    if (!key) throw new Error(`receipt from an unpinned relay: ${claimed}`);

    const ok = await crypto.subtle.verify(
      { name: 'Ed25519' }, key, b64(j.sig), receiptBytes(j.receipt),
    );
    if (!ok) throw new Error(`bad receipt signature for claimed id ${claimed}`);

    // The relay must have signed OUR record. A signature over something else, however
    // valid, is not an acknowledgement of this spend.
    for (const f of ['epoch_id', 'commitment_id', 'rid', 'package_hash']) {
      if (j.receipt[f] !== want[f]) {
        throw new Error(`receipt ${f} does not bind this record: got `
          + `${String(j.receipt[f]).slice(0, 20)}, wanted ${String(want[f]).slice(0, 20)}`);
      }
    }
    return { relay_id: claimed, seq: j.receipt.seq, sig: j.sig };
  }

  /// Collect receipts from `this.required` DISTINCT pinned relays.
  ///
  /// Distinctness is keyed on the relay id the signature actually verified under, so two
  /// receipts can never count as two unless two different pinned keys signed. The same
  /// relay listed twice, a relay impersonating another, and a forged signature all
  /// collapse to fewer than the threshold.
  ///
  /// Every relay is asked, not just the first `required`: more acknowledgers means more
  /// chances that one of them is honest and reachable later, which is the entire basis of
  /// the restore check.
  async collectReceipts(want) {
    const settled = await Promise.allSettled(this.relays.map((r) => this.receiptFrom(r, want)));
    const good = [], errors = [];
    for (const s of settled) {
      if (s.status === 'fulfilled') good.push(s.value);
      else errors.push(s.reason.message);
    }
    const distinct = new Map(good.map((g) => [g.relay_id, g]));
    if (distinct.size < this.required) {
      const e = new Error('receipts_required');
      e.detail = { need: this.required, got: [...distinct.keys()], errors };
      throw e;
    }
    return [...distinct.values()];
  }

  // ── epoch ────────────────────────────────────────────────────────────────

  async newEpoch(reason) {
    const epoch_id = hex(crypto.getRandomValues(new Uint8Array(8)));
    await tx(this.db, ['meta', 'nonces'], 'readwrite', (t) => {
      t.objectStore('meta').put({ k: 'epoch', epoch_id, reason });
      const c = t.objectStore('nonces').openCursor();
      c.onsuccess = () => {
        const cur = c.result;
        if (!cur) return;
        // Retire AND destroy the secret. Retiring alone would leave the dangerous bytes
        // on disk for a later bug to find.
        cur.update({ ...cur.value, state: 'Retired', secret: null, retired_reason: reason });
        cur.continue();
      };
    });
    return this.note('new_epoch', { epoch_id, reason });
  }

  async generate(n) {
    const { epoch_id } = await this.epoch();
    const ids = [];
    await tx(this.db, ['nonces'], 'readwrite', (t) => {
      for (let i = 0; i < n; i++) {
        const id = `${epoch_id}-${i}`;
        ids.push(id);
        t.objectStore('nonces').put({
          id, epoch_id, state: 'Generated',
          secret: hex(crypto.getRandomValues(new Uint8Array(32))),
          assigned: null,
        });
      }
    });
    for (const r of this.relays) {
      try { await this.call(r, 'publish', { epoch_id, ids }); } catch { /* advisory */ }
    }
    return this.note('generated', { epoch_id, count: n, ids });
  }

  // ── the spend protocol ───────────────────────────────────────────────────
  //
  //   0. refuse outright if strict durability is unsupported
  //   1. WAL intent, carrying the package digest                 durable, strict
  //   2. signed receipts from `required` distinct pinned relays   network
  //   3. WAL receipted, every receipt persisted                  durable, strict
  //   4. consume: Spent + secret DELETED + phase consumed         ONE strict transaction
  //   5. compute the share in memory
  //   6. save the share: THE SHARE IS RELEASED HERE               durable, strict
  //
  // Receipts come before the secret is touched, so an honest relay can refuse and nothing
  // is lost. The share is released only after the receipts are in hand AND persisted.

  async spend(rid, id, msg, crashAt) {
    // 0. No strict durability, no spend. Every crash drill's conclusion depends on a
    //    committed transaction being on disk, so a platform that cannot promise that must
    //    not be allowed to look like one that can.
    if (DURABILITY.supported === false) {
      return this.note('refused', {
        rid, id, code: 'durability_unsupported', detail: { ...DURABILITY },
      });
    }

    const { epoch_id } = await this.epoch();
    const package_hash = hex(await sha256(new TextEncoder().encode(`${epoch_id}|${id}|${msg}`)));
    const want = { epoch_id, commitment_id: id, rid, package_hash };

    // 1. intent
    await tx(this.db, ['wal'], 'readwrite', (t) => {
      t.objectStore('wal').put({ rid, epoch_id, ids: [id], msg, package_hash, phase: 'intent' });
    });
    if (crashAt === 'after_wal') return this.note('reached', { at: 'after_wal', rid });

    // 2. receipts
    let receipts;
    try {
      receipts = await this.collectReceipts(want);
    } catch (e) {
      return this.note('refused', {
        rid, id,
        code: e.message === 'receipts_required' ? 'receipts_required' : 'receipt_invalid',
        detail: e.detail ?? e.message,
      });
    }
    if (crashAt === 'after_receipts') return this.note('reached', { at: 'after_receipts', rid });

    const acks = receipts.map(({ relay_id, seq, sig }) => ({ relay_id, seq, sig }));
    const walRec = { rid, epoch_id, ids: [id], msg, package_hash, receipts: acks };

    // 3. persist them. A receipt that is not durable is not a receipt: after a crash the
    //    device must be able to show which relays acknowledged this record.
    await tx(this.db, ['wal'], 'readwrite', (t) => {
      t.objectStore('wal').put({ ...walRec, phase: 'receipted' });
    });
    if (crashAt === 'after_receipt_save') {
      return this.note('reached', { at: 'after_receipt_save', rid });
    }

    // 4. consume. The state check sits INSIDE the same readwrite transaction that does
    //    the update. This compare-and-set is the local safety property: two tabs cannot
    //    both observe `Generated` here, because IndexedDB serializes readwrite
    //    transactions over the same store. Web Locks are a convenience on top of it.
    let secret = null;
    try {
      const box = await tx(this.db, ['nonces', 'wal'], 'readwrite', (t) => {
        const ns = t.objectStore('nonces');
        const r = ns.get(id);
        const b = { secret: null };
        r.onsuccess = () => {
          const n = r.result;
          if (!n || n.epoch_id !== epoch_id) { t.abort(); return; }
          if (n.state !== 'Generated' && n.state !== 'Published') { t.abort(); return; }
          b.secret = n.secret;
          ns.put({ ...n, state: 'Spent', secret: null, assigned: rid });
          t.objectStore('wal').put({ ...walRec, phase: 'consumed' });
        };
        return b;
      });
      secret = box.secret;
    } catch {
      return this.note('refused', { rid, id, code: 'nonce_not_available' });
    }
    if (!secret) return this.note('refused', { rid, id, code: 'nonce_not_available' });
    if (crashAt === 'after_consume') return this.note('reached', { at: 'after_consume', rid });

    // 5. compute in memory
    const k = BigInt('0x' + secret) % Q;
    const e = await h2s('challenge', msg);
    const x = await h2s('signing-key', epoch_id);       // stands in for the key share
    const s = mod(k + e * x);
    const commit = hex(await sha256(bytes(secret)));
    if (crashAt === 'before_share_save') {
      return this.note('reached', { at: 'before_share_save', rid });
    }

    // 6. release
    await tx(this.db, ['shares', 'wal'], 'readwrite', (t) => {
      t.objectStore('shares').put({ rid, id, msg, commit, e: e.toString(16), s: s.toString(16) });
      t.objectStore('wal').put({ ...walRec, phase: 'saved' });
    });
    return this.note('share_saved', {
      rid, id, commit: commit.slice(0, 16), receipts: acks.map((a) => a.relay_id),
    });
  }

  spendLocked(rid, id, msg, crashAt) {
    return navigator.locks.request(`nonce:${id}`, () => this.spend(rid, id, msg, crashAt));
  }

  // ── recovery ─────────────────────────────────────────────────────────────

  /// Resolve every WAL record that did not reach `saved`.
  ///
  /// `intent`     no receipts were obtained, so no relay acknowledged this and the secret
  ///              is intact. Resuming would be sound. The policy still RETIRES: it stays
  ///              correct if the ordering is ever changed, and a retired nonce costs one
  ///              slot while a reused one costs the key.
  /// `receipted`  relays acknowledged it and the secret is intact. Retire, same reason.
  ///              The receipts stay on disk as the record of who acknowledged what.
  /// `consumed`   the secret is gone and no share was saved. The slot is lost. There is
  ///              nothing to recover and nothing that could be reused.
  async recover() {
    const open_ = (await this.walOut())
      .filter((w) => ['intent', 'receipted', 'consumed'].includes(w.phase));
    const resolved = [];
    for (const w of open_) {
      const retire = w.phase !== 'consumed';
      await tx(this.db, ['nonces', 'wal'], 'readwrite', (t) => {
        if (retire) {
          const ns = t.objectStore('nonces');
          for (const id of w.ids) {
            const r = ns.get(id);
            r.onsuccess = () => {
              if (r.result) {
                ns.put({
                  ...r.result, state: 'Retired', secret: null,
                  retired_reason: `wal_${w.phase}`,
                });
              }
            };
          }
        }
        t.objectStore('wal').put({ ...w, phase: retire ? 'retired' : 'lost' });
      });
      resolved.push({
        rid: w.rid, from: w.phase,
        action: retire ? 'nonces_retired' : 'slot_lost_no_share',
      });
    }
    return this.note('recovered', { resolved });
  }

  // ── startup, including the restore check ─────────────────────────────────

  /// Which commitments this device can account for.
  ///
  /// A relay only ever acknowledges a record the device wrote an intent for, so EVERY WAL
  /// record counts, `intent` included. Leaving `intent` out made a crash in the window
  /// between obtaining receipts and persisting them look exactly like a rollback, which
  /// burned a healthy epoch; that false positive was measured, and this is the fix.
  async accountedFor() {
    const ids = new Set();
    for (const w of await this.walOut()) for (const id of w.ids) ids.add(id);
    for (const n of await tx(this.db, ['nonces'], 'readonly', (t) => all(t, 'nonces'))) {
      if (n.state === 'Spent' || n.state === 'Retired') ids.add(n.id);
    }
    return ids;
  }

  /// Ask every relay which commitments it has acknowledged, and look for one the device
  /// cannot account for. Comparing SETS rather than counts matters: a count can be
  /// inflated by the device itself, whereas a named commitment the device has no record
  /// of is positive evidence that local state was rolled back.
  ///
  /// The detection condition is precise, and the restore drills test exactly it: **at
  /// least one relay that acknowledged the original record must be honest and reachable
  /// now.** A relay that is honest but never acknowledged has nothing to report; a relay
  /// that acknowledged but lies reports nothing; a relay that acknowledged and is honest
  /// but unreachable cannot be asked.
  async startup() {
    const ep = await this.epoch();
    if (!ep) {
      await this.newEpoch('first_run');
      return this.note('startup', { decision: 'fresh' });
    }

    const local = await this.accountedFor();
    const answers = [];
    for (const r of this.relays) {
      try { answers.push(await this.call(r, 'acknowledged', { epoch_id: ep.epoch_id })); }
      catch { answers.push({ relay_id: r.relay_id, unreachable: true }); }
    }
    const reachable = answers.filter((a) => !a.unreachable);
    const reported = reachable.map((a) => ({
      relay_id: a.relay_id, acked: (a.acked_ids ?? []).length,
    }));

    const unaccounted = [];
    for (const a of reachable) {
      for (const id of a.acked_ids ?? []) {
        if (!local.has(id)) unaccounted.push({ relay_id: a.relay_id, id });
      }
    }
    if (unaccounted.length) {
      await this.newEpoch('rollback_detected');
      return this.note('startup', {
        decision: 'new_epoch', cause: 'rollback_detected',
        local: local.size, reported, unaccounted: unaccounted.slice(0, 4),
      });
    }

    // Fewer reachable relays than the threshold. The epoch is KEPT rather than burned: a
    // spend needs `required` receipts, so the device cannot spend anyway, and destroying
    // good inventory on a transient outage would be a worse trade.
    if (reachable.length < this.required) {
      await this.recover();
      return this.note('startup', {
        decision: 'degraded', cause: 'insufficient_relays',
        local: local.size, reported,
        unreachable: answers.filter((a) => a.unreachable).map((a) => a.relay_id),
      });
    }

    await this.recover();
    return this.note('startup', { decision: 'continue', local: local.size, reported });
  }
}

/// Given every share ever emitted, find any nonce used twice and recover the key.
///
/// This is the drills' oracle. A drill does not pass because no error was printed; it
/// passes because this returns nothing.
export function extractOnReuse(shares) {
  const seen = new Map();
  const found = [];
  for (const sh of shares) {
    const prev = seen.get(sh.commit);
    if (!prev) { seen.set(sh.commit, sh); continue; }
    const e1 = BigInt('0x' + prev.e), e2 = BigInt('0x' + sh.e);
    if (e1 === e2) continue;                    // the same message twice is not reuse
    const s1 = BigInt('0x' + prev.s), s2 = BigInt('0x' + sh.s);
    found.push({
      commit: sh.commit.slice(0, 16),
      messages: [prev.msg, sh.msg],
      recovered_key: mod((s1 - s2) * inv(e1 - e2)).toString(16),
    });
  }
  return found;
}
