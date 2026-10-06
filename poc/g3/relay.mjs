// A SIMULATED relay operator: issues signed write-ahead receipts and reports which
// commitments it has acknowledged.
//
// SIMULATED is the operative word. This is a local Node process on loopback. Three of
// them are three processes on one machine with three keypairs, which is NOT three
// independent operators: they share a kernel, a disk, a clock, a filesystem and whoever
// can run `kill`. Nothing in this prototype measures operator independence, and the
// "at least one honest" assumption the threshold rests on is exactly the thing local
// processes cannot demonstrate.
//
// Modes. `honest` and `lying` are the two operator behaviours; the rest are targeted
// adversaries that exist so the store's receipt validation has positive fixtures instead
// of being merely implemented.
//
//   honest                 refuses a receipt for a commitment it already acknowledged
//                          under a DIFFERENT package; reports its true acknowledgements
//   lying                  signs replays; reports that it has acknowledged nothing
//   forge                  returns a well-formed receipt with a garbage signature
//   impersonate:<relay_id> signs with its own key but claims to be <relay_id>
//   mismatch:commitment    signs a receipt naming a different commitment
//   mismatch:epoch         signs a receipt naming a different epoch
//   mismatch:package       signs a receipt naming a different package digest
//
// An outage is not a mode. It is the absence of this process.

import { createServer } from 'node:http';
import { createHash, createPrivateKey, createPublicKey, randomBytes, sign } from 'node:crypto';

const MODE = process.env.RELAY_MODE || 'honest';
const PORT = Number(process.env.RELAY_PORT);
const ID = process.env.RELAY_ID || `relay-${PORT}`;
const [KIND, ARG] = MODE.split(':');

/// The keypair is DERIVED FROM THE RELAY ID, not generated fresh, so an operator that
/// restarts keeps its identity. That matters for the drills: a restarted relay has to be
/// the same pinned operator with an empty record, otherwise "honest but never
/// acknowledged" would be indistinguishable from "unpinned key", and the drill would pass
/// for the wrong reason. A real operator does not rotate its identity key on restart
/// either. Obviously not how a real operator should hold a key.
const seed = createHash('sha256').update(`loki-g3-simulated-operator|${ID}`).digest();
const privateKey = createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), seed]),
  format: 'der',
  type: 'pkcs8',
});
const SPKI = createPublicKey(privateKey).export({ type: 'spki', format: 'der' }).toString('base64');

// epoch_id -> Map(commitment_id -> { rid, package_hash, seq })
const acked = new Map();
let seq = 0;
const epochOf = (e) => acked.get(e) ?? acked.set(e, new Map()).get(e);

/// The signed bytes. Both sides build the object in this exact key order; that is the
/// canonicalization, which is adequate for a prototype and would not be for a wallet.
const receiptBytes = (r) => Buffer.from(JSON.stringify({
  relay_id: r.relay_id,
  epoch_id: r.epoch_id,
  commitment_id: r.commitment_id,
  rid: r.rid,
  package_hash: r.package_hash,
  seq: r.seq,
}));

const body = (req) => new Promise((res) => {
  let b = ''; req.on('data', (c) => (b += c)); req.on('end', () => res(b ? JSON.parse(b) : {}));
});

const CORS = {
  'access-control-allow-origin': '*',
  'access-control-allow-headers': 'content-type',
  'access-control-allow-methods': 'POST,GET,OPTIONS',
};

createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const json = (code, o) => {
    res.writeHead(code, { 'content-type': 'application/json', ...CORS });
    res.end(JSON.stringify(o));
  };
  if (req.method === 'OPTIONS') { res.writeHead(204, CORS); return res.end(); }
  if (url.pathname === '/pubkey') return json(200, { relay_id: ID, spki: SPKI, mode: MODE });

  const b = await body(req);

  switch (url.pathname) {
    case '/publish':
      return json(200, { ok: true, relay_id: ID });

    case '/receipt': {
      const ep = epochOf(b.epoch_id);
      const prior = ep.get(b.commitment_id);

      // The honest gate. A commitment already acknowledged under a different package is a
      // replay, and an honest operator will not sign the second one. This is what turns a
      // relay from an after-the-fact detector into something that blocks the spend.
      if (prior && prior.package_hash !== b.package_hash && KIND !== 'lying') {
        return json(409, {
          error: 'already_acknowledged', relay_id: ID,
          prior: { rid: prior.rid, package_hash: prior.package_hash, seq: prior.seq },
        });
      }

      const receipt = {
        relay_id: KIND === 'impersonate' ? ARG : ID,
        epoch_id: KIND === 'mismatch' && ARG === 'epoch'
          ? 'not-the-epoch-you-asked-for' : b.epoch_id,
        commitment_id: KIND === 'mismatch' && ARG === 'commitment'
          ? `${b.commitment_id}-but-different` : b.commitment_id,
        rid: b.rid,
        package_hash: KIND === 'mismatch' && ARG === 'package'
          ? randomBytes(32).toString('hex') : b.package_hash,
        seq: prior ? prior.seq : ++seq,
      };
      if (!prior) {
        ep.set(b.commitment_id, { rid: b.rid, package_hash: b.package_hash, seq: receipt.seq });
      }

      const sig = KIND === 'forge'
        ? randomBytes(64).toString('base64')
        : sign(null, receiptBytes(receipt), privateKey).toString('base64');
      return json(200, { receipt, sig });
    }

    case '/acknowledged': {
      const ids = [...epochOf(b.epoch_id).keys()];
      // The device compares SETS, not counts, so a lie has to be a withheld id.
      return json(200, {
        relay_id: ID, mode: MODE,
        acked_ids: KIND === 'lying' ? [] : ids,
        real_acked: ids.length,
      });
    }

    case '/dump':
      return json(200, {
        relay_id: ID, mode: MODE,
        acked: [...acked].map(([e, m]) => [e, [...m.keys()]]),
      });
  }
  res.writeHead(404, CORS); res.end();
}).listen(PORT, () => console.log(`relay ${ID} mode=${MODE} port=${PORT}`));
