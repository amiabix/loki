// Thin main-thread client for the in-browser signer worker (signer-worker.js).
//
// The worker owns the wasm core + the OPFS pre-open protocol; this is just a promise-based
// postMessage bridge the UI imports. One worker per page; a page reload makes a fresh one
// (and the persisted OPFS state is what proves the signer survived the reload).
//
// Methods mirror the lifecycle half of W5's `SignerModule`:
//   hasSigner() → bool
//   createSigner({ method, name, passphrase?, prfSecret? }) → { id, name }
//   unlock({ method, passphrase?, prfSecret? }) → { id, name }
//   lock() → void
// `request()` (DKG/payment) is NOT here — Phase B/C.

export function createSignerClient(workerUrl = "./signer-worker.js") {
  const worker = new Worker(workerUrl, { type: "module" });
  const pending = new Map();
  let seq = 0;
  const loaded = new Promise((resolve) => {
    const onload = (e) => {
      if (e.data && e.data.cmd === "loaded") {
        worker.removeEventListener("message", onload);
        resolve();
      }
    };
    worker.addEventListener("message", onload);
  });
  worker.addEventListener("message", (e) => {
    const { id, ok, result, error } = e.data || {};
    const p = pending.get(id);
    if (!p) return;
    pending.delete(id);
    ok ? p.resolve(result) : p.reject(new Error(error));
  });

  async function call(msg) {
    await loaded;
    const id = ++seq;
    return new Promise((resolve, reject) => {
      pending.set(id, { resolve, reject });
      worker.postMessage({ id, ...msg });
    });
  }

  return {
    hasSigner: () => call({ op: "has" }),
    createSigner: ({ method, name, passphrase, prfSecret }) =>
      call({ op: "create", method, name, passphrase, prfSecret }),
    unlock: ({ method, passphrase, prfSecret }) =>
      call({ op: "unlock", method, passphrase, prfSecret }),
    lock: () => call({ op: "lock" }),
    terminate: () => worker.terminate(),
  };
}
