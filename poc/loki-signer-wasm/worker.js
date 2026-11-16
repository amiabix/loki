// Module Web Worker: OPFS sync-handle store seam proof. OPFS createSyncAccessHandle is
// only available inside a Worker, which is exactly where the in-browser signer will run.
import init, { opfsSelftest } from "./pkg/loki_signer_wasm.js";
import {
  opfsPreopenWrite,
  opfsPreopenRead,
  opfsRead,
} from "./pkg/snippets/loki-signer-core-8724841f4db15c9f/js/opfs_fs.js";

const PATH = "loki/selftest.bin";
const ready = init();

self.onmessage = async (e) => {
  try {
    await ready;
    const { cmd, text } = e.data;
    if (cmd === "roundtrip") {
      await opfsPreopenWrite(PATH); // acquire the sync handle (async) before the sync write
      const out = opfsSelftest(PATH, new TextEncoder().encode(text)); // Rust: sync write+read
      self.postMessage({ ok: true, read: new TextDecoder().decode(out) });
    } else if (cmd === "readback") {
      await opfsPreopenRead(PATH);
      const b = opfsRead(PATH);
      self.postMessage({ ok: true, read: b ? new TextDecoder().decode(b) : null });
    }
  } catch (err) {
    self.postMessage({ ok: false, error: String((err && err.message) || err) });
  }
};
self.postMessage({ cmd: "loaded" });
