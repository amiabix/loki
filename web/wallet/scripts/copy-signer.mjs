// Stage the in-browser signer assets into public/signer/ so Next serves them, keeping the
// worker's relative `./pkg/...` + snippet imports intact. Runs on predev/prebuild.
//
// Build the wasm first (both pkgs are gitignored, so this script only copies):
//   cd poc/loki-signer-wasm && RUSTFLAGS='--cfg getrandom_backend="wasm_js"' wasm-pack build --dev --target web
//   cd poc/wasm-transport   && wasm-pack build --target web
//
// Served layout (what src/lib/signer.ts points at):
//   /signer/signer-worker.js          imports ./pkg/loki_signer_wasm.js + ./pkg/snippets/.../opfs_fs.js
//   /signer/pkg/                       loki-signer-wasm wasm-pack output
//   /signer/wasm-transport/pkg/        loki-wasm-transport wasm-pack output (transportUrl)
//
// If the signer pkg has not been built, this skips (exit 0) and the app runs with the mock —
// so a plain `next build` stays green without the Rust toolchain.
import { cpSync, existsSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const poc = resolve(here, "../../../poc");
const out = resolve(here, "../public/signer");

const signerPkg = resolve(poc, "loki-signer-wasm/pkg");
if (!existsSync(signerPkg)) {
  console.warn(
    "[copy-signer] poc/loki-signer-wasm/pkg not found — serving the mock signer.\n" +
    "  Build it: cd poc/loki-signer-wasm && RUSTFLAGS='--cfg getrandom_backend=\"wasm_js\"' wasm-pack build --dev --target web",
  );
  process.exit(0);
}

rmSync(out, { recursive: true, force: true });
cpSync(signerPkg, resolve(out, "pkg"), { recursive: true });
for (const f of ["signer-worker.js", "signer-client.js"]) {
  cpSync(resolve(poc, "loki-signer-wasm", f), resolve(out, f));
}

const transportPkg = resolve(poc, "wasm-transport/pkg");
if (existsSync(transportPkg)) {
  cpSync(transportPkg, resolve(out, "wasm-transport/pkg"), { recursive: true });
} else {
  console.warn(
    "[copy-signer] poc/wasm-transport/pkg not found — DKG/payment (frostd) will not load.\n" +
    "  Build it: cd poc/wasm-transport && wasm-pack build --target web",
  );
}

console.log(`[copy-signer] staged signer assets into ${out}`);
