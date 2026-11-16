// OPFS synchronous-store backend for loki-signer-core's `signer/durable.rs` (wasm arm).
//
// WHY THIS SHAPE. The audited signing/DKG core is synchronous and must stay synchronous:
// a nonce commitment may only be emitted AFTER the sealed nonce is flushed to disk
// (nonce.rs persist-before-emit). OPFS `FileSystemSyncAccessHandle` is the only browser
// storage whose read/write/flush are synchronous — but ONLY inside a Web Worker, and the
// handle must first be acquired asynchronously (`createSyncAccessHandle()` returns a
// Promise). So the split is:
//
//   async, worker message loop:  opfsPreopenWrite / opfsPreopenRead  (acquire + cache)
//   sync, called from wasm:      opfsRead / opfsWrite / opfsRemove / opfsExists / opfsMkdir
//
// CONTRACT the worker must honor: before invoking a synchronous core op, pre-open every
// path that op will touch — preopenWrite for files it may create/replace, preopenRead for
// files it may read. The signer's file set is small and the worker knows it:
//   <dir>/signer.meta, <dir>/{identity,roster,setup,share}.sealed,
//   <dir>/nonces/<id>.nonce, <dir>/nonces/<id>.burn
// A sync call on a path that was not pre-opened throws (loud misuse) for writes, and reads
// as "absent" for reads/exists.
//
// This module is browser-only (OPFS + Worker). It is imported by wasm-bindgen as a local
// snippet (`#[wasm_bindgen(module = "/js/opfs_fs.js")]`). It has no node/test double here;
// the OPFS paths need a real browser Worker to exercise.

// path (string) -> { h: FileSystemSyncAccessHandle | null, size: number }
// h === null means "pre-opened read of a file that does not exist" (cached absence).
const handles = new Map();
let rootDir = null;

function normalize(path) {
  // Rust passes `<dir>/<name>`; OPFS is rooted, so drop a leading slash and collapse "".
  return path.replace(/^\/+/, "").split("/").filter((s) => s.length > 0);
}

async function getDir(segments, create) {
  if (!rootDir) rootDir = await navigator.storage.getDirectory();
  let dir = rootDir;
  for (const seg of segments) {
    dir = await dir.getDirectoryHandle(seg, { create });
  }
  return dir;
}

// Acquire a writable sync handle for `path`, creating parent dirs and the file. Call this
// (and await it) before any synchronous opfsWrite/opfsRemove on `path`.
export async function opfsPreopenWrite(path) {
  if (handles.get(path)?.h) return;
  const segs = normalize(path);
  const name = segs.pop();
  const dir = await getDir(segs, true);
  const fh = await dir.getFileHandle(name, { create: true });
  const h = await fh.createSyncAccessHandle();
  handles.set(path, { h, size: h.getSize() });
}

// Acquire a read handle for `path` if it exists; cache absence otherwise. Call this (and
// await it) before any synchronous opfsRead/opfsExists on `path`.
export async function opfsPreopenRead(path) {
  if (handles.has(path)) return;
  const segs = normalize(path);
  const name = segs.pop();
  try {
    const dir = await getDir(segs, false);
    const fh = await dir.getFileHandle(name, { create: false });
    const h = await fh.createSyncAccessHandle();
    handles.set(path, { h, size: h.getSize() });
  } catch (e) {
    if (e && (e.name === "NotFoundError" || e.name === "NotFound")) {
      handles.set(path, { h: null, size: 0 });
    } else {
      throw e;
    }
  }
}

function entry(path) {
  const e = handles.get(path);
  if (e === undefined) return { h: null, size: 0 }; // not pre-opened => treat as absent for reads
  return e;
}

// --- synchronous, called from wasm (signer/durable.rs) ---

// Uint8Array | null (null == absent / empty).
export function opfsRead(path) {
  const e = entry(path);
  if (!e.h) return null;
  const size = e.h.getSize();
  if (size === 0) return null;
  const buf = new Uint8Array(size);
  e.h.read(buf, { at: 0 });
  return buf;
}

export function opfsExists(path) {
  const e = entry(path);
  return !!e.h && e.h.getSize() > 0;
}

// create_new == true  => write-once: keep existing non-empty content (durable.rs write_durable).
// create_new == false => atomic-ish replace: truncate + write + flush (durable.rs replace_durable).
export function opfsWrite(path, bytes, create_new) {
  const e = handles.get(path);
  if (!e || !e.h) {
    throw new Error(`opfs: path not pre-opened for write: ${path}`);
  }
  if (create_new && e.h.getSize() > 0) return; // write-once record already present
  e.h.truncate(0);
  e.h.write(bytes, { at: 0 });
  e.h.flush(); // durability barrier: returns only once the bytes are persisted
  e.size = bytes.length;
}

// Logical remove: truncate to zero (exists() -> false) and flush. OPFS has no sync
// removeEntry; a zero-length file is indistinguishable from absent to this layer.
// ponytail: leaves a 0-byte file behind; the worker can dir.removeEntry() it out of band.
export function opfsRemove(path) {
  const e = handles.get(path);
  if (!e || !e.h) return; // already absent
  e.h.truncate(0);
  e.h.flush();
  e.size = 0;
}

// Directories are created lazily by opfsPreopenWrite's parent walk, so this is a no-op;
// it exists so durable.rs create_dir_private/create_dir_all stay synchronous.
export function opfsMkdir(_path) {}

// Test / teardown helpers (not called from wasm).
export function opfsClose(path) {
  const e = handles.get(path);
  if (e?.h) e.h.close();
  handles.delete(path);
}
export function opfsCloseAll() {
  for (const e of handles.values()) if (e.h) e.h.close();
  handles.clear();
}
