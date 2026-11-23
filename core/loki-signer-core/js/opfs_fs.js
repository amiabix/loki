const handles = new Map();
let rootDir = null;

function normalize(path) {
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

export async function opfsPreopenWrite(path) {
  if (handles.get(path)?.h) return;
  const segs = normalize(path);
  const name = segs.pop();
  const dir = await getDir(segs, true);
  const fh = await dir.getFileHandle(name, { create: true });
  const h = await fh.createSyncAccessHandle();
  handles.set(path, { h, size: h.getSize() });
}

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
  if (e === undefined) return { h: null, size: 0 };
  return e;
}

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

export function opfsWrite(path, bytes, create_new) {
  const e = handles.get(path);
  if (!e || !e.h) {
    throw new Error(`opfs: path not pre-opened for write: ${path}`);
  }
  if (create_new && e.h.getSize() > 0) return;
  e.h.truncate(0);
  e.h.write(bytes, { at: 0 });
  e.h.flush();
  e.size = bytes.length;
}

export function opfsRemove(path) {
  const e = handles.get(path);
  if (!e || !e.h) return;
  e.h.truncate(0);
  e.h.flush();
  e.size = 0;
}

export function opfsMkdir(_path) {}

export function opfsClose(path) {
  const e = handles.get(path);
  if (e?.h) e.h.close();
  handles.delete(path);
}
export function opfsCloseAll() {
  for (const e of handles.values()) if (e.h) e.h.close();
  handles.clear();
}
