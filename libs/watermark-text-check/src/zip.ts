/**
 * Minimal ZIP reader/writer for DOCX/ODT processing.
 * Replaces Python's zipfile for this library's needs: no encryption, no
 * zip64, store and deflate methods only. Inflate/deflate use the standard
 * DecompressionStream/CompressionStream (browsers, Node 18+, Deno, Bun).
 * Includes the same decompressed size budget as container_meta.py to reject
 * zip bombs before inflation.
 */

import { concatBytes } from "./imageMeta.js";
import { utf8Decode, utf8Encode } from "./markers.js";

export const MAX_ZIP_DECOMPRESSED_BYTES = 128 * 1024 * 1024;

export interface ZipEntry {
  name: string;
  data: Uint8Array;
}

const EOCD_SIG = 0x06054b50;
const CDIR_SIG = 0x02014b50;
const LOCAL_SIG = 0x04034b50;

function u16(view: DataView, pos: number): number {
  return view.getUint16(pos, true);
}

function u32(view: DataView, pos: number): number {
  return view.getUint32(pos, true);
}

async function inflateRaw(data: Uint8Array): Promise<Uint8Array> {
  const ds = new DecompressionStream("deflate-raw");
  const stream = new Blob([data as BlobPart]).stream().pipeThrough(ds);
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function deflateRaw(data: Uint8Array): Promise<Uint8Array | null> {
  if (typeof CompressionStream === "undefined") return null;
  const cs = new CompressionStream("deflate-raw");
  const stream = new Blob([data as BlobPart]).stream().pipeThrough(cs);
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/** Read all entries (files only, directories skipped) from zip bytes. */
export async function readZip(data: Uint8Array): Promise<ZipEntry[]> {
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  // Find end of central directory record, scanning back over the comment.
  let eocd = -1;
  const minPos = Math.max(0, data.length - 65557);
  for (let pos = data.length - 22; pos >= minPos; pos -= 1) {
    if (u32(view, pos) === EOCD_SIG) {
      eocd = pos;
      break;
    }
  }
  if (eocd < 0) throw new Error("not a valid zip (no end of central directory)");
  const count = u16(view, eocd + 10);
  let cdPos = u32(view, eocd + 16);

  const entries: ZipEntry[] = [];
  let budget = 0;
  for (let idx = 0; idx < count; idx += 1) {
    if (cdPos + 46 > data.length || u32(view, cdPos) !== CDIR_SIG) {
      throw new Error("corrupt zip central directory");
    }
    const method = u16(view, cdPos + 10);
    const compSize = u32(view, cdPos + 20);
    const uncompSize = u32(view, cdPos + 24);
    const nameLen = u16(view, cdPos + 28);
    const extraLen = u16(view, cdPos + 30);
    const commentLen = u16(view, cdPos + 32);
    const localOffset = u32(view, cdPos + 42);
    const name = utf8Decode(data.subarray(cdPos + 46, cdPos + 46 + nameLen));
    cdPos += 46 + nameLen + extraLen + commentLen;

    if (name.endsWith("/")) continue; // directory entry

    budget += uncompSize;
    if (budget > MAX_ZIP_DECOMPRESSED_BYTES) {
      throw new Error(
        `zip decompressed size exceeds cap (${MAX_ZIP_DECOMPRESSED_BYTES} bytes); refusing to process`,
      );
    }

    if (localOffset + 30 > data.length || u32(view, localOffset) !== LOCAL_SIG) {
      throw new Error(`corrupt zip local header for ${name}`);
    }
    const lNameLen = u16(view, localOffset + 26);
    const lExtraLen = u16(view, localOffset + 28);
    const dataStart = localOffset + 30 + lNameLen + lExtraLen;
    const raw = data.subarray(dataStart, dataStart + compSize);

    let content: Uint8Array;
    if (method === 0) content = raw.slice();
    else if (method === 8) content = await inflateRaw(raw);
    else throw new Error(`unsupported zip compression method ${method} for ${name}`);
    entries.push({ name, data: content });
  }
  return entries;
}

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

export function crc32(data: Uint8Array): number {
  let c = 0xffffffff;
  for (let i = 0; i < data.length; i += 1) {
    c = CRC_TABLE[(c ^ data[i]!) & 0xff]! ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}

function le16(value: number): Uint8Array {
  return new Uint8Array([value & 0xff, (value >>> 8) & 0xff]);
}

function le32(value: number): Uint8Array {
  return new Uint8Array([
    value & 0xff,
    (value >>> 8) & 0xff,
    (value >>> 16) & 0xff,
    (value >>> 24) & 0xff,
  ]);
}

/**
 * Write entries into a new zip. Deflates when CompressionStream is
 * available, otherwise stores. UTF-8 names (general purpose flag bit 11).
 */
export async function writeZip(entries: ZipEntry[]): Promise<Uint8Array> {
  const localParts: Uint8Array[] = [];
  const centralParts: Uint8Array[] = [];
  let offset = 0;

  for (const entry of entries) {
    const nameBytes = utf8Encode(entry.name);
    const crc = crc32(entry.data);
    let method = 0;
    let payload = entry.data;
    const deflated = await deflateRaw(entry.data);
    if (deflated !== null && deflated.length < entry.data.length) {
      method = 8;
      payload = deflated;
    }

    const localHeader = concatBytes([
      le32(LOCAL_SIG),
      le16(20), // version needed
      le16(0x0800), // flags: UTF-8 names
      le16(method),
      le16(0), // mod time
      le16(0x21), // mod date (1980-01-01)
      le32(crc),
      le32(payload.length),
      le32(entry.data.length),
      le16(nameBytes.length),
      le16(0), // extra len
      nameBytes,
    ]);
    localParts.push(localHeader, payload);

    centralParts.push(
      concatBytes([
        le32(CDIR_SIG),
        le16(20), // version made by
        le16(20), // version needed
        le16(0x0800),
        le16(method),
        le16(0),
        le16(0x21),
        le32(crc),
        le32(payload.length),
        le32(entry.data.length),
        le16(nameBytes.length),
        le16(0), // extra
        le16(0), // comment
        le16(0), // disk start
        le16(0), // internal attrs
        le32(0), // external attrs
        le32(offset),
        nameBytes,
      ]),
    );
    offset += localHeader.length + payload.length;
  }

  const centralDir = concatBytes(centralParts);
  const eocd = concatBytes([
    le32(EOCD_SIG),
    le16(0), // disk
    le16(0), // cd start disk
    le16(entries.length),
    le16(entries.length),
    le32(centralDir.length),
    le32(offset),
    le16(0), // comment len
  ]);
  return concatBytes([...localParts, centralDir, eocd]);
}
