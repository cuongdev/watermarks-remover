/**
 * Native JUMBF / C2PA manifest detector (pure JS, no dependency).
 *
 * Replaces the `c2patool` inspect pass: instead of shelling out to c2patool
 * to answer "is there a real C2PA manifest here", this walks the JUMBF box
 * tree (ISO/IEC 19566-5) inside a PNG `caBX` chunk or reassembled JPEG APP11
 * segments and looks for a C2PA manifest store box. That is a structural
 * signal (a parsed provenance container), stronger than the byte scan for
 * the string "c2pa", and it works in the browser and on the server alike.
 *
 * Scope: detection, not cryptographic validation. It confirms a manifest
 * store is present and surfaces the JUMBF labels; it does not verify the
 * claim signature (that needs the full C2PA trust stack).
 */

const PNG_SIG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const JPEG_SOI = [0xff, 0xd8];

/** C2PA manifest store label and UUID (ISO 19566 / C2PA spec). */
const C2PA_LABELS = new Set(["c2pa", "c2ma"]);
// UUID for a C2PA manifest store content type box.
const C2PA_UUID = [
  0x63, 0x32, 0x70, 0x61, 0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71,
];

function u32(data: Uint8Array, pos: number): number {
  return (
    ((data[pos]! << 24) | (data[pos + 1]! << 16) | (data[pos + 2]! << 8) | data[pos + 3]!) >>> 0
  );
}

function startsWith(data: Uint8Array, sig: number[]): boolean {
  if (data.length < sig.length) return false;
  for (let i = 0; i < sig.length; i += 1) if (data[i] !== sig[i]) return false;
  return true;
}

export interface C2paDetection {
  hasManifest: boolean;
  /** JUMBF labels found while walking the box tree (for reporting). */
  labels: string[];
}

/**
 * Walk a JUMBF byte stream and collect box labels, flagging a C2PA manifest
 * store. Box layout: [LBox u32][TBox 4 bytes]. LBox==1 means a 64-bit XLBox
 * follows; LBox==0 means the box runs to the end of the buffer.
 */
function walkJumbf(data: Uint8Array, labels: string[], depth = 0): boolean {
  if (depth > 32) return false; // guard pathological nesting
  let pos = 0;
  let found = false;
  while (pos + 8 <= data.length) {
    let boxLen = u32(data, pos);
    const type = String.fromCharCode(data[pos + 4]!, data[pos + 5]!, data[pos + 6]!, data[pos + 7]!);
    let headerLen = 8;
    if (boxLen === 1) {
      if (pos + 16 > data.length) break;
      // 64-bit length; only the low 32 bits are supported here.
      boxLen = u32(data, pos + 12);
      headerLen = 16;
    } else if (boxLen === 0) {
      boxLen = data.length - pos;
    }
    if (boxLen < headerLen || pos + boxLen > data.length) break;
    const payload = data.subarray(pos + headerLen, pos + boxLen);

    if (type === "jumd") {
      // Description box: 16-byte content-type UUID, 1 toggle byte, then an
      // optional NUL-terminated label.
      if (payload.length >= 17) {
        const uuid = payload.subarray(0, 16);
        let uuidMatch = true;
        for (let i = 0; i < 16; i += 1) if (uuid[i] !== C2PA_UUID[i]) uuidMatch = false;
        let label = "";
        const toggles = payload[16]!;
        if (toggles & 0x03) {
          // label present (requested/present bit); read until NUL
          let i = 17;
          while (i < payload.length && payload[i] !== 0) {
            label += String.fromCharCode(payload[i]!);
            i += 1;
          }
        }
        if (label) labels.push(label);
        if (uuidMatch || C2PA_LABELS.has(label.toLowerCase())) found = true;
      }
    } else if (type === "jumb") {
      // Superbox: recurse into nested boxes.
      if (walkJumbf(payload, labels, depth + 1)) found = true;
    }

    pos += boxLen;
  }
  return found;
}

/** Extract the JUMBF payload from a PNG caBX chunk, if present. */
function pngJumbf(data: Uint8Array): Uint8Array | null {
  if (!startsWith(data, PNG_SIG)) return null;
  let pos = 8;
  while (pos + 8 <= data.length) {
    const length = u32(data, pos);
    const type = String.fromCharCode(data[pos + 4]!, data[pos + 5]!, data[pos + 6]!, data[pos + 7]!);
    const start = pos + 8;
    const end = start + length;
    if (end + 4 > data.length) break;
    if (type === "caBX") return data.subarray(start, end);
    if (type === "IEND") break;
    pos = end + 4;
  }
  return null;
}

/**
 * Reassemble the JUMBF stream from JPEG APP11 segments. Each APP11 payload is
 * CI(2 "JP") | En(2 box instance) | Z(4 packet seq) | JUMBF data. Segments
 * are grouped by box instance and ordered by packet sequence, then their data
 * portions are concatenated (a manifest often spans several APP11 markers).
 */
function jpegJumbf(data: Uint8Array): Uint8Array | null {
  if (!startsWith(data, JPEG_SOI)) return null;
  const groups = new Map<number, Array<{ z: number; chunk: Uint8Array }>>();
  let i = 2;
  const n = data.length;
  while (i + 4 <= n) {
    if (data[i] !== 0xff) {
      i += 1;
      continue;
    }
    while (i < n && data[i] === 0xff) i += 1;
    if (i >= n) break;
    const marker = data[i]!;
    i += 1;
    if (marker === 0xd8 || marker === 0xd9) continue;
    if (marker === 0xda) break; // SOS
    if (marker >= 0xd0 && marker <= 0xd7) continue;
    if (i + 2 > n) break;
    const seglen = (data[i]! << 8) | data[i + 1]!;
    if (seglen < 2 || i + seglen > n) break;
    const payload = data.subarray(i + 2, i + seglen);
    i += seglen;
    if (marker === 0xeb && payload.length >= 8 && payload[0] === 0x4a && payload[1] === 0x50) {
      const en = (payload[2]! << 8) | payload[3]!;
      const z = u32(payload, 4);
      const chunk = payload.subarray(8);
      if (!groups.has(en)) groups.set(en, []);
      groups.get(en)!.push({ z, chunk });
    }
  }
  if (!groups.size) return null;
  const parts: Uint8Array[] = [];
  for (const segs of groups.values()) {
    segs.sort((a, b) => a.z - b.z);
    for (const s of segs) parts.push(s.chunk);
  }
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

/**
 * Detect a C2PA manifest store in PNG or JPEG bytes by parsing the JUMBF box
 * tree. Returns hasManifest plus the JUMBF labels seen. This is the library's
 * native replacement for the optional `c2patool` inspect pass.
 */
export function detectC2paManifest(data: Uint8Array): C2paDetection {
  const labels: string[] = [];
  let jumbf: Uint8Array | null = null;
  if (startsWith(data, PNG_SIG)) jumbf = pngJumbf(data);
  else if (startsWith(data, JPEG_SOI)) jumbf = jpegJumbf(data);
  if (!jumbf) return { hasManifest: false, labels };
  const hasManifest = walkJumbf(jumbf, labels);
  return { hasManifest, labels };
}
