/**
 * Detect and strip C2PA / AI related metadata from PNG and JPEG bytes.
 * Port of image_meta.py (stdlib parsers only). External tool integrations
 * (exiftool, c2patool) and the SynthID / CtrlRegen model hooks are Python
 * side subprocess features and are intentionally not part of this
 * isomorphic library; see the repo scripts for those.
 */

import { detectC2paManifest } from "./c2pa.js";
import {
  AI_META_HINTS,
  C2PA_MARKERS,
  bytesToLatin1,
  classifyFindingConfidence,
  containsAny,
  type FindingConfidence,
} from "./markers.js";

export type ImageFormat = "png" | "jpeg" | "unknown";

const PNG_SIG = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
const JPEG_SOI = [0xff, 0xd8];

function startsWithBytes(data: Uint8Array, sig: number[]): boolean {
  if (data.length < sig.length) return false;
  for (let i = 0; i < sig.length; i += 1) if (data[i] !== sig[i]) return false;
  return true;
}

export function detectImageFormat(data: Uint8Array): ImageFormat {
  if (startsWithBytes(data, PNG_SIG)) return "png";
  if (startsWithBytes(data, JPEG_SOI)) return "jpeg";
  return "unknown";
}

export interface ImageInspectReport {
  format: ImageFormat;
  hasC2pa: boolean;
  hasAiMetadata: boolean;
  findings: string[];
  findingsConfidence: FindingConfidence[];
  notes: string[];
}

function readU32(data: Uint8Array, pos: number): number {
  return (
    ((data[pos]! << 24) | (data[pos + 1]! << 16) | (data[pos + 2]! << 8) | data[pos + 3]!) >>> 0
  );
}

function readU16(data: Uint8Array, pos: number): number {
  return (data[pos]! << 8) | data[pos + 1]!;
}

function chunkName(data: Uint8Array, pos: number): string {
  return bytesToLatin1(data.subarray(pos, pos + 4));
}

const PNG_TEXT_CHUNKS = new Set(["tEXt", "zTXt", "iTXt", "eXIf"]);
const PNG_C2PA_CHUNKS = new Set(["caBX", "juMB", "jumb"]);
const PNG_CORE_CHUNKS = new Set([
  "IHDR",
  "IDAT",
  "IEND",
  "PLTE",
  "tRNS",
  "gAMA",
  "pHYs",
  "sRGB",
  "cHRM",
  "iCCP",
]);

export function inspectPng(data: Uint8Array): {
  hasC2pa: boolean;
  hasAi: boolean;
  findings: string[];
} {
  const findings: string[] = [];
  let hasC2pa = false;
  let hasAi = false;
  if (!startsWithBytes(data, PNG_SIG)) {
    return { hasC2pa: false, hasAi: false, findings: ["not a PNG"] };
  }
  let pos = 8;
  while (pos + 8 <= data.length) {
    const length = readU32(data, pos);
    const name = chunkName(data, pos + 4);
    const chunkStart = pos + 8;
    const chunkEnd = chunkStart + length;
    if (chunkEnd + 4 > data.length) {
      findings.push(`truncated chunk ${name}`);
      break;
    }
    const payload = data.subarray(chunkStart, chunkEnd);
    if (PNG_C2PA_CHUNKS.has(name) || name.startsWith("c2")) {
      hasC2pa = true;
      findings.push(`PNG chunk ${name} (possible C2PA container)`);
    }
    if (PNG_TEXT_CHUNKS.has(name)) {
      const hits = containsAny(bytesToLatin1(payload), [...AI_META_HINTS, ...C2PA_MARKERS]);
      if (hits.length) {
        hasAi = true;
        if (hits.some((h) => ["c2pa", "contentcredentials", "jumb"].includes(h.toLowerCase()))) {
          hasC2pa = true;
        }
        findings.push(`PNG ${name}: ${hits.slice(0, 8).join(", ")}`);
      }
    }
    if (name === "IEND") break;
    pos = chunkEnd + 4; // skip CRC
  }
  const whole = containsAny(bytesToLatin1(data), C2PA_MARKERS);
  if (whole.length && !hasC2pa) {
    hasC2pa = true;
    findings.push(`byte-scan C2PA markers: ${whole.slice(0, 6).join(", ")}`);
  }
  return { hasC2pa, hasAi: hasAi || hasC2pa, findings };
}

export function inspectJpeg(data: Uint8Array): {
  hasC2pa: boolean;
  hasAi: boolean;
  findings: string[];
} {
  const findings: string[] = [];
  let hasC2pa = false;
  let hasAi = false;
  if (!startsWithBytes(data, JPEG_SOI)) {
    return { hasC2pa: false, hasAi: false, findings: ["not a JPEG"] };
  }
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
    if (marker === 0xd8 || marker === 0xd9) continue; // SOI/EOI
    if (marker === 0xda) break; // SOS, image data follows
    if (marker >= 0xd0 && marker <= 0xd7) continue; // RSTn
    if (i + 2 > n) break;
    const seglen = readU16(data, i);
    if (seglen < 2 || i + seglen > n) {
      findings.push(`bad segment length at marker 0x${marker.toString(16).toUpperCase()}`);
      break;
    }
    const payload = data.subarray(i + 2, i + seglen);
    i += seglen;

    if (marker === 0xeb) {
      // APP11 often holds JUMBF/C2PA
      hasC2pa = true;
      findings.push("JPEG APP11 segment (JUMBF/C2PA common)");
    }
    if ([0xe1, 0xe2, 0xed, 0xee, 0xeb].includes(marker)) {
      const hits = containsAny(bytesToLatin1(payload), [...AI_META_HINTS, ...C2PA_MARKERS]);
      if (hits.length) {
        hasAi = true;
        if (
          hits.some((h) =>
            ["c2pa", "contentcredentials", "jumb", "contentauth"].includes(h.toLowerCase()),
          )
        ) {
          hasC2pa = true;
        }
        findings.push(`JPEG APP${marker - 0xe0}: ${hits.slice(0, 8).join(", ")}`);
      }
    }
  }
  const whole = containsAny(bytesToLatin1(data), C2PA_MARKERS);
  if (whole.length && !hasC2pa) {
    hasC2pa = true;
    findings.push(`byte-scan C2PA markers: ${whole.slice(0, 6).join(", ")}`);
  }
  return { hasC2pa, hasAi: hasAi || hasC2pa, findings };
}

export function inspectImage(data: Uint8Array): ImageInspectReport {
  const format = detectImageFormat(data);
  let result: { hasC2pa: boolean; hasAi: boolean; findings: string[] };
  if (format === "png") result = inspectPng(data);
  else if (format === "jpeg") result = inspectJpeg(data);
  else result = { hasC2pa: false, hasAi: false, findings: ["unsupported format (MVP: PNG/JPEG)"] };

  // Native JUMBF parse: the library's replacement for the c2patool inspect
  // pass. A parsed manifest store is a confirmed structural signal, unlike a
  // stray byte-scan hit.
  const findings = [...result.findings];
  let hasC2pa = result.hasC2pa;
  let hasAi = result.hasAi;
  if (format === "png" || format === "jpeg") {
    const c2 = detectC2paManifest(data);
    if (c2.hasManifest) {
      hasC2pa = true;
      hasAi = true;
      const label = c2.labels.length ? ` (labels: ${c2.labels.slice(0, 6).join(", ")})` : "";
      findings.push(`c2pa manifest store present in JUMBF${label}`);
    }
  }

  const notes: string[] = [];
  if (format === "unknown") {
    notes.push("format not fully inspected; only PNG/JPEG are supported");
  }
  notes.push(
    "C2PA manifests are detected natively via a JUMBF parser (replaces c2patool). Residual-metadata tool passes for non-PNG/JPEG formats (exiftool) and pixel domain checks (SynthID, CtrlRegen) remain Python script features.",
  );
  return {
    format,
    hasC2pa,
    hasAiMetadata: hasAi,
    findings,
    findingsConfidence: findings.map(classifyFindingConfidence),
    notes,
  };
}

// ---------------------------------------------------------------------------
// Strip
// ---------------------------------------------------------------------------

export interface StripImageOptions {
  /** Drop every text/APP metadata segment (default true); false drops only AI/C2PA matches. */
  stripAllMetadata?: boolean;
}

export function stripPng(
  data: Uint8Array,
  options: StripImageOptions = {},
): { data: Uint8Array; actions: string[] } {
  const stripAllText = options.stripAllMetadata ?? true;
  if (!startsWithBytes(data, PNG_SIG)) throw new Error("not PNG");
  const actions: string[] = [];
  const parts: Uint8Array[] = [new Uint8Array(PNG_SIG)];
  let pos = 8;
  while (pos + 8 <= data.length) {
    const length = readU32(data, pos);
    const name = chunkName(data, pos + 4);
    const chunkStart = pos + 8;
    const chunkEnd = chunkStart + length;
    if (chunkEnd + 4 > data.length) break;
    const payload = data.subarray(chunkStart, chunkEnd);
    const record = data.subarray(pos, chunkEnd + 4); // length + type + payload + crc
    pos = chunkEnd + 4;

    let drop = false;
    if (name === "eXIf" || name === "caBX" || name.startsWith("c2")) {
      drop = true;
      actions.push(`drop chunk ${name}`);
    } else if (name === "tEXt" || name === "zTXt" || name === "iTXt") {
      if (
        stripAllText ||
        containsAny(bytesToLatin1(payload), [...AI_META_HINTS, ...C2PA_MARKERS]).length
      ) {
        drop = true;
        actions.push(`drop chunk ${name}`);
      }
    } else if (
      containsAny(name + bytesToLatin1(payload), C2PA_MARKERS).length &&
      !PNG_CORE_CHUNKS.has(name)
    ) {
      drop = true;
      actions.push(`drop chunk ${name} (C2PA marker in payload)`);
    }

    if (!drop) parts.push(record);
    if (name === "IEND") break;
  }
  if (!actions.length) {
    actions.push("no PNG metadata chunks removed (already clean or none matched)");
  }
  return { data: concatBytes(parts), actions };
}

export function stripJpeg(
  data: Uint8Array,
  options: StripImageOptions = {},
): { data: Uint8Array; actions: string[] } {
  const stripAllApp = options.stripAllMetadata ?? true;
  if (!startsWithBytes(data, JPEG_SOI)) throw new Error("not JPEG");
  const actions: string[] = [];
  const parts: Uint8Array[] = [new Uint8Array(JPEG_SOI)];
  let i = 2;
  const n = data.length;
  while (i < n) {
    if (data[i] !== 0xff) {
      parts.push(data.subarray(i));
      actions.push("copied remainder after non-marker byte");
      break;
    }
    while (i < n && data[i] === 0xff) i += 1;
    if (i >= n) break;
    const marker = data[i]!;
    i += 1;

    if (marker === 0xd9) {
      parts.push(new Uint8Array([0xff, 0xd9]));
      break;
    }
    if (marker === 0xd8) continue;
    if (marker >= 0xd0 && marker <= 0xd7) {
      parts.push(new Uint8Array([0xff, marker]));
      continue;
    }
    if (marker === 0xda) {
      // SOS: copy from here through end of file (entropy coded scan)
      parts.push(new Uint8Array([0xff, 0xda]));
      parts.push(data.subarray(i));
      actions.push("preserved entropy-coded scan (SOS to EOF)");
      break;
    }

    if (i + 2 > n) break;
    const seglen = readU16(data, i);
    if (seglen < 2 || i + seglen > n) {
      parts.push(data.subarray(i - 2));
      actions.push("truncated segment; copied remainder");
      break;
    }
    const payload = data.subarray(i + 2, i + seglen);
    const segment = data.subarray(i, i + seglen);
    const nextI = i + seglen;

    let keep = false;
    let drop = false;
    if (marker >= 0xe0 && marker <= 0xef) {
      if (marker === 0xeb) {
        drop = true;
        actions.push("drop APP11 (C2PA/JUMBF)");
      } else if (stripAllApp && marker !== 0xe0) {
        // keep APP0 (JFIF) by default
        drop = true;
        actions.push(`drop APP${marker - 0xe0}`);
      } else if (
        containsAny(bytesToLatin1(payload), [...AI_META_HINTS, ...C2PA_MARKERS]).length
      ) {
        drop = true;
        actions.push(`drop APP${marker - 0xe0} (AI/C2PA markers)`);
      } else {
        keep = true;
      }
    } else if (marker === 0xfe) {
      drop = true;
      actions.push("drop COM comment");
    } else {
      keep = true;
    }

    if (keep && !drop) {
      parts.push(new Uint8Array([0xff, marker]));
      parts.push(segment);
    }
    i = nextI;
  }
  if (!actions.length) actions.push("no JPEG APP segments removed");
  return { data: concatBytes(parts), actions };
}

export interface CleanImageResult {
  format: ImageFormat;
  data: Uint8Array;
  actions: string[];
  bytesIn: number;
  bytesOut: number;
  stillHasC2pa: boolean;
  stillHasAiMetadata: boolean;
  postFindings: string[];
}

/** Port of image_meta.clean_image, minus the external tool and model passes. */
export function cleanImage(
  data: Uint8Array,
  options: StripImageOptions = {},
): CleanImageResult {
  const format = detectImageFormat(data);
  let cleaned: Uint8Array;
  let actions: string[];
  if (format === "png") ({ data: cleaned, actions } = stripPng(data, options));
  else if (format === "jpeg") ({ data: cleaned, actions } = stripJpeg(data, options));
  else throw new Error(`unsupported format: ${format}`);

  const after = inspectImage(cleaned);
  return {
    format,
    data: cleaned,
    actions,
    bytesIn: data.length,
    bytesOut: cleaned.length,
    stillHasC2pa: after.hasC2pa,
    stillHasAiMetadata: after.hasAiMetadata,
    postFindings: after.findings,
  };
}

export function concatBytes(parts: Uint8Array[]): Uint8Array {
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
