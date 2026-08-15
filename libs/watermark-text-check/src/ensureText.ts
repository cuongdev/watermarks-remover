/**
 * Input guard: verify a watermark check input is plausibly text.
 * Port of looks_binary / read_text_input in common.py, adapted to the
 * isomorphic surface (string, Uint8Array, ArrayBuffer instead of file paths).
 */

const BINARY_SNIFF_BYTES = 8192;
const CONTROL_RATIO_LIMIT = 0.05;
const ALLOWED_CONTROLS = new Set([0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x1b]);
/** Same default cap as the Python scripts (256 MiB). */
export const MAX_INPUT_BYTES = 256 << 20;

const BINARY_MAGIC: ReadonlyArray<[number[], string]> = [
  [[0x50, 0x4b, 0x03, 0x04], "a ZIP container (DOCX, ODT, XLSX, PPTX, EPUB, JAR)"],
  [[0x50, 0x4b, 0x05, 0x06], "an empty ZIP container"],
  [[0x50, 0x4b, 0x07, 0x08], "a spanned ZIP container"],
  [[0x25, 0x50, 0x44, 0x46, 0x2d], "a PDF"],
  [[0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a], "a PNG image"],
  [[0xff, 0xd8, 0xff], "a JPEG image"],
  [[0x47, 0x49, 0x46, 0x38, 0x37, 0x61], "a GIF image"],
  [[0x47, 0x49, 0x46, 0x38, 0x39, 0x61], "a GIF image"],
  [[0x49, 0x49, 0x2a, 0x00], "a TIFF image"],
  [[0x4d, 0x4d, 0x00, 0x2a], "a TIFF image"],
  [[0x52, 0x49, 0x46, 0x46], "a RIFF container (WEBP, WAV, AVI)"],
  [[0x4f, 0x67, 0x67, 0x53], "an Ogg media file"],
  [[0x1f, 0x8b], "a gzip archive"],
  [[0x42, 0x5a, 0x68], "a bzip2 archive"],
  [[0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00], "an xz archive"],
  [[0x37, 0x7a, 0xbc, 0xaf, 0x27, 0x1c], "a 7-Zip archive"],
  [[0x52, 0x61, 0x72, 0x21, 0x1a, 0x07], "a RAR archive"],
  [[0x7f, 0x45, 0x4c, 0x46], "an ELF binary"],
  [[0xca, 0xfe, 0xba, 0xbe], "a Java class or Mach-O fat binary"],
  [[0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1], "a legacy Office document (.doc, .xls, .ppt)"],
  [
    [0x53, 0x51, 0x4c, 0x69, 0x74, 0x65, 0x20, 0x66, 0x6f, 0x72, 0x6d, 0x61, 0x74, 0x20, 0x33, 0x00],
    "a SQLite database",
  ],
  [[0x38, 0x42, 0x50, 0x53], "a Photoshop document"],
  [[0x77, 0x4f, 0x46, 0x46], "a WOFF font"],
  [[0x77, 0x4f, 0x46, 0x32], "a WOFF2 font"],
  [[0x00, 0x01, 0x00, 0x00, 0x00], "a TrueType font"],
];

function startsWith(data: Uint8Array, magic: number[]): boolean {
  if (data.length < magic.length) return false;
  for (let i = 0; i < magic.length; i += 1) {
    if (data[i] !== magic[i]) return false;
  }
  return true;
}

/**
 * Describe why the bytes are not plausibly text, or null when they look like
 * text. Deliberately conservative: encodings other than UTF-8 must keep
 * working, so undecodable bytes alone are not proof.
 */
export function sniffBinary(data: Uint8Array): string | null {
  if (data.length === 0) return null;
  for (const [magic, label] of BINARY_MAGIC) {
    if (startsWith(data, magic)) return label;
  }
  const head = data.subarray(0, BINARY_SNIFF_BYTES);
  let controls = 0;
  for (const b of head) {
    if (b === 0x00) return "binary data (contains NUL bytes)";
    if (b < 0x20 && !ALLOWED_CONTROLS.has(b)) controls += 1;
  }
  if (controls / head.length > CONTROL_RATIO_LIMIT) {
    return "binary data (dense in control bytes)";
  }
  return null;
}

/** Same heuristic applied to an already decoded string (pasted content). */
export function sniffBinaryString(text: string): string | null {
  if (text.length === 0) return null;
  const head = text.slice(0, BINARY_SNIFF_BYTES);
  let controls = 0;
  for (let i = 0; i < head.length; i += 1) {
    const cu = head.charCodeAt(i);
    if (cu === 0x00) return "binary data (contains NUL characters)";
    if (cu < 0x20 && !ALLOWED_CONTROLS.has(cu)) controls += 1;
  }
  if (controls / head.length > CONTROL_RATIO_LIMIT) {
    return "binary data (dense in control characters)";
  }
  return null;
}

export type EnsureTextResult =
  | { ok: true; text: string }
  | { ok: false; reason: string };

export interface EnsureTextOptions {
  /** Reject inputs larger than this many bytes (default 256 MiB). */
  maxBytes?: number;
  /** Scan even when the input looks like a binary container. */
  forceText?: boolean;
}

/** True when the value is a string (the runtime type guard half of the check). */
export function isText(input: unknown): input is string {
  return typeof input === "string";
}

/**
 * Validate that a watermark check input is text, and return the decoded
 * string. Accepts a string (pasted content), Uint8Array, or ArrayBuffer
 * (file uploads). Rejects known binary containers, NUL bytes, control dense
 * data, oversized inputs, and non text runtime types.
 */
export function ensureText(input: unknown, options: EnsureTextOptions = {}): EnsureTextResult {
  const { maxBytes = MAX_INPUT_BYTES, forceText = false } = options;

  if (isText(input)) {
    if (input.length * 4 > maxBytes && byteLength(input) > maxBytes) {
      return { ok: false, reason: `input larger than ${maxBytes} bytes` };
    }
    if (!forceText) {
      const reason = sniffBinaryString(input);
      if (reason) return { ok: false, reason: `input looks like ${reason}` };
    }
    return { ok: true, text: input };
  }

  let bytes: Uint8Array | null = null;
  if (input instanceof Uint8Array) bytes = input;
  else if (input instanceof ArrayBuffer) bytes = new Uint8Array(input);
  if (bytes === null) {
    return { ok: false, reason: `input is not text (got ${describeType(input)})` };
  }

  if (bytes.length > maxBytes) {
    return { ok: false, reason: `input larger than ${maxBytes} bytes` };
  }
  if (!forceText) {
    const reason = sniffBinary(bytes);
    if (reason) return { ok: false, reason: `input looks like ${reason}` };
  }
  // Non fatal decode mirrors the Python surrogateescape fallback: stray
  // bytes become U+FFFD instead of aborting the scan.
  const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  return { ok: true, text };
}

function describeType(input: unknown): string {
  if (input === null) return "null";
  if (Array.isArray(input)) return "array";
  return typeof input;
}

function byteLength(text: string): number {
  return new TextEncoder().encode(text).length;
}
