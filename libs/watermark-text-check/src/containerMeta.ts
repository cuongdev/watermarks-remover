/**
 * Inspect/clean AI provenance metadata in non raster containers.
 * Port of container_meta.py. Formats: SVG, PDF (best effort, degraded
 * stdlib mode only), DOCX, ODT, HTML, Markdown frontmatter.
 *
 * The Python side prefers exiftool/qpdf for PDFs; those subprocess passes
 * do not exist in an isomorphic JS library, so PDF cleaning here is always
 * the degraded XMP packet strip with an explicit warning, matching the
 * Python fallback path.
 */

import { cleanText } from "./clean.js";
import { cleanPdfDeep, PdfLibUnavailableError } from "./pdfClean.js";
import {
  AI_META_HINTS,
  blobHits,
  bytesToLatin1,
  classifyFindingConfidence,
  latin1ToBytes,
  utf8Decode,
  utf8Encode,
  type FindingConfidence,
} from "./markers.js";
import { readZip, writeZip, type ZipEntry } from "./zip.js";

export type ContainerFormat =
  | "svg"
  | "pdf"
  | "docx"
  | "odt"
  | "html"
  | "markdown"
  | "unknown";

/** Frontmatter / meta keys that often carry AI provenance. */
export const AI_FRONTMATTER_KEYS: ReadonlySet<string> = new Set([
  "generator",
  "ai",
  "ai_generated",
  "ai-generated",
  "claude",
  "anthropic",
  "openai",
  "gemini",
  "synthid",
  "c2pa",
  "content_credentials",
  "contentcredentials",
  "provenance",
  "digital_source_type",
  "digitalsourcetype",
  "created_with",
  "createdwith",
  "model",
  "llm",
]);

const AI_META_NAME_RE =
  /generator|ai[-_ ]?generated|claude|anthropic|openai|gemini|synthid|c2pa|content.?credential|provenance|digital.?source|aigc/i;

export interface ContainerInspectReport {
  format: ContainerFormat;
  hasC2pa: boolean;
  hasAiMetadata: boolean;
  findings: string[];
  findingsConfidence: FindingConfidence[];
  details: Record<string, unknown>;
  notes: string[];
}

export function detectContainerFormat(
  filename: string | null,
  data: Uint8Array | null = null,
): ContainerFormat {
  const ext = filename ? (filename.match(/\.[^./\\]+$/)?.[0] ?? "").toLowerCase() : "";
  if (ext === ".svg") return "svg";
  if (ext === ".pdf") return "pdf";
  if (ext === ".docx") return "docx";
  if (ext === ".odt") return "odt";
  if (ext === ".html" || ext === ".htm") return "html";
  if ([".md", ".markdown", ".mdx"].includes(ext)) return "markdown";
  if (data !== null) {
    const head = bytesToLatin1(data.subarray(0, 500));
    if (head.startsWith("%PDF")) return "pdf";
    if (head.slice(0, 100).trimStart().startsWith("<") && head.toLowerCase().includes("svg")) {
      return "svg";
    }
    // zip based sniffing is async (needs inflate); use detectZipContainerFormat
  }
  return "unknown";
}

/** Async half of format sniffing: distinguishes DOCX from ODT inside a zip. */
export async function detectZipContainerFormat(data: Uint8Array): Promise<ContainerFormat> {
  if (data.length < 2 || data[0] !== 0x50 || data[1] !== 0x4b) return "unknown";
  try {
    const names = new Set((await readZip(data)).map((e) => e.name));
    if (names.has("word/document.xml")) return "docx";
    if (names.has("content.xml") && names.has("meta.xml")) return "odt";
  } catch {
    // fall through
  }
  return "unknown";
}

// ---------------------------------------------------------------------------
// Markdown frontmatter
// ---------------------------------------------------------------------------

const FM_RE = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?/;
const YAML_KEY_RE = /^([A-Za-z0-9_.-]+)\s*:/;

function parseSimpleYamlKeys(block: string): Array<{ key: string; line: string }> {
  const rows: Array<{ key: string; line: string }> = [];
  for (const line of block.split(/\r?\n/)) {
    const stripped = line.trim();
    if (!stripped || stripped.startsWith("#")) continue;
    if (line[0] === " " || line[0] === "\t" || line[0] === "-") continue; // nested / list
    const m = YAML_KEY_RE.exec(line);
    if (m) rows.push({ key: m[1] as string, line });
  }
  return rows;
}

export function inspectMarkdown(text: string): {
  hasC2pa: boolean;
  hasAi: boolean;
  findings: string[];
  details: Record<string, unknown>;
} {
  const findings: string[] = [];
  let hasAi = false;
  const m = FM_RE.exec(text);
  if (!m) return { hasC2pa: false, hasAi: false, findings: [], details: { hasFrontmatter: false } };
  const block = m[1] as string;
  const keys: string[] = [];
  for (const { key, line } of parseSimpleYamlKeys(block)) {
    keys.push(key);
    if (AI_FRONTMATTER_KEYS.has(key.toLowerCase()) || AI_META_NAME_RE.test(key)) {
      hasAi = true;
      findings.push(`frontmatter key: ${key}`);
    }
    const val = line.includes(":") ? line.split(":").slice(1).join(":") : "";
    if (AI_META_NAME_RE.test(val)) {
      hasAi = true;
      findings.push(`frontmatter value hit on ${key}`);
    }
  }
  const hasC2pa = findings.some(
    (f) => f.toLowerCase().includes("c2pa") || f.toLowerCase().includes("content"),
  );
  return { hasC2pa, hasAi, findings, details: { hasFrontmatter: true, keys } };
}

export function cleanMarkdown(text: string): { text: string; actions: string[] } {
  const actions: string[] = [];
  const m = FM_RE.exec(text);
  if (!m) return { text, actions: ["no YAML frontmatter"] };
  const block = m[1] as string;
  const body = text.slice(m[0].length);
  const kept: string[] = [];
  let dropping = false; // inside the nested block of a dropped top level key
  for (const line of block.split(/\r?\n/)) {
    const stripped = line.trim();

    if (!stripped || stripped.startsWith("#")) {
      if (!dropping) kept.push(line);
      continue;
    }
    if (line[0] === " " || line[0] === "\t" || line[0] === "-") {
      if (!dropping) kept.push(line);
      continue;
    }

    const km = YAML_KEY_RE.exec(line);
    if (!km) {
      dropping = false;
      kept.push(line);
      continue;
    }
    const key = km[1] as string;
    const val = line.includes(":") ? line.split(":").slice(1).join(":") : "";
    if (AI_FRONTMATTER_KEYS.has(key.toLowerCase()) || AI_META_NAME_RE.test(key)) {
      actions.push(`drop frontmatter key: ${key}`);
      dropping = true;
      continue;
    }
    if (AI_META_NAME_RE.test(val)) {
      actions.push(`drop frontmatter key (value hit): ${key}`);
      dropping = true;
      continue;
    }
    dropping = false;
    kept.push(line);
  }
  if (!actions.length) actions.push("no AI frontmatter keys removed");
  const newBlock = kept.join("\n").replace(/^\n+|\n+$/g, "");
  let out: string;
  if (newBlock) {
    out = `---\n${newBlock}\n---\n${body}`;
  } else {
    out = body.replace(/^\n+/, "");
    actions.push("removed empty frontmatter block");
  }
  return { text: out, actions };
}

// ---------------------------------------------------------------------------
// HTML
// ---------------------------------------------------------------------------

const META_TAG_RE = /<meta\b[^>]*>/gi;
const META_ATTR_RE = /(name|property|content|generator)\s*=\s*["']([^"']*)["']/gi;

/**
 * Known AI vendor names for the "generator" meta tag. A plain CMS generator
 * (WordPress, Elementor) is CMS provenance, not AI generator metadata.
 */
const GENERATOR_AI_RE =
  /claude|anthropic|openai|chatgpt|gemini|synthid|copilot|midjourney|dall.?e|stable.?diffusion/i;

const JSONLD_RE =
  /<script\b[^>]*type\s*=\s*["']application\/ld\+json["'][^>]*>[\s\S]*?<\/script>/gi;

const DATA_AI_ATTR_RE = /\bdata-ai[\w-]*\s*=\s*["'][^"']*["']/gi;

function metaAttrs(tag: string): Record<string, string> {
  const attrs: Record<string, string> = {};
  for (const m of tag.matchAll(META_ATTR_RE)) {
    attrs[(m[1] as string).toLowerCase()] = m[2] as string;
  }
  return attrs;
}

function isCmsGeneratorMeta(tag: string): boolean {
  const attrs = metaAttrs(tag);
  const nameOrProp = (attrs["name"] || attrs["property"] || attrs["generator"] || "").toLowerCase();
  if (nameOrProp !== "generator") return false;
  if (GENERATOR_AI_RE.test(attrs["content"] || "") || GENERATOR_AI_RE.test(tag)) return false;
  return true;
}

const AI_HINT_PREFIX = AI_META_HINTS.slice(0, 12).map((h) => h.toLowerCase());

export function inspectHtml(text: string): {
  hasC2pa: boolean;
  hasAi: boolean;
  findings: string[];
  details: Record<string, unknown>;
} {
  const findings: string[] = [];
  let hasAi = false;
  let hasC2pa = false;
  for (const m of text.matchAll(META_TAG_RE)) {
    const tag = m[0];
    if (/c2pa|content.?credential/i.test(tag)) hasC2pa = true;
    if (isCmsGeneratorMeta(tag)) {
      findings.push(`info: cms generator: ${tag.slice(0, 120)}`);
      continue;
    }
    const tagLower = tag.toLowerCase();
    if (AI_META_NAME_RE.test(tag) || AI_HINT_PREFIX.some((h) => tagLower.includes(h))) {
      hasAi = true;
      findings.push(`meta: ${tag.slice(0, 120)}`);
    }
  }
  for (const m of text.matchAll(JSONLD_RE)) {
    const blob = m[0];
    if (
      AI_META_NAME_RE.test(blob) ||
      /DigitalSourceType|trainedAlgorithmicMedia|SoftwareAgent/i.test(blob)
    ) {
      hasAi = true;
      findings.push("json-ld provenance-like block");
      if (/c2pa|contentcredential/i.test(blob)) hasC2pa = true;
    }
  }
  for (const m of text.matchAll(DATA_AI_ATTR_RE)) {
    hasAi = true;
    findings.push(`attr: ${m[0].slice(0, 80)}`);
  }
  return { hasC2pa, hasAi, findings, details: {} };
}

export function cleanHtml(text: string): { text: string; actions: string[] } {
  const actions: string[] = [];
  let out = text.replace(META_TAG_RE, (tag) => {
    if (isCmsGeneratorMeta(tag)) return tag;
    if (
      AI_META_NAME_RE.test(tag) ||
      /generator|claude|anthropic|openai|gemini|synthid|c2pa|aigc/i.test(tag)
    ) {
      actions.push(`drop meta: ${tag.slice(0, 80)}`);
      return "";
    }
    return tag;
  });
  out = out.replace(JSONLD_RE, (blob) => {
    if (
      AI_META_NAME_RE.test(blob) ||
      /DigitalSourceType|trainedAlgorithmicMedia|SoftwareAgent/i.test(blob)
    ) {
      actions.push("drop json-ld provenance-like script");
      return "";
    }
    return blob;
  });
  let attrCount = 0;
  const out2 = out.replace(/\sdata-ai[\w-]*\s*=\s*["'][^"']*["']/gi, () => {
    attrCount += 1;
    return "";
  });
  if (attrCount) {
    actions.push(`drop data-ai* attributes x${attrCount}`);
    out = out2;
  }
  if (!actions.length) actions.push("no HTML AI meta removed");
  return { text: out, actions };
}

// ---------------------------------------------------------------------------
// SVG
// ---------------------------------------------------------------------------

export function inspectSvg(data: Uint8Array): {
  hasC2pa: boolean;
  hasAi: boolean;
  findings: string[];
  details: Record<string, unknown>;
} {
  const findings: string[] = [];
  const blob = blobHits(bytesToLatin1(data));
  let { hasC2pa, hasAi } = blob;
  findings.push(...blob.findings);
  const text = utf8Decode(data);
  if (/<metadata[\s>]/i.test(text)) {
    findings.push("svg <metadata> present");
    hasAi = true; // often XMP; treat as inspect signal
  }
  if (/xmpmeta|rdf:RDF|contentcredentials/i.test(text)) {
    hasAi = true;
    findings.push("XMP/RDF-like content in SVG");
  }
  if (/c2pa|jumbf/i.test(text)) hasC2pa = true;
  return { hasC2pa, hasAi: hasAi || hasC2pa, findings, details: {} };
}

export function cleanSvg(data: Uint8Array): { data: Uint8Array; actions: string[] } {
  const actions: string[] = [];
  let text = utf8Decode(data);

  let count = 0;
  let next = text.replace(/<metadata\b[^>]*>[\s\S]*?<\/metadata\s*>/gi, () => {
    count += 1;
    return "";
  });
  if (count) {
    actions.push(`drop <metadata> x${count}`);
    text = next;
  }
  count = 0;
  next = text.replace(/<x:xmpmeta\b[^>]*>[\s\S]*?<\/x:xmpmeta\s*>/gi, () => {
    count += 1;
    return "";
  });
  if (count) {
    actions.push(`drop xmpmeta x${count}`);
    text = next;
  }
  text = text.replace(/<!--[\s\S]*?-->/g, (body) => {
    if (AI_META_NAME_RE.test(body)) {
      actions.push("drop SVG comment with AI markers");
      return "";
    }
    return body;
  });
  if (!actions.length) {
    count = 0;
    next = text.replace(
      /\s(inkscape:version|sodipodi:docname|generator)\s*=\s*"[^"]*"/gi,
      () => {
        count += 1;
        return "";
      },
    );
    if (count) {
      actions.push(`drop generator-like attrs x${count}`);
      text = next;
    }
  }
  if (!actions.length) actions.push("no SVG metadata removed");
  return { data: utf8Encode(text), actions };
}

// ---------------------------------------------------------------------------
// DOCX / ODT (zip + XML)
// ---------------------------------------------------------------------------

function isDocxMetaPart(name: string): boolean {
  return name.startsWith("docProps/") || name.startsWith("customXml/");
}

export async function inspectDocx(data: Uint8Array): Promise<{
  hasC2pa: boolean;
  hasAi: boolean;
  findings: string[];
  details: Record<string, unknown>;
}> {
  const findings: string[] = [];
  let hasC2pa = false;
  let hasAi = false;
  let entries: ZipEntry[];
  try {
    entries = await readZip(data);
  } catch {
    return { hasC2pa: false, hasAi: false, findings: ["not a valid DOCX zip"], details: {} };
  }
  for (const entry of entries) {
    // Only metadata/provenance parts carry AI markers. The visible body
    // (word/*.xml) may legitimately mention vendor names such as "Claude"
    // without being AI generated metadata.
    if (!isDocxMetaPart(entry.name)) continue;
    const { hasC2pa: c2, hasAi: ai, findings: hits } = blobHits(bytesToLatin1(entry.data));
    if (c2 || ai) {
      if (c2) hasC2pa = true;
      if (ai) hasAi = true;
      findings.push(`${entry.name}: ${hits.slice(0, 6).join(", ")}`);
    }
  }
  const custom = entries.filter((e) => e.name.startsWith("customXml/"));
  if (custom.length) findings.push(`customXml parts: ${custom.length}`);
  return { hasC2pa, hasAi: hasAi || hasC2pa, findings, details: { parts: entries.length } };
}

const DOCX_FIELD_PATTERNS: Array<{ re: RegExp; label: string }> = [
  { re: /(<dc:creator[^>]*>)([\s\S]*?)(<\/dc:creator>)/gi, label: "dc:creator" },
  { re: /(<cp:lastModifiedBy[^>]*>)([\s\S]*?)(<\/cp:lastModifiedBy>)/gi, label: "cp:lastModifiedBy" },
  { re: /(<Application[^>]*>)([\s\S]*?)(<\/Application>)/gi, label: "Application" },
  { re: /(<AppVersion[^>]*>)([\s\S]*?)(<\/AppVersion>)/gi, label: "AppVersion" },
];

export async function cleanDocx(
  data: Uint8Array,
): Promise<{ data: Uint8Array; actions: string[] }> {
  const actions: string[] = [];
  const entries = await readZip(data);
  const out: ZipEntry[] = [];
  for (const entry of entries) {
    const name = entry.name;
    let raw = entry.data;
    // Drop entire customXml trees (often provenance injects); body stays in word/
    if (name.startsWith("customXml/")) {
      actions.push(`drop part ${name}`);
      continue;
    }
    if (name.startsWith("docProps/")) {
      const text = utf8Decode(raw);
      let updated = text;
      for (const { re, label } of DOCX_FIELD_PATTERNS) {
        updated = updated.replace(re, (whole: string, open: string, inner: string, close: string) => {
          if (AI_META_NAME_RE.test(inner) || AI_META_NAME_RE.test(label)) {
            actions.push(`scrub ${name} field ${label}`);
            return open + close;
          }
          if (
            (label === "Application" || label === "AppVersion") &&
            /claude|openai|anthropic|gemini|chatgpt|synthid|copilot/i.test(inner)
          ) {
            actions.push(`scrub ${name} field ${label}`);
            return open + close;
          }
          return whole;
        });
      }
      // Drop custom.xml entirely if AI-ish
      if (
        name.endsWith("custom.xml") &&
        (blobHits(bytesToLatin1(raw)).hasAi || AI_META_NAME_RE.test(text))
      ) {
        actions.push(`drop part ${name}`);
        continue;
      }
      raw = utf8Encode(updated);
    }
    if (name === "[Content_Types].xml") {
      const text = utf8Decode(raw);
      let count = 0;
      const updated = text.replace(
        /<Override\b[^>]*PartName="\/customXml\/[^"]*"[^>]*\/>/g,
        () => {
          count += 1;
          return "";
        },
      );
      if (count) {
        actions.push(`drop Content_Types customXml overrides x${count}`);
        raw = utf8Encode(updated);
      }
    }
    out.push({ name, data: raw });
  }
  if (!actions.length) actions.push("no DOCX metadata parts removed");
  return { data: await writeZip(out), actions };
}

export async function inspectOdt(data: Uint8Array): Promise<{
  hasC2pa: boolean;
  hasAi: boolean;
  findings: string[];
  details: Record<string, unknown>;
}> {
  const findings: string[] = [];
  let hasC2pa = false;
  let hasAi = false;
  let entries: ZipEntry[];
  try {
    entries = await readZip(data);
  } catch {
    return { hasC2pa: false, hasAi: false, findings: ["not a valid ODT zip"], details: {} };
  }
  for (const entry of entries) {
    const { hasC2pa: c2, hasAi: ai, findings: hits } = blobHits(bytesToLatin1(entry.data));
    if (c2 || ai) {
      if (c2) hasC2pa = true;
      if (ai) hasAi = true;
      findings.push(`${entry.name}: ${hits.slice(0, 6).join(", ")}`);
    }
  }
  const meta = entries.find((e) => e.name === "meta.xml");
  if (meta && /generator|claude|openai|anthropic|gemini/i.test(utf8Decode(meta.data))) {
    hasAi = true;
    findings.push("meta.xml generator-like fields");
  }
  return { hasC2pa, hasAi: hasAi || hasC2pa, findings, details: {} };
}

const ODT_KEEP_PARTS = new Set([
  "content.xml",
  "styles.xml",
  "mimetype",
  "META-INF/manifest.xml",
]);

export async function cleanOdt(
  data: Uint8Array,
): Promise<{ data: Uint8Array; actions: string[] }> {
  const actions: string[] = [];
  const entries = await readZip(data);
  const out: ZipEntry[] = [];
  for (const entry of entries) {
    const name = entry.name;
    let raw = entry.data;
    if (name === "meta.xml") {
      let text = utf8Decode(raw);
      let count = 0;
      const noGen = text.replace(/<meta:generator\b[^>]*>[\s\S]*?<\/meta:generator\s*>/gi, () => {
        count += 1;
        return "";
      });
      if (count) {
        actions.push("drop meta:generator");
        text = noGen;
      }
      text = text.replace(/<dc:creator\b[^>]*>[\s\S]*?<\/dc:creator\s*>/gi, (whole) => {
        if (AI_META_NAME_RE.test(whole)) {
          actions.push("scrub creator-like meta");
          return "";
        }
        return whole;
      });
      raw = utf8Encode(text);
    } else {
      const { hasC2pa: c2, hasAi: ai } = blobHits(bytesToLatin1(raw));
      if ((c2 || ai) && !ODT_KEEP_PARTS.has(name)) {
        actions.push(`drop part ${name} (AI/C2PA markers)`);
        continue;
      }
    }
    out.push({ name, data: raw });
  }
  if (!actions.length) actions.push("no ODT metadata removed");
  return { data: await writeZip(out), actions };
}

// ---------------------------------------------------------------------------
// PDF (best effort, stdlib/degraded mode only)
// ---------------------------------------------------------------------------

const XMP_PACKET_RE = /<\?xpacket begin[\s\S]*?<\?xpacket end[^?]*\?>/gi;

/**
 * Return PDF content (as latin-1 string) with stream payloads removed, plus
 * XMP packets. Stream payloads are often compressed binary where an AI
 * marker byte sequence (e.g. "AIGC") can occur by chance; scanning only
 * dictionaries and XMP packets avoids treating those collisions as findings.
 */
function pdfStructuredBlob(latin1: string): string {
  const noStreams = latin1.replace(/stream\r?\n[\s\S]*?endstream/g, "stream endstream");
  const xmp = (latin1.match(XMP_PACKET_RE) || []).join("\n");
  return noStreams + "\n" + xmp;
}

export function inspectPdf(data: Uint8Array): {
  hasC2pa: boolean;
  hasAi: boolean;
  findings: string[];
  details: Record<string, unknown>;
} {
  const latin1 = bytesToLatin1(data);
  const findings: string[] = [];
  const blob = blobHits(pdfStructuredBlob(latin1));
  let { hasC2pa, hasAi } = blob;
  findings.push(...blob.findings.map((h) => `pdf-structured:${h}`));
  const xmpBlob = (latin1.match(XMP_PACKET_RE) || []).join("\n");
  if (xmpBlob) {
    findings.push("XMP packet present");
    hasAi =
      hasAi ||
      /digitalSourceType|trainedAlgorithmicMedia|SoftwareAgent|c2pa/i.test(xmpBlob);
  }
  return { hasC2pa, hasAi: hasAi || hasC2pa, findings, details: {} };
}

/**
 * Degraded PDF clean: strip obvious XMP packets between xpacket begin/end.
 * The Python scripts prefer exiftool plus a qpdf structural rewrite; without
 * those, stripped metadata bytes may remain recoverable elsewhere in the
 * file and offsets may be broken. Prefer the Python path for real PDF work.
 */
export function cleanPdf(data: Uint8Array): {
  data: Uint8Array;
  actions: string[];
  meta: Record<string, unknown>;
} {
  const actions: string[] = [];
  const latin1 = bytesToLatin1(data);
  let count = 0;
  const stripped = latin1.replace(XMP_PACKET_RE, () => {
    count += 1;
    return "";
  });
  if (count) {
    actions.push(`stripped XMP xpacket x${count} (degraded; may leave offsets broken)`);
    actions.push(
      "warning: pure JS PDF strip is best effort; prefer the Python scripts with exiftool and qpdf",
    );
    return { data: latin1ToBytes(stripped), actions, meta: { mode: "stdlib-xmp", degraded: true } };
  }
  actions.push(
    "no PDF cleaner available in this library (use the Python scripts with exiftool for a reliable strip); copied as-is",
  );
  return { data: data.slice(), actions, meta: { mode: "copy", degraded: true } };
}

// ---------------------------------------------------------------------------
// Unified API
// ---------------------------------------------------------------------------

export async function resolveContainerFormat(
  filename: string | null,
  data: Uint8Array,
): Promise<ContainerFormat> {
  const byName = detectContainerFormat(filename, data);
  if (byName !== "unknown") return byName;
  return detectZipContainerFormat(data);
}

export async function inspectContainer(
  data: Uint8Array,
  filename: string | null = null,
): Promise<ContainerInspectReport> {
  const format = await resolveContainerFormat(filename, data);
  let result: {
    hasC2pa: boolean;
    hasAi: boolean;
    findings: string[];
    details: Record<string, unknown>;
  };

  if (format === "svg") result = inspectSvg(data);
  else if (format === "pdf") result = inspectPdf(data);
  else if (format === "docx") result = await inspectDocx(data);
  else if (format === "odt") result = await inspectOdt(data);
  else if (format === "html") result = inspectHtml(utf8Decode(data));
  else if (format === "markdown") result = inspectMarkdown(utf8Decode(data));
  else {
    result = {
      hasC2pa: false,
      hasAi: false,
      findings: [`unsupported container: ${format}`],
      details: { unsupported: true },
    };
  }

  const notes: string[] = [];
  if (format === "pdf") {
    notes.push(
      "PDF inspection is best effort; exiftool/c2patool (Python script path) give more reliable metadata detection",
    );
  } else if (format === "docx") {
    notes.push("DOCX: only metadata/provenance parts are scanned; visible body text is ignored");
  }
  if (result.details["unsupported"]) notes.push(`format not fully inspected: ${format}`);

  return {
    format,
    hasC2pa: result.hasC2pa,
    hasAiMetadata: result.hasAi,
    findings: result.findings,
    findingsConfidence: result.findings.map(classifyFindingConfidence),
    details: result.details,
    notes,
  };
}

export interface CleanContainerOptions {
  /** Layer A scrub text bodies for markdown/html (default true). */
  alsoLayerAText?: boolean;
}

export interface CleanContainerResult {
  format: ContainerFormat;
  data: Uint8Array;
  actions: string[];
  bytesIn: number;
  bytesOut: number;
  stillHasC2pa: boolean;
  stillHasAiMetadata: boolean;
  postFindings: string[];
  meta: Record<string, unknown>;
}

export async function cleanContainer(
  data: Uint8Array,
  filename: string | null = null,
  options: CleanContainerOptions = {},
): Promise<CleanContainerResult> {
  const alsoLayerAText = options.alsoLayerAText ?? true;
  const format = await resolveContainerFormat(filename, data);
  let actions: string[] = [];
  let cleaned: Uint8Array;
  const meta: Record<string, unknown> = { format };

  if (format === "svg") {
    ({ data: cleaned, actions } = cleanSvg(data));
  } else if (format === "pdf") {
    // Prefer the pdf-lib deep clean (structural rewrite, no recoverable
    // metadata bytes); fall back to the degraded stdlib XMP strip when the
    // optional dependency is absent.
    try {
      const deep = await cleanPdfDeep(data);
      cleaned = deep.data;
      actions = deep.actions;
      Object.assign(meta, deep.meta);
    } catch (e) {
      if (!(e instanceof PdfLibUnavailableError)) throw e;
      const r = cleanPdf(data);
      cleaned = r.data;
      actions = r.actions;
      actions.push(e.message);
      Object.assign(meta, r.meta);
    }
  } else if (format === "docx") {
    ({ data: cleaned, actions } = await cleanDocx(data));
  } else if (format === "odt") {
    ({ data: cleaned, actions } = await cleanOdt(data));
  } else if (format === "html" || format === "markdown") {
    let text = utf8Decode(data);
    const r = format === "html" ? cleanHtml(text) : cleanMarkdown(text);
    text = r.text;
    actions = r.actions;
    if (alsoLayerAText) {
      const { text: text2, stats } = cleanText(text);
      if (stats.removedCount || stats.replacedCount) {
        actions.push(
          `layer A text: removed=${stats.removedCount} replaced=${stats.replacedCount}`,
        );
        text = text2;
      }
    }
    cleaned = utf8Encode(text);
  } else {
    throw new Error(`unsupported container format: ${format}`);
  }

  const after = await inspectContainer(cleaned, filename);
  return {
    format,
    data: cleaned,
    actions,
    bytesIn: data.length,
    bytesOut: cleaned.length,
    stillHasC2pa: after.hasC2pa,
    stillHasAiMetadata: after.hasAiMetadata,
    postFindings: after.findings,
    meta,
  };
}
