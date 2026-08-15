/**
 * watermark-text-check
 *
 * Isomorphic (browser + Node + edge) TypeScript port of the watermarks-remover
 * Layer A text checks. Two responsibilities:
 *
 *   1. ensureText / isText: verify a watermark check input actually is text
 *      (runtime type guard plus binary container sniffing).
 *   2. inspectText / cleanText: detect and remove invisible Unicode watermark
 *      carriers (zero width chars, bidi controls, tag chars, variation
 *      selectors, private use, exotic spaces, confusables).
 *
 * Scope guardrails: Layer A is deterministic and covers edit based carriers
 * only. Statistical (token sampling) watermarks are out of scope. Intended
 * for provenance hygiene on content you own; verify use against your
 * organization's legal and regulatory obligations before deploying.
 */

export {
  ensureText,
  isText,
  sniffBinary,
  sniffBinaryString,
  MAX_INPUT_BYTES,
  type EnsureTextOptions,
  type EnsureTextResult,
} from "./ensureText.js";

export {
  inspectText,
  hasWatermarkCarriers,
  reportToJson,
  scanText,
  type CharHit,
  type InspectOptions,
  type TextInspectReport,
  type TextMark,
} from "./inspect.js";

export {
  cleanText,
  type CleanOptions,
  type CleanResult,
  type CleanStats,
} from "./clean.js";

export type { HitKind } from "./classify.js";

export {
  AI_META_HINTS,
  C2PA_MARKERS,
  CONFIDENCE_LEVELS,
  classifyFindingConfidence,
  type FindingConfidence,
} from "./markers.js";

export {
  cleanImage,
  detectImageFormat,
  inspectImage,
  inspectJpeg,
  inspectPng,
  stripJpeg,
  stripPng,
  type CleanImageResult,
  type ImageFormat,
  type ImageInspectReport,
  type StripImageOptions,
} from "./imageMeta.js";

export {
  AI_FRONTMATTER_KEYS,
  cleanContainer,
  cleanDocx,
  cleanHtml,
  cleanMarkdown,
  cleanOdt,
  cleanPdf,
  cleanSvg,
  detectContainerFormat,
  detectZipContainerFormat,
  inspectContainer,
  inspectDocx,
  inspectHtml,
  inspectMarkdown,
  inspectOdt,
  inspectPdf,
  inspectSvg,
  resolveContainerFormat,
  type CleanContainerOptions,
  type CleanContainerResult,
  type ContainerFormat,
  type ContainerInspectReport,
} from "./containerMeta.js";

export {
  MAX_ZIP_DECOMPRESSED_BYTES,
  crc32,
  readZip,
  writeZip,
  type ZipEntry,
} from "./zip.js";

export { detectC2paManifest, type C2paDetection } from "./c2pa.js";

export {
  PdfLibUnavailableError,
  cleanPdfDeep,
  isPdfLibAvailable,
  type PdfDeepCleanResult,
} from "./pdfClean.js";

export {
  PROMPTS,
  buildPrompt,
  callOllama,
  callOpenAiCompatible,
  checkRemote,
  lexicalDivergence,
  rewriteText,
  selectCandidate,
  type RewriteBackend,
  type RewriteInfo,
  type RewriteOptions,
  type RewriteStrength,
} from "./rewrite.js";

export {
  DEFAULT_SKIP_DIRS,
  aggregate,
  auditItems,
  isActionable,
  renderAuditReport,
  scanItem,
  type AuditInput,
  type AuditItem,
  type AuditReport,
  type AuditSummary,
} from "./audit.js";

export {
  AUDIT_USER_AGENT,
  auditWebsite,
  collectUrls,
  discoverSitemap,
  fetchCapped,
  guessKind,
  inspectRemote,
  parseSitemap,
  type WebsiteAuditOptions,
  type WebsiteAuditReport,
} from "./auditWebsite.js";

export {
  classifyInput,
  cleanFile,
  inspectFile,
  type CleanFileOptions,
  type FileCleanResult,
  type FileInspectResult,
  type InputKind,
  type RouterOptions,
} from "./router.js";

import { ensureText, type EnsureTextOptions } from "./ensureText.js";
import { inspectText, type InspectOptions, type TextInspectReport } from "./inspect.js";

export type CheckWatermarkResult =
  | { ok: true; report: TextInspectReport; watermarked: boolean }
  | { ok: false; reason: string };

/**
 * One shot convenience: validate the input is text, then inspect it.
 * Suitable as a backend request handler body or a frontend form check.
 */
export function checkWatermark(
  input: unknown,
  options: InspectOptions & EnsureTextOptions = {},
): CheckWatermarkResult {
  const guarded = ensureText(input, options);
  if (!guarded.ok) return guarded;
  const report = inspectText(guarded.text, options);
  return { ok: true, report, watermarked: report.suspiciousTotal > 0 };
}
