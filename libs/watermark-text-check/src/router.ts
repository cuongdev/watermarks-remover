/**
 * Unified inspect/clean routing by format.
 * Port of inspect_file.py / clean_file.py, adapted from file paths to
 * (filename, bytes) so it works in browsers and servers alike.
 */

import { cleanText, type CleanOptions, type CleanStats } from "./clean.js";
import {
  cleanContainer,
  detectContainerFormat,
  detectZipContainerFormat,
  inspectContainer,
  type CleanContainerResult,
  type ContainerInspectReport,
} from "./containerMeta.js";
import { ensureText, sniffBinary } from "./ensureText.js";
import {
  cleanImage,
  detectImageFormat,
  inspectImage,
  type CleanImageResult,
  type ImageInspectReport,
  type StripImageOptions,
} from "./imageMeta.js";
import { inspectText, type InspectOptions, type TextInspectReport } from "./inspect.js";
import { utf8Decode, utf8Encode } from "./markers.js";

export type InputKind = "text" | "image" | "container";

const IMAGE_EXTS = new Set([".png", ".jpg", ".jpeg"]);
const CONTAINER_EXTS = new Set([
  ".svg",
  ".pdf",
  ".docx",
  ".odt",
  ".html",
  ".htm",
  ".md",
  ".markdown",
  ".mdx",
]);
const TEXT_EXTS = new Set([
  ".txt",
  ".text",
  ".css",
  ".js",
  ".py",
  ".rs",
  ".go",
  ".json",
  ".yaml",
  ".yml",
  ".toml",
  ".csv",
]);

function extOf(filename: string | null): string {
  if (!filename) return "";
  return (filename.match(/\.[^./\\]+$/)?.[0] ?? "").toLowerCase();
}

/** Port of clean_file.classify: route by extension first, then magic bytes. */
export async function classifyInput(
  filename: string | null,
  data: Uint8Array,
): Promise<InputKind> {
  const ext = extOf(filename);
  if (IMAGE_EXTS.has(ext)) return "image";
  if (CONTAINER_EXTS.has(ext)) return "container";
  if (TEXT_EXTS.has(ext)) return "text";
  if (detectImageFormat(data) !== "unknown") return "image";
  if (detectContainerFormat(filename, data) !== "unknown") return "container";
  if ((await detectZipContainerFormat(data)) !== "unknown") return "container";
  return "text";
}

export type FileInspectResult =
  | { kind: "text"; report: TextInspectReport }
  | { kind: "image"; report: ImageInspectReport }
  | { kind: "container"; report: ContainerInspectReport }
  | { kind: "refused"; reason: string };

export interface RouterOptions extends InspectOptions {
  /** Force a kind instead of auto classification. */
  as?: InputKind;
  /** Treat unknown binary bytes as text anyway. */
  forceText?: boolean;
}

/** Unified inspect: routes to Layer A text, image metadata, or container. */
export async function inspectFile(
  data: Uint8Array | string,
  filename: string | null = null,
  options: RouterOptions = {},
): Promise<FileInspectResult> {
  const bytes = typeof data === "string" ? utf8Encode(data) : data;
  const kind = options.as ?? (await classifyInput(filename, bytes));

  if (kind === "text") {
    // classifyInput falls back to text for unrecognised bytes, so an unknown
    // binary would otherwise be decoded and scanned as garbage.
    if (!options.forceText) {
      const reason = sniffBinary(bytes);
      if (reason) {
        return {
          kind: "refused",
          reason: `refusing to treat input as text: it looks like ${reason}`,
        };
      }
    }
    const guarded = ensureText(bytes, { forceText: true });
    if (!guarded.ok) return { kind: "refused", reason: guarded.reason };
    return { kind: "text", report: inspectText(guarded.text, options) };
  }
  if (kind === "image") return { kind: "image", report: inspectImage(bytes) };
  return { kind: "container", report: await inspectContainer(bytes, filename) };
}

export type FileCleanResult =
  | { kind: "text"; text: string; data: Uint8Array; stats: CleanStats }
  | ({ kind: "image" } & CleanImageResult)
  | ({ kind: "container" } & CleanContainerResult)
  | { kind: "refused"; reason: string };

export interface CleanFileOptions extends CleanOptions, StripImageOptions {
  as?: InputKind;
  forceText?: boolean;
  /** Container option: Layer A scrub of markdown/html bodies (default true). */
  alsoLayerAText?: boolean;
}

/** Unified clean: Layer A text, PNG/JPEG metadata, or document containers. */
export async function cleanFile(
  data: Uint8Array | string,
  filename: string | null = null,
  options: CleanFileOptions = {},
): Promise<FileCleanResult> {
  const bytes = typeof data === "string" ? utf8Encode(data) : data;
  const kind = options.as ?? (await classifyInput(filename, bytes));

  if (kind === "text") {
    if (!options.forceText) {
      const reason = sniffBinary(bytes);
      if (reason) {
        return {
          kind: "refused",
          reason: `refusing to clean input as text: it looks like ${reason}`,
        };
      }
    }
    const text = utf8Decode(bytes);
    const { text: cleaned, stats } = cleanText(text, options);
    return { kind: "text", text: cleaned, data: utf8Encode(cleaned), stats };
  }
  if (kind === "image") {
    return { kind: "image", ...cleanImage(bytes, options) };
  }
  return {
    kind: "container",
    ...(await cleanContainer(bytes, filename, { alsoLayerAText: options.alsoLayerAText })),
  };
}
