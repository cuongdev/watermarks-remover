/**
 * Aggregate AI provenance audit over the URLs listed in a sitemap.
 * Port of audit_website.py using fetch instead of urllib. Downloads each
 * URL with a byte cap, classifies it by content type, suffix, then magic
 * bytes, and runs the same deterministic inspections as the local audit.
 *
 * Guardrails: http(s) URLs only, per response byte caps, bounded page
 * count, bounded sitemap index recursion. This is meant for auditing sites
 * you own or operate; respect robots and applicable terms before scanning
 * third party hosts.
 */

import {
  aggregate,
  scanItem,
  type AuditItem,
  type AuditSummary,
} from "./audit.js";
import { bytesToLatin1, utf8Decode } from "./markers.js";

export const DEFAULT_MAX_BYTES = 4 << 20;
export const DEFAULT_TIMEOUT_MS = 15_000;
export const DEFAULT_MAX_PAGES = 200;
export const AUDIT_USER_AGENT = "remove-ai-marks-audit/1.0";

type FetchLike = typeof fetch;

const EXT_FOR_KIND: Record<string, string> = {
  png: ".png",
  jpeg: ".jpg",
  svg: ".svg",
  pdf: ".pdf",
  docx: ".docx",
  odt: ".odt",
  html: ".html",
  markdown: ".md",
  text: ".txt",
};

/** Classify a downloaded URL from headers, suffix, then magic bytes. */
export function guessKind(
  url: string,
  data: Uint8Array,
  contentType: string | null = null,
): string {
  const ct = (contentType ?? "").toLowerCase().split(";")[0]!.trim();
  if (ct.includes("html")) return "html";
  if (ct === "image/png") return "png";
  if (ct === "image/jpeg") return "jpeg";
  if (ct.includes("svg")) return "svg";
  if (ct === "application/pdf") return "pdf";
  if (ct.includes("wordprocessingml")) return "docx";
  if (ct.includes("opendocument.text")) return "odt";
  if (ct.includes("markdown")) return "markdown";
  if (ct === "text/plain") return "text";

  let path = "";
  try {
    path = new URL(url).pathname.toLowerCase();
  } catch {
    path = url.toLowerCase();
  }
  const suffixKinds: Array<[string, string]> = [
    [".png", "png"],
    [".jpg", "jpeg"],
    [".jpeg", "jpeg"],
    [".svg", "svg"],
    [".pdf", "pdf"],
    [".docx", "docx"],
    [".odt", "odt"],
    [".html", "html"],
    [".htm", "html"],
    [".md", "markdown"],
    [".markdown", "markdown"],
    [".txt", "text"],
  ];
  for (const [ext, kind] of suffixKinds) {
    if (path.endsWith(ext)) return kind;
  }

  const head = bytesToLatin1(data.subarray(0, 2000));
  if (head.startsWith("\x89PNG")) return "png";
  if (head.startsWith("\xff\xd8")) return "jpeg";
  if (head.startsWith("%PDF")) return "pdf";
  const head100 = head.slice(0, 100).trimStart();
  if (head100.startsWith("<") && head.slice(0, 500).toLowerCase().includes("svg")) return "svg";
  if (head.toLowerCase().includes("<html") || head100.toLowerCase().startsWith("<")) return "html";
  return "text";
}

async function gunzip(data: Uint8Array): Promise<Uint8Array> {
  const ds = new DecompressionStream("gzip");
  const stream = new Blob([data as BlobPart]).stream().pipeThrough(ds);
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

/** Parse a (possibly gzip compressed) sitemap into (kind, urls). */
export async function parseSitemap(
  data: Uint8Array,
): Promise<{ kind: string; urls: string[] }> {
  let bytes = data;
  if (bytes.length >= 2 && bytes[0] === 0x1f && bytes[1] === 0x8b) {
    bytes = await gunzip(bytes);
  }
  const text = utf8Decode(bytes);
  const rootMatch = /<\s*(?:[A-Za-z0-9_-]+:)?([A-Za-z0-9_-]+)/.exec(
    text.replace(/<\?[\s\S]*?\?>/g, "").replace(/<!--[\s\S]*?-->/g, ""),
  );
  if (!rootMatch) throw new Error("not an XML sitemap");
  const kind = rootMatch[1] as string;
  const urls: string[] = [];
  for (const m of text.matchAll(/<(?:[A-Za-z0-9_-]+:)?loc[^>]*>([\s\S]*?)<\/(?:[A-Za-z0-9_-]+:)?loc>/gi)) {
    const loc = (m[1] as string).trim();
    if (loc) urls.push(loc);
  }
  return { kind, urls };
}

function assertHttpUrl(url: string): void {
  const u = new URL(url);
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new Error(`refusing non-http(s) URL: ${url}`);
  }
}

/** Fetch a URL with a hard byte cap; returns (body, contentType). */
export async function fetchCapped(
  url: string,
  options: { timeoutMs?: number; maxBytes?: number; fetchImpl?: FetchLike } = {},
): Promise<{ data: Uint8Array; contentType: string | null }> {
  assertHttpUrl(url);
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;
  const fetchImpl = options.fetchImpl ?? fetch;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetchImpl(url, {
      headers: { "User-Agent": AUDIT_USER_AGENT },
      signal: controller.signal,
    });
    if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
    const contentType = resp.headers.get("Content-Type");
    if (!resp.body) {
      const buf = new Uint8Array(await resp.arrayBuffer());
      if (buf.length > maxBytes) throw new Error(`exceeds ${maxBytes} bytes`);
      return { data: buf, contentType };
    }
    const reader = resp.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > maxBytes) {
        await reader.cancel();
        throw new Error(`exceeds ${maxBytes} bytes`);
      }
      chunks.push(value);
    }
    const out = new Uint8Array(total);
    let off = 0;
    for (const c of chunks) {
      out.set(c, off);
      off += c.length;
    }
    return { data: out, contentType };
  } finally {
    clearTimeout(timer);
  }
}

/** Inspect downloaded bytes using the local scanItem pipeline. */
export async function inspectRemote(
  url: string,
  data: Uint8Array,
  contentType: string | null = null,
): Promise<AuditItem> {
  const kind = guessKind(url, data, contentType);
  const ext = EXT_FOR_KIND[kind] ?? ".bin";
  // The synthetic name routes classifyInput by extension, like the Python
  // temp file with a kind derived suffix.
  const item = await scanItem(data, `asset${ext}`);
  item.path = url;
  item.kind = kind;
  return item;
}

/** Find a sitemap for baseUrl via /sitemap.xml then /robots.txt. */
export async function discoverSitemap(
  baseUrl: string,
  options: { timeoutMs?: number; fetchImpl?: FetchLike } = {},
): Promise<string | null> {
  const base = baseUrl.replace(/\/+$/, "");
  for (const candidate of [`${base}/sitemap.xml`, `${base}/sitemap_index.xml`]) {
    try {
      const { data } = await fetchCapped(candidate, options);
      await parseSitemap(data);
      return candidate;
    } catch {
      continue;
    }
  }
  try {
    const { data } = await fetchCapped(`${base}/robots.txt`, {
      ...options,
      maxBytes: 1 << 20,
    });
    for (const line of utf8Decode(data).split(/\r?\n/)) {
      if (line.toLowerCase().startsWith("sitemap:")) {
        return line.split(/:(.*)/s)[1]!.trim();
      }
    }
  } catch {
    // no robots.txt either
  }
  return null;
}

/** Collect page/asset URLs from a sitemap, following nested indexes. */
export async function collectUrls(
  sitemapUrl: string,
  options: { timeoutMs?: number; maxPages?: number; fetchImpl?: FetchLike } = {},
): Promise<string[]> {
  const maxPages = options.maxPages ?? DEFAULT_MAX_PAGES;
  const urls: string[] = [];
  const seen = new Set<string>();

  const recurse = async (url: string, depth: number): Promise<void> => {
    if (urls.length >= maxPages || depth > 3) return;
    const { data } = await fetchCapped(url, options);
    const { kind, urls: locs } = await parseSitemap(data);
    if (kind === "sitemapindex") {
      for (const loc of locs) {
        if (!seen.has(loc)) {
          seen.add(loc);
          await recurse(loc, depth + 1);
        }
      }
    } else {
      for (const loc of locs) {
        if (!seen.has(loc)) {
          seen.add(loc);
          urls.push(loc);
        }
      }
    }
  };

  await recurse(sitemapUrl, 0);
  return urls;
}

export interface WebsiteAuditReport {
  sitemap: string;
  urlsCollected: number;
  urlsScanned: number;
  urlsFailed: Array<{ url: string; error: string }>;
  summary: AuditSummary;
  items: AuditItem[];
}

export interface WebsiteAuditOptions {
  /** Sitemap URL to audit; alternatively pass baseUrl for discovery. */
  sitemapUrl?: string;
  /** Base URL; the sitemap is discovered via /sitemap.xml then robots.txt. */
  baseUrl?: string;
  maxPages?: number;
  timeoutMs?: number;
  maxBytes?: number;
  fetchImpl?: FetchLike;
}

/** Port of the audit_website.py main flow. */
export async function auditWebsite(
  options: WebsiteAuditOptions,
): Promise<WebsiteAuditReport> {
  let sitemapUrl = options.sitemapUrl;
  if (!sitemapUrl) {
    if (!options.baseUrl) throw new Error("provide sitemapUrl or baseUrl");
    const discovered = await discoverSitemap(options.baseUrl, options);
    if (!discovered) throw new Error(`no sitemap found for ${options.baseUrl}`);
    sitemapUrl = discovered;
  }

  const urls = await collectUrls(sitemapUrl, options);
  if (!urls.length) throw new Error("no URLs collected from sitemap");

  const items: AuditItem[] = [];
  const failures: Array<{ url: string; error: string }> = [];
  const maxPages = options.maxPages ?? DEFAULT_MAX_PAGES;
  for (const url of urls.slice(0, maxPages)) {
    let fetched: { data: Uint8Array; contentType: string | null };
    try {
      fetched = await fetchCapped(url, options);
    } catch (e) {
      failures.push({ url, error: String(e) });
      continue;
    }
    try {
      items.push(await inspectRemote(url, fetched.data, fetched.contentType));
    } catch (e) {
      failures.push({ url, error: `inspect failed: ${String(e)}` });
    }
  }

  return {
    sitemap: sitemapUrl,
    urlsCollected: urls.length,
    urlsScanned: items.length,
    urlsFailed: failures,
    summary: aggregate(items),
    items,
  };
}
