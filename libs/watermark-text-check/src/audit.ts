/**
 * Aggregate AI provenance audit over a set of items.
 * Port of audit_lib.py (and the aggregation half of audit_dir.py).
 *
 * The filesystem walk in audit_dir.py is Node specific, so this module
 * takes an already collected list of (name, bytes) items and stays
 * isomorphic; a Node caller walks the tree itself (example in the README)
 * and a browser caller passes dropped Files. DEFAULT_SKIP_DIRS is exported
 * so walkers can share the Python default skip list.
 */

import { inspectContainer } from "./containerMeta.js";
import { inspectImage } from "./imageMeta.js";
import { inspectText } from "./inspect.js";
import {
  CONFIDENCE_LEVELS,
  classifyFindingConfidence,
  utf8Decode,
  utf8Encode,
  type FindingConfidence,
} from "./markers.js";
import { classifyInput } from "./router.js";

export const DEFAULT_SKIP_DIRS: ReadonlySet<string> = new Set([
  ".git",
  ".hg",
  ".svn",
  "node_modules",
  "__pycache__",
  ".venv",
  "venv",
  ".tox",
  ".mypy_cache",
  ".pytest_cache",
  "dist",
  "build",
  ".next",
  "target",
  ".cache",
]);

export interface AuditItem {
  path: string;
  kind: string;
  error?: string;
  hasC2pa: boolean;
  hasAiMetadata: boolean;
  suspiciousTotal: number;
  findings: string[];
  confidence: FindingConfidence[];
  notes: string[];
}

/** Layer A space homoglyphs are weaker context than invisible carriers. */
function textHitConfidence(kind: string): FindingConfidence {
  return kind === "space" ? "informational" : "probable";
}

function textFindings(text: string): {
  findings: string[];
  confidences: FindingConfidence[];
  suspicious: number;
} {
  const report = inspectText(text);
  const findings: string[] = [];
  const confidences: FindingConfidence[] = [];
  for (const h of report.hits) {
    findings.push(`layer-a [${h.kind}] ${h.label} x${h.count}`);
    confidences.push(textHitConfidence(h.kind));
  }
  return { findings, confidences, suspicious: report.suspiciousTotal };
}

/** Inspect one item and return a normalized audit entry (audit_lib.scan_file). */
export async function scanItem(
  data: Uint8Array | string,
  name: string,
): Promise<AuditItem> {
  const bytes = typeof data === "string" ? utf8Encode(data) : data;
  const kind = await classifyInput(name, bytes);

  if (kind === "text") {
    const text = typeof data === "string" ? data : utf8Decode(bytes);
    const { findings, confidences, suspicious } = textFindings(text);
    return {
      path: name,
      kind: "text",
      hasC2pa: false,
      hasAiMetadata: false,
      suspiciousTotal: suspicious,
      findings,
      confidence: confidences,
      notes: [],
    };
  }

  if (kind === "image") {
    const report = inspectImage(bytes);
    return {
      path: name,
      kind: report.format,
      hasC2pa: report.hasC2pa,
      hasAiMetadata: report.hasAiMetadata,
      suspiciousTotal: 0,
      findings: report.findings,
      confidence: report.findings.map(classifyFindingConfidence),
      notes: report.notes,
    };
  }

  const report = await inspectContainer(bytes, name);
  const findings = [...report.findings];
  const confidences = report.findings.map(classifyFindingConfidence);
  let suspicious = 0;

  // Text bearing containers also get a Layer A scan of their visible text,
  // mirroring the skill's "container + Layer A" workflow.
  if (report.format === "html" || report.format === "markdown") {
    const text = utf8Decode(bytes);
    if (text) {
      const t = textFindings(text);
      findings.push(...t.findings);
      confidences.push(...t.confidences);
      suspicious = t.suspicious;
    }
  }

  return {
    path: name,
    kind: report.format,
    hasC2pa: report.hasC2pa,
    hasAiMetadata: report.hasAiMetadata,
    suspiciousTotal: suspicious,
    findings,
    confidence: confidences,
    notes: report.notes,
  };
}

/** An item is actionable when it has a confirmed/probable finding or C2PA. */
export function isActionable(item: AuditItem): boolean {
  if (item.hasC2pa) return true;
  return item.confidence.some((c) => c === "confirmed" || c === "probable");
}

export interface AuditSummary {
  total: number;
  byKind: Record<string, number>;
  withC2pa: number;
  withAiMetadata: number;
  withSuspiciousText: number;
  actionableFiles: number;
  findingsByConfidence: Record<FindingConfidence, number>;
}

/** Build the summary block shared by directory and website audits. */
export function aggregate(items: AuditItem[]): AuditSummary {
  const summary: AuditSummary = {
    total: items.length,
    byKind: {},
    withC2pa: 0,
    withAiMetadata: 0,
    withSuspiciousText: 0,
    actionableFiles: 0,
    findingsByConfidence: Object.fromEntries(
      CONFIDENCE_LEVELS.map((c) => [c, 0]),
    ) as Record<FindingConfidence, number>,
  };
  for (const item of items) {
    const kind = item.kind || "error";
    summary.byKind[kind] = (summary.byKind[kind] ?? 0) + 1;
    if (item.hasC2pa) summary.withC2pa += 1;
    if (item.hasAiMetadata) summary.withAiMetadata += 1;
    if (item.suspiciousTotal > 0) summary.withSuspiciousText += 1;
    for (const c of item.confidence) {
      if (c in summary.findingsByConfidence) summary.findingsByConfidence[c] += 1;
    }
    if (isActionable(item)) summary.actionableFiles += 1;
  }
  return summary;
}

export interface AuditReport {
  itemsScanned: number;
  itemsSkipped: Array<{ path: string; reason: string }>;
  summary: AuditSummary;
  items: AuditItem[];
}

export interface AuditInput {
  name: string;
  data: Uint8Array | string;
}

/**
 * Audit a collected set of items (port of the audit_dir.py loop, minus the
 * Node only filesystem walk). One bad item never aborts the audit.
 */
export async function auditItems(
  inputs: AuditInput[],
  options: { maxBytes?: number } = {},
): Promise<AuditReport> {
  const maxBytes = options.maxBytes ?? 256 << 20;
  const items: AuditItem[] = [];
  const skipped: Array<{ path: string; reason: string }> = [];
  for (const input of inputs) {
    try {
      const size =
        typeof input.data === "string" ? input.data.length : input.data.length;
      if (size > maxBytes) {
        skipped.push({ path: input.name, reason: "too large" });
        continue;
      }
      items.push(await scanItem(input.data, input.name));
    } catch (e) {
      skipped.push({ path: input.name, reason: String(e) });
    }
  }
  return {
    itemsScanned: items.length,
    itemsSkipped: skipped,
    summary: aggregate(items),
    items,
  };
}

/** Shared plain text rendering (audit_lib.print_human_report, returned as a string). */
export function renderAuditReport(
  items: AuditItem[],
  summary: AuditSummary,
  extraHeader: Record<string, string> = {},
): string {
  const lines: string[] = [];
  for (const [key, value] of Object.entries(extraHeader)) lines.push(`${key}: ${value}`);
  lines.push(`Files scanned: ${summary.total}`);
  lines.push(`By kind: ${JSON.stringify(summary.byKind)}`);
  lines.push(`With C2PA: ${summary.withC2pa}`);
  lines.push(`With AI metadata: ${summary.withAiMetadata}`);
  lines.push(`With suspicious text: ${summary.withSuspiciousText}`);
  lines.push(`Actionable files: ${summary.actionableFiles}`);
  lines.push(`Findings by confidence: ${JSON.stringify(summary.findingsByConfidence)}`);
  for (const item of items) {
    item.findings.forEach((msg, i) => {
      lines.push(`  [${item.confidence[i] ?? "informational"}] ${item.path}: ${msg}`);
    });
  }
  return lines.join("\n");
}
