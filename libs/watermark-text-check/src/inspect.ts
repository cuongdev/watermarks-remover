/**
 * Layer A inspection: report invisible Unicode / space homoglyph carriers.
 * Port of inspect_text in text_unicode.py.
 */

import {
  charLabel,
  decide,
  hitConfidence,
  isGlue,
  type HitKind,
} from "./classify.js";

export interface CharHit {
  codepoint: number;
  char: string;
  label: string;
  count: number;
  kind: HitKind;
  confidence: "informational" | "probable";
  /** Codepoint offsets (matches the Python reports), first 10. */
  samples: number[];
  /** UTF-16 code unit offsets for string slicing / highlighting, first 10. */
  samplesUtf16: number[];
}

export interface TextInspectReport {
  /** Length in codepoints (matches Python len(text)). */
  length: number;
  suspiciousTotal: number;
  hits: CharHit[];
  notes: string[];
}

export interface InspectOptions {
  /** Also flag Latin confusable / fullwidth lookalikes. */
  aggressive?: boolean;
  /** Paranoid: flag load bearing invisibles too (emoji glue, script joiners, flag tags, fillers, orthographic Cf). */
  stripEmojiGlue?: boolean;
}

export function inspectText(text: string, options: InspectOptions = {}): TextInspectReport {
  const { aggressive = false, stripEmojiGlue = false } = options;

  const buckets = new Map<string, { cp: number; kind: HitKind; cpOffsets: number[]; u16Offsets: number[] }>();
  let prevKept: number | null = null;
  let cpIndex = 0;
  let u16Index = 0;

  for (const ch of text) {
    const cp = ch.codePointAt(0) as number;
    const d = decide(cp, prevKept, {
      normalizeSpaces: true,
      treatConfusables: aggressive,
      stripEmojiGlue,
    });
    if (d.kind === null) {
      // Kept; glue (emoji/script joiner/tag) does not advance the
      // "previous kept" base so ZWJ chains and flag runs stay bound.
      if (!isGlue(cp)) prevKept = cp;
    } else {
      const key = `${cp}:${d.kind}`;
      let bucket = buckets.get(key);
      if (!bucket) {
        bucket = { cp, kind: d.kind, cpOffsets: [], u16Offsets: [] };
        buckets.set(key, bucket);
      }
      bucket.cpOffsets.push(cpIndex);
      bucket.u16Offsets.push(u16Index);
      if (d.action === "replace") prevKept = d.outChar.codePointAt(0) as number;
      // strip: prevKept unchanged
    }
    cpIndex += 1;
    u16Index += ch.length;
  }

  const sorted = [...buckets.values()].sort(
    (a, b) => b.cpOffsets.length - a.cpOffsets.length || a.cp - b.cp,
  );

  let total = 0;
  const hits: CharHit[] = sorted.map((b) => {
    total += b.cpOffsets.length;
    return {
      codepoint: b.cp,
      char: String.fromCodePoint(b.cp),
      label: charLabel(b.cp),
      count: b.cpOffsets.length,
      kind: b.kind,
      confidence: hitConfidence(b.kind),
      samples: b.cpOffsets.slice(0, 10),
      samplesUtf16: b.u16Offsets.slice(0, 10),
    };
  });

  const notes = [
    "Layer A only: invisible/format Unicode and space homoglyphs (edit based carriers).",
    "Statistical (token sampling) watermarks are not detectable here; use a Layer B rewrite.",
    "Inspect kinds: strip, bidi, tag_chars, variation_selector, zwj_family, private_use, space, confusable, other_cf.",
    "Load bearing invisibles are preserved by default: emoji glue (ZWJ/VS after an emoji base), script joiners (ZWNJ/ZWJ inside complex scripts), flag tag chars, same script fillers/selectors, and orthographic Arabic/Syriac Cf marks. Use stripEmojiGlue for paranoid mode.",
  ];
  if (hits.length === 0) {
    notes.push(
      "No deterministic Layer A (invisible Unicode/format) carriers detected; " +
        "statistical and pixel domain marks are out of scope here.",
    );
  }

  return { length: cpIndex, suspiciousTotal: total, hits, notes };
}

/** Convenience: true when any Layer A carrier is present. */
export function hasWatermarkCarriers(text: string, options: InspectOptions = {}): boolean {
  return inspectText(text, options).suspiciousTotal > 0;
}

/** One suspicious character located in the source text, in reading order. */
export interface TextMark {
  /** Codepoint offset (matches the Python reports). */
  index: number;
  /** UTF-16 code unit offset, for slicing/highlighting JavaScript strings. */
  utf16Index: number;
  /** UTF-16 code unit length of the source character (2 for astral). */
  utf16Length: number;
  codepoint: number;
  char: string;
  label: string;
  kind: HitKind;
  confidence: "informational" | "probable";
  action: "strip" | "replace";
  /** Surviving character for a replace (e.g. a normal space); "" for strip. */
  replacement: string;
}

/**
 * Locate every suspicious character (not just the first ten per class that
 * inspectText samples). Returns marks in reading order, which is what a UI
 * needs to render the source with each hidden character shown in place.
 */
export function scanText(text: string, options: InspectOptions = {}): TextMark[] {
  const { aggressive = false, stripEmojiGlue = false } = options;
  const marks: TextMark[] = [];
  let prevKept: number | null = null;
  let cpIndex = 0;
  let u16Index = 0;
  for (const ch of text) {
    const cp = ch.codePointAt(0) as number;
    const d = decide(cp, prevKept, {
      normalizeSpaces: true,
      treatConfusables: aggressive,
      stripEmojiGlue,
    });
    if (d.kind === null) {
      if (!isGlue(cp)) prevKept = cp;
    } else {
      marks.push({
        index: cpIndex,
        utf16Index: u16Index,
        utf16Length: ch.length,
        codepoint: cp,
        char: ch,
        label: charLabel(cp),
        kind: d.kind,
        confidence: hitConfidence(d.kind),
        action: d.action === "replace" ? "replace" : "strip",
        replacement: d.action === "replace" ? d.outChar : "",
      });
      if (d.action === "replace") prevKept = d.outChar.codePointAt(0) as number;
    }
    cpIndex += 1;
    u16Index += ch.length;
  }
  return marks;
}

/** JSON shape matching the Python report.to_dict(), for cross stack parity. */
export function reportToJson(report: TextInspectReport): {
  length: number;
  suspicious_total: number;
  hits: Array<{
    codepoint: string;
    label: string;
    count: number;
    kind: HitKind;
    confidence: string;
    sample_offsets: number[];
  }>;
  notes: string[];
} {
  return {
    length: report.length,
    suspicious_total: report.suspiciousTotal,
    hits: report.hits.map((h) => ({
      codepoint: `U+${h.codepoint.toString(16).toUpperCase().padStart(4, "0")}`,
      label: h.label,
      count: h.count,
      kind: h.kind,
      confidence: h.confidence,
      sample_offsets: h.samples,
    })),
    notes: report.notes,
  };
}
