/**
 * Layer A cleaning: strip carriers, normalize space homoglyphs.
 * Port of clean_text in text_unicode.py.
 */

import { charLabel, decide, isGlue } from "./classify.js";

export interface CleanOptions {
  /** Apply NFKC normalization after cleaning. */
  nfkc?: boolean;
  /** Replace Latin confusable / fullwidth lookalikes. */
  aggressiveHomoglyphs?: boolean;
  /** Replace exotic spaces with U+0020 (default true). */
  normalizeSpaces?: boolean;
  /** Paranoid: strip load bearing invisibles too. */
  stripEmojiGlue?: boolean;
}

export interface CleanStats {
  inputLength: number;
  outputLength: number;
  removed: Record<string, number>;
  replaced: Record<string, number>;
  removedCount: number;
  replacedCount: number;
}

export interface CleanResult {
  text: string;
  stats: CleanStats;
}

export function cleanText(text: string, options: CleanOptions = {}): CleanResult {
  const {
    nfkc = false,
    aggressiveHomoglyphs = false,
    normalizeSpaces = true,
    stripEmojiGlue = false,
  } = options;

  const removed = new Map<string, number>();
  const replaced = new Map<string, number>();
  const outChars: string[] = [];
  let prevKept: number | null = null;
  let inputLength = 0;

  for (const ch of text) {
    inputLength += 1;
    const cp = ch.codePointAt(0) as number;
    const d = decide(cp, prevKept, {
      normalizeSpaces,
      treatConfusables: aggressiveHomoglyphs,
      stripEmojiGlue,
    });
    if (d.action === "keep") {
      outChars.push(d.outChar);
      // Glue does not advance the "previous kept" base, so ZWJ chains
      // and flag runs stay bound.
      if (!isGlue(cp)) prevKept = cp;
    } else if (d.action === "replace") {
      outChars.push(d.outChar);
      const label = charLabel(cp);
      replaced.set(label, (replaced.get(label) ?? 0) + 1);
      prevKept = d.outChar.codePointAt(0) as number;
    } else {
      const label = charLabel(cp);
      removed.set(label, (removed.get(label) ?? 0) + 1);
      // prevKept unchanged
    }
  }

  let result = outChars.join("");
  if (nfkc) {
    const before = result;
    result = result.normalize("NFKC");
    if (result !== before) {
      const delta = Math.abs([...before].length - [...result].length) || 1;
      replaced.set("NFKC_normalize", delta);
    }
  }

  let replacedCount = 0;
  for (const [label, count] of replaced) {
    if (label !== "NFKC_normalize") replacedCount += count;
  }
  let removedCount = 0;
  for (const count of removed.values()) removedCount += count;

  return {
    text: result,
    stats: {
      inputLength,
      outputLength: [...result].length,
      removed: Object.fromEntries(removed),
      replaced: Object.fromEntries(replaced),
      removedCount,
      replacedCount,
    },
  };
}
