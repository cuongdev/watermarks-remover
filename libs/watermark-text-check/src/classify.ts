/**
 * Per character classification shared by inspect and clean.
 * Port of the _decide pipeline in text_unicode.py, with Unicode property
 * escapes standing in for Python's unicodedata.category.
 */

import {
  BIDI_CPS,
  CODEPOINT_NAMES,
  EMOJI_GLUE_CODEPOINTS,
  HANGUL_FILLERS,
  KHMER_VOWELS,
  LATIN_CONFUSABLES,
  MONGOLIAN_FVS,
  ORTHOGRAPHIC_CF,
  SCRIPT_JOINERS,
  SPACE_HOMOGLYPHS,
  STRIP_CODEPOINTS,
  ZW_FAMILY,
  isPrivateUse,
  isTagChar,
  isTagGlue,
  isVsSupplement,
} from "./tables.js";

export type HitKind =
  | "strip"
  | "bidi"
  | "tag_chars"
  | "variation_selector"
  | "zwj_family"
  | "private_use"
  | "space"
  | "confusable"
  | "other_cf";

export type Action = "keep" | "strip" | "replace";

export interface Decision {
  action: Action;
  /** Surviving character for keep/replace, empty string for strip. */
  outChar: string;
  /** Inspect classification, null when the character is not suspicious. */
  kind: HitKind | null;
}

export interface ClassifyOptions {
  normalizeSpaces: boolean;
  treatConfusables: boolean;
  stripEmojiGlue: boolean;
}

const FORMAT_RE = /\p{Cf}/u;
const LETTER_OR_MARK_RE = /[\p{L}\p{M}]/u;
const LETTER_RE = /\p{L}/u;

function isFormatChar(cp: number): boolean {
  return FORMAT_RE.test(String.fromCodePoint(cp));
}

/** Non ASCII letter/mark, the neighbour that makes a joiner orthographic. */
function isJoiningLetter(cp: number): boolean {
  return cp > 0x7f && LETTER_OR_MARK_RE.test(String.fromCodePoint(cp));
}

function isMongolianLetter(cp: number): boolean {
  return cp >= 0x1800 && cp <= 0x18af && LETTER_RE.test(String.fromCodePoint(cp));
}

function isKhmerLetter(cp: number): boolean {
  return cp >= 0x1780 && cp <= 0x17ff && LETTER_RE.test(String.fromCodePoint(cp));
}

function isHangulJamo(cp: number): boolean {
  return (
    (cp >= 0x1100 && cp <= 0x11ff) ||
    (cp >= 0xa960 && cp <= 0xa97c) || // Hangul Jamo Extended A
    (cp >= 0xd7b0 && cp <= 0xd7c6) // Hangul Jamo Extended B
  );
}

function isEmojiGlue(cp: number): boolean {
  return EMOJI_GLUE_CODEPOINTS.has(cp);
}

/** True for characters that can start or continue an emoji sequence. */
export function isEmojiBase(cp: number): boolean {
  if (cp >= 0x1f000 && cp <= 0x1faff) return true;
  if (cp >= 0x2600 && cp <= 0x27bf) return true; // misc symbols / dingbats / arrows
  if (cp >= 0x2b00 && cp <= 0x2bff) return true; // misc symbols and arrows
  if ([0x00a9, 0x00ae, 0x2122, 0x3030, 0x303d, 0x3297, 0x3299].includes(cp)) return true;
  if (cp === 0x0023 || cp === 0x002a || (cp >= 0x0030 && cp <= 0x0039)) return true; // keycap bases
  return false;
}

/**
 * Load bearing invisible char: emoji glue, script joiner, flag tag char,
 * or same script filler/selector. Glue never advances the "previous kept"
 * base, so ZWJ chains and flag runs stay bound to their emoji base.
 */
export function isGlue(cp: number): boolean {
  return (
    isEmojiGlue(cp) ||
    SCRIPT_JOINERS.has(cp) ||
    isTagGlue(cp) ||
    MONGOLIAN_FVS.has(cp) ||
    KHMER_VOWELS.has(cp) ||
    HANGUL_FILLERS.has(cp)
  );
}

function isStripCp(cp: number): boolean {
  if (STRIP_CODEPOINTS.has(cp)) return true;
  if (isVsSupplement(cp)) return true;
  if (isTagChar(cp)) return true;
  if (isPrivateUse(cp)) return true;
  return false;
}

/** Finer grained inspect kind for strip class codepoints. */
function stripKind(cp: number): HitKind {
  if (isTagChar(cp)) return "tag_chars";
  if (isVsSupplement(cp) || (cp >= 0xfe00 && cp <= 0xfe0f) || (cp >= 0x180b && cp <= 0x180d)) {
    return "variation_selector";
  }
  if (BIDI_CPS.has(cp)) return "bidi";
  if (ZW_FAMILY.has(cp)) return "zwj_family";
  if (isPrivateUse(cp)) return "private_use";
  return "strip";
}

/**
 * Classify one input codepoint given the previous kept codepoint.
 * prevKept is null at start of text (and stays put across stripped chars).
 */
export function decide(
  cp: number,
  prevKept: number | null,
  opts: ClassifyOptions,
): Decision {
  const ch = String.fromCodePoint(cp);
  if (isEmojiGlue(cp) && !opts.stripEmojiGlue) {
    if (prevKept !== null && isEmojiBase(prevKept)) {
      return { action: "keep", outChar: ch, kind: null };
    }
  }
  if (!opts.stripEmojiGlue) {
    if (SCRIPT_JOINERS.has(cp) && prevKept !== null && isJoiningLetter(prevKept)) {
      return { action: "keep", outChar: ch, kind: null };
    }
    if (isTagGlue(cp) && prevKept !== null && isEmojiBase(prevKept)) {
      return { action: "keep", outChar: ch, kind: null };
    }
    if (MONGOLIAN_FVS.has(cp) && prevKept !== null && isMongolianLetter(prevKept)) {
      return { action: "keep", outChar: ch, kind: null };
    }
    if (KHMER_VOWELS.has(cp) && prevKept !== null && isKhmerLetter(prevKept)) {
      return { action: "keep", outChar: ch, kind: null };
    }
    if (HANGUL_FILLERS.has(cp) && prevKept !== null && isHangulJamo(prevKept)) {
      return { action: "keep", outChar: ch, kind: null };
    }
    if (ORTHOGRAPHIC_CF.has(cp)) {
      return { action: "keep", outChar: ch, kind: null };
    }
  }
  if (isStripCp(cp)) {
    return { action: "strip", outChar: "", kind: stripKind(cp) };
  }
  if (opts.normalizeSpaces && SPACE_HOMOGLYPHS.has(cp)) {
    return { action: "replace", outChar: SPACE_HOMOGLYPHS.get(cp) as string, kind: "space" };
  }
  if (opts.treatConfusables && LATIN_CONFUSABLES.has(cp)) {
    return { action: "replace", outChar: LATIN_CONFUSABLES.get(cp) as string, kind: "confusable" };
  }
  if (isFormatChar(cp) && !SPACE_HOMOGLYPHS.has(cp)) {
    return { action: "strip", outChar: "", kind: "other_cf" };
  }
  return { action: "keep", outChar: ch, kind: null };
}

/** Label like "U+200B ZERO WIDTH SPACE"; falls back to the bare codepoint. */
export function charLabel(cp: number): string {
  const hex = cp.toString(16).toUpperCase().padStart(4, "0");
  const name = CODEPOINT_NAMES.get(cp);
  return name ? `U+${hex} ${name}` : `U+${hex}`;
}

/** Layer A hits are edit based carriers; space homoglyphs are weaker context. */
export function hitConfidence(kind: HitKind): "informational" | "probable" {
  return kind === "space" ? "informational" : "probable";
}
