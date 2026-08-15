/**
 * Codepoint tables for Layer A detection.
 * Direct port of skills/remove-ai-marks/scripts/text_unicode.py.
 * Keep the two files in sync when either side changes.
 */

/** Format / invisible controls commonly used for steganography or broken pastes. */
export const STRIP_CODEPOINTS: ReadonlySet<number> = new Set([
  0x00ad, // soft hyphen
  0x034f, // combining grapheme joiner
  0x061c, // Arabic letter mark
  0x115f, // Hangul choseong filler
  0x1160, // Hangul jungseong filler
  0x17b4, // Khmer vowel inherent AQ
  0x17b5, // Khmer vowel inherent AA
  0x180b, // Mongolian free variation selector 1
  0x180c,
  0x180d,
  0x180e, // Mongolian vowel separator
  0x200b, // zero width space
  0x200c, // zero width non joiner
  0x200d, // zero width joiner
  0x200e, // LRM
  0x200f, // RLM
  0x202a, // LRE
  0x202b, // RLE
  0x202c, // PDF (pop directional formatting)
  0x202d, // LRO
  0x202e, // RLO
  0x2060, // word joiner
  0x2061, // function application
  0x2062, // invisible times
  0x2063, // invisible separator
  0x2064, // invisible plus
  0x2066, // LRI
  0x2067, // RLI
  0x2068, // FSI
  0x2069, // PDI
  0x206a, // inhibit symmetric swapping
  0x206b,
  0x206c,
  0x206d,
  0x206e,
  0x206f,
  0xfeff, // BOM / ZWNBSP
  0xfe00, // variation selectors VS1..VS16
  0xfe01,
  0xfe02,
  0xfe03,
  0xfe04,
  0xfe05,
  0xfe06,
  0xfe07,
  0xfe08,
  0xfe09,
  0xfe0a,
  0xfe0b,
  0xfe0c,
  0xfe0d,
  0xfe0e,
  0xfe0f,
  0xfff9, // interlinear annotation
  0xfffa,
  0xfffb,
]);

/** Spaces that look like (or substitute for) U+0020. */
export const SPACE_HOMOGLYPHS: ReadonlyMap<number, string> = new Map([
  [0x00a0, " "], // no break space
  [0x1680, " "], // Ogham space mark
  [0x2000, " "], // en quad
  [0x2001, " "], // em quad
  [0x2002, " "], // en space
  [0x2003, " "], // em space
  [0x2004, " "], // three per em space
  [0x2005, " "], // four per em space
  [0x2006, " "], // six per em space
  [0x2007, " "], // figure space
  [0x2008, " "], // punctuation space
  [0x2009, " "], // thin space
  [0x200a, " "], // hair space
  [0x202f, " "], // narrow no break space
  [0x205f, " "], // medium mathematical space
  [0x3000, " "], // ideographic space
]);

/** Optional confusable Latin lookalikes (aggressive mode only). */
export const LATIN_CONFUSABLES: ReadonlyMap<number, string> = new Map([
  [0x0410, "A"], // Cyrillic
  [0x0412, "B"],
  [0x0415, "E"],
  [0x041a, "K"],
  [0x041c, "M"],
  [0x041d, "H"],
  [0x041e, "O"],
  [0x0420, "P"],
  [0x0421, "C"],
  [0x0422, "T"],
  [0x0425, "X"],
  [0x0430, "a"],
  [0x0435, "e"],
  [0x043e, "o"],
  [0x0440, "p"],
  [0x0441, "c"],
  [0x0443, "y"],
  [0x0445, "x"],
  [0x0456, "i"],
  [0xff21, "A"], // fullwidth
  [0xff22, "B"],
  [0xff23, "C"],
  [0xff24, "D"],
  [0xff25, "E"],
  [0xff26, "F"],
  [0xff27, "G"],
  [0xff28, "H"],
  [0xff29, "I"],
  [0xff2a, "J"],
  [0xff2b, "K"],
  [0xff2c, "L"],
  [0xff2d, "M"],
  [0xff2e, "N"],
  [0xff2f, "O"],
  [0xff30, "P"],
  [0xff31, "Q"],
  [0xff32, "R"],
  [0xff33, "S"],
  [0xff34, "T"],
  [0xff35, "U"],
  [0xff36, "V"],
  [0xff37, "W"],
  [0xff38, "X"],
  [0xff39, "Y"],
  [0xff3a, "Z"],
  [0xff41, "a"],
  [0xff42, "b"],
  [0xff43, "c"],
  [0xff44, "d"],
  [0xff45, "e"],
  [0xff46, "f"],
  [0xff47, "g"],
  [0xff48, "h"],
  [0xff49, "i"],
  [0xff4a, "j"],
  [0xff4b, "k"],
  [0xff4c, "l"],
  [0xff4d, "m"],
  [0xff4e, "n"],
  [0xff4f, "o"],
  [0xff50, "p"],
  [0xff51, "q"],
  [0xff52, "r"],
  [0xff53, "s"],
  [0xff54, "t"],
  [0xff55, "u"],
  [0xff56, "v"],
  [0xff57, "w"],
  [0xff58, "x"],
  [0xff59, "y"],
  [0xff5a, "z"],
]);

/** Variation selectors beyond FE0x (VS17..VS256 in Supplementary Special purpose). */
export function isVsSupplement(cp: number): boolean {
  return cp >= 0xe0100 && cp <= 0xe01ef;
}

/** Bidi / directional format controls (subset of strip set, finer inspect labels). */
export const BIDI_CPS: ReadonlySet<number> = new Set([
  0x061c, 0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2066,
  0x2067, 0x2068, 0x2069,
]);

/** Zero width family (common edit based carriers). */
export const ZW_FAMILY: ReadonlySet<number> = new Set([
  0x200b, 0x200c, 0x200d, 0x2060, 0xfeff, 0x180e,
]);

/** BMP and supplementary private use planes (Co: no portable meaning). */
export function isPrivateUse(cp: number): boolean {
  return (
    (cp >= 0xe000 && cp <= 0xf8ff) ||
    (cp >= 0xf0000 && cp <= 0xffffd) ||
    (cp >= 0x100000 && cp <= 0x10fffd)
  );
}

/**
 * Emoji presentation glue: zero width joiner and text/emoji variation
 * selectors. Invisible carriers when free floating, but after an emoji base
 * they are part of the visible sequence and stripping them alters the text.
 */
export const EMOJI_GLUE_CODEPOINTS: ReadonlySet<number> = new Set([
  0x200d, 0xfe0e, 0xfe0f,
]);

/** ZWNJ/ZWJ are orthographic inside complex scripts. */
export const SCRIPT_JOINERS: ReadonlySet<number> = new Set([0x200c, 0x200d]);

/** Tag characters used by flag emoji sequences (U+E0020..U+E007F). */
export function isTagGlue(cp: number): boolean {
  return cp >= 0xe0020 && cp <= 0xe007f;
}

/** Tag characters used in some stego schemes (U+E0001..U+E007F). */
export function isTagChar(cp: number): boolean {
  return cp >= 0xe0001 && cp <= 0xe007f;
}

/** Cf codepoints that are normal Arabic/Syriac orthography, not carriers. */
export const ORTHOGRAPHIC_CF: ReadonlySet<number> = new Set([
  0x0600, 0x0601, 0x0602, 0x0603, 0x0604, 0x0605, 0x06dd, 0x070f, 0x08e2,
  0x110bd, 0x110cd,
]);

export const MONGOLIAN_FVS: ReadonlySet<number> = new Set([0x180b, 0x180c, 0x180d]);
export const KHMER_VOWELS: ReadonlySet<number> = new Set([0x17b4, 0x17b5]);
export const HANGUL_FILLERS: ReadonlySet<number> = new Set([0x115f, 0x1160]);

/** Human readable names for the labels, mirroring unicodedata.name output. */
export const CODEPOINT_NAMES: ReadonlyMap<number, string> = new Map([
  [0x00ad, "SOFT HYPHEN"],
  [0x034f, "COMBINING GRAPHEME JOINER"],
  [0x061c, "ARABIC LETTER MARK"],
  [0x115f, "HANGUL CHOSEONG FILLER"],
  [0x1160, "HANGUL JUNGSEONG FILLER"],
  [0x17b4, "KHMER VOWEL INHERENT AQ"],
  [0x17b5, "KHMER VOWEL INHERENT AA"],
  [0x180b, "MONGOLIAN FREE VARIATION SELECTOR ONE"],
  [0x180c, "MONGOLIAN FREE VARIATION SELECTOR TWO"],
  [0x180d, "MONGOLIAN FREE VARIATION SELECTOR THREE"],
  [0x180e, "MONGOLIAN VOWEL SEPARATOR"],
  [0x200b, "ZERO WIDTH SPACE"],
  [0x200c, "ZERO WIDTH NON-JOINER"],
  [0x200d, "ZERO WIDTH JOINER"],
  [0x200e, "LEFT-TO-RIGHT MARK"],
  [0x200f, "RIGHT-TO-LEFT MARK"],
  [0x202a, "LEFT-TO-RIGHT EMBEDDING"],
  [0x202b, "RIGHT-TO-LEFT EMBEDDING"],
  [0x202c, "POP DIRECTIONAL FORMATTING"],
  [0x202d, "LEFT-TO-RIGHT OVERRIDE"],
  [0x202e, "RIGHT-TO-LEFT OVERRIDE"],
  [0x2060, "WORD JOINER"],
  [0x2061, "FUNCTION APPLICATION"],
  [0x2062, "INVISIBLE TIMES"],
  [0x2063, "INVISIBLE SEPARATOR"],
  [0x2064, "INVISIBLE PLUS"],
  [0x2066, "LEFT-TO-RIGHT ISOLATE"],
  [0x2067, "RIGHT-TO-LEFT ISOLATE"],
  [0x2068, "FIRST STRONG ISOLATE"],
  [0x2069, "POP DIRECTIONAL ISOLATE"],
  [0xfeff, "ZERO WIDTH NO-BREAK SPACE"],
  [0xfe0e, "VARIATION SELECTOR-15"],
  [0xfe0f, "VARIATION SELECTOR-16"],
  [0x00a0, "NO-BREAK SPACE"],
  [0x1680, "OGHAM SPACE MARK"],
  [0x2000, "EN QUAD"],
  [0x2001, "EM QUAD"],
  [0x2002, "EN SPACE"],
  [0x2003, "EM SPACE"],
  [0x2004, "THREE-PER-EM SPACE"],
  [0x2005, "FOUR-PER-EM SPACE"],
  [0x2006, "SIX-PER-EM SPACE"],
  [0x2007, "FIGURE SPACE"],
  [0x2008, "PUNCTUATION SPACE"],
  [0x2009, "THIN SPACE"],
  [0x200a, "HAIR SPACE"],
  [0x202f, "NARROW NO-BREAK SPACE"],
  [0x205f, "MEDIUM MATHEMATICAL SPACE"],
  [0x3000, "IDEOGRAPHIC SPACE"],
]);
