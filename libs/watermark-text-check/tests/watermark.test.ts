import assert from "node:assert/strict";
import { test } from "node:test";

import {
  checkWatermark,
  cleanText,
  ensureText,
  hasWatermarkCarriers,
  inspectText,
  isText,
  reportToJson,
  sniffBinary,
} from "../src/index.js";

test("clean text has no hits", () => {
  const report = inspectText("Hello, world. Plain ASCII text.");
  assert.equal(report.suspiciousTotal, 0);
  assert.equal(report.hits.length, 0);
  assert.equal(hasWatermarkCarriers("Hello"), false);
});

test("zero width space is detected and stripped", () => {
  const text = "wa\u200Bter\u200Bmark";
  const report = inspectText(text);
  assert.equal(report.suspiciousTotal, 2);
  assert.equal(report.hits[0]?.kind, "zwj_family");
  assert.equal(report.hits[0]?.confidence, "probable");
  assert.deepEqual(report.hits[0]?.samples, [2, 6]);

  const { text: cleaned, stats } = cleanText(text);
  assert.equal(cleaned, "watermark");
  assert.equal(stats.removedCount, 2);
});

test("bidi controls are classified as bidi", () => {
  const report = inspectText("abc\u202Edef");
  assert.equal(report.hits[0]?.kind, "bidi");
});

test("tag characters are flagged when free floating", () => {
  const stego = "hi" + String.fromCodePoint(0xe0041) + String.fromCodePoint(0xe0042);
  const report = inspectText(stego);
  assert.equal(report.suspiciousTotal, 2);
  assert.equal(report.hits.every((h) => h.kind === "tag_chars"), true);
});

test("emoji ZWJ sequences are preserved by default", () => {
  // heart, VS16, ZWJ, fire
  const heartFire = "\u2764\uFE0F\u200D\u{1F525}";
  const report = inspectText(heartFire);
  assert.equal(report.suspiciousTotal, 0);
  const { text: cleaned } = cleanText(heartFire);
  assert.equal(cleaned, heartFire);
});

test("paranoid mode flags emoji glue too", () => {
  const heartFire = "\u2764\uFE0F\u200D\u{1F525}";
  const report = inspectText(heartFire, { stripEmojiGlue: true });
  assert.ok(report.suspiciousTotal >= 2);
});

test("scotland flag tag run is preserved by default", () => {
  const flag =
    "\u{1F3F4}\u{E0067}\u{E0062}\u{E0073}\u{E0063}\u{E0074}\u{E007F}";
  const report = inspectText(flag);
  assert.equal(report.suspiciousTotal, 0);
  assert.equal(cleanText(flag).text, flag);
});

test("persian ZWNJ between letters is orthographic and kept", () => {
  // mi (meem, yeh), ZWNJ, ravam (reh, waw, meem)
  const persian = "\u0645\u06CC\u200C\u0631\u0648\u0645";
  const report = inspectText(persian);
  assert.equal(report.suspiciousTotal, 0);
  assert.equal(cleanText(persian).text, persian);
});

test("isolated ZWNJ after ASCII is contraband", () => {
  const report = inspectText("ab\u200Ccd");
  assert.equal(report.suspiciousTotal, 1);
  assert.equal(report.hits[0]?.kind, "zwj_family");
});

test("space homoglyphs are informational and normalized", () => {
  const text = "a\u00A0b\u2009c";
  const report = inspectText(text);
  assert.equal(report.suspiciousTotal, 2);
  assert.equal(report.hits.every((h) => h.kind === "space"), true);
  assert.equal(report.hits.every((h) => h.confidence === "informational"), true);
  assert.equal(cleanText(text).text, "a b c");
});

test("confusables flagged only in aggressive mode", () => {
  const text = "p\u0430ge"; // Cyrillic small a
  assert.equal(inspectText(text).suspiciousTotal, 0);
  const aggressive = inspectText(text, { aggressive: true });
  assert.equal(aggressive.suspiciousTotal, 1);
  assert.equal(aggressive.hits[0]?.kind, "confusable");
  assert.equal(cleanText(text, { aggressiveHomoglyphs: true }).text, "page");
});

test("private use codepoints are flagged", () => {
  const report = inspectText("x\uE000y");
  assert.equal(report.hits[0]?.kind, "private_use");
});

test("utf16 offsets track astral characters", () => {
  const text = "\u{1F600}\u200B"; // emoji (2 code units) then ZWSP
  const report = inspectText(text);
  assert.deepEqual(report.hits[0]?.samples, [1]);
  assert.deepEqual(report.hits[0]?.samplesUtf16, [2]);
});

test("report JSON matches the Python shape", () => {
  const json = reportToJson(inspectText("a\u200Bb"));
  assert.equal(json.suspicious_total, 1);
  assert.equal(json.hits[0]?.codepoint, "U+200B");
  assert.equal(json.hits[0]?.confidence, "probable");
  assert.deepEqual(json.hits[0]?.sample_offsets, [1]);
});

test("isText guards runtime types", () => {
  assert.equal(isText("hello"), true);
  assert.equal(isText(42), false);
  assert.equal(isText(null), false);
});

test("ensureText rejects non text runtime types", () => {
  const result = ensureText(12345);
  assert.equal(result.ok, false);
  if (!result.ok) assert.match(result.reason, /not text/);
});

test("ensureText rejects PNG bytes by magic", () => {
  const png = new Uint8Array([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 1, 2, 3]);
  assert.match(sniffBinary(png) ?? "", /PNG/);
  const result = ensureText(png);
  assert.equal(result.ok, false);
  if (!result.ok) assert.match(result.reason, /PNG/);
});

test("ensureText rejects NUL laden strings unless forced", () => {
  const weird = "abc\u0000def";
  assert.equal(ensureText(weird).ok, false);
  const forced = ensureText(weird, { forceText: true });
  assert.equal(forced.ok, true);
});

test("ensureText decodes UTF-8 bytes", () => {
  const bytes = new TextEncoder().encode("caf\u00E9 \u200B");
  const result = ensureText(bytes);
  assert.equal(result.ok, true);
  if (result.ok) assert.equal(result.text, "caf\u00E9 \u200B");
});

test("checkWatermark end to end", () => {
  const clean = checkWatermark("plain text");
  assert.equal(clean.ok, true);
  if (clean.ok) assert.equal(clean.watermarked, false);

  const marked = checkWatermark("wa\u200Bter\u2060mark");
  assert.equal(marked.ok, true);
  if (marked.ok) {
    assert.equal(marked.watermarked, true);
    assert.equal(marked.report.suspiciousTotal, 2);
  }

  const binary = checkWatermark(new Uint8Array([0x25, 0x50, 0x44, 0x46, 0x2d]));
  assert.equal(binary.ok, false);
});

test("nfkc option is applied after cleaning", () => {
  const { text, stats } = cleanText("\uFF21BC", { nfkc: true });
  assert.equal(text, "ABC");
  assert.ok(stats.replaced["NFKC_normalize"]);
});
