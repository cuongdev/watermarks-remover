import assert from "node:assert/strict";
import { test } from "node:test";

import { classifyInput, cleanFile, inspectFile, writeZip } from "../src/index.js";

const enc = new TextEncoder();
const dec = new TextDecoder();

const PNG_BYTES = new Uint8Array([
  0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0, 0x49, 0x45, 0x4e, 0x44,
  0, 0, 0, 0,
]);

test("classifyInput routes by extension then magic", async () => {
  assert.equal(await classifyInput("a.png", new Uint8Array()), "image");
  assert.equal(await classifyInput("a.md", new Uint8Array()), "container");
  assert.equal(await classifyInput("a.txt", new Uint8Array()), "text");
  assert.equal(await classifyInput(null, PNG_BYTES), "image");
  assert.equal(await classifyInput(null, enc.encode("plain prose")), "text");
});

test("zip without extension is sniffed as a container", async () => {
  const docx = await writeZip([
    { name: "word/document.xml", data: enc.encode("<w:document/>") },
  ]);
  assert.equal(await classifyInput(null, docx), "container");
});

test("inspectFile routes text and finds Layer A carriers", async () => {
  const result = await inspectFile("wa\u200Btermark", "note.txt");
  assert.equal(result.kind, "text");
  if (result.kind === "text") assert.equal(result.report.suspiciousTotal, 1);
});

test("inspectFile routes png bytes to the image inspector", async () => {
  const result = await inspectFile(PNG_BYTES);
  assert.equal(result.kind, "image");
  if (result.kind === "image") assert.equal(result.report.format, "png");
});

test("inspectFile refuses unknown binary as text", async () => {
  const gzip = new Uint8Array([0x1f, 0x8b, 8, 0, 1, 2, 3, 4]);
  const result = await inspectFile(gzip);
  assert.equal(result.kind, "refused");
  if (result.kind === "refused") assert.match(result.reason, /gzip/);
});

test("cleanFile on markdown applies container clean plus Layer A", async () => {
  const md = "---\ngenerator: Claude\n---\nBo\u200Bdy.\n";
  const result = await cleanFile(md, "post.md");
  assert.equal(result.kind, "container");
  if (result.kind === "container") {
    const text = dec.decode(result.data);
    assert.ok(!text.includes("Claude"));
    assert.ok(text.includes("Body."));
    assert.ok(result.actions.some((a) => a.startsWith("layer A text:")));
    assert.equal(result.stillHasAiMetadata, false);
  }
});

test("cleanFile on plain text runs Layer A", async () => {
  const result = await cleanFile("a\u200Bb", "note.txt");
  assert.equal(result.kind, "text");
  if (result.kind === "text") {
    assert.equal(result.text, "ab");
    assert.equal(result.stats.removedCount, 1);
  }
});

test("forced kind overrides classification", async () => {
  const result = await cleanFile("just text", null, { as: "text" });
  assert.equal(result.kind, "text");
});
