import assert from "node:assert/strict";
import { test } from "node:test";

import {
  cleanContainer,
  cleanPdfDeep,
  detectC2paManifest,
  inspectImage,
  isPdfLibAvailable,
} from "../src/index.js";

const enc = new TextEncoder();

// A small but structurally valid PDF carrying AI provenance in /Info,
// mirroring tests/test_pdf_structural_rewrite.py::_ai_pdf.
function aiPdf(): Uint8Array {
  const objs = [
    "<< /Type /Catalog /Pages 2 0 R >>",
    "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Resources << >> >>",
    "<< /Producer (Claude Opus) /Creator (Anthropic Claude) >>",
  ];
  let out = "%PDF-1.4\n";
  const offsets: number[] = [];
  objs.forEach((body, idx) => {
    offsets.push(out.length);
    out += `${idx + 1} 0 obj\n${body}\nendobj\n`;
  });
  const xref = out.length;
  out += `xref\n0 ${objs.length + 1}\n0000000000 65535 f \n`;
  for (const off of offsets) out += `${String(off).padStart(10, "0")} 00000 n \n`;
  out += `trailer\n<< /Size ${objs.length + 1} /Root 1 0 R /Info 4 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return enc.encode(out);
}

test("pdf-lib is available in this dev environment", async () => {
  assert.equal(await isPdfLibAvailable(), true);
});

test("cleanPdfDeep removes recoverable metadata bytes (the qpdf+exiftool goal)", async () => {
  const pdf = aiPdf();
  assert.ok(Buffer.from(pdf).includes("Claude"));

  const { data, actions, meta } = await cleanPdfDeep(pdf);
  const body = Buffer.from(data);
  // The whole point of the qpdf structural rewrite: nothing readable survives.
  assert.ok(!body.includes("Claude"), "Claude must not survive");
  assert.ok(!body.includes("Anthropic"), "Anthropic must not survive");
  assert.ok(body.slice(0, 5).toString().startsWith("%PDF-"));
  assert.equal(meta["structuralRewrite"], true);
  assert.ok(actions.some((a) => a.includes("structural rewrite")));
});

test("cleanContainer routes PDF through the deep clean when pdf-lib is present", async () => {
  const result = await cleanContainer(aiPdf(), "report.pdf");
  assert.equal(result.format, "pdf");
  assert.equal(result.meta["mode"], "pdf-lib");
  assert.equal(result.meta["degraded"], false);
  assert.ok(!Buffer.from(result.data).includes("Claude"));
  assert.equal(result.stillHasAiMetadata, false);
});

// ---------------------------------------------------------------------------
// C2PA / JUMBF native detection
// ---------------------------------------------------------------------------

function jumdBox(uuid: number[], label: string): number[] {
  // jumd payload: 16-byte UUID + 1 toggle byte (label present) + NUL label
  const labelBytes = [...enc.encode(label), 0];
  const payload = [...uuid, 0x03, ...labelBytes];
  return box("jumd", payload);
}

function box(type: string, payload: number[]): number[] {
  const len = 8 + payload.length;
  return [
    (len >>> 24) & 0xff,
    (len >>> 16) & 0xff,
    (len >>> 8) & 0xff,
    len & 0xff,
    ...[...type].map((c) => c.charCodeAt(0)),
    ...payload,
  ];
}

const C2PA_UUID = [
  0x63, 0x32, 0x70, 0x61, 0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71,
];

// A jumb superbox whose description box declares the c2pa manifest store.
function c2paSuperbox(): number[] {
  const inner = jumdBox(C2PA_UUID, "c2pa");
  return box("jumb", inner);
}

function u32be(v: number): number[] {
  return [(v >>> 24) & 0xff, (v >>> 16) & 0xff, (v >>> 8) & 0xff, v & 0xff];
}

function pngWithCaBX(jumbf: number[]): Uint8Array {
  const chunk = (type: string, payload: number[]) => [
    ...u32be(payload.length),
    ...[...type].map((c) => c.charCodeAt(0)),
    ...payload,
    0,
    0,
    0,
    0,
  ];
  return new Uint8Array([
    0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a,
    ...chunk("IHDR", new Array(13).fill(1)),
    ...chunk("caBX", jumbf),
    ...chunk("IDAT", [1, 2, 3]),
    ...chunk("IEND", []),
  ]);
}

test("detectC2paManifest parses a C2PA manifest store in a PNG caBX chunk", () => {
  const png = pngWithCaBX(c2paSuperbox());
  const det = detectC2paManifest(png);
  assert.equal(det.hasManifest, true);
  assert.ok(det.labels.includes("c2pa"));
});

test("a non-c2pa JUMBF box is not a manifest", () => {
  const other = box("jumb", jumdBox(new Array(16).fill(0), "xmp "));
  const png = pngWithCaBX(other);
  const det = detectC2paManifest(png);
  assert.equal(det.hasManifest, false);
});

test("plain PNG without JUMBF has no manifest", () => {
  const png = pngWithCaBX([]); // empty caBX
  assert.equal(detectC2paManifest(png).hasManifest, false);
});

test("JPEG APP11 with a c2pa JUMBF is detected and reassembled", () => {
  const jumbf = c2paSuperbox();
  // APP11 payload: "JP"(2) + En(2) + Z(4) + jumbf data
  const appPayload = [0x4a, 0x50, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, ...jumbf];
  const segLen = appPayload.length + 2;
  const jpeg = new Uint8Array([
    0xff, 0xd8,
    0xff, 0xeb, (segLen >>> 8) & 0xff, segLen & 0xff, ...appPayload,
    0xff, 0xda, 0x00, 0x02, // SOS
    0xff, 0xd9,
  ]);
  const det = detectC2paManifest(jpeg);
  assert.equal(det.hasManifest, true);
  assert.ok(det.labels.includes("c2pa"));
});

test("inspectImage elevates a parsed manifest to a confirmed C2PA finding", () => {
  const png = pngWithCaBX(c2paSuperbox());
  const report = inspectImage(png);
  assert.equal(report.hasC2pa, true);
  assert.ok(report.findings.some((f) => f.startsWith("c2pa manifest store present")));
  const idx = report.findings.findIndex((f) => f.startsWith("c2pa manifest store"));
  assert.equal(report.findingsConfidence[idx], "confirmed");
});
