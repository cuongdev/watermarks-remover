# watermark-text-check

Isomorphic TypeScript port of this repo's watermark detection and removal
techniques (see `skills/remove-ai-marks/scripts/`). Zero runtime
dependencies, pure ES2021, works in browsers, Node 18+, Deno, Bun, and edge
runtimes. Everything operates on strings and `Uint8Array`s, so the same code
runs in a React paste handler and an Express route.

## Technique coverage

| Technique (Python source) | TypeScript module | API |
| --- | --- | --- |
| Input is text guard, binary sniff (`common.py`) | `ensureText.ts` | `isText`, `ensureText`, `sniffBinary` |
| Layer A: invisible Unicode carriers (`text_unicode.py`) | `inspect.ts`, `clean.ts` | `inspectText`, `cleanText`, `hasWatermarkCarriers`, `checkWatermark` |
| Finding confidence buckets (`common.py`) | `markers.ts` | `classifyFindingConfidence` |
| PNG/JPEG metadata inspect and strip (`image_meta.py`) | `imageMeta.ts` | `inspectImage`, `cleanImage`, `stripPng`, `stripJpeg` |
| Markdown frontmatter (`container_meta.py`) | `containerMeta.ts` | `inspectMarkdown`, `cleanMarkdown` |
| HTML meta / JSON-LD / data-ai attrs | `containerMeta.ts` | `inspectHtml`, `cleanHtml` |
| SVG metadata / XMP / comments | `containerMeta.ts` | `inspectSvg`, `cleanSvg` |
| DOCX docProps / customXml (zip) | `containerMeta.ts` + `zip.ts` | `inspectDocx`, `cleanDocx` |
| ODT meta.xml (zip) | `containerMeta.ts` + `zip.ts` | `inspectOdt`, `cleanOdt` |
| PDF XMP packets (best effort) | `containerMeta.ts` | `inspectPdf`, `cleanPdf` |
| Unified format routing (`inspect_file.py`, `clean_file.py`) | `router.ts` | `classifyInput`, `inspectFile`, `cleanFile` |
| Layer B rewrite prompts and backends (`rewrite_text.py`) | `rewrite.ts` | `buildPrompt`, `rewriteText`, `lexicalDivergence`, `selectCandidate` |
| Aggregate audit and reporting (`audit_lib.py`, `audit_dir.py`) | `audit.ts` | `scanItem`, `auditItems`, `aggregate`, `isActionable`, `renderAuditReport` |
| Website / sitemap audit (`audit_website.py`) | `auditWebsite.ts` | `auditWebsite`, `discoverSitemap`, `collectUrls`, `parseSitemap`, `guessKind` |
| PDF structural rewrite + metadata strip (`qpdf` + `exiftool` PDF pass) | `pdfClean.ts` | `cleanPdfDeep`, `isPdfLibAvailable` |
| C2PA manifest detection (`c2patool` inspect pass) | `c2pa.ts` | `detectC2paManifest` |

The `skills/remove-ai-marks/SKILL.md` and `references/` files are agent
workflow documentation, not code; the workflows they describe (route by
format, inspect, clean, verify, escalate to Layer B) are what the unified
`inspectFile`/`cleanFile`/`auditItems` APIs implement.

### External tools replaced with JS libraries

The Python scripts shell out to three optional CLI tools. All three are now
covered without a subprocess:

- **`qpdf` (PDF structural rewrite)** and the **`exiftool` PDF pass** →
  `pdf-lib`. Loading and re-saving a PDF rebuilds it from the parsed object
  graph and drops the now-unreferenced metadata objects, exactly what
  `qpdf --linearize` does after `exiftool -all=`. Clearing the document info
  dictionary removes the provenance fields, so nothing readable survives in
  the output bytes (the same assertion the Python end-to-end test makes).
  `pdf-lib` is an **optional peer dependency**, loaded via dynamic import:
  install it for the full strip, otherwise the library falls back to the
  degraded stdlib XMP-packet strip with a warning.
- **`exiftool` residual pass on PNG/JPEG** → the native chunk/segment
  strippers already remove every metadata chunk (PNG `tEXt`/`zTXt`/`iTXt`/
  `eXIf`/`caBX`/`c2*`) and APP segment (JPEG APP1..APP14, APP11 JUMBF, COM),
  so an exiftool residual pass is redundant for the supported image formats.
- **`c2patool` (C2PA manifest inspect)** → `c2pa.ts`, a native JUMBF box
  parser (no dependency). It walks the JUMBF tree in a PNG `caBX` chunk or
  reassembled JPEG APP11 segments and confirms a real C2PA manifest store, a
  stronger structural signal than a byte scan for the string "c2pa".

Because these are JS libraries, PDF and C2PA handling works even where
`exiftool`/`qpdf`/`c2patool` are not installed.

**Genuinely not portable** (real ML model integrations, not CLI tools): the
reverse SynthID pixel-domain scorer (`score_synthid.py`: torch, OpenCV,
numpy plus an external checkout) and the CtrlRegen pixel-domain remover
(`clean_ctrlregen.py`: torch, diffusers plus an external checkout). These
run a diffusion model / spectral analysis over image pixels and have no
pure-JS equivalent; use the Python scripts for them. `exiftool` for image
formats beyond PNG/JPEG (TIFF, WebP, HEIC) is also out of the library's
image scope, which matches `image_meta.py`'s PNG/JPEG MVP scope. The
recursive directory walk from `audit_dir.py` is Node specific, so
`auditItems` takes a collected item list instead (walk example below).

## Layer A behavior

Detects and removes invisible Unicode carriers: zero width characters, bidi
controls, tag characters, variation selectors, private use codepoints,
exotic space homoglyphs, and (optionally) Latin confusables. Load bearing
invisibles are preserved by default, matching the Python implementation:
emoji glue (ZWJ and VS16 after an emoji base), script joiners (ZWNJ/ZWJ
inside Persian, Devanagari, and similar), flag tag runs, Mongolian free
variation selectors, Khmer inherent vowels, Hangul jamo fillers, and
orthographic Arabic/Syriac format marks.

## Scope and compliance guardrails

- Layer A and metadata stripping are deterministic. Statistical (token
  sampling) watermarks such as SynthID-Text are not detectable from
  characters; Layer B (`rewriteText`) is a best effort model rewrite and
  cannot certify removal against a vendor detector.
- Intended for provenance hygiene on **content you own**. Before deploying
  in a regulated environment (including federal contracting), confirm that
  removing provenance metadata is permitted under your contracts, agency
  rules, and records retention obligations. Detection (`inspect*`) is
  always safe; removal (`clean*`) is the step to review with compliance.
- The Layer B endpoint policy is default deny: only loopback (localhost)
  model endpoints are accepted, redirects are refused so API keys cannot
  leak to unvalidated hosts, and remote endpoints require an explicit
  `allowRemote: true`. Keep API keys server side; never embed them in
  frontend code.
- Zip processing rejects archives whose declared decompressed size exceeds
  128 MiB (zip bomb guard), and `ensureText` caps inputs at 256 MiB by
  default, both matching the Python scripts.

## Install / build

```bash
cd libs/watermark-text-check
npm install
npm test        # builds with tsc, runs the Node test runner (76 tests)
```

`pdf-lib` is an optional peer dependency. Install it only if you need the
full PDF metadata strip:

```bash
npm install pdf-lib
```

Without it, PDF cleaning falls back to the degraded XMP-packet strip. Every
other technique (text, image, DOCX/ODT/SVG/HTML/Markdown, C2PA detection,
audits) is fully zero-dependency.

## Unified API (recommended entry point)

```ts
import { classifyInput, inspectFile, cleanFile } from "watermark-text-check";

// Works on a string, or on Uint8Array/ArrayBuffer bytes from a file upload.
const result = await inspectFile(bytes, file.name);
// result.kind: "text" | "image" | "container" | "refused"

const cleaned = await cleanFile(bytes, file.name);
if (cleaned.kind !== "refused") {
  // cleaned.data is the cleaned bytes; text results also expose .text
}
```

Routing matches `clean_file.py`: extension first (`.png`, `.md`, `.docx`,
...), then magic bytes (PNG/JPEG signatures, `%PDF`, zip sniffing that
distinguishes DOCX from ODT), falling back to text with a binary refusal
guard so unknown binaries are never mangled as text.

## Text API

```ts
import {
  isText, ensureText, sniffBinary,          // input guards
  inspectText, hasWatermarkCarriers,        // Layer A detect
  cleanText,                                // Layer A remove
  checkWatermark, reportToJson,             // one shot + Python JSON shape
} from "watermark-text-check";
```

`TextInspectReport.hits[]` entries carry `codepoint`, `label`, `count`,
`kind`, `confidence`, `samples` (codepoint offsets, matching the Python
reports), and `samplesUtf16` (UTF-16 offsets for JavaScript string slicing).

## Image and container APIs

```ts
import { inspectImage, cleanImage } from "watermark-text-check";
const report = inspectImage(pngBytes);      // hasC2pa, hasAiMetadata, findings
const { data, actions } = cleanImage(pngBytes); // stripped bytes

import { inspectContainer, cleanContainer } from "watermark-text-check";
const doc = await cleanContainer(docxBytes, "report.docx");
// drops customXml parts, scrubs dc:creator / Application fields, rewrites the zip
```

Every finding comes with a confidence bucket (`confirmed`, `probable`,
`informational`, `likely_false_positive`) via the same heuristic as the
Python scripts. Markdown and HTML container cleans also run a Layer A scrub
over the body text (disable with `alsoLayerAText: false`).

## Aggregate audits

```ts
import { auditItems, auditWebsite, renderAuditReport, DEFAULT_SKIP_DIRS } from "watermark-text-check";

// Directory audit (Node): walk the tree yourself, then hand items over.
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
function* walk(dir: string): Generator<string> {
  for (const name of readdirSync(dir).sort()) {
    if (DEFAULT_SKIP_DIRS.has(name) || name.startsWith(".")) continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) yield* walk(p);
    else yield p;
  }
}
const report = await auditItems([...walk("./content")].map((p) => ({ name: p, data: readFileSync(p) })));
console.log(renderAuditReport(report.items, report.summary));
// report.summary.actionableFiles > 0 mirrors the Python script's exit code 1

// Website audit via sitemap (own or operated sites only):
const site = await auditWebsite({ baseUrl: "https://example.com" });
```

In a browser, pass dropped `File`s to `auditItems` after
`file.arrayBuffer()`; every item is normalized to the same shape
(`findings`, per finding `confidence`, `hasC2pa`, `suspiciousTotal`) and
aggregated with the same actionability rule as the Python audits.

## Layer B rewrite

```ts
import { rewriteText } from "watermark-text-check";

// Default backend returns the prompt only (CI safe, no model call):
const { text: prompt } = await rewriteText(input, { strength: "paraphrase" });

// Local Ollama, three candidates, pick the most lexically diverged,
// then Layer A scrub the output:
const { text, info } = await rewriteText(input, {
  backend: "ollama",
  model: "llama3.2",
  baseUrl: "http://127.0.0.1:11434",
  candidates: 3,
});
```

Strengths: `paraphrase`, `humanize`, `code`, `backtranslate`, `structural`.

## Frontend usage (React example)

```tsx
import { checkWatermark, cleanText, inspectFile } from "watermark-text-check";

function onPaste(value: string) {
  const result = checkWatermark(value);
  if (result.ok && result.watermarked) {
    setWarning(`${result.report.suspiciousTotal} hidden character(s) found`);
  }
}

async function onUpload(file: File) {
  const report = await inspectFile(new Uint8Array(await file.arrayBuffer()), file.name);
  // report.kind tells you whether it routed as text, image, or container
}
```

## Backend usage (Express example)

```ts
import express from "express";
import { checkWatermark, cleanFile, reportToJson } from "watermark-text-check";

const app = express();
app.use(express.json({ limit: "10mb" }));

app.post("/api/watermark/check", (req, res) => {
  const result = checkWatermark(req.body?.text, { maxBytes: 10 << 20 });
  if (!result.ok) return res.status(400).json({ error: result.reason });
  return res.json({ watermarked: result.watermarked, report: reportToJson(result.report) });
});

app.post("/api/watermark/clean-file", express.raw({ type: "*/*", limit: "50mb" }), async (req, res) => {
  const result = await cleanFile(new Uint8Array(req.body), String(req.query.name ?? ""));
  if (result.kind === "refused") return res.status(400).json({ error: result.reason });
  res.setHeader("X-Clean-Actions", JSON.stringify(result.kind === "text" ? [] : result.actions));
  return res.send(Buffer.from(result.kind === "text" ? result.data : result.data));
});
```

## Parity with the Python source

The Layer A report JSON (`reportToJson`) is byte identical to
`inspect_text.py --json`, and the markdown/HTML/SVG cleaners produce byte
identical output to `container_meta.py` on shared fixtures (verified in
development). Offsets in `samples` are codepoint offsets like Python's; use
`samplesUtf16` when slicing JavaScript strings. `unicodedata.category`
checks are implemented with Unicode property escapes (`\p{Cf}`, `\p{L}`,
`\p{M}`), and Python's `zipfile` is replaced by a minimal built in zip
reader/writer on top of `DecompressionStream`/`CompressionStream`.
