# Provenance Examiner (web)

A bilingual (Tiếng Việt / English) browser front end for the
`watermark-text-check` library. Paste text or drop a file; it reveals the
invisible characters, C2PA manifests, and AI metadata that software leaves
behind, and shows exactly where each one sits.

Everything runs client side. Nothing pasted or dropped is uploaded. The app
imports the library source directly, so it is a real consumer of the
library, not a reimplementation.

## What it detects, and what it does not

- **Detects**: deterministic provenance markers, invisible Unicode carriers
  (zero width, bidi, tag characters, variation selectors), substitute
  spaces, lookalike letters, C2PA manifests (native JUMBF parse), and AI
  metadata fields in images and documents. Each finding is shown in place
  and listed with a confidence level.
- **Does not detect**: statistical token sampling watermarks (SynthID-Text
  class). A clean result is not proof a human wrote the content. The UI
  states this plainly; the tool reports evidence, not a verdict on authorship.

## Design

Forensic proof-marking aesthetic: a cool light-table palette, red used only
as evidence ink, a machine monospace set against human sans. The signature
element is the **marked exhibit** that re-renders your text with each hidden
character shown in place as a codepoint chip. Full width, theme aware
(light / dark), and language aware (default Vietnamese, toggle to English),
both remembered across visits.

## Build

```bash
cd apps/web
npm install
npm run build     # -> dist/index.html (standalone) and dist/artifact.html
npm run serve     # build, then serve dist/index.html at http://localhost:4321
```

`build.mjs` bundles `src/main.ts` with esbuild (pdf-lib marked external, so
PDF handling uses the library's degraded browser path), then inlines the CSS
and JS into two self-contained HTML files:

- `dist/index.html` — a full standalone document you can host or open directly.
- `dist/artifact.html` — body-inner content for the Claude Artifact publisher.

No network access at runtime, no external assets, no analytics.
