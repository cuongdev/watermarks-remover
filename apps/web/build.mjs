/**
 * Bundle the Provenance Examiner into self-contained HTML.
 *
 * esbuild bundles src/main.ts (which imports the watermark-text-check library
 * directly) into one IIFE. pdf-lib is marked external so its dynamic import
 * is left unresolved in the browser; the library then falls back to the
 * degraded PDF path, which is the intended browser behavior.
 *
 * Outputs:
 *   dist/index.html    full standalone document (host or open directly)
 *   dist/artifact.html body-inner content for the Artifact publisher
 */

import { build } from "esbuild";
import { readFile, writeFile, mkdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const here = dirname(fileURLToPath(import.meta.url));
const dist = join(here, "dist");

const result = await build({
  entryPoints: [join(here, "src", "main.ts")],
  bundle: true,
  format: "iife",
  platform: "browser",
  target: "es2021",
  minify: true,
  external: ["pdf-lib"],
  write: false,
  legalComments: "none",
});

const js = result.outputFiles[0].text;
const css = await readFile(join(here, "styles.css"), "utf8");
const body = await readFile(join(here, "body.html"), "utf8");

const head = `<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<meta name="description" content="Reveal invisible watermarks, C2PA manifests, and AI metadata in text and files. Evidence-first, runs in your browser.">`;

const styleTag = `<style>\n${css}\n</style>`;
const scriptTag = `<script>\n${js}\n</script>`;

// Standalone document.
const standalone = `<!doctype html>
<html lang="vi">
<head>
${head}
${styleTag}
</head>
<body>
${body}
${scriptTag}
</body>
</html>
`;

// Artifact publisher wraps its own doctype/head/body, so emit inner content.
// styles first so the <title> in body.html stays inside the scanned prefix.
const artifact = `${body}\n${styleTag}\n${scriptTag}\n`;

await mkdir(dist, { recursive: true });
await writeFile(join(dist, "index.html"), standalone);
await writeFile(join(dist, "artifact.html"), artifact);

const kb = (s) => (Buffer.byteLength(s) / 1024).toFixed(0) + " KB";
console.log(`bundled JS ${kb(js)} · standalone ${kb(standalone)} · artifact ${kb(artifact)}`);
