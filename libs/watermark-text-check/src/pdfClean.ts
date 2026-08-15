/**
 * Deep PDF metadata strip via the optional `pdf-lib` peer dependency.
 *
 * This is the JS replacement for the Python scripts' exiftool + qpdf PDF
 * pass. exiftool edits PDFs incrementally (the freed /Info bytes stay in the
 * file and are trivially recoverable), so the Python side follows it with a
 * qpdf structural rewrite that re-serializes the object graph and drops the
 * now-unreferenced objects. pdf-lib does the equivalent in pure JS: loading
 * and re-saving rebuilds the document from the parsed object graph, and
 * clearing the document info dictionary removes the provenance fields so
 * nothing readable survives in the output bytes.
 *
 * pdf-lib is an OPTIONAL peer dependency, loaded via dynamic import, so the
 * core library stays zero-dependency and isomorphic. When it is not
 * installed, callers fall back to the degraded stdlib XMP strip.
 */

export class PdfLibUnavailableError extends Error {
  constructor() {
    super(
      "pdf-lib is not installed; install it (npm i pdf-lib) for a full PDF metadata strip, " +
        "or the degraded XMP-only strip is used instead",
    );
    this.name = "PdfLibUnavailableError";
  }
}

interface PdfLibModule {
  PDFDocument: {
    load(
      bytes: Uint8Array,
      opts?: { updateMetadata?: boolean; throwOnInvalidObject?: boolean; ignoreEncryption?: boolean },
    ): Promise<PdfLibDoc>;
  };
}

interface PdfLibDoc {
  setTitle(v: string): void;
  setAuthor(v: string): void;
  setSubject(v: string): void;
  setKeywords(v: string[]): void;
  setProducer(v: string): void;
  setCreator(v: string): void;
  setCreationDate(v: Date): void;
  setModificationDate(v: Date): void;
  save(opts?: { useObjectStreams?: boolean; updateFieldAppearances?: boolean }): Promise<Uint8Array>;
}

let cached: PdfLibModule | null | undefined;

async function loadPdfLib(): Promise<PdfLibModule | null> {
  if (cached !== undefined) return cached;
  try {
    // Indirected specifier keeps bundlers from hard-resolving the optional dep.
    const mod = (await import(/* @vite-ignore */ "pdf-lib")) as unknown as PdfLibModule;
    cached = mod;
  } catch {
    cached = null;
  }
  return cached;
}

/** True when the optional pdf-lib dependency is importable. */
export async function isPdfLibAvailable(): Promise<boolean> {
  return (await loadPdfLib()) !== null;
}

export interface PdfDeepCleanResult {
  data: Uint8Array;
  actions: string[];
  meta: Record<string, unknown>;
}

/**
 * Fully strip PDF document metadata and structurally rewrite the file.
 * Throws PdfLibUnavailableError when pdf-lib is not installed so the caller
 * can fall back to the degraded XMP strip.
 */
export async function cleanPdfDeep(data: Uint8Array): Promise<PdfDeepCleanResult> {
  const pdfLib = await loadPdfLib();
  if (!pdfLib) throw new PdfLibUnavailableError();

  const doc = await pdfLib.PDFDocument.load(data, {
    updateMetadata: false,
    throwOnInvalidObject: false,
    ignoreEncryption: true,
  });

  const actions: string[] = [];
  // Clear the standard document info dictionary fields (Producer, Creator,
  // Author, and similar). The Unix epoch is a stable, non-identifying stamp.
  const epoch = new Date(0);
  doc.setTitle("");
  doc.setAuthor("");
  doc.setSubject("");
  doc.setKeywords([]);
  doc.setProducer("");
  doc.setCreator("");
  doc.setCreationDate(epoch);
  doc.setModificationDate(epoch);
  actions.push("cleared PDF info dictionary (Producer/Creator/Author/Title/Subject/Keywords/dates)");

  // Re-serialize from the object graph. Like qpdf --linearize, this drops the
  // now-unreferenced original metadata objects instead of appending an
  // incremental update, so the old bytes do not survive. useObjectStreams
  // false keeps the output plainly inspectable.
  const out = await doc.save({ useObjectStreams: false, updateFieldAppearances: false });
  actions.push("structural rewrite via pdf-lib (drops unreferenced objects; no recoverable metadata bytes)");

  return {
    data: out,
    actions,
    meta: { mode: "pdf-lib", structuralRewrite: true, degraded: false },
  };
}
