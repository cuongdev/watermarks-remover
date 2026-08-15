/**
 * Provenance Examiner — a bilingual (Vietnamese / English) browser front end
 * for watermark-text-check. Everything runs client side; pasted or dropped
 * content never leaves the page. The app calls the library directly and
 * renders its evidence.
 */

import {
  cleanText,
  inspectContainer,
  inspectImage,
  inspectText,
  scanText,
  detectC2paManifest,
  classifyInput,
  type ContainerInspectReport,
  type HitKind,
  type ImageInspectReport,
  type TextInspectReport,
  type TextMark,
} from "../../../libs/watermark-text-check/src/index.js";

const $ = <T extends HTMLElement>(sel: string): T => {
  const el = document.querySelector<T>(sel);
  if (!el) throw new Error(`missing element: ${sel}`);
  return el;
};

type Lang = "vi" | "en";
type Severity = "clear" | "weak" | "marked";

// ---------------------------------------------------------------------------
// Dictionary
// ---------------------------------------------------------------------------

interface Verdict {
  kicker: string;
  line: string;
  note: string;
}

interface Pack {
  langName: string; // shown on the toggle for the OTHER language
  theme: string;
  role: string;
  headline: string; // innerHTML (contains a .mono span)
  lede: string;
  tabText: string;
  tabFile: string;
  placeholder: string;
  run: string;
  loadSpec: string;
  clear: string;
  copy: string;
  copied: string;
  optAggr: string;
  optParanoid: string;
  labExhibit: string;
  labLedger: string;
  labCleaned: string;
  dzTitle: string;
  dzSub: string;
  footProves: string;
  footNot: string;
  footRuns: string;
  exhibitEmpty: string;
  ledgerHead: [string, string, string, string, string, string];
  fileHead: [string, string];
  kindLabel: Record<HitKind, string>;
  kindWhy: Record<HitKind, string>;
  conf: Record<string, string>;
  verdict: Record<Severity, Verdict>;
  countZero: string;
  count: (total: number, classes: number) => string;
  remedyStats: (removed: number, normalised: number) => string;
  fileKicker: { c2pa: string; ai: string; none: string };
  fileLine: { c2pa: string; ai: string; none: string };
  fileMeta: (name: string, fmt: string, bytes: number) => string;
  manifest: (labels: string) => string;
  noFindings: (note: string) => string;
}

const VI: Pack = {
  langName: "EN",
  theme: "Giao diện",
  role: "kiểm tra provenance và dấu chìm tất định",
  headline:
    'Kiểm tra xem văn bản có phải do <span class="mono">AI tạo ra</span> hay không, và xem bằng chứng.',
  lede:
    "Dán văn bản hoặc thả một tệp vào. Công cụ phát hiện các ký tự vô hình, manifest đã ký, và metadata mà phần mềm để lại, rồi chỉ rõ từng dấu vết nằm ở đâu. Nó đưa ra bằng chứng, không phải phán đoán.",
  tabText: "Kiểm tra văn bản",
  tabFile: "Kiểm tra tệp",
  placeholder:
    "Dán văn bản cần kiểm tra. Nội dung không rời khỏi trang này, toàn bộ phân tích chạy ngay trong trình duyệt của bạn.",
  run: "Kiểm tra",
  loadSpec: "Nạp mẫu có dấu vết",
  clear: "Xóa",
  copy: "Sao chép",
  copied: "Đã chép",
  optAggr: "đánh dấu chữ cái giả dạng",
  optParanoid: "đánh dấu ký tự nối emoji",
  labExhibit: "Tang vật đã đánh dấu",
  labLedger: "Bảng bằng chứng",
  labCleaned: "Bản đã làm sạch",
  dzTitle: "Thả tệp vào đây, hoặc bấm để chọn",
  dzSub: "PNG · JPEG · PDF · DOCX · ODT · SVG · HTML · Markdown",
  footProves:
    '<span class="mono">Chứng minh điều gì.</span> Một phát hiện nghĩa là nội dung mang một dấu vết tất định: một ký tự vô hình, một manifest C2PA, hoặc một trường metadata AI. Đó là bằng chứng cụ thể cho thấy nội dung đã đi qua phần mềm.',
  footNot:
    '<span class="mono">Không chứng minh điều gì.</span> Kết quả sạch không phải bằng chứng do con người viết. Dấu chìm token sampling thống kê không để lại dấu vết nhìn thấy và nằm ngoài phạm vi ở đây. Vắng bằng chứng không phải bằng chứng của sự vắng mặt.',
  footRuns:
    'Chạy hoàn toàn trong trình duyệt của bạn trên thư viện <span class="mono">watermark-text-check</span>. Không có gì bạn dán hay thả bị tải lên. Dùng cho việc vệ sinh nội dung bạn sở hữu, và đối chiếu mọi thao tác gỡ metadata với nghĩa vụ pháp lý và lưu trữ hồ sơ của bạn.',
  exhibitEmpty: "Chưa có gì để hiển thị.",
  ledgerHead: ["Điểm mã", "Tên", "Loại", "Độ tin cậy", "Số lần", "Vị trí"],
  fileHead: ["Độ tin cậy", "Phát hiện"],
  kindLabel: {
    strip: "Điều khiển định dạng",
    bidi: "Điều khiển hai chiều",
    tag_chars: "Ký tự tag",
    variation_selector: "Bộ chọn biến thể",
    zwj_family: "Ký tự bề rộng 0",
    private_use: "Điểm mã dùng riêng",
    space: "Khoảng trắng thay thế",
    confusable: "Chữ cái giả dạng",
    other_cf: "Ký tự định dạng",
  },
  kindWhy: {
    strip: "Một ký tự điều khiển vô hình, không có chỗ trong văn bản gõ tay.",
    bidi: "Đảo thứ tự chữ một cách vô hình, một phương tiện chở dữ liệu ẩn đã biết.",
    tag_chars: "Điểm mã tag đã lỗi thời, dùng để giấu dữ liệu bên trong văn bản.",
    variation_selector: "Chọn một biến thể glyph không nhìn thấy, một phương tiện giấu tin phổ biến.",
    zwj_family: "Một ký tự bề rộng 0 mà bạn không thấy và không gõ.",
    private_use: "Một điểm mã không có nghĩa chuẩn, được gán riêng.",
    space: "Một khoảng trắng nhái U+0020, có thể mã hóa một mẫu ẩn.",
    confusable: "Một chữ cái từ hệ chữ khác nhái theo chữ Latinh.",
    other_cf: "Một ký tự định dạng vô hình nằm ngoài chữ viết thông thường.",
  },
  conf: {
    confirmed: "xác nhận",
    probable: "nhiều khả năng",
    informational: "tham khảo",
    likely_false_positive: "có thể nhầm",
  },
  verdict: {
    marked: {
      kicker: "Có dấu vết provenance",
      line: "Văn bản này chứa các ký tự vô hình mà việc gõ phím thông thường không tạo ra.",
      note: "Các ký tự bề rộng 0 và điều khiển định dạng như thế này là cách phần mềm gắn thẻ hoặc đóng dấu chìm văn bản do máy viết. Sự hiện diện của chúng là bằng chứng mạnh cho thấy văn bản đã đi qua phần mềm, không phải gõ tay.",
    },
    weak: {
      kicker: "Chỉ có tín hiệu yếu",
      line: "Bất thường duy nhất là khoảng trắng thay thế hoặc chữ cái giả dạng.",
      note: "Chúng có thể đến từ thao tác sao chép dán, trình soạn thảo, hoặc bàn phím không phải Latinh. Tự thân chúng không chứng minh nguồn gốc từ máy. Hãy xem là ngữ cảnh, không phải kết luận.",
    },
    clear: {
      kicker: "Không tìm thấy dấu vết provenance",
      line: "Không phát hiện ký tự vô hình, điều khiển hai chiều, hay ký tự tag nào.",
      note: "Công cụ chỉ tìm dấu chìm tất định và ký tự ẩn. Nó không thấy được dấu chìm dạng token sampling thống kê, nên kết quả sạch không chứng minh văn bản do con người viết.",
    },
  },
  countZero: "0 dấu vết",
  count: (t, c) => `${t} dấu vết · ${c} loại`,
  remedyStats: (r, n) => `đã gỡ ${r}, đã chuẩn hóa ${n}`,
  fileKicker: {
    c2pa: "Có provenance đã ký",
    ai: "Có metadata AI",
    none: "Không có metadata provenance",
  },
  fileLine: {
    c2pa: "Tệp có nhúng một manifest content credentials theo chuẩn C2PA.",
    ai: "Tệp mang metadata gắn với việc tạo bằng AI.",
    none: "Không phát hiện manifest C2PA hay trường metadata AI nào.",
  },
  fileMeta: (name, fmt, bytes) => `${name} · ${fmt} · ${bytes.toLocaleString("vi")} byte`,
  manifest: (labels) =>
    `<span class="chip chip--marked"><span class="chip-cp">C2PA</span></span> kho manifest được phân tích từ các hộp JUMBF của tệp${labels ? ` · nhãn: <span class="mono">${labels}</span>` : ""}`,
  noFindings: (note) => `Không có phát hiện. ${note}`,
};

const EN: Pack = {
  langName: "VI",
  theme: "Theme",
  role: "deterministic provenance and watermark inspection",
  headline:
    'Find out whether text was <span class="mono">made by AI</span>, and see the proof.',
  lede:
    "Paste text or drop a file. The examiner reveals the invisible characters, signed manifests, and metadata that software leaves behind, then shows exactly where each one sits. It reports evidence, not opinions.",
  tabText: "Examine text",
  tabFile: "Examine a file",
  placeholder:
    "Paste the text you want examined. It never leaves this page, the analysis runs entirely in your browser.",
  run: "Examine",
  loadSpec: "Load a marked specimen",
  clear: "Clear",
  copy: "Copy",
  copied: "Copied",
  optAggr: "flag lookalike letters",
  optParanoid: "flag emoji glue",
  labExhibit: "Marked exhibit",
  labLedger: "Evidence ledger",
  labCleaned: "Cleaned copy",
  dzTitle: "Drop a file, or click to choose",
  dzSub: "PNG · JPEG · PDF · DOCX · ODT · SVG · HTML · Markdown",
  footProves:
    '<span class="mono">What this proves.</span> A finding means the content carries a deterministic marker: an invisible character, a C2PA manifest, or an AI metadata field. That is concrete evidence the content passed through software.',
  footNot:
    '<span class="mono">What it does not prove.</span> A clean result is not proof a human wrote it. Statistical token sampling watermarks leave no visible trace and are out of scope here. Absence of evidence is not evidence of absence.',
  footRuns:
    'Runs fully in your browser on the <span class="mono">watermark-text-check</span> library. Nothing you paste or drop is uploaded. Use it for hygiene on content you own, and confirm any metadata removal against your own legal and records retention obligations.',
  exhibitEmpty: "Nothing to show.",
  ledgerHead: ["Codepoint", "Name", "Class", "Confidence", "Count", "At offset"],
  fileHead: ["Confidence", "Finding"],
  kindLabel: {
    strip: "Format control",
    bidi: "Bidirectional control",
    tag_chars: "Tag character",
    variation_selector: "Variation selector",
    zwj_family: "Zero width character",
    private_use: "Private use codepoint",
    space: "Substitute space",
    confusable: "Lookalike letter",
    other_cf: "Format character",
  },
  kindWhy: {
    strip: "An invisible formatting control with no place in typed prose.",
    bidi: "Reorders text invisibly, a known carrier for hidden payloads.",
    tag_chars: "Deprecated tag codepoints, used to smuggle data inside text.",
    variation_selector: "Selects an unseen glyph variant, a common stego carrier.",
    zwj_family: "A zero width character you cannot see and did not type.",
    private_use: "A codepoint with no standard meaning, assigned privately.",
    space: "A space that imitates U+0020, can encode a hidden pattern.",
    confusable: "A letter from another script that mimics a Latin one.",
    other_cf: "An invisible format character outside normal writing.",
  },
  conf: {
    confirmed: "confirmed",
    probable: "probable",
    informational: "informational",
    likely_false_positive: "likely false positive",
  },
  verdict: {
    marked: {
      kicker: "Provenance markers present",
      line: "This text carries invisible characters that normal typing does not produce.",
      note: "Zero width and format controls like these are how tools tag or watermark machine written text. Their presence is strong evidence the text was processed by software, not typed by hand.",
    },
    weak: {
      kicker: "Weak signals only",
      line: "The only anomalies are substitute spaces or lookalike letters.",
      note: "These can come from copy paste, word processors, or non Latin keyboards. On their own they are not proof of machine origin. Read them as context, not a verdict.",
    },
    clear: {
      kicker: "No provenance markers found",
      line: "No invisible carriers, bidirectional controls, or tag characters were detected.",
      note: "This checks for deterministic watermarks and hidden characters only. It cannot see statistical token sampling watermarks, so a clean result is not proof the text was written by a human.",
    },
  },
  countZero: "0 markers",
  count: (t, c) => `${t} marker${t === 1 ? "" : "s"} · ${c} class${c === 1 ? "" : "es"}`,
  remedyStats: (r, n) => `${r} removed, ${n} normalised`,
  fileKicker: {
    c2pa: "Signed provenance found",
    ai: "AI metadata found",
    none: "No provenance metadata",
  },
  fileLine: {
    c2pa: "The file embeds a C2PA content credentials manifest.",
    ai: "The file carries metadata associated with AI generation.",
    none: "No C2PA manifest or AI metadata fields were detected.",
  },
  fileMeta: (name, fmt, bytes) => `${name} · ${fmt} · ${bytes.toLocaleString("en")} bytes`,
  manifest: (labels) =>
    `<span class="chip chip--marked"><span class="chip-cp">C2PA</span></span> manifest store parsed from the file's JUMBF boxes${labels ? ` · labels: <span class="mono">${labels}</span>` : ""}`,
  noFindings: (note) => `No findings. ${note}`,
};

const PACKS: Record<Lang, Pack> = { vi: VI, en: EN };
const LANG_KEY = "examiner-lang";

let LANG: Lang = "vi";
let P: Pack = VI;

function detectInitialLang(): Lang {
  try {
    const saved = localStorage.getItem(LANG_KEY);
    if (saved === "vi" || saved === "en") return saved;
  } catch {
    /* ignore */
  }
  // Vietnamese is the default; a returning visitor's saved choice wins above.
  return "vi";
}

const SPECIMEN =
  "Báo cáo quý\u200B đã được\u2060 hội đồng xem xét\u200B và\u200E phê duyệt\u00A0mà không\u2003 chỉnh sửa\u200B.";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function esc(s: string): string {
  return s.replace(/[&<>"]/g, (c) =>
    c === "&" ? "&amp;" : c === "<" ? "&lt;" : c === ">" ? "&gt;" : "&quot;",
  );
}

function cp(codepoint: number): string {
  return "U+" + codepoint.toString(16).toUpperCase().padStart(4, "0");
}

function textSeverity(report: TextInspectReport): Severity {
  if (report.suspiciousTotal === 0) return "clear";
  return report.hits.some((h) => h.confidence === "probable") ? "marked" : "weak";
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function renderExhibit(text: string, marks: TextMark[]): string {
  if (!text) return `<span class="exhibit-empty">${P.exhibitEmpty}</span>`;
  const byOffset = new Map<number, TextMark>();
  for (const m of marks) byOffset.set(m.utf16Index, m);

  let html = "";
  let i = 0;
  while (i < text.length) {
    const mark = byOffset.get(i);
    if (mark) {
      const sev = mark.confidence === "probable" ? "marked" : "weak";
      html +=
        `<mark class="chip chip--${sev}" tabindex="0" ` +
        `title="${esc(mark.label)}, ${esc(P.kindWhy[mark.kind])}">` +
        `<span class="chip-cp">${cp(mark.codepoint)}</span></mark>`;
      i += mark.utf16Length;
      continue;
    }
    let next = text.length;
    for (const off of byOffset.keys()) {
      if (off > i && off < next) next = off;
    }
    html += esc(text.slice(i, next)).replace(/\n/g, "<br>");
    i = next;
  }
  return html;
}

function renderLedger(report: TextInspectReport): string {
  if (!report.hits.length) return "";
  const rows = report.hits
    .map((h) => {
      const sev = h.confidence === "probable" ? "marked" : "weak";
      const offsets = h.samples.slice(0, 6).join(", ") + (h.count > 6 ? ", …" : "");
      return `<tr>
        <td class="mono">${cp(h.codepoint)}</td>
        <td>${esc(h.label.replace(/^U\+[0-9A-F]+ /, ""))}</td>
        <td>${P.kindLabel[h.kind]}</td>
        <td><span class="dot dot--${sev}"></span>${P.conf[h.confidence] ?? h.confidence}</td>
        <td class="num">${h.count}</td>
        <td class="mono num">${offsets}</td>
      </tr>`;
    })
    .join("");
  const head = P.ledgerHead.map((h) => `<th>${h}</th>`).join("");
  return `<table class="ledger"><thead><tr>${head}</tr></thead><tbody>${rows}</tbody></table>`;
}

// ---------------------------------------------------------------------------
// Examination
// ---------------------------------------------------------------------------

function examineText(): void {
  const input = $<HTMLTextAreaElement>("#specimen").value;
  const aggressive = $<HTMLInputElement>("#opt-aggressive").checked;
  const stripEmojiGlue = $<HTMLInputElement>("#opt-paranoid").checked;
  const opts = { aggressive, stripEmojiGlue };

  const report = inspectText(input, opts);
  const marks = scanText(input, opts);
  const sev = textSeverity(report);
  const v = P.verdict[sev];

  const results = $<HTMLElement>("#text-results");
  results.hidden = false;
  results.dataset["sev"] = sev;

  $<HTMLElement>("#verdict-kicker").textContent = v.kicker;
  $<HTMLElement>("#verdict-line").textContent = v.line;
  $<HTMLElement>("#verdict-note").textContent = v.note;
  $<HTMLElement>("#verdict-count").textContent =
    report.suspiciousTotal === 0 ? P.countZero : P.count(report.suspiciousTotal, report.hits.length);

  $<HTMLElement>("#exhibit").innerHTML = renderExhibit(input, marks);
  $<HTMLElement>("#ledger-wrap").innerHTML = renderLedger(report);

  const remedy = $<HTMLElement>("#remedy");
  if (report.suspiciousTotal > 0) {
    const { text: cleaned, stats } = cleanText(input, {
      aggressiveHomoglyphs: aggressive,
      stripEmojiGlue,
    });
    remedy.hidden = false;
    $<HTMLTextAreaElement>("#cleaned").value = cleaned;
    $<HTMLElement>("#remedy-stats").textContent = P.remedyStats(stats.removedCount, stats.replacedCount);
  } else {
    remedy.hidden = true;
  }
}

let lastFile: File | null = null;

async function examineFile(file: File): Promise<void> {
  lastFile = file;
  const bytes = new Uint8Array(await file.arrayBuffer());
  const kind = await classifyInput(file.name, bytes);
  const out = $<HTMLElement>("#file-results");
  out.hidden = false;

  let findings: string[] = [];
  let confidence: string[] = [];
  let hasC2pa = false;
  let hasAi = false;
  let format = kind as string;
  let notes: string[] = [];

  if (kind === "image") {
    const report: ImageInspectReport = inspectImage(bytes);
    ({ hasC2pa } = report);
    hasAi = report.hasAiMetadata;
    format = report.format;
    findings = report.findings;
    confidence = report.findingsConfidence;
    notes = report.notes;
  } else if (kind === "container") {
    const report: ContainerInspectReport = await inspectContainer(bytes, file.name);
    ({ hasC2pa } = report);
    hasAi = report.hasAiMetadata;
    format = report.format;
    findings = report.findings;
    confidence = report.findingsConfidence;
    notes = report.notes;
  } else {
    const report = inspectText(new TextDecoder().decode(bytes));
    hasAi = report.suspiciousTotal > 0;
    format = "text";
    findings = report.hits.map((h) => `${cp(h.codepoint)} ${P.kindLabel[h.kind]} ×${h.count}`);
    confidence = report.hits.map((h) => h.confidence);
    notes = report.notes.slice(0, 1);
  }

  let manifestLabels: string[] = [];
  if (kind === "image") {
    const det = detectC2paManifest(bytes);
    if (det.hasManifest) {
      hasC2pa = true;
      manifestLabels = det.labels;
    }
  }

  const sev: Severity = hasC2pa ? "marked" : hasAi ? "weak" : "clear";
  out.dataset["sev"] = sev;

  const which = hasC2pa ? "c2pa" : hasAi ? "ai" : "none";
  $<HTMLElement>("#file-kicker").textContent = P.fileKicker[which];
  $<HTMLElement>("#file-line").textContent = P.fileLine[which];
  $<HTMLElement>("#file-meta").textContent = P.fileMeta(file.name, format.toUpperCase(), bytes.length);

  const manifest = $<HTMLElement>("#file-manifest");
  if (manifestLabels.length || hasC2pa) {
    manifest.hidden = false;
    manifest.innerHTML = P.manifest(manifestLabels.length ? esc(manifestLabels.join(", ")) : "");
  } else {
    manifest.hidden = true;
  }

  const wrap = $<HTMLElement>("#file-ledger-wrap");
  if (findings.length) {
    const rows = findings
      .map((f, idx) => {
        const c = confidence[idx] ?? "informational";
        const dot = c === "confirmed" || c === "probable" ? "marked" : "weak";
        return `<tr><td><span class="dot dot--${dot}"></span>${P.conf[c] ?? c}</td><td>${esc(f)}</td></tr>`;
      })
      .join("");
    wrap.innerHTML = `<table class="ledger ledger--file"><thead><tr><th>${P.fileHead[0]}</th><th>${P.fileHead[1]}</th></tr></thead><tbody>${rows}</tbody></table>`;
  } else {
    wrap.innerHTML = `<p class="quiet">${esc(P.noFindings(notes[0] ?? ""))}</p>`;
  }
}

// ---------------------------------------------------------------------------
// Language
// ---------------------------------------------------------------------------

function applyLang(): void {
  P = PACKS[LANG];
  document.documentElement.lang = LANG;

  document.querySelectorAll<HTMLElement>("[data-i18n]").forEach((el) => {
    const key = el.dataset["i18n"] as keyof Pack;
    const val = P[key];
    if (typeof val === "string") el.textContent = val;
  });
  document.querySelectorAll<HTMLElement>("[data-i18n-html]").forEach((el) => {
    const key = el.dataset["i18nHtml"] as keyof Pack;
    const val = P[key];
    if (typeof val === "string") el.innerHTML = val;
  });
  document.querySelectorAll<HTMLElement>("[data-i18n-ph]").forEach((el) => {
    const key = el.dataset["i18nPh"] as keyof Pack;
    const val = P[key];
    if (typeof val === "string") (el as HTMLTextAreaElement).placeholder = val;
  });

  $<HTMLElement>("#lang-toggle").textContent = P.langName;

  // Re-render any open results in the new language.
  if (!$<HTMLElement>("#text-results").hidden) examineText();
  if (!$<HTMLElement>("#file-results").hidden && lastFile) void examineFile(lastFile);
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

function setupTabs(): void {
  const tabs = document.querySelectorAll<HTMLButtonElement>("[data-tab]");
  const panels = document.querySelectorAll<HTMLElement>("[data-panel]");
  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      const name = tab.dataset["tab"];
      tabs.forEach((t) => {
        const on = t === tab;
        t.classList.toggle("is-on", on);
        t.setAttribute("aria-selected", on ? "true" : "false");
      });
      panels.forEach((p) => {
        p.hidden = p.dataset["panel"] !== name;
      });
    });
  });
}

function copyFrom(sel: string, btn: HTMLElement): void {
  const el = document.querySelector<HTMLTextAreaElement>(sel);
  if (!el) return;
  void navigator.clipboard.writeText(el.value).then(() => {
    const prev = btn.textContent;
    btn.textContent = P.copied;
    window.setTimeout(() => (btn.textContent = prev), 1200);
  });
}

function init(): void {
  LANG = detectInitialLang();
  setupTabs();
  applyLang();

  $<HTMLButtonElement>("#lang-toggle").addEventListener("click", () => {
    LANG = LANG === "vi" ? "en" : "vi";
    try {
      localStorage.setItem(LANG_KEY, LANG);
    } catch {
      /* ignore */
    }
    applyLang();
  });

  $<HTMLButtonElement>("#run-text").addEventListener("click", examineText);
  $<HTMLButtonElement>("#load-specimen").addEventListener("click", () => {
    $<HTMLTextAreaElement>("#specimen").value = SPECIMEN;
    examineText();
  });
  $<HTMLButtonElement>("#clear-text").addEventListener("click", () => {
    $<HTMLTextAreaElement>("#specimen").value = "";
    $<HTMLElement>("#text-results").hidden = true;
  });
  $<HTMLButtonElement>("#copy-clean").addEventListener("click", (e) =>
    copyFrom("#cleaned", e.currentTarget as HTMLElement),
  );
  $<HTMLTextAreaElement>("#specimen").addEventListener("keydown", (e) => {
    if ((e.metaKey || e.ctrlKey) && e.key === "Enter") examineText();
  });

  const drop = $<HTMLElement>("#dropzone");
  const fileInput = $<HTMLInputElement>("#file-input");
  drop.addEventListener("click", () => fileInput.click());
  drop.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      fileInput.click();
    }
  });
  fileInput.addEventListener("change", () => {
    const f = fileInput.files?.[0];
    if (f) void examineFile(f);
  });
  ["dragover", "dragenter"].forEach((ev) =>
    drop.addEventListener(ev, (e) => {
      e.preventDefault();
      drop.classList.add("is-over");
    }),
  );
  ["dragleave", "drop"].forEach((ev) =>
    drop.addEventListener(ev, (e) => {
      e.preventDefault();
      drop.classList.remove("is-over");
    }),
  );
  drop.addEventListener("drop", (e) => {
    const f = (e as DragEvent).dataTransfer?.files?.[0];
    if (f) void examineFile(f);
  });
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
