// Parse every ```mermaid block in README.md and docs/**/*.md with mermaid.parse(), without a browser
// (jsdom provides the DOM that mermaid's sanitiser expects). Exits 1 and names the block on any parse
// error, or when no block is found. Used by the docs workflow; mkdocs --strict does not parse mermaid.
//
//   npm install --no-save mermaid@11 jsdom@26   # once, in the repo root or a scratch directory
//   node scripts/check_mermaid.mjs [files or folders ...]
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { JSDOM } from "jsdom";

const dom = new JSDOM("<!doctype html><html><body></body></html>", { pretendToBeVisual: true });
globalThis.window = dom.window;
globalThis.document = dom.window.document;
for (const k of ["Element", "HTMLElement", "Node", "DOMParser", "navigator"]) {
  if (!(k in globalThis)) globalThis[k] = dom.window[k];
}
const { default: mermaid } = await import("mermaid");
mermaid.initialize({ startOnLoad: false });

function markdownFiles(p) {
  if (statSync(p).isDirectory()) {
    return readdirSync(p).flatMap((f) => markdownFiles(join(p, f)));
  }
  return p.endsWith(".md") ? [p] : [];
}

const targets = process.argv.length > 2 ? process.argv.slice(2) : ["README.md", "docs"];
const files = targets.flatMap(markdownFiles);
let blocks = 0;
let failed = 0;
for (const f of files) {
  const text = readFileSync(f, "utf8");
  const re = /^([ \t]*)```mermaid[ \t]*\r?\n([\s\S]*?)^\1```/gm;
  for (const m of text.matchAll(re)) {
    blocks += 1;
    const line = text.slice(0, m.index).split("\n").length;
    const code = m[2].split(/\r?\n/).map((l) => l.slice(m[1].length)).join("\n");
    try {
      const r = await mermaid.parse(code);
      console.log(`ok   ${f}:${line} (${r && r.diagramType ? r.diagramType : "parsed"})`);
    } catch (e) {
      failed += 1;
      console.log(`FAIL ${f}:${line}: ${String(e.message || e).split("\n").slice(0, 3).join(" | ")}`);
    }
  }
}
console.log(`${blocks} mermaid block(s), ${failed} failed`);
process.exit(failed || blocks === 0 ? 1 : 0);
