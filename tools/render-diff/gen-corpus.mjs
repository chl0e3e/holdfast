// Writes the shared corpus to a TSV both harness sides read.
//
//   node tools/render-diff/gen-corpus.mjs > corpus.tsv
//
// Columns: name, category, flags(JSON), bytes(hex). Hex keeps the file
// line-oriented even though many cases contain NUL, ESC and invalid UTF-8.

import { cases } from "./corpus.mjs";

const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");

const seen = new Set();
for (const c of cases) {
  if (seen.has(c.name)) throw new Error(`duplicate case name: ${c.name}`);
  seen.add(c.name);
  process.stdout.write(`${c.name}\t${c.category}\t${JSON.stringify(c.flags)}\t${hex(c.bytes)}\n`);
}
process.stderr.write(`${cases.length} cases\n`);
