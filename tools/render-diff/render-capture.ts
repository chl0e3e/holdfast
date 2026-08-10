// Render a captured byte stream through xterm.js and print the resulting grid.
//
//   COLS=155 ROWS=40 npx tsx render-capture.ts <corpus.tsv> [row-filter-regex]
//
// The live probe writes its capture in the corpus TSV format, so this shows
// exactly what a client painted from those bytes — the quickest way to see a
// layout defect rather than infer it from a cell-by-cell diff. With a filter,
// only matching rows are printed, with their row numbers and lengths, which is
// how column drift becomes obvious: rows that should end at the same column
// don't.

import headless from "@xterm/headless";
import { ServerWidthAddon, SERVER_WIDTH_VERSION } from "../../web/src/client/server-width.js";
import { readFileSync } from "node:fs";

const { Terminal } = headless;
const COLS = Number(process.env.COLS ?? 80);
const ROWS = Number(process.env.ROWS ?? 24);

const [path, filter] = process.argv.slice(2);
if (!path) {
  console.error("usage: render-capture.ts <corpus.tsv> [row-filter-regex]");
  process.exit(2);
}
const re = filter ? new RegExp(filter) : null;

const hex = readFileSync(path, "utf8").split("\n")[0]!.split("\t")[3]!;
const bytes = Uint8Array.from(hex.match(/../g)!.map((h) => parseInt(h, 16)));

const term = new Terminal({ cols: COLS, rows: ROWS, allowProposedApi: true, scrollback: 10_000 });
term.loadAddon(new ServerWidthAddon() as never);
term.unicode.activeVersion = SERVER_WIDTH_VERSION;
await new Promise<void>((resolve) => term.write(bytes, () => resolve()));

const buf = term.buffer.active;
for (let y = 0; y < ROWS; y++) {
  const line = buf.getLine(buf.baseY + y);
  if (!line) continue;
  const text = line.translateToString(false).replace(/\s+$/, "");
  if (re && !re.test(text)) continue;
  if (!re && !text) continue;
  console.log(`${String(y).padStart(2)} len=${String(text.length).padStart(3)} |${text}`);
}
console.log(`cursor: col ${buf.cursorX}, row ${buf.cursorY}`);
