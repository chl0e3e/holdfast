// Client side of the render differential harness.
//
//   node tools/render-diff/gen-corpus.mjs > corpus.tsv
//   cargo run -p hf-terminal-model --example modelgrid < corpus.tsv > model.tsv
//   npx tsx ../../tools/render-diff/xterm-diff.ts corpus.tsv model.tsv   # from web/
//
// For every case it renders the SAME bytes twice and compares the two grids
// cell by cell, characters and attributes alike:
//
//   LIVE  — xterm.js fed the raw PTY bytes, i.e. what you see while attached;
//   SNAP  — xterm.js fed the server model's attach snapshot, i.e. what you see
//           after a roam, a reload, or any reattach.
//
// Those two must be identical. Every rendering bug this project has shipped
// was a case where they were not: the screen looked right until you came back
// to it. Two further checks ride along — the model's own text view against
// LIVE, and the snapshot the model produces when bytes arrive one at a time
// against the one it produces from a single write.

// @xterm/headless ships CommonJS, so it has no named ESM exports.
import headless from "@xterm/headless";
import { ServerWidthAddon, SERVER_WIDTH_VERSION } from "../../web/src/client/server-width.js";
import { readFileSync } from "node:fs";

const { Terminal } = headless;
type Terminal = InstanceType<typeof Terminal>;

// The live probe can capture at any size; the offline corpus is 80x24.
const COLS = Number(process.env.COLS ?? 80);
const ROWS = Number(process.env.ROWS ?? 24);

type Cell = {
  chars: string;
  width: number;
  fg: number;
  fgMode: number;
  bg: number;
  bgMode: number;
  attrs: string;
};

type Grid = { rows: Cell[][]; cursorX: number; cursorY: number };

function unhex(s: string): Uint8Array {
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.substr(i * 2, 2), 16);
  return out;
}

function makeTerminal(cols = COLS, rows = ROWS): Terminal {
  const term = new Terminal({
    cols,
    rows,
    scrollback: 10_000,
    allowProposedApi: true,
    convertEol: false,
  });
  term.loadAddon(new ServerWidthAddon() as never);
  term.unicode.activeVersion = SERVER_WIDTH_VERSION;
  return term;
}

function write(term: Terminal, data: Uint8Array): Promise<void> {
  return new Promise((resolve) => term.write(data, resolve));
}

/// The visible screen only: the snapshot restores the screen, not scrollback.
function grid(term: Terminal, cols = COLS, rows_ = ROWS): Grid {
  const buf = term.buffer.active;
  const rows: Cell[][] = [];
  for (let y = 0; y < rows_; y++) {
    const line = buf.getLine(buf.baseY + y);
    const cells: Cell[] = [];
    for (let x = 0; x < cols; x++) {
      const cell = line?.getCell(x);
      if (!cell) {
        cells.push({ chars: "", width: 1, fg: 0, fgMode: 0, bg: 0, bgMode: 0, attrs: "" });
        continue;
      }
      // Compare SCREEN COLUMNS, not buffer cells. A zero-width character with
      // no base (a bidi isolate or combining mark at the very start of a line)
      // gets its own buffer cell in xterm.js and none in the model, which
      // shifts every later cell INDEX without moving anything on screen.
      // Fold it into the previous column so only real displacement counts.
      if (cell.getWidth() === 0) {
        const chars = cell.getChars();
        if (chars !== "" && cells.length > 0) cells[cells.length - 1]!.chars += chars;
        else if (chars !== "") cells.push({
          chars, width: 1, fg: cell.getFgColor(), fgMode: cell.getFgColorMode(),
          bg: cell.getBgColor(), bgMode: cell.getBgColorMode(), attrs: "",
        });
        continue;
      }
      const attrs = [
        cell.isBold() ? "b" : "",
        cell.isDim() ? "d" : "",
        cell.isItalic() ? "i" : "",
        cell.isUnderline() ? "u" : "",
        cell.isBlink() ? "k" : "",
        cell.isInverse() ? "r" : "",
        cell.isInvisible() ? "h" : "",
        cell.isStrikethrough() ? "s" : "",
      ].join("");
      cells.push({
        // A never-written cell reports "" and a written blank reports " ";
        // both paint a blank in the cell's own attributes, so the distinction
        // is not user-visible and must not count as a difference.
        chars: cell.getChars() === "" ? " " : cell.getChars(),
        width: cell.getWidth(),
        fg: cell.getFgColor(),
        fgMode: cell.getFgColorMode(),
        bg: cell.getBgColor(),
        bgMode: cell.getBgColorMode(),
        attrs,
      });
    }
    while (cells.length < cols) {
      cells.push({ chars: " ", width: 1, fg: 0, fgMode: 0, bg: 0, bgMode: 0, attrs: "" });
    }
    rows.push(cells.slice(0, cols));
  }
  return { rows, cursorX: buf.cursorX, cursorY: buf.cursorY };
}

function rowText(cells: Cell[]): string {
  return cells.map((c) => (c.width === 0 ? "" : c.chars === "" ? " " : c.chars)).join("").replace(/\s+$/, "");
}

function cellEq(a: Cell, b: Cell): boolean {
  return a.chars === b.chars && a.width === b.width && a.fg === b.fg && a.fgMode === b.fgMode &&
    a.bg === b.bg && a.bgMode === b.bgMode && a.attrs === b.attrs;
}

function describeCell(c: Cell): string {
  const colour = `${c.fgMode}:${c.fg}/${c.bgMode}:${c.bg}`;
  return `${JSON.stringify(c.chars)}w${c.width}${c.attrs ? " " + c.attrs : ""} ${colour}`;
}

type Diff = { kind: string; detail: string[] };

function diffGrids(live: Grid, snap: Grid): Diff[] {
  const diffs: Diff[] = [];
  const cellDetail: string[] = [];
  let differingRows = 0;
  const rowCount = Math.min(live.rows.length, snap.rows.length);
  const colCount = Math.min(live.rows[0]?.length ?? 0, snap.rows[0]?.length ?? 0);
  for (let y = 0; y < rowCount; y++) {
    let rowDiffers = false;
    for (let x = 0; x < colCount; x++) {
      const a = live.rows[y]![x]!;
      const b = snap.rows[y]![x]!;
      if (cellEq(a, b)) continue;
      rowDiffers = true;
      if (cellDetail.length < 6) {
        cellDetail.push(`  r${y}c${x}: live ${describeCell(a)} | snap ${describeCell(b)}`);
      }
    }
    if (rowDiffers) {
      differingRows++;
      if (differingRows <= 3) {
        cellDetail.push(`  row ${y} live: ${JSON.stringify(rowText(live.rows[y]!))}`);
        cellDetail.push(`  row ${y} snap: ${JSON.stringify(rowText(snap.rows[y]!))}`);
      }
    }
  }
  if (differingRows > 0) {
    diffs.push({ kind: "grid", detail: [`${differingRows}/${rowCount} rows differ`, ...cellDetail] });
  }
  if (live.cursorX !== snap.cursorX || live.cursorY !== snap.cursorY) {
    diffs.push({
      kind: "cursor",
      detail: [`live (${live.cursorX},${live.cursorY}) vs snap (${snap.cursorX},${snap.cursorY})`],
    });
  }
  return diffs;
}

async function main() {
  const [corpusPath, modelPath] = process.argv.slice(2);
  if (!corpusPath || !modelPath) {
    console.error("usage: xterm-diff.ts <corpus.tsv> <model.tsv>");
    process.exit(2);
  }
  const only = process.env.ONLY ? new RegExp(process.env.ONLY) : null;

  const corpus = new Map<string, { category: string; bytes: Uint8Array; bounded?: string }>();
  for (const line of readFileSync(corpusPath, "utf8").split("\n")) {
    if (!line.trim()) continue;
    const [name, category, flags, hex] = line.split("\t");
    const parsed = flags ? JSON.parse(flags) : {};
    corpus.set(name!, { category: category!, bytes: unhex(hex!), bounded: parsed.bounded });
  }
  const model = new Map<string, {
    snapshot: Uint8Array; visible: string; chunked: Uint8Array;
    grown?: Uint8Array; shrunk?: Uint8Array;
  }>();
  for (const line of readFileSync(modelPath, "utf8").split("\n")) {
    if (!line.trim()) continue;
    const [name, snapshot, visible, chunked, grown, shrunk] = line.split("\t");
    model.set(name!, {
      snapshot: unhex(snapshot!),
      visible: new TextDecoder().decode(unhex(visible!)),
      chunked: unhex(chunked!),
      grown: grown ? unhex(grown) : undefined,
      shrunk: shrunk ? unhex(shrunk) : undefined,
    });
  }

  let pass = 0;
  const failures: { name: string; category: string; diffs: Diff[] }[] = [];
  // Divergences the model bounds on purpose: reported, never silently passed.
  const bounded: { name: string; why: string }[] = [];

  for (const [name, entry] of corpus) {
    if (only && !only.test(name)) continue;
    const m = model.get(name);
    if (!m) {
      failures.push({ name, category: entry.category, diffs: [{ kind: "missing", detail: ["no model row"] }] });
      continue;
    }

    const liveTerm = makeTerminal();
    await write(liveTerm, entry.bytes);
    const live = grid(liveTerm);

    const snapTerm = makeTerminal();
    await write(snapTerm, m.snapshot);
    const snap = grid(snapTerm);

    const diffs = diffGrids(live, snap);

    // Roaming: the client resizes its own terminal and reattaches, so the
    // snapshot taken at the new size must match what the live terminal shows
    // once resized to it. Mismatches here are what "opened it on the laptop
    // and the screen was mangled" looks like.
    for (const [label, expected, cols, rows] of [
      ["resize-grow", m.grown, 100, 30],
      ["resize-shrink", m.shrunk, 60, 20],
    ] as const) {
      if (!expected) continue;
      const resized = makeTerminal();
      await write(resized, entry.bytes);
      resized.resize(cols, rows);
      const after = grid(resized, cols, rows);

      const fresh = makeTerminal(cols, rows);
      await write(fresh, expected);
      const fromSnap = grid(fresh, cols, rows);

      for (const d of diffGrids(after, fromSnap)) {
        diffs.push({ kind: `${label}:${d.kind}`, detail: d.detail });
      }
      resized.dispose();
      fresh.dispose();
    }

    // The model's own text view should match what the client shows. The live
    // probe cannot see it, and leaves the column empty to skip this check.
    const liveText = live.rows.map(rowText).join("\n").replace(/\n+$/, "");
    const modelText = m.visible.split("\n").map((l) => l.replace(/\s+$/, "")).join("\n").replace(/\n+$/, "");
    if (m.visible.length > 0 && liveText !== modelText) {
      const liveLines = liveText.split("\n");
      const modelLines = modelText.split("\n");
      const detail: string[] = [];
      for (let i = 0; i < Math.max(liveLines.length, modelLines.length) && detail.length < 6; i++) {
        if (liveLines[i] !== modelLines[i]) {
          detail.push(`  row ${i} xterm: ${JSON.stringify(liveLines[i] ?? null)}`);
          detail.push(`  row ${i} model: ${JSON.stringify(modelLines[i] ?? null)}`);
        }
      }
      diffs.push({ kind: "model-text", detail });
    }

    // A PTY delivers bytes in arbitrary chunks; the snapshot must not depend
    // on how they were split.
    if (Buffer.compare(Buffer.from(m.snapshot), Buffer.from(m.chunked)) !== 0) {
      const chunkTerm = makeTerminal();
      await write(chunkTerm, m.chunked);
      const chunkGrid = grid(chunkTerm);
      const gridDiffs = diffGrids(snap, chunkGrid);
      diffs.push({
        kind: "chunk-boundary",
        detail: gridDiffs.length === 0
          ? ["snapshot bytes differ but render identically (benign)"]
          : gridDiffs.flatMap((d) => [`whole-write vs byte-at-a-time: ${d.kind}`, ...d.detail]),
        // Only a rendered difference is a real bug.
        ...(gridDiffs.length === 0 ? { benign: true } : {}),
      } as Diff & { benign?: boolean });
    }

    const real = diffs.filter((d) => !(d as Diff & { benign?: boolean }).benign);
    if (real.length === 0) pass++;
    else if (entry.bounded) bounded.push({ name, why: entry.bounded });
    else failures.push({ name, category: entry.category, diffs: real });

    liveTerm.dispose();
    snapTerm.dispose();
  }

  for (const f of failures) {
    console.log(`FAIL [${f.category}] ${f.name}`);
    for (const d of f.diffs) {
      console.log(`  ${d.kind}:`);
      for (const line of d.detail) console.log(`  ${line}`);
    }
    console.log("");
  }

  const byCategory = new Map<string, number>();
  for (const f of failures) byCategory.set(f.category, (byCategory.get(f.category) ?? 0) + 1);
  if (bounded.length > 0) {
    console.log("Diverges by design (bounded, not a defect):");
    for (const b of bounded) console.log(`  ${b.name} — ${b.why}`);
    console.log("");
  }
  console.log("=".repeat(60));
  console.log(`pass ${pass}  fail ${failures.length}  bounded ${bounded.length}`);
  for (const [cat, n] of [...byCategory].sort((a, b) => b[1] - a[1])) {
    console.log(`  ${cat}: ${n} failing`);
  }
  process.exit(failures.length > 0 ? 1 : 0);
}

main();
