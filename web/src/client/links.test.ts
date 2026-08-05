import assert from "node:assert/strict";

import {
  DOCKERWM_DEFAULT,
  dockerwmOpenUrl,
  findLinks,
  loadDockerwmBase,
  rowText,
  type CellReader,
} from "./links.js";

// --- findLinks ---

assert.deepEqual(findLinks("no links here"), [], "plain text → nothing");
assert.deepEqual(
  findLinks("see https://example.com/x for details"),
  [{ start: 4, end: 25, url: "https://example.com/x" }],
  "basic https link with offsets",
);
assert.equal(findLinks("http://a.b and https://c.d/e?f=1&g=2")!.length, 2, "two links");
assert.equal(
  findLinks("go to https://example.com/page, then stop")[0]!.url,
  "https://example.com/page",
  "trailing comma stripped",
);
assert.equal(
  findLinks("(see https://example.com/page)")[0]!.url,
  "https://example.com/page",
  "unbalanced closing paren stripped",
);
assert.equal(
  findLinks("https://en.wikipedia.org/wiki/Foo_(bar)")[0]!.url,
  "https://en.wikipedia.org/wiki/Foo_(bar)",
  "balanced paren kept",
);
assert.equal(
  findLinks("wow https://example.com/a!?")[0]!.url,
  "https://example.com/a",
  "stacked trailing punctuation stripped",
);
assert.deepEqual(findLinks("ftp://example.com/x gopher://y"), [], "non-http schemes ignored");
assert.deepEqual(findLinks("visit https://x. now"), [], "too short after stripping → dropped");
assert.equal(
  findLinks("https://a.example/x ".repeat(100)).length,
  32,
  "per-row link count is bounded",
);

// --- rowText: string index ↔ buffer column mapping ---

function fakeLine(cells: [string, number][]): CellReader {
  // Expand wide cells with their trailing width-0 half, like a real buffer.
  const expanded: { chars: string; width: number }[] = [];
  for (const [chars, width] of cells) {
    expanded.push({ chars, width });
    if (width === 2) expanded.push({ chars: "", width: 0 });
  }
  return {
    length: expanded.length,
    getCell: (x) => {
      const cell = expanded[x];
      return cell && { getChars: () => cell.chars, getWidth: () => cell.width };
    },
  };
}

{
  const { text, cols } = rowText(fakeLine([["a", 1], ["b", 1]]));
  assert.equal(text, "ab");
  assert.deepEqual(cols, [0, 1], "ascii maps 1:1");
}
{
  // Wide emoji before a URL shifts columns by one relative to string indices.
  const { text, cols } = rowText(fakeLine([["🦀", 2], [" ", 1], ["h", 1], ["t", 1]]));
  assert.equal(text, "🦀 ht");
  // "🦀" is two UTF-16 units, both mapped to column 0; " " sits at column 2.
  assert.deepEqual(cols, [0, 0, 2, 3, 4], "wide cell occupies two columns");
}
{
  // A combining cluster shares one cell: both units map to the same column.
  const { text, cols } = rowText(fakeLine([["é", 1], ["x", 1]]));
  assert.equal(text, "éx");
  assert.deepEqual(cols, [0, 0, 1], "cluster maps to its base cell");
}
{
  // Empty cells (right of the last glyph) read as spaces.
  const { text } = rowText(fakeLine([["a", 1], ["", 1]]));
  assert.equal(text, "a ");
}

// --- dockerwm helpers ---

assert.equal(
  dockerwmOpenUrl("https://docker.example/", "https://a.b/c?d=e&f=g"),
  "https://docker.example/newswall/open?url=https%3A%2F%2Fa.b%2Fc%3Fd%3De%26f%3Dg",
  "URL is fully encoded and base slash-trimmed",
);

const store = (value: string | null) => ({ getItem: () => value, setItem: () => {} });
assert.equal(loadDockerwmBase(store(null)), DOCKERWM_DEFAULT, "nothing stored → default");
assert.equal(loadDockerwmBase(store("https://other.example")), "https://other.example");
assert.equal(loadDockerwmBase(store("")), "", "empty string disables the button");

console.log("links.test: ok");
