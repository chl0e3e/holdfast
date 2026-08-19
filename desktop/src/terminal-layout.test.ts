import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const css = readFileSync(new URL("./styles.css", import.meta.url), "utf8");

function declarations(selector: string): string {
  const escaped = selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = css.match(new RegExp(`${escaped}\\s*\\{([^}]*)\\}`));
  assert.ok(match, `${selector} rule exists`);
  return match[1]!;
}

// @xterm/addon-fit measures the .panel border box and subtracts padding from
// .xterm itself. Parent padding therefore overstates the available row area.
assert.doesNotMatch(declarations(".panel"), /(?:^|;)\s*padding\s*:/, "panel has no padding");
assert.match(
  declarations(".panel .xterm"),
  /(?:^|;)\s*padding\s*:\s*7px\s+6px\s+5px\s*;/,
  "terminal owns the inset that FitAddon subtracts",
);

// xterm pauses rendering for non-intersecting elements. A display:none tab can
// therefore stay black in WebView2 until keyboard input triggers another
// refresh. Keep every panel geometrically mounted and hide it visually.
assert.doesNotMatch(declarations(".panel"), /(?:^|;)\s*display\s*:\s*none\s*;/, "inactive panels stay mounted");
assert.match(declarations(".panel"), /(?:^|;)\s*visibility\s*:\s*hidden\s*;/, "inactive panels are visually hidden");
assert.match(declarations(".panel.active"), /(?:^|;)\s*visibility\s*:\s*visible\s*;/, "the selected panel becomes visible");

console.log("terminal layout tests passed");
