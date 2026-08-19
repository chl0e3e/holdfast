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

console.log("terminal layout tests passed");
