import assert from "node:assert/strict";

import { clampFontSize, loadFontSize, FONT_SIZE_DEFAULT } from "./font-size.js";

const store = (value: string | null) => ({
  getItem: () => value,
  setItem: () => {},
});

assert.equal(loadFontSize(store(null)), FONT_SIZE_DEFAULT, "nothing stored → default");
assert.equal(loadFontSize(store("18")), 18, "stored size is used");
assert.equal(loadFontSize(store("garbage")), FONT_SIZE_DEFAULT, "junk → default");
assert.equal(loadFontSize(store("2")), 8, "below minimum clamps up");
assert.equal(loadFontSize(store("400")), 40, "above maximum clamps down");
assert.equal(clampFontSize(13.6), 14, "fractional sizes round");

console.log("font-size.test: ok");
