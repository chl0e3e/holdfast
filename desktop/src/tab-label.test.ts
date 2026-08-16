import assert from "node:assert/strict";
import { TabLabel } from "./tab-label.js";

class FakeElement {
  className = "";
  textContent: string | null = null;
  readonly children: FakeElement[] = [];
  readonly attributes = new Map<string, string>();

  append(...children: FakeElement[]): void {
    this.children.push(...children);
  }

  setAttribute(name: string, value: string): void {
    this.attributes.set(name, value);
  }

  getAttribute(name: string): string | null {
    return this.attributes.get(name) ?? null;
  }
}

const button = new FakeElement();
const label = new TabLabel(
  button as unknown as HTMLButtonElement,
  () => new FakeElement() as unknown as HTMLSpanElement,
);
const buttonChildren = [...button.children];
const textChildren = [...button.children[1]!.children];

// Animated OSC titles must only change text. Replacing any element between
// pointer-down and pointer-up can cancel a WebView2 click on the tab.
for (const title of ["Working", "Working.", "Working..", "Working..."]) {
  label.update(title, "shell 1 · odysseus");
  assert.equal(button.children[0], buttonChildren[0]);
  assert.equal(button.children[1], buttonChildren[1]);
  assert.equal(button.children[1]!.children[0], textChildren[0]);
  assert.equal(button.children[1]!.children[1], textChildren[1]);
}

assert.equal(label.primary.textContent, "Working...");
assert.equal(label.secondary.textContent, "shell 1 · odysseus");
assert.equal(label.status.getAttribute("aria-hidden"), "true");

console.log("tab-label tests passed");
