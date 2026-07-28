// Browser harness for the emoji/picker input fix — not part of the app build.
// It mounts a real xterm.js and records what would be sent, with the fix on
// (default) or off (`?control`), so the two can be compared in a real browser.
//
// Reproduce (needs Chromium with a remote-debugging port):
//   npx esbuild src/spike/emoji-e2e-entry.ts --bundle --format=iife \
//       --outfile=/tmp/emoji/bundle.js
//   cp node_modules/@xterm/xterm/css/xterm.css /tmp/emoji/
//   # page.html: <link rel=stylesheet href=xterm.css><div id=term
//   #   style="width:800px;height:400px"></div><script src=bundle.js></script>
// then, over CDP: focus `textarea.xterm-helper-textarea`, dispatch a keyDown
// with NO matching keyUp (the picker steals focus mid-chord), and call
// `Input.insertText` — Chrome's emulation of "text that doesn't come from a
// key press, for example an emoji keyboard or an IME". `window.__sent` stays
// empty in `?control` and holds the emoji with the fix. Classic script, not a
// module: `file://` blocks ES-module loads.
import { Terminal } from "@xterm/xterm";
import { InsertedTextForwarder } from "../client/inserted-text.js";

declare global {
  interface Window { __sent: string[]; __ready: boolean }
}

const sent: string[] = [];
window.__sent = sent;

const panel = document.getElementById("term")!;
const term = new Terminal({ scrollback: 100, fontSize: 14, convertEol: false });
term.open(panel);

const withFix = !location.search.includes("control");
const inserted = new InsertedTextForwarder();
if (withFix) panel.addEventListener("input", () => inserted.beginInputEvent(), true);
term.onData((data) => {
  inserted.noteTerminalData();
  sent.push(data);
});
if (withFix) {
  const helper = panel.querySelector<HTMLTextAreaElement>("textarea.xterm-helper-textarea");
  helper?.addEventListener("input", (event) => {
    const insert = event as InputEvent;
    const text = inserted.pendingInsert(insert.inputType, insert.data);
    if (text === null) return;
    helper.value = "";
    sent.push(text);
  });
}
term.focus();
window.__ready = true;
