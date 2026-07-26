// One shell tab: xterm.js terminal + state machine + render composition.
// Ported from web/src/client/app.ts (the reference implementation); the
// transport underneath is the Rust core instead of a browser WebTransport.

import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { sanitizeTitle } from "./terminal-safety.js";

export type TabState =
  | "connecting"
  | "live"
  | "detached"
  | "reconnecting"
  | "orphaned"
  | "exited";

const LIVE_BUFFER_CAP = 2 * 1024 * 1024; // re-render buffer bound (spec §8 spirit)

/** What a Tab needs from the app (avoids a circular import). */
export interface TabDelegate {
  select(tab: Tab): void;
  sendInput(tab: Tab, data: string): void;
  sendResize(tab: Tab, cols: number, rows: number): void;
  fetchOlderHistory(tab: Tab): Promise<void>;
  handlePaste(tab: Tab, event: ClipboardEvent): void;
}

export class Tab {
  readonly server: string; // server key (hex)
  readonly shell: string; // shell id (hex)
  name: string;
  state: TabState = "connecting";
  term: Terminal;
  fit: FitAddon;
  panel: HTMLElement;
  button: HTMLButtonElement;
  /** Sanitized, shell-set window title (T9); shown only in the label. */
  title = "";

  snapshot: Uint8Array = new Uint8Array();
  awaitingSnapshot = true;
  historyLines: string[] = [];
  oldestFetched = 0; // history line ID; 0 = nothing fetched
  oldestAvailable = 1;
  historyExhausted = false;
  fetchingHistory = false;
  liveChunks: Uint8Array[] = [];
  liveBytes = 0;
  liveOverflowed = false;
  /** Guards against overlapping attach attempts. */
  attaching = false;

  constructor(
    server: string,
    shell: string,
    name: string,
    tabSlot: HTMLElement,
    app: TabDelegate,
  ) {
    this.server = server;
    this.shell = shell;
    this.name = name;

    this.panel = document.createElement("div");
    this.panel.className = "panel";
    document.getElementById("panels")!.appendChild(this.panel);

    this.button = document.createElement("button");
    tabSlot.appendChild(this.button);
    this.button.onclick = () => app.select(this);

    // Safe defaults (threat model T9): no clipboard/web-links/image addons,
    // so OSC 52 writes and OSC 8 auto-hyperlinks are inert. The window title
    // is sanitized and only ever shown as the tab's own textContent.
    this.term = new Terminal({ scrollback: 10_000, fontSize: 14, convertEol: false });
    this.fit = new FitAddon();
    this.term.loadAddon(this.fit);
    this.term.open(this.panel);
    this.term.onData((data) => app.sendInput(this, data));
    this.term.onResize(({ cols, rows }) => app.sendResize(this, cols, rows));
    this.term.onScroll(() => {
      if (this.term.buffer.active.viewportY === 0) void app.fetchOlderHistory(this);
    });
    this.term.onTitleChange((title) => {
      this.title = sanitizeTitle(title);
      this.refreshLabel();
    });
    // xterm.js rewrites Alt+Up/Down into Ctrl+Up/Down on non-Mac platforms;
    // send the real CSI 1;3A/B ourselves (same fix as the web client).
    this.term.attachCustomKeyEventHandler((event) => {
      if (
        event.type === "keydown" &&
        event.altKey && !event.ctrlKey && !event.metaKey && !event.shiftKey &&
        (event.key === "ArrowUp" || event.key === "ArrowDown")
      ) {
        app.sendInput(this, event.key === "ArrowUp" ? "\x1b[1;3A" : "\x1b[1;3B");
        event.preventDefault();
        return false;
      }
      return true;
    });
    // Paste guard (T9): newline/control-char pastes need confirmation.
    this.panel.addEventListener("paste", (event) => app.handlePaste(this, event));
    this.setState("connecting");
  }

  setState(state: TabState): void {
    this.state = state;
    this.button.dataset.state = state;
    this.refreshLabel();
  }

  /** Rebuild the label from name + title + state; textContent only (T9). */
  refreshLabel(): void {
    const base = this.title ? `${this.name}: ${this.title}` : this.name;
    this.button.textContent = `${base} · ${this.state}`;
  }

  /** First channel message is the snapshot; everything after is live. */
  onChannelMessage(bytes: Uint8Array): void {
    if (this.awaitingSnapshot) {
      this.awaitingSnapshot = false;
      this.snapshot = bytes;
      return;
    }
    this.appendLive(bytes);
  }

  appendLive(data: Uint8Array): void {
    this.term.write(data);
    this.liveChunks.push(data);
    this.liveBytes += data.length;
    while (this.liveBytes > LIVE_BUFFER_CAP && this.liveChunks.length > 1) {
      this.liveBytes -= this.liveChunks.shift()!.length;
      this.liveOverflowed = true;
    }
  }

  resetForAttach(): void {
    this.awaitingSnapshot = true;
    this.snapshot = new Uint8Array();
    this.historyLines = [];
    this.oldestFetched = 0;
    this.oldestAvailable = 1;
    this.historyExhausted = false;
    this.liveChunks = [];
    this.liveBytes = 0;
    this.liveOverflowed = false;
  }

  /** Full re-render: history, spacer, server snapshot, then live output. */
  render(): void {
    this.term.reset();
    if (this.historyLines.length > 0) {
      const note = this.historyExhausted || this.oldestFetched <= this.oldestAvailable
        ? "── start of retained history ──"
        : "── scroll up for older history ──";
      this.term.write(`\x1b[2m${note}\x1b[0m\r\n`);
      this.term.write(this.historyLines.join("\r\n") + "\r\n");
    }
    this.term.write("\r\n".repeat(this.term.rows));
    this.term.write(this.snapshot);
    if (this.liveOverflowed) {
      this.term.write("\r\n\x1b[2m── some earlier live output not re-rendered ──\x1b[0m\r\n");
    }
    for (const chunk of this.liveChunks) this.term.write(chunk);
    this.term.scrollToBottom();
  }

  dispose(): void {
    this.term.dispose();
    this.panel.remove();
    this.button.remove();
  }
}
