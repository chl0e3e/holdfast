// One shell tab: xterm.js terminal + state machine + render composition.
// Ported from web/src/client/app.ts (the reference implementation); the
// transport underneath is the Rust core instead of a browser WebTransport.

import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { ServerWidthAddon, SERVER_WIDTH_VERSION } from "./server-width.js";
import { sanitizeTitle } from "./terminal-safety.js";
import { InsertedTextForwarder } from "./inserted-text.js";
import { findLinks, rowText, type LinkPopover } from "./links.js";
import { TabLabel } from "./tab-label.js";
import type { TabState } from "./ui-state.js";
import {
  composeBoundedReplay,
  prependBoundedHistory,
  TERMINAL_WRITE_QUEUE_CAP,
  TERMINAL_WRITE_QUEUE_CHUNK_CAP,
  viewportFromBottom,
} from "./terminal-render-state.js";

export type { TabState } from "./ui-state.js";

const LIVE_BUFFER_CAP = 2 * 1024 * 1024; // re-render buffer bound (spec §8 spirit)
const LIVE_CHUNK_CAP = 4_096;
const encoder = new TextEncoder();

type LiveChunk = { sequence: number; data: Uint8Array };

/** What a Tab needs from the app (avoids a circular import). */
export interface TabDelegate {
  /** Shared, persisted terminal font size (see font-size.ts). */
  fontSize: number;
  /** Shared hover popover for URLs in output (see links.ts). */
  linkPopover: LinkPopover;
  adjustFontSize(delta: number): void;
  select(tab: Tab): void;
  sendInput(tab: Tab, data: string): void;
  sendResize(tab: Tab, cols: number, rows: number): void;
  fetchOlderHistory(tab: Tab): Promise<void>;
  handlePaste(tab: Tab, event: ClipboardEvent): void;
  renameTab(tab: Tab): void;
  closeTab(tab: Tab): void;
  recoverTerminal(tab: Tab): void;
  serverDisplayName(server: string): string;
  tabStateChanged(tab: Tab): void;
}

export class Tab {
  readonly server: string; // server key (hex)
  readonly shell: string; // shell id (hex)
  name: string;
  state: TabState = "connecting";
  term: Terminal;
  fit: FitAddon;
  panel: HTMLElement;
  tabElement: HTMLElement;
  button: HTMLButtonElement;
  closeButton: HTMLButtonElement;
  private readonly label: TabLabel;
  /** Sanitized, shell-set window title (T9); shown only in the label. */
  title = "";
  /// Recovers picker-inserted text (emoji) that xterm.js declines.
  inserted = new InsertedTextForwarder();
  private readonly delegate: TabDelegate;

  snapshot: Uint8Array = new Uint8Array();
  awaitingSnapshot = true;
  historyLines: string[] = [];
  historyBytes = 0;
  historyClientTruncated = false;
  oldestFetched = 0; // history line ID; 0 = nothing fetched
  oldestAvailable = 1;
  historyExhausted = false;
  fetchingHistory = false;
  attachmentGeneration = 0;
  liveChunks: LiveChunk[] = [];
  liveBytes = 0;
  liveOverflowed = false;
  private liveSequence = 0;
  private writeQueue: Uint8Array[] = [];
  private writeQueueBytes = 0;
  private writeInFlight = false;
  private replayInFlight = false;
  private renderPending = false;
  private pendingOffsetFromBottom: number | null = null;
  private recoveryRequested = false;
  private userScrollIntentUntil = 0;
  private ignoreScrollUntil = 0;
  /** False between attach and the first render(): live bytes are buffered
   *  but not written, so they can never composite over a stale frame. */
  presented = false;
  /** Guards against overlapping attach attempts. */
  attaching = false;
  /** Distinguishes an intentional detach event from a transport-side drop. */
  detaching = false;
  /** Prevents reconnect/event handlers from reviving a tab being closed. */
  closing = false;

  constructor(
    server: string,
    shell: string,
    name: string,
    tabSlot: HTMLElement,
    app: TabDelegate,
  ) {
    this.delegate = app;
    this.server = server;
    this.shell = shell;
    this.name = name;

    this.panel = document.createElement("div");
    this.panel.className = "panel";
    // Selection is the only visibility path. Without this, every tab created
    // after the active one overlays it despite a different tab being marked
    // active (the last-created shell appeared to corrupt the first).
    this.panel.style.display = "none";
    document.getElementById("panels")!.appendChild(this.panel);

    this.tabElement = document.createElement("div");
    this.tabElement.className = "shell-tab";
    this.tabElement.setAttribute("role", "presentation");
    this.button = document.createElement("button");
    this.button.className = "shell-tab-select";
    this.button.setAttribute("role", "tab");
    this.button.type = "button";
    this.label = new TabLabel(this.button);
    this.closeButton = document.createElement("button");
    this.closeButton.className = "shell-tab-close";
    this.closeButton.type = "button";
    this.closeButton.textContent = "×";
    this.closeButton.onclick = (event) => {
      event.stopPropagation();
      app.closeTab(this);
    };
    this.tabElement.append(this.button, this.closeButton);
    tabSlot.appendChild(this.tabElement);
    this.button.onclick = () => app.select(this);
    this.button.ondblclick = () => app.renameTab(this);

    // Safe defaults (threat model T9): no clipboard/web-links/image addons,
    // so OSC 52 writes and OSC 8 auto-hyperlinks are inert. The window title
    // is sanitized and only ever shown as the tab's own textContent.
    this.term = new Terminal({
      scrollback: 10_000,
      fontSize: app.fontSize,
      convertEol: false,
      allowProposedApi: true, // Terminal.unicode is a "proposed" API
    });
    this.fit = new FitAddon();
    this.term.loadAddon(this.fit);
    // Cell widths GENERATED from the server model's unicode-width table —
    // see the web client (app.ts) and tools/xterm-width-tables; any width
    // disagreement garbles every snapshot replay.
    this.term.loadAddon(new ServerWidthAddon());
    this.term.unicode.activeVersion = SERVER_WIDTH_VERSION;
    this.term.open(this.panel);
    const fetchHistoryAtTop = () => {
      const now = performance.now();
      if (
        now >= this.ignoreScrollUntil &&
        now <= this.userScrollIntentUntil &&
        this.term.buffer.active.viewportY === 0
      ) {
        this.userScrollIntentUntil = 0;
        void app.fetchOlderHistory(this);
      }
    };
    // Ctrl+scroll resizes the terminal font (the gesture most terminals use).
    this.panel.addEventListener("wheel", (event) => {
      if (event.ctrlKey) {
        event.preventDefault();
        app.adjustFontSize(event.deltaY < 0 ? 1 : -1);
      } else if (event.deltaY < 0) {
        this.userScrollIntentUntil = performance.now() + 750;
        // xterm's wheel listener can report onScroll before its public buffer
        // view has caught up. Recheck after the browser dispatch completes.
        requestAnimationFrame(fetchHistoryAtTop);
      }
    }, { passive: false, capture: true });
    this.panel.addEventListener("pointerdown", (event) => {
      if ((event.target as Element | null)?.closest(".xterm-viewport")) {
        this.userScrollIntentUntil = performance.now() + 750;
      }
    });
    // Reset before xterm.js's own key handlers (capture on an ancestor always
    // runs first). On keydown/keyup, NOT the input event: xterm.js handles
    // space in `keypress`, whose leftover input event fires after onData — a
    // per-input-event reset there doubled every space.
    const beginKey = () => this.inserted.beginKeyEvent();
    this.panel.addEventListener("keydown", beginKey, true);
    this.panel.addEventListener("keyup", beginKey, true);
    this.term.onData((data) => {
      this.inserted.noteTerminalData();
      app.sendInput(this, data);
    });
    // Emoji/character pickers insert text that xterm.js drops when the keyup
    // of the opening chord never arrived (Win+. gives focus to the picker).
    // Send what it declined, and clear the leftover from its hidden textarea.
    const helper = this.panel.querySelector<HTMLTextAreaElement>("textarea.xterm-helper-textarea");
    helper?.addEventListener("input", (event) => {
      const insert = event as InputEvent;
      const text = this.inserted.pendingInsert(insert.inputType, insert.data);
      if (text === null) return;
      helper.value = "";
      app.sendInput(this, text);
    });
    this.term.onResize(({ cols, rows }) => app.sendResize(this, cols, rows));
    this.term.onScroll(fetchHistoryAtTop);
    this.term.onTitleChange((title) => {
      this.title = sanitizeTitle(title);
      this.refreshLabel();
    });
    // xterm.js rewrites Alt+Up/Down into Ctrl+Up/Down on non-Mac platforms;
    // send the real CSI 1;3A/B ourselves (same fix as the web client).
    this.term.attachCustomKeyEventHandler((event) => {
      if (
        event.type === "keydown" &&
        (event.key === "PageUp" || event.key === "Home" || event.key === "ArrowUp")
      ) {
        this.userScrollIntentUntil = performance.now() + 750;
      }
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
    // URLs in output get a hover popover with explicit open actions (T9: no
    // auto-open, full destination shown). Hover detection works even when the
    // application owns the mouse (weechat mouse mode), where click-to-open
    // can't: clicks are forwarded to the app, popover buttons are plain DOM.
    this.term.registerLinkProvider({
      provideLinks: (bufferLineNumber, callback) => {
        const line = this.term.buffer.active.getLine(bufferLineNumber - 1);
        if (!line) return callback(undefined);
        const row = rowText({
          length: line.length,
          getCell: (x) => line.getCell(x),
        });
        const links = findLinks(row.text).map((found) => ({
          range: {
            start: { x: row.cols[found.start]! + 1, y: bufferLineNumber },
            end: { x: row.cols[found.end - 1]! + 1, y: bufferLineNumber },
          },
          text: found.url,
          activate: (event: MouseEvent, url: string) => app.linkPopover.show(event, url),
          hover: (event: MouseEvent, url: string) => app.linkPopover.show(event, url),
          leave: () => app.linkPopover.scheduleHide(),
        }));
        callback(links.length > 0 ? links : undefined);
      },
    });
    this.setState("connecting");
  }

  setState(state: TabState): void {
    this.state = state;
    this.tabElement.dataset.state = state;
    this.refreshLabel();
    this.delegate.tabStateChanged(this);
  }

  /** Browser-style title plus full shell metadata; textContent only (T9). */
  refreshLabel(): void {
    const primary = this.title || this.name;
    const server = this.delegate.serverDisplayName(this.server);
    const secondary = this.title ? `${this.name} · ${server}` : server;
    this.label.update(primary, secondary);

    const details = [
      primary,
      `Shell: ${this.name}`,
      `Server: ${server}`,
      `State: ${this.state}`,
      `Shell ID: ${this.shell}`,
    ].join("\n");
    this.tabElement.title = details;
    this.button.setAttribute("aria-label", `${primary}, ${this.name} on ${server}, ${this.state}`);
    this.closeButton.title = this.state === "exited"
      ? `Close ${this.name}`
      : `Close tab (the ${this.name} shell keeps running)`;
    this.closeButton.setAttribute("aria-label", `Close ${this.name}`);
  }

  /** First channel message is the snapshot; everything after is live. */
  onChannelMessage(bytes: Uint8Array, generation = this.attachmentGeneration): void {
    if (this.closing || generation !== this.attachmentGeneration) return;
    if (this.awaitingSnapshot) {
      this.awaitingSnapshot = false;
      this.snapshot = bytes;
      return;
    }
    this.appendLive(bytes);
  }

  appendLive(data: Uint8Array): void {
    if (this.closing) return;
    if (data.length > LIVE_BUFFER_CAP) {
      this.liveOverflowed = true;
      if (this.presented) this.requestRecovery();
      return;
    }
    const chunk = { sequence: ++this.liveSequence, data };
    this.liveChunks.push(chunk);
    this.liveBytes += data.length;
    while (
      (this.liveBytes > LIVE_BUFFER_CAP || this.liveChunks.length > LIVE_CHUNK_CAP) &&
      this.liveChunks.length > 1
    ) {
      this.liveBytes -= this.liveChunks.shift()!.data.length;
      this.liveOverflowed = true;
    }
    if (this.presented && !this.replayInFlight && !this.renderPending) {
      this.enqueueWrite(data);
    }
  }

  appendNotice(text: string): void {
    this.appendLive(encoder.encode(text));
  }

  prependHistory(lines: readonly string[]): boolean {
    const bounded = prependBoundedHistory(this.historyLines, this.historyBytes, lines);
    this.historyLines = bounded.lines;
    this.historyBytes = bounded.bytes;
    if (!bounded.acceptedAll) {
      this.historyClientTruncated = true;
      this.historyExhausted = true;
    }
    return bounded.acceptedAll;
  }

  resetForAttach(): number {
    this.attachmentGeneration += 1;
    this.presented = false;
    this.awaitingSnapshot = true;
    this.snapshot = new Uint8Array();
    this.historyLines = [];
    this.historyBytes = 0;
    this.historyClientTruncated = false;
    this.oldestFetched = 0;
    this.oldestAvailable = 1;
    this.historyExhausted = false;
    this.fetchingHistory = false;
    this.liveChunks = [];
    this.liveBytes = 0;
    this.liveOverflowed = false;
    this.liveSequence = 0;
    this.writeQueue = [];
    this.writeQueueBytes = 0;
    this.renderPending = false;
    this.pendingOffsetFromBottom = null;
    this.recoveryRequested = false;
    return this.attachmentGeneration;
  }

  /**
   * Atomically replay history + snapshot + live bytes. xterm parses write()
   * asynchronously, so no other write is issued until its callback fires.
   * When history was prepended, preserve the same distance from the bottom.
   */
  render(preserveScroll = false): void {
    if (this.closing) return;
    if (this.liveOverflowed) {
      this.requestRecovery();
      return;
    }
    if (preserveScroll && this.pendingOffsetFromBottom === null) {
      const buffer = this.term.buffer.active;
      this.pendingOffsetFromBottom = Math.max(0, buffer.baseY - buffer.viewportY);
    } else if (!preserveScroll) {
      this.pendingOffsetFromBottom = null;
    }
    this.presented = false;
    this.renderPending = true;
    // These bytes are all represented by liveChunks in the coming replay.
    this.writeQueue = [];
    this.writeQueueBytes = 0;
    this.startRenderIfIdle();
  }

  setActive(active: boolean): void {
    this.panel.style.display = active ? "block" : "none";
    this.tabElement.classList.toggle("active", active);
    this.button.setAttribute("aria-selected", String(active));
  }

  private buildReplay(): Uint8Array | null {
    const parts: Uint8Array[] = [];
    if (this.historyLines.length > 0) {
      const note = this.historyClientTruncated
        ? "── local history display limit reached ──"
        : this.historyExhausted || this.oldestFetched <= this.oldestAvailable
        ? "── start of retained history ──"
        : "── scroll up for older history ──";
      parts.push(encoder.encode(`\x1b[2m${note}\x1b[0m\r\n`));
      parts.push(encoder.encode(this.historyLines.join("\r\n") + "\r\n"));
    }
    parts.push(encoder.encode("\r\n".repeat(this.term.rows)));
    parts.push(this.snapshot);
    for (const chunk of this.liveChunks) parts.push(chunk.data);
    return composeBoundedReplay(parts);
  }

  private startRenderIfIdle(): void {
    if (!this.renderPending || this.writeInFlight || this.replayInFlight || this.closing) return;
    const replay = this.buildReplay();
    if (!replay) {
      this.renderPending = false;
      this.requestRecovery();
      return;
    }
    const coveredThrough = this.liveSequence;
    const generation = this.attachmentGeneration;
    const offsetFromBottom = this.pendingOffsetFromBottom;
    this.pendingOffsetFromBottom = null;
    this.renderPending = false;
    this.replayInFlight = true;
    this.term.reset();
    this.term.write(replay, () => {
      this.replayInFlight = false;
      if (this.closing) return;
      if (generation !== this.attachmentGeneration) {
        this.startRenderIfIdle();
        return;
      }
      if (this.renderPending) {
        this.startRenderIfIdle();
        return;
      }
      this.presented = true;
      this.ignoreScrollUntil = performance.now() + 150;
      if (offsetFromBottom === null) {
        this.term.scrollToBottom();
      } else {
        this.term.scrollToLine(viewportFromBottom(this.term.buffer.active.baseY, offsetFromBottom));
      }
      if (this.liveOverflowed) {
        this.requestRecovery();
        return;
      }
      for (const chunk of this.liveChunks) {
        if (chunk.sequence > coveredThrough) this.enqueueWrite(chunk.data);
      }
      this.pumpWrites();
    });
  }

  private enqueueWrite(data: Uint8Array): void {
    if (
      data.length > TERMINAL_WRITE_QUEUE_CAP - this.writeQueueBytes ||
      this.writeQueue.length >= TERMINAL_WRITE_QUEUE_CHUNK_CAP
    ) {
      this.writeQueue = [];
      this.writeQueueBytes = 0;
      this.presented = false;
      if (this.liveOverflowed) this.requestRecovery();
      else this.render(false);
      return;
    }
    this.writeQueue.push(data);
    this.writeQueueBytes += data.length;
    this.pumpWrites();
  }

  private pumpWrites(): void {
    if (this.writeInFlight || this.replayInFlight || this.renderPending || this.closing) return;
    const data = this.writeQueue.shift();
    if (!data) return;
    this.writeQueueBytes -= data.length;
    this.writeInFlight = true;
    this.term.write(data, () => {
      this.writeInFlight = false;
      if (this.renderPending) this.startRenderIfIdle();
      else this.pumpWrites();
    });
  }

  private requestRecovery(): void {
    if (this.recoveryRequested || this.closing) return;
    this.recoveryRequested = true;
    this.delegate.recoverTerminal(this);
  }

  dispose(): void {
    this.closing = true;
    this.term.dispose();
    this.panel.remove();
    this.tabElement.remove();
  }
}
