// URL detection + hover popover for terminal output (threat model T9).
//
// Terminal output is attacker-controlled, so nothing here auto-opens: links
// are only *decorated*, and navigation happens when the user clicks a button
// in the popover, which always shows the full destination. Only http/https
// is recognized. This is deliberately not the web-links addon (OSC 8 stays
// inert — an escape sequence must not be able to relabel a destination).
//
// The popover exists because weechat's mouse mode swallows clicks: xterm.js
// forwards mouse reporting to the application, so click-to-open cannot work
// there. Hover detection still runs client-side, so the popover offers the
// two open actions ("open directly" / "open in dockerwm") as ordinary DOM
// buttons outside the terminal's mouse capture.

/// A link found in a row's text: [start, end) string indices plus the URL.
export type FoundLink = { start: number; end: number; url: string };

const URL_PATTERN = /https?:\/\/[^\s<>"'`\x00-\x1f\x7f]+/g;
/// Punctuation that is far more likely to trail a URL in prose than to end
/// one: `look at https://x.example/a, then …`.
const TRAILING = new Set([".", ",", ";", ":", "!", "?", "'", '"', "…"]);
const CLOSERS: Record<string, string> = { ")": "(", "]": "[", "}": "{" };
/// Sanity bounds: a row of hostile output must not produce unbounded work.
const MAX_LINKS_PER_ROW = 32;
const MIN_URL_LEN = "http://x.y".length;

/// Find http/https URLs in one row of terminal text. Trailing prose
/// punctuation is stripped; a closing bracket is kept only when its opener
/// is part of the match (Wikipedia-style `/wiki/Foo_(bar)` survives).
export function findLinks(text: string): FoundLink[] {
  const out: FoundLink[] = [];
  URL_PATTERN.lastIndex = 0;
  let match: RegExpExecArray | null;
  while (out.length < MAX_LINKS_PER_ROW && (match = URL_PATTERN.exec(text)) !== null) {
    let url = match[0];
    for (;;) {
      const last = url[url.length - 1]!;
      if (TRAILING.has(last)) {
        url = url.slice(0, -1);
        continue;
      }
      const opener = CLOSERS[last];
      if (opener !== undefined) {
        const opens = url.split(opener).length - 1;
        const closes = url.split(last).length - 1;
        if (closes > opens) {
          url = url.slice(0, -1);
          continue;
        }
      }
      break;
    }
    if (url.length >= MIN_URL_LEN) {
      out.push({ start: match.index, end: match.index + url.length, url });
    }
  }
  return out;
}

/// The subset of xterm's IBufferLine/IBufferCell this module reads — kept
/// minimal so tests can supply a fake without a DOM or a real Terminal.
export type CellReader = {
  length: number;
  getCell(x: number): { getChars(): string; getWidth(): number } | undefined;
};

/// Flatten one buffer row into its text plus, per string index, the buffer
/// column (0-based) of the cell that character lives in. Wide cells (emoji,
/// CJK) occupy two columns and combining marks share their base cell, so
/// string indices and columns diverge — the map keeps link underlines and
/// ranges aligned with what is actually on screen.
export function rowText(line: CellReader): { text: string; cols: number[] } {
  let text = "";
  const cols: number[] = [];
  let x = 0;
  while (x < line.length) {
    const cell = line.getCell(x);
    if (cell === undefined) break;
    const width = cell.getWidth();
    if (width === 0) {
      // Trailing half of a wide cell reached directly (defensive; normally
      // skipped by the width advance below).
      x += 1;
      continue;
    }
    const chars = cell.getChars();
    if (chars.length === 0) {
      text += " ";
      cols.push(x);
    } else {
      // Map every UTF-16 unit (regex indices are UTF-16) to this cell.
      for (let i = 0; i < chars.length; i++) cols.push(x);
      text += chars;
    }
    x += width;
  }
  return { text, cols };
}

/// dockerwm's cookie-authenticated open page (provisions a disposable
/// containerized browser and redirects to its viewer).
export function dockerwmOpenUrl(base: string, url: string): string {
  return `${base.replace(/\/+$/, "")}/newswall/open?url=${encodeURIComponent(url)}`;
}

const DOCKERWM_KEY = "holdfast.dockerwm.url";
export const DOCKERWM_DEFAULT = "https://docker.asylum.st";

type StorageLike = Pick<Storage, "getItem" | "setItem">;

/// dockerwm base URL: override — or disable the button entirely (store an
/// empty string) — via localStorage key `holdfast.dockerwm.url`.
export function loadDockerwmBase(storage: StorageLike = localStorage): string {
  const stored = storage.getItem(DOCKERWM_KEY);
  return stored === null ? DOCKERWM_DEFAULT : stored.trim();
}

/// Hover popover offering the open actions for one hovered URL. One instance
/// serves every tab; the popover follows whichever link is hovered.
export class LinkPopover {
  private el: HTMLDivElement;
  private urlEl: HTMLSpanElement;
  private url = "";
  private hideTimer: number | undefined;

  constructor(dockerwmBase: string) {
    this.el = document.createElement("div");
    this.el.id = "link-popover";
    this.el.hidden = true;

    this.urlEl = document.createElement("span");
    this.urlEl.className = "link-popover-url";
    this.el.appendChild(this.urlEl);

    const open = document.createElement("button");
    open.textContent = "Open";
    open.title = "Open in a new tab";
    open.onclick = () => {
      window.open(this.url, "_blank", "noopener,noreferrer");
      this.hide();
    };
    this.el.appendChild(open);

    if (dockerwmBase !== "") {
      const sandboxed = document.createElement("button");
      sandboxed.textContent = "dockerwm";
      sandboxed.title = "Open in a disposable dockerwm browser";
      sandboxed.onclick = () => {
        window.open(dockerwmOpenUrl(dockerwmBase, this.url), "_blank", "noopener,noreferrer");
        this.hide();
      };
      this.el.appendChild(sandboxed);
    }

    // Crossing from the link into the popover must not dismiss it.
    this.el.addEventListener("pointerenter", () => this.cancelHide());
    this.el.addEventListener("pointerleave", () => this.scheduleHide());
    document.body.appendChild(this.el);
  }

  /// Show near the pointer. The URL is rendered via textContent — hostile
  /// output cannot inject markup here.
  show(event: MouseEvent, url: string): void {
    this.cancelHide();
    this.url = url;
    this.urlEl.textContent = url.length > 100 ? `${url.slice(0, 100)}…` : url;
    this.el.hidden = false;
    const rect = this.el.getBoundingClientRect();
    const x = Math.min(event.clientX + 8, window.innerWidth - rect.width - 8);
    const y = event.clientY + 14 + rect.height > window.innerHeight
      ? event.clientY - rect.height - 10
      : event.clientY + 14;
    this.el.style.left = `${Math.max(4, x)}px`;
    this.el.style.top = `${Math.max(4, y)}px`;
  }

  scheduleHide(): void {
    this.cancelHide();
    this.hideTimer = window.setTimeout(() => this.hide(), 250);
  }

  private cancelHide(): void {
    if (this.hideTimer !== undefined) window.clearTimeout(this.hideTimer);
    this.hideTimer = undefined;
  }

  private hide(): void {
    this.cancelHide();
    this.el.hidden = true;
  }
}
