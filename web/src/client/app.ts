// Holdfast browser client: xterm.js shells as tabs over WebTransport (QUIC
// only — ADR 0014).
//
// Reload recovery: shell IDs + the latest rotated resume tokens persist in
// localStorage; on (re)connect every stored shell is reattached and its
// screen restored from the server snapshot. Detach and terminate are
// distinct: closing a tab detaches (shell keeps running, reload brings it
// back); Terminate kills after confirmation.

import { create } from "@bufbuild/protobuf";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import { ServerWidthAddon, SERVER_WIDTH_VERSION } from "./server-width.js";
import { findLinks, LinkPopover, loadDockerwmBase, rowText } from "./links.js";
import {
  AttachShellSchema,
  AuthenticateSchema,
  Capability,
  ClientHelloSchema,
  ClientKind,
  DetachShellSchema,
  Encoding,
  ErrorCode,
  OpenShellSchema,
  PongSchema,
  RequestHistorySchema,
  PasswordRequestSchema,
  SshChallengeRequestSchema,
  SshChallengeResponseSchema,
  TerminalInputSchema,
  TerminalResizeSchema,
  TerminateShellSchema,
  type Envelope,
} from "../gen/messages_pb.js";
import {
  connectTransport,
  envelope,
  QuicUnavailableError,
  type HfTransport,
} from "./transport.js";
import { pasteNeedsConfirmation, sanitizeTitle } from "./terminal-safety.js";
import { InsertedTextForwarder } from "./inserted-text.js";
import { clampFontSize, loadFontSize, saveFontSize } from "./font-size.js";
import { snapshotReplayPreamble } from "./terminal-replay.js";

const PROTOCOL_MAJOR = 0;
const PROTOCOL_MINOR = 2;
const STORAGE_KEY = "holdfast.shells.v1";
const GRANT_KEY = "holdfast.grant.v1";
const HISTORY_PAGE_LINES = 200;
const HISTORY_PAGE_BYTES = 128 * 1024;
const LIVE_BUFFER_CAP = 2 * 1024 * 1024; // re-render buffer bound (spec §8 spirit)

/// `idem` is the idempotency key the shell was opened with. It is the ONLY
/// way back to a still-running shell whose resume token has expired: the
/// daemon returns the existing shell for a repeated key from the same user
/// (session-core `open_shell`). Optional because entries written before
/// 2026-08-11 do not have it — those cannot be recovered, and are kept rather
/// than deleted so the shell is not silently lost from this browser.
type StoredShell = { id: string; token: string; name: string; idem?: string };

function loadStored(): StoredShell[] {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "[]") as StoredShell[];
  } catch {
    return [];
  }
}
function saveStored(shells: StoredShell[]): void {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(shells));
}
const b64 = {
  enc: (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)),
  dec: (text: string) => Uint8Array.from(atob(text), (c) => c.charCodeAt(0)),
};

type TabState = "connecting" | "live" | "detached" | "reconnecting" | "exited";

class Tab {
  shellId: Uint8Array;
  name: string;
  channel = 0;
  state: TabState = "connecting";
  term: Terminal;
  fit: FitAddon;
  panel: HTMLElement;
  button: HTMLButtonElement;
  /// Sanitized, shell-set window title (T9); shown only as part of the label.
  title = "";
  /// Recovers picker-inserted text (emoji) that xterm.js declines.
  inserted = new InsertedTextForwarder();

  snapshot: Uint8Array = new Uint8Array();
  historyLines: string[] = [];
  oldestFetched = 0n; // history line ID; 0 = nothing fetched
  oldestAvailable = 1n;
  historyExhausted = false;
  fetchingHistory = false;
  liveChunks: Uint8Array[] = [];
  liveBytes = 0;
  liveOverflowed = false;
  /// False between attach and the first render(): live bytes are buffered
  /// but not written, so they can never composite over a stale frame.
  presented = false;

  constructor(shellId: Uint8Array, name: string, app: App) {
    this.shellId = shellId;
    this.name = name;

    this.panel = document.createElement("div");
    this.panel.className = "panel";
    document.getElementById("panels")!.appendChild(this.panel);

    this.button = document.createElement("button");
    document.getElementById("tabs")!.insertBefore(
      this.button,
      document.getElementById("new-shell"),
    );
    this.button.onclick = () => app.select(this);

    // Safe defaults (threat model T9): we do NOT load the clipboard, web-links
    // or image addons, so OSC 52 clipboard writes and OSC 8 auto-hyperlinks
    // are inert. The window title (OSC 0/2) is sanitized before it reaches the
    // tab label; it is never written to document.title.
    this.term = new Terminal({
      scrollback: 10_000,
      fontSize: app.fontSize,
      convertEol: false,
      allowProposedApi: true, // Terminal.unicode is a "proposed" API
    });
    this.fit = new FitAddon();
    this.term.loadAddon(this.fit);
    // Cell widths must match the server model exactly — the provider is
    // GENERATED from the same unicode-width table avt uses (the Unicode-11
    // addon previously used here disagreed on post-U11 emoji, shearing
    // snapshot replays). See tools/xterm-width-tables.
    this.term.loadAddon(new ServerWidthAddon());
    this.term.unicode.activeVersion = SERVER_WIDTH_VERSION;
    this.term.open(this.panel);
    // Ctrl+scroll resizes the terminal font (the gesture most terminals use).
    this.panel.addEventListener("wheel", (event) => {
      if (!event.ctrlKey) return;
      event.preventDefault();
      app.adjustFontSize(event.deltaY < 0 ? 1 : -1);
    }, { passive: false });
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
    this.term.onScroll(() => {
      if (this.term.buffer.active.viewportY === 0) void app.fetchOlderHistory(this);
    });
    // A shell-set title is untrusted output — sanitize, then show only as the
    // tab's own label (not the browser title/DOM markup).
    this.term.onTitleChange((title) => {
      const clean = sanitizeTitle(title);
      this.title = clean;
      this.refreshLabel();
    });
    // xterm.js rewrites Alt+Up/Down into Ctrl+Up/Down on non-Mac platforms
    // (an old word-navigation hack in its Keyboard.ts), so apps like weechat
    // never see the Alt+arrow sequences they bind. Send the real CSI 1;3A/B
    // ourselves and bypass xterm's handling for those keys.
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
    // Paste guard: a paste carrying newlines/control chars can inject commands.
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
    this.button.dataset.state = state;
    this.refreshLabel();
  }

  /// Rebuild the tab label from name + (sanitized) title + state. Uses
  /// textContent so nothing here can inject markup.
  refreshLabel(): void {
    const base = this.title ? `${this.name}: ${this.title}` : this.name;
    this.button.textContent = `${base} · ${this.state}`;
  }

  appendLive(data: Uint8Array): void {
    if (this.presented) this.term.write(data);
    this.liveChunks.push(data);
    this.liveBytes += data.length;
    while (this.liveBytes > LIVE_BUFFER_CAP && this.liveChunks.length > 1) {
      this.liveBytes -= this.liveChunks.shift()!.length;
      this.liveOverflowed = true;
    }
  }

  /// Full re-render: fetched history, spacer to push it into scrollback,
  /// server snapshot, then everything received live since attach.
  render(): void {
    this.presented = true;
    this.term.reset();
    if (this.historyLines.length > 0) {
      const note = this.historyExhausted || this.oldestFetched <= this.oldestAvailable
        ? "── start of retained history ──"
        : "── scroll up for older history ──";
      this.term.write(`\x1b[2m${note}\x1b[0m\r\n`);
      this.term.write(this.historyLines.join("\r\n") + "\r\n");
    }
    this.term.write(snapshotReplayPreamble(this.term.rows));
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

class App {
  transport: HfTransport | null = null;
  tabs: Tab[] = [];
  active: Tab | null = null;
  resizeFrame: number | null = null;
  pending = new Map<bigint, (channel: number, env: Envelope) => void>();
  channelToTab = new Map<number, Tab>();
  backoffMs = 1000;
  status = document.getElementById("status")!;
  fontSize = loadFontSize();
  linkPopover = new LinkPopover(loadDockerwmBase());

  async start(): Promise<void> {
    document.getElementById("new-shell")!.onclick = () => void this.newShell();
    document.getElementById("detach")!.onclick = () => this.detachActive();
    document.getElementById("terminate")!.onclick = () => void this.terminateActive();
    document.getElementById("font-smaller")!.onclick = () => this.adjustFontSize(-1);
    document.getElementById("font-larger")!.onclick = () => this.adjustFontSize(1);
    window.addEventListener("resize", () => this.scheduleFit());
    await this.connect();
  }

  /// One font size for all tabs, persisted. Emoji render at cell size, so
  /// this is also the only "make emoji readable" knob.
  adjustFontSize(delta: number): void {
    const size = clampFontSize(this.fontSize + delta);
    if (size === this.fontSize) return;
    this.fontSize = size;
    saveFontSize(size);
    for (const tab of this.tabs) tab.term.options.fontSize = size;
    this.active?.fit.fit();
  }

  /// Coalesce resize work to one fit per frame, as the desktop client does.
  /// `window.onresize` fires continuously through a drag and `fit()` triggers
  /// `term.onResize`, which sends a `TerminalResize` — so an untamed drag sent
  /// one resize per event to the daemon and re-laid-out the terminal just as
  /// often. Skipping a zero-sized panel matters too: fitting a panel that is
  /// not laid out yet proposes garbage dimensions.
  scheduleFit(): void {
    if (this.resizeFrame !== null) return;
    this.resizeFrame = requestAnimationFrame(() => {
      this.resizeFrame = null;
      const tab = this.active;
      if (!tab || tab.panel.clientWidth === 0 || tab.panel.clientHeight === 0) return;
      tab.fit.fit();
    });
  }

  setStatus(text: string, kind: "ok" | "warn" | "err"): void {
    this.status.textContent = text;
    this.status.dataset.kind = kind;
  }

  async connect(): Promise<void> {
    this.setStatus("connecting over QUIC…", "warn");
    try {
      this.transport = await connectTransport(
        (channel, env) => this.onFrame(channel, env),
        () => this.onDisconnect(),
      );
    } catch (error) {
      if (error instanceof QuicUnavailableError) {
        // No fallback (ADR 0014): say QUIC is required and keep retrying.
        this.setStatus(
          `QUIC required — WebTransport unreachable, retrying in ${this.backoffMs / 1000}s`,
          "err",
        );
        setTimeout(() => void this.connect(), this.backoffMs);
        this.backoffMs = Math.min(this.backoffMs * 2, 15_000);
        return;
      }
      this.onDisconnect();
      return;
    }

    await this.hello();
    await this.authenticate();
    this.backoffMs = 1000;
    this.setStatus("connected · WebTransport (QUIC)", "ok");

    // Reattach persisted shells; open a first shell on a fresh start.
    const stored = loadStored();
    if (stored.length === 0 && this.tabs.length === 0) {
      await this.newShell();
      return;
    }
    for (const entry of stored) {
      await this.attachShell(b64.dec(entry.id), b64.dec(entry.token), entry.name);
    }
  }

  onDisconnect(): void {
    this.transport = null;
    this.pending.clear();
    this.channelToTab.clear();
    for (const tab of this.tabs) {
      if (tab.state !== "exited") tab.setState("reconnecting");
    }
    this.setStatus(`disconnected — retrying in ${this.backoffMs / 1000}s`, "err");
    setTimeout(() => void this.connect(), this.backoffMs);
    this.backoffMs = Math.min(this.backoffMs * 2, 15_000);
  }

  request(channel: number, env: Envelope): Promise<[number, Envelope]> {
    const transport = this.transport;
    if (!transport) return Promise.reject(new Error("not connected"));
    const requestId = transport.nextRequestId();
    env.requestId = requestId;
    return new Promise((resolve) => {
      this.pending.set(requestId, (ch, response) => {
        this.pending.delete(requestId);
        resolve([ch, response]);
      });
      transport.send(channel, env);
    });
  }

  async hello(): Promise<void> {
    const [, reply] = await this.request(0, envelope({
      message: {
        case: "clientHello",
        value: create(ClientHelloSchema, {
          protocolMajor: PROTOCOL_MAJOR,
          protocolMinor: PROTOCOL_MINOR,
          clientKind: ClientKind.BROWSER_WEBTRANSPORT,
          clientBuild: "holdfast-web phase-2",
          capabilities: [Capability.DATAGRAMS],
          maxFrameBytes: 256 * 1024,
          maxDatagramBytes: 0,
          encodings: [Encoding.UTF8],
        }),
      },
    }));
    if (reply.message.case !== "serverHello") throw new Error("hello failed");
  }

  /// Auth ladder (spec §5): stored connection grant → dev empty grant →
  /// interactive SSH challenge/response. The private key never leaves the
  /// user's machine: the browser shows the exact `ssh-keygen -Y sign`
  /// command and the user pastes back the SSHSIG.
  async authenticate(): Promise<void> {
    const stored = localStorage.getItem(GRANT_KEY);
    if (stored) {
      if (await this.tryGrant(b64.dec(stored))) return;
      localStorage.removeItem(GRANT_KEY); // expired or daemon key rotated
    }
    // Dev daemons (hash-pin certificates) accept an empty grant. Don't burn a
    // guaranteed-failing attempt against production daemons — failed auths
    // feed the rate limiter (threat model T1).
    const info = (await fetch("/webtransport-info").then((r) => r.json())) as {
      certificateMode: "hash-pin" | "webpki";
    };
    if (info.certificateMode !== "webpki" && (await this.tryGrant(new Uint8Array()))) {
      return;
    }
    await this.sshLogin();
  }

  async tryGrant(grant: Uint8Array): Promise<boolean> {
    const [, reply] = await this.request(0, envelope({
      message: {
        case: "authenticate",
        value: create(AuthenticateSchema, {
          method: { case: "connectionGrant", value: grant },
        }),
      },
    }));
    return reply.message.case === "authenticationResult" && reply.message.value.ok;
  }

  async sshLogin(): Promise<void> {
    const dialog = document.getElementById("login") as HTMLDialogElement;
    const passwordSection = document.getElementById("login-password-section")!;
    const step1 = document.getElementById("login-step1")!;
    const step2 = document.getElementById("login-step2")!;
    const errorLine = document.getElementById("login-error")!;
    const username = document.getElementById("login-username") as HTMLInputElement;
    const password = document.getElementById("login-password") as HTMLInputElement;
    const pubkey = document.getElementById("login-pubkey") as HTMLTextAreaElement;
    const command = document.getElementById("login-command")!;
    const signature = document.getElementById("login-signature") as HTMLTextAreaElement;

    // Channel binding (ADR 0008): the server certificate hash, mixed into the
    // signed message so a relayed challenge cannot be reused elsewhere. The
    // same endpoint advertises whether password login (ADR 0016) is enabled.
    const info = (await fetch("/webtransport-info").then((r) => r.json())) as {
      certHashBase64: string;
      passwordAuth?: boolean;
    };
    const binding = b64.dec(info.certHashBase64);

    // Password is the default form when the daemon offers it; the key flow
    // stays one click away either way (and is the only form otherwise).
    const showPassword = (show: boolean) => {
      passwordSection.hidden = !show;
      step1.hidden = show;
      step2.hidden = true;
      errorLine.textContent = "";
    };
    document.getElementById("login-use-password-line")!.hidden = !info.passwordAuth;
    showPassword(info.passwordAuth === true);
    dialog.showModal();

    await new Promise<void>((resolve) => {
      let challenge: Uint8Array | null = null;

      const finish = (grant: Uint8Array) => {
        if (grant.length > 0) localStorage.setItem(GRANT_KEY, b64.enc(grant));
        password.value = "";
        dialog.close();
        resolve();
      };

      document.getElementById("login-use-key")!.onclick = (event) => {
        event.preventDefault();
        showPassword(false);
      };
      document.getElementById("login-use-password")!.onclick = (event) => {
        event.preventDefault();
        showPassword(true);
      };

      const submitPassword = async () => {
        errorLine.textContent = "";
        const [, reply] = await this.request(0, envelope({
          message: {
            case: "authenticate",
            value: create(AuthenticateSchema, {
              method: {
                case: "passwordRequest",
                value: create(PasswordRequestSchema, {
                  username: username.value.trim(),
                  password: password.value,
                }),
              },
            }),
          },
        }));
        if (reply.message.case !== "authenticationResult" || !reply.message.value.ok) {
          errorLine.textContent = "sign-in failed — check the username and password";
          return;
        }
        finish(reply.message.value.challenge);
      };
      document.getElementById("login-password-submit")!.onclick = submitPassword;
      password.onkeydown = (event) => {
        if (event.key === "Enter") void submitPassword();
      };

      document.getElementById("login-request")!.onclick = async () => {
        errorLine.textContent = "";
        const [, reply] = await this.request(0, envelope({
          message: {
            case: "authenticate",
            value: create(AuthenticateSchema, {
              method: {
                case: "sshChallengeRequest",
                value: create(SshChallengeRequestSchema, {
                  username: username.value.trim(),
                  publicKey: new TextEncoder().encode(pubkey.value.trim()),
                }),
              },
            }),
          },
        }));
        if (reply.message.case !== "authenticationResult"
            || reply.message.value.challenge.length === 0) {
          errorLine.textContent = "key not authorized for that user";
          return;
        }
        challenge = reply.message.value.challenge;
        const message = new Uint8Array(binding.length + challenge.length);
        message.set(binding, 0);
        message.set(challenge, binding.length);
        command.textContent =
          `echo ${b64.enc(message)} | base64 -d | ` +
          `ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n holdfast-auth@v0`;
        step1.hidden = true;
        step2.hidden = false;
      };

      document.getElementById("login-submit")!.onclick = async () => {
        if (!challenge) return;
        errorLine.textContent = "";
        const [, reply] = await this.request(0, envelope({
          message: {
            case: "authenticate",
            value: create(AuthenticateSchema, {
              method: {
                case: "sshChallengeResponse",
                value: create(SshChallengeResponseSchema, {
                  challenge,
                  signature: new TextEncoder().encode(signature.value.trim() + "\n"),
                }),
              },
            }),
          },
        }));
        if (reply.message.case !== "authenticationResult" || !reply.message.value.ok) {
          errorLine.textContent = "signature rejected — check the key and try again";
          return;
        }
        finish(reply.message.value.challenge); // issued grant (spec §5)
      };
    });
  }

  async newShell(): Promise<void> {
    const key = crypto.getRandomValues(new Uint8Array(16));
    const [, reply] = await this.request(0, envelope({
      message: {
        case: "openShell",
        value: create(OpenShellSchema, {
          command: "",
          initialCols: 80,
          initialRows: 24,
          idempotencyKey: key,
        }),
      },
    }));
    if (reply.message.case === "error") {
      this.setStatus(`open failed: ${reply.message.value.humanMessage}`, "err");
      return;
    }
    if (reply.message.case !== "shellOpened") return;
    const shellId = reply.shellId;
    const token = reply.message.value.resumeToken;
    const name = `shell ${this.tabs.length + 1}`;
    const stored = loadStored();
    stored.push({ id: b64.enc(shellId), token: b64.enc(token), name, idem: b64.enc(key) });
    saveStored(stored);
    await this.attachShell(shellId, token, name);
  }

  findTab(shellId: Uint8Array): Tab | undefined {
    const key = b64.enc(shellId);
    return this.tabs.find((t) => b64.enc(t.shellId) === key);
  }

  async attachShell(shellId: Uint8Array, token: Uint8Array, name: string): Promise<void> {
    const transport = this.transport;
    if (!transport) return;
    let tab = this.findTab(shellId);
    if (!tab) {
      tab = new Tab(shellId, name, this);
      this.tabs.push(tab);
      if (!this.active) this.select(tab);
    }
    tab.fit.fit();

    // Retire the previous attachment's channel before opening the new one.
    // Output still arriving on it belongs to the pre-snapshot stream and is
    // already reflected in the snapshot about to replace it; left mapped, it
    // would be replayed on top and double-applied.
    if (tab.channel !== 0) this.channelToTab.delete(tab.channel);
    tab.channel = transport.openChannel();
    this.channelToTab.set(tab.channel, tab);

    // Reset the live buffer HERE, not after the await. The daemon registers
    // the new attachment's queue and takes the snapshot under one lock, so
    // everything that can arrive on this channel is post-snapshot and must be
    // replayed. Clearing after the await discarded exactly the frames that
    // were batched behind ShellAttached in the same QUIC read — output that
    // is in neither the snapshot nor the replay, and simply vanished.
    tab.liveChunks = [];
    tab.liveBytes = 0;
    tab.liveOverflowed = false;
    tab.presented = false;

    const [, reply] = await this.request(tab.channel, envelope({
      shellId,
      message: {
        case: "attachShell",
        value: create(AttachShellSchema, {
          resumeToken: token,
          cols: tab.term.cols,
          rows: tab.term.rows,
        }),
      },
    }));

    if (reply.message.case === "error") {
      const err = reply.message.value;
      if (err.code === ErrorCode.ERR_NOT_FOUND) {
        // The shell is genuinely gone; dropping the entry is correct.
        this.forget(shellId);
        tab.setState("exited");
        tab.term.write(`\r\n\x1b[31m[cannot reattach: ${err.humanMessage}]\x1b[0m\r\n`);
        return;
      }
      if (err.code === ErrorCode.ERR_TOKEN_EXPIRED) {
        // An expired token does NOT mean the shell died — it usually means
        // another attach rotated it. This used to call forget(), which
        // permanently deleted a still-running shell from this browser: every
        // attach rotates the token, so any racing attach cost the user their
        // only way back. Recover through the idempotency key instead, which
        // is what the daemon's open_shell is for.
        if (await this.recoverExpired(tab, shellId, name)) return;
        tab.setState("exited");
        tab.term.write(
          `\r\n\x1b[31m[cannot reattach: ${err.humanMessage}]\x1b[0m\r\n` +
            `\x1b[33m[the shell may still be running; it has been kept in this ` +
            `browser's list]\x1b[0m\r\n`,
        );
        return;
      }
      return;
    }
    if (reply.message.case !== "shellAttached") return;
    const attached = reply.message.value;

    // Persist the rotated token immediately — it is the only way back in.
    const stored = loadStored();
    const entry = stored.find((s) => s.id === b64.enc(shellId));
    if (entry) {
      entry.token = b64.enc(attached.rotatedResumeToken);
      saveStored(stored);
    }

    tab.snapshot = attached.screenSnapshot;
    tab.historyLines = [];
    tab.oldestFetched = 0n;
    tab.oldestAvailable = attached.oldestHistoryLineId;
    tab.historyExhausted = attached.newestHistoryLineId === 0n;
    tab.setState("live");

    // Render the snapshot NOW: until this reset+redraw runs, live output
    // composites over whatever stale frame the terminal held, which is
    // exactly how a burst-triggered reattach used to shear the screen.
    // History arrives in the background and re-renders when ready.
    tab.render();
    if (!tab.historyExhausted) {
      void this.fetchOlderHistory(tab, true)
        .then(() => tab.render())
        .catch(() => {});
    }
  }

  /// Recover a shell whose resume token expired, using the idempotency key it
  /// was opened with. `open_shell` is idempotent per (owner, key): a repeated
  /// key returns the SAME shell with a freshly rotated token rather than
  /// creating a second one. Returns whether the shell was recovered.
  ///
  /// Entries stored before the key was persisted have no `idem` and cannot be
  /// recovered this way; they are left in place rather than deleted, because
  /// the shell is very likely still running and another client can still
  /// reach it.
  async recoverExpired(tab: Tab, shellId: Uint8Array, name: string): Promise<boolean> {
    const entry = loadStored().find((s) => s.id === b64.enc(shellId));
    if (!entry?.idem) return false;

    const [, reply] = await this.request(0, envelope({
      message: {
        case: "openShell",
        value: create(OpenShellSchema, {
          command: "",
          initialCols: tab.term.cols,
          initialRows: tab.term.rows,
          idempotencyKey: b64.dec(entry.idem),
        }),
      },
    }));
    if (reply.message.case !== "shellOpened") return false;

    // The daemon may hand back a different shell id only if the original was
    // reaped and the key opened a fresh one; either way persist what we got
    // BEFORE attaching, so a failure here cannot lose the new token too.
    const recoveredId = reply.shellId;
    const token = reply.message.value.resumeToken;
    const stored = loadStored();
    const row = stored.find((s) => s.id === b64.enc(shellId));
    if (row) {
      row.id = b64.enc(recoveredId);
      row.token = b64.enc(token);
    }
    saveStored(stored);

    await this.attachShell(recoveredId, token, name);
    return true;
  }

  /// Reattach a live tab the server force-detached (ERR_TOO_SLOW): fetch a
  /// fresh snapshot under the stored rotated token. The shell is still
  /// running; only the attachment died.
  async reattachDropped(tab: Tab): Promise<void> {
    const entry = loadStored().find((s) => s.id === b64.enc(tab.shellId));
    if (!entry) return;
    await this.attachShell(tab.shellId, b64.dec(entry.token), tab.name);
  }

  async fetchOlderHistory(tab: Tab, initial = false): Promise<void> {
    if (tab.fetchingHistory || tab.historyExhausted || tab.state !== "live") return;
    if (!initial && tab.oldestFetched === 0n) return;
    tab.fetchingHistory = true;
    try {
      const [, reply] = await this.request(tab.channel, envelope({
        message: {
          case: "requestHistory",
          value: create(RequestHistorySchema, {
            beforeLineId: tab.oldestFetched,
            maximumLines: HISTORY_PAGE_LINES,
            maximumBytes: HISTORY_PAGE_BYTES,
          }),
        },
      }));
      if (reply.message.case !== "historyChunk") return;
      const chunk = reply.message.value;
      if (chunk.lines.length === 0) {
        tab.historyExhausted = true;
        return;
      }
      tab.historyLines = [...chunk.lines, ...tab.historyLines];
      tab.oldestFetched = chunk.firstLineId;
      if (chunk.truncatedByEviction || chunk.firstLineId <= tab.oldestAvailable) {
        tab.historyExhausted = true;
      }
      if (!initial) tab.render();
    } finally {
      tab.fetchingHistory = false;
    }
  }

  sendInput(tab: Tab, data: string): void {
    if (tab.state !== "live" || !this.transport) return;
    this.transport.send(tab.channel, envelope({
      message: {
        case: "terminalInput",
        value: create(TerminalInputSchema, { data: new TextEncoder().encode(data) }),
      },
    }));
  }

  /// Intercept clipboard paste (T9): a paste carrying newlines or control
  /// characters can inject commands, so confirm before sending it. Plain text
  /// pastes fall through to xterm.js's normal handling.
  handlePaste(tab: Tab, event: ClipboardEvent): void {
    const text = event.clipboardData?.getData("text") ?? "";
    if (!pasteNeedsConfirmation(text)) return; // let xterm.js paste it
    event.preventDefault();
    event.stopPropagation();
    const lines = text.split(/\r\n|\r|\n/).length;
    if (confirm(`Paste ${lines} lines into the terminal? It contains newlines or control characters.`)) {
      this.sendInput(tab, text);
    }
  }

  sendResize(tab: Tab, cols: number, rows: number): void {
    if (tab.state !== "live" || !this.transport) return;
    this.transport.send(tab.channel, envelope({
      message: { case: "terminalResize", value: create(TerminalResizeSchema, { cols, rows }) },
    }));
  }

  select(tab: Tab): void {
    this.active = tab;
    for (const t of this.tabs) {
      t.panel.style.display = t === tab ? "block" : "none";
      t.button.classList.toggle("active", t === tab);
    }
    tab.fit.fit();
    tab.term.focus();
  }

  detachActive(): void {
    const tab = this.active;
    if (!tab || tab.state !== "live" || !this.transport) return;
    this.transport.send(tab.channel, envelope({
      message: { case: "detachShell", value: create(DetachShellSchema, {}) },
    }));
    this.channelToTab.delete(tab.channel);
    tab.setState("detached");
    tab.term.write("\r\n\x1b[2m[detached — shell keeps running; reload to reattach]\x1b[0m\r\n");
  }

  async terminateActive(): Promise<void> {
    const tab = this.active;
    if (!tab || !this.transport) return;
    if (!confirm(`Terminate ${tab.name}? The shell process will be killed.`)) return;
    const env = envelope({
      shellId: tab.shellId,
      message: { case: "terminateShell", value: create(TerminateShellSchema, {}) },
    });
    await this.request(0, env);
    this.markExited(tab, "terminated");
  }

  markExited(tab: Tab, how: string): void {
    tab.setState("exited");
    tab.term.write(`\r\n\x1b[31m[shell ${how}]\x1b[0m\r\n`);
    this.forget(tab.shellId);
  }

  forget(shellId: Uint8Array): void {
    const key = b64.enc(shellId);
    saveStored(loadStored().filter((s) => s.id !== key));
  }

  onFrame(channel: number, env: Envelope): void {
    if (env.requestId !== 0n) {
      const resolver = this.pending.get(env.requestId);
      if (resolver) {
        resolver(channel, env);
        return;
      }
    }
    const tab = this.channelToTab.get(channel);
    switch (env.message.case) {
      case "terminalOutput":
        tab?.appendLive(env.message.value.data);
        break;
      case "shellExited":
        if (tab) this.markExited(tab, `exited (code ${env.message.value.exitCode})`);
        break;
      case "error":
        // ERR_TOO_SLOW (spec §8): the server dropped this attachment because
        // output overran its bounded queue (e.g. an IRC art-spam burst). The
        // shell is fine — reattach for a fresh snapshot instead of leaving a
        // wedged tab that still claims to be live.
        if (
          tab &&
          tab.state === "live" &&
          env.message.value.code === ErrorCode.ERR_TOO_SLOW
        ) {
          this.channelToTab.delete(tab.channel);
          tab.setState("reconnecting");
          void this.reattachDropped(tab);
        }
        break;
      case "ping":
        this.transport?.send(channel, envelope({
          requestId: env.requestId,
          message: { case: "pong", value: create(PongSchema, { nonce: env.message.value.nonce }) },
        }));
        break;
      default:
        break;
    }
  }
}

void new App().start();
