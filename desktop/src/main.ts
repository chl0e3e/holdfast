// Holdfast desktop frontend: shells as tabs grouped per server. The Rust
// core (hf-client-core) owns connections, auth, tokens and reconnect; this
// layer renders terminals and reacts to core events (ADR 0019).
//
// Startup: bootstrap() → a Tab per stored shell → attach_shell for each.
// Attach commands queue in the Rust supervisor until its server connects, so
// the frontend just fires them and lets the promises resolve.

import {
  ipc,
  subscribe,
  type ServerStatus,
  type ServerView,
  type ShellRow,
} from "./ipc.js";
import { Tab, type TabDelegate } from "./tab.js";
import { pasteNeedsConfirmation } from "./terminal-safety.js";
import { clampFontSize, loadFontSize, saveFontSize } from "./font-size.js";
import { dockerwmOpenUrl, LinkPopover, loadDockerwmBase } from "./links.js";
import {
  attachmentAction,
  closeBehavior,
  detachedEventAction,
  emptyWorkspace,
  quotePosixShellWord,
  shouldAttachWhenConnected,
  uploadAction,
} from "./ui-state.js";

const HISTORY_PAGE_LINES = 200;
const CLOSED_SHELL_CAP = 1_024;

type ServerGroup = {
  key: string;
  displayName: string;
  username?: string;
  status: ServerStatus;
  fileUploads: boolean;
  container: HTMLElement;
  label: HTMLElement;
  slot: HTMLElement; // where this server's tab buttons live
};

class App implements TabDelegate {
  tabs: Tab[] = [];
  groups = new Map<string, ServerGroup>();
  active: Tab | null = null;
  status = document.getElementById("status")!;
  attachmentAction = document.getElementById("attachment-action") as HTMLButtonElement;
  terminateAction = document.getElementById("terminate") as HTMLButtonElement;
  uploadAction = document.getElementById("upload") as HTMLButtonElement;
  emptyState = document.getElementById("empty-state")!;
  resizeTimers = new Map<Tab, ReturnType<typeof setTimeout>>();
  private resizeFrame: number | null = null;
  private panelObserver: ResizeObserver | null = null;
  private activeUploads = new Map<string, { bytes: number; totalBytes: number }>();
  private uploadedResult: { server: string; shell: string; path: string } | null = null;
  /** Tabs deliberately closed during this run. Bounded so authoritative
   *  server updates do not immediately recreate them as "elsewhere". */
  private closedShells = new Set<string>();
  /** Running shells on a server we hold no resume token for (opened by
   *  another client): server key → shell hex → its dim button. */
  elsewhere = new Map<string, Map<string, HTMLButtonElement>>();
  /** Server key the login dialog is currently prompting for. */
  loginFor: string | null = null;
  fontSize = loadFontSize();
  private dockerwmBase = loadDockerwmBase();
  // Navigation goes through the Rust side: the webview has no working
  // window.open, and open_external re-validates the scheme (T9).
  linkPopover = new LinkPopover(
    this.dockerwmBase,
    (url) => { void ipc.openExternal(url).catch(() => {}); },
    (url) => {
      void ipc.openInDockerwm(url)
        .then((opened) => {
          if (!opened) return ipc.openExternal(dockerwmOpenUrl(this.dockerwmBase, url));
        })
        .catch((error) => {
          const detail = error instanceof Error ? error.message : String(error);
          this.status.textContent = `DockerWM could not open the link: ${detail}`;
        });
    },
  );

  async start(): Promise<void> {
    document.getElementById("add-server")!.onclick = () => this.addServerDialog();
    document.getElementById("empty-primary")!.onclick = () => this.emptyPrimaryAction();
    this.attachmentAction.onclick = () => void this.toggleAttachment();
    this.terminateAction.onclick = () => void this.terminateActive();
    this.uploadAction.onclick = () => void this.uploadActive();
    document.getElementById("upload-copy")!.onclick = () => void this.copyUploadedPath();
    document.getElementById("upload-insert")!.onclick = () => this.insertUploadedPath();
    document.getElementById("font-smaller")!.onclick = () => this.adjustFontSize(-1);
    document.getElementById("font-larger")!.onclick = () => this.adjustFontSize(1);
    // Cancel buttons are type=button (see index.html); close their dialogs here.
    document.getElementById("srv-cancel")!.onclick = () =>
      (document.getElementById("add-server-dialog") as HTMLDialogElement).close();
    document.getElementById("login-cancel")!.onclick = () =>
      (document.getElementById("login-dialog") as HTMLDialogElement).close();
    window.addEventListener("resize", () => this.scheduleFit());
    // WebView2 may discard or pause the terminal renderer while the desktop
    // window is hidden/occluded. Do not wait for terminal input to wake it.
    window.addEventListener("focus", () => this.scheduleFit());
    window.addEventListener("pageshow", () => this.scheduleFit());
    document.addEventListener("visibilitychange", () => {
      if (!document.hidden) this.scheduleFit();
    });
    this.panelObserver = new ResizeObserver(() => this.scheduleFit());
    this.panelObserver.observe(document.getElementById("panels")!);

    await this.subscribeAndBootstrap();
  }

  tabStateChanged(tab: Tab): void {
    if (tab === this.active) this.syncChrome();
  }

  presentTerminal(tab: Tab): void {
    if (tab === this.active) this.scheduleFit();
  }

  serverDisplayName(server: string): string {
    return this.groups.get(server)?.displayName ?? server.slice(0, 8);
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

  private async subscribeAndBootstrap(): Promise<void> {
    await subscribe({
      serverStatus: (e) => {
        const group = this.groups.get(e.server);
        if (group) {
          group.status = e.status;
          group.label.dataset.status = e.status;
          group.label.title = e.detail ?? "";
        }
        if (e.status === "auth-required") this.promptLogin(e.server, e.detail);
        if (e.status === "connected") {
          // Bring back every tab that lost its attachment while we were away.
          for (const tab of this.tabs) {
            if (tab.server === e.server && shouldAttachWhenConnected(tab.state)) {
              void this.attach(tab);
            }
          }
        } else {
          for (const tab of this.tabs) {
            if (tab.server === e.server && tab.state === "live") tab.setState("reconnecting");
          }
        }
        this.refreshStatusLine();
      },
      shellState: (e) => {
        const tab = this.findTab(e.server, e.shell);
        if (!tab || tab.closing) return;
        switch (e.state) {
          case "attached":
            break; // attach() drives the live transition itself
          case "detached":
            if (detachedEventAction(tab.state, tab.detaching) === "mark-detached") {
              tab.setState("detached");
              break;
            }
            // Server-initiated drop (ERR_TOO_SLOW after an output burst) or
            // transport death. The connection is often still healthy, so try
            // to reattach immediately for a fresh snapshot — attach() is
            // guarded against overlap and a failed attempt falls back to the
            // next `connected` retry loop.
            if (detachedEventAction(tab.state, false) === "reattach") {
              tab.setState("reconnecting");
              void this.attach(tab);
            }
            break;
          case "orphaned":
            tab.setState("orphaned");
            tab.appendNotice("\r\n\x1b[31m[token unrecoverable — Terminate to kill, or close the tab]\x1b[0m\r\n");
            break;
          case "exited":
            this.markExited(tab, e.exitCode !== undefined ? `exited (code ${e.exitCode})` : "exited");
            break;
        }
      },
      shellsUpdated: (e) => this.reconcileShells(e.server, e.shells),
      storeWarning: (e) => this.setStatus(e.message, "warn"),
      serverCapabilities: (e) => {
        const group = this.groups.get(e.server);
        if (group) group.fileUploads = e.fileUploads;
        this.syncChrome();
      },
      uploadProgress: (e) => {
        const key = this.shellKey(e.server, e.shell);
        if (!this.activeUploads.has(key)) return;
        this.activeUploads.set(key, { bytes: e.bytes, totalBytes: e.totalBytes });
        const tab = this.findTab(e.server, e.shell);
        const percent = e.totalBytes === 0 ? 100 : Math.floor((e.bytes / e.totalBytes) * 100);
        this.setStatus(
          `${e.phase === "hashing" ? "Checking" : "Uploading"} ${tab?.name ?? "file"} — ${percent}%`,
          "ok",
        );
        this.syncChrome();
      },
    });

    const boot = await ipc.bootstrap();
    for (const server of boot.servers) {
      const group = this.ensureGroup(server);
      group.fileUploads = server.fileUploads;
      // Statuses emitted before this frontend subscribed (auth-required
      // fires milliseconds after core spawn) arrive via the bootstrap
      // snapshot instead of an event.
      if (server.status) {
        group.status = server.status;
        group.label.dataset.status = server.status;
        if (server.status === "auth-required") {
          this.promptLogin(server.key, server.statusDetail);
        }
      }
    }
    for (const server of boot.servers) {
      for (const shell of server.shells) {
        const tab = this.ensureTab(server.key, shell.shell, shell.name);
        void this.attach(tab);
      }
    }
    if (boot.servers.length === 0) {
      this.setStatus("no servers — add one to begin", "warn");
      this.addServerDialog();
    } else {
      this.refreshStatusLine();
    }
    this.syncChrome();
  }

  ensureGroup(server: Pick<ServerView, "key" | "displayName" | "username">): ServerGroup {
    let group = this.groups.get(server.key);
    if (group) return group;
    const container = document.createElement("div");
    container.className = "server-group";
    const label = document.createElement("button");
    label.className = "server-label";
    label.textContent = server.displayName;
    label.dataset.status = "connecting";
    // A dismissed login prompt can be reopened from the server label.
    label.onclick = () => {
      if (this.groups.get(server.key)?.status === "auth-required") this.promptLogin(server.key);
    };
    const slot = document.createElement("span");
    slot.style.display = "contents";
    const newShell = document.createElement("button");
    newShell.textContent = "New";
    newShell.className = "new-shell";
    newShell.title = `New shell on ${server.displayName}`;
    newShell.onclick = () => void this.newShell(server.key);
    const remove = document.createElement("button");
    remove.textContent = "×";
    remove.className = "remove-server";
    remove.title = `Remove ${server.displayName} (shells keep running on the server)`;
    remove.onclick = () => void this.removeServer(server.key);
    container.append(label, slot, newShell, remove);
    document.getElementById("tabs")!.appendChild(container);
    group = {
      key: server.key,
      displayName: server.displayName,
      username: server.username,
      status: "connecting",
      fileUploads: false,
      container,
      label,
      slot,
    };
    this.groups.set(server.key, group);
    this.syncChrome();
    return group;
  }

  async removeServer(server: string): Promise<void> {
    const group = this.groups.get(server);
    if (!group) return;
    if (
      !confirm(
        `Remove ${group.displayName}?\n\nShells keep running on the server, but the stored ` +
          `resume tokens and grant for it are deleted — reattaching later needs fresh auth.`,
      )
    ) {
      return;
    }
    try {
      await ipc.removeServer(server);
    } catch (error) {
      this.setStatus(`remove failed: ${error}`, "err");
      return;
    }
    for (const tab of this.tabs.filter((t) => t.server === server)) {
      if (tab === this.active) this.active = null;
      tab.dispose();
    }
    this.tabs = this.tabs.filter((t) => t.server !== server);
    this.elsewhere.delete(server);
    group.container.remove();
    this.groups.delete(server);
    const next = this.tabs[0];
    if (!this.active && next) this.select(next);
    this.refreshStatusLine();
    this.syncChrome();
  }

  renameTab(tab: Tab): void {
    const name = prompt("Rename shell", tab.name)?.trim();
    if (!name || name === tab.name) return;
    void ipc.renameShell(tab.server, tab.shell, name).then(
      () => {
        tab.name = name;
        tab.refreshLabel();
      },
      (error) => this.setStatus(`rename failed: ${error}`, "err"),
    );
  }

  findTab(server: string, shell: string): Tab | undefined {
    return this.tabs.find((t) => t.server === server && t.shell === shell);
  }

  ensureTab(server: string, shell: string, name: string): Tab {
    let tab = this.findTab(server, shell);
    if (tab) return tab;
    this.closedShells.delete(this.shellKey(server, shell));
    const group = this.groups.get(server);
    if (!group) throw new Error(`no group for server ${server}`);
    tab = new Tab(server, shell, name, group.slot, this);
    this.tabs.push(tab);
    if (!this.active) this.select(tab);
    return tab;
  }

  /** Reconcile the server's authoritative shell list (sent on every
   *  connect) with our tabs: adopt running shells we hold a token for,
   *  surface the rest as dim "elsewhere" entries (terminate-only — without
   *  a resume token there is no attach path, spec section 12). */
  reconcileShells(server: string, rows: ShellRow[]): void {
    const group = this.groups.get(server);
    if (!group) return;
    const running = new Set<string>();
    for (const row of rows) {
      const closedKey = this.shellKey(server, row.shell);
      if (this.closedShells.has(closedKey)) {
        if (row.state !== "running") this.closedShells.delete(closedKey);
        continue;
      }
      if (row.state !== "running") {
        const tab = this.findTab(server, row.shell);
        if (tab && tab.state !== "exited") this.markExited(tab, "exited while away");
        continue;
      }
      running.add(row.shell);
      if (this.findTab(server, row.shell)) continue;
      if (row.hasToken) {
        // e.g. imported from the CLI's state, or opened by a previous run.
        const tab = this.ensureTab(server, row.shell, row.name ?? `shell ${row.shell.slice(0, 8)}`);
        void this.attach(tab);
      } else {
        this.ensureElsewhere(group, server, row);
      }
    }
    // Prune entries that exited, were terminated, or got adopted as tabs.
    const map = this.elsewhere.get(server);
    if (map) {
      for (const [shell, button] of [...map]) {
        if (!running.has(shell) || this.findTab(server, shell)) {
          button.remove();
          map.delete(shell);
        }
      }
    }
  }

  ensureElsewhere(group: ServerGroup, server: string, row: ShellRow): void {
    let map = this.elsewhere.get(server);
    if (!map) {
      map = new Map();
      this.elsewhere.set(server, map);
    }
    if (map.has(row.shell)) return;
    const button = document.createElement("button");
    button.className = "elsewhere";
    const label = row.name ?? row.shell.slice(0, 8);
    button.textContent = `${label} · elsewhere`;
    button.title = "Running on the server, opened by another client — no resume token here.";
    button.onclick = () => {
      if (!confirm(`"${label}" was opened by another client; you cannot attach it from here. Terminate it?`)) return;
      void ipc.terminateShell(server, row.shell).then(
        () => {
          button.remove();
          this.elsewhere.get(server)?.delete(row.shell);
        },
        (error) => this.setStatus(`terminate failed: ${error}`, "err"),
      );
    };
    group.slot.appendChild(button);
    map.set(row.shell, button);
  }

  async attach(tab: Tab): Promise<void> {
    if (tab.closing || tab.attaching || tab.state === "exited" || tab.state === "orphaned") return;
    tab.attaching = true;
    this.syncChrome();
    try {
      tab.fit.fit();
      const generation = tab.resetForAttach();
      const reply = await ipc.attachShell(
        tab.server,
        tab.shell,
        tab.term.cols,
        tab.term.rows,
        (bytes) => tab.onChannelMessage(bytes, generation),
      );
      if (tab.closing) return;
      tab.oldestAvailable = reply.oldestHistoryLineId;
      tab.historyExhausted = reply.newestHistoryLineId === 0;
      tab.setState("live");
      // Render the snapshot NOW: until this reset+redraw runs, live output
      // would composite over whatever stale frame the terminal held — the
      // burst-reattach shear. History arrives in the background.
      tab.render();
      if (!tab.historyExhausted) {
        void this.fetchOlderHistory(tab, true)
          .then(() => tab.render())
          .catch(() => {});
      }
    } catch (error) {
      // The Rust side classified the failure: unrecoverable ones arrive as
      // shell-state events (orphaned/exited) which may have already updated
      // tab.state during the await; everything else retries on the next
      // `connected`. (Widened read: events mutate state across await points.)
      const state = tab.state as import("./tab.js").TabState;
      if (state !== "exited" && state !== "orphaned") {
        tab.setState("reconnecting");
      }
      console.warn(`attach ${tab.shell.slice(0, 8)}:`, error);
    } finally {
      tab.attaching = false;
      this.syncChrome();
    }
  }

  async newShell(server: string): Promise<void> {
    const count = this.tabs.filter((t) => t.server === server).length;
    const name = `shell ${count + 1}`;
    try {
      const shell = await ipc.openShell(server, name, this.active?.term.cols ?? 80, this.active?.term.rows ?? 24);
      const tab = this.ensureTab(server, shell, name);
      this.select(tab);
      await this.attach(tab);
    } catch (error) {
      this.setStatus(`open failed: ${error}`, "err");
    }
  }

  async fetchOlderHistory(tab: Tab, initial = false): Promise<void> {
    if (tab.fetchingHistory || tab.historyExhausted || tab.state !== "live") return;
    if (!initial && tab.oldestFetched === 0) return;
    const generation = tab.attachmentGeneration;
    tab.fetchingHistory = true;
    try {
      const page = await ipc.requestHistory(tab.server, tab.shell, tab.oldestFetched, HISTORY_PAGE_LINES);
      if (tab.closing || generation !== tab.attachmentGeneration || tab.state !== "live") return;
      if (page.lines.length === 0) {
        tab.historyExhausted = true;
        return;
      }
      tab.prependHistory(page.lines);
      tab.oldestFetched = page.firstLineId;
      if (page.truncatedByEviction || page.firstLineId <= tab.oldestAvailable) {
        tab.historyExhausted = true;
      }
      if (!initial) tab.render(true);
    } catch {
      // History is a nicety; the live screen is already correct.
    } finally {
      if (generation === tab.attachmentGeneration) tab.fetchingHistory = false;
    }
  }

  sendInput(tab: Tab, data: string): void {
    if (tab.closing || tab.state !== "live") return;
    void ipc.shellInput(tab.server, tab.shell, new TextEncoder().encode(data));
  }

  sendResize(tab: Tab, cols: number, rows: number): void {
    if (tab.closing || tab.state !== "live") return;
    // Debounce: drags produce floods; the Rust writer coalesces further.
    const existing = this.resizeTimers.get(tab);
    if (existing) clearTimeout(existing);
    this.resizeTimers.set(
      tab,
      setTimeout(() => void ipc.resizeShell(tab.server, tab.shell, cols, rows), 50),
    );
  }

  /** Paste guard (T9), same policy as the web client. */
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

  select(tab: Tab): void {
    if (tab.closing) return;
    this.active = tab;
    for (const t of this.tabs) {
      t.setActive(t === tab);
    }
    this.scheduleFit();
    requestAnimationFrame(() => tab.term.focus());
    this.syncChrome();
  }

  closeTab(tab: Tab): void {
    void this.closeTabNow(tab);
  }

  private async closeTabNow(tab: Tab): Promise<void> {
    if (tab.closing) return;
    const behavior = closeBehavior(tab.state);
    if (
      behavior.confirmRunning &&
      !confirm(
        `Close ${tab.name}?\n\nThe shell keeps running on ${this.serverDisplayName(tab.server)}, ` +
          `and its tab will return the next time Holdfast starts.`,
      )
    ) {
      return;
    }

    tab.closing = true;
    tab.detaching = true;
    this.syncChrome();
    try {
      if (this.activeUploads.has(this.shellKey(tab.server, tab.shell))) {
        await ipc.cancelUpload(tab.server, tab.shell);
      }
      if (behavior.detach) await ipc.detachShell(tab.server, tab.shell);
      // Running-shell close is intentionally reversible: retain its resume
      // token so restarting the client can reopen it. Exited/orphaned tabs
      // have nothing useful to resume and are forgotten permanently.
      if (behavior.forget) await ipc.forgetShell(tab.server, tab.shell);
    } catch (error) {
      tab.closing = false;
      tab.detaching = false;
      this.setStatus(`close failed: ${error}`, "err");
      this.syncChrome();
      return;
    }

    this.rememberClosed(tab.server, tab.shell);
    const elsewhere = this.elsewhere.get(tab.server)?.get(tab.shell);
    elsewhere?.remove();
    this.elsewhere.get(tab.server)?.delete(tab.shell);
    const oldIndex = this.tabs.indexOf(tab);
    const wasActive = this.active === tab;
    const timer = this.resizeTimers.get(tab);
    if (timer) clearTimeout(timer);
    this.resizeTimers.delete(tab);
    this.tabs = this.tabs.filter((candidate) => candidate !== tab);
    if (wasActive) this.active = null;
    tab.dispose();
    if (wasActive) {
      const next = this.tabs[Math.min(Math.max(oldIndex, 0), this.tabs.length - 1)];
      if (next) this.select(next);
    }
    this.syncChrome();
  }

  recoverTerminal(tab: Tab): void {
    // render() may detect overflow inside attach() just before that method's
    // finally block clears `attaching`; defer one microtask so recovery is not
    // mistaken for an overlapping user attach.
    queueMicrotask(() => void this.recoverTerminalNow(tab));
  }

  private async recoverTerminalNow(tab: Tab): Promise<void> {
    if (tab.closing || tab.attaching || tab.detaching || tab.state === "exited" || tab.state === "orphaned") {
      return;
    }
    tab.detaching = true;
    tab.setState("reconnecting");
    try {
      // A fresh attachment supplies an authoritative snapshot and drops any
      // xterm parser backlog whose bounded local replay could not cover it.
      await ipc.detachShell(tab.server, tab.shell);
    } catch (error) {
      console.warn(`render recovery detach ${tab.shell.slice(0, 8)}:`, error);
    } finally {
      tab.detaching = false;
    }
    if (!tab.closing) await this.attach(tab);
  }

  async toggleAttachment(): Promise<void> {
    const tab = this.active;
    if (!tab || tab.attaching || tab.detaching) return;
    if (tab.state === "detached") {
      await this.attach(tab);
      return;
    }
    if (tab.state !== "live") return;
    tab.detaching = true;
    this.syncChrome();
    try {
      await ipc.detachShell(tab.server, tab.shell);
      tab.setState("detached");
      tab.appendNotice("\r\n\x1b[2m[detached — shell keeps running; choose Attach when ready]\x1b[0m\r\n");
    } catch (error) {
      this.setStatus(`detach failed: ${error}`, "err");
    } finally {
      tab.detaching = false;
      this.syncChrome();
    }
  }

  async terminateActive(): Promise<void> {
    const tab = this.active;
    if (!tab) return;
    if (!confirm(`Terminate ${tab.name}? The shell process will be killed.`)) return;
    try {
      await ipc.terminateShell(tab.server, tab.shell);
      this.markExited(tab, "terminated");
    } catch (error) {
      // An orphaned tab whose server-side shell is already gone: just forget.
      await ipc.forgetShell(tab.server, tab.shell);
      this.markExited(tab, `gone (${error})`);
    }
  }

  async uploadActive(): Promise<void> {
    const tab = this.active;
    if (!tab) return;
    const key = this.shellKey(tab.server, tab.shell);
    if (this.activeUploads.has(key)) {
      await ipc.cancelUpload(tab.server, tab.shell).catch((error) =>
        this.setStatus(`cancel failed: ${error}`, "err"),
      );
      return;
    }
    const group = this.groups.get(tab.server);
    const action = uploadAction(
      tab.state,
      group?.status === "connected",
      group?.fileUploads ?? false,
      false,
    );
    if (!action.enabled) return;
    this.activeUploads.set(key, { bytes: 0, totalBytes: 0 });
    this.syncChrome();
    try {
      const result = await ipc.pickAndUpload(tab.server, tab.shell);
      if (!result) return; // native picker dismissed
      this.uploadedResult = {
        server: tab.server,
        shell: tab.shell,
        path: result.remotePath,
      };
      (document.getElementById("upload-remote-path") as HTMLInputElement).value = result.remotePath;
      (document.getElementById("upload-finished-dialog") as HTMLDialogElement).showModal();
      this.setStatus(`uploaded ${result.bytesWritten.toLocaleString()} bytes`, "ok");
    } catch (error) {
      const detail = String(error);
      this.setStatus(detail.includes("cancelled") ? "upload cancelled" : `upload failed: ${detail}`, detail.includes("cancelled") ? "warn" : "err");
    } finally {
      this.activeUploads.delete(key);
      this.syncChrome();
      requestAnimationFrame(() => tab.term.focus());
    }
  }

  private async copyUploadedPath(): Promise<void> {
    if (!this.uploadedResult) return;
    try {
      await navigator.clipboard.writeText(this.uploadedResult.path);
      this.setStatus("remote path copied", "ok");
    } catch (error) {
      this.setStatus(`copy failed: ${error}`, "err");
    }
  }

  private insertUploadedPath(): void {
    const uploaded = this.uploadedResult;
    if (!uploaded) return;
    const tab = this.findTab(uploaded.server, uploaded.shell);
    if (!tab || tab.state !== "live") {
      this.setStatus("attach to the original shell before inserting the path", "warn");
      return;
    }
    this.sendInput(tab, quotePosixShellWord(uploaded.path));
    (document.getElementById("upload-finished-dialog") as HTMLDialogElement).close();
    this.select(tab);
  }

  markExited(tab: Tab, how: string): void {
    tab.setState("exited");
    tab.appendNotice(`\r\n\x1b[31m[shell ${how}]\x1b[0m\r\n`);
  }

  addServerDialog(): void {
    const dialog = document.getElementById("add-server-dialog") as HTMLDialogElement;
    const form = document.getElementById("add-server-form") as HTMLFormElement;
    const url = document.getElementById("srv-url") as HTMLInputElement;
    const name = document.getElementById("srv-name") as HTMLInputElement;
    const user = document.getElementById("srv-user") as HTMLInputElement;
    const key = document.getElementById("srv-key") as HTMLInputElement;
    form.onsubmit = (event) => {
      if ((event.submitter as HTMLButtonElement | null)?.value !== "default") return;
      const trimmedUrl = url.value.trim();
      if (!trimmedUrl) return;
      void (async () => {
        try {
          const server = await ipc.addServer(
            trimmedUrl,
            name.value.trim() || trimmedUrl,
            user.value.trim() || undefined,
            key.value.trim() || undefined,
          );
          this.ensureGroup({
            key: server,
            displayName: name.value.trim() || trimmedUrl,
            username: user.value.trim() || undefined,
          });
          this.refreshStatusLine();
        } catch (error) {
          this.setStatus(`add server failed: ${error}`, "err");
        }
      })();
    };
    dialog.showModal();
  }

  /** Password prompt for a server in `auth-required` (ADR 0016). The
   *  password goes straight to the Rust core for one connect attempt and is
   *  never stored; a wrong password produces another `auth-required` event
   *  whose detail reopens this dialog with the failure message. */
  promptLogin(server: string, detail?: string): void {
    const group = this.groups.get(server);
    if (!group) return;
    const dialog = document.getElementById("login-dialog") as HTMLDialogElement;
    const error = document.getElementById("login-error")!;
    if (dialog.open) {
      if (this.loginFor === server && detail) {
        error.hidden = false;
        error.textContent = detail;
      }
      return;
    }
    this.loginFor = server;
    document.getElementById("login-target")!.textContent =
      group.username
        ? `Log in to ${group.displayName} as ${group.username}.`
        : `${group.displayName} needs a password to connect.`;
    error.hidden = !detail;
    error.textContent = detail ?? "";
    const form = document.getElementById("login-form") as HTMLFormElement;
    const password = document.getElementById("login-password") as HTMLInputElement;
    password.value = "";
    form.onsubmit = (event) => {
      if ((event.submitter as HTMLButtonElement | null)?.value !== "default") return;
      const value = password.value;
      password.value = "";
      if (value) {
        void ipc.login(server, value).catch((e) => this.setStatus(`login failed: ${e}`, "err"));
      }
    };
    dialog.onclose = () => {
      this.loginFor = null;
      password.value = "";
      // Another server may be waiting for its own login.
      for (const other of this.groups.values()) {
        if (other.key !== server && other.status === "auth-required") {
          this.promptLogin(other.key);
          break;
        }
      }
    };
    dialog.showModal();
    password.focus();
  }

  setStatus(text: string, kind: "ok" | "warn" | "err"): void {
    this.status.textContent = text;
    this.status.dataset.kind = kind;
  }

  refreshStatusLine(): void {
    const groups = [...this.groups.values()];
    const connected = groups.filter((g) => g.status === "connected").length;
    if (groups.length === 0) return;
    this.setStatus(
      connected === groups.length
        ? `${connected} server${connected === 1 ? "" : "s"} connected`
        : `${connected} of ${groups.length} servers connected`,
      connected === groups.length ? "ok" : "warn",
    );
  }

  private emptyPrimaryAction(): void {
    if (this.groups.size === 0) {
      this.addServerDialog();
      return;
    }
    const server = [...this.groups.values()].find((group) => group.status === "connected")
      ?? this.groups.values().next().value;
    if (server) void this.newShell(server.key);
  }

  private scheduleFit(): void {
    if (this.resizeFrame !== null) return;
    this.resizeFrame = requestAnimationFrame(() => {
      this.resizeFrame = null;
      const tab = this.active;
      if (!tab || tab.closing || tab.panel.clientWidth === 0 || tab.panel.clientHeight === 0) return;
      tab.present();
    });
  }

  private shellKey(server: string, shell: string): string {
    return `${server}:${shell}`;
  }

  private rememberClosed(server: string, shell: string): void {
    const key = this.shellKey(server, shell);
    this.closedShells.delete(key);
    this.closedShells.add(key);
    while (this.closedShells.size > CLOSED_SHELL_CAP) {
      const oldest = this.closedShells.values().next().value as string | undefined;
      if (oldest === undefined) break;
      this.closedShells.delete(oldest);
    }
  }

  /** Keep shell actions and the empty workspace synchronized with the active
   *  tab. This closes the old dead-end where Detach offered no Attach path. */
  private syncChrome(): void {
    const tab = this.active;
    this.emptyState.hidden = tab !== null;
    if (!tab) {
      const configured = this.groups.size > 0;
      const empty = emptyWorkspace(configured);
      document.getElementById("empty-title")!.textContent = empty.title;
      document.getElementById("empty-copy")!.textContent = empty.copy;
      document.getElementById("empty-primary")!.textContent = empty.action;
    }

    const busy = (tab?.attaching ?? false) || (tab?.detaching ?? false);
    const action = attachmentAction(tab?.state ?? null, busy);
    this.attachmentAction.textContent = action.label;
    this.attachmentAction.disabled = !action.enabled;
    this.attachmentAction.title = action.title;
    this.terminateAction.disabled = !tab || tab.state === "exited" || busy;
    const group = tab ? this.groups.get(tab.server) : undefined;
    const upload = uploadAction(
      tab?.state ?? null,
      group?.status === "connected",
      group?.fileUploads ?? false,
      tab ? this.activeUploads.has(this.shellKey(tab.server, tab.shell)) : false,
    );
    this.uploadAction.textContent = upload.label;
    this.uploadAction.disabled = !upload.enabled;
    this.uploadAction.title = upload.title;
  }
}

void new App().start();
