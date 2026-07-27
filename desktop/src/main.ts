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

const HISTORY_PAGE_LINES = 200;

type ServerGroup = {
  key: string;
  displayName: string;
  status: ServerStatus;
  container: HTMLElement;
  label: HTMLElement;
  slot: HTMLElement; // where this server's tab buttons live
};

class App implements TabDelegate {
  tabs: Tab[] = [];
  groups = new Map<string, ServerGroup>();
  active: Tab | null = null;
  status = document.getElementById("status")!;
  resizeTimers = new Map<Tab, ReturnType<typeof setTimeout>>();
  /** Running shells on a server we hold no resume token for (opened by
   *  another client): server key → shell hex → its dim button. */
  elsewhere = new Map<string, Map<string, HTMLButtonElement>>();
  /** Server key the login dialog is currently prompting for. */
  loginFor: string | null = null;

  async start(): Promise<void> {
    document.getElementById("add-server")!.onclick = () => this.addServerDialog();
    document.getElementById("detach")!.onclick = () => void this.detachActive();
    document.getElementById("terminate")!.onclick = () => void this.terminateActive();
    window.addEventListener("resize", () => this.active?.fit.fit());

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
            if (
              tab.server === e.server &&
              (tab.state === "reconnecting" || tab.state === "detached" || tab.state === "connecting")
            ) {
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
        if (!tab) return;
        switch (e.state) {
          case "attached":
            break; // attach() drives the live transition itself
          case "detached":
            if (tab.state === "live") tab.setState("reconnecting");
            break;
          case "orphaned":
            tab.setState("orphaned");
            tab.term.write("\r\n\x1b[31m[token unrecoverable — Terminate to kill, or close the tab]\x1b[0m\r\n");
            break;
          case "exited":
            this.markExited(tab, e.exitCode !== undefined ? `exited (code ${e.exitCode})` : "exited");
            break;
        }
      },
      shellsUpdated: (e) => this.reconcileShells(e.server, e.shells),
      storeWarning: (e) => this.setStatus(e.message, "warn"),
    });

    const boot = await ipc.bootstrap();
    for (const server of boot.servers) this.ensureGroup(server);
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
  }

  ensureGroup(server: Pick<ServerView, "key" | "displayName">): ServerGroup {
    let group = this.groups.get(server.key);
    if (group) return group;
    const container = document.createElement("div");
    container.className = "server-group";
    const label = document.createElement("span");
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
    newShell.textContent = "+";
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
      status: "connecting",
      container,
      label,
      slot,
    };
    this.groups.set(server.key, group);
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
    if (tab.attaching || tab.state === "exited" || tab.state === "orphaned") return;
    tab.attaching = true;
    try {
      tab.fit.fit();
      tab.resetForAttach();
      const reply = await ipc.attachShell(
        tab.server,
        tab.shell,
        tab.term.cols,
        tab.term.rows,
        (bytes) => tab.onChannelMessage(bytes),
      );
      tab.oldestAvailable = reply.oldestHistoryLineId;
      tab.historyExhausted = reply.newestHistoryLineId === 0;
      tab.setState("live");
      if (!tab.historyExhausted) await this.fetchOlderHistory(tab, true);
      tab.render();
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
    tab.fetchingHistory = true;
    try {
      const page = await ipc.requestHistory(tab.server, tab.shell, tab.oldestFetched, HISTORY_PAGE_LINES);
      if (page.lines.length === 0) {
        tab.historyExhausted = true;
        return;
      }
      tab.historyLines = [...page.lines, ...tab.historyLines];
      tab.oldestFetched = page.firstLineId;
      if (page.truncatedByEviction || page.firstLineId <= tab.oldestAvailable) {
        tab.historyExhausted = true;
      }
      if (!initial) tab.render();
    } catch {
      // History is a nicety; the live screen is already correct.
    } finally {
      tab.fetchingHistory = false;
    }
  }

  sendInput(tab: Tab, data: string): void {
    if (tab.state !== "live") return;
    void ipc.shellInput(tab.server, tab.shell, new TextEncoder().encode(data));
  }

  sendResize(tab: Tab, cols: number, rows: number): void {
    if (tab.state !== "live") return;
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
    this.active = tab;
    for (const t of this.tabs) {
      t.panel.style.display = t === tab ? "block" : "none";
      t.button.classList.toggle("active", t === tab);
    }
    tab.fit.fit();
    tab.term.focus();
  }

  async detachActive(): Promise<void> {
    const tab = this.active;
    if (!tab || tab.state !== "live") return;
    await ipc.detachShell(tab.server, tab.shell);
    tab.setState("detached");
    tab.term.write("\r\n\x1b[2m[detached — shell keeps running; restart the app to reattach]\x1b[0m\r\n");
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

  markExited(tab: Tab, how: string): void {
    tab.setState("exited");
    tab.term.write(`\r\n\x1b[31m[shell ${how}]\x1b[0m\r\n`);
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
          this.ensureGroup({ key: server, displayName: name.value.trim() || trimmedUrl });
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
      `${group.displayName} needs a password to connect.`;
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
      `${connected}/${groups.length} servers connected`,
      connected === groups.length ? "ok" : "warn",
    );
  }
}

void new App().start();
