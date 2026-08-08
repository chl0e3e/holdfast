// Typed bridge to the Rust side (ADR 0019). Terminal output arrives on a
// per-attachment Channel as base64 strings (first message = screen snapshot,
// then live PTY bytes); input goes up as a plain byte array. WebView2
// delivers raw invoke bodies as JSON and drops raw channel payloads, so the
// byte paths must stay JSON-safe. Everything else is ordinary JSON commands
// and events.

import { Channel, invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export type ShellView = { shell: string; name: string };
export type ServerView = {
  key: string;
  url: string;
  displayName: string;
  username?: string;
  shells: ShellView[];
  /** Status at bootstrap time — set when the core emitted one before the
   *  frontend subscribed (e.g. auth-required right after launch). */
  status?: ServerStatus;
  statusDetail?: string;
};
export type BootstrapView = { servers: ServerView[] };

export type ServerStatus = "connecting" | "connected" | "reconnecting" | "auth-required";
export type ShellStateName = "attached" | "detached" | "orphaned" | "exited";

export type ServerStatusEvent = {
  type: "serverStatus";
  server: string;
  status: ServerStatus;
  detail?: string;
};
export type ShellStateEvent = {
  type: "shellState";
  server: string;
  shell: string;
  state: ShellStateName;
  exitCode?: number;
};
export type ShellRow = {
  shell: string;
  state: string;
  name?: string;
  hasToken: boolean;
};
export type ShellsUpdatedEvent = {
  type: "shellsUpdated";
  server: string;
  shells: ShellRow[];
};
export type StoreWarningEvent = { type: "storeWarning"; message: string };

export type AttachReply = {
  oldestHistoryLineId: number;
  newestHistoryLineId: number;
};
export type HistoryPage = {
  lines: string[];
  firstLineId: number;
  truncatedByEviction: boolean;
};

export const ipc = {
  bootstrap: () => invoke<BootstrapView>("bootstrap"),

  addServer: (url: string, displayName: string, username?: string, sshKeyPath?: string) =>
    invoke<string>("add_server", { url, displayName, username, sshKeyPath }),

  removeServer: (server: string) => invoke<void>("remove_server", { server }),

  /** One-shot password login (ADR 0016); result arrives as a server-status event. */
  login: (server: string, password: string) => invoke<void>("login", { server, password }),

  openShell: (server: string, name: string, cols: number, rows: number) =>
    invoke<string>("open_shell", { server, name, cols, rows }),

  /** `onOutput` receives the snapshot first, then live bytes, in order. */
  attachShell: (
    server: string,
    shell: string,
    cols: number,
    rows: number,
    onOutput: (bytes: Uint8Array) => void,
  ) => {
    const output = new Channel<string>();
    output.onmessage = (b64) =>
      onOutput(Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)));
    return invoke<AttachReply>("attach_shell", { server, shell, cols, rows, output });
  },

  shellInput: (server: string, shell: string, bytes: Uint8Array) =>
    invoke<void>("shell_input", { server, shell, data: Array.from(bytes) }),

  resizeShell: (server: string, shell: string, cols: number, rows: number) =>
    invoke<void>("resize_shell", { server, shell, cols, rows }),

  detachShell: (server: string, shell: string) =>
    invoke<void>("detach_shell", { server, shell }),

  terminateShell: (server: string, shell: string) =>
    invoke<number>("terminate_shell", { server, shell }),

  requestHistory: (server: string, shell: string, beforeLineId: number, maxLines: number) =>
    invoke<HistoryPage>("request_history", { server, shell, beforeLineId, maxLines }),

  forgetShell: (server: string, shell: string) =>
    invoke<void>("forget_shell", { server, shell }),

  renameShell: (server: string, shell: string, name: string) =>
    invoke<void>("rename_shell", { server, shell, name }),

  /** Open an http(s) URL in the OS default browser (scheme re-validated in
   *  Rust — hostile terminal output must not reach other scheme handlers). */
  openExternal: (url: string) => invoke<void>("open_external", { url }),
};

export type Events = {
  serverStatus: (event: ServerStatusEvent) => void;
  shellState: (event: ShellStateEvent) => void;
  shellsUpdated: (event: ShellsUpdatedEvent) => void;
  storeWarning: (event: StoreWarningEvent) => void;
};

export async function subscribe(handlers: Events): Promise<UnlistenFn[]> {
  return Promise.all([
    listen<ServerStatusEvent>("server-status", (e) => handlers.serverStatus(e.payload)),
    listen<ShellStateEvent>("shell-state", (e) => handlers.shellState(e.payload)),
    listen<ShellsUpdatedEvent>("shells-updated", (e) => handlers.shellsUpdated(e.payload)),
    listen<StoreWarningEvent>("store-warning", (e) => handlers.storeWarning(e.payload)),
  ]);
}
