// Typed bridge to the Rust side (ADR 0019). Terminal output arrives on a
// per-attachment raw Channel (first message = screen snapshot, then live PTY
// bytes); input goes up as a raw-body command with the shell address in
// headers. Everything else is ordinary JSON commands and events.

import { Channel, invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";

export type ShellView = { shell: string; name: string };
export type ServerView = {
  key: string;
  url: string;
  displayName: string;
  shells: ShellView[];
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
    const output = new Channel<ArrayBuffer>();
    output.onmessage = (buffer) => onOutput(new Uint8Array(buffer));
    return invoke<AttachReply>("attach_shell", { server, shell, cols, rows, output });
  },

  /** Raw hot path: bytes in the body, shell address in headers. */
  shellInput: (server: string, shell: string, bytes: Uint8Array) =>
    invoke<void>("shell_input", bytes, {
      headers: { "x-hf-server": server, "x-hf-shell": shell },
    }),

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
