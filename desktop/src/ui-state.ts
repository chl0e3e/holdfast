export type TabState =
  | "connecting"
  | "live"
  | "detached"
  | "reconnecting"
  | "orphaned"
  | "exited";

export type AttachmentAction = {
  label: "Attach" | "Detach";
  enabled: boolean;
  title: string;
};

/** Pure presentation policy for the active shell's attachment control. */
export function attachmentAction(
  state: TabState | null,
  attaching: boolean,
): AttachmentAction {
  const canAttach = state === "detached" && !attaching;
  const canDetach = state === "live" && !attaching;
  return {
    label: canAttach ? "Attach" : "Detach",
    enabled: canAttach || canDetach,
    title: canAttach
      ? "Attach to the still-running shell"
      : "Detach while leaving the shell running",
  };
}

export function emptyWorkspace(configured: boolean): {
  title: string;
  copy: string;
  action: string;
} {
  return configured
    ? {
        title: "No shell open",
        copy: "Open a persistent shell on one of your configured servers.",
        action: "Open shell",
      }
    : {
        title: "Connect your first server",
        copy: "Add a Holdfast daemon, then open a shell that stays put while you roam.",
        action: "Add server",
      };
}

/** A deliberate detach survives later connection-status refreshes. */
export function shouldAttachWhenConnected(state: TabState): boolean {
  return state === "connecting" || state === "reconnecting";
}

export function detachedEventAction(
  state: TabState,
  userDetachInFlight: boolean,
): "mark-detached" | "reattach" | "ignore" {
  if (userDetachInFlight) return "mark-detached";
  return state === "live" ? "reattach" : "ignore";
}

export type CloseBehavior = {
  confirmRunning: boolean;
  detach: boolean;
  forget: boolean;
};

/** Closing is UI-only for a running shell and permanent for a dead tab. */
export function closeBehavior(state: TabState): CloseBehavior {
  const dead = state === "exited" || state === "orphaned";
  return {
    confirmRunning: !dead,
    detach: !dead && state !== "detached",
    forget: dead,
  };
}
