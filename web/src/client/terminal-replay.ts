export const TERMINAL_REPLAY_ROW_CAP = 4_096;

/**
 * Blank one viewport into scrollback, then restore the home position expected
 * by the server snapshot. Snapshot redraw sequences are generated for a fresh
 * emulator at row 1; leaving the cursor at the bottom splits painted text from
 * the cursor when the snapshot ends with its authoritative CUP position.
 */
export function snapshotReplayPreamble(rows: number): string {
  if (!Number.isSafeInteger(rows) || rows <= 0 || rows > TERMINAL_REPLAY_ROW_CAP) {
    throw new RangeError(`invalid terminal replay row count: ${rows}`);
  }
  return "\r\n".repeat(rows) + "\x1b[H";
}
