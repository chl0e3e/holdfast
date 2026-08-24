export const TERMINAL_REPLAY_ROW_CAP = 4_096;
export const TERMINAL_REPLAY_BYTE_CAP = 6 * 1024 * 1024;

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

/** Concatenate a replay only after proving the allocation is within its cap. */
export function composeBoundedReplay(
  parts: readonly Uint8Array[],
  cap = TERMINAL_REPLAY_BYTE_CAP,
): Uint8Array | null {
  let length = 0;
  for (const part of parts) {
    if (part.length > cap - length) return null;
    length += part.length;
  }
  const replay = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    replay.set(part, offset);
    offset += part.length;
  }
  return replay;
}
