export const HISTORY_RENDER_LINE_CAP = 5_000;
export const HISTORY_RENDER_BYTE_CAP = 2 * 1024 * 1024;
export const TERMINAL_WRITE_QUEUE_CAP = 2 * 1024 * 1024;
export const TERMINAL_WRITE_QUEUE_CHUNK_CAP = 4_096;
export const TERMINAL_REPLAY_CAP = 6 * 1024 * 1024;
export const TERMINAL_REPLAY_ROW_CAP = 4_096;

const encoder = new TextEncoder();

/**
 * Blank one viewport into scrollback, then restore the home position expected
 * by the server snapshot. The snapshot is an avt dump for a fresh emulator;
 * replaying it from the bottom row paints its contents there while its final
 * CUP restores the cursor near the top, splitting xterm's text and cursor.
 */
export function snapshotReplayPreamble(rows: number): Uint8Array {
  if (!Number.isSafeInteger(rows) || rows <= 0 || rows > TERMINAL_REPLAY_ROW_CAP) {
    throw new RangeError(`invalid terminal replay row count: ${rows}`);
  }
  return encoder.encode("\r\n".repeat(rows) + "\x1b[H");
}

export type BoundedHistory = {
  lines: string[];
  bytes: number;
  acceptedAll: boolean;
};

/**
 * Prepend older history while keeping the browser-side display cache bounded.
 * `incoming` is oldest-to-newest, so when only part fits we retain its newest
 * suffix: that is the part adjacent to the history already on screen.
 */
export function prependBoundedHistory(
  existing: readonly string[],
  existingBytes: number,
  incoming: readonly string[],
  lineCap = HISTORY_RENDER_LINE_CAP,
  byteCap = HISTORY_RENDER_BYTE_CAP,
): BoundedHistory {
  let bytes = existingBytes;
  let remainingLines = Math.max(0, lineCap - existing.length);
  const accepted: string[] = [];

  for (let index = incoming.length - 1; index >= 0 && remainingLines > 0; index -= 1) {
    const line = incoming[index]!;
    // Include the CRLF used by the replay composition in the byte accounting.
    const lineBytes = encoder.encode(line).length + 2;
    if (bytes + lineBytes > byteCap) break;
    accepted.push(line);
    bytes += lineBytes;
    remainingLines -= 1;
  }
  accepted.reverse();

  return {
    lines: [...accepted, ...existing],
    bytes,
    acceptedAll: accepted.length === incoming.length,
  };
}

/** Concatenate a replay only after proving the allocation is within its cap. */
export function composeBoundedReplay(
  parts: readonly Uint8Array[],
  cap = TERMINAL_REPLAY_CAP,
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

/** Restore the same distance from the bottom after older rows are prepended. */
export function viewportFromBottom(baseY: number, offsetFromBottom: number): number {
  return Math.max(0, baseY - Math.max(0, offsetFromBottom));
}
