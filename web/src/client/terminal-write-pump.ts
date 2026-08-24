export const TERMINAL_WRITE_QUEUE_CAP = 256 * 1024;
export const TERMINAL_WRITE_QUEUE_CHUNK_CAP = 256;

type WriteItem = {
  data: Uint8Array;
  before?: () => void;
  after?: () => void;
  live: boolean;
};

export type TerminalWrite = (data: Uint8Array, complete: () => void) => void;

/**
 * Keep xterm.js's asynchronous parser queue bounded and observable.
 *
 * Only one write is handed to xterm at a time. Live writes count against both
 * byte and message bounds; an authoritative replay replaces every queued item
 * and runs only after the current parser write completes. Once overloaded, no
 * more live bytes are accepted until a replay resets the pump.
 */
export class TerminalWritePump {
  private readonly queue: WriteItem[] = [];
  private queuedLiveBytes = 0;
  private queuedLiveChunks = 0;
  private inFlight = false;
  private overloaded = false;

  constructor(
    private readonly write: TerminalWrite,
    private readonly onOverload: () => void,
    private readonly byteCap = TERMINAL_WRITE_QUEUE_CAP,
    private readonly chunkCap = TERMINAL_WRITE_QUEUE_CHUNK_CAP,
  ) {
    if (!Number.isSafeInteger(byteCap) || byteCap <= 0) {
      throw new RangeError(`invalid terminal write byte cap: ${byteCap}`);
    }
    if (!Number.isSafeInteger(chunkCap) || chunkCap <= 0) {
      throw new RangeError(`invalid terminal write chunk cap: ${chunkCap}`);
    }
  }

  /** Queue live output, or signal that a fresh server snapshot is required. */
  enqueue(data: Uint8Array): boolean {
    if (data.length === 0) return !this.overloaded;
    if (this.overloaded) return false;
    if (
      data.length > this.byteCap - this.queuedLiveBytes ||
      this.queuedLiveChunks >= this.chunkCap
    ) {
      this.queue.length = 0;
      this.queuedLiveBytes = 0;
      this.queuedLiveChunks = 0;
      this.overloaded = true;
      this.onOverload();
      return false;
    }
    this.queue.push({ data, live: true });
    this.queuedLiveBytes += data.length;
    this.queuedLiveChunks += 1;
    this.pump();
    return true;
  }

  /**
   * Replace queued presentation work with one authoritative replay. The replay
   * itself is bounded by the caller independently from the smaller live queue.
   */
  replace(data: Uint8Array, before: () => void, after: () => void): void {
    this.queue.length = 0;
    this.queuedLiveBytes = 0;
    this.queuedLiveChunks = 0;
    this.overloaded = false;
    this.queue.push({ data, before, after, live: false });
    this.pump();
  }

  get pendingLiveBytes(): number {
    return this.queuedLiveBytes;
  }

  get pendingLiveChunks(): number {
    return this.queuedLiveChunks;
  }

  private pump(): void {
    if (this.inFlight) return;
    const item = this.queue.shift();
    if (!item) return;
    if (item.live) {
      this.queuedLiveBytes -= item.data.length;
      this.queuedLiveChunks -= 1;
    }
    item.before?.();
    this.inFlight = true;
    this.write(item.data, () => {
      this.inFlight = false;
      item.after?.();
      this.pump();
    });
  }
}
