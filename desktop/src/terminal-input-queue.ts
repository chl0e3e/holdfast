export const TERMINAL_INPUT_QUEUE_BYTE_CAP = 64 * 1024;
export const TERMINAL_INPUT_QUEUE_CHUNK_CAP = 1_024;

export type InputSender = (data: Uint8Array) => Promise<void>;

/**
 * Serialize desktop input across Tauri IPC and retain it while an attachment
 * is being replaced. An item leaves the queue only after the Rust command has
 * accepted it, so a following detach cannot overtake an earlier keystroke.
 */
export class TerminalInputQueue {
  private readonly queue: Uint8Array[] = [];
  private queuedBytes = 0;
  private paused = true;
  private inFlight: Promise<void> | null = null;

  constructor(
    private readonly send: InputSender,
    private readonly onError: (error: unknown) => void,
    private readonly byteCap = TERMINAL_INPUT_QUEUE_BYTE_CAP,
    private readonly chunkCap = TERMINAL_INPUT_QUEUE_CHUNK_CAP,
  ) {
    if (!Number.isSafeInteger(byteCap) || byteCap <= 0) {
      throw new RangeError(`invalid terminal input byte cap: ${byteCap}`);
    }
    if (!Number.isSafeInteger(chunkCap) || chunkCap <= 0) {
      throw new RangeError(`invalid terminal input chunk cap: ${chunkCap}`);
    }
  }

  /** Queue input in arrival order. False is an explicit, observable reject. */
  enqueue(data: Uint8Array): boolean {
    if (data.length === 0) return true;
    if (
      data.length > this.byteCap - this.queuedBytes ||
      this.queue.length >= this.chunkCap
    ) {
      return false;
    }
    this.queue.push(data);
    this.queuedBytes += data.length;
    this.pump();
    return true;
  }

  pause(): void {
    this.paused = true;
  }

  resume(): void {
    this.paused = false;
    this.pump();
  }

  /** Stop new sends and wait until the currently-started send is accepted. */
  async pauseAndWait(): Promise<void> {
    this.pause();
    await this.inFlight;
  }

  clear(): void {
    this.queue.length = 0;
    this.queuedBytes = 0;
  }

  get pendingBytes(): number {
    return this.queuedBytes;
  }

  get pendingChunks(): number {
    return this.queue.length;
  }

  private pump(): void {
    if (this.paused || this.inFlight !== null) return;
    const data = this.queue[0];
    if (!data) return;

    const operation = this.send(data)
      .then(() => {
        if (this.queue[0] === data) {
          this.queue.shift();
          this.queuedBytes -= data.length;
        }
      })
      .catch((error) => {
        // Retain this item at the head for the replacement attachment.
        this.paused = true;
        this.onError(error);
      })
      .finally(() => {
        if (this.inFlight === operation) this.inFlight = null;
        this.pump();
      });
    this.inFlight = operation;
  }
}
