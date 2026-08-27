export const TERMINAL_INPUT_QUEUE_BYTE_CAP = 64 * 1024;
export const TERMINAL_INPUT_QUEUE_CHUNK_CAP = 1_024;

/** Bounded ordered input retained while a WebTransport attachment rotates. */
export class TerminalInputQueue {
  private readonly queue: Uint8Array[] = [];
  private bytes = 0;
  private paused = true;

  enqueue(data: Uint8Array): boolean {
    if (data.length === 0) return true;
    if (
      data.length > TERMINAL_INPUT_QUEUE_BYTE_CAP - this.bytes ||
      this.queue.length >= TERMINAL_INPUT_QUEUE_CHUNK_CAP
    ) return false;
    this.queue.push(data);
    this.bytes += data.length;
    return true;
  }

  pause(): void {
    this.paused = true;
  }

  resume(send: (data: Uint8Array) => void): void {
    this.paused = false;
    while (!this.paused) {
      const data = this.queue[0];
      if (!data) return;
      try {
        send(data);
      } catch {
        this.paused = true;
        return;
      }
      this.queue.shift();
      this.bytes -= data.length;
    }
  }

  clear(): void {
    this.queue.length = 0;
    this.bytes = 0;
  }

  get pendingBytes(): number {
    return this.bytes;
  }
}
