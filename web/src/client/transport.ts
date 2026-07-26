// Client transport (spec §2, ADR 0014): WebTransport over HTTP/3, only.
// Every bidirectional stream is a channel; the first client-opened stream is
// control (0). Frames are plain §3 length-prefixed envelopes. There is no
// TCP fallback — when QUIC is unreachable the app says so and retries.

import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import type { MessageInitShape } from "@bufbuild/protobuf";
import type { Envelope } from "../gen/messages_pb.js";
import { EnvelopeSchema } from "../gen/messages_pb.js";

export const MAX_FRAME_BYTES = 256 * 1024;

export type FrameHandler = (channel: number, envelope: Envelope) => void;

export interface HfTransport {
  readonly kind: "webtransport";
  nextRequestId(): bigint;
  /** Allocate a fresh client-initiated channel (control channel 0 exists implicitly). */
  openChannel(): number;
  send(channel: number, envelope: Envelope): void;
  close(): void;
}

export function webTransportCertificateOptions(
  certHashBase64: string | null,
): WebTransportOptions | undefined {
  if (!certHashBase64) return undefined;
  return {
    serverCertificateHashes: [
      {
        algorithm: "sha-256",
        value: Uint8Array.from(atob(certHashBase64), (c) => c.charCodeAt(0)).buffer,
      },
    ],
  };
}

export function envelope(init: MessageInitShape<typeof EnvelopeSchema>): Envelope {
  return create(EnvelopeSchema, init);
}

function encodeFrame(env: Envelope): Uint8Array {
  const payload = toBinary(EnvelopeSchema, env);
  if (payload.length > MAX_FRAME_BYTES) throw new Error("frame too large");
  const out = new Uint8Array(4 + payload.length);
  new DataView(out.buffer).setUint32(0, payload.length);
  out.set(payload, 4);
  return out;
}

/** Incremental §3 frame parser for stream-oriented transports. */
class FrameParser {
  private buf = new Uint8Array(0);

  feed(data: Uint8Array): Envelope[] {
    const merged = new Uint8Array(this.buf.length + data.length);
    merged.set(this.buf, 0);
    merged.set(data, this.buf.length);
    this.buf = merged;

    const frames: Envelope[] = [];
    for (;;) {
      if (this.buf.length < 4) break;
      const len = new DataView(this.buf.buffer, this.buf.byteOffset).getUint32(0);
      if (len > MAX_FRAME_BYTES) throw new Error(`oversized frame: ${len}`);
      if (this.buf.length < 4 + len) break;
      frames.push(fromBinary(EnvelopeSchema, this.buf.subarray(4, 4 + len)));
      this.buf = this.buf.subarray(4 + len);
    }
    return frames;
  }
}

// ------------------------------------------------------------- WebTransport

type WtChannel = {
  writer: WritableStreamDefaultWriter<Uint8Array> | null;
  queue: Uint8Array[];
};

export class WtTransport implements HfTransport {
  readonly kind = "webtransport";
  private session: WebTransport;
  private nextRequestIdValue = 1n;
  private nextChannelValue = 1;
  private channels = new Map<number, WtChannel>();
  private onFrame: FrameHandler;

  private constructor(session: WebTransport, onFrame: FrameHandler) {
    this.session = session;
    this.onFrame = onFrame;
  }

  static async connect(
    url: string,
    certHashBase64: string | null,
    onFrame: FrameHandler,
    onClose: () => void,
  ): Promise<WtTransport> {
    const options = webTransportCertificateOptions(certHashBase64);
    const session = new WebTransport(url, options);
    await session.ready;
    session.closed.then(onClose, onClose);
    const transport = new WtTransport(session, onFrame);
    // Control channel = the first client-opened bidirectional stream.
    transport.startChannel(0);
    return transport;
  }

  nextRequestId(): bigint {
    return this.nextRequestIdValue++;
  }

  openChannel(): number {
    const channel = this.nextChannelValue++;
    this.startChannel(channel);
    return channel;
  }

  private startChannel(channel: number): void {
    const entry: WtChannel = { writer: null, queue: [] };
    this.channels.set(channel, entry);
    void (async () => {
      try {
        const stream = await this.session.createBidirectionalStream();
        const writer = stream.writable.getWriter();
        entry.writer = writer;
        for (const queued of entry.queue.splice(0)) await writer.write(queued);

        const parser = new FrameParser();
        const reader = stream.readable.getReader();
        for (;;) {
          const { value, done } = await reader.read();
          if (done) break;
          for (const env of parser.feed(value)) this.onFrame(channel, env);
        }
      } catch {
        // Stream failure: surface as channel silence; connection-level
        // failures arrive via session.closed.
      }
    })();
  }

  send(channel: number, env: Envelope): void {
    const entry = this.channels.get(channel);
    if (!entry) throw new Error(`unknown channel ${channel}`);
    const frame = encodeFrame(env);
    if (entry.writer) {
      void entry.writer.write(frame);
    } else {
      entry.queue.push(frame); // stream still opening
    }
  }

  close(): void {
    try {
      this.session.close();
    } catch {
      /* already closed */
    }
  }
}

// ------------------------------------------------------------- negotiation

/// QUIC (WebTransport) could not be reached. There is no fallback (ADR
/// 0014): the app surfaces this as a "QUIC required" state and retries.
export class QuicUnavailableError extends Error {
  constructor(reason: string) {
    super(`QUIC (WebTransport) unavailable: ${reason}`);
    this.name = "QuicUnavailableError";
  }
}

export async function connectTransport(
  onFrame: FrameHandler,
  onClose: () => void,
): Promise<HfTransport> {
  if (!("WebTransport" in window)) {
    throw new QuicUnavailableError("this browser does not support WebTransport");
  }
  try {
    const response = await fetch("/webtransport-info");
    if (!response.ok) {
      throw new Error(`webtransport-info: HTTP ${response.status}`);
    }
    const info = (await response.json()) as {
      port: number;
      certHashBase64: string;
      certificateMode: "hash-pin" | "webpki";
    };
    const url = `https://${location.hostname}:${info.port}/`;
    return await withTimeout(
      WtTransport.connect(
        url,
        info.certificateMode === "hash-pin" ? info.certHashBase64 : null,
        onFrame,
        onClose,
      ),
      3000,
    );
  } catch (error) {
    throw new QuicUnavailableError(
      error instanceof Error ? error.message : String(error),
    );
  }
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) =>
      setTimeout(() => reject(new Error("webtransport connect timeout")), ms),
    ),
  ]);
}
