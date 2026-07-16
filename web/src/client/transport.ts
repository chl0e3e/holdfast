// Client transports (spec §2). Both speak identical protocol semantics:
// - WebTransport (primary): every bidirectional stream is a channel; the
//   first client-opened stream is control (0). Frames are plain §3
//   length-prefixed envelopes.
// - WebSocket (fallback): one connection; binary message = varint channel
//   prefix + one frame.

import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import type { MessageInitShape } from "@bufbuild/protobuf";
import type { Envelope } from "../gen/messages_pb.js";
import { EnvelopeSchema } from "../gen/messages_pb.js";
import { decodeVarint, encodeVarint } from "./varint.js";

export const MAX_FRAME_BYTES = 256 * 1024;

export type FrameHandler = (channel: number, envelope: Envelope) => void;

export interface HfTransport {
  readonly kind: "webtransport" | "websocket";
  nextRequestId(): bigint;
  /** Allocate a fresh client-initiated channel (control channel 0 exists implicitly). */
  openChannel(): number;
  send(channel: number, envelope: Envelope): void;
  close(): void;
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

// ---------------------------------------------------------------- WebSocket

export class WsTransport implements HfTransport {
  readonly kind = "websocket";
  private ws: WebSocket;
  private nextRequestIdValue = 1n;
  private nextChannelValue = 1; // WS mapping: client channels are odd

  private constructor(ws: WebSocket, onFrame: FrameHandler, onClose: () => void) {
    this.ws = ws;
    ws.binaryType = "arraybuffer";
    ws.onmessage = (event) => {
      const data = new Uint8Array(event.data as ArrayBuffer);
      const [channel, used] = decodeVarint(data);
      const body = data.subarray(used);
      if (body.length < 4) throw new Error("truncated frame");
      const len = new DataView(body.buffer, body.byteOffset).getUint32(0);
      if (len > MAX_FRAME_BYTES) throw new Error(`oversized frame: ${len}`);
      onFrame(channel, fromBinary(EnvelopeSchema, body.subarray(4, 4 + len)));
    };
    ws.onclose = onClose;
    ws.onerror = () => ws.close();
  }

  static connect(url: string, onFrame: FrameHandler, onClose: () => void): Promise<WsTransport> {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(url);
      const transport = new WsTransport(ws, onFrame, onClose);
      ws.addEventListener("open", () => resolve(transport), { once: true });
      ws.addEventListener("error", () => reject(new Error("websocket connect failed")), {
        once: true,
      });
    });
  }

  nextRequestId(): bigint {
    return this.nextRequestIdValue++;
  }

  openChannel(): number {
    const channel = this.nextChannelValue;
    this.nextChannelValue += 2;
    return channel;
  }

  send(channel: number, env: Envelope): void {
    const frame = encodeFrame(env);
    const prefix = encodeVarint(channel);
    const out = new Uint8Array(prefix.length + frame.length);
    out.set(prefix, 0);
    out.set(frame, prefix.length);
    this.ws.send(out);
  }

  close(): void {
    this.ws.onclose = null;
    this.ws.close();
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
    certHashBase64: string,
    onFrame: FrameHandler,
    onClose: () => void,
  ): Promise<WtTransport> {
    const hash = Uint8Array.from(atob(certHashBase64), (c) => c.charCodeAt(0));
    const session = new WebTransport(url, {
      serverCertificateHashes: [{ algorithm: "sha-256", value: hash.buffer }],
    });
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

export async function connectTransport(
  onFrame: FrameHandler,
  onClose: () => void,
): Promise<HfTransport> {
  if ("WebTransport" in window) {
    try {
      const response = await fetch("/webtransport-info");
      if (response.ok) {
        const info = (await response.json()) as { port: number; certHashBase64: string };
        const url = `https://${location.hostname}:${info.port}/`;
        const wt = await withTimeout(
          WtTransport.connect(url, info.certHashBase64, onFrame, onClose),
          3000,
        );
        return wt;
      }
    } catch {
      // Fall through to WebSocket — fallback is a product feature (spec §2).
    }
  }
  const wsUrl = `${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/terminal/ws`;
  return WsTransport.connect(wsUrl, onFrame, onClose);
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return Promise.race([
    promise,
    new Promise<T>((_, reject) =>
      setTimeout(() => reject(new Error("webtransport connect timeout")), ms),
    ),
  ]);
}
