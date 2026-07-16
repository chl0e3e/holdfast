// Unsigned LEB128 varints for the WebSocket channel prefix (spec §2).

export function encodeVarint(value: number): Uint8Array {
  if (value < 0 || !Number.isSafeInteger(value)) {
    throw new Error(`invalid varint value: ${value}`);
  }
  const out: number[] = [];
  let v = value;
  for (;;) {
    const byte = v & 0x7f;
    v = Math.floor(v / 128);
    if (v !== 0) {
      out.push(byte | 0x80);
    } else {
      out.push(byte);
      break;
    }
  }
  return new Uint8Array(out);
}

export function decodeVarint(buf: Uint8Array): [value: number, bytesUsed: number] {
  let value = 0;
  let factor = 1;
  for (let i = 0; i < buf.length && i < 9; i++) {
    const byte = buf[i]!;
    value += (byte & 0x7f) * factor;
    if ((byte & 0x80) === 0) {
      return [value, i + 1];
    }
    factor *= 128;
  }
  throw new Error("truncated varint");
}
