/** UTF-8 encodings of U+2066 LRI through U+2069 PDI. */
const BIDI_ISOLATE_LEAD = 0xe2;
const BIDI_ISOLATE_SECOND = 0x81;
const BIDI_ISOLATE_MIN_LAST = 0xa6;
const BIDI_ISOLATE_MAX_LAST = 0xa9;

/**
 * Remove bidi isolate controls from complete JavaScript text before xterm.js
 * sees it. Traditional terminal level-1 bidi handling discards these
 * zero-width controls; xterm.js instead attaches each control to one cell and
 * paints cells separately, so an FSI/PDI pair can never reach the browser's
 * text renderer as a pair.
 */
export function stripBidiIsolates(text: string): string {
  return text.replace(/[\u2066-\u2069]/gu, "");
}

/**
 * Streaming form of {@link stripBidiIsolates} for raw PTY bytes.
 *
 * PTY reads and protocol frames may split a three-byte UTF-8 sequence at any
 * boundary. At most two possible prefix bytes are retained between calls;
 * every other byte, including malformed UTF-8, is passed through unchanged.
 */
export class TerminalOutputFilter {
  private pending = new Uint8Array(0);

  reset(): void {
    this.pending = new Uint8Array(0);
  }

  filter(data: Uint8Array): Uint8Array {
    if (data.length === 0) return data;

    const input = new Uint8Array(this.pending.length + data.length);
    input.set(this.pending);
    input.set(data, this.pending.length);
    this.pending = new Uint8Array(0);

    const output = new Uint8Array(input.length);
    let read = 0;
    let written = 0;

    while (read < input.length) {
      if (input[read] === BIDI_ISOLATE_LEAD) {
        if (read + 1 === input.length) break;
        if (input[read + 1] === BIDI_ISOLATE_SECOND) {
          if (read + 2 === input.length) break;
          const last = input[read + 2]!;
          if (last >= BIDI_ISOLATE_MIN_LAST && last <= BIDI_ISOLATE_MAX_LAST) {
            read += 3;
            continue;
          }
        }
      }
      output[written++] = input[read++]!;
    }

    if (read < input.length) this.pending = input.slice(read);
    return output.slice(0, written);
  }
}
