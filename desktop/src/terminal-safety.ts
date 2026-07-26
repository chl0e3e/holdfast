// Browser-side defenses against hostile terminal output (threat model T9).
//
// Terminal output is attacker-controlled (e.g. `cat`ing a malicious file), so
// anything the client lifts out of the stream into the DOM, the clipboard, or
// back into shell input must be treated as untrusted. These are pure helpers,
// unit-tested in isolation; app.ts wires them into the xterm.js terminal.

/// Max characters we let a terminal-set window title contribute.
export const MAX_TITLE_LEN = 256;
/// Max bytes accepted for a clipboard write requested by the shell (OSC 52).
export const MAX_CLIPBOARD_BYTES = 100 * 1024;

function isControl(code: number): boolean {
  const isC0 = code < 0x20;
  const isDel = code === 0x7f;
  const isC1 = code >= 0x80 && code <= 0x9f;
  return isC0 || isDel || isC1;
}

/// Sanitize an OSC 0/2 title before it is shown anywhere in the DOM: strip C0
/// and C1 control characters (including ESC), collapse whitespace, and cap the
/// length. Prevents a title escape from smuggling markup or control sequences
/// into the page chrome.
export function sanitizeTitle(raw: string): string {
  let out = "";
  for (const ch of raw) {
    const code = ch.codePointAt(0)!;
    // Whitespace-like controls (tab, newline, CR, VT, FF) become a space so
    // words are not silently merged; other controls are dropped entirely.
    if (code === 0x09 || (code >= 0x0a && code <= 0x0d)) out += " ";
    else if (!isControl(code)) out += ch;
  }
  out = out.replace(/\s+/g, " ").trim();
  return out.length > MAX_TITLE_LEN ? out.slice(0, MAX_TITLE_LEN) + "…" : out;
}

/// Unicode format/control code points that are invisible or reorder text, so a
/// pasted command can read differently than it runs (Trojan Source, CVE-2021-
/// 42574) or smuggle a line break past a naive newline check:
///   U+2028/U+2029  line / paragraph separator (newline-equivalent to some shells)
///   U+202A–U+202E  bidi embeddings and overrides (LRE/RLE/PDF/LRO/RLO)
///   U+2066–U+2069  bidi isolates (LRI/RLI/FSI/PDI)
///   U+200B–U+200F  zero-width spaces/joiners and LRM/RLM marks
///   U+FEFF         zero-width no-break space / BOM
function isDangerousFormatChar(code: number): boolean {
  return (
    code === 0x2028 ||
    code === 0x2029 ||
    (code >= 0x202a && code <= 0x202e) ||
    (code >= 0x2066 && code <= 0x2069) ||
    (code >= 0x200b && code <= 0x200f) ||
    code === 0xfeff
  );
}

/// A paste that contains newlines, control characters, or invisible/direction-
/// altering Unicode can execute commands the user did not intend (paste-
/// injection). Callers should confirm before sending such a paste to the shell.
export function pasteNeedsConfirmation(text: string): boolean {
  for (const ch of text) {
    const code = ch.codePointAt(0)!;
    if (code === 0x09) continue; // tab is benign
    if (code === 0x0a || code === 0x0d) return true; // newline / CR
    if (isControl(code)) return true; // other C0 / C1 / DEL
    if (isDangerousFormatChar(code)) return true; // bidi / zero-width / separators
  }
  return false;
}

export type ClipboardDecision =
  | { allow: true; text: string }
  | { allow: false; reason: string };

/// Policy for a shell-initiated clipboard write (OSC 52). Denied unless the
/// feature is explicitly enabled and the terminal is focused, and always
/// size-capped. Clipboard *reads* are never exposed to the shell, so there is
/// no corresponding decode-to-shell path.
export function clipboardWriteDecision(opts: {
  enabled: boolean;
  focused: boolean;
  byteLength: number;
  text: string;
}): ClipboardDecision {
  if (!opts.enabled) return { allow: false, reason: "clipboard writes disabled" };
  if (!opts.focused) return { allow: false, reason: "terminal not focused" };
  if (opts.byteLength > MAX_CLIPBOARD_BYTES) {
    return { allow: false, reason: "clipboard payload too large" };
  }
  return { allow: true, text: opts.text };
}
