/// Emoji and character pickers (Windows Win+., the browser's own emoji menu)
/// insert text with an `input` event instead of keystrokes. xterm.js ignores
/// such an insertion whenever it has seen a keydown without a matching keyup
/// — precisely what happens when the picker steals focus mid-chord and the
/// keyup never reaches the page — so the character is silently dropped.
///
/// This tracks whether xterm.js emitted text for the current key action, so
/// the client can forward only what xterm.js declined. The flag must survive
/// from a keystroke into the `input` event that same keystroke produces:
/// xterm.js claims printable keys in `keydown` only for `keyCode >= 48`, so
/// space (32) is handled in `keypress` instead, without preventDefault — the
/// space also lands in the hidden textarea and fires an `input` event *after*
/// onData. Resetting per input event would wipe the flag right there and
/// forward the space a second time. Hence: reset on keydown/keyup (capture
/// phase on an ancestor, which always runs before the textarea's own
/// listeners), record from `Terminal.onData`, then decide — and consume — in
/// a bubble-phase `input` listener on the textarea.
export class InsertedTextForwarder {
  private handledByTerminal = false;

  /// Capture-phase keydown AND keyup hook on an ancestor of the terminal's
  /// hidden textarea. Keyup matters too: it ends the key action, so a later
  /// mouse-only picker insertion is not suppressed by a stale flag.
  beginKeyEvent(): void {
    this.handledByTerminal = false;
  }

  /// Hook for `Terminal.onData` — xterm.js produced this text itself.
  noteTerminalData(): void {
    this.handledByTerminal = true;
  }

  /// The text still needing to be sent, or null when xterm.js already emitted
  /// it — whether during this `input` event or during the keystroke that
  /// produced it. One key action excuses at most one insertion, so the flag
  /// is consumed here; picker insertions with no keystroke at all keep
  /// forwarding. Only plain insertions qualify: composition is xterm.js's own
  /// business, and pastes (`insertFromPaste`) must keep going through the
  /// paste guard.
  pendingInsert(inputType: string, data: string | null | undefined): string | null {
    const handled = this.handledByTerminal;
    this.handledByTerminal = false;
    if (handled) return null;
    if (inputType !== "insertText") return null;
    return data ? data : null;
  }
}
