/// Emoji and character pickers (Windows Win+., the browser's own emoji menu)
/// insert text with an `input` event instead of keystrokes. xterm.js ignores
/// such an insertion whenever it has seen a keydown without a matching keyup
/// — precisely what happens when the picker steals focus mid-chord and the
/// keyup never reaches the page — so the character is silently dropped.
///
/// This tracks, per `input` event, whether xterm.js emitted the text itself,
/// so the client can forward only what xterm.js declined. It deliberately
/// avoids timing heuristics: reset in the capture phase on an ancestor (which
/// always runs before the textarea's own listeners), record from
/// `Terminal.onData`, then decide in a bubble-phase listener on the textarea.
export class InsertedTextForwarder {
  private handledByTerminal = false;

  /// Capture-phase hook on an ancestor of the terminal's hidden textarea.
  beginInputEvent(): void {
    this.handledByTerminal = false;
  }

  /// Hook for `Terminal.onData` — xterm.js produced this text itself.
  noteTerminalData(): void {
    this.handledByTerminal = true;
  }

  /// The text still needing to be sent, or null when xterm.js handled it.
  /// Only plain insertions qualify: composition is xterm.js's own business,
  /// and pastes (`insertFromPaste`) must keep going through the paste guard.
  pendingInsert(inputType: string, data: string | null | undefined): string | null {
    if (this.handledByTerminal) return null;
    if (inputType !== "insertText") return null;
    return data ? data : null;
  }
}
