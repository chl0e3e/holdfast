export type TerminalPresentationState = {
  active: boolean;
  closing: boolean;
  width: number;
  height: number;
};

/**
 * Fit and repaint a terminal only while its panel is the visible one.
 *
 * xterm.js deliberately pauses rendering for non-intersecting terminals. On
 * WebView2 an instance that was opened under `display:none`, or whose window
 * was occluded for a while, does not always receive the intersection change
 * that would request xterm's own full refresh. Keeping panels mounted avoids
 * the first half of that failure; this explicit refresh closes the renderer
 * invalidation/window-return half.
 */
export function repaintVisibleTerminal(
  state: TerminalPresentationState,
  fit: () => void,
  rows: () => number,
  refresh: (start: number, end: number) => void,
): boolean {
  if (!state.active || state.closing || state.width <= 0 || state.height <= 0) {
    return false;
  }

  fit();
  const rowCount = rows();
  if (!Number.isInteger(rowCount) || rowCount <= 0) return false;
  refresh(0, rowCount - 1);
  return true;
}
