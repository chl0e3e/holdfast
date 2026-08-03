// One persisted terminal font size, shared by every tab. xterm.js draws
// emoji at cell size, so the only way to make them readable is a bigger
// font — there is no separate emoji scale.

const STORAGE_KEY = "holdfast.fontsize.v1";
export const FONT_SIZE_DEFAULT = 14;
const FONT_SIZE_MIN = 8;
const FONT_SIZE_MAX = 40;

type StorageLike = Pick<Storage, "getItem" | "setItem">;

export function clampFontSize(size: number): number {
  if (!Number.isFinite(size)) return FONT_SIZE_DEFAULT;
  return Math.min(FONT_SIZE_MAX, Math.max(FONT_SIZE_MIN, Math.round(size)));
}

export function loadFontSize(storage: StorageLike = localStorage): number {
  const raw = storage.getItem(STORAGE_KEY);
  if (raw === null) return FONT_SIZE_DEFAULT;
  return clampFontSize(Number(raw));
}

export function saveFontSize(size: number, storage: StorageLike = localStorage): void {
  storage.setItem(STORAGE_KEY, String(size));
}
