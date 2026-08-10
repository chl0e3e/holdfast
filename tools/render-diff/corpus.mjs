// Shared corpus for the render differential harness.
//
// One case = a name, a category, and the exact bytes a PTY would emit. Both
// sides of the harness consume this same list, so the server model and
// xterm.js are always fed byte-identical input:
//
//   corpus.mjs --(gen-corpus.mjs)--> corpus.tsv --> modelgrid.rs  --> model.tsv
//                                             \--> xterm-diff.mjs --> report
//
// Cases are deliberately small and single-purpose: when one fails, the name
// alone should say what broke. Anything that needs a real application in the
// loop (weechat's own redraw logic) belongs in the live probe instead.

const ESC = "\x1b";
const CSI = `${ESC}[`;
const OSC = `${ESC}]`;
const ST = `${ESC}\\`;
const BEL = "\x07";
const DCS = `${ESC}P`;

/// Cases are written as parts: JS strings are UTF-8 encoded, number arrays are
/// taken as raw bytes (so we can emit sequences that are not valid UTF-8).
function bytes(...parts) {
  const chunks = [];
  for (const part of parts) {
    if (typeof part === "string") chunks.push(new TextEncoder().encode(part));
    else chunks.push(Uint8Array.from(part));
  }
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.length;
  }
  return out;
}

const cases = [];
/// `flags.bounded: <why>` marks a case whose divergence is a DELIBERATE bound
/// rather than a defect (the model caps some untrusted-input structure that
/// xterm.js leaves unbounded). Those are reported separately, never hidden.
function add(category, name, flags, ...parts) {
  cases.push({ category, name, flags, bytes: bytes(...parts) });
}

// ---------------------------------------------------------------------------
// A. Unicode width, composition and grapheme clustering
//
// Every past shearing bug in this project was a width disagreement between
// avt (server) and xterm.js (client), so this section is the densest.
// ---------------------------------------------------------------------------

add("unicode", "ascii-baseline", {}, "hello world\r\n");
add("unicode", "combining-acute-x60", {}, "é".repeat(60), "END\r\n");
add("unicode", "combining-acute-single", {}, "[é]\r\n");
add("unicode", "zalgo-stack-8", {}, "à́̂̃̄̅̆̇b\r\n");
add("unicode", "zalgo-stack-64", { bounded: "64 marks exceeds MAX_ZERO_WIDTH (8)" }, "a" + "́".repeat(64) + "b\r\n");
add("unicode", "cjk-wide", {}, "你好世界\r\n");
add("unicode", "cjk-wide-fill-row", {}, "漢".repeat(40), "\r\n");
// A wide glyph that cannot fit in the last column: terminals wrap it whole.
add("unicode", "wide-at-last-column", {}, "x".repeat(79), "漢", "END\r\n");
add("unicode", "wide-at-column-78", {}, "x".repeat(78), "漢", "END\r\n");
add("unicode", "hangul-precomposed", {}, "한국어\r\n");
add("unicode", "hangul-conjoining-jamo", {}, "각\r\n");
add("unicode", "emoji-bmp-text", {}, "[☺]\r\n");
add("unicode", "emoji-bmp-vs16", {}, "[☺️]\r\n");
add("unicode", "emoji-bmp-vs15", {}, "[⚠︎]\r\n");
add("unicode", "emoji-astral", {}, "[\u{1f600}]\r\n");
// Post-Unicode-11 additions: the exact class that shipped broken in v0.0.6.
add("unicode", "emoji-post-u11-melting", {}, "[\u{1fae0}]\r\n");
add("unicode", "emoji-post-u11-blueberry", {}, "[\u{1fad0}]\r\n");
add("unicode", "emoji-post-u13-heart-hands", {}, "[\u{1faf6}]\r\n");
add("unicode", "emoji-zwj-family", {}, "[\u{1f468}‍\u{1f469}‍\u{1f467}‍\u{1f466}]\r\n");
add("unicode", "emoji-zwj-profession", {}, "[\u{1f469}‍\u{1f4bb}]\r\n");
add("unicode", "emoji-zwj-with-vs16", {}, "[❤️‍\u{1f525}]\r\n");
add("unicode", "emoji-skin-tone", {}, "[\u{1f44d}\u{1f3fd}]\r\n");
add("unicode", "emoji-keycap", {}, "[1️⃣]\r\n");
add("unicode", "emoji-flag-regional", {}, "[\u{1f1ec}\u{1f1e7}]\r\n");
add("unicode", "emoji-flag-tag-sequence", {}, "[\u{1f3f4}\u{e0067}\u{e0062}\u{e0073}\u{e0063}\u{e0074}\u{e007f}]\r\n");
add("unicode", "emoji-run-fills-row", {}, "\u{1f600}".repeat(40), "\r\n");
add("unicode", "soft-hyphen", {}, "[a­b]\r\n");
add("unicode", "zero-width-space", {}, "[a​b]\r\n");
add("unicode", "zero-width-non-joiner", {}, "[a‌b]\r\n");
add("unicode", "zero-width-joiner-bare", {}, "[a‍b]\r\n");
add("unicode", "word-joiner", {}, "[a⁠b]\r\n");
add("unicode", "bom-mid-stream", { bounded: "zero-width U+FEFF kept by the model's text extraction, dropped by xterm.js; no grid difference" }, "[a﻿b]\r\n");
// Bidi isolates as emitted by IRC title bots (a real "[YouTube] ⁨Title⁩" line
// from a live weechat log). Zero-width in glibc, unicode-width and xterm.js
// alike, but they sit mid-line exactly where weechat then wraps.
add("unicode", "bidi-isolate-youtube-line", {},
  "[YouTube] \u2068Donny Ben\u00e9t - Konichiwa (Official Music Video)\u2069 | 4m 41s"
  + " | Channel: \u2068Donny Ben\u00e9t\u2069 | 2,115,527 views | 48,669 likes"
  + " | 2017-08-31 - 22:00:01 UTC\r\n");
add("unicode", "bidi-isolate-after-wrap", {}, "x".repeat(80), "\u2068abc\u2069\r\n");
add("unicode", "bidi-isolate-run", {}, "a\u2068\u2069".repeat(40), "END\r\n");
add("unicode", "bidi-isolate-at-col0",
  { bounded: "orphan zero-width character: xterm.js gives it a width-0 cell, the model has no base to attach it to — identical on screen, differs only in extracted text" },
  "\u2068abc\u2069\r\n");

add("unicode", "rtl-arabic", {}, "[مرحبا]\r\n");
add("unicode", "rtl-hebrew", {}, "[שלום]\r\n");
add("unicode", "rtl-override-spoof", {}, "[a‮b‬c]\r\n");
add("unicode", "bidi-isolates", {}, "[⁦abc⁩]\r\n");
add("unicode", "combining-enclosing-keycap", {}, "[a⃣]\r\n");
add("unicode", "devanagari-cluster", {}, "[क्ष]\r\n");
add("unicode", "thai-combining", {}, "[กุ้]\r\n");
add("unicode", "ambiguous-width-punct", {}, "[‘q’ ± ° —]\r\n");
add("unicode", "box-drawing", {}, "┌─┐│└┴┘┼\r\n");
add("unicode", "block-elements", {}, "█▓▒░▌▐\r\n");
add("unicode", "braille-spinner", {}, "⠁⠉⠙⠹⠸⠼\r\n");
add("unicode", "powerline-private-use", {}, "\r\n");
add("unicode", "nerdfont-private-use", {}, "[  ]\r\n");
add("unicode", "variation-selector-on-cjk", {}, "[辻︀]\r\n");
add("unicode", "tab-in-text", {}, "a\tb\tc\r\n");
add("unicode", "long-grapheme-cluster", { bounded: "200 marks exceeds MAX_ZERO_WIDTH (8)" }, "[e" + "́".repeat(200) + "]\r\n");

// Malformed byte sequences: the model decodes incrementally (utf8.rs) and
// xterm.js has its own decoder; both must land on the same U+FFFD count.
add("unicode", "invalid-utf8-lone-continuation", {}, "[", [0x80, 0x81], "]\r\n");
add("unicode", "invalid-utf8-truncated-3byte", {}, "[", [0xe4, 0xbd], "]\r\n");
add("unicode", "invalid-utf8-overlong-slash", {}, "[", [0xc0, 0xaf], "]\r\n");
add("unicode", "invalid-utf8-surrogate-cesu", {}, "[", [0xed, 0xa0, 0x80], "]\r\n");
add("unicode", "invalid-utf8-ff-fe", {}, "[", [0xff, 0xfe], "]\r\n");
add("unicode", "invalid-utf8-5byte", {}, "[", [0xf8, 0x88, 0x80, 0x80, 0x80], "]\r\n");
add("unicode", "nul-and-c0-in-text", {}, "[a", [0x00], "b", [0x01, 0x06], "c]\r\n");
add("unicode", "del-byte-in-text", { bounded: "DEL kept by the model's text extraction, dropped by xterm.js; no grid difference" }, "[a", [0x7f], "b]\r\n");

// ---------------------------------------------------------------------------
// B. CSI / SGR — colour and attribute handling
//
// Colour matters here beyond "does it crash": the attach snapshot has to
// reproduce every attribute, or reattaching an IRC window loses its colours.
// ---------------------------------------------------------------------------

add("sgr", "basic-8-fg", {}, ...Array.from({ length: 8 }, (_, i) => `${CSI}3${i}mfg${i} `), `${CSI}0m\r\n`);
add("sgr", "basic-8-bg", {}, ...Array.from({ length: 8 }, (_, i) => `${CSI}4${i}mbg${i} `), `${CSI}0m\r\n`);
add("sgr", "bright-fg", {}, ...Array.from({ length: 8 }, (_, i) => `${CSI}9${i}mbr${i} `), `${CSI}0m\r\n`);
add("sgr", "bright-bg", {}, ...Array.from({ length: 8 }, (_, i) => `${CSI}10${i}mbb${i} `), `${CSI}0m\r\n`);
add("sgr", "indexed-256-fg-sample", {}, ...[0, 1, 15, 16, 51, 128, 196, 231, 232, 255].map((n) => `${CSI}38;5;${n}mc${n} `), `${CSI}0m\r\n`);
add("sgr", "indexed-256-bg-sample", {}, ...[0, 16, 100, 200, 255].map((n) => `${CSI}48;5;${n}mB${n} `), `${CSI}0m\r\n`);
add("sgr", "truecolor-fg", {}, `${CSI}38;2;255;100;0mORANGE${CSI}0m\r\n`);
add("sgr", "truecolor-bg", {}, `${CSI}48;2;0;80;160mBLUEBG${CSI}0m\r\n`);
add("sgr", "truecolor-colon-form", {}, `${CSI}38:2::255:100:0mCOLON${CSI}0m\r\n`);
add("sgr", "truecolor-colon-nospace", { bounded: "ambiguous 4-subparam colon form; xterm.js reads R as the colour-space id, the model normalises it" }, `${CSI}38:2:255:100:0mCOLON2${CSI}0m\r\n`);
add("sgr", "attrs-each", {}, `${CSI}1mB${CSI}22m ${CSI}2mD${CSI}22m ${CSI}3mI${CSI}23m ${CSI}4mU${CSI}24m ${CSI}5mK${CSI}25m ${CSI}7mR${CSI}27m ${CSI}8mH${CSI}28m ${CSI}9mS${CSI}29m\r\n`);
add("sgr", "underline-styles", {}, ...[1, 2, 3, 4, 5].map((n) => `${CSI}4:${n}mU${n}${CSI}4:0m `), `${CSI}0m\r\n`);
add("sgr", "underline-colour", {}, `${CSI}4m${CSI}58;5;196mUCOL${CSI}59m${CSI}0m\r\n`);
add("sgr", "underline-colour-rgb", {}, `${CSI}4m${CSI}58;2;0;255;0mUCOLRGB${CSI}0m\r\n`);
add("sgr", "reset-empty-param", {}, `${CSI}1;31mBOLDRED${CSI}mPLAIN\r\n`);
add("sgr", "reset-implicit", {}, `${CSI}1;31mBOLDRED${CSI}0mPLAIN\r\n`);
add("sgr", "combined-nesting", {}, `${CSI}1m${CSI}4m${CSI}31mB+U+RED${CSI}24mB+RED${CSI}22mRED${CSI}0mPLAIN\r\n`);
add("sgr", "many-params", {}, `${CSI}0;1;3;4;7;31;46mALL${CSI}0m\r\n`);
add("sgr", "unknown-param", {}, `${CSI}1;99;31mUNKNOWN99${CSI}0m\r\n`);
add("sgr", "huge-param-overflow", {}, `${CSI}99999999999mOVERFLOW${CSI}0m\r\n`);
add("sgr", "empty-params-run", {}, `${CSI};;;mEMPTY${CSI}0m\r\n`);
add("sgr", "default-fg-bg-39-49", {}, `${CSI}31;42mCOL${CSI}39mDEFFG${CSI}49mDEFBG\r\n`);
add("sgr", "colour-then-newline-fill", {}, `${CSI}41mRED-BG-LINE${CSI}0m\r\n`);
add("sgr", "bg-colour-erase-to-eol", {}, `${CSI}44mBLUE${CSI}K${CSI}0m\r\n`);

// ---------------------------------------------------------------------------
// C. CSI — cursor, editing, scrolling, modes
// ---------------------------------------------------------------------------

add("csi", "cursor-moves", {}, "line1\r\nline2\r\nline3", `${CSI}2A`, `${CSI}3C`, "X", `${CSI}2B`, "Y\r\n");
add("csi", "cursor-position-cup", {}, `${CSI}2J`, `${CSI}5;10HAT-5-10`, `${CSI}1;1HTOP\r\n`);
add("csi", "cursor-hvp", {}, `${CSI}2J`, `${CSI}3;3fHVP\r\n`);
add("csi", "cursor-cha-vpa", {}, "abcdef", `${CSI}3G`, "X", `${CSI}5d`, "Y\r\n");
add("csi", "cursor-next-prev-line", {}, "a\r\nb\r\nc", `${CSI}2F`, "P", `${CSI}2E`, "N\r\n");
add("csi", "cursor-clamp-out-of-range", {}, `${CSI}999;999HEDGE\r\n`);
add("csi", "erase-display-modes", {}, "keep\r\nmid\r\nend", `${CSI}2;1H`, `${CSI}0J`, "AFTER\r\n");
add("csi", "erase-display-scrollback-3j", {}, "old\r\n".repeat(5), `${CSI}3J`, "AFTER\r\n");
add("csi", "erase-line-modes", {}, "abcdefghij", `${CSI}5G`, `${CSI}1K`, `${CSI}20G`, "Z\r\n");
add("csi", "insert-delete-lines", {}, "L1\r\nL2\r\nL3", `${CSI}2;1H`, `${CSI}1L`, "NEW", `${CSI}4;1H`, `${CSI}1M`, "\r\n");
add("csi", "insert-delete-chars", {}, "abcdef", `${CSI}3G`, `${CSI}2@`, `${CSI}1G`, `${CSI}2P`, "\r\n");
add("csi", "erase-chars-ech", {}, "abcdefghij", `${CSI}3G`, `${CSI}4X`, "\r\n");
add("csi", "repeat-rep", {}, "x", `${CSI}30b`, "END\r\n");
add("csi", "repeat-rep-after-wide", {}, "漢", `${CSI}10b`, "END\r\n");
add("csi", "repeat-rep-after-combining", {}, "é", `${CSI}10b`, "END\r\n");
add("csi", "scroll-up-down", {}, "1\r\n2\r\n3\r\n4\r\n", `${CSI}2S`, `${CSI}1T`, "AFTER\r\n");
add("csi", "scroll-region-decstbm", {}, `${CSI}2J`, `${CSI}5;10r`, `${CSI}10;1H`, "in-region\r\n".repeat(8), `${CSI}r`, "AFTER\r\n");
add("csi", "scroll-region-with-colour", {}, `${CSI}3;6r`, `${CSI}6;1H`, `${CSI}42m`, "green\r\n".repeat(5), `${CSI}0m${CSI}r`, "\r\n");
add("csi", "left-right-margins", {}, `${CSI}?69h`, `${CSI}10;40s`, `${CSI}5;12H`, "MARGINED", `${CSI}?69l`, `${CSI}r`, "\r\n");
add("csi", "save-restore-cursor-decsc", {}, "abc", `${ESC}7`, `${CSI}10;10H`, "far", `${ESC}8`, "BACK\r\n");
add("csi", "save-restore-cursor-csi", {}, "abc", `${CSI}s`, `${CSI}10;10H`, "far", `${CSI}u`, "BACK\r\n");
add("csi", "save-restore-keeps-sgr", {}, `${CSI}31m`, `${ESC}7`, `${CSI}0m`, "plain", `${ESC}8`, "RED?\r\n");
add("csi", "autowrap-off", {}, `${CSI}?7l`, "x".repeat(100), `${CSI}?7h`, "\r\nAFTER\r\n");
add("csi", "autowrap-on-exact-fill", {}, "x".repeat(80), "WRAPPED\r\n");
add("csi", "insert-mode-irm", {}, "abcdef", `${CSI}1G`, `${CSI}4h`, "XY", `${CSI}4l`, "\r\n");
add("csi", "origin-mode-decom", {}, `${CSI}5;10r`, `${CSI}?6h`, `${CSI}1;1H`, "ORIGIN", `${CSI}?6l`, `${CSI}r`, "\r\n");
add("csi", "tab-stops", {}, `${CSI}3g`, "a", `${ESC}H`, "\r\n", "x\ty\tz\r\n");
add("csi", "tab-forward-backward", {}, "a\tb", `${CSI}2Z`, "Z", `${CSI}3I`, "F\r\n");
add("csi", "reverse-index-ri", {}, "top\r\nsecond", `${ESC}M`, `${ESC}M`, "RI\r\n");
add("csi", "index-nel", {}, "a", `${ESC}D`, "b", `${ESC}E`, "c\r\n");
add("csi", "decaln", {}, `${ESC}#8`);
add("csi", "double-width-line", {}, `${ESC}#6`, "DOUBLE-WIDTH\r\n", `${ESC}#5`, "single\r\n");
add("csi", "double-height-line", {}, `${ESC}#3`, "TOP\r\n", `${ESC}#4`, "BOTTOM\r\n", `${ESC}#5`, "\r\n");
add("csi", "cursor-visibility", {}, `${CSI}?25l`, "hidden-cursor", `${CSI}?25h`, "\r\n");
add("csi", "cursor-shape-decscusr", {}, `${CSI}5 q`, "bar-cursor", `${CSI}0 q`, "\r\n");
add("csi", "window-ops-ignored", {}, `${CSI}18t`, `${CSI}22;0t`, "AFTER-WINOPS\r\n");
add("csi", "soft-reset-decstr", {}, `${CSI}31m${CSI}4h`, `${CSI}!p`, "AFTER-SOFT-RESET\r\n");
add("csi", "full-reset-ris", {}, `${CSI}31m`, "before", `${ESC}c`, "AFTER-RIS\r\n");
add("csi", "unterminated-csi-then-text", {}, `${CSI}1;2;3`, "TEXTAFTER\r\n");
add("csi", "csi-with-intermediates", {}, `${CSI}?1;2$pAFTER\r\n`);
add("csi", "huge-param-count", {}, `${CSI}` + "1;".repeat(40) + "mAFTER", `${CSI}0m\r\n`);
add("csi", "c1-8bit-csi", {}, "[", [0x9b], "31m", "RED-VIA-C1", [0x9b], "0m]\r\n");
add("csi", "esc-only-then-text", {}, `${ESC}`, "AFTER-BARE-ESC\r\n");

// Alternate screen: the snapshot has to restore whichever screen is active.
add("altscreen", "alt-1049-enter-exit", {}, "primary\r\n", `${CSI}?1049h`, `${CSI}2J${CSI}1;1H`, "ALTERNATE", `${CSI}?1049l`, "\r\nback\r\n");
add("altscreen", "alt-1049-stay-in-alt", {}, "primary\r\n", `${CSI}?1049h`, `${CSI}2J${CSI}1;1H`, "STILL-IN-ALT\r\n");
add("altscreen", "alt-47-legacy", {}, "primary\r\n", `${CSI}?47h`, "LEGACY-ALT\r\n");
add("altscreen", "alt-1047-1048", {}, "primary\r\n", `${CSI}?1048h${CSI}?1047h`, "ALT-1047\r\n");
add("altscreen", "alt-with-colour-and-region", {}, `${CSI}?1049h`, `${CSI}2J`, `${CSI}44m`, `${CSI}3;10r`, `${CSI}1;1H`, "ALT-COLOURED\r\n");

// Input-encoding modes: avt's dump drops these, so modes.rs replays them.
// A divergence here silently breaks mouse/paste in weechat after reattach.
add("modes", "mouse-1000", {}, `${CSI}?1000h`, "mouse-click-tracking\r\n");
add("modes", "mouse-1002-1006", {}, `${CSI}?1002h${CSI}?1006h`, "mouse-drag-sgr\r\n");
add("modes", "mouse-1003-1015", {}, `${CSI}?1003h${CSI}?1015h`, "mouse-any-urxvt\r\n");
add("modes", "mouse-1005-utf8", {}, `${CSI}?1005h`, "mouse-utf8\r\n");
add("modes", "mouse-set-then-unset", {}, `${CSI}?1002h`, "on", `${CSI}?1002l`, "off\r\n");
add("modes", "bracketed-paste", {}, `${CSI}?2004h`, "bracketed-paste-on\r\n");
add("modes", "app-cursor-keys-decckm", {}, `${CSI}?1h`, "app-cursor-keys\r\n");
add("modes", "app-keypad-deckpam", {}, `${ESC}=`, "app-keypad\r\n");
add("modes", "focus-events-1004", {}, `${CSI}?1004h`, "focus-events\r\n");
add("modes", "synchronised-output-2026", {}, `${CSI}?2026h`, "sync-begin", `${CSI}?2026l`, "sync-end\r\n");
add("modes", "modes-combo-weechat-like", {}, `${CSI}?1049h${CSI}?1002h${CSI}?1006h${CSI}?2004h${CSI}?25l`, "weechat-mode-set\r\n");

// Charsets: `ESC ( 0` + SI/SO is how older curses apps draw lines.
add("charset", "dec-special-graphics", {}, `${ESC}(0`, "lqqqk", `${ESC}(B`, "\r\n");
add("charset", "so-si-shift", {}, `${ESC})0`, "\x0elqqqk\x0f", "ascii\r\n");
add("charset", "charset-then-utf8", {}, `${ESC}(0`, "lqk", `${ESC}(B`, "──\r\n");

// ---------------------------------------------------------------------------
// D. OSC / DCS / other string sequences
//
// The dangerous ones are unterminated strings: a terminal that keeps
// swallowing output eats the rest of the screen.
// ---------------------------------------------------------------------------

add("osc", "title-osc0-bel", {}, `${OSC}0;window title${BEL}`, "after-title\r\n");
add("osc", "title-osc2-st", {}, `${OSC}2;another title${ST}`, "after-title2\r\n");
add("osc", "title-osc1-icon", {}, `${OSC}1;icon name${BEL}`, "after-icon\r\n");
add("osc", "title-with-utf8", {}, `${OSC}2;\u{1f600} 你好${BEL}`, "after-utf8-title\r\n");
add("osc", "title-with-control-chars", {}, `${OSC}2;bad`, "after-embedded-bel\r\n");
add("osc", "palette-osc4-set", {}, `${OSC}4;1;rgb:ff/00/00${BEL}`, "after-palette\r\n");
add("osc", "palette-osc104-reset", {}, `${OSC}104${BEL}`, "after-palette-reset\r\n");
add("osc", "default-colours-osc10-11", {}, `${OSC}10;#ffffff${BEL}${OSC}11;#000000${BEL}`, "after-defaults\r\n");
add("osc", "cursor-colour-osc12", {}, `${OSC}12;#ff0000${BEL}`, "after-cursor-colour\r\n");
add("osc", "hyperlink-osc8", {}, `${OSC}8;;https://example.com/irc${ST}`, "LINKTEXT", `${OSC}8;;${ST}`, "\r\n");
add("osc", "hyperlink-osc8-with-id", {}, `${OSC}8;id=x1;https://example.com/a${ST}`, "LINK2", `${OSC}8;;${ST}`, "\r\n");
add("osc", "clipboard-osc52", {}, `${OSC}52;c;aGVsbG8=${ST}`, "after-clipboard\r\n");
add("osc", "notify-osc9", {}, `${OSC}9;notification body${BEL}`, "after-notify\r\n");
add("osc", "notify-osc777", {}, `${OSC}777;notify;title;body${ST}`, "after-777\r\n");
add("osc", "unterminated-osc", {}, `${OSC}2;never terminated and then lots of text that should not vanish\r\n`);
add("osc", "osc-terminated-by-esc-only", {}, `${OSC}2;title${ESC}`, "after\r\n");
add("dcs", "dcs-passthrough-tmux", {}, `${DCS}tmux;${ESC}${ESC}[31mnested${ST}`, "after-dcs\r\n");
add("dcs", "dcs-xtgettcap", {}, `${DCS}+q544e${ST}`, "after-xtgettcap\r\n");
add("dcs", "dcs-sixel-small", {}, `${DCS}0;0;0q"1;1;2;2#0;2;0;0;0#0@@${ST}`, "after-sixel\r\n");
add("dcs", "dcs-unterminated", {}, `${DCS}tmux;never ends and swallows this line\r\n`);
add("dcs", "apc-kitty-graphics", {}, `${ESC}_Ga=T,f=24,s=1,v=1;AAAA${ST}`, "after-kitty\r\n");
add("dcs", "pm-string", {}, `${ESC}^private message${ST}`, "after-pm\r\n");
add("dcs", "sos-string", {}, `${ESC}Xstart of string${ST}`, "after-sos\r\n");

// Device queries produce *replies* on the input side; here we only assert
// they do not corrupt the screen and are not echoed as text.
add("query", "primary-da", {}, `${CSI}c`, "after-da\r\n");
add("query", "secondary-da", {}, `${CSI}>c`, "after-da2\r\n");
add("query", "cursor-position-report", {}, `${CSI}6n`, "after-cpr\r\n");
add("query", "device-status-report", {}, `${CSI}5n`, "after-dsr\r\n");
add("query", "xtversion", {}, `${CSI}>0q`, "after-xtversion\r\n");

// ---------------------------------------------------------------------------
// E. IRC wire formatting (mIRC / ircv3)
//
// These arrive as raw C0 bytes. A client that is *not* an IRC client must
// treat them as non-printing control characters — and, critically, the server
// model and xterm.js must treat them the SAME way, or every coloured IRC line
// shifts by a column on reattach.
// ---------------------------------------------------------------------------

const IRC = {
  bold: "\x02",
  colour: "\x03",
  hex: "\x04",
  reset: "\x0f",
  reverse: "\x16",
  italic: "\x1d",
  strike: "\x1e",
  underline: "\x1f",
  mono: "\x11",
};

add("irc", "raw-bold", {}, `[${IRC.bold}bold${IRC.bold}]\r\n`);
add("irc", "raw-italic", {}, `[${IRC.italic}italic${IRC.italic}]\r\n`);
add("irc", "raw-underline", {}, `[${IRC.underline}under${IRC.underline}]\r\n`);
add("irc", "raw-strikethrough", {}, `[${IRC.strike}strike${IRC.strike}]\r\n`);
add("irc", "raw-monospace", {}, `[${IRC.mono}mono${IRC.mono}]\r\n`);
add("irc", "raw-reverse", {}, `[${IRC.reverse}reverse${IRC.reverse}]\r\n`);
add("irc", "raw-reset", {}, `[${IRC.bold}bold${IRC.reset}plain]\r\n`);
add("irc", "raw-colour-single-digit", {}, `[${IRC.colour}4red${IRC.reset}]\r\n`);
add("irc", "raw-colour-two-digit", {}, `[${IRC.colour}04red${IRC.reset}]\r\n`);
add("irc", "raw-colour-fg-bg", {}, `[${IRC.colour}4,8redonyellow${IRC.reset}]\r\n`);
add("irc", "raw-colour-fg-bg-padded", {}, `[${IRC.colour}04,08redonyellow${IRC.reset}]\r\n`);
add("irc", "raw-colour-ambiguous-digits", {}, `[${IRC.colour}12,34text${IRC.reset}]\r\n`);
add("irc", "raw-colour-digits-follow", {}, `[${IRC.colour}041234${IRC.reset}]\r\n`);
add("irc", "raw-colour-bare-terminator", {}, `[${IRC.colour}4red${IRC.colour}plain]\r\n`);
add("irc", "raw-colour-trailing-comma", {}, `[${IRC.colour}4,text${IRC.reset}]\r\n`);
add("irc", "raw-colour-at-eol", {}, `[text${IRC.colour}]\r\n`);
add("irc", "raw-colour-extended-99", {}, ...[16, 27, 50, 71, 88, 98, 99].map((n) => `${IRC.colour}${n}c${n} `), `${IRC.reset}\r\n`);
add("irc", "raw-hex-colour", {}, `[${IRC.hex}FF0000hexred${IRC.hex}]\r\n`);
add("irc", "raw-nested-attrs", {}, `[${IRC.bold}${IRC.colour}4${IRC.underline}all${IRC.reset}plain]\r\n`);
add("irc", "raw-codes-with-emoji", {}, `[${IRC.colour}4\u{1f600}${IRC.bold}\u{1fae0}${IRC.reset}]\r\n`);
add("irc", "raw-codes-with-combining", {}, `[${IRC.colour}4é${IRC.reset}]\r\n`);
add("irc", "raw-full-line-realistic", {}, `${IRC.bold}<nick>${IRC.reset} ${IRC.colour}3hello${IRC.reset} ${IRC.colour}4,1world${IRC.reset} \u{1f600}\r\n`);

// What weechat actually emits once it has translated mIRC codes: 256-colour
// SGR runs, often re-issued per word.
add("irc", "weechat-style-sgr-run", {}, ...["31", "32", "33", "34", "35", "36"].map((c) => `${CSI}${c}mword${CSI}39m `), "\r\n");
add("irc", "weechat-style-256-nick-colours", {}, ...[39, 76, 141, 178, 203].map((n) => `${CSI}38;5;${n}m<nick${n}>${CSI}39m `), "\r\n");
add("irc", "weechat-style-bar-reverse", {}, `${CSI}7m`, " status bar ".padEnd(80, " "), `${CSI}27m\r\n`);

// ---------------------------------------------------------------------------
// F. Composite / stress — the shapes that actually broke in production
// ---------------------------------------------------------------------------

add("composite", "wrapped-long-line", {}, "w".repeat(250), "\r\n");
add("composite", "wrapped-long-line-coloured", {}, `${CSI}33m`, "y".repeat(250), `${CSI}0m\r\n`);
add("composite", "wrapped-wide-chars", {}, "漢字".repeat(80), "\r\n");
add("composite", "wrapped-emoji", {}, "\u{1f600}\u{1fae0}".repeat(60), "\r\n");
add("composite", "wrapped-combining", {}, "é".repeat(200), "\r\n");
add("composite", "scroll-past-screen", {}, ...Array.from({ length: 60 }, (_, i) => `line ${i}\r\n`));
add("composite", "scroll-past-screen-coloured", {}, ...Array.from({ length: 60 }, (_, i) => `${CSI}3${i % 8}mline ${i}${CSI}0m\r\n`));
add("composite", "full-screen-redraw", {},
  `${CSI}?1049h${CSI}2J`,
  ...Array.from({ length: 24 }, (_, r) => `${CSI}${r + 1};1H${CSI}4${r % 8}m${`row ${r}`.padEnd(80, ".")}${CSI}0m`),
);
add("composite", "weechat-like-layout", {},
  `${CSI}?1049h${CSI}2J${CSI}?25l`,
  `${CSI}1;1H${CSI}7m${"[12:00] holdfast | #channel".padEnd(80)}${CSI}27m`,
  `${CSI}2;62r`,
  ...Array.from({ length: 20 }, (_, i) => `${CSI}${i + 2};1H${CSI}38;5;${100 + i}m<nick${i}>${CSI}39m message ${i} \u{1f600} 你好 é`),
  `${CSI}23;1H${CSI}7m${"[status]".padEnd(80)}${CSI}27m`,
  `${CSI}24;1H${CSI}?25h`,
);
add("composite", "erase-then-rewrite-same-cell", {}, "abc", `${CSI}1G`, `${CSI}2K`, "xyz\r\n");
add("composite", "overwrite-wide-with-narrow", {}, "漢字", `${CSI}1G`, "a\r\n");
add("composite", "overwrite-narrow-with-wide", {}, "abcd", `${CSI}2G`, "漢\r\n");
add("composite", "split-wide-by-cursor", {}, "漢字", `${CSI}2G`, "X\r\n");
add("composite", "combining-onto-wide", {}, "漢́X\r\n");
add("composite", "combining-at-line-start", { bounded: "orphan combining mark with no base cell; identical on screen, differs only in extracted text" }, "́X\r\n");
add("composite", "combining-after-wrap", {}, "x".repeat(80), "́Y\r\n");
add("composite", "cr-without-lf-overwrite", {}, "aaaaaaaaaa\rbbb\r\n");
add("composite", "backspace-overwrite", {}, "abcdef", "\b\b\bXYZ\r\n");
add("composite", "backspace-over-wide", {}, "漢", "\bX\r\n");
add("composite", "vertical-tab-formfeed", {}, "a\vb\fc\r\n");
add("composite", "progress-bar-redraw", {}, ...Array.from({ length: 10 }, (_, i) => `\r${CSI}42m${"#".repeat(i * 4)}${CSI}0m${".".repeat(40 - i * 4)} ${i * 10}%`), "\r\n");
add("composite", "spinner-redraw", {}, ...["⠁", "⠉", "⠙", "⠹"].map((g) => `\r${g} working`), "\r\n");

export { cases, bytes };
