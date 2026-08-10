#!/usr/bin/env python3
"""Minimal IRC server that feeds weechat a scripted torture corpus.

It speaks just enough of the protocol to get one client registered and into a
channel, then pushes messages whose formatting is the point: mIRC colour and
attribute codes, emoji and combining sequences, bidi text, and deliberately
invalid UTF-8. Everything weechat then draws is real weechat output, so the
holdfast render path is exercised exactly as it is in daily use.

    python3 fake-ircd.py --port 6667 [--host 127.0.0.1]

Bind to loopback only; this speaks no authentication and is a test fixture.
"""

import argparse
import socket
import threading
import time

# mIRC / ircv3 formatting bytes, named so the corpus below stays readable.
B = b"\x02"   # bold
C = b"\x03"   # colour
H = b"\x04"   # hex colour
R = b"\x0f"   # reset
V = b"\x16"   # reverse
I = b"\x1d"   # italic
S = b"\x1e"   # strikethrough
U = b"\x1f"   # underline
M = b"\x11"   # monospace

CHANNEL = "#render"


def messages():
    """(nick, kind, payload) triples. kind is 'privmsg', 'action' or 'notice'."""
    out = []

    def msg(nick, payload, kind="privmsg"):
        out.append((nick, kind, payload))

    # --- mIRC attributes ------------------------------------------------
    msg("attrs", B + b"bold" + B + b" plain")
    msg("attrs", I + b"italic" + I + b" plain")
    msg("attrs", U + b"underline" + U + b" plain")
    msg("attrs", S + b"strikethrough" + S + b" plain")
    msg("attrs", M + b"monospace" + M + b" plain")
    msg("attrs", V + b"reverse" + V + b" plain")
    msg("attrs", B + b"bold " + U + b"and underline" + R + b" reset")

    # --- mIRC colours ---------------------------------------------------
    msg("colour", C + b"4red" + R + b" default")
    msg("colour", C + b"04red-padded" + R + b" default")
    msg("colour", C + b"4,8red-on-yellow" + R + b" default")
    msg("colour", C + b"04,08padded-pair" + R + b" default")
    # Digit-boundary ambiguity: is "12,34" a colour pair or is "34" text?
    msg("colour", C + b"12,34text" + R)
    msg("colour", C + b"041234" + R)
    msg("colour", C + b"4red" + C + b"implicit-reset")
    msg("colour", C + b"4,trailing-comma" + R)
    msg("colour", b"text-then-bare-colour" + C)
    # The full 16-colour palette, then the extended 16..98 range.
    msg("colour", b"".join(C + str(n).encode() + b"c%d " % n for n in range(16)) + R)
    msg("colour", b"".join(C + str(n).encode() + b"c%d " % n for n in range(16, 40)) + R)
    msg("colour", b"".join(C + str(n).encode() + b"c%d " % n for n in range(40, 70)) + R)
    msg("colour", b"".join(C + str(n).encode() + b"c%d " % n for n in range(70, 99)) + R)
    msg("colour", H + b"FF0000hex-red" + H + b"00FF00hex-green" + R)
    msg("colour", B + C + b"4" + U + b"bold-red-underline" + R + b" plain")

    # --- Unicode --------------------------------------------------------
    msg("uni", "emoji basic \U0001f600 \U0001f602 ☺️".encode())
    # Post-Unicode-11 additions: the class that shipped broken once already.
    msg("uni", "emoji post-u11 \U0001fae0 \U0001fad0 \U0001faf6".encode())
    msg("uni", "zwj \U0001f468‍\U0001f469‍\U0001f467‍\U0001f466 "
               "\U0001f469‍\U0001f4bb".encode())
    msg("uni", "skin \U0001f44d\U0001f3fd flag \U0001f1ec\U0001f1e7 "
               "tagflag \U0001f3f4\U000e0067\U000e0062\U000e0073\U000e0063\U000e0074\U000e007f".encode())
    msg("uni", "keycap 1️⃣ vs15 ⚠︎ vs16 ⚠️".encode())
    msg("uni", ("combining e-acute x40 " + "\u0065\u0301" * 40).encode())
    msg("uni", ("zalgo a" + "́" * 24 + "b").encode())
    msg("uni", "cjk 你好世界 hangul 한국어".encode())
    msg("uni", "rtl مرحبا שלום".encode())
    msg("uni", "boxes ┌─┐│└┴┘ blocks █▓▒░".encode())
    msg("uni", "braille ⠁⠉⠙⠹ powerline ".encode())
    msg("uni", "softhyphen a­b zwsp a​b wj a⁠b".encode())
    msg("uni", b"wide-run " + "\u6f22".encode() * 30)
    msg("uni", b"emoji-run " + "\U0001f600".encode() * 30)

    # --- Deliberately invalid UTF-8 (routine on IRC) --------------------
    msg("bytes", b"latin1 caf\xe9 na\xefve")
    msg("bytes", b"lone-continuation \x80\x81 end")
    msg("bytes", b"truncated-3byte \xe4\xbd end")
    msg("bytes", b"overlong \xc0\xaf end")
    msg("bytes", b"surrogate \xed\xa0\x80 end")
    msg("bytes", b"ff-fe \xff\xfe end")

    # --- Regression: bidi isolates from title bots (the "Konichiwa" line) --
    # U+2068 FIRST STRONG ISOLATE / U+2069 POP DIRECTIONAL ISOLATE are
    # zero-width, and land mid-line where weechat then wraps. Reported live as
    # a torn buflist entry.
    msg("druqs", "[YouTube] \u2068Donny Ben\u00e9t - Konichiwa (Official Music Video)\u2069"
                 " | 4m 41s | Channel: \u2068Donny Ben\u00e9t\u2069 | 2,115,527 views |"
                 " 48,669 likes | 2017-08-31 - 22:00:01 UTC".encode())
    msg("druqs", "\u2068isolate at start of message\u2069".encode())
    msg("druqs", ("\u2068" + "wrap " * 40 + "\u2069").encode())

    # --- Does weechat count a bidi isolate as a column when it wraps? ----
    # Two identical repeating rulers, the second prefixed with FSI+PDI. If
    # weechat treats them as zero-width the rows wrap at the same digit; if it
    # charges a column each, the second ruler's rows start two digits earlier.
    msg("ruler", ("0123456789" * 20).encode())
    msg("ruler", ("\u2068\u2069" + "0123456789" * 20).encode())

    # --- Shapes that stress wrapping and the nick column -----------------
    msg("wrap", b"w" * 240)
    msg("wrap", C + b"3" + b"coloured-wrap " * 20 + R)
    msg("wrap", ("mixed 漢字 " * 30).encode())
    msg("wrap", ("\U0001f600 é 你 " * 30).encode())
    msg("verylongnickname_that_pushes_the_prefix_column", b"long nick test")

    msg("act", "waves \U0001f44b at everyone".encode(), kind="action")
    msg("act", C + b"4angry action" + R, kind="action")
    msg("srv", b"notice with " + C + b"7colour" + R, kind="notice")

    # A URL, so the client's link popover sees a real target.
    msg("links", b"see https://example.com/a/very/long/path?q=1&r=2 for details")
    msg("links", C + b"12https://example.com/coloured-link" + R)

    return out


class Server:
    def __init__(self, host, port):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(4)

    def serve(self):
        while True:
            conn, _ = self.sock.accept()
            threading.Thread(target=self.session, args=(conn,), daemon=True).start()

    def session(self, conn):
        conn.settimeout(300)
        buf = b""
        nick = None
        registered = False
        try:
            while True:
                data = conn.recv(4096)
                if not data:
                    return
                buf += data
                while b"\r\n" in buf:
                    line, buf = buf.split(b"\r\n", 1)
                    parts = line.split(b" ")
                    cmd = parts[0].upper()
                    if cmd == b"NICK":
                        nick = parts[1].decode("utf8", "replace")
                    elif cmd == b"PING":
                        conn.sendall(b"PONG :" + parts[1] + b"\r\n")
                    elif cmd == b"JOIN":
                        # A real server treats "JOIN #a,#b" as several channels;
                        # echoing the comma-joined string back made weechat open
                        # one absurdly-named buffer instead.
                        for chan in parts[1].decode().split(","):
                            if not chan:
                                continue
                            conn.sendall(f":{nick}!u@fake JOIN {chan}\r\n".encode())
                            conn.sendall(f":fake 353 {nick} = {chan} :{nick} @op alice bob\r\n".encode())
                            conn.sendall(f":fake 366 {nick} {chan} :End of /NAMES list\r\n".encode())
                            if chan == CHANNEL:
                                threading.Thread(target=self.push, args=(conn, nick, chan), daemon=True).start()
                    elif cmd == b"QUIT":
                        return
                    if cmd == b"USER" and nick and not registered:
                        registered = True
                        for code, text in (
                            ("001", "Welcome to the render test network"),
                            ("002", "Your host is fake"),
                            ("003", "This server was created now"),
                            ("004", "fake 1.0 o o"),
                            ("375", "- MOTD -"),
                            ("372", "- render differential fixture -"),
                            ("376", "End of /MOTD command."),
                        ):
                            conn.sendall(f":fake {code} {nick} :{text}\r\n".encode())
        except (OSError, IndexError):
            return
        finally:
            conn.close()

    def push(self, conn, nick, chan):
        # A short settle so weechat has finished drawing the join before the
        # first message lands.
        time.sleep(1.5)
        for sender, kind, payload in messages():
            if kind == "action":
                body = b"\x01ACTION " + payload + b"\x01"
                head = f":{sender}!u@fake PRIVMSG {chan} :".encode()
            elif kind == "notice":
                body = payload
                head = f":{sender}!u@fake NOTICE {chan} :".encode()
            else:
                body = payload
                head = f":{sender}!u@fake PRIVMSG {chan} :".encode()
            try:
                conn.sendall(head + body + b"\r\n")
            except OSError:
                return
            time.sleep(0.05)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=6667)
    args = ap.parse_args()
    print(f"fake ircd on {args.host}:{args.port}, channel {CHANNEL}", flush=True)
    Server(args.host, args.port).serve()


if __name__ == "__main__":
    main()
