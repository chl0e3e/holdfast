#!/bin/bash
# Launcher for the live render probe (crates/client-core/examples/ircprobe.rs).
#
# Starts the fake ircd on loopback and runs weechat against a THROWAWAY config
# directory, so an operator's own weechat session and config are untouched.
# Staged on the server at /tmp/hf-render/run.sh and exec'd by the probe.

set -u

DIR=/tmp/hf-render
PORT=${PORT:-6767}
WC=$DIR/wc

# A holdfast PTY supplies both of these; the fallbacks only matter when the
# launcher is smoke-tested over plain ssh, where neither is set.
export TERM=${TERM:-xterm-256color}
case "${LANG:-}" in *[Uu][Tt][Ff]*) ;; *) export LANG=C.UTF-8 ;; esac

rm -rf "$WC"
mkdir -p "$WC"

# Reproduce the operator's own bar layout (buflist is a root bar, auto-sized)
# without touching their config or their credentials: only the two layout
# files are copied, never irc.conf or sec.conf.
if [ -d "$DIR/refconf" ]; then
  cp "$DIR"/refconf/weechat.conf "$DIR"/refconf/buflist.conf "$WC"/ 2>/dev/null || true
fi

pkill -f "fake-ircd.py --port $PORT" 2>/dev/null
python3 "$DIR/fake-ircd.py" --port "$PORT" >"$DIR/ircd.log" 2>&1 &
IRCD=$!
trap 'kill $IRCD 2>/dev/null' EXIT

# Give the listener a moment before weechat dials it.
sleep 0.5

# The operator runs weechat inside GNU screen, which is a second terminal
# emulator with its own width tables and its own redraw logic. Reproducing
# without it misses every disagreement between screen and the client.
exec screen -m -S hfprobe -c /dev/null weechat --dir "$WC" -r "/set weechat.look.confirm_quit off;/server add fake 127.0.0.1/$PORT -notls;/set irc.server.fake.nicks probe;/set irc.server.fake.autojoin #alpha,#bravo,#charlie,#delta,#echo,#foxtrot,#golf,#hotel,#india,#juliet,#kilo,#lima,#mike,#render;/connect fake"
