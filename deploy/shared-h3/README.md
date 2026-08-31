# Shared dockerwm HTTP/3 front door

This is the opt-in ADR 0030 deployment. `dockerwm-h3-frontdoord` owns the one
UDP/443 socket and selects Holdfast by exact TLS SNI. `holdfastd` remains the
application server but accepts raw WebTransport streams through a UID-checked
Unix socket. There is no TCP, WebSocket, HTTP/2 or application fallback.

The direct `--wt-bind`, `--wt-cert` and `--wt-key` options must not be used in
this mode. Development authentication is refused even when the daemon's TCP
bootstrap address is loopback.

## Runtime directory

The packaged dockerwm front door normally uses UID 973 and the
`dockerwm-viewer-ipc` group. Add the `holdfast` account to that group and create
a protected setgid runtime directory so the socket inherits the shared group:

```sh
sudo usermod -aG dockerwm-viewer-ipc holdfast
sudo install -Dm644 deploy/tmpfiles.d/holdfast-h3-bridge.conf \
  /etc/tmpfiles.d/holdfast-h3-bridge.conf
sudo systemd-tmpfiles --create /etc/tmpfiles.d/holdfast-h3-bridge.conf
```

The bridge still checks UID 973 on every accepted connection; group membership
alone grants no protocol authority. If a downstream package allocated another
front-door UID/GID, change the unit, tmpfiles entry and dockerwm route together.

## Holdfast daemon

Install and customize `deploy/systemd/holdfastd-shared-h3.service`. Its relevant
arguments are:

```text
--no-webtransport
--h3-frontdoor-socket /run/holdfast-h3/h3-bridge.sock
--h3-frontdoor-uid 973
--h3-frontdoor-hostname terminal.example.com
--h3-frontdoor-port 443
```

All four front-door values are mandatory. The hostname is canonical lowercase
DNS and must equal the dockerwm route exactly. The daemon also needs its normal
real SSH/PAM authentication, account policy, grant key and optional spawner and
upload configuration.

## Front-door assets and route

Install these root-owned, non-writable web assets:

```text
/usr/share/holdfast/web/index.html
/usr/share/holdfast/web/app.js
/usr/share/holdfast/web/holdfast.css
/usr/share/holdfast/web/xterm.css
/usr/share/holdfast/web/webtransport-info.json
```

Generate the last file from the exact leaf certificate used by the SNI route:

```sh
deploy/shared-h3/render-webtransport-info.sh \
  /etc/holdfast/tls/fullchain.pem 443 false > /tmp/webtransport-info.json
sudo install -o root -g root -m 0644 /tmp/webtransport-info.json \
  /usr/share/holdfast/web/webtransport-info.json
```

Use `true` only when Holdfast actually enables password authentication. The
leaf hash is not a substitute for WebPKI validation; it is the ADR 0008 value
the browser includes in its SSH-key signature. A stale value fails closed but
prevents login. Every certificate renewal hook must regenerate and atomically
install this file before restarting the front door.

Add this exact route to the root-owned dockerwm front-door configuration (merge
it into the existing `routes` array):

```json
{
  "hostname": "terminal.example.com",
  "certificate_file": "/etc/holdfast/tls/fullchain.pem",
  "private_key_file": "/etc/holdfast/tls/privkey-pkcs8.pem",
  "webtransport_path": "/",
  "backend_socket": "/run/holdfast-h3/h3-bridge.sock",
  "backend_uid": 974,
  "maximum_sessions": 256,
  "maximum_streams_per_session": 64,
  "allow_hex_document_alias": false,
  "assets": [
    {"path":"/","content_type":"text/html; charset=utf-8","file":"/usr/share/holdfast/web/index.html"},
    {"path":"/app.js","content_type":"text/javascript; charset=utf-8","file":"/usr/share/holdfast/web/app.js"},
    {"path":"/holdfast.css","content_type":"text/css; charset=utf-8","file":"/usr/share/holdfast/web/holdfast.css"},
    {"path":"/xterm.css","content_type":"text/css; charset=utf-8","file":"/usr/share/holdfast/web/xterm.css"},
    {"path":"/webtransport-info","content_type":"application/json","file":"/usr/share/holdfast/web/webtransport-info.json"}
  ]
}
```

`backend_uid` is the actual `holdfast` service UID, not the illustrative 974
unless that is what the host allocated. The private key must be unencrypted
PKCS#8 PEM for the current front door.

Validate both sides before switching UDP 443:

```sh
sudo -u dockerwm-h3-frontdoor /usr/libexec/dockerwm-h3-frontdoord \
  --config /etc/dockerwm/h3-frontdoor.json --check
sudo systemd-analyze verify deploy/systemd/holdfastd-shared-h3.service
cargo test -p hf-daemon --test frontdoor_bridge --locked
```

The cross-repository live gate is:

```sh
cd /home/development/dockerOS/dockerwm-v2
tests/public-viewer/live-stack.sh
```

It opens the Holdfast login and a disposable dockerwm viewer concurrently in
real Chromium, proves both pages and WebTransport sessions use HTTP/3 on one
UDP socket, verifies the viewer remains live, and checks one-use container
destruction and leak-free shutdown.

