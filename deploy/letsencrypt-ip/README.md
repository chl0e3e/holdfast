# DNS-free deployment: Let's Encrypt IP certificate + QUIC on UDP 443

The reference recipe running on 185.206.149.176 (deployed 2026-07-19). No
domain name anywhere: the origin is `https://<ip>`, authenticated by a Let's
Encrypt **IP-address certificate** (generally available since 2026-01-15).
IP certs are only issued under the `shortlived` ACME profile — **160 hours
(~6 days)** — so renewal automation is not optional.

## Pieces

- **Certificate** — certbot ≥ 5.4 (venv install at `/opt/certbot`; distro
  packages are too old):

  ```bash
  /opt/certbot/bin/certbot certonly --preferred-profile shortlived \
      --webroot -w /var/www/html --ip-address <ip> --agree-tos -m <email> -n
  ```

  http-01 validation rides whatever already serves TCP 80 (here: nginx's
  default server with webroot `/var/www/html`).

- **Daemon** — `deploy/systemd/holdfastd.service` adapted: `--wt-bind
  0.0.0.0:443` (UDP; `CAP_NET_BIND_SERVICE` is already in the unit),
  `--wt-cert`/`--wt-key` pointing at holdfast-owned 0600 **copies** under
  `/etc/holdfast/tls` (the daemon refuses group/world-readable keys and must
  not read `/etc/letsencrypt` as root), `--ssh-auth <user> <authorized_keys
  copy>`, `--allowed-origin https://<ip>`, and `--grant-key
  /var/lib/holdfast/grant.key` so issued grants — and therefore signed-in
  browsers — survive the restarts renewal forces every few days.

- **TCP 443** — nginx `default_server` block for the bare IP
  (`deploy/letsencrypt-ip/nginx-ip.conf` shape): browsers hitting an IP send
  no SNI, so default_server is what answers them. It terminates TLS with the
  same IP certificate and proxies to the daemon's loopback TCP listener,
  which serves the ADR 0014 "QUIC required" interstitial with
  `Alt-Svc: h3=":443"`. The app itself is only ever served over HTTP/3.

- **Renewal** — `/etc/letsencrypt/renewal-hooks/deploy/holdfast.sh` re-copies
  the PEMs (holdfast-owned, 0600), restarts `holdfastd` and reloads nginx; a
  systemd timer runs `certbot renew` every 6 hours (certbot's ARI scheduling
  decides when renewal actually happens, around two-thirds of the 160-hour
  lifetime). **A daemon restart terminates running shells** — attached
  clients resume their connections, but the shells are daemon children.
  Certificate hot-reload is future work.

## Browser sign-in (no key ever leaves your machine)

Visit `https://<ip>`. The interstitial upgrades to HTTP/3, the app loads, and
the login dialog asks for your username and public key, fetches a challenge,
and shows the exact command to run locally:

```bash
echo <blob> | base64 -d | ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n holdfast-auth@v0
```

Paste the SSHSIG back. The signed message is bound to the server's
certificate hash (ADR 0008), so a phishing relay cannot reuse it. The issued
grant persists in the browser and re-authenticates reconnects until expiry.
CLI equivalent: `hf --url https://<ip> --user <user> --key ~/.ssh/id_ed25519 open`
(`https://` means direct WebTransport with WebPKI validation — no bootstrap
fetch).

## Optional: password sign-in (ADR 0016, deployed here 2026-07-23)

`--password-auth <user>` (repeatable) lets allowlisted users sign in with
their Unix password instead; the dialog then defaults to a username/password
form (the key flow stays one click away) and yields the same stored grant.
Two deployment steps beyond the flag:

- install the PAM stack: `install -m 0644 deploy/pam/holdfast-ssh
  /etc/pam.d/holdfast-ssh`;
- since the daemon runs as the unprivileged `holdfast` service user, give the
  unit `SupplementaryGroups=shadow` so pam_unix can read `/etc/shadow`
  (`RestrictSUIDSGID` blocks the setgid `unix_chkpwd` helper route). Without
  it every password is rejected — fail closed, verified.

The password rides only inside the WebTransport TLS session; failures are
rate-limited per source address. Unlike the SSH flow it has no ADR 0008
channel binding — threat model T13 records the trade-off. Prefer keys where
provisioning allows.
