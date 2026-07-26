# nginx TCP fallback in front of Holdfast

nginx handles ordinary HTTPS and the WebSocket fallback on **TCP 443**.
`holdfastd` separately terminates WebTransport/HTTP3 on **UDP 443** with the
same public hostname and certificate. Do not attempt to proxy WebTransport
through this nginx server block.

Example (adapt paths and hostname; do not reuse an unrelated site's config):

```nginx
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    server_name terminal.example.com;

    ssl_certificate     /etc/holdfast/tls/fullchain.pem;
    ssl_certificate_key /etc/holdfast/tls/privkey.pem;

    location /terminal/ws {
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_pass http://127.0.0.1:8080;
    }

    location / {
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_pass http://127.0.0.1:8080;
    }
}
```

Run `holdfastd` with `--bind 127.0.0.1:8080`, `--wt-bind 0.0.0.0:443`, matching
`--wt-cert`/`--wt-key`, and
`--allowed-origin https://terminal.example.com`. Open both TCP and UDP 443 in
the firewall. A DNS-only hostname is required when a CDN cannot proxy the
WebTransport endpoint.

Validate and reload only after the configuration passes:

```bash
sudo nginx -t
sudo systemctl reload nginx
```
