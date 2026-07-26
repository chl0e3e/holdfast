#!/bin/sh
# Let's Encrypt deploy hook: publish the renewed shortlived IP certificate to
# holdfastd (which reads holdfast-owned 0600 copies) and to nginx (which reads
# /etc/letsencrypt directly as root). Runs only after a successful renewal.
set -eu

case "$RENEWED_LINEAGE" in
*/185.206.149.176) ;;
*) exit 0 ;;
esac

install -m600 -o holdfast -g holdfast "$RENEWED_LINEAGE/fullchain.pem" /etc/holdfast/tls/fullchain.pem
install -m600 -o holdfast -g holdfast "$RENEWED_LINEAGE/privkey.pem" /etc/holdfast/tls/privkey.pem

# NOTE: restart (not reload) — holdfastd loads TLS at startup; active shells
# do not survive. Attached clients auto-resume with their rotated tokens, but
# the shells themselves are daemon children. Cert hot-reload is future work.
systemctl restart holdfastd
systemctl reload nginx
