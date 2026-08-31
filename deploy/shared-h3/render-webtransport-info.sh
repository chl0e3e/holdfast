#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
  echo "usage: $0 CERTIFICATE_PEM PUBLIC_UDP_PORT PASSWORD_AUTH_TRUE_OR_FALSE" >&2
  exit 2
fi

certificate=$1
port=$2
password_auth=$3

case "$port" in
  ''|*[!0-9]*) echo "public UDP port must be an integer" >&2; exit 2 ;;
esac
if [ "$port" -lt 1 ] || [ "$port" -gt 65535 ]; then
  echo "public UDP port must be in 1..65535" >&2
  exit 2
fi
case "$password_auth" in
  true|false) ;;
  *) echo "password-auth value must be true or false" >&2; exit 2 ;;
esac

leaf_sha256=$(
  openssl x509 -in "$certificate" -outform DER \
    | openssl dgst -sha256 -binary \
    | base64 | tr -d '\n'
)
if [ "${#leaf_sha256}" -ne 44 ]; then
  echo "could not derive a SHA-256 leaf-certificate hash" >&2
  exit 1
fi

printf '{"port":%s,"certHashBase64":"%s","certificateMode":"webpki","passwordAuth":%s}\n' \
  "$port" "$leaf_sha256" "$password_auth"

