#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/openssl-env.sh"
INIT_CA="$SCRIPT_DIR/init-local-ca.sh"
GEN_OVPN="$SCRIPT_DIR/generate-local-ovpn.sh"
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT HUP INT TERM

cd "$WORK_DIR"

"$INIT_CA" >/dev/null
[ -f local/ca/ca.key ]
[ -f local/ca/ca.crt ]
[ "$(stat -c '%a' local/ca/ca.key)" = "600" ]
[ "$(stat -c '%a' local/ca/ca.crt)" = "644" ]
"$OPENSSL" verify -CAfile local/ca/ca.crt local/ca/ca.crt >/dev/null
"$OPENSSL" x509 -in local/ca/ca.crt -noout -text | grep 'CA:TRUE' >/dev/null

OUTPUT=$("$GEN_OVPN" --name client_a --remote 127.0.0.1 --port 5556)
OVPN=$(printf '%s\n' "$OUTPUT" | sed -n 's/^OVPN: //p')
KEY=$(printf '%s\n' "$OUTPUT" | sed -n 's/^Private key: //p')
CERT=$(printf '%s\n' "$OUTPUT" | sed -n 's/^Certificate: //p')
CSR=$(printf '%s\n' "$OUTPUT" | sed -n 's/^CSR: //p')

[ -f "$OVPN" ]
[ -f "$KEY" ]
[ -f "$CERT" ]
[ -f "$CSR" ]
[ "$(stat -c '%a' "$KEY")" = "600" ]
[ "$(stat -c '%a' "$OVPN")" = "644" ]
"$OPENSSL" verify -CAfile local/ca/ca.crt -purpose sslclient "$CERT" >/dev/null
"$OPENSSL" req -in "$CSR" -noout -verify >/dev/null

grep '^client$' "$OVPN" >/dev/null
grep '^dev tun$' "$OVPN" >/dev/null
grep '^proto udp$' "$OVPN" >/dev/null
grep '^remote 127.0.0.1 5556$' "$OVPN" >/dev/null
grep '^key keys/client_a-.*\.key$' "$OVPN" >/dev/null
grep '^<ca>$' "$OVPN" >/dev/null
grep '^<cert>$' "$OVPN" >/dev/null

if "$INIT_CA" >/dev/null 2>&1; then
    echo "existing CA was overwritten" >&2
    exit 1
fi

if "$GEN_OVPN" --name bad --remote 'bad host' --port 5556 >/dev/null 2>&1; then
    echo "unsafe remote host was accepted" >&2
    exit 1
fi

if "$GEN_OVPN" --name bad --remote 127.0.0.1 --port 70000 >/dev/null 2>&1; then
    echo "invalid port was accepted" >&2
    exit 1
fi

echo "local OVPN provisioning tests passed"
