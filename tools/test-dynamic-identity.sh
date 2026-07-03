#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/openssl-env.sh"
ENSURE="$SCRIPT_DIR/ensure-dynamic-identity.sh"
STAMP="$$"
ROOT="local/test-dynamic-identity-$STAMP"
BUNDLE="$ROOT/bundle"
CA_DIR="$ROOT/ca"
CLIENT="client_dyn_test_$STAMP"
GATEWAY="gateway_dyn_test_$STAMP"

cleanup() {
    rm -rf -- "$ROOT"
}
trap cleanup EXIT HUP INT TERM

"$ENSURE" \
    --allocation-id "dynamic-vpn-test-$STAMP" \
    --client-peer-id "$CLIENT" \
    --gateway-peer-id "$GATEWAY" \
    --remote 127.0.0.1 \
    --gateway-port 32001 \
    --output-dir "$BUNDLE" \
    --ca-dir "$CA_DIR" >/dev/null

# The second call must reuse the complete bundle.
"$ENSURE" \
    --allocation-id "dynamic-vpn-test-$STAMP" \
    --client-peer-id "$CLIENT" \
    --gateway-peer-id "$GATEWAY" \
    --remote 127.0.0.1 \
    --gateway-port 32001 \
    --output-dir "$BUNDLE" \
    --ca-dir "$CA_DIR" >/dev/null

SECOND_BUNDLE="$ROOT/bundle-2"
SECOND_CLIENT="client_dyn_test_2_$STAMP"
SECOND_GATEWAY="gateway_dyn_test_2_$STAMP"
"$ENSURE" \
    --allocation-id "dynamic-vpn-test-2-$STAMP" \
    --client-peer-id "$SECOND_CLIENT" \
    --gateway-peer-id "$SECOND_GATEWAY" \
    --remote 127.0.0.1 \
    --gateway-port 32002 \
    --output-dir "$SECOND_BUNDLE" \
    --ca-dir "$CA_DIR" >/dev/null

[ -f "$BUNDLE/$CLIENT.ovpn" ]
[ -f "$BUNDLE/keys/$CLIENT.key" ]
[ -f "$BUNDLE/certs/$CLIENT.crt" ]
[ -f "$BUNDLE/keys/$GATEWAY.key" ]
[ -f "$BUNDLE/certs/$GATEWAY.crt" ]
[ -f "$SECOND_BUNDLE/$SECOND_CLIENT.ovpn" ]
[ -f "$SECOND_BUNDLE/certs/$SECOND_GATEWAY.crt" ]

grep -q "remote 127.0.0.1 32001" "$BUNDLE/$CLIENT.ovpn"
grep -q "key keys/$CLIENT.key" "$BUNDLE/$CLIENT.ovpn"

CLIENT_SUBJECT=$($OPENSSL x509 -in "$BUNDLE/certs/$CLIENT.crt" -noout -subject -nameopt RFC2253)
GATEWAY_SUBJECT=$($OPENSSL x509 -in "$BUNDLE/certs/$GATEWAY.crt" -noout -subject -nameopt RFC2253)
[ "$CLIENT_SUBJECT" = "subject=CN=$CLIENT" ]
[ "$GATEWAY_SUBJECT" = "subject=CN=$GATEWAY" ]

$OPENSSL verify -CAfile "$CA_DIR/ca.crt" "$BUNDLE/certs/$CLIENT.crt" >/dev/null
$OPENSSL verify -CAfile "$CA_DIR/ca.crt" "$BUNDLE/certs/$GATEWAY.crt" >/dev/null

echo "Dynamic identity helper tests passed."
