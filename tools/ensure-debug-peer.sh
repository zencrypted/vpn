#!/bin/sh
set -eu

OPENSSL="${OPENSSL3:-openssl}"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
INIT_CA="$SCRIPT_DIR/init-local-ca.sh"
OUTPUT_DIR="local/debug"
CA_DIR="local/ca"
NAME="peer_c"
FORCE=0

usage() {
    cat <<USAGE
Usage:
  $0 [--force] [--name <peer-name>]
     [--output-dir <relative-path>] [--ca-dir <relative-path>]

Ensures a stable RSA debug identity for a directly configured VPN peer.
Existing compatible material is reused. Unsupported or mismatched material is
replaced automatically because vpn_identity currently accepts RSA peer keys.
USAGE
}

fail() {
    echo "$1" >&2
    exit "${2:-1}"
}

validate_name() {
    case "$1" in
        ""|*[!A-Za-z0-9._-]*) fail "Unsafe name: use only letters, digits, dot, underscore and dash." 65 ;;
    esac
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --force)
            FORCE=1
            shift
            ;;
        --name)
            [ "$#" -ge 2 ] || fail "Missing value for --name." 64
            NAME="$2"
            shift 2
            ;;
        --output-dir)
            [ "$#" -ge 2 ] || fail "Missing value for --output-dir." 64
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --ca-dir)
            [ "$#" -ge 2 ] || fail "Missing value for --ca-dir." 64
            CA_DIR="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *) fail "Unknown option: $1" 64 ;;
    esac
done

validate_name "$NAME"
[ -x "$INIT_CA" ] || fail "Local CA initializer is not executable: $INIT_CA"

KEY_FILE="$OUTPUT_DIR/keys/$NAME.key"
CSR_FILE="$OUTPUT_DIR/csr/$NAME.csr"
CERT_FILE="$OUTPUT_DIR/certs/$NAME.crt"
CA_KEY="$CA_DIR/ca.key"
CA_CERT="$CA_DIR/ca.crt"
SERIAL_FILE="$CA_DIR/ca.srl"

if [ ! -f "$CA_KEY" ] || [ ! -f "$CA_CERT" ]; then
    if [ -e "$CA_KEY" ] || [ -e "$CA_CERT" ]; then
        fail "Local CA is incomplete in $CA_DIR; repair or remove it before debug bootstrap."
    fi
    "$INIT_CA" --output-dir "$CA_DIR"
fi

identity_is_compatible() {
    [ -f "$KEY_FILE" ] && [ ! -L "$KEY_FILE" ] || return 1
    [ -f "$CSR_FILE" ] && [ ! -L "$CSR_FILE" ] || return 1
    [ -f "$CERT_FILE" ] && [ ! -L "$CERT_FILE" ] || return 1

    "$OPENSSL" rsa -in "$KEY_FILE" -check -noout >/dev/null 2>&1 || return 1
    "$OPENSSL" verify -CAfile "$CA_CERT" -purpose sslclient "$CERT_FILE" >/dev/null 2>&1 || return 1

    cert_pub=$($OPENSSL x509 -in "$CERT_FILE" -pubkey -noout 2>/dev/null | \
        $OPENSSL pkey -pubin -outform DER 2>/dev/null | $OPENSSL dgst -sha256)
    key_pub=$($OPENSSL pkey -in "$KEY_FILE" -pubout -outform DER 2>/dev/null | \
        $OPENSSL dgst -sha256)
    [ -n "$cert_pub" ] && [ "$cert_pub" = "$key_pub" ]
}

if [ "$FORCE" -eq 0 ] && identity_is_compatible; then
    echo "Debug peer identity already exists: $CERT_FILE"
    echo "Reusing existing RSA peer identity. Use --force to replace it."
    exit 0
fi

if [ "$FORCE" -eq 0 ] && { [ -e "$KEY_FILE" ] || [ -e "$CSR_FILE" ] || [ -e "$CERT_FILE" ]; }; then
    echo "Replacing incompatible debug peer identity for $NAME." >&2
fi

rm -f -- "$KEY_FILE" "$CSR_FILE" "$CERT_FILE"
mkdir -p -- "$OUTPUT_DIR/keys" "$OUTPUT_DIR/csr" "$OUTPUT_DIR/certs"

EXT_FILE=$(mktemp)
cleanup() {
    status=$?
    rm -f -- "$EXT_FILE"
    if [ "$status" -ne 0 ]; then
        rm -f -- "$KEY_FILE" "$CSR_FILE" "$CERT_FILE"
    fi
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

"$OPENSSL" genpkey \
    -algorithm RSA \
    -pkeyopt rsa_keygen_bits:2048 \
    -out "$KEY_FILE"
chmod 600 "$KEY_FILE"

"$OPENSSL" req \
    -new \
    -key "$KEY_FILE" \
    -out "$CSR_FILE" \
    -subj "/CN=$NAME"
chmod 644 "$CSR_FILE"

cat > "$EXT_FILE" <<EOF_EXT
[v3_client]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
EOF_EXT

"$OPENSSL" x509 -req \
    -in "$CSR_FILE" \
    -CA "$CA_CERT" \
    -CAkey "$CA_KEY" \
    -CAserial "$SERIAL_FILE" \
    -CAcreateserial \
    -out "$CERT_FILE" \
    -days 365 \
    -sha384 \
    -extfile "$EXT_FILE" \
    -extensions v3_client
chmod 644 "$CERT_FILE"

identity_is_compatible || fail "Generated debug peer identity is not compatible."

trap - EXIT HUP INT TERM
rm -f -- "$EXT_FILE"

echo "Debug peer identity ready: $CERT_FILE"
