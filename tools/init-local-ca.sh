#!/bin/sh
set -eu

OPENSSL="${OPENSSL3:-openssl}"
OUTPUT_DIR="local/ca"
COMMON_NAME="VPN Local Development CA"
DAYS="3650"

usage() {
    cat <<USAGE
Usage:
  $0 [--output-dir <relative-path>] [--common-name <name>] [--days <number>]

Creates a local development CA for standalone VPN testing.
The CA private key must never be committed or used outside development.

Environment:
  OPENSSL3    OpenSSL executable to use. Defaults to openssl.
USAGE
}

fail() {
    echo "$1" >&2
    exit "${2:-1}"
}

validate_relative_path() {
    value="$1"
    label="$2"
    case "$value" in
        "") fail "$label must not be empty." 65 ;;
        /*|*\\*) fail "$label must be a relative POSIX path." 65 ;;
        *[!A-Za-z0-9._/-]*) fail "$label contains unsupported characters." 65 ;;
    esac
    case "/$value/" in
        *"//"*|*"/./"*|*"/../"*) fail "$label contains an unsafe path segment." 65 ;;
    esac
}

validate_days() {
    case "$1" in
        ""|*[!0-9]*) fail "Days must be a positive integer." 65 ;;
    esac
    [ "$1" -gt 0 ] || fail "Days must be greater than zero." 65
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --output-dir)
            [ "$#" -ge 2 ] || fail "Missing value for --output-dir." 64
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --common-name)
            [ "$#" -ge 2 ] || fail "Missing value for --common-name." 64
            COMMON_NAME="$2"
            shift 2
            ;;
        --days)
            [ "$#" -ge 2 ] || fail "Missing value for --days." 64
            DAYS="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *) fail "Unknown option: $1" 64 ;;
    esac
done

validate_relative_path "$OUTPUT_DIR" "Output directory"
[ -n "$COMMON_NAME" ] || fail "Common name must not be empty." 65
CR=$(printf '\r')
NL='
'
case "$COMMON_NAME" in
    *"$CR"*|*"$NL"*) fail "Common name must be a single line." 65 ;;
esac
validate_days "$DAYS"

KEY_FILE="$OUTPUT_DIR/ca.key"
CERT_FILE="$OUTPUT_DIR/ca.crt"
SERIAL_FILE="$OUTPUT_DIR/ca.srl"

if [ -e "$KEY_FILE" ] || [ -L "$KEY_FILE" ] || [ -e "$CERT_FILE" ] || [ -L "$CERT_FILE" ]; then
    fail "Refusing to overwrite an existing local CA."
fi

mkdir -p -- "$OUTPUT_DIR"
CONF_FILE=$(mktemp)
cleanup() {
    status=$?
    rm -f -- "$CONF_FILE"
    if [ "$status" -ne 0 ]; then
        rm -f -- "$KEY_FILE" "$CERT_FILE" "$SERIAL_FILE"
    fi
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

cat > "$CONF_FILE" <<EOF_CONF
[req]
distinguished_name = dn
x509_extensions = v3_ca
prompt = no

[dn]
CN = $COMMON_NAME

[v3_ca]
basicConstraints = critical,CA:TRUE,pathlen:0
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
EOF_CONF

"$OPENSSL" ecparam -name secp384r1 -genkey -noout -out "$KEY_FILE"
chmod 600 "$KEY_FILE"

"$OPENSSL" req -new -x509 \
    -key "$KEY_FILE" \
    -out "$CERT_FILE" \
    -days "$DAYS" \
    -sha384 \
    -config "$CONF_FILE"
chmod 644 "$CERT_FILE"

"$OPENSSL" x509 -in "$CERT_FILE" -noout -subject -issuer >/dev/null
"$OPENSSL" verify -CAfile "$CERT_FILE" "$CERT_FILE" >/dev/null

trap - EXIT HUP INT TERM
rm -f -- "$CONF_FILE"

echo "WARNING: local development CA only; do not use in production."
echo "CA private key: $KEY_FILE"
echo "CA certificate: $CERT_FILE"
