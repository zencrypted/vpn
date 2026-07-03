#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/openssl-env.sh"
CSR_GENERATOR="$SCRIPT_DIR/generate-device-csr.sh"
NAME=""
REMOTE=""
PORT=""
OUTPUT_DIR="local"
CA_DIR="local/ca"
DAYS="365"
BASENAME=""

usage() {
    cat <<USAGE
Usage:
  $0 --name <peer-name> --remote <host> --port <1-65535>
     [--output-dir <relative-path>] [--ca-dir <relative-path>] [--days <number>]
     [--basename <safe-name>]

Creates a Device-local EC P-384 key, CSR, CA-signed client certificate,
and canonical OVPN envelope without IAS. Initialize the local CA first:

  ./tools/init-local-ca.sh

Environment:
  OPENSSL3    OpenSSL executable to use. Defaults to openssl.
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

validate_remote() {
    case "$1" in
        ""|*[!A-Za-z0-9._:-]*) fail "Remote host contains unsupported characters." 65 ;;
    esac
}

validate_positive_integer() {
    value="$1"
    label="$2"
    case "$value" in
        ""|*[!0-9]*) fail "$label must be a positive integer." 65 ;;
    esac
    [ "$value" -gt 0 ] || fail "$label must be greater than zero." 65
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --name)
            [ "$#" -ge 2 ] || fail "Missing value for --name." 64
            NAME="$2"
            shift 2
            ;;
        --remote)
            [ "$#" -ge 2 ] || fail "Missing value for --remote." 64
            REMOTE="$2"
            shift 2
            ;;
        --port)
            [ "$#" -ge 2 ] || fail "Missing value for --port." 64
            PORT="$2"
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
        --days)
            [ "$#" -ge 2 ] || fail "Missing value for --days." 64
            DAYS="$2"
            shift 2
            ;;
        --basename)
            [ "$#" -ge 2 ] || fail "Missing value for --basename." 64
            BASENAME="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *) fail "Unknown option: $1" 64 ;;
    esac
done

[ -n "$NAME" ] && [ -n "$REMOTE" ] && [ -n "$PORT" ] || {
    usage >&2
    exit 64
}

validate_name "$NAME"
if [ -n "$BASENAME" ]; then
    validate_name "$BASENAME"
fi
validate_remote "$REMOTE"
validate_positive_integer "$PORT" "Port"
[ "$PORT" -le 65535 ] || fail "Port must not exceed 65535." 65
validate_positive_integer "$DAYS" "Days"
validate_relative_path "$OUTPUT_DIR" "Output directory"
validate_relative_path "$CA_DIR" "CA directory"

CA_KEY="$CA_DIR/ca.key"
CA_CERT="$CA_DIR/ca.crt"
[ -f "$CA_KEY" ] && [ ! -L "$CA_KEY" ] || fail "Local CA private key not found: $CA_KEY. Run ./tools/init-local-ca.sh first."
[ -f "$CA_CERT" ] && [ ! -L "$CA_CERT" ] || fail "Local CA certificate not found: $CA_CERT. Run ./tools/init-local-ca.sh first."
[ -x "$CSR_GENERATOR" ] || fail "CSR generator is not executable: $CSR_GENERATOR"

if [ -z "$BASENAME" ]; then
    STAMP=$(date +%Y%m%d-%H%M%S)
    BASENAME="${NAME}-${STAMP}"
fi
KEY_FILE="$OUTPUT_DIR/keys/${BASENAME}.key"
CSR_FILE="$OUTPUT_DIR/csr/${BASENAME}.csr"
CERT_FILE="$OUTPUT_DIR/certs/${BASENAME}.crt"
OVPN_FILE="$OUTPUT_DIR/${BASENAME}.ovpn"
KEY_REF="keys/${BASENAME}.key"
SERIAL_FILE="$CA_DIR/ca.srl"

for path in "$CERT_FILE" "$OVPN_FILE"; do
    if [ -e "$path" ] || [ -L "$path" ]; then
        fail "Refusing to overwrite existing output: $path"
    fi
done

mkdir -p -- "$OUTPUT_DIR/certs"
EXT_FILE=$(mktemp)
cleanup() {
    status=$?
    rm -f -- "$EXT_FILE"
    if [ "$status" -ne 0 ]; then
        rm -f -- "$KEY_FILE" "$CSR_FILE" "$CERT_FILE" "$OVPN_FILE"
    fi
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

"$CSR_GENERATOR" \
    --common-name "$BASENAME" \
    --key-file "$KEY_FILE" \
    --csr-file "$CSR_FILE" >/dev/null

cat > "$EXT_FILE" <<EOF_EXT
[v3_client]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
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
    -days "$DAYS" \
    -sha384 \
    -extfile "$EXT_FILE" \
    -extensions v3_client
chmod 644 "$CERT_FILE"

"$OPENSSL" verify -CAfile "$CA_CERT" -purpose sslclient "$CERT_FILE" >/dev/null
CERT_PUB=$("$OPENSSL" x509 -in "$CERT_FILE" -pubkey -noout | "$OPENSSL" pkey -pubin -outform DER | "$OPENSSL" dgst -sha256)
KEY_PUB=$("$OPENSSL" pkey -in "$KEY_FILE" -pubout -outform DER | "$OPENSSL" dgst -sha256)
[ "$CERT_PUB" = "$KEY_PUB" ] || fail "Generated certificate does not match the private key."

{
    echo "client"
    echo "dev tun"
    echo "proto udp"
    echo "remote $REMOTE $PORT"
    echo
    echo "nobind"
    echo "persist-key"
    echo "persist-tun"
    echo "remote-cert-tls server"
    echo
    echo "<ca>"
    cat "$CA_CERT"
    echo "</ca>"
    echo
    echo "<cert>"
    cat "$CERT_FILE"
    echo "</cert>"
    echo
    echo "key $KEY_REF"
} > "$OVPN_FILE"
chmod 644 "$OVPN_FILE"

trap - EXIT HUP INT TERM
rm -f -- "$EXT_FILE"

echo "Private key: $KEY_FILE"
echo "CSR: $CSR_FILE"
echo "Certificate: $CERT_FILE"
echo "OVPN: $OVPN_FILE"
