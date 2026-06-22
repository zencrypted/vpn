#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
INIT_CA="$SCRIPT_DIR/init-local-ca.sh"
GENERATE_OVPN="$SCRIPT_DIR/generate-local-ovpn.sh"
OUTPUT_DIR="local/debug"
CA_DIR="local/ca"
NAME="client_a"
REMOTE="127.0.0.1"
PORT="5556"
FORCE=0

usage() {
    cat <<USAGE
Usage:
  $0 [--force]
     [--name <peer-name>] [--remote <host>] [--port <1-65535>]
     [--output-dir <relative-path>] [--ca-dir <relative-path>]

Ensures that a stable development OVPN bundle exists. Existing complete
material is reused. --force replaces only the selected Device bundle; it does
not rotate the local development CA.
USAGE
}

fail() {
    echo "$1" >&2
    exit "${2:-1}"
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
        -h|--help)
            usage
            exit 0
            ;;
        *) fail "Unknown option: $1" 64 ;;
    esac
done

[ -x "$INIT_CA" ] || fail "Local CA initializer is not executable: $INIT_CA"
[ -x "$GENERATE_OVPN" ] || fail "Local OVPN generator is not executable: $GENERATE_OVPN"

KEY_FILE="$OUTPUT_DIR/keys/$NAME.key"
CSR_FILE="$OUTPUT_DIR/csr/$NAME.csr"
CERT_FILE="$OUTPUT_DIR/certs/$NAME.crt"
OVPN_FILE="$OUTPUT_DIR/$NAME.ovpn"

if [ ! -f "$CA_DIR/ca.key" ] || [ ! -f "$CA_DIR/ca.crt" ]; then
    if [ -e "$CA_DIR/ca.key" ] || [ -e "$CA_DIR/ca.crt" ]; then
        fail "Local CA is incomplete in $CA_DIR; repair or remove it before debug bootstrap."
    fi
    "$INIT_CA" --output-dir "$CA_DIR"
fi

complete=1
for path in "$KEY_FILE" "$CSR_FILE" "$CERT_FILE" "$OVPN_FILE"; do
    [ -f "$path" ] && [ ! -L "$path" ] || complete=0
done

if [ "$complete" -eq 1 ] && [ "$FORCE" -eq 0 ]; then
    echo "Debug OVPN already exists: $OVPN_FILE"
    echo "Reusing existing Device identity. Use --force to replace it."
    exit 0
fi

if [ "$complete" -eq 0 ] && [ "$FORCE" -eq 0 ]; then
    found=0
    for path in "$KEY_FILE" "$CSR_FILE" "$CERT_FILE" "$OVPN_FILE"; do
        if [ -e "$path" ] || [ -L "$path" ]; then
            found=1
        fi
    done
    [ "$found" -eq 0 ] || fail "Debug bundle is incomplete in $OUTPUT_DIR; use --force to replace it."
fi

if [ "$FORCE" -eq 1 ]; then
    rm -f -- "$KEY_FILE" "$CSR_FILE" "$CERT_FILE" "$OVPN_FILE"
fi

"$GENERATE_OVPN" \
    --name "$NAME" \
    --basename "$NAME" \
    --remote "$REMOTE" \
    --port "$PORT" \
    --output-dir "$OUTPUT_DIR" \
    --ca-dir "$CA_DIR"

echo "Debug OVPN ready: $OVPN_FILE"
