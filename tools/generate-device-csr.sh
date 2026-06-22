#!/bin/sh
set -eu

OPENSSL="${OPENSSL3:-openssl}"

if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <name>" >&2
    exit 64
fi

NAME="$1"

case "$NAME" in
    ""|*[!A-Za-z0-9._-]*)
        echo "Unsafe name: use only letters, digits, dot, underscore and dash." >&2
        exit 65
        ;;
esac

STAMP="$(date +%Y%m%d-%H%M%S)"
BASENAME="${NAME}-${STAMP}"

KEY_DIR="keys"
CSR_DIR="csr"

KEY_FILE="${KEY_DIR}/${BASENAME}.key"
CSR_FILE="${CSR_DIR}/${BASENAME}.csr"

mkdir -p "$KEY_DIR" "$CSR_DIR"

if [ -e "$KEY_FILE" ] || [ -e "$CSR_FILE" ]; then
    echo "Refusing to overwrite existing files." >&2
    exit 1
fi

"$OPENSSL" ecparam \
    -name secp384r1 \
    -genkey \
    -noout \
    -out "$KEY_FILE"

chmod 600 "$KEY_FILE"

"$OPENSSL" req \
    -new \
    -key "$KEY_FILE" \
    -out "$CSR_FILE" \
    -subj "/CN=$NAME"

"$OPENSSL" req \
    -verify \
    -noout \
    -in "$CSR_FILE" >/dev/null

echo "Private key: $KEY_FILE"
echo "CSR: $CSR_FILE"