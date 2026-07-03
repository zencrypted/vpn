#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/openssl-env.sh"
GENERATOR="$SCRIPT_DIR/generate-device-csr.sh"
WORK_DIR=$(mktemp -d)
trap 'rm -rf "$WORK_DIR"' EXIT HUP INT TERM

cd "$WORK_DIR"

"$GENERATOR" laptop >/dev/null
KEY=$(find keys -type f -name 'laptop-*.key' -print)
CSR=$(find csr -type f -name 'laptop-*.csr' -print)
[ -f "$KEY" ]
[ -f "$CSR" ]
[ "$(stat -c '%a' "$KEY")" = "600" ]
[ "$(stat -c '%a' "$CSR")" = "644" ]
"$OPENSSL" req -in "$CSR" -noout -verify -subject | grep 'subject=CN=laptop' >/dev/null

"$GENERATOR" \
    --common-name laptop-plan-001 \
    --key-file local/keys/laptop-plan-001.key \
    --csr-file local/csr/laptop-plan-001.csr >/dev/null

[ -f local/keys/laptop-plan-001.key ]
[ -f local/csr/laptop-plan-001.csr ]
"$OPENSSL" req -in local/csr/laptop-plan-001.csr -noout -verify -subject \
    | grep 'subject=CN=laptop-plan-001' >/dev/null

if "$GENERATOR" \
    --common-name bad \
    --key-file ../escape.key \
    --csr-file safe.csr >/dev/null 2>&1; then
    echo "unsafe path was accepted" >&2
    exit 1
fi

if "$GENERATOR" \
    --common-name bad \
    --key-file safe//escape.key \
    --csr-file safe.csr >/dev/null 2>&1; then
    echo "path with an empty segment was accepted" >&2
    exit 1
fi

if "$GENERATOR" \
    --common-name laptop-plan-001 \
    --key-file local/keys/laptop-plan-001.key \
    --csr-file local/csr/laptop-plan-001.csr >/dev/null 2>&1; then
    echo "existing files were overwritten" >&2
    exit 1
fi

echo "generate-device-csr.sh tests passed"
