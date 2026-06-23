#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
TMP_DIR=$(mktemp -d)
cleanup() { rm -rf -- "$TMP_DIR"; }
trap cleanup EXIT HUP INT TERM

cd "$TMP_DIR"
OUT="debug"
CA="ca"

"$SCRIPT_DIR/ensure-debug-ovpn.sh" \
    --name client_a \
    --remote 127.0.0.1 \
    --port 5556 \
    --output-dir "$OUT" \
    --ca-dir "$CA" >/dev/null

[ -f "$OUT/client_a.ovpn" ]
[ -f "$OUT/keys/client_a.key" ]
[ -f "$OUT/csr/client_a.csr" ]
[ -f "$OUT/certs/client_a.crt" ]
[ "$(stat -c '%a' "$OUT/keys/client_a.key")" = "600" ]
grep -q '^remote 127.0.0.1 5556$' "$OUT/client_a.ovpn"
grep -q '^key keys/client_a.key$' "$OUT/client_a.ovpn"

KEY_BEFORE=$(sha256sum "$OUT/keys/client_a.key")
"$SCRIPT_DIR/ensure-debug-ovpn.sh" \
    --name client_a \
    --remote 127.0.0.1 \
    --port 5556 \
    --output-dir "$OUT" \
    --ca-dir "$CA" >/dev/null
KEY_AFTER=$(sha256sum "$OUT/keys/client_a.key")
[ "$KEY_BEFORE" = "$KEY_AFTER" ]

"$SCRIPT_DIR/ensure-debug-ovpn.sh" \
    --force \
    --name client_a \
    --remote 127.0.0.1 \
    --port 5556 \
    --output-dir "$OUT" \
    --ca-dir "$CA" >/dev/null
KEY_FORCED=$(sha256sum "$OUT/keys/client_a.key")
[ "$KEY_FORCED" != "$KEY_AFTER" ]

grep -q 'previous_epoch_grace_ms => 15000' "$REPO_DIR/config/sys.debug.config"

echo "Debug OVPN bootstrap tests passed."
