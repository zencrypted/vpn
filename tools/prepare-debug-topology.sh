#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
REPO_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
FORCE_ARG=""

case "${1:-}" in
    "") ;;
    --force) FORCE_ARG="--force" ;;
    -h|--help)
        echo "Usage: $0 [--force]"
        echo "Ensures the complete two-slot debug identity topology without starting Erlang."
        exit 0
        ;;
    *) echo "Unknown option: $1" >&2; exit 64 ;;
esac

ensure_identity() {
    name="$1"
    port="$2"
    if [ -n "$FORCE_ARG" ]; then
        "$SCRIPT_DIR/ensure-debug-ovpn.sh" "$FORCE_ARG" --name "$name" --port "$port"
    else
        "$SCRIPT_DIR/ensure-debug-ovpn.sh" --name "$name" --port "$port"
    fi
}

require_file() {
    path="$1"
    [ -f "$path" ] && [ ! -L "$path" ] || {
        echo "Debug topology file is missing or unsafe: $path" >&2
        exit 1
    }
}

cd "$REPO_DIR"
ensure_identity client_a 5556
ensure_identity client_b 5557
ensure_identity peer_c 5562

for name in client_a client_b peer_c; do
    require_file "local/debug/$name.ovpn"
    require_file "local/debug/keys/$name.key"
    require_file "local/debug/certs/$name.crt"
done

printf '%s\n' \
    "Debug VPN topology is ready:" \
    "  client_a <-> peer_b" \
    "  client_b <-> peer_c"
