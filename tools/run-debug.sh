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
        echo "Ensures the two client slots and their gateway identity, then starts rebar3 with config/sys.debug.config."
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

cd "$REPO_DIR"
ensure_identity client_a 5556
ensure_identity client_b 5557
ensure_identity peer_c 5562

exec rebar3 as debug shell
