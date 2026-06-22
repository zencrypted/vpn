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
        echo "Ensures local/debug/client_a.ovpn and starts rebar3 with config/sys.debug.config."
        exit 0
        ;;
    *) echo "Unknown option: $1" >&2; exit 64 ;;
esac

cd "$REPO_DIR"
if [ -n "$FORCE_ARG" ]; then
    "$SCRIPT_DIR/ensure-debug-ovpn.sh" "$FORCE_ARG"
else
    "$SCRIPT_DIR/ensure-debug-ovpn.sh"
fi

exec rebar3 as debug shell
