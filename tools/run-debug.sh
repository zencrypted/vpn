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
        echo "Prepares the complete two-slot debug topology, then starts the named VPN node."
        exit 0
        ;;
    *) echo "Unknown option: $1" >&2; exit 64 ;;
esac

cd "$REPO_DIR"
if [ -n "$FORCE_ARG" ]; then
    "$SCRIPT_DIR/prepare-debug-topology.sh" "$FORCE_ARG"
else
    "$SCRIPT_DIR/prepare-debug-topology.sh"
fi

if [ -z "${ERL_FLAGS:-}" ]; then
    ERL_FLAGS="-name vpn@127.0.0.1 -setcookie node_runner"
    export ERL_FLAGS
fi

printf '%s\n' \
    "Starting VPN debug node with prepared local identities." \
    "ERL_FLAGS=$ERL_FLAGS"

exec rebar3 as debug shell
