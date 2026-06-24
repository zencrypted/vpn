#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ENSURE_OVPN="$SCRIPT_DIR/ensure-debug-ovpn.sh"
ENSURE_PEER="$SCRIPT_DIR/ensure-debug-peer.sh"
ALLOCATION_ID=""
CLIENT_PEER_ID=""
GATEWAY_PEER_ID=""
REMOTE=""
GATEWAY_PORT=""
OUTPUT_DIR=""
CA_DIR=""

usage() {
    cat <<USAGE
Usage:
  $0 --allocation-id <safe-id>
     --client-peer-id <safe-id> --gateway-peer-id <safe-id>
     --remote <host> --gateway-port <1-65535>
     --output-dir <relative-path> --ca-dir <relative-path>

Creates or reuses development-only identity material for one dynamic VPN
allocation. The client receives a canonical OVPN envelope and EC private key;
the gateway receives a directly configured RSA identity. The local development
CA is reused and never copied into allocator state.
USAGE
}

fail() {
    echo "$1" >&2
    exit "${2:-1}"
}

safe_name() {
    case "$1" in
        ""|*[!A-Za-z0-9._-]*) fail "Unsafe identifier: $1" 65 ;;
    esac
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --allocation-id)
            [ "$#" -ge 2 ] || fail "Missing value for --allocation-id." 64
            ALLOCATION_ID="$2"
            shift 2
            ;;
        --client-peer-id)
            [ "$#" -ge 2 ] || fail "Missing value for --client-peer-id." 64
            CLIENT_PEER_ID="$2"
            shift 2
            ;;
        --gateway-peer-id)
            [ "$#" -ge 2 ] || fail "Missing value for --gateway-peer-id." 64
            GATEWAY_PEER_ID="$2"
            shift 2
            ;;
        --remote)
            [ "$#" -ge 2 ] || fail "Missing value for --remote." 64
            REMOTE="$2"
            shift 2
            ;;
        --gateway-port)
            [ "$#" -ge 2 ] || fail "Missing value for --gateway-port." 64
            GATEWAY_PORT="$2"
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

[ -n "$ALLOCATION_ID" ] && [ -n "$CLIENT_PEER_ID" ] &&
[ -n "$GATEWAY_PEER_ID" ] && [ -n "$REMOTE" ] &&
[ -n "$GATEWAY_PORT" ] && [ -n "$OUTPUT_DIR" ] && [ -n "$CA_DIR" ] || {
    usage >&2
    exit 64
}

safe_name "$ALLOCATION_ID"
safe_name "$CLIENT_PEER_ID"
safe_name "$GATEWAY_PEER_ID"
[ -x "$ENSURE_OVPN" ] || fail "OVPN identity helper is not executable: $ENSURE_OVPN"
[ -x "$ENSURE_PEER" ] || fail "Gateway identity helper is not executable: $ENSURE_PEER"

"$ENSURE_OVPN" \
    --name "$CLIENT_PEER_ID" \
    --remote "$REMOTE" \
    --port "$GATEWAY_PORT" \
    --output-dir "$OUTPUT_DIR" \
    --ca-dir "$CA_DIR"

"$ENSURE_PEER" \
    --name "$GATEWAY_PEER_ID" \
    --output-dir "$OUTPUT_DIR" \
    --ca-dir "$CA_DIR"

printf 'Dynamic identity bundle ready: %s (%s <-> %s)\n' \
    "$ALLOCATION_ID" "$CLIENT_PEER_ID" "$GATEWAY_PEER_ID"
