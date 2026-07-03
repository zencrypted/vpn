#!/bin/sh

# Resolve a usable OpenSSL executable and, for locally installed builds,
# expose sibling lib64/lib directories to the dynamic loader.
OPENSSL=${OPENSSL3:-${OPENSSL:-}}
if [ -z "$OPENSSL" ]; then
    OPENSSL=$(command -v openssl 2>/dev/null || true)
fi
if [ -z "$OPENSSL" ]; then
    echo "OpenSSL executable was not found." >&2
    exit 127
fi

case "$OPENSSL" in
    */*)
        OPENSSL_DIR=$(CDPATH= cd -- "$(dirname -- "$OPENSSL")" && pwd)
        OPENSSL_PREFIX=$(CDPATH= cd -- "$OPENSSL_DIR/.." && pwd)
        OPENSSL_LIB_PATH=""
        for candidate in "$OPENSSL_PREFIX/lib64" "$OPENSSL_PREFIX/lib"; do
            if [ -d "$candidate" ]; then
                if [ -n "$OPENSSL_LIB_PATH" ]; then
                    OPENSSL_LIB_PATH="$OPENSSL_LIB_PATH:$candidate"
                else
                    OPENSSL_LIB_PATH="$candidate"
                fi
            fi
        done
        if [ -n "$OPENSSL_LIB_PATH" ]; then
            if [ -n "${LD_LIBRARY_PATH:-}" ]; then
                LD_LIBRARY_PATH="$OPENSSL_LIB_PATH:$LD_LIBRARY_PATH"
            else
                LD_LIBRARY_PATH="$OPENSSL_LIB_PATH"
            fi
            export LD_LIBRARY_PATH
        fi
        ;;
esac

export OPENSSL
