#!/bin/sh
set -eu

OPENSSL="${OPENSSL3:-openssl}"

usage() {
    cat <<USAGE
Usage:
  $0 <name>
  $0 --common-name <name> --key-file <relative-path> --csr-file <relative-path>

Modes:
  <name>
      Generates timestamped files under keys/ and csr/.

  --common-name, --key-file, --csr-file
      Generates exactly the filenames selected by an IAS provisioning plan.
      All three options are required together.

Environment:
  OPENSSL3
      OpenSSL executable to use. Defaults to openssl.
USAGE
}

fail() {
    echo "$1" >&2
    exit "${2:-1}"
}

validate_name() {
    value="$1"
    case "$value" in
        ""|*[!A-Za-z0-9._-]*)
            fail "Unsafe common name: use only letters, digits, dot, underscore and dash." 65
            ;;
    esac
}

validate_relative_path() {
    value="$1"
    label="$2"

    case "$value" in
        "") fail "$label must not be empty." 65 ;;
        /*) fail "$label must be a relative path." 65 ;;
        *\\*) fail "$label must use '/' separators." 65 ;;
        *[!A-Za-z0-9._/-]*)
            fail "$label contains unsupported characters." 65
            ;;
    esac

    case "/$value/" in
        *"//"*|*"/./"*|*"/../"*)
            fail "$label must not contain empty, '.' or '..' path segments." 65
            ;;
    esac

    old_ifs=$IFS
    IFS='/ '
    set -- $value
    IFS=$old_ifs

    [ "$#" -gt 0 ] || fail "$label must contain at least one path segment." 65
    for segment in "$@"; do
        case "$segment" in
            ""|.|..)
                fail "$label must not contain empty, '.' or '..' path segments." 65
                ;;
        esac
    done
}

COMMON_NAME=""
KEY_FILE=""
CSR_FILE=""

case "$#" in
    1)
        case "$1" in
            -h|--help)
                usage
                exit 0
                ;;
            --*)
                usage >&2
                exit 64
                ;;
        esac

        COMMON_NAME="$1"
        validate_name "$COMMON_NAME"

        STAMP="$(date +%Y%m%d-%H%M%S)"
        BASENAME="${COMMON_NAME}-${STAMP}"
        KEY_FILE="keys/${BASENAME}.key"
        CSR_FILE="csr/${BASENAME}.csr"
        ;;
    *)
        while [ "$#" -gt 0 ]; do
            case "$1" in
                --common-name)
                    [ "$#" -ge 2 ] || fail "Missing value for --common-name." 64
                    [ -z "$COMMON_NAME" ] || fail "Duplicate --common-name option." 64
                    COMMON_NAME="$2"
                    shift 2
                    ;;
                --key-file)
                    [ "$#" -ge 2 ] || fail "Missing value for --key-file." 64
                    [ -z "$KEY_FILE" ] || fail "Duplicate --key-file option." 64
                    KEY_FILE="$2"
                    shift 2
                    ;;
                --csr-file)
                    [ "$#" -ge 2 ] || fail "Missing value for --csr-file." 64
                    [ -z "$CSR_FILE" ] || fail "Duplicate --csr-file option." 64
                    CSR_FILE="$2"
                    shift 2
                    ;;
                -h|--help)
                    usage
                    exit 0
                    ;;
                *)
                    fail "Unknown option: $1" 64
                    ;;
            esac
        done

        [ -n "$COMMON_NAME" ] && [ -n "$KEY_FILE" ] && [ -n "$CSR_FILE" ] || {
            usage >&2
            exit 64
        }

        validate_name "$COMMON_NAME"
        validate_relative_path "$KEY_FILE" "Private-key path"
        validate_relative_path "$CSR_FILE" "CSR path"
        ;;
esac

validate_relative_path "$KEY_FILE" "Private-key path"
validate_relative_path "$CSR_FILE" "CSR path"

KEY_PARENT=$(dirname -- "$KEY_FILE")
CSR_PARENT=$(dirname -- "$CSR_FILE")
mkdir -p -- "$KEY_PARENT" "$CSR_PARENT"

if [ -e "$KEY_FILE" ] || [ -L "$KEY_FILE" ] || [ -e "$CSR_FILE" ] || [ -L "$CSR_FILE" ]; then
    fail "Refusing to overwrite an existing key or CSR file."
fi

cleanup() {
    status=$?
    if [ "$status" -ne 0 ]; then
        rm -f -- "$KEY_FILE" "$CSR_FILE"
    fi
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

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
    -subj "/CN=$COMMON_NAME"

chmod 644 "$CSR_FILE"

"$OPENSSL" req \
    -verify \
    -noout \
    -in "$CSR_FILE"

trap - EXIT HUP INT TERM

echo "Private key: $KEY_FILE"
echo "CSR: $CSR_FILE"
