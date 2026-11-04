#!/bin/sh
set -eu

usage() {
    cat >&2 <<'EOF'
Usage: extract-yabbt.sh ARCHIVE OUT_DIR

Extract a yabbt archive using standard CLI tools:

  age --decrypt ARCHIVE | zstd -d | tar -x -C OUT_DIR
EOF
}

die() {
    printf '%s\n' "$*" >&2
    exit 1
}

require_command() {
    command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

[ "$#" -eq 2 ] || {
    usage
    exit 2
}

archive=$1
out_dir=$2

[ -f "$archive" ] || die "archive does not exist: $archive"

require_command age
require_command zstd
require_command tar

mkdir -p -- "$out_dir"

age --decrypt "$archive" | zstd -d | tar -x -C "$out_dir"
