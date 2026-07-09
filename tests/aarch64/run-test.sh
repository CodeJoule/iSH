#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ISH="${ISH:-$ROOT/build/ish}"
HELLO="$ROOT/tests/aarch64/hello"

if [[ ! -x "$ISH" ]]; then
    echo "aarch64 ish binary not found at $ISH" >&2
    exit 1
fi

if [[ ! -f "$HELLO" ]]; then
  clang -target aarch64-linux -fuse-ld=lld -nostdlib -static \
    -o "$HELLO" "$ROOT/tests/aarch64/hello.S"
fi

EXIT42="$ROOT/tests/aarch64/exit42"
if [[ ! -f "$EXIT42" ]]; then
  clang -target aarch64-linux -fuse-ld=lld -nostdlib -static \
    -o "$EXIT42" "$ROOT/tests/aarch64/exit42.S"
fi

out="$("$ISH" "$HELLO" 2>/dev/null)"
test "$out" = "hello"

"$ISH" "$EXIT42" 2>/dev/null || rc=$?
test "${rc:-0}" = "42"
