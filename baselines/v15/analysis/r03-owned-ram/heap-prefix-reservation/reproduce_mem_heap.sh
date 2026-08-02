#!/bin/sh
# Rebuild the exact public-SDK mem_heap object used by the v15 allocator audit.
# Usage: reproduce_mem_heap.sh SDK_ROOT PI32_CLANG OUTPUT_OBJECT
set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 SDK_ROOT PI32_CLANG OUTPUT_OBJECT" >&2
    exit 2
fi

SDK=$1
CLANG=$2
OUTPUT=$3
mkdir -p "$(dirname "$OUTPUT")"

FLAGS="-target pi32v2 -integrated-as -mcpu=r3 -mfprev1 -Wuninitialized -Wno-invalid-noreturn -fno-common -Oz -fallow-pointer-null -fprefer-gnu-section -femulated-tls -Wno-shift-negative-value -Wframe-larger-than=2560 -mllvm -pi32v2-large-program=true -fms-extensions -w"
INCLUDES="-I$SDK/include_lib/driver/cpu/wl82 -I$SDK/include_lib -I$SDK/include_lib/system -I$SDK/include_lib/newlib/include -I$SDK/apps/common/include -I$(dirname "$CLANG")/../include"

# shellcheck disable=SC2086
"$CLANG" $FLAGS $INCLUDES -DSUPPORT_MS_EXTENSIONS \
    -c "$SDK/apps/common/system/mem_heap.c" -o "$OUTPUT"

if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$OUTPUT" "$SDK/apps/common/system/mem_heap.c" "$CLANG"
else
    shasum -a 256 "$OUTPUT" "$SDK/apps/common/system/mem_heap.c" "$CLANG"
fi
