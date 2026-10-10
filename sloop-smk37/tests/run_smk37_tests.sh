#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# SLOOP for SMK-37 Pro: host tests (no hardware, no device).
#   tests/run_smk37_tests.sh
#   SLOOP_SRC=/path/to/sloop-fm1   (default: upstream/sloop-fm1, fetched at the
#                                   pin in ../SLOOP_PIN by tools/fetch_sloop.py)
#   SKIP_UI=1                      only the board-map test (no Pillow needed)
#
# 1. panel_smk37_test   the SMK-37 board map: pads carry the nine FM-1 buttons
#                       the panel has no silkscreen for, the 27-key window,
#                       matrix bijectivity, calibration fallback.
# 2. ui_pages_smk37_test  upstream's live-UI fuzz (tests/ui_pages_test.c of the
#                       pinned SLOOP) compiled with THIS port's panel: every
#                       page, layer, hold and 20000 random frames must behave
#                       exactly as on the FM-1. Needs Pillow for the generated
#                       font / icons / logo headers.
set -e
cd "$(dirname "$0")/.."
PORT=$(pwd)
OUT=build/host
GEN=build/gen
mkdir -p "$OUT" "$GEN"
CC="${CC:-cc} -O1 -Wall -Wno-unused-function"
fail=0
run() { echo "== $1"; shift; "$@" || fail=1; }

if [ -z "$SLOOP_SRC" ]; then
    if [ ! -f upstream/sloop-fm1/firmware/src/felucca.c ]; then
        python3 tools/fetch_sloop.py
    fi
    SLOOP_SRC="$PORT/upstream/sloop-fm1"
fi
PIN=$(awk '{print $1; exit}' SLOOP_PIN)
GOT=$(git -C "$SLOOP_SRC" rev-parse HEAD 2>/dev/null || echo unknown)
[ "$GOT" = "$PIN" ] || echo "warning: SLOOP_SRC is $GOT, pin is $PIN"

# generated headers the UI needs (tables and FM6 patches need no Pillow)
[ -f "$GEN/felucca_tables.h" ] || python3 "$SLOOP_SRC/tools/gen_tables.py" "$GEN/felucca_tables.h"
[ -f "$GEN/felucca_fm6.h" ] || python3 "$SLOOP_SRC/tools/gen_fm6_patches.py" "$GEN/felucca_fm6.h"

$CC -Iboard/hal -o "$OUT/panel_smk37_test" tests/panel_smk37_test.c
run "SMK-37 board map (pads = the missing FM-1 buttons, LED map)" "$OUT/panel_smk37_test"

if [ "$SKIP_UI" != 1 ]; then
    for g in "gen_font.py felucca_font.h" "gen_icons.py felucca_icons.h" \
             "gen_samples.py felucca_samples.h" "gen_drumkits.py felucca_drumkits.h" \
             "gen_logo.py sloop_logo.h"; do
        set -- $g
        [ -f "$GEN/$2" ] || python3 "$SLOOP_SRC/tools/$1" "$GEN/$2" || {
            echo "note: $1 needs Pillow; skipping the UI test (SKIP_UI=1 silences this)"
            exit $fail
        }
    done
    # the whole SLOOP unity TU against this port's HAL and panel: every
    # interface name and type the core uses must resolve (syntax only; the
    # pi32v2 build itself runs in build_smk37.py on the owner's toolchain)
    run "unity TU compiles against the SMK-37 HAL (syntax)" \
        sh tests/unity_syntax.sh "$SLOOP_SRC" "$GEN"
    $CC -O2 -w -Iboard/hal -Iboard/src -I"$SLOOP_SRC/tests" -I"$SLOOP_SRC/firmware/src" \
        -I"$GEN" -o "$OUT/ui_pages_smk37_test" tests/ui_pages_smk37_test.c -lm
    mkdir -p "$OUT/ppm"
    run "live UI on the SMK-37 panel (upstream fuzz, this port's mapping)" \
        "$OUT/ui_pages_smk37_test" "$OUT/ppm"
fi
[ $fail -eq 0 ] && echo "sloop-smk37: host tests PASS" || echo "sloop-smk37: FAILURES"
exit $fail
