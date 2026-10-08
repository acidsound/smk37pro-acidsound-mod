#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# SLOOP for SMK-37 Pro: compile the whole SLOOP unity TU (felucca.c, with the
# port's HAL and panel first on the include path) for syntax and types only.
# Flags match tools/build_smk37.py FLAGS (FELUCCA_FLASH=0 on purpose).
# Every interface name the core uses from the HAL must resolve here. Host
# 'cc' is enough; the pi32v2 build runs in tools/build_smk37.py.
#   usage: tests/unity_syntax.sh <SLOOP_SRC> <generated-header-dir>
set -e
SLOOP_SRC=$1
GEN=$2
PORT=$(cd "$(dirname "$0")/.." && pwd)
cd "$PORT"
exec cc -fsyntax-only -Wall -Wno-unused-function \
    -Wno-int-to-pointer-cast -Wno-pointer-to-int-cast -Wno-builtin-declaration-mismatch \
    -DFELUCCA_FLASH=0 -DFELUCCA_OTA=0 -DFELUCCA_CDC=1 -DFELUCCA_UART=0 -DFELUCCA_UAC=1 \
    '-DFELUCCA_ID="SMK37_900"' \
    -Iboard/hal -Iboard/src -I"$SLOOP_SRC/firmware/hal" -I"$SLOOP_SRC/firmware/src" \
    -I"$GEN" -I"$SLOOP_SRC/tests" \
    -x c "$SLOOP_SRC/firmware/src/felucca.c"
