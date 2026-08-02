#!/bin/bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../../../../../" && pwd)"
DIR="$ROOT/baselines/v15/analysis/r03-owned-ram/atomic-publish"
VM=jcode-pi32
VM_HOME=/home/spectrum.guest
TOOLCHAIN=$VM_HOME/jieli-toolchain/common/bin
SOURCE_B64="$(base64 < "$DIR/r03-trylock.c" | tr -d '\n')"

limactl shell "$VM" -- bash -lc \
  "printf '%s' '$SOURCE_B64' | base64 -d > $VM_HOME/r03-trylock.c && \
   $TOOLCHAIN/clang -target pi32v2 -O2 -c $VM_HOME/r03-trylock.c -o $VM_HOME/r03-trylock.o && \
   $TOOLCHAIN/objdump -d $VM_HOME/r03-trylock.o > $VM_HOME/r03-trylock.objdump"

OBJECT_B64="$(limactl shell "$VM" -- bash -lc "base64 -w0 $VM_HOME/r03-trylock.o")"
OBJDUMP="$(limactl shell "$VM" -- bash -lc "cat $VM_HOME/r03-trylock.objdump")"
REBUILT="$JCODE_SCRATCH_DIR/r03-trylock-rebuilt.pi32.o"
printf '%s' "$OBJECT_B64" | base64 -d > "$REBUILT"
cmp "$REBUILT" "$DIR/r03-trylock.pi32.o"
printf '%s\n' "$OBJDUMP" | grep -F 'testset b[r0]'
printf '%s\n' "$OBJDUMP" | grep -F 'ifeq goto 6'
printf '%s\n' "$OBJDUMP" | grep -F 'r0 = 1'
printf '%s\n' "$OBJDUMP" | grep -F 'r0 = 0'
printf 'official PI32 try-lock rebuild and objdump: PASS\n'
