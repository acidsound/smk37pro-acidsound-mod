#!/bin/bash
# Coverage-extension run: seed disassembly at prologue candidates past 0x57000.
#
# Two environment facts learned the hard way, both recorded in the map:
#   * Ghidra's ProjectLocator rejects any path element starting with '.', so the
#     project dir cannot live under ~/.hermes.  It uses a dot-free dir instead.
#   * The pi32v2 language extension must be visible from the isolated user.home,
#     so it is copied in.  Ghidra logs "previously defined" for it and carries on;
#     that ERROR is cosmetic, the abort is the project path.
#
# -noanalysis: the script does its own DisassembleCommand seeding and reads
# instruction flow directly, so the 685-function auto-analysis pass is skipped.
#
# -loader-baseAddr 0x02000000 is mandatory: without it BinaryLoader maps the
# image at ram:0 and every address in the script is out of range.  The original
# V15DecoderAnalysis run set it the same way.
set -u

REPO=/Users/spectrum/Documents/SMK37ProMod
GHIDRA=/opt/homebrew/Cellar/ghidra/12.1.2/libexec
JAVA_HOME=/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home
export JAVA_HOME

RUN=/Users/spectrum/.hermes/cache/scratch/cov-ext
# Dot-free project location: Ghidra rejects '.'-prefixed path elements.
PROJDIR=/Users/spectrum/ghidra-cov-proj
OUT=$REPO/baselines/v15/analysis/quarkslab/results/cov-ext

mkdir -p "$RUN/home" "$OUT" "$PROJDIR"
export JAVA_TOOL_OPTIONS="-Duser.home=$RUN/home"

EXTREL=Library/ghidra/ghidra_12.1.2_PUBLIC/Extensions/ghidra-jieli-v15
if [ ! -d "$RUN/home/$EXTREL" ]; then
  mkdir -p "$RUN/home/$(dirname $EXTREL)"
  cp -R /Users/spectrum/Library/ghidra/ghidra_12.1.2_PUBLIC/Extensions/ghidra-jieli-v15 \
        "$RUN/home/$EXTREL"
fi

rm -rf "$PROJDIR/proj.gpr" "$PROJDIR/proj.rep"

"$GHIDRA/support/analyzeHeadless" "$PROJDIR" proj \
  -import "$REPO/build/v16-analysis/app-015-decoded.bin" \
  -processor pi32v2:LE:32:default \
  -loader BinaryLoader \
  -loader-baseAddr 0x02000000 \
  -noanalysis \
  -scriptPath "$REPO/baselines/v15/analysis/quarkslab" \
  -postScript V15CoverageExtension.java "$OUT" \
  -deleteProject \
  > "$RUN/analyze.log" 2>&1

rc=$?
echo "ghidra_exit=$rc"
grep -E "EXT |ERROR|Exception" "$RUN/analyze.log" | tail -40

# Propagate Ghidra's status.  This script used to end on the grep pipeline above,
# so it exited 0 even when the run aborted -- two aborted runs in a row reported
# "exit code 0" to the caller and looked like successes.  A missing or partial
# listing is now also a failure, not just a non-zero Ghidra exit.
if [ "$rc" -ne 0 ]; then
  echo "FAIL: analyzeHeadless exited $rc"
  exit "$rc"
fi
if ! grep -q "EXT listing_rows=" "$RUN/analyze.log"; then
  echo "FAIL: run finished without writing a listing (no EXT listing_rows line)"
  exit 1
fi
echo "OK: coverage extension listing written"
