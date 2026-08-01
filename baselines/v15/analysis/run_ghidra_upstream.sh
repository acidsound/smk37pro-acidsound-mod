#!/usr/bin/env bash
set -euo pipefail

# Required environment:
#   GHIDRA_HOME        extracted Ghidra 12.x directory
#   GHIDRA_JIELI_DIR   clean clone of kagaimiq/ghidra-jieli at the commit below
#   JCODE_JAVA_HOME    JDK 21 home
# Optional:
#   WORK_DIR           non-hidden scratch path; defaults to $HOME/jcode-v15-analysis-work

EXPECTED_IMAGE_SHA256='36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055'
EXPECTED_JIELI_COMMIT='b5e60122b6cd3e6b615387035994b8bed0ea1a26'

: "${GHIDRA_HOME:?set GHIDRA_HOME to an extracted Ghidra directory}"
: "${GHIDRA_JIELI_DIR:?set GHIDRA_JIELI_DIR to a clean ghidra-jieli clone}"
: "${JCODE_JAVA_HOME:?set JCODE_JAVA_HOME to a JDK 21 home}"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../.." && pwd)"
IMAGE="$REPO_ROOT/build/v15-official-app.bin"
DECODER_PATCH="$REPO_ROOT/patches/ghidra-jieli-pi32v2-smk37.patch"
WORK_DIR="${WORK_DIR:-$HOME/jcode-v15-analysis-work}"
CLEAN_HOME="$WORK_DIR/home"
PROJECTS="$WORK_DIR/projects"
PROJECT_NAME='v15-pi32-clean'
PROCESSOR_DIR="$GHIDRA_HOME/Ghidra/Processors/JieLi"
PATCHED_MODULE="$WORK_DIR/ghidra-jieli-patched"
ANALYZE_HEADLESS="$GHIDRA_HOME/support/analyzeHeadless"

actual_sha="$(shasum -a 256 "$IMAGE" | awk '{print $1}')"
if [[ "$actual_sha" != "$EXPECTED_IMAGE_SHA256" ]]; then
  echo "refusing analysis: unexpected image SHA-256 $actual_sha" >&2
  exit 1
fi

if [[ -d "$GHIDRA_JIELI_DIR/.git" ]]; then
  actual_commit="$(git -C "$GHIDRA_JIELI_DIR" rev-parse HEAD)"
  if [[ "$actual_commit" != "$EXPECTED_JIELI_COMMIT" ]]; then
    echo "refusing analysis: ghidra-jieli commit $actual_commit is not $EXPECTED_JIELI_COMMIT" >&2
    exit 1
  fi
else
  echo 'refusing analysis: GHIDRA_JIELI_DIR must retain .git for provenance verification' >&2
  exit 1
fi

if [[ ! -f "$DECODER_PATCH" ]]; then
  echo "refusing analysis: missing tracked decoder patch $DECODER_PATCH" >&2
  exit 1
fi

mkdir -p "$CLEAN_HOME" "$PROJECTS"
if [[ ! -d "$PATCHED_MODULE/data" ]]; then
  mkdir -p "$PATCHED_MODULE"
  cp -R "$GHIDRA_JIELI_DIR/data" "$PATCHED_MODULE/data"
  cp "$GHIDRA_JIELI_DIR/Module.manifest" "$PATCHED_MODULE/Module.manifest"
  patch -d "$PATCHED_MODULE" -p1 < "$DECODER_PATCH"
fi
if [[ -e "$PROCESSOR_DIR" ]]; then
  echo "refusing analysis: processor target already exists: $PROCESSOR_DIR" >&2
  echo "use a fresh extracted GHIDRA_HOME" >&2
  exit 1
fi
mkdir -p "$PROCESSOR_DIR"
cp -R "$PATCHED_MODULE/data" "$PROCESSOR_DIR/data"
cp "$PATCHED_MODULE/Module.manifest" "$PROCESSOR_DIR/Module.manifest"

export JAVA_HOME="$JCODE_JAVA_HOME"
export PATH="$JAVA_HOME/bin:$PATH"
export JAVA_TOOL_OPTIONS="-Duser.home=$CLEAN_HOME"

if [[ ! -f "$PROJECTS/$PROJECT_NAME.gpr" ]]; then
  "$ANALYZE_HEADLESS" "$PROJECTS" "$PROJECT_NAME" \
    -import "$IMAGE" \
    -loader BinaryLoader \
    -loader-baseAddr 0x02000000 \
    -processor pi32v2:LE:32:default \
    -cspec default \
    -analysisTimeoutPerFile 600
fi

"$ANALYZE_HEADLESS" "$PROJECTS" "$PROJECT_NAME" \
  -process v15-official-app.bin \
  -noanalysis \
  -scriptPath "$SCRIPT_DIR" \
  -postScript V15Pi32Xrefs.java \
  | tee "$WORK_DIR/v15-pi32-xrefs.log"
