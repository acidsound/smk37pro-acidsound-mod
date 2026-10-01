#!/usr/bin/env bash
set -euo pipefail

# Reproducible v16 (1.16) Ghidra listing generation.
# Mirrors baselines/v15/analysis/quarkslab/run_analysis.sh, but for the decoded 016 app.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

IMAGE="${IMAGE:-$REPO_ROOT/build/v16-analysis/app-016-decoded.bin}"
EXPECTED_IMAGE_SHA256='0f64fbf6ffc454eea686d78cf89f35e593229765bdcf166f10a8bd714abcb09a'
EXPECTED_SLA_SHA256='6d774eacaa7f5769ebb536699c6c13500dbb806a265740094464c64951a906d4'
QUARKSLAB_COMMIT='e1bd0707874b77b759401555d24839ad43af1267'

GHIDRA_HOME="${GHIDRA_HOME:-/opt/homebrew/Cellar/ghidra/12.1.2/libexec}"
JDK_HOME="${JDK_HOME:-/opt/homebrew/opt/openjdk@21/libexec/openjdk.jdk/Contents/Home}"
WORK="${WORK:-$HOME/jcode-v16-analysis}"
MODULE="${MODULE:-$WORK/module-quarkslab}"
PROJECT_ROOT="${PROJECT_ROOT:-$WORK/projects}"
RESULTS_DIR="${RESULTS_DIR:-$SCRIPT_DIR/results}"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
PROJECT_NAME="${PROJECT_NAME:-v16-$RUN_ID}"
USER_HOME="$WORK/home-$RUN_ID"

ANALYZE_HEADLESS="$GHIDRA_HOME/support/analyzeHeadless"
test -x "$ANALYZE_HEADLESS"
test -x "$JDK_HOME/bin/java"

actual="$(shasum -a 256 "$IMAGE" | awk '{print $1}')"
if [ "$actual" != "$EXPECTED_IMAGE_SHA256" ]; then
  echo "refusing analysis: unexpected image SHA-256 $actual" >&2
  exit 1
fi
sla="$(shasum -a 256 "$MODULE/data/languages/pi32v2.sla" | awk '{print $1}')"
if [ "$sla" != "$EXPECTED_SLA_SHA256" ]; then
  echo "refusing analysis: unexpected pi32v2.sla SHA-256 $sla" >&2
  exit 1
fi

mkdir -p "$PROJECT_ROOT" "$RESULTS_DIR" "$USER_HOME"
export JAVA_HOME="$JDK_HOME"
export PATH="$JAVA_HOME/bin:$PATH"
export JAVA_TOOL_OPTIONS="-Duser.home=$USER_HOME"

PREFIX="$RESULTS_DIR/v16"
LOG="$RESULTS_DIR/v16-headless.log"

"$ANALYZE_HEADLESS" "$PROJECT_ROOT" "$PROJECT_NAME" \
  -import "$IMAGE" \
  -loader BinaryLoader \
  -loader-baseAddr 0x02000000 \
  -processor pi32v2:LE:32:default \
  -cspec default \
  -analysisTimeoutPerFile 1800 \
  -scriptPath "$SCRIPT_DIR" \
  -postScript V16DecoderAnalysis.java "$PREFIX" \
  2>&1 | tee "$LOG"

if grep -q 'REPORT SCRIPT ERROR' "$LOG"; then
  echo "Ghidra script failed" >&2
  exit 1
fi
grep -q "PROVENANCE image_sha256=$EXPECTED_IMAGE_SHA256" "$LOG"
grep -q 'PROVENANCE mapped_memory_base=02000000' "$LOG"
test -s "$PREFIX-recursive-listing.tsv"
test -s "$PREFIX-exhaustive-listing.tsv"

# Store the listings gzipped, matching baselines/v15/analysis/quarkslab/results/.
gzip -9 -f "$PREFIX-recursive-listing.tsv" "$PREFIX-exhaustive-listing.tsv"
test -s "$PREFIX-recursive-listing.tsv.gz"
test -s "$PREFIX-exhaustive-listing.tsv.gz"

GW=$(awk -F= '$1 == "application.version" { print $2 }' "$GHIDRA_HOME/Ghidra/application.properties")
JDKV=$($JDK_HOME/bin/java -version 2>&1 | sed -n '1p')
TREE=$(git -C "$WORK/sources/quarkslab-ghidra-jieli" rev-parse HEAD^{tree})
SCRIPTSHA=$(shasum -a 256 "$SCRIPT_DIR/V16DecoderAnalysis.java" | awk '{print $1}')
cat > "$RESULTS_DIR/provenance.txt" <<EOF
run_id=$RUN_ID
image=$IMAGE
image_sha256=$EXPECTED_IMAGE_SHA256
runtime_mapped_base=0x02000000
processor=pi32v2:LE:32:default
ghidra_home=$GHIDRA_HOME
ghidra_version=$GW
jdk=$JDKV
quarkslab_url=https://github.com/quarkslab/ghidra-jieli.git
quarkslab_commit=$QUARKSLAB_COMMIT
quarkslab_tree=$TREE
quarkslab_sla_sha256=$sla
script=V16DecoderAnalysis.java
script_sha256=$SCRIPTSHA
EOF

python3 - "$RESULTS_DIR" <<'PY'
import hashlib, sys
from pathlib import Path
root = Path(sys.argv[1])
lines = []
for path in sorted(root.iterdir(), key=lambda item: item.name):
    if not path.is_file() or path.name in {'SHA256SUMS', 'provenance.txt'}:
        continue
    if path.name.endswith('.log'):
        continue
    lines.append(f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}')
(root / 'SHA256SUMS').write_text('\n'.join(lines) + '\n')
PY

echo "v16 listing complete: $RESULTS_DIR"
