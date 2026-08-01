#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../../../.." && pwd)"

EXPECTED_APP_SHA256='36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055'
EXPECTED_PACKAGE_SHA256='f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff'
QUARKSLAB_COMMIT='e1bd0707874b77b759401555d24839ad43af1267'
KAGAIMIQ_COMMIT='b5e60122b6cd3e6b615387035994b8bed0ea1a26'

IMAGE="${IMAGE:-$REPO_ROOT/build/v15-official-app.bin}"
PACKAGE="${PACKAGE:-$REPO_ROOT/build/SMK-37_Pro_015.fwsc}"
MANIFEST="${MANIFEST:-$REPO_ROOT/baselines/v15/official/package-manifest.json}"
GHIDRA_HOME="${GHIDRA_HOME:?set GHIDRA_HOME to a Ghidra 12.1.2 directory}"
JDK_HOME="${JDK_HOME:?set JDK_HOME to a JDK 21 home}"
WORK_DIR="${WORK_DIR:-${JCODE_SCRATCH_DIR:-$HOME/jcode-v15-analysis-scratch}/smk37-v15-quarkslab}"
PROJECT_ROOT="${PROJECT_ROOT:-$HOME/jcode-v15-quarkslab-work}"
RESULTS_DIR="${RESULTS_DIR:-$SCRIPT_DIR/results}"
RUN_ID="${RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)}"
RUN_ROOT="$WORK_DIR/runs/$RUN_ID"
SOURCE_ROOT="$WORK_DIR/sources"

ANALYZE_HEADLESS="$GHIDRA_HOME/support/analyzeHeadless"
SLEIGH="$GHIDRA_HOME/support/sleigh"
PATCH_FILE="$REPO_ROOT/patches/ghidra-jieli-pi32v2-smk37.patch"

for command_name in git python3 patch shasum gzip tee; do
  command -v "$command_name" >/dev/null
done
test -x "$ANALYZE_HEADLESS"
test -x "$SLEIGH"
test -x "$JDK_HOME/bin/java"

# Ghidra's ProjectLocator rejects any project path component beginning with '.'.
if [[ "$PROJECT_ROOT" == .* || "$PROJECT_ROOT" == */.* || "$PROJECT_ROOT" == */.*/** ]]; then
  echo "PROJECT_ROOT must not contain a hidden path component: $PROJECT_ROOT" >&2
  exit 1
fi

mkdir -p "$RUN_ROOT" "$SOURCE_ROOT" "$PROJECT_ROOT" "$RESULTS_DIR"

sha256_file() {
  shasum -a 256 "$1" | awk '{print $1}'
}

require_sha256() {
  local path="$1"
  local expected="$2"
  local actual
  actual="$(sha256_file "$path")"
  if [[ "$actual" != "$expected" ]]; then
    echo "refusing analysis: SHA-256 $actual != expected $expected for $path" >&2
    exit 1
  fi
}

require_sha256 "$IMAGE" "$EXPECTED_APP_SHA256"
require_sha256 "$PACKAGE" "$EXPECTED_PACKAGE_SHA256"

python3 - "$IMAGE" "$PACKAGE" "$MANIFEST" <<'PY'
import hashlib
import json
import sys
from pathlib import Path

image, package, manifest_path = map(Path, sys.argv[1:])
manifest = json.loads(manifest_path.read_text())
checks = {
    "app_sha256": hashlib.sha256(image.read_bytes()).hexdigest(),
    "package_sha256": hashlib.sha256(package.read_bytes()).hexdigest(),
}
for key, actual in checks.items():
    if manifest[key] != actual:
        raise SystemExit(f"manifest mismatch: {key} expected {manifest[key]} got {actual}")
if manifest["layout"]["app_data_size"] != image.stat().st_size:
    raise SystemExit("manifest app_data_size does not match exact app")
print(json.dumps({"manifest_checks": checks, "app_size": image.stat().st_size}, sort_keys=True))
PY

clone_pin() {
  local url="$1"
  local commit="$2"
  local destination="$3"
  if [[ ! -d "$destination/.git" ]]; then
    git clone "$url" "$destination"
  fi
  git -C "$destination" fetch --all --tags --prune
  git -C "$destination" checkout --detach "$commit"
  if [[ "$(git -C "$destination" rev-parse HEAD)" != "$commit" ]]; then
    echo "failed to pin $destination to $commit" >&2
    exit 1
  fi
  if [[ -n "$(git -C "$destination" status --short)" ]]; then
    echo "refusing dirty decoder clone: $destination" >&2
    exit 1
  fi
}

QUARKSLAB_SOURCE="$SOURCE_ROOT/quarkslab-ghidra-jieli"
KAGAIMIQ_SOURCE="$SOURCE_ROOT/kagaimiq-ghidra-jieli"
clone_pin 'https://github.com/quarkslab/ghidra-jieli.git' "$QUARKSLAB_COMMIT" "$QUARKSLAB_SOURCE"
clone_pin 'https://github.com/kagaimiq/ghidra-jieli.git' "$KAGAIMIQ_COMMIT" "$KAGAIMIQ_SOURCE"

QUARKSLAB_MODULE="$RUN_ROOT/module-quarkslab"
KAGAIMIQ_MODULE="$RUN_ROOT/module-kagaimiq-patched"
mkdir -p "$QUARKSLAB_MODULE" "$KAGAIMIQ_MODULE"
cp -R "$QUARKSLAB_SOURCE/data" "$QUARKSLAB_MODULE/data"
cp "$QUARKSLAB_SOURCE/Module.manifest" "$QUARKSLAB_MODULE/Module.manifest"
cp -R "$KAGAIMIQ_SOURCE/data" "$KAGAIMIQ_MODULE/data"
cp "$KAGAIMIQ_SOURCE/Module.manifest" "$KAGAIMIQ_MODULE/Module.manifest"
patch -d "$KAGAIMIQ_MODULE" -p1 < "$PATCH_FILE"

export JAVA_HOME="$JDK_HOME"
export PATH="$JAVA_HOME/bin:$PATH"

(
  cd "$QUARKSLAB_MODULE/data/languages"
  "$SLEIGH" -a .
) 2>&1 | tee "$RESULTS_DIR/quarkslab-sleigh-build.log"
(
  cd "$KAGAIMIQ_MODULE/data/languages"
  "$SLEIGH" -a .
) 2>&1 | tee "$RESULTS_DIR/kagaimiq-patched-sleigh-build.log"

python3 "$SCRIPT_DIR/decoder_source_metrics.py" \
  --quarkslab-module "$QUARKSLAB_MODULE" \
  --kagaimiq-module "$KAGAIMIQ_MODULE" \
  --output "$RESULTS_DIR/decoder-source-metrics.json"

copy_ghidra() {
  local destination="$1"
  if [[ "$(uname -s)" == 'Darwin' ]]; then
    cp -cR "$GHIDRA_HOME" "$destination"
  else
    cp -a "$GHIDRA_HOME" "$destination"
  fi
}

prepare_ghidra() {
  local variant="$1"
  local module_source="$2"
  local private_home="$RUN_ROOT/ghidra-$variant"
  copy_ghidra "$private_home"
  local module_target="$private_home/Ghidra/Processors/JieLi"
  if [[ -e "$module_target" || -L "$module_target" ]]; then
    mv "$module_target" "$RUN_ROOT/inherited-JieLi-$variant"
  fi
  mkdir -p "$module_target"
  cp -R "$module_source/data" "$module_target/data"
  cp "$module_source/Module.manifest" "$module_target/Module.manifest"
  printf '%s\n' "$private_home"
}

run_variant() {
  local variant="$1"
  local module_source="$2"
  local private_home
  private_home="$(prepare_ghidra "$variant" "$module_source")"
  local user_home="$RUN_ROOT/home-$variant"
  local project_dir="$PROJECT_ROOT/$RUN_ID-$variant"
  local project_name="v15-$RUN_ID-$variant"
  local output_prefix="$RESULTS_DIR/$variant"
  local log="$RESULTS_DIR/$variant-headless.log"
  mkdir -p "$user_home" "$project_dir"
  export JAVA_TOOL_OPTIONS="-Duser.home=$user_home"

  "$private_home/support/analyzeHeadless" "$project_dir" "$project_name" \
    -import "$IMAGE" \
    -loader BinaryLoader \
    -loader-baseAddr 0x02000000 \
    -processor pi32v2:LE:32:default \
    -cspec default \
    -analysisTimeoutPerFile 1200 \
    -scriptPath "$SCRIPT_DIR" \
    -postScript V15DecoderAnalysis.java "$output_prefix" \
    2>&1 | tee "$log"

  if grep -q 'REPORT SCRIPT ERROR' "$log"; then
    echo "Ghidra script failed for $variant" >&2
    exit 1
  fi
  grep -q "PROVENANCE image_sha256=$EXPECTED_APP_SHA256" "$log"
  grep -q 'PROVENANCE mapped_memory_base=02000000' "$log"
  test -s "$output_prefix-recursive-listing.tsv"
  test -s "$output_prefix-exhaustive-listing.tsv"
}

run_variant quarkslab "$QUARKSLAB_MODULE"
run_variant kagaimiq-patched "$KAGAIMIQ_MODULE"

python3 "$SCRIPT_DIR/summarize_results.py" \
  --quarkslab-log "$RESULTS_DIR/quarkslab-headless.log" \
  --kagaimiq-log "$RESULTS_DIR/kagaimiq-patched-headless.log" \
  --json "$RESULTS_DIR/comparison.json" \
  --markdown "$RESULTS_DIR/comparison.md"

python3 "$SCRIPT_DIR/extract_candidate_traces.py" \
  --image "$IMAGE" \
  --log "$RESULTS_DIR/quarkslab-headless.log" \
  --recursive-listing "$RESULTS_DIR/quarkslab-recursive-listing.tsv" \
  --exhaustive-listing "$RESULTS_DIR/quarkslab-exhaustive-listing.tsv" \
  --output "$RESULTS_DIR/candidate-traces.md"

gzip -f "$RESULTS_DIR/quarkslab-recursive-listing.tsv"
gzip -f "$RESULTS_DIR/quarkslab-exhaustive-listing.tsv"
gzip -f "$RESULTS_DIR/kagaimiq-patched-recursive-listing.tsv"
gzip -f "$RESULTS_DIR/kagaimiq-patched-exhaustive-listing.tsv"

cat > "$RESULTS_DIR/provenance.txt" <<EOF
run_id=$RUN_ID
image=$IMAGE
image_sha256=$EXPECTED_APP_SHA256
package=$PACKAGE
package_sha256=$EXPECTED_PACKAGE_SHA256
runtime_mapped_base=0x02000000
ghidra_home=$GHIDRA_HOME
ghidra_version=$(awk -F= '$1 == "application.version" { print $2 }' "$GHIDRA_HOME/Ghidra/application.properties")
jdk=$($JDK_HOME/bin/java -version 2>&1 | sed -n '1p')
quarkslab_url=https://github.com/quarkslab/ghidra-jieli.git
quarkslab_commit=$QUARKSLAB_COMMIT
quarkslab_tree=$(git -C "$QUARKSLAB_SOURCE" rev-parse HEAD^{tree})
quarkslab_sla_sha256=$(sha256_file "$QUARKSLAB_MODULE/data/languages/pi32v2.sla")
kagaimiq_url=https://github.com/kagaimiq/ghidra-jieli.git
kagaimiq_commit=$KAGAIMIQ_COMMIT
kagaimiq_tree=$(git -C "$KAGAIMIQ_SOURCE" rev-parse HEAD^{tree})
patch=$PATCH_FILE
patch_sha256=$(sha256_file "$PATCH_FILE")
kagaimiq_patched_sla_sha256=$(sha256_file "$KAGAIMIQ_MODULE/data/languages/pi32v2.sla")
EOF

python3 - "$RESULTS_DIR" <<'PY'
import hashlib
import sys
from pathlib import Path

root = Path(sys.argv[1])
lines = []
for path in sorted(root.iterdir(), key=lambda item: item.name):
    if not path.is_file() or path.name == "SHA256SUMS":
        continue
    lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}")
(root / "SHA256SUMS").write_text("\n".join(lines) + "\n")
PY

echo "analysis complete: $RESULTS_DIR"
