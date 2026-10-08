#!/bin/bash
#
# Build the project's own device-side AC79 sources into the SDK demo app.
#
# What it does (all inside the amd64 build container of
# docs/linux-build-flash-procedure.md section 3, offline, no device access):
#
#   1. streams ac79/app/*.c|*.h into the container over stdin
#   2. restores the SDK app tree from git (deterministic stock baseline)
#   3. adds the project translation units to the app's c_SRC_FILES and calls
#      their self-tests from app_main():
#        smk_ota_transport.c   -> smk_ota_transport_self_test()   (A-increment)
#        smk_usb_descriptors.c -> smk_usb_descriptor_self_test()  (B1)
#   4. builds ac791n_demo_demo_hello and proves the artifact really comes from
#      this project: the project symbols are in the linked image and the
#      project's own byte strings (OTA vectors, the recovered USB descriptor, the
#      evidence-pinned interface fragment and the recovered product-name text)
#      are in app.bin
#   5. copies sdk.elf / sdk.map / app.bin / symbol_tbl.txt out to $OUT
#   6. runs tools/check_sdk_app_layout.py on the ELF and the map
#   7. restores the SDK app tree to stock, so section 3 of the build procedure
#      (which builds the pristine demo_hello) keeps working afterwards
#
# Offline invariant: it only ever writes inside the container's SDK tree and
# $OUT. It never flashes, never packs a package and never talks to a device.
#
# Usage: bash ac79/build/build_sdk_app_project_source.sh
# Env:   SMK_BUILD_CONTAINER (default smk-build)
#        SMK_SDK_ROOT        (default /root/fw-AC79_AIoT_SDK inside the container)
#        SMK_OUT_DIR         (default <repo>/build/ac79-project-source)
#
set -euo pipefail

REPO_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
CONTAINER=${SMK_BUILD_CONTAINER:-smk-build}
SDK_ROOT=${SMK_SDK_ROOT:-/root/fw-AC79_AIoT_SDK}
APP_REL=apps/demo/demo_hello
OUT=${SMK_OUT_DIR:-$REPO_ROOT/build/ac79-project-source}

# SHA-256 of the project sources this recipe was verified with. The build is
# recorded in ac79/target/smk37pro-ac7911b8.json known_builds; if a source
# changes, the recorded artifact no longer corresponds to it, so say so out
# loud unless SMK_ALLOW_SOURCE_CHANGE=1 is set deliberately.
EXPECT_C_SHA=f07caa6f465ddc4f37ca88a0d9348062294283c7067fd96736393c7b70829fa7
EXPECT_H_SHA=dc12dc2122ea39a1c5da39e8276fa385d0e59fe46c8f3c0ab7f5d6d0da369f14
EXPECT_USB_C_SHA=0999cc5e83c48576a15ff02fd8156654145c7e6ddba5869c74d5678ca633b3ab
EXPECT_USB_H_SHA=2a780be6522a9633e8e7effbd3fb3fe6f96bc560df0a0b60bf5a5dc6f69e6699

# The project sources that get compiled into the app.
PROJECT_SOURCES="smk_ota_transport.c smk_ota_transport.h smk_usb_descriptors.c smk_usb_descriptors.h"

for tool in container python3 shasum; do
    command -v "$tool" >/dev/null 2>&1 || { echo "missing required command: $tool" >&2; exit 2; }
done

echo "container:  $CONTAINER"
echo "sdk root:   $SDK_ROOT"
echo "app dir:    $SDK_ROOT/$APP_REL"
echo "output:     $OUT"

if ! container exec "$CONTAINER" bash -c 'true' 2>/dev/null; then
    echo "container $CONTAINER is not running; see docs/linux-build-flash-procedure.md section 3" >&2
    exit 2
fi
if ! container exec "$CONTAINER" bash -c "test -d '$SDK_ROOT/$APP_REL'"; then
    echo "SDK app tree $SDK_ROOT/$APP_REL is not present in $CONTAINER" >&2
    exit 2
fi

echo "=== pin project source hashes (host) ==="
ACTUAL_C_SHA=$(shasum -a 256 "$REPO_ROOT/ac79/app/smk_ota_transport.c" | cut -d' ' -f1)
ACTUAL_H_SHA=$(shasum -a 256 "$REPO_ROOT/ac79/app/smk_ota_transport.h" | cut -d' ' -f1)
ACTUAL_USB_C_SHA=$(shasum -a 256 "$REPO_ROOT/ac79/app/smk_usb_descriptors.c" | cut -d' ' -f1)
ACTUAL_USB_H_SHA=$(shasum -a 256 "$REPO_ROOT/ac79/app/smk_usb_descriptors.h" | cut -d' ' -f1)
echo "smk_ota_transport.c    $ACTUAL_C_SHA"
echo "smk_ota_transport.h    $ACTUAL_H_SHA"
echo "smk_usb_descriptors.c  $ACTUAL_USB_C_SHA"
echo "smk_usb_descriptors.h  $ACTUAL_USB_H_SHA"
if [ "$ACTUAL_C_SHA" != "$EXPECT_C_SHA" ] || [ "$ACTUAL_H_SHA" != "$EXPECT_H_SHA" ] || \
   [ "$ACTUAL_USB_C_SHA" != "$EXPECT_USB_C_SHA" ] || [ "$ACTUAL_USB_H_SHA" != "$EXPECT_USB_H_SHA" ]; then
    echo "project sources differ from the pinned hashes; the recorded artifact in the target map no longer corresponds to them" >&2
    echo "set SMK_ALLOW_SOURCE_CHANGE=1 to build anyway" >&2
    [ "${SMK_ALLOW_SOURCE_CHANGE:-0}" = 1 ] || exit 3
fi


echo
echo "=== 1. stream project sources into the container ==="
for f in $PROJECT_SOURCES; do
    cat "$REPO_ROOT/ac79/app/$f" | container exec -i "$CONTAINER" bash -c "cat > /root/$f"
done
container exec "$CONTAINER" bash -c 'sha256sum /root/smk_ota_transport.c /root/smk_ota_transport.h /root/smk_usb_descriptors.c /root/smk_usb_descriptors.h'

echo
echo "=== 2-4. patch, build, prove project origin ==="
container exec -i "$CONTAINER" bash -s "$SDK_ROOT" "$APP_REL" <<'IN_CONTAINER'
set -eu
S=$1
APP_REL=$2
A="$S/$APP_REL"

# deterministic stock baseline, and always leave the app tree exactly stock again.
# The objects and dependency files of the patched sources must go too: a stale
# objs/app_main.c.d keeps referencing the removed header as a prerequisite, and
# make then aborts with "No rule to make target .../smk_ota_transport.h" for
# every later build, including the stock procedure of
# docs/linux-build-flash-procedure.md section 3.
restore() {
    git -C "$S" checkout -- "$APP_REL/app_main.c" "$APP_REL/board/wl82/Makefile"
    rm -f "$A/smk_ota_transport.c" "$A/smk_ota_transport.h" \
          "$A/smk_usb_descriptors.c" "$A/smk_usb_descriptors.h"
    rm -rf "$A/board/wl82/objs/apps/demo/demo_hello"
}
restore
trap restore EXIT

cp /root/smk_ota_transport.c /root/smk_ota_transport.h \
   /root/smk_usb_descriptors.c /root/smk_usb_descriptors.h "$A/"

python3 - "$S" "$APP_REL" <<'PY'
import pathlib, sys

S, APP_REL = sys.argv[1], sys.argv[2]
A = pathlib.Path(S) / APP_REL

MAKEFILE_ANCHOR = '\t../../../../../apps/demo/demo_hello/app_main.c \\\n'
PROJECT_TUS = ('smk_ota_transport.c', 'smk_usb_descriptors.c')

makefile = (A / 'board/wl82/Makefile').read_text()
assert makefile.count(MAKEFILE_ANCHOR) == 1, 'app_main.c anchor in c_SRC_FILES is not unique'
makefile = makefile.replace(
    MAKEFILE_ANCHOR,
    MAKEFILE_ANCHOR + ''.join(
        '\t../../../../../apps/demo/demo_hello/%s \\\n' % tu for tu in PROJECT_TUS))
(A / 'board/wl82/Makefile').write_text(makefile)

app_main = (A / 'app_main.c').read_text()
assert 'smk_ota_transport.h' not in app_main, 'app_main.c is already patched'
app_main = app_main.replace(
    '#include "app_config.h"',
    '#include "app_config.h"\n'
    '#include "smk_ota_transport.h"\n'
    '#include "smk_usb_descriptors.h"', 1)
assert app_main.count('void app_main()\n{\n') == 1, 'app_main() definition not unique'
app_main = app_main.replace(
    'void app_main()\n{\n',
    'void app_main()\n{\n'
    '    /* Project-authored increments, run once at boot before the demo task\n'
    '     * exists. These are self-checks only: no USB access, no flash access, no\n'
    '     * boot-sector involvement. Ground truth for the USB descriptor is\n'
    '     * asserted on the host by ac79/test/usb_descriptor_test.c, not here. */\n'
    '    smk_ota_selftest_result = smk_ota_transport_self_test();\n'
    '    printf("smk_ota_transport_self_test: %s\\r\\n",\n'
    '           smk_ota_selftest_result == 0 ? "PASS" : "FAIL");\n'
    '    smk_usb_selftest_result = smk_usb_descriptor_self_test();\n'
    '    printf("smk_usb_descriptor_self_test: %s\\r\\n",\n'
    '           smk_usb_selftest_result == 0 ? "PASS" : "FAIL");\n', 1)
app_main = app_main.replace(
    'void app_main()',
    'static volatile int smk_ota_selftest_result;\n'
    'static volatile int smk_usb_selftest_result;\n\n'
    'void app_main()', 1)
(A / 'app_main.c').write_text(app_main)
print('patch: ok (Makefile c_SRC_FILES + app_main.c, both project TUs)')
PY

cd "$S"
make ac791n_demo_demo_hello

echo "--- project symbols in the linked image ---"
grep -E 'smk_(ota|usb)_' "$S/cpu/wl82/tools/symbol_tbl.txt"
grep -E 'smk_(ota_transport|usb_descriptors)\.c\.o' "$S/cpu/wl82/tools/sdk.map" | head -3

echo "--- project byte strings in app.bin (these are project data, not stock) ---"
python3 - "$S/cpu/wl82/tools/app.bin" <<'PY'
import sys
app = open(sys.argv[1], 'rb').read()
strings = {
    # OTA transport mirror: the reference's own vectors
    'ota expected_request': bytes.fromhex('0059300800000178563412f10300f6'),
    'ota success_ack': bytes.fromhex('0059301000000000 0000f00800007375636365737300 0e'.replace(' ', '')),
    # B1: the 18-byte device descriptor recovered from flash 0x0BDDE5
    'usb recovered device descriptor':
        bytes.fromhex('12010002000000404a4d5541000101020001'),
    # B1: the 30-byte MIDIStreaming interface fragment whose every field is
    # pinned by docs/research-notes.md, baselines/v15/device-info/probe.txt or
    # the USB MIDI 1.0 definition (see smk_usb_facts in the project source).
    # Its absence would mean -flto folded the table away again.
    'usb evidence-pinned interface fragment':
        bytes.fromhex('0904010002010300 00' '07240600010700'
                      '07050402400000' '07058402400000'),
    # B1 corrected (2026-10-09b): the 40-byte UTF-16LE product-name text
    # recovered from the update-mode firmware image at flash 0x0BB558. Same
    # LTO trap: a table nobody reads can be folded away.
    'usb recovered product-name text':
        bytes.fromhex('5500530042002000 43006f006d007000 6f00730069007400'
                      '6500200044006500 7600690063006500'),
}
for name, blob in strings.items():
    count = app.count(blob)
    print(f'{name}: {len(blob)} B x {count} occurrence(s) in app.bin of {len(app)} B')
    assert count >= 1, f'{name} missing from app.bin'
PY
echo "--- artifacts ---"
for f in sdk.elf sdk.map app.bin symbol_tbl.txt; do
    sha256sum "$S/cpu/wl82/tools/$f"
    stat -c '%s bytes %n' "$S/cpu/wl82/tools/$f"
done
IN_CONTAINER

echo
echo "=== 5. copy artifacts out to $OUT ==="
mkdir -p "$OUT"
for f in sdk.elf sdk.map app.bin symbol_tbl.txt; do
    container exec "$CONTAINER" bash -c "cat '$SDK_ROOT/cpu/wl82/tools/$f'" > "$OUT/$f"
    printf '%s ' "$(wc -c < "$OUT/$f" | tr -d ' ')"
    echo "bytes  $OUT/$f"
done

echo
echo "=== 6. layout gate ==="
python3 "$REPO_ROOT/tools/check_sdk_app_layout.py" "$OUT/sdk.elf" --app "$OUT/app.bin"
python3 "$REPO_ROOT/tools/check_sdk_app_layout.py" "$OUT/sdk.map" --app "$OUT/app.bin"

echo
echo "SDK app project-source build: DONE (container app tree restored to stock and buildable)"
echo "verify with: container exec $CONTAINER bash -c 'cd $SDK_ROOT && make ac791n_demo_demo_hello'  # -> +app.bin: 119748 bytes"
