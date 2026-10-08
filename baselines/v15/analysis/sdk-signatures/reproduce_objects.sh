#!/bin/sh
# Rebuild relocation-bearing pi32v2 objects from the pinned SDK bitcode archives.
# Usage: ./reproduce_objects.sh SDK_ROOT /path/to/pi32v2/bin/clang OUT_DIR
set -eu

if [ "$#" -ne 3 ]; then
    echo "usage: $0 SDK_ROOT PI32_CLANG OUT_DIR" >&2
    exit 2
fi
SDK_ROOT=$1
CLANG=$2
OUT_DIR=$3
mkdir -p "$OUT_DIR"

python3 - "$SDK_ROOT" "$OUT_DIR" <<'PY'
from pathlib import Path
import sys

sdk = Path(sys.argv[1])
out = Path(sys.argv[2])
wanted = {
    "cpu/wl82/liba/lib_midi_dec.a": ["midi_fread_tone.o", "midi_synth.o", "midi_tabs.o"],
    "cpu/wl82/liba/audio_server.a": ["midi_ctrl_decoder.c.o", "midi_dec.c.o", "midi_event.c.o", "midi_play.c.o"],
    # Calibration members with multiple known exact v15 matches.
    "cpu/wl82/liba/cpu.a": ["gpio.c.o"],
    "cpu/wl82/liba/fs.a": ["sdfile_new.c.o"],
}

def members(path):
    raw = path.read_bytes()
    if raw[:8] != b"!<arch>\n": raise SystemExit(f"not an archive: {path}")
    names=b""; pos=8
    while pos+60 <= len(raw):
        h=raw[pos:pos+60]; pos += 60
        name=h[:16].decode("ascii", "replace").rstrip()
        size=int(h[48:58].decode().strip())
        body=raw[pos:pos+size]; pos += size + (size & 1)
        if name == "//": names=body; continue
        if name in ("/", "__.SYMDEF", "__.SYMDEF SORTED"): continue
        resolved=name.rstrip("/")
        if name.startswith("/") and name[1:].isdigit() and names:
            start=int(name[1:]); end=names.find(b"/\n", start)
            resolved=names[start:end].decode()
        yield resolved, body

for rel, names in wanted.items():
    found = {name: body for name, body in members(sdk / rel) if name in names}
    missing = set(names) - set(found)
    if missing: raise SystemExit(f"missing {sorted(missing)} in {rel}")
    for name in names:
        stem = name.removesuffix(".c.o").removesuffix(".o")
        (out / f"{stem}.bc").write_bytes(found[name])
PY

# Pinned SDK CFLAGS, except -flto is intentionally omitted so relocations remain
# inspectable in the generated ELF objects.
FLAGS="-target pi32v2 -integrated-as -mcpu=r3 -mfprev1 -Wuninitialized -Wno-invalid-noreturn -fno-common -Oz -g -fallow-pointer-null -fprefer-gnu-section -femulated-tls -Wno-shift-negative-value -Wframe-larger-than=2560 -mllvm -pi32v2-large-program=true -fms-extensions -w"
for bc in "$OUT_DIR"/*.bc; do
    base=$(basename "$bc" .bc)
    # shellcheck disable=SC2086
    "$CLANG" $FLAGS -c "$bc" -o "$OUT_DIR/$base.pi32.o"
done

if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$OUT_DIR"/*.bc "$OUT_DIR"/*.pi32.o
else
    shasum -a 256 "$OUT_DIR"/*.bc "$OUT_DIR"/*.pi32.o
fi
