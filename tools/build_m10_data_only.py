#!/usr/bin/env python3
"""Build the M10 data-only follow-up to the known-good M08 image.

M10 keeps every M08 execution byte and hook unchanged.  It only populates the
candidate application data range used by the revoked M09 experiment and
changes the four-byte display marker.  This isolates the persistent-data
boundary from M09's new wrapper and pad-bridge code.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from build_m05_app import APP_SIZE, VERSION_OFFSET, app_offset, sha256
from m09_drum_voices import NOTE_TEMPLATE_KEYS, TEMPLATES, build_runtime_templates


DATA_CAVE_START = 0x020959EE
DATA_CAVE_END = 0x02095F96
M08_APP_SHA256 = "73ae9baa5c732f91e91e7133cda4a9146a00d3b70333ed53814e3747a1297e25"


def compact_ranges(offsets: list[int]) -> list[dict[str, int]]:
    if not offsets:
        return []
    result: list[dict[str, int]] = []
    start = previous = offsets[0]
    for value in offsets[1:]:
        if value != previous + 1:
            result.append({"start": start, "end_exclusive": previous + 1})
            start = value
        previous = value
    result.append({"start": start, "end_exclusive": previous + 1})
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="byte-exact M08 app.bin")
    parser.add_argument("output", type=Path)
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()

    original = args.input.read_bytes()
    if len(original) != APP_SIZE or sha256(original) != M08_APP_SHA256:
        raise SystemExit("input is not the recorded byte-exact M08 app.bin")

    runtime_templates, note_map = build_runtime_templates()
    data = runtime_templates + note_map
    if DATA_CAVE_START + len(data) > DATA_CAVE_END:
        raise SystemExit("M10 data exceeds the audited candidate data range")

    data_offset = app_offset(DATA_CAVE_START)
    old_data = original[data_offset:data_offset + len(data)]
    if old_data != b"\0" * len(data):
        raise SystemExit("M08 candidate data range is not byte-exact zero-filled")

    output = bytearray(original)
    output[data_offset:data_offset + len(data)] = data
    marker_offset = VERSION_OFFSET
    if bytes(output[marker_offset:marker_offset + 4]) != b"M08\0":
        raise SystemExit("M08 display marker is missing")
    output[marker_offset:marker_offset + 4] = b"M10\0"

    changed = [index for index, pair in enumerate(zip(original, output)) if pair[0] != pair[1]]
    expected = {
        data_offset + index
        for index, value in enumerate(data)
        if value != 0
    } | {
        marker_offset + index
        for index, value in enumerate(b"M10\0")
        if value != original[marker_offset + index]
    }
    if set(changed) != expected:
        raise SystemExit("M10 changed bytes are outside the data range and marker")

    args.output.write_bytes(output)
    manifest = {
        "format": "smk37-m10-data-only-follow-up-v1",
        "input_sha256": sha256(original),
        "output_sha256": sha256(output),
        "execution_delta": "none; all M08 code, hooks, and call targets are preserved",
        "data_delta": {
            "start_address": f"0x{DATA_CAVE_START:08x}",
            "end_exclusive_address": f"0x{DATA_CAVE_START + len(data):08x}",
            "audited_range_end_exclusive": f"0x{DATA_CAVE_END:08x}",
            "app_offset": data_offset,
            "bytes": len(data),
            "template_bytes": len(runtime_templates),
            "map_bytes": len(note_map),
            "sha256": hashlib.sha256(data).hexdigest(),
            "nonzero_bytes": sum(value != 0 for value in data),
            "template_names": [template.key for template in TEMPLATES],
            "gm_note_template_keys": list(NOTE_TEMPLATE_KEYS),
        },
        "marker_delta": {
            "app_offset": marker_offset,
            "old_hex": b"M08\0".hex(),
            "new_hex": b"M10\0".hex(),
        },
        "changed_ranges": compact_ranges(changed),
        "policy": {
            "ch1_and_local_keys": "M08 behavior",
            "ch10_and_local_pads": "M08 behavior; no M10 data is read by new code",
            "purpose": "boot/data-cave isolation experiment before any code-only derivative",
        },
    }
    rendered = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    if args.manifest:
        args.manifest.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
