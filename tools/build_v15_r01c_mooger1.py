#!/usr/bin/env python3
"""Build v15 R01c: Channel-10 Mooger #1 with matched Note On/Off voice.

This is the live-follow-up to R01. R01 proved Channel-10 timbre separation but
left the stock Note Off memcpy in place, so Note On used HAND DRUM while Note
Off used the current UI patch. R01c routes both proven memcpy sites through the
same Channel-10 wrapper and uses official-v15 Bank D display 14, zero-based preset 13, Mooger #1.

No v12 address, layout, or firmware artifact is consumed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from build_v15_r01_hand_drum import (
    APP_SHA256,
    APP_SIZE,
    CHANNEL_10,
    CODE_CAVE,
    CODE_CAVE_END,
    DUMP_SHA256,
    DUMP_SIZE,
    MEMCPY,
    RUNTIME_BASE,
    SYSEX_CALLS,
    build_wrapper,
    call32,
    expand_v15_factory_voice,
    off,
    replace_exact,
    sha256,
)

NOTE_ON_MEMCPY_CALL = 0x0201C67C
NOTE_ON_STOCK = bytes.fromhex("80ff4cc60200")
NOTE_OFF_MEMCPY_CALL = 0x0201C63E
NOTE_OFF_STOCK = bytes.fromhex("80ff8ac60200")
BANK = 3
PRESET = 13
VOICE_OFFSET = 0xF7680
VOICE_NAME = b"Mooger #1 "


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("app", type=Path)
    parser.add_argument("clean_dump", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()

    app = args.app.read_bytes()
    dump = args.clean_dump.read_bytes()
    if len(app) != APP_SIZE or sha256(app) != APP_SHA256:
        raise SystemExit("refusing non-official v15 app")
    if len(dump) != DUMP_SIZE or sha256(dump) != DUMP_SHA256:
        raise SystemExit("refusing non-baseline v15 full flash dump")

    packed = dump[VOICE_OFFSET:VOICE_OFFSET + 128]
    if packed[118:128] != VOICE_NAME:
        raise SystemExit("factory voice identity mismatch")
    snapshot = expand_v15_factory_voice(packed)
    wrapper, layout = build_wrapper(snapshot)
    if layout["end"] > CODE_CAVE_END:
        raise SystemExit("wrapper exceeds audited replaced function")

    output = bytearray(app)
    changes: list[dict[str, object]] = []
    cave_old = app[off(CODE_CAVE):off(CODE_CAVE) + len(wrapper)]
    changes.append(replace_exact(output, app, CODE_CAVE, cave_old, wrapper))
    changes.append(replace_exact(
        output, app, NOTE_ON_MEMCPY_CALL, NOTE_ON_STOCK,
        call32(NOTE_ON_MEMCPY_CALL, CODE_CAVE),
    ))
    changes.append(replace_exact(
        output, app, NOTE_OFF_MEMCPY_CALL, NOTE_OFF_STOCK,
        call32(NOTE_OFF_MEMCPY_CALL, CODE_CAVE),
    ))
    for address, expected in SYSEX_CALLS:
        changes.append(replace_exact(output, app, address, expected, b"\0" * 4))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(output)
    manifest = {
        "format": "smk37-v15-r01c-channel10-factory-mooger1-noteoff-v1",
        "input_app_sha256": sha256(app),
        "output_app_sha256": sha256(output),
        "source_dump_sha256": sha256(dump),
        "runtime_base": f"0x{RUNTIME_BASE:08x}",
        "evidence": {
            "dispatcher": "0x0201c5ec",
            "channel_register": "r9",
            "channel_10_nibble": CHANNEL_10,
            "note_on_memcpy": "0x0201c67c",
            "note_off_memcpy": "0x0201c63e",
            "factory_loader": "0x02005660",
            "memcpy": f"0x{MEMCPY:08x}",
            "live_root_cause": (
                "R01 Note On used HAND DRUM snapshot while Note Off retained "
                "the current UI patch snapshot, producing a stuck Ch10 voice"
            ),
        },
        "voice": {
            "bank": BANK,
            "preset": PRESET,
            "name": VOICE_NAME.decode("ascii"),
            "packed_flash_offset": f"0x{VOICE_OFFSET:08x}",
            "packed_sha256": sha256(packed),
            "runtime_sha256": sha256(snapshot),
        },
        "layout": {key: f"0x{value:08x}" for key, value in layout.items()},
        "changes": changes,
    }
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print("output app", sha256(output))
    print("voice", VOICE_NAME.decode("ascii"), sha256(snapshot))
    print("Note On and Note Off both routed through", f"0x{CODE_CAVE:08x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
