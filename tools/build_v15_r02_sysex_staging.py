#!/usr/bin/env python3
"""Build v15 R02: Ch10 reads an official-product SysEx staging buffer.

R02 adds no boot-time hook and embeds no static voice snapshot.  It reuses the
exact wrapper instruction sequence that booted in R01b/R01c, changing only the
Ch10 source pointer to the official v15 bulk-patch staging buffer at
0x01c37fd0.  Note On and Note Off use the same source.

The stock packer at 0x0201e13e is replaced by the wrapper, so all three known
direct callers are neutralized.  The official one-shot product-packet handler
still copies bytes after F0 43 00 00 01 1B into staging before the neutralized
packer call.  The generated 163-byte packet places an exact 156-byte runtime
Mooger #1 voice in staging and terminates with F7.

This tool is offline only.  It never accesses a device or performs OTA.
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
    call32,
    jne_imm7,
    mov_imm32,
    mov_reg,
    off,
    replace_exact,
    sha256,
    word,
)
from dx7_vmem import unpack_voice


FORMAT = "smk37-v15-r02-channel10-sysex-staging-v1"
NOTE_ON_MEMCPY_CALL = 0x0201C67C
NOTE_ON_STOCK = bytes.fromhex("80ff4cc60200")
NOTE_OFF_MEMCPY_CALL = 0x0201C63E
NOTE_OFF_STOCK = bytes.fromhex("80ff8ac60200")
RAM_STAGING = 0x01C37FD0
VOICE_SIZE = 0x9C
MOOGER1_OFFSET = 0xF7680
MOOGER1_NAME = b"Mooger #1 "
PRODUCT_PACKET_HEADER = bytes.fromhex("f0430000011b")
PRODUCT_PACKET_SIZE = 163
PRODUCT_PACKET_SHA256 = "6a9b4097cce1d28780ef3a507f42999743cc10e09770c17c5c78d185e9abff27"
PACKER_CALLS = (
    (0x0201E468, bytes.fromhex("bfea69fe"), "one-shot product packet"),
    (0x0201E49C, bytes.fromhex("bfea4ffe"), "fragmented product packet"),
    (0x02026DAC, bytes.fromhex("bfeac7b9"), "UI SAVE path"),
)


def build_wrapper() -> tuple[bytes, dict[str, int]]:
    """Build the exact R01b wrapper shape with RAM_STAGING as the source."""
    block = bytearray()
    entry = CODE_CAVE
    block += word(0x0479)                 # push {rets,r9..r4}
    block += mov_reg(3, 9)                # r3 = MIDI channel nibble
    branch_at = CODE_CAVE + len(block)
    block += b"\0" * 4

    special = CODE_CAVE + len(block)
    block += mov_reg(4, 0)                # preserve per-voice destination
    block += mov_imm32(1, RAM_STAGING)    # exact official staging address
    block += mov_reg(0, 4)
    block += word(0x3C62)                 # r2 = 0x9c
    at = CODE_CAVE + len(block)
    block += call32(at, MEMCPY)
    block += word(0x0459)                 # pop {pc,r9..r4}

    stock = CODE_CAVE + len(block)
    at = CODE_CAVE + len(block)
    block += call32(at, MEMCPY)           # original source already in r1
    block += word(0x0459)

    block[branch_at - CODE_CAVE:branch_at - CODE_CAVE + 4] = jne_imm7(
        branch_at, 3, CHANNEL_10, stock
    )
    return bytes(block), {
        "entry": entry,
        "special": special,
        "stock": stock,
        "end": CODE_CAVE + len(block),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("app", type=Path)
    parser.add_argument("clean_dump", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--sysex-output", type=Path, required=True)
    args = parser.parse_args()

    app = args.app.read_bytes()
    dump = args.clean_dump.read_bytes()
    if len(app) != APP_SIZE or sha256(app) != APP_SHA256:
        raise SystemExit("refusing non-official v15 app")
    if len(dump) != DUMP_SIZE or sha256(dump) != DUMP_SHA256:
        raise SystemExit("refusing non-baseline v15 full flash dump")

    packed = dump[MOOGER1_OFFSET:MOOGER1_OFFSET + 128]
    if packed[118:128] != MOOGER1_NAME:
        raise SystemExit("factory Mooger #1 identity mismatch")
    runtime_voice = unpack_voice(packed)
    if len(runtime_voice) != VOICE_SIZE or runtime_voice[155] != 0x3F:
        raise SystemExit("unexpected runtime voice layout")
    packet = PRODUCT_PACKET_HEADER + runtime_voice + b"\xF7"
    if len(packet) != PRODUCT_PACKET_SIZE or sha256(packet) != PRODUCT_PACKET_SHA256:
        raise SystemExit("runtime product packet invariant mismatch")

    wrapper, layout = build_wrapper()
    if layout["end"] > CODE_CAVE_END:
        raise SystemExit("wrapper exceeds replaced packer entry region")

    output = bytearray(app)
    changes: list[dict[str, object]] = []
    old_wrapper = app[off(CODE_CAVE):off(CODE_CAVE) + len(wrapper)]
    changes.append(replace_exact(output, app, CODE_CAVE, old_wrapper, wrapper))
    changes.append(replace_exact(
        output, app, NOTE_ON_MEMCPY_CALL, NOTE_ON_STOCK,
        call32(NOTE_ON_MEMCPY_CALL, CODE_CAVE),
    ))
    changes.append(replace_exact(
        output, app, NOTE_OFF_MEMCPY_CALL, NOTE_OFF_STOCK,
        call32(NOTE_OFF_MEMCPY_CALL, CODE_CAVE),
    ))
    for address, expected, purpose in PACKER_CALLS:
        change = replace_exact(output, app, address, expected, b"\0" * 4)
        change["purpose"] = purpose
        changes.append(change)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.sysex_output.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(output)
    args.sysex_output.write_bytes(packet)

    manifest = {
        "format": FORMAT,
        "artifact_scope": "offline artifact integrity only; not a live functional claim",
        "input_app_sha256": sha256(app),
        "output_app_sha256": sha256(output),
        "source_dump_sha256": sha256(dump),
        "runtime_base": f"0x{RUNTIME_BASE:08x}",
        "design": {
            "boot_time_hook": None,
            "embedded_voice": False,
            "channel_register": "r9",
            "channel_10_nibble": CHANNEL_10,
            "note_on_memcpy": "0x0201c67c",
            "note_off_memcpy": "0x0201c63e",
            "runtime_source": f"0x{RAM_STAGING:08x}",
            "source_length": VOICE_SIZE,
            "one_shot_handler_copy": "message+6 to 0x01c37030+0xfa0",
            "disabled_packer_callers": [f"0x{x[0]:08x}" for x in PACKER_CALLS],
            "save_behavior": "disabled while R02 is installed",
        },
        "voice_packet": {
            "name": MOOGER1_NAME.decode("ascii"),
            "packed_flash_offset": f"0x{MOOGER1_OFFSET:08x}",
            "runtime_sha256": sha256(runtime_voice),
            "header_hex": PRODUCT_PACKET_HEADER.hex(),
            "size": len(packet),
            "sha256": sha256(packet),
            "terminator": "f7",
        },
        "layout": {key: f"0x{value:08x}" for key, value in layout.items()},
        "changes": changes,
        "live_test_order": [
            "boot and verify firmware 015 before touching pads",
            "send the exact generated runtime product packet once",
            "compare Bank D display 14 keyboard sound with Pad Ch10",
            "change Ch1 UI patch and confirm Ch10 remains Mooger #1",
            "verify repeated Ch10 Note On/Off with no stuck voice",
            "do not press SAVE or send another preset SysEx during this checkpoint",
        ],
    }
    args.manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print("output app", sha256(output))
    print("runtime packet", len(packet), sha256(packet))
    print("wrapper", f"0x{layout['entry']:08x}..0x{layout['end']:08x}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
