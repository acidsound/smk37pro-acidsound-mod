#!/usr/bin/env python3
"""Build the M06 local-pad/channel-10 FM checkpoint application image.

MIDI channel 1 and the local keyboard retain current patch N. MIDI channel 10
and local raw-MIDI pad events snapshot the next patch in the same 32-preset
bank, with preset 31 wrapping to 0. The 16 factory pads retain notes 36..51,
velocity, and their original Note On/Off timing.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from build_m05_app import (
    APP_SIZE,
    CODE_CAVE,
    CODE_CAVE_END,
    NOTE_OFF_MEMCPY_CALL,
    NOTE_ON_MEMCPY_CALL,
    STOCK_APP_SHA256,
    SYSEX_PACK_CALLS,
    VERSION_OFFSET,
    WRAPPER_OFF,
    WRAPPER_ON,
    app_offset,
    build_wrapper,
    call32,
    jne_imm7,
    mov_reg,
    replace_exact,
    sha256,
    word,
)


PAD_CALLBACK_HOOK = 0x0202357A
PAD_BRIDGE = 0x0201DC80
RAW_MIDI_OUTPUT = 0x0201C01C
LOCAL_FM_DISPATCH = 0x0201C272
CHANNEL_10_NIBBLE = 9


def build_pad_bridge() -> tuple[bytes, dict[str, int]]:
    block = bytearray()

    block.extend(word(0x0476))                 # push {rets,r6,r5,r4}
    block.extend(mov_reg(4, 0))                # preserve message pointer
    block.extend(mov_reg(5, 1))                # preserve byte length
    nonempty_branch = PAD_BRIDGE + len(block)
    block.extend(b"\0" * 4)
    block.extend(word(0x0456))                 # empty message: pop/return

    nonempty = PAD_BRIDGE + len(block)
    block.extend(mov_reg(0, 4))
    block.extend(mov_reg(1, 5))
    at = PAD_BRIDGE + len(block)
    block.extend(call32(at, RAW_MIDI_OUTPUT))

    length_branch = PAD_BRIDGE + len(block)
    block.extend(b"\0" * 4)
    block.extend(bytes.fromhex("4840"))        # lb.z r0,[r4+0]
    block.extend(bytes.fromhex("60e10f00"))    # and r0,r0,#0x0f
    channel_branch = PAD_BRIDGE + len(block)
    block.extend(b"\0" * 4)
    block.extend(mov_reg(0, 4))
    at = PAD_BRIDGE + len(block)
    block.extend(call32(at, LOCAL_FM_DISPATCH))

    end = PAD_BRIDGE + len(block)
    block.extend(word(0x0456))                 # pop/return

    block[nonempty_branch - PAD_BRIDGE:nonempty_branch - PAD_BRIDGE + 4] = \
        jne_imm7(nonempty_branch, 5, 0, nonempty)
    block[length_branch - PAD_BRIDGE:length_branch - PAD_BRIDGE + 4] = \
        jne_imm7(length_branch, 5, 3, end)
    block[channel_branch - PAD_BRIDGE:channel_branch - PAD_BRIDGE + 4] = \
        jne_imm7(channel_branch, 0, CHANNEL_10_NIBBLE, end)

    return bytes(block), {
        "start": PAD_BRIDGE,
        "nonempty": nonempty,
        "end_exclusive": PAD_BRIDGE + len(block),
        "size": len(block),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()

    original = args.input.read_bytes()
    if len(original) != APP_SIZE or sha256(original) != STOCK_APP_SHA256:
        raise SystemExit("input is not the byte-exact official v12 app.bin")
    output = bytearray(original)
    timbre_wrapper, timbre_layout = build_wrapper(CHANNEL_10_NIBBLE)
    pad_bridge, pad_layout = build_pad_bridge()
    if PAD_BRIDGE < CODE_CAVE + len(timbre_wrapper):
        raise SystemExit("M06 wrappers overlap")
    if PAD_BRIDGE + len(pad_bridge) > CODE_CAVE_END:
        raise SystemExit("M06 wrappers exceed replaced SysEx function")

    changes: list[dict[str, object]] = []
    old_cave = original[
        app_offset(CODE_CAVE):app_offset(PAD_BRIDGE) + len(pad_bridge)
    ]
    new_cave = bytearray(old_cave)
    new_cave[:len(timbre_wrapper)] = timbre_wrapper
    pad_offset = PAD_BRIDGE - CODE_CAVE
    new_cave[pad_offset:pad_offset + len(pad_bridge)] = pad_bridge
    changes.append(replace_exact(output, CODE_CAVE, old_cave, bytes(new_cave)))

    changes.append(replace_exact(
        output,
        NOTE_ON_MEMCPY_CALL,
        bytes.fromhex("80ff42c30200"),
        call32(NOTE_ON_MEMCPY_CALL, WRAPPER_ON),
    ))
    changes.append(replace_exact(
        output,
        NOTE_OFF_MEMCPY_CALL,
        bytes.fromhex("80ff3ec40200"),
        call32(NOTE_OFF_MEMCPY_CALL, WRAPPER_OFF),
    ))
    for address, stock_call in SYSEX_PACK_CALLS:
        changes.append(replace_exact(output, address, stock_call, b"\0" * 4))

    # Replace the raw callback's stock zero-length test plus short call with a
    # long call to the bridge. The stock pop/return immediately afterward stays.
    changes.append(replace_exact(
        output,
        PAD_CALLBACK_HOOK,
        bytes.fromhex("0142bfea4ec5"),
        call32(PAD_CALLBACK_HOOK, PAD_BRIDGE),
    ))

    if bytes(output[VERSION_OFFSET:VERSION_OFFSET + 4]) != b"1.05":
        raise SystemExit("stock display version field is not 1.05")
    output[VERSION_OFFSET:VERSION_OFFSET + 4] = b"M06\0"
    changes.append({
        "address": None,
        "app_offset": VERSION_OFFSET,
        "old_hex": b"1.05".hex(),
        "new_hex": b"M06\0".hex(),
    })

    args.output.write_bytes(output)
    manifest = {
        "format": "smk37-m06-local-pad-channel10-fm-v1",
        "input_sha256": sha256(original),
        "output_sha256": sha256(output),
        "policy": {
            "midi_channel_1_and_local_keys": "current patch N",
            "midi_channel_10_and_local_pads": "same bank, patch (N + 1) & 31",
            "local_pad_notes": "preserve factory notes 36..51, velocity, note-off",
            "other_channels": "stock current patch",
            "ui": "none except M06 version marker",
            "disabled_during_checkpoint": "Yamaha SysEx single-voice pack/save",
        },
        "timbre_wrapper": {
            key: f"0x{value:08x}" if key != "size" else value
            for key, value in timbre_layout.items()
        },
        "pad_bridge": {
            key: f"0x{value:08x}" if key != "size" else value
            for key, value in pad_layout.items()
        },
        "changes": changes,
    }
    rendered = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    if args.manifest:
        args.manifest.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
