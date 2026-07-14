#!/usr/bin/env python3
"""Reproduce the revoked M09 app image for offline forensic analysis only."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from build_m05_app import (
    APP_SIZE,
    CODE_CAVE,
    CODE_CAVE_END,
    MEMCPY,
    NOTE_OFF_MEMCPY_CALL,
    NOTE_ON_MEMCPY_CALL,
    STOCK_APP_SHA256,
    SYSEX_PACK_CALLS,
    VERSION_OFFSET,
    app_offset,
    call32,
    jne_imm7,
    mov_imm32,
    mov_reg,
    replace_exact,
    sha256,
    word,
)
from build_m07_app import add_imm8
from build_m08_app import CHANNEL_10_NIBBLE, forward_goto
from dx7_vmem import RUNTIME_VOICE_SIZE, self_test as dx7_self_test
from m09_drum_voices import NOTE_TEMPLATE_KEYS, TEMPLATES, build_runtime_templates


PAD_CALLBACK_HOOK = 0x0202357A
DATA_CAVE_START = 0x020959EE
DATA_CAVE_END = 0x02095F96
SUPPORTED_NOTE_BASE = 36
SUPPORTED_NOTE_MASK = 0x0F


def add_register(destination: int, source: int) -> bytes:
    if not all(0 <= register <= 15 for register in (destination, source)):
        raise ValueError("register add operands must be r0..r15")
    return word(0x1800 | destination | (source << 4))


def load_byte_indexed(destination: int, base: int, index: int) -> bytes:
    if not all(0 <= register <= 15 for register in (destination, base, index)):
        raise ValueError("indexed byte-load registers must be r0..r15")
    return word(0xEED8) + word((destination << 12) | (index << 8) | (base << 4))


def multiply_immediate(destination: int, source: int, immediate: int) -> bytes:
    if not all(0 <= register <= 15 for register in (destination, source)):
        raise ValueError("multiply registers must be r0..r15")
    if not 0 <= immediate <= 0xFF:
        raise ValueError("packed multiply immediate must fit eight bits")
    return word(0xE1E0 | destination) + word((source << 12) | immediate)


def build_timbre_wrapper(template_address: int, map_address: int) -> tuple[bytes, dict[str, int]]:
    block = bytearray()

    wrapper_off = CODE_CAVE + len(block)
    block.extend(word(0x0479))                 # push {rets,r9..r4}
    block.extend(mov_reg(3, 8))                # Note Off channel
    off_stock_branch = CODE_CAVE + len(block)
    block.extend(b"\0" * 4)
    block.extend(mov_reg(7, 5))                # Note Off note
    off_special_goto = CODE_CAVE + len(block)
    block.extend(b"\0" * 2)

    wrapper_on = CODE_CAVE + len(block)
    block.extend(word(0x0479))                 # push {rets,r9..r4}
    block.extend(mov_reg(3, 9))                # Note On channel
    on_stock_branch = CODE_CAVE + len(block)
    block.extend(b"\0" * 4)
    block.extend(mov_reg(7, 8))                # Note On note

    special = CODE_CAVE + len(block)
    block.extend(mov_reg(4, 0))                # preserve event destination
    block.extend(mov_reg(0, 7))                # note
    block.extend(add_imm8(0, -SUPPORTED_NOTE_BASE))
    block.extend(bytes.fromhex("60e10f00"))    # safe cyclic index 0..15
    block.extend(mov_imm32(1, map_address))
    block.extend(load_byte_indexed(0, 1, 0))   # template ID
    block.extend(multiply_immediate(0, 0, RUNTIME_VOICE_SIZE))
    block.extend(mov_imm32(1, template_address))
    block.extend(add_register(1, 0))           # selected 156-byte snapshot
    block.extend(mov_reg(0, 4))                # event destination
    block.extend(word(0x3C62))                 # mov r2,#0x9c
    at = CODE_CAVE + len(block)
    block.extend(call32(at, MEMCPY))
    block.extend(word(0x0459))                 # pop {pc,r9..r4}

    stock_path = CODE_CAVE + len(block)
    at = CODE_CAVE + len(block)
    block.extend(call32(at, MEMCPY))
    block.extend(word(0x0459))

    for branch_at in (off_stock_branch, on_stock_branch):
        offset = branch_at - CODE_CAVE
        block[offset:offset + 4] = jne_imm7(
            branch_at, 3, CHANNEL_10_NIBBLE, stock_path
        )
    goto_offset = off_special_goto - CODE_CAVE
    block[goto_offset:goto_offset + 2] = forward_goto(off_special_goto, special)
    return bytes(block), {
        "wrapper_off": wrapper_off,
        "wrapper_on": wrapper_on,
        "special": special,
        "stock_path": stock_path,
        "end_exclusive": CODE_CAVE + len(block),
        "size": len(block),
    }


def build_pad_bridge(start: int) -> tuple[bytes, dict[str, int]]:
    from build_m07_app import build_pad_bridge as inherited_bridge
    return inherited_bridge(start)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--manifest", type=Path)
    args = parser.parse_args()

    dx7_self_test()
    original = args.input.read_bytes()
    if len(original) != APP_SIZE or sha256(original) != STOCK_APP_SHA256:
        raise SystemExit("input is not the byte-exact official v12 app.bin")
    output = bytearray(original)

    runtime_templates, note_map = build_runtime_templates()
    data = runtime_templates + note_map
    if DATA_CAVE_START + len(data) > DATA_CAVE_END:
        raise SystemExit("M09 drum data exceeds the audited zero data cave")
    old_data = original[
        app_offset(DATA_CAVE_START):app_offset(DATA_CAVE_START + len(data))
    ]
    if old_data != b"\0" * len(data):
        raise SystemExit("M09 data cave is not byte-exact zero-filled stock data")
    map_address = DATA_CAVE_START + len(runtime_templates)

    wrapper, wrapper_layout = build_timbre_wrapper(DATA_CAVE_START, map_address)
    pad_start = (CODE_CAVE + len(wrapper) + 1) & ~1
    pad_bridge, pad_layout = build_pad_bridge(pad_start)
    if pad_start + len(pad_bridge) > CODE_CAVE_END:
        raise SystemExit("M09 wrapper and pad bridge exceed replaced SysEx function")

    changes: list[dict[str, object]] = []
    cave_end = pad_start + len(pad_bridge)
    old_cave = original[app_offset(CODE_CAVE):app_offset(cave_end)]
    new_cave = bytearray(old_cave)
    new_cave[:len(wrapper)] = wrapper
    pad_offset = pad_start - CODE_CAVE
    new_cave[pad_offset:pad_offset + len(pad_bridge)] = pad_bridge
    changes.append(replace_exact(output, CODE_CAVE, old_cave, bytes(new_cave)))
    changes.append(replace_exact(output, DATA_CAVE_START, old_data, data))
    changes.append(replace_exact(
        output, NOTE_ON_MEMCPY_CALL, bytes.fromhex("80ff42c30200"),
        call32(NOTE_ON_MEMCPY_CALL, wrapper_layout["wrapper_on"]),
    ))
    changes.append(replace_exact(
        output, NOTE_OFF_MEMCPY_CALL, bytes.fromhex("80ff3ec40200"),
        call32(NOTE_OFF_MEMCPY_CALL, wrapper_layout["wrapper_off"]),
    ))
    for address, stock_call in SYSEX_PACK_CALLS:
        changes.append(replace_exact(output, address, stock_call, b"\0" * 4))
    changes.append(replace_exact(
        output, PAD_CALLBACK_HOOK, bytes.fromhex("0142bfea4ec5"),
        call32(PAD_CALLBACK_HOOK, pad_start),
    ))
    if bytes(output[VERSION_OFFSET:VERSION_OFFSET + 4]) != b"1.05":
        raise SystemExit("stock display version field is not 1.05")
    output[VERSION_OFFSET:VERSION_OFFSET + 4] = b"M09\0"
    changes.append({
        "address": None,
        "app_offset": VERSION_OFFSET,
        "old_hex": b"1.05".hex(),
        "new_hex": b"M09\0".hex(),
    })

    args.output.write_bytes(output)
    manifest = {
        "format": "smk37-m09-app-resident-channel10-dx7-drums-v1",
        "input_sha256": sha256(original),
        "output_sha256": sha256(output),
        "policy": {
            "midi_channel_1_and_local_keys": "UI-selected current bank/patch",
            "midi_channel_10_and_local_pads": "app-resident DX7 drum templates",
            "physical_pad_map": "GM notes 36..51",
            "ui_patch_effect": "Ch1 only; Ch10 does not call the factory patch loader",
            "global_patch_state": "not read or modified by Ch10",
            "note_pitch_velocity_and_note_off": "preserved",
            "other_channels": "stock current patch",
            "out_of_range_channel10_notes": "cyclic alias through (note-36)&15",
            "disabled_during_checkpoint": "Yamaha SysEx single-voice pack/save",
        },
        "runtime_data": {
            "start": f"0x{DATA_CAVE_START:08x}",
            "end_exclusive": f"0x{DATA_CAVE_START + len(data):08x}",
            "audited_cave_end": f"0x{DATA_CAVE_END:08x}",
            "template_bytes": len(runtime_templates),
            "map_bytes": len(note_map),
            "template_names": [template.key for template in TEMPLATES],
            "gm_note_template_keys": list(NOTE_TEMPLATE_KEYS),
        },
        "timbre_wrapper": {
            key: f"0x{value:08x}" if key != "size" else value
            for key, value in wrapper_layout.items()
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
