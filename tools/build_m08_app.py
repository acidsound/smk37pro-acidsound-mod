#!/usr/bin/env python3
"""Build the M08 isolated channel-10 fixed-map FM application image.

Local keys and MIDI channel 1 retain the UI-selected bank and patch. MIDI
channel 10 and the factory pads use a fixed logical map: notes 36..51 select
factory bank 0 presets 0..15. The temporary global bank/preset selection is
restored after each per-voice snapshot, so Patch UI changes affect Ch1 only.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from build_m05_app import (
    APP_SIZE,
    CODE_CAVE,
    CODE_CAVE_END,
    GLOBALS_BASE,
    MEMCPY,
    NOTE_OFF_MEMCPY_CALL,
    NOTE_ON_MEMCPY_CALL,
    PATCH_BUFFER,
    PATCH_LOADER,
    STOCK_APP_SHA256,
    SYSEX_PACK_CALLS,
    SYSEX_SCRATCH,
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
from build_m07_app import add_imm8, build_pad_bridge


CHANNEL_10_NIBBLE = 9
BANK_SELECTOR = GLOBALS_BASE + 0x394
PRESET_INDEX_ARRAY = GLOBALS_BASE + 0x390
FIXED_DRUM_BANK = 0
PAD_CALLBACK_HOOK = 0x0202357A


def mov_imm8(register: int, immediate: int) -> bytes:
    if not 0 <= register <= 7:
        raise ValueError("small-immediate destination must be r0..r7")
    if not 0 <= immediate <= 0xFF:
        raise ValueError("small immediate must fit eight bits")
    return word(
        0x2040
        | register
        | ((immediate >> 5) << 3)
        | ((immediate & 0x1F) << 8)
    )


def load_byte(destination: int, base: int, offset: int = 0) -> bytes:
    if not all(0 <= register <= 7 for register in (destination, base)):
        raise ValueError("byte-load registers must be r0..r7")
    if not -16 <= offset <= 15:
        raise ValueError("byte-load offset must fit signed five bits")
    return word(0x4008 | destination | (base << 4) | ((offset & 0x1F) << 8))


def store_byte(source: int, base: int, offset: int = 0) -> bytes:
    if not all(0 <= register <= 7 for register in (source, base)):
        raise ValueError("byte-store registers must be r0..r7")
    if not -16 <= offset <= 15:
        raise ValueError("byte-store offset must fit signed five bits")
    return word(0x4088 | source | (base << 4) | ((offset & 0x1F) << 8))


def forward_goto(at: int, target: int) -> bytes:
    displacement = target - (at + 2)
    if displacement < 0 or displacement & 1:
        raise ValueError("forward goto requires a nonnegative aligned target")
    halfwords = displacement // 2
    if halfwords > 31:
        raise ValueError("forward goto exceeds compact encoding")
    return word(0x8004 | (halfwords << 8))


def build_timbre_wrapper() -> tuple[bytes, dict[str, int]]:
    block = bytearray()

    # Each entry performs the channel gate before reading or moving the note.
    # This preserves the exact M06 channel-source registers while avoiding the
    # pre-gate r2/r3 disturbance that regressed M07 isolation.
    wrapper_off = CODE_CAVE + len(block)
    block.extend(word(0x0479))                 # push {rets,r9..r4}
    block.extend(mov_reg(3, 8))                # Note Off channel
    off_stock_branch = CODE_CAVE + len(block)
    block.extend(b"\0" * 4)
    block.extend(mov_reg(7, 5))                # Note Off note, after gate
    off_special_goto = CODE_CAVE + len(block)
    block.extend(b"\0" * 2)

    wrapper_on = CODE_CAVE + len(block)
    block.extend(word(0x0479))                 # push {rets,r9..r4}
    block.extend(mov_reg(3, 9))                # Note On channel
    on_stock_branch = CODE_CAVE + len(block)
    block.extend(b"\0" * 4)
    block.extend(mov_reg(7, 8))                # Note On note, after gate

    special = CODE_CAVE + len(block)
    block.extend(mov_reg(4, 0))                # preserve destination slot

    # Save UI-selected bank and the fixed bank's preset index.
    block.extend(mov_imm32(0, BANK_SELECTOR))
    block.extend(load_byte(5, 0))              # r5=UI bank
    block.extend(mov_imm32(0, PRESET_INDEX_ARRAY + FIXED_DRUM_BANK))
    block.extend(load_byte(6, 0))              # r6=old bank-0 preset

    # Physical notes 36..51 become fixed preset IDs 0..15.
    block.extend(mov_reg(0, 7))
    block.extend(add_imm8(0, -36))
    block.extend(bytes.fromhex("60e11f00"))    # preset=(note-36)&31
    block.extend(mov_reg(7, 0))

    # Temporarily select fixed bank 0 and the mapped preset.
    block.extend(mov_imm32(0, BANK_SELECTOR))
    block.extend(mov_imm8(1, FIXED_DRUM_BANK))
    block.extend(store_byte(1, 0))
    block.extend(mov_imm32(0, PRESET_INDEX_ARRAY + FIXED_DRUM_BANK))
    block.extend(store_byte(7, 0))
    at = CODE_CAVE + len(block)
    block.extend(call32(at, PATCH_LOADER))

    block.extend(mov_imm32(0, SYSEX_SCRATCH))
    block.extend(mov_imm32(1, PATCH_BUFFER))
    block.extend(word(0x3C62))                 # mov r2,#0x9c
    at = CODE_CAVE + len(block)
    block.extend(call32(at, MEMCPY))

    # Restore both pieces of UI state, then reload the UI patch buffer.
    block.extend(mov_imm32(0, PRESET_INDEX_ARRAY + FIXED_DRUM_BANK))
    block.extend(store_byte(6, 0))
    block.extend(mov_imm32(0, BANK_SELECTOR))
    block.extend(store_byte(5, 0))
    at = CODE_CAVE + len(block)
    block.extend(call32(at, PATCH_LOADER))

    block.extend(mov_reg(0, 4))
    block.extend(mov_imm32(1, SYSEX_SCRATCH))
    block.extend(word(0x3C62))
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
    wrapper, wrapper_layout = build_timbre_wrapper()
    pad_start = (CODE_CAVE + len(wrapper) + 1) & ~1
    pad_bridge, pad_layout = build_pad_bridge(pad_start)
    if pad_start + len(pad_bridge) > CODE_CAVE_END:
        raise SystemExit("M08 wrapper and pad bridge exceed replaced SysEx function")

    cave_end = pad_start + len(pad_bridge)
    old_cave = original[app_offset(CODE_CAVE):app_offset(cave_end)]
    new_cave = bytearray(old_cave)
    new_cave[:len(wrapper)] = wrapper
    pad_offset = pad_start - CODE_CAVE
    new_cave[pad_offset:pad_offset + len(pad_bridge)] = pad_bridge
    changes: list[dict[str, object]] = [
        replace_exact(output, CODE_CAVE, old_cave, bytes(new_cave))
    ]

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
    output[VERSION_OFFSET:VERSION_OFFSET + 4] = b"M08\0"
    changes.append({
        "address": None,
        "app_offset": VERSION_OFFSET,
        "old_hex": b"1.05".hex(),
        "new_hex": b"M08\0".hex(),
    })

    args.output.write_bytes(output)
    manifest = {
        "format": "smk37-m08-isolated-fixed-channel10-map-v1",
        "input_sha256": sha256(original),
        "output_sha256": sha256(output),
        "policy": {
            "midi_channel_1_and_local_keys": "UI-selected current bank/patch",
            "midi_channel_10_and_local_pads": "fixed bank 0 presets 0..15",
            "physical_pad_map": "notes 36..51 map to fixed preset IDs 0..15",
            "ui_patch_effect": "Ch1 only; Ch10 mapping is fixed",
            "global_state": "bank selector and bank-0 preset index restored per event",
            "note_pitch_velocity_and_note_off": "preserved",
            "other_channels": "stock current patch",
            "ui": "none except M08 version marker",
            "disabled_during_checkpoint": "Yamaha SysEx single-voice pack/save",
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
