#!/usr/bin/env python3
"""Build the M07 per-note channel-10 FM application image.

Local keys and MIDI channel 1 retain current patch N.  MIDI channel 10 and
the 16 factory pads map notes 36..51 to same-bank patches N+1..N+16,
wrapping within the 32-preset bank.  Note pitch, velocity, Note Off timing,
and the original local-pad MIDI output are preserved.
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


PAD_CALLBACK_HOOK = 0x0202357A
RAW_MIDI_OUTPUT = 0x0201C01C
LOCAL_FM_DISPATCH = 0x0201C272
CHANNEL_10_NIBBLE = 9
WRAPPER_OFF = CODE_CAVE
WRAPPER_ON = CODE_CAVE + 6


def add_imm8(register: int, immediate: int) -> bytes:
    """Encode the Pi32v2 in-place signed eight-bit add."""
    if not 0 <= register <= 7:
        raise ValueError("add immediate register must be r0..r7")
    if not -128 <= immediate <= 127:
        raise ValueError("add immediate must fit signed eight bits")
    encoded = immediate & 0xFF
    return word(0x20C0 | register | ((encoded >> 5) << 3) | ((encoded & 0x1F) << 8))


def add_three(destination: int, left: int, right: int) -> bytes:
    """Encode Pi32v2 ``add destination,left,right`` for r0..r7."""
    if not all(0 <= register <= 7 for register in (destination, left, right)):
        raise ValueError("three-register add operands must be r0..r7")
    split_right = ((right >> 1) << 7) | ((right & 1) << 3)
    return word(0x1C00 | destination | (left << 4) | split_right)


def build_timbre_wrapper() -> tuple[bytes, dict[str, int]]:
    block = bytearray()

    # Normalize the channel into r3 and the note into r2.  At the stock memcpy
    # call, Note Off retains note/channel in r5/r8 and Note On in r8/r9.
    block.extend(mov_reg(3, 8))               # Note Off channel
    block.extend(mov_reg(2, 5))               # Note Off note
    block.extend(word(0x8204))                 # goto common (+4 bytes)
    block.extend(mov_reg(3, 9))               # Note On channel
    block.extend(mov_reg(2, 8))               # Note On note
    common = CODE_CAVE + len(block)

    block.extend(word(0x0477))                 # push {rets,r7,r6,r5,r4}
    block.extend(mov_reg(7, 2))                # preserve note across calls
    branch_at = CODE_CAVE + len(block)
    block.extend(b"\0" * 4)

    block.extend(mov_reg(4, 0))                # preserve destination slot
    block.extend(bytes.fromhex("40e09403"))    # bank selector offset 0x394
    block.extend(mov_imm32(6, GLOBALS_BASE))
    block.extend(bytes.fromhex("d8ee6000"))    # lb.z r0,[r6+r0]
    block.extend(word(0x1806))                 # r6 += selected bank
    block.extend(bytes.fromhex("40e09003"))    # preset-index array offset 0x390
    block.extend(word(0x1806))                 # r6=&preset_index[bank]
    block.extend(word(0x406D))                 # r5=current preset N

    # Physical GM notes 36..51 become offsets 1..16.  Other Ch10 notes use the
    # same cyclic 32-note formula, keeping this checkpoint table-free.
    block.extend(mov_reg(0, 7))
    block.extend(add_imm8(0, -35))
    block.extend(bytes.fromhex("60e11f00"))    # offset=(note-35)&31
    block.extend(mov_reg(7, 0))
    block.extend(add_three(0, 5, 7))           # selected=N+offset
    block.extend(bytes.fromhex("60e11f00"))    # wrap selected within bank
    block.extend(word(0x40E8))                 # store selected preset index

    at = CODE_CAVE + len(block)
    block.extend(call32(at, PATCH_LOADER))
    block.extend(mov_imm32(0, SYSEX_SCRATCH))
    block.extend(mov_imm32(1, PATCH_BUFFER))
    block.extend(word(0x3C62))                 # mov r2,#0x9c
    at = CODE_CAVE + len(block)
    block.extend(call32(at, MEMCPY))

    block.extend(word(0x40ED))                 # restore preset index N
    at = CODE_CAVE + len(block)
    block.extend(call32(at, PATCH_LOADER))

    block.extend(mov_reg(0, 4))
    block.extend(mov_imm32(1, SYSEX_SCRATCH))
    block.extend(word(0x3C62))
    at = CODE_CAVE + len(block)
    block.extend(call32(at, MEMCPY))
    block.extend(word(0x0457))                 # pop {pc,r7,r6,r5,r4}

    stock_path = CODE_CAVE + len(block)
    at = CODE_CAVE + len(block)
    block.extend(call32(at, MEMCPY))
    block.extend(word(0x0457))

    branch_offset = branch_at - CODE_CAVE
    block[branch_offset:branch_offset + 4] = jne_imm7(
        branch_at, 3, CHANNEL_10_NIBBLE, stock_path
    )
    return bytes(block), {
        "wrapper_off": WRAPPER_OFF,
        "wrapper_on": WRAPPER_ON,
        "common": common,
        "stock_path": stock_path,
        "end_exclusive": CODE_CAVE + len(block),
        "size": len(block),
    }


def build_pad_bridge(start: int) -> tuple[bytes, dict[str, int]]:
    block = bytearray()

    block.extend(word(0x0476))                 # push {rets,r6,r5,r4}
    block.extend(mov_reg(4, 0))                # preserve message pointer
    block.extend(mov_reg(5, 1))                # preserve byte length
    nonempty_branch = start + len(block)
    block.extend(b"\0" * 4)
    block.extend(word(0x0456))                 # empty message: pop/return

    nonempty = start + len(block)
    block.extend(mov_reg(0, 4))
    block.extend(mov_reg(1, 5))
    at = start + len(block)
    block.extend(call32(at, RAW_MIDI_OUTPUT))

    length_branch = start + len(block)
    block.extend(b"\0" * 4)
    block.extend(bytes.fromhex("4840"))        # lb.z r0,[r4+0]
    block.extend(bytes.fromhex("60e10f00"))    # status channel nibble
    channel_branch = start + len(block)
    block.extend(b"\0" * 4)
    block.extend(mov_reg(0, 4))
    at = start + len(block)
    block.extend(call32(at, LOCAL_FM_DISPATCH))

    end = start + len(block)
    block.extend(word(0x0456))
    block[nonempty_branch - start:nonempty_branch - start + 4] = \
        jne_imm7(nonempty_branch, 5, 0, nonempty)
    block[length_branch - start:length_branch - start + 4] = \
        jne_imm7(length_branch, 5, 3, end)
    block[channel_branch - start:channel_branch - start + 4] = \
        jne_imm7(channel_branch, 0, CHANNEL_10_NIBBLE, end)

    return bytes(block), {
        "start": start,
        "nonempty": nonempty,
        "end_exclusive": start + len(block),
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
        raise SystemExit("M07 wrapper and pad bridge exceed replaced SysEx function")

    changes: list[dict[str, object]] = []
    cave_end = pad_start + len(pad_bridge)
    old_cave = original[app_offset(CODE_CAVE):app_offset(cave_end)]
    new_cave = bytearray(old_cave)
    new_cave[:len(wrapper)] = wrapper
    pad_offset = pad_start - CODE_CAVE
    new_cave[pad_offset:pad_offset + len(pad_bridge)] = pad_bridge
    changes.append(replace_exact(output, CODE_CAVE, old_cave, bytes(new_cave)))

    changes.append(replace_exact(
        output, NOTE_ON_MEMCPY_CALL, bytes.fromhex("80ff42c30200"),
        call32(NOTE_ON_MEMCPY_CALL, WRAPPER_ON),
    ))
    changes.append(replace_exact(
        output, NOTE_OFF_MEMCPY_CALL, bytes.fromhex("80ff3ec40200"),
        call32(NOTE_OFF_MEMCPY_CALL, WRAPPER_OFF),
    ))
    for address, stock_call in SYSEX_PACK_CALLS:
        changes.append(replace_exact(output, address, stock_call, b"\0" * 4))
    changes.append(replace_exact(
        output, PAD_CALLBACK_HOOK, bytes.fromhex("0142bfea4ec5"),
        call32(PAD_CALLBACK_HOOK, pad_start),
    ))

    if bytes(output[VERSION_OFFSET:VERSION_OFFSET + 4]) != b"1.05":
        raise SystemExit("stock display version field is not 1.05")
    output[VERSION_OFFSET:VERSION_OFFSET + 4] = b"M07\0"
    changes.append({
        "address": None,
        "app_offset": VERSION_OFFSET,
        "old_hex": b"1.05".hex(),
        "new_hex": b"M07\0".hex(),
    })

    args.output.write_bytes(output)
    manifest = {
        "format": "smk37-m07-channel10-per-note-fm-v1",
        "input_sha256": sha256(original),
        "output_sha256": sha256(output),
        "policy": {
            "midi_channel_1_and_local_keys": "current patch N",
            "midi_channel_10_and_local_pads": (
                "patch (N + ((note - 35) & 31)) & 31"
            ),
            "physical_pad_map": "notes 36..51 map to N+1..N+16",
            "note_pitch_velocity_and_note_off": "preserved",
            "other_channels": "stock current patch",
            "ui": "none except M07 version marker",
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
