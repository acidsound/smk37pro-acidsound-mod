#!/usr/bin/env python3
"""Build the minimal M05 two-timbre checkpoint application image.

MIDI channel 1 retains the current FM patch. MIDI channel 2 snapshots the next
patch in the same 32-preset bank, with preset 31 wrapping to 0. Other channels
retain stock behavior. The Yamaha SysEx single-voice pack/save routine is used
as a code cave and is intentionally unavailable in M05.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import struct
from pathlib import Path


APP_BASE = 0x02000120
APP_SIZE = 615_828
STOCK_APP_SHA256 = "7383d5f02dcbb85465c14acbb20df2fa3b8452b505c65a0ac2a9139627cd95b6"

NOTE_OFF_MEMCPY_CALL = 0x0201C0C8
NOTE_ON_MEMCPY_CALL = 0x0201C1C4
CODE_CAVE = 0x0201DC14
CODE_CAVE_END = 0x0201DD3C
WRAPPER_OFF = CODE_CAVE
WRAPPER_ON = CODE_CAVE + 4
SYSEX_PACK_CALLS = (
    (0x0201DF4C, bytes.fromhex("bfea62fe")),
    (0x0201DF7A, bytes.fromhex("bfea4bfe")),
)

PATCH_LOADER = 0x020051E2
# The exact archived official v12 differs from the unit's first live dump in
# later linked-library placement. Its memcpy entry is eight bytes earlier.
MEMCPY = 0x0204850C
GLOBALS_BASE = 0x01C33700
PATCH_BUFFER = 0x01C35104
SYSEX_SCRATCH = 0x01C38460
VERSION_OFFSET = 354_750


def sha256(data: bytes | bytearray) -> str:
    return hashlib.sha256(data).hexdigest()


def app_offset(address: int) -> int:
    offset = address - APP_BASE
    if not 0 <= offset < APP_SIZE:
        raise ValueError(f"address outside app.bin: 0x{address:08x}")
    return offset


def word(value: int) -> bytes:
    return struct.pack("<H", value & 0xFFFF)


def mov_reg(destination: int, source: int) -> bytes:
    return word(0x1600 | source << 4 | destination)


def mov_imm32(destination: int, value: int) -> bytes:
    return word(0xFFC0 | destination) + struct.pack("<I", value)


def call32(at: int, target: int) -> bytes:
    displacement = target - (at + 6)
    if not -(1 << 31) <= displacement < (1 << 31):
        raise ValueError("call target outside signed 32-bit displacement")
    return b"\x80\xff" + struct.pack("<i", displacement)


def jne_imm7(at: int, register: int, immediate: int, target: int) -> bytes:
    displacement = target - (at + 4)
    if displacement & 1:
        raise ValueError("conditional branch target must be 2-byte aligned")
    halfwords = displacement // 2
    if not -256 <= halfwords <= 255:
        raise ValueError("conditional branch target outside signed 9-bit displacement")
    return word(0xF880 | register) + word(immediate << 9 | (halfwords & 0x1FF))


def emit(block: bytearray, data: bytes) -> int:
    address = CODE_CAVE + len(block)
    block.extend(data)
    return address


def build_wrapper(special_channel: int = 1) -> tuple[bytes, dict[str, int]]:
    if not 0 <= special_channel <= 15:
        raise ValueError("special MIDI channel nibble must be 0..15")
    block = bytearray()

    # Separate entry stubs normalize the channel number into r3.
    emit(block, mov_reg(3, 8))               # Note Off: channel is in r8
    emit(block, word(0x8104))                 # goto common (+2 bytes)
    emit(block, mov_reg(3, 9))               # Note On: channel is in r9
    common = CODE_CAVE + len(block)

    emit(block, word(0x0476))                 # push {rets,r6,r5,r4}
    branch_at = emit(block, b"\x00" * 4)

    emit(block, mov_reg(4, 0))                # preserve destination slot
    emit(block, bytes.fromhex("40e09403"))    # movz r0,#0x394 (bank selector offset)
    emit(block, mov_imm32(6, GLOBALS_BASE))
    emit(block, bytes.fromhex("d8ee6000"))    # lb.z r0,[r6+r0]
    emit(block, word(0x1806))                 # add r6,r0
    emit(block, bytes.fromhex("40e09003"))    # movz r0,#0x390 (preset array offset)
    emit(block, word(0x1806))                 # r6=&preset_index[bank]
    emit(block, word(0x406D))                 # lb.z r5,[r6+0]
    emit(block, word(0x8158))                 # add r0,r5,#1
    emit(block, bytes.fromhex("60e11f00"))    # and r0,r0,#0x1f
    emit(block, word(0x40E8))                 # sb r0,[r6+0]
    at = emit(block, b"\x00" * 6)
    block[at - CODE_CAVE:at - CODE_CAVE + 6] = call32(at, PATCH_LOADER)

    emit(block, mov_imm32(0, SYSEX_SCRATCH))
    emit(block, mov_imm32(1, PATCH_BUFFER))
    emit(block, word(0x3C62))                 # mov r2,#0x9c
    at = emit(block, b"\x00" * 6)
    block[at - CODE_CAVE:at - CODE_CAVE + 6] = call32(at, MEMCPY)

    emit(block, word(0x40ED))                 # restore preset index
    at = emit(block, b"\x00" * 6)
    block[at - CODE_CAVE:at - CODE_CAVE + 6] = call32(at, PATCH_LOADER)

    emit(block, mov_reg(0, 4))
    emit(block, mov_imm32(1, SYSEX_SCRATCH))
    emit(block, word(0x3C62))
    at = emit(block, b"\x00" * 6)
    block[at - CODE_CAVE:at - CODE_CAVE + 6] = call32(at, MEMCPY)
    emit(block, word(0x0456))                 # pop {pc,r6,r5,r4}

    stock_path = CODE_CAVE + len(block)
    at = emit(block, b"\x00" * 6)
    block[at - CODE_CAVE:at - CODE_CAVE + 6] = call32(at, MEMCPY)
    emit(block, word(0x0456))

    branch_slice = slice(branch_at - CODE_CAVE, branch_at - CODE_CAVE + 4)
    block[branch_slice] = jne_imm7(branch_at, 3, special_channel, stock_path)

    if CODE_CAVE + len(block) > CODE_CAVE_END:
        raise ValueError("M05 wrapper exceeds the replaced SysEx function")

    return bytes(block), {
        "wrapper_off": WRAPPER_OFF,
        "wrapper_on": WRAPPER_ON,
        "common": common,
        "stock_path": stock_path,
        "end_exclusive": CODE_CAVE + len(block),
        "size": len(block),
    }


def replace_exact(image: bytearray, address: int, old: bytes, new: bytes) -> dict[str, object]:
    if len(old) != len(new):
        raise ValueError("replacement length changed")
    offset = app_offset(address)
    actual = bytes(image[offset:offset + len(old)])
    if actual != old:
        raise ValueError(
            f"stock bytes mismatch at 0x{address:08x}: {actual.hex()} != {old.hex()}"
        )
    image[offset:offset + len(new)] = new
    return {
        "address": f"0x{address:08x}",
        "app_offset": offset,
        "old_hex": old.hex(),
        "new_hex": new.hex(),
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
    wrapper, layout = build_wrapper()
    changes: list[dict[str, object]] = []

    old_wrapper = original[
        app_offset(CODE_CAVE):app_offset(CODE_CAVE) + len(wrapper)
    ]
    changes.append(replace_exact(output, CODE_CAVE, old_wrapper, wrapper))

    stock_memcpy_call = bytes.fromhex("80ff42c30200")
    changes.append(replace_exact(
        output,
        NOTE_ON_MEMCPY_CALL,
        stock_memcpy_call,
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

    if bytes(output[VERSION_OFFSET:VERSION_OFFSET + 4]) != b"1.05":
        raise SystemExit("stock display version field is not 1.05")
    output[VERSION_OFFSET:VERSION_OFFSET + 4] = b"M05\0"
    changes.append({
        "address": None,
        "app_offset": VERSION_OFFSET,
        "old_hex": b"1.05".hex(),
        "new_hex": b"M05\0".hex(),
    })

    args.output.write_bytes(output)
    manifest = {
        "format": "smk37-m05-two-timbre-app-v1",
        "input_sha256": sha256(original),
        "output_sha256": sha256(output),
        "policy": {
            "midi_channel_1": "current patch N",
            "midi_channel_2": "same bank, patch (N + 1) & 31",
            "other_channels": "stock current patch",
            "ui": "none except M05 version marker",
            "disabled_during_checkpoint": "Yamaha SysEx single-voice pack/save",
            "scratch_ram": "SysEx receive buffer 0x01c38460",
        },
        "wrapper": {key: f"0x{value:08x}" if key != "size" else value
                    for key, value in layout.items()},
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
