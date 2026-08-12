#!/usr/bin/env python3
"""Build the offline-only v15 R03 fixed-heap-prefix controlled checkpoint.

R03 reserves a zeroed 0xa0-byte prefix immediately before the shifted heap,
copies an accepted product voice from the stock staging buffer into that owned
region, and routes Channel 10 Note On and Note Off through the same voice.

The stock packer body is replaced by the R03 wrappers. SAVE is therefore
explicitly disabled while this checkpoint is installed. No boot-time call hook,
device access, OTA, or flash write is performed by this tool.
"""
from __future__ import annotations

import argparse
import json
import struct
from pathlib import Path

from build_v15_r01_hand_drum import (
    APP_SHA256,
    APP_SIZE,
    CHANNEL_10,
    CODE_CAVE,
    CODE_CAVE_END,
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

FORMAT = "smk37-v15-r03-fixed-heap-prefix-v1"
NOTE_OFF_CALL = 0x0201C63E
NOTE_OFF_STOCK = bytes.fromhex("80ff8ac60200")
NOTE_ON_CALL = 0x0201C67C
NOTE_ON_STOCK = bytes.fromhex("80ff4cc60200")
PRODUCT_CALLS = (
    (0x0201E468, bytes.fromhex("bfea69fe"), "one-shot accepted product packet"),
    (0x0201E49C, bytes.fromhex("bfea4ffe"), "segmented accepted product packet"),
)
SAVE_REJECT_CALL = 0x02026DA6
SAVE_REJECT_STOCK = bytes.fromhex("beeaacee")
SAVE_REJECT_BRANCH = bytes.fromhex("04960000")  # goto 0x02026dd4; nop
SAVE_CALL = 0x02026DAC
SAVE_STOCK = bytes.fromhex("bfeac7b9")

BSS_SIZE_INSN = 0x0200001E
BSS_SIZE_STOCK = bytes.fromhex("c2ff48cb0300")
BSS_SIZE_R03 = bytes.fromhex("c2ffeccb0300")  # 0x3cbec: zero through 0x01c465c0
HEAP_BEGIN_INSN = 0x0205E9F8
HEAP_BEGIN_STOCK = bytes.fromhex("c5ff2065c401")
HEAP_BEGIN_R03 = bytes.fromhex("c5ffc065c401")

STAGING = 0x01C37FD0
VOICE = 0x01C46520
VALID = 0x01C465BC
LOCK = 0x01C465BD
RESERVED_END = 0x01C465C0
VOICE_SIZE = 0x9C
SHORT_CALL_WINDOW_BYTES = 0x20000
ATOMIC_TRY_PREFIX = bytes.fromhex("2000b000")  # csync; testset b[r0]
ATOMIC_SUCCESS_BARRIER = bytes.fromhex("2000")


def short_call(at: int, target: int) -> bytes:
    """Encode the v15-observed four-byte PI32 short call."""
    displacement = target - (at + 4)
    if displacement & 1:
        raise ValueError("unaligned short-call target")
    halfwords = displacement // 2
    if (at + 4 + ((halfwords & 0xFFFF) * 2)) % SHORT_CALL_WINDOW_BYTES != target % SHORT_CALL_WINDOW_BYTES:
        raise ValueError("short-call target outside architectural window")
    return b"\xbf\xea" + struct.pack("<H", halfwords & 0xFFFF)


def add_imm8(register: int, immediate: int) -> bytes:
    """Encode the PI32v2 in-place signed eight-bit add."""
    if not 0 <= register <= 7 or not -128 <= immediate <= 127:
        raise ValueError("add immediate operands out of range")
    encoded = immediate & 0xFF
    return word(0x20C0 | register | ((encoded >> 5) << 3) | ((encoded & 0x1F) << 8))


def mov_imm8(register: int, immediate: int) -> bytes:
    if not 0 <= register <= 7 or not 0 <= immediate <= 0xFF:
        raise ValueError("small move operands out of range")
    return word(0x2040 | register | ((immediate >> 5) << 3) | ((immediate & 0x1F) << 8))


def ifeq(at: int, target: int) -> bytes:
    """Encode the official-toolchain PI32v2 `ifeq goto` relative branch."""
    displacement = target - (at + 4)
    if displacement & 1 or not -0x10000 <= displacement <= 0xFFFE:
        raise ValueError("ifeq target out of range or unaligned")
    return bytes.fromhex("40e8") + struct.pack("<h", displacement // 2)


def load_byte(destination: int, base: int, offset: int = 0) -> bytes:
    if not all(0 <= register <= 7 for register in (destination, base)) or not -16 <= offset <= 15:
        raise ValueError("byte load operands out of range")
    return word(0x4008 | destination | (base << 4) | ((offset & 0x1F) << 8))


def store_byte(source: int, base: int, offset: int = 0) -> bytes:
    if not all(0 <= register <= 7 for register in (source, base)) or not -16 <= offset <= 15:
        raise ValueError("byte store operands out of range")
    return word(0x4088 | source | (base << 4) | ((offset & 0x1F) << 8))


def build_cave() -> tuple[bytes, dict[str, int]]:
    block = bytearray()
    branches: list[tuple[int, int, int, str]] = []

    off_entry = CODE_CAVE + len(block)
    block += word(0x0479)                 # push {rets,r9..r4}
    block += mov_reg(3, 9)                # channel nibble, R02-live-proven
    off_channel_branch = CODE_CAVE + len(block)
    block += b"\0" * 4
    block += mov_reg(5, 0)                # preserve destination
    block += mov_imm32(4, VALID)
    block += load_byte(0, 4)
    off_valid_branch = CODE_CAVE + len(block)
    block += b"\0" * 4
    block += mov_reg(0, 5)
    block += mov_imm32(1, VOICE)
    block += word(0x3C62)                 # r2 = 0x9c
    at = CODE_CAVE + len(block)
    block += call32(at, MEMCPY)
    block += word(0x0459)
    off_stock = CODE_CAVE + len(block)
    at = CODE_CAVE + len(block)
    block += call32(at, MEMCPY)
    block += word(0x0459)
    branches += [
        (off_channel_branch, 3, CHANNEL_10, "off-stock"),
        (off_valid_branch, 0, 1, "off-stock"),
    ]

    on_entry = CODE_CAVE + len(block)
    block += word(0x0479)
    block += mov_reg(3, 9)
    on_channel_branch = CODE_CAVE + len(block)
    block += b"\0" * 4
    block += mov_reg(5, 0)
    block += mov_imm32(4, VALID)
    block += load_byte(0, 4)
    on_valid_branch = CODE_CAVE + len(block)
    block += b"\0" * 4
    block += mov_reg(0, 5)
    block += mov_imm32(1, VOICE)
    block += word(0x3C62)
    at = CODE_CAVE + len(block)
    block += call32(at, MEMCPY)
    block += word(0x0459)
    on_stock = CODE_CAVE + len(block)
    at = CODE_CAVE + len(block)
    block += call32(at, MEMCPY)
    block += word(0x0459)
    branches += [
        (on_channel_branch, 3, CHANNEL_10, "on-stock"),
        (on_valid_branch, 0, 1, "on-stock"),
    ]

    producer = CODE_CAVE + len(block)
    block += word(0x0479)
    block += mov_reg(4, 0)                # accepted staging pointer
    block += mov_imm32(0, LOCK)
    block += ATOMIC_TRY_PREFIX
    try_fail_branch = CODE_CAVE + len(block)
    block += b"\0" * 4
    block += ATOMIC_SUCCESS_BARRIER
    block += mov_imm32(5, VALID)
    block += load_byte(0, 5)
    producer_valid_branch = CODE_CAVE + len(block)
    block += b"\0" * 4
    block += mov_imm32(0, VOICE)
    block += mov_reg(1, 4)
    block += word(0x3C62)
    at = CODE_CAVE + len(block)
    block += call32(at, MEMCPY)
    block += mov_imm32(5, VALID)
    block += mov_imm8(0, 1)
    block += store_byte(0, 5)             # publish validity last
    producer_unlock = CODE_CAVE + len(block)
    block += mov_imm32(0, LOCK)
    block += word(0x0020)                 # csync
    block += mov_imm8(1, 0)
    block += store_byte(1, 0)
    block += word(0x0020)                 # csync
    producer_return = CODE_CAVE + len(block)
    block += word(0x0459)
    branches.append((producer_valid_branch, 0, 0, "producer-unlock"))
    start = try_fail_branch - CODE_CAVE
    block[start:start + 4] = ifeq(try_fail_branch, producer_return)

    targets = {
        "off-stock": off_stock,
        "on-stock": on_stock,
        "producer-unlock": producer_unlock,
    }
    for address, register, immediate, target_name in branches:
        start = address - CODE_CAVE
        block[start:start + 4] = jne_imm7(address, register, immediate, targets[target_name])

    layout = {
        "off_entry": off_entry,
        "off_stock": off_stock,
        "on_entry": on_entry,
        "on_stock": on_stock,
        "producer": producer,
        "try_fail_branch": try_fail_branch,
        "producer_unlock": producer_unlock,
        "producer_return": producer_return,
        "end": CODE_CAVE + len(block),
    }
    if layout["end"] > CODE_CAVE_END:
        raise SystemExit(f"R03 wrapper exceeds replaced packer: 0x{layout['end']:08x}")
    return bytes(block), layout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("app", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()

    app = args.app.read_bytes()
    if len(app) != APP_SIZE or sha256(app) != APP_SHA256:
        raise SystemExit("refusing non-official v15 app")

    cave, layout = build_cave()
    output = bytearray(app)
    changes: list[dict[str, object]] = []
    old_cave = app[off(CODE_CAVE):off(CODE_CAVE) + len(cave)]
    changes.append(replace_exact(output, app, CODE_CAVE, old_cave, cave))
    changes.append(replace_exact(output, app, NOTE_OFF_CALL, NOTE_OFF_STOCK, call32(NOTE_OFF_CALL, layout["off_entry"])))
    changes.append(replace_exact(output, app, NOTE_ON_CALL, NOTE_ON_STOCK, call32(NOTE_ON_CALL, layout["on_entry"])))
    for address, expected, purpose in PRODUCT_CALLS:
        change = replace_exact(output, app, address, expected, short_call(address, layout["producer"]))
        change["purpose"] = purpose
        changes.append(change)
    save = replace_exact(output, app, SAVE_CALL, SAVE_STOCK, b"\0" * 4)
    save["purpose"] = "neutralize unreachable stock packer call after SAVE rejection branch"
    changes.append(save)
    reject = replace_exact(output, app, SAVE_REJECT_CALL, SAVE_REJECT_STOCK, SAVE_REJECT_BRANCH)
    reject["purpose"] = "reject SAVE before either persistent write by branching to stock local exit"
    changes.append(reject)
    changes.append(replace_exact(output, app, BSS_SIZE_INSN, BSS_SIZE_STOCK, BSS_SIZE_R03))
    changes.append(replace_exact(output, app, HEAP_BEGIN_INSN, HEAP_BEGIN_STOCK, HEAP_BEGIN_R03))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(output)
    manifest = {
        "format": FORMAT,
        "artifact_scope": "offline integrity and ABI checkpoint only; not a live functional claim",
        "input_app_sha256": sha256(app),
        "output_app_sha256": sha256(output),
        "runtime_base": f"0x{RUNTIME_BASE:08x}",
        "owned_ram": {
            "range": f"0x{VOICE:08x}..0x{RESERVED_END:08x}",
            "size": RESERVED_END - VOICE,
            "voice": f"0x{VOICE:08x}..0x{VOICE + VOICE_SIZE:08x}",
            "valid": f"0x{VALID:08x}",
            "lock": f"0x{LOCK:08x}",
            "initialization": "boot BSS zero extension, ending exactly at shifted HEAP_BEGIN",
            "heap_capacity_reduction": RESERVED_END - VOICE,
        },
        "protocol": {
            "source": f"0x{STAGING:08x}",
            "copy_size": VOICE_SIZE,
            "publish_order": "voice, valid=1",
            "producer_serialization": "nonblocking PI32v2 atomic testset try-lock; a concurrent or interrupt reentry returns immediately instead of spinning",
            "reload_after_first_publish": "rejected until reboot",
            "invalid_ch10": "falls back to stock source",
            "save": "no-write rejection at 0x02026da6 branches to stock local exit 0x02026dd4; later packer call also neutralized",
            "segmented_and_one_shot_product_packets": "the first accepted post-F7 callsite publishes; later packets cannot replace the snapshot",
        },
        "layout": {key: f"0x{value:08x}" for key, value in layout.items()},
        "changes": changes,
        "hard_stops": [
            "normal boot or identity 015 fails before pad input",
            "any pad is used before the exact guarded product packet",
            "SAVE is required during this checkpoint",
            "unexpected reboot, USB loss, stuck note, or cross-channel timbre change",
            "heap or allocation stress shows a regression",
        ],
    }
    args.manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print("R03 app", sha256(output))
    print("cave", f"0x{CODE_CAVE:08x}..0x{layout['end']:08x}", len(cave), "bytes")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
