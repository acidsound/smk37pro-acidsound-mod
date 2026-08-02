#!/usr/bin/env python3
"""Build official-v15-only R01d: preload Mooger #1 via the official loader into RAM.

R01d deliberately does not embed a program/text static snapshot.  It hooks the
post-init loader callsite at 0x02005f9c so the official v15 loader materializes
Bank D / preset 13 (display 14, Mooger #1) into the current source, copies the
first 0x9c bytes to dedicated RAM staging at 0x01c37fd0, restores the original
selection, and calls the official loader again.  Note On and Note Off then use a
matched wrapper: r9 == 9 reads the RAM staging buffer, otherwise the original r1
source is passed through to memcpy.

No flash, OTA, or device access is performed.  This script only writes an app.bin
artifact and an app manifest for later packaging with tools/smk37_v15_app_patch.py.
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
    DUMP_SHA256,
    DUMP_SIZE,
    MEMCPY,
    RUNTIME_BASE,
    SYSEX_CALLS,
    call32,
    jne_imm7,
    mov_imm32,
    mov_reg,
    off,
    replace_exact,
    sha256,
    word,
)

FORMAT = "smk37-v15-r01d-ram-preload-mooger1-noteoff-v1"
POST_INIT_LOADER_CALL = 0x02005F9C
POST_INIT_LOADER_STOCK = bytes.fromhex("bfea60fb")
FACTORY_LOADER = 0x02005660
NOTE_ON_MEMCPY_CALL = 0x0201C67C
NOTE_ON_STOCK = bytes.fromhex("80ff4cc60200")
NOTE_OFF_MEMCPY_CALL = 0x0201C63E
NOTE_OFF_STOCK = bytes.fromhex("80ff8ac60200")
RAM_OBJECT_BASE = 0x01C33260
CURRENT_SOURCE = 0x01C34C74
RAM_STAGING = 0x01C37FD0
VOICE_COPY_SIZE = 0x9C
BANK_D_ZERO_BASED = 3
MOOGER1_ZERO_BASED_PRESET = 13
MOOGER1_VOICE_OFFSET = 0xF7680
MOOGER1_VOICE_NAME = b"Mooger #1 "
OFFSET_PRESET_BASE = 0x03A0
OFFSET_BANK_D_PRESET = OFFSET_PRESET_BASE + BANK_D_ZERO_BASED
OFFSET_SELECTED_BANK = 0x03A4
SHORT_CALL_WINDOW_BYTES = 0x20000


def movz(dst: int, value: int) -> bytes:
    if not 0 <= dst <= 7:
        raise ValueError("movz helper currently covers r0..r7")
    if not 0 <= value <= 0xFFFF:
        raise ValueError("movz immediate out of range")
    return bytes([0x40 | dst, 0xE0]) + struct.pack("<H", value)


def mov_small(dst: int, value: int) -> bytes:
    if not 0 <= dst <= 7:
        raise ValueError("small mov helper currently covers r0..r7")
    if not 0 <= value <= 0x0F:
        raise ValueError("small mov immediate out of audited range")
    return word(
        0x2040
        | dst
        | ((value >> 5) << 3)
        | ((value & 0x1F) << 8)
    )


def lb_index(dst: int, base: int, index: int) -> bytes:
    for name, value in (("dst", dst), ("base", base), ("index", index)):
        if not 0 <= value <= 15:
            raise ValueError(f"{name} register out of range")
    return bytes([0xD8, 0xEE, base << 4, (dst << 4) | index])


def sb_index(src: int, base: int, index: int) -> bytes:
    for name, value in (("src", src), ("base", base), ("index", index)):
        if not 0 <= value <= 15:
            raise ValueError(f"{name} register out of range")
    return bytes([0xD8, 0xEE, (base << 4) | 1, (src << 4) | index])


def short_call(at: int, target: int) -> bytes:
    displacement = target - (at + 4)
    if displacement & 1:
        raise ValueError("unaligned short call target")
    halfwords = displacement // 2
    # The official listing contains bfea calls that wrap inside a 0x20000-byte
    # code window, for example 0x020255a6 -> 0x02005660 encodes as 0x005b.
    if (at + 4 + ((halfwords & 0xFFFF) * 2)) % SHORT_CALL_WINDOW_BYTES != target % SHORT_CALL_WINDOW_BYTES:
        raise ValueError("short call target is outside the architectural window")
    return b"\xbf\xea" + struct.pack("<H", halfwords & 0xFFFF)


def build_preload_wrapper(start: int) -> tuple[bytes, dict[str, int | str]]:
    block = bytearray()
    block += word(0x0479)                         # push {rets,r9..r4}
    block += mov_imm32(4, RAM_OBJECT_BASE)        # r4 = live global object base

    block += movz(0, OFFSET_SELECTED_BANK)        # save selected bank
    block += lb_index(5, 4, 0)                    # r5 = obj[0x3a4]
    block += word(0x1D50)                         # r0 = r5 + r4
    block += movz(1, OFFSET_PRESET_BASE)
    block += lb_index(6, 0, 1)                    # r6 = obj[0x3a0 + selected bank]
    block += movz(0, OFFSET_BANK_D_PRESET)
    block += lb_index(7, 4, 0)                    # r7 = original Bank D preset slot

    block += movz(0, OFFSET_SELECTED_BANK)        # select Bank D
    block += mov_small(1, BANK_D_ZERO_BASED)
    block += sb_index(1, 4, 0)
    block += movz(0, OFFSET_BANK_D_PRESET)        # select Mooger #1 in Bank D
    block += mov_small(1, MOOGER1_ZERO_BASED_PRESET)
    block += sb_index(1, 4, 0)

    first_loader_call = start + len(block)
    block += call32(first_loader_call, FACTORY_LOADER)

    block += mov_imm32(0, RAM_STAGING)            # memcpy(staging, current, 0x9c)
    block += mov_imm32(1, CURRENT_SOURCE)
    block += word(0x3C62)                         # r2 = 0x9c
    capture_call = start + len(block)
    block += call32(capture_call, MEMCPY)

    block += word(0x1D50)                         # restore current-bank preset slot
    block += movz(1, OFFSET_PRESET_BASE)
    block += sb_index(6, 0, 1)
    block += movz(0, OFFSET_BANK_D_PRESET)        # restore Bank D preset slot
    block += sb_index(7, 4, 0)
    block += movz(0, OFFSET_SELECTED_BANK)        # restore selected bank
    block += sb_index(5, 4, 0)

    second_loader_call = start + len(block)
    block += call32(second_loader_call, FACTORY_LOADER)
    block += word(0x0459)                         # pop {pc,r9..r4}

    return bytes(block), {
        "entry": start,
        "first_loader_call": first_loader_call,
        "capture_memcpy_call": capture_call,
        "restore_loader_call": second_loader_call,
        "end": start + len(block),
        "state_saved": "selected bank, selected-bank preset, Bank D preset slot",
    }


def build_note_wrapper(start: int) -> tuple[bytes, dict[str, int]]:
    block = bytearray()
    block += word(0x0479)                         # push {rets,r9..r4}
    block += mov_reg(3, 9)                        # r3 = MIDI channel nibble
    branch_at = start + len(block)
    block += b"\0" * 4

    special = start + len(block)
    block += mov_reg(4, 0)                        # preserve per-voice destination
    block += mov_imm32(1, RAM_STAGING)            # source = preload RAM staging
    block += mov_reg(0, 4)
    block += word(0x3C62)                         # r2 = 0x9c
    at = start + len(block)
    block += call32(at, MEMCPY)
    block += word(0x0459)                         # pop {pc,r9..r4}

    stock = start + len(block)
    at = start + len(block)
    block += call32(at, MEMCPY)                   # pass original r1 through
    block += word(0x0459)

    block[branch_at - start:branch_at - start + 4] = jne_imm7(
        branch_at, 3, CHANNEL_10, stock
    )
    return bytes(block), {
        "entry": start,
        "special": special,
        "stock": stock,
        "end": start + len(block),
    }


def build_code_cave() -> tuple[bytes, dict[str, dict[str, int | str]]]:
    preload, preload_layout = build_preload_wrapper(CODE_CAVE)
    note_start = CODE_CAVE + len(preload)
    if note_start & 1:
        preload += b"\0"
        note_start += 1
        preload_layout["end"] = note_start
    note, note_layout = build_note_wrapper(note_start)
    code = preload + note
    end = CODE_CAVE + len(code)
    if end > CODE_CAVE_END:
        raise SystemExit(
            f"wrapper exceeds audited code cave: 0x{end:08x} > 0x{CODE_CAVE_END:08x}"
        )
    return code, {"preload": preload_layout, "note_wrapper": note_layout, "cave": {"entry": CODE_CAVE, "end": end}}


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

    packed = dump[MOOGER1_VOICE_OFFSET:MOOGER1_VOICE_OFFSET + 128]
    if packed[118:128] != MOOGER1_VOICE_NAME:
        raise SystemExit("factory voice identity mismatch")

    cave, layout = build_code_cave()
    output = bytearray(app)
    changes: list[dict[str, object]] = []
    cave_old = app[off(CODE_CAVE):off(CODE_CAVE) + len(cave)]
    changes.append(replace_exact(output, app, CODE_CAVE, cave_old, cave))
    changes.append(replace_exact(
        output, app, POST_INIT_LOADER_CALL, POST_INIT_LOADER_STOCK,
        short_call(POST_INIT_LOADER_CALL, CODE_CAVE),
    ))
    note_entry = layout["note_wrapper"]["entry"]
    assert isinstance(note_entry, int)
    changes.append(replace_exact(
        output, app, NOTE_ON_MEMCPY_CALL, NOTE_ON_STOCK,
        call32(NOTE_ON_MEMCPY_CALL, note_entry),
    ))
    changes.append(replace_exact(
        output, app, NOTE_OFF_MEMCPY_CALL, NOTE_OFF_STOCK,
        call32(NOTE_OFF_MEMCPY_CALL, note_entry),
    ))
    for address, expected in SYSEX_CALLS:
        changes.append(replace_exact(output, app, address, expected, b"\0" * 4))

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(output)
    manifest = {
        "format": FORMAT,
        "input_app_sha256": sha256(app),
        "output_app_sha256": sha256(output),
        "source_dump_sha256": sha256(dump),
        "runtime_base": f"0x{RUNTIME_BASE:08x}",
        "artifact_scope": "artifact integrity only; not a functional success claim",
        "evidence": {
            "dispatcher": "0x0201c5ec",
            "channel_register": "r9",
            "channel_10_nibble": CHANNEL_10,
            "post_init_loader_callsite": f"0x{POST_INIT_LOADER_CALL:08x}",
            "factory_loader": f"0x{FACTORY_LOADER:08x}",
            "note_on_memcpy": f"0x{NOTE_ON_MEMCPY_CALL:08x}",
            "note_off_memcpy": f"0x{NOTE_OFF_MEMCPY_CALL:08x}",
            "current_source": f"0x{CURRENT_SOURCE:08x}",
            "ram_staging": f"0x{RAM_STAGING:08x}",
            "memcpy": f"0x{MEMCPY:08x}",
            "neutralized_old_sysex_direct_callers": [f"0x{addr:08x}" for addr, _ in SYSEX_CALLS],
        },
        "preload": {
            "bank_zero_based": BANK_D_ZERO_BASED,
            "preset_zero_based": MOOGER1_ZERO_BASED_PRESET,
            "name": MOOGER1_VOICE_NAME.decode("ascii"),
            "packed_flash_offset": f"0x{MOOGER1_VOICE_OFFSET:08x}",
            "packed_sha256": sha256(packed),
            "captured_bytes": VOICE_COPY_SIZE,
            "current_source": f"0x{CURRENT_SOURCE:08x}",
            "ram_staging": f"0x{RAM_STAGING:08x}",
            "state_preservation": "selected bank, selected-bank preset, and Bank D preset slot are saved/restored before final loader call",
        },
        "layout": {
            section: {key: (f"0x{value:08x}" if isinstance(value, int) else value)
                      for key, value in values.items()}
            for section, values in layout.items()
        },
        "branch_ranges": {
            "post_init_short_call_window_bytes": SHORT_CALL_WINDOW_BYTES,
            "post_init_call_new_hex": short_call(POST_INIT_LOADER_CALL, CODE_CAVE).hex(),
            "note_on_call_new_hex": call32(NOTE_ON_MEMCPY_CALL, note_entry).hex(),
            "note_off_call_new_hex": call32(NOTE_OFF_MEMCPY_CALL, note_entry).hex(),
        },
        "changes": changes,
    }
    args.manifest.parent.mkdir(parents=True, exist_ok=True)
    args.manifest.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    print("output app", sha256(output))
    print("preload wrapper", f"0x{CODE_CAVE:08x}", "note wrapper", f"0x{note_entry:08x}")
    print("artifact integrity only; no functional success claim")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
