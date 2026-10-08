#!/usr/bin/env python3
"""Build the official-v15/S1-C1 based S1-C2 two-slot selector candidate.

Offline builder only. It creates deterministic app/FWSC artifacts and rollback
sector files, but it never opens a MIDI/device transport, flashes, resets, or
runs an OTA flow.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
sys.path.insert(0, str(HERE))

from smk37_v15_app_patch import (  # noqa: E402
    APP_DATA_OFFSET,
    APP_DATA_SIZE,
    FLASH_SIZE,
    AppImage,
    Ufw,
    compact_ranges,
    difference_offsets,
    protected_hashes,
    unpack_fwsc,
)

FORMAT = "smk37-v15-s1c2-two-slot-selector-live-v2"
RUNTIME_BASE = 0x02000000
APP_SIZE = APP_DATA_SIZE
SECTOR_SIZE = 0x2000
PROTECTED_PREFIX_END = 0x4000
PACKAGE_NAME = "SMK37Pro-v15-S1C2-two-slot-selector-live-v2.fwsc"

OFFICIAL_FWSC = HERE / "inputs/SMK-37_Pro_015.fwsc"
OFFICIAL_APP = HERE / "inputs/v15-official-app.bin"
S1C1_APP = HERE / "inputs/S1C1-boundary-only-app.bin"
SELECTOR_BIN_INPUT = HERE / "inputs/selector.bin"
PACKET0_INPUT = HERE / "inputs/slot0-note36-direct-product-163.bin"
PACKET1_INPUT = HERE / "inputs/slot1-note45-direct-product-163.bin"

EXPECTED = {
    "official_fwsc": "f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff",
    "official_app": "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055",
    "s1c1_app": "16023c9006f2d4d6467ef2d72d6165c14ffeb6cb758d074f7d8163a68146fb2e",
    "selector": "adb8774971811f6dbdce8b7338f2265f18b8bb22544ccab746e74610366d4e35",
    "mooger_runtime": "e0bf5adb328b25de2c64d24cf8f6fe8f8e293e968dd56dbbfbf771ad92fe8275",
    "hand_runtime": "98bc86e7d9625c837ee6c07fa3f01cbd6079960c9d1071017cf51194aa48c1bf",
}

SELECTOR_START = 0x0201E13E
SELECTOR_END = 0x0201E19E
PRODUCER_START = 0x0201E1A2
PRODUCER_END_LIMIT = 0x0201E254
OFFICIAL_HANDLER = 0x0201E254
SEGMENTED_STUB_MIN = PRODUCER_START
DIRECT_PRODUCT_CALL = 0x0201E468
DIRECT_RELOAD_CALL = 0x0201E46C
SEGMENTED_PRODUCT_CALL = 0x0201E49C
SEGMENTED_RELOAD_CALL = 0x0201E4A0
MEMCPY = 0x02048CCE
NOTE_OFF_CALL = 0x0201C63E
NOTE_ON_CALL = 0x0201C67C
NOTE_OFF_SELECTOR_ENTRY = SELECTOR_START
NOTE_ON_SELECTOR_ENTRY = SELECTOR_START + 4

SLOT0 = 0x01C46520
VALID0 = 0x01C465BC
LOCK = 0x01C465BD
NOTE0 = 0x01C465BE
STATE = 0x01C465BF
SLOT1 = 0x01C465C0
VALID1 = 0x01C4665C
NOTE1 = 0x01C4665E
VOICE_SIZE = 0x9C
DIRECT_TOTAL_LEN = 0xA3
FIXED_NOTE0 = 36
FIXED_NOTE1 = 45
EMPTY = 0
LOADING = 1
ARMED = 2
HEADER = bytes.fromhex("f0430000011b")
TERM = bytes([0xf7])


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def sha256(data: bytes | bytearray) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_path(path: Path) -> str:
    return sha256(path.read_bytes())


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def off(address: int) -> int:
    value = address - RUNTIME_BASE
    require(0 <= value < APP_SIZE, f"address outside app: 0x{address:08x}")
    return value


def word(value: int) -> bytes:
    return struct.pack("<H", value & 0xFFFF)


def mov_reg(dst: int, src: int) -> bytes:
    require(0 <= dst <= 15 and 0 <= src <= 15, "mov_reg operands")
    return word(0x1600 | (src << 4) | dst)


def mov_imm32(dst: int, value: int) -> bytes:
    require(0 <= dst <= 15, "mov_imm32 register")
    return word(0xFFC0 | dst) + struct.pack("<I", value)


def mov_imm8(register: int, immediate: int) -> bytes:
    require(0 <= register <= 7 and 0 <= immediate <= 0xFF, "mov_imm8 operands")
    return word(0x2040 | register | ((immediate >> 5) << 3) | ((immediate & 0x1F) << 8))


def add_imm8(register: int, immediate: int) -> bytes:
    require(0 <= register <= 7 and -128 <= immediate <= 127, "add_imm8 operands")
    encoded = immediate & 0xFF
    return word(0x20C0 | register | ((encoded >> 5) << 3) | ((encoded & 0x1F) << 8))


def add_imm12(destination: int, source: int, immediate: int) -> bytes:
    require(0 <= destination <= 15 and 0 <= source <= 15 and 0 <= immediate <= 0xFFF, "add_imm12 operands")
    return bytes((destination, 0xE1, immediate & 0xFF, (source << 4) | (immediate >> 8)))


def load_byte(destination: int, base: int, offset: int = 0) -> bytes:
    require(all(0 <= register <= 7 for register in (destination, base)), "load_byte registers")
    require(-16 <= offset <= 15, "load_byte offset")
    return word(0x4008 | destination | (base << 4) | ((offset & 0x1F) << 8))


def store_byte(source: int, base: int, offset: int = 0) -> bytes:
    require(all(0 <= register <= 7 for register in (source, base)), "store_byte registers")
    require(-16 <= offset <= 15, "store_byte offset")
    return word(0x4088 | source | (base << 4) | ((offset & 0x1F) << 8))


def call32(at: int, target: int) -> bytes:
    displacement = target - (at + 6)
    require(-(1 << 31) <= displacement < (1 << 31), "call32 displacement")
    return b"\x80\xff" + struct.pack("<i", displacement)


def short_call(at: int, target: int) -> bytes:
    displacement = target - (at + 4)
    require(displacement % 2 == 0, "short call alignment")
    halfwords = displacement // 2
    require((at + 4 + ((halfwords & 0xFFFF) * 2)) % 0x20000 == target % 0x20000, "short call window")
    return b"\xbf\xea" + struct.pack("<H", halfwords & 0xFFFF)


def sx(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def jne_imm7(at: int, register: int, immediate: int, target: int) -> bytes:
    displacement = target - (at + 4)
    require(displacement % 2 == 0, "jne alignment")
    halfwords = displacement // 2
    require(-256 <= halfwords <= 255, "jne reach")
    require(0 <= register <= 7 and 0 <= immediate <= 0x7F, "jne operands")
    return word(0xF880 | register) + word((immediate << 9) | (halfwords & 0x1FF))


def ifeq(at: int, target: int) -> bytes:
    displacement = target - (at + 4)
    require(displacement % 2 == 0 and -0x10000 <= displacement <= 0xFFFE, "ifeq reach")
    return bytes.fromhex("40e8") + struct.pack("<h", displacement // 2)


def forward_goto(at: int, target: int) -> bytes:
    displacement = target - (at + 2)
    require(displacement >= 0 and displacement % 2 == 0, "forward goto")
    halfwords = displacement // 2
    require(halfwords <= 31, "forward goto reach")
    return word(0x8004 | (halfwords << 8))


class Builder:
    def __init__(self, start: int) -> None:
        self.start = start
        self.block = bytearray()
        self.insns: list[dict[str, Any]] = []
        self.labels: dict[str, int] = {"entry": start}

    @property
    def pc(self) -> int:
        return self.start + len(self.block)

    def mark(self, name: str) -> int:
        self.labels[name] = self.pc
        return self.pc

    def emit(self, name: str, blob: bytes, meaning: str) -> int:
        at = self.pc
        self.block.extend(blob)
        self.insns.append({"address": f"0x{at:08x}", "bytes": blob.hex(), "name": name, "meaning": meaning})
        return at

    def patch(self, at: int, blob: bytes) -> None:
        start = at - self.start
        self.block[start:start + len(blob)] = blob
        for insn in self.insns:
            if int(insn["address"], 16) == at:
                insn["bytes"] = blob.hex()
                return
        raise AssertionError(f"no instruction at 0x{at:08x}")


def selector_bytes() -> bytes:
    data = SELECTOR_BIN_INPUT.read_bytes()
    require(len(data) == SELECTOR_END - SELECTOR_START, "selector size")
    require(sha256(data) == EXPECTED["selector"], "selector hash")
    return data


def build_producer_and_stub() -> tuple[bytes, dict[str, int], list[dict[str, Any]]]:
    b = Builder(PRODUCER_START)
    b.emit("push_saved", word(0x0479), "save rets,r9..r4 like H2 producer")
    b.emit("save_stage", mov_reg(4, 0), "r4 = accepted product staging pointer")
    b.emit("length_gate_source", mov_reg(0, 9), "r0 = r9 so low-register arithmetic can gate exact direct length")
    b.emit("length_gate_sub_0x80", add_imm8(0, -0x80), "r0 = r9 - 0x80")
    b.emit("length_gate_sub_0x23", add_imm8(0, -0x23), "r0 = r9 - 0xa3")
    length_reject_branch = b.emit("length_reject_branch", b"\0" * 4, "r9 != 0xa3 -> return before testset/lock/state/slot mutation")
    b.emit("lock_pointer", mov_imm32(0, LOCK), "r0 = lock byte 0x01c465bd")
    b.emit("trylock", bytes.fromhex("2000b000"), "csync; testset b[r0]")
    try_fail_branch = b.emit("trylock_failed_return_branch", b"\0" * 4, "ifeq -> return without clearing somebody else's lock")
    b.emit("acquired_csync", word(0x0020), "csync after acquired lock")
    b.emit("metadata_base", mov_imm32(5, VALID0), "r5 = slot0 metadata base")
    b.emit("state_load", load_byte(0, 5, STATE - VALID0), "r0 = state")
    state_not_empty_branch = b.emit("state_not_empty_branch", b"\0" * 4, "state != EMPTY -> loading/armed path")

    b.mark("empty_path")
    b.emit("state_loading_value", mov_imm8(0, LOADING), "r0 = LOADING")
    b.emit("state_loading_store", store_byte(0, 5, STATE - VALID0), "state = LOADING before slot0 copy")
    b.emit("loading_csync", word(0x0020), "order LOADING before slot0 data publication")
    b.emit("note0_value", mov_imm8(0, FIXED_NOTE0), "r0 = fixed note 36")
    b.emit("note0_store", store_byte(0, 5, NOTE0 - VALID0), "note0 = 36")
    b.emit("slot0_destination", mov_imm32(0, SLOT0), "r0 = slot0 destination")
    b.emit("slot0_source", mov_reg(1, 4), "r1 = accepted staging pointer")
    b.emit("copy_size", mov_imm8(2, VOICE_SIZE), "r2 = 0x9c")
    b.emit("slot0_memcpy", call32(b.pc, MEMCPY), "memcpy(slot0, staging, 0x9c)")
    b.emit("slot0_csync", word(0x0020), "order slot0 copy before valid0")
    b.emit("valid0_value", mov_imm8(0, 1), "r0 = 1")
    b.emit("valid0_store", store_byte(0, 5), "valid0 = 1 last for first product")
    empty_done_goto = b.emit("empty_done_unlock_goto", b"\0" * 2, "skip loading path and unlock")

    not_empty = b.mark("not_empty_path")
    state_not_loading_branch = b.emit("state_not_loading_branch", b"\0" * 4, "state != LOADING -> unlock/no mutation")
    b.emit("valid0_load", load_byte(0, 5), "r0 = valid0")
    valid0_missing_branch = b.emit("valid0_missing_branch", b"\0" * 4, "valid0 != 1 -> unlock/no mutation")
    b.emit("slot1_metadata_base", add_imm12(6, 5, VALID1 - VALID0), "r6 = slot1 metadata base")
    b.emit("valid1_load", load_byte(0, 6), "r0 = valid1")
    valid1_present_branch = b.emit("valid1_present_branch", b"\0" * 4, "valid1 != 0 -> unlock/no mutation")
    b.emit("note1_value", mov_imm8(0, FIXED_NOTE1), "r0 = fixed note 45")
    b.emit("note1_store", store_byte(0, 6, NOTE1 - VALID1), "note1 = 45")
    b.emit("slot1_destination", mov_imm32(0, SLOT1), "r0 = slot1 destination")
    b.emit("slot1_source", mov_reg(1, 4), "r1 = accepted staging pointer")
    b.emit("slot1_copy_size", mov_imm8(2, VOICE_SIZE), "r2 = 0x9c")
    b.emit("slot1_memcpy", call32(b.pc, MEMCPY), "memcpy(slot1, staging, 0x9c)")
    b.emit("slot1_csync", word(0x0020), "order slot1 copy before valid1")
    b.emit("valid1_value", mov_imm8(0, 1), "r0 = 1")
    b.emit("valid1_store", store_byte(0, 6), "valid1 = 1 before ARMED")
    b.emit("armed_csync", word(0x0020), "order valid1 before ARMED")
    b.emit("armed_value", mov_imm8(0, ARMED), "r0 = ARMED")
    b.emit("armed_store", store_byte(0, 5, STATE - VALID0), "state = ARMED last")

    unlock = b.mark("unlock")
    b.emit("unlock_pointer", mov_imm32(0, LOCK), "r0 = lock byte")
    b.emit("unlock_csync_before", word(0x0020), "csync before unlock store")
    b.emit("unlock_zero", mov_imm8(1, 0), "r1 = 0")
    b.emit("unlock_store", store_byte(1, 0), "lock = 0")
    b.emit("unlock_csync_after", word(0x0020), "csync after unlock store")
    ret = b.mark("return")
    b.emit("return_restore", word(0x0459), "pop pc,r9..r4; caller reload/return ABI preserved")

    segmented_stub = b.mark("segmented_stub")
    b.emit("segmented_stub_push", word(0x0479), "segmented no-slot-mutation stub saves call return/register frame")
    b.emit("segmented_stub_return", word(0x0459), "segmented no-slot-mutation stub immediately returns")

    b.patch(length_reject_branch, jne_imm7(length_reject_branch, 0, 0, ret))
    b.patch(try_fail_branch, ifeq(try_fail_branch, ret))
    b.patch(state_not_empty_branch, jne_imm7(state_not_empty_branch, 0, EMPTY, not_empty))
    b.patch(empty_done_goto, forward_goto(empty_done_goto, unlock))
    b.patch(state_not_loading_branch, jne_imm7(state_not_loading_branch, 0, LOADING, unlock))
    b.patch(valid0_missing_branch, jne_imm7(valid0_missing_branch, 0, 1, unlock))
    b.patch(valid1_present_branch, jne_imm7(valid1_present_branch, 0, 0, unlock))

    for insn in b.insns:
        address = int(insn["address"], 16)
        size = len(bytes.fromhex(insn["bytes"]))
        insn["bytes"] = bytes(b.block[address - b.start:address - b.start + size]).hex()

    layout = dict(b.labels)
    layout.update({
        "length_reject_branch": length_reject_branch,
        "try_fail_branch": try_fail_branch,
        "state_not_empty_branch": state_not_empty_branch,
        "empty_done_goto": empty_done_goto,
        "state_not_loading_branch": state_not_loading_branch,
        "valid0_missing_branch": valid0_missing_branch,
        "valid1_present_branch": valid1_present_branch,
        "end": PRODUCER_START + len(b.block),
    })
    require(layout["segmented_stub"] >= SEGMENTED_STUB_MIN, "segmented stub in owned range")
    require(layout["end"] <= PRODUCER_END_LIMIT, "producer and stub fit owned range")
    return bytes(b.block), layout, b.insns


def render_decode(insns: list[dict[str, Any]]) -> str:
    lines = ["address\tbytes\tname\tmeaning"]
    lines.extend(f"{i['address']}\t{i['bytes']}\t{i['name']}\t{i['meaning']}" for i in insns)
    return "\n".join(lines) + "\n"


def patch_exact(output: bytearray, before: bytes, address: int, old: bytes, new: bytes, purpose: str) -> dict[str, Any]:
    start = off(address)
    end = start + len(old)
    require(before[start:end] == old, f"old bytes mismatch at 0x{address:08x}")
    output[start:end] = new
    return {"address": f"0x{address:08x}", "file_offset": start, "old_hex": old.hex(), "new_hex": new.hex(), "purpose": purpose}


def extract_app_from_fwsc(path: Path) -> tuple[bytes, bytearray, bytes]:
    raw = path.read_bytes()
    payload, _metadata = unpack_fwsc(raw) if sha256(raw) == EXPECTED["official_fwsc"] else unpack_nonofficial_fwsc(raw)
    flash = Ufw.parse(payload).flash()
    app = AppImage.parse(flash).app_bytes()
    return raw, flash, app


def unpack_nonofficial_fwsc(raw: bytes) -> tuple[bytearray, bytes]:
    from smk37_v15_app_patch import FWSC_BLOCK_SIZE, FWSC_DATA_SIZE, FWSC_SLOTS, OFFICIAL_V15_PAYLOAD_SIZE
    require(len(raw) == 701_140, "FWSC size")
    metadata = bytes(raw[index * FWSC_BLOCK_SIZE + FWSC_DATA_SIZE] for index in range(FWSC_SLOTS))
    payload = bytearray()
    for index in range(FWSC_SLOTS):
        start = index * FWSC_BLOCK_SIZE
        payload.extend(raw[start:start + FWSC_DATA_SIZE])
    payload.extend(raw[FWSC_SLOTS * FWSC_BLOCK_SIZE:])
    require(len(payload) == OFFICIAL_V15_PAYLOAD_SIZE, "payload size")
    return payload, metadata


def build_app(parent: bytes) -> tuple[bytes, dict[str, Any], bytes, dict[str, int], list[dict[str, Any]]]:
    require(len(parent) == APP_SIZE and sha256(parent) == EXPECTED["s1c1_app"], "S1-C1 parent app hash")
    selector = selector_bytes()
    producer, layout, insns = build_producer_and_stub()
    output = bytearray(parent)
    changes: list[dict[str, Any]] = []
    changes.append(patch_exact(output, parent, SELECTOR_START, parent[off(SELECTOR_START):off(SELECTOR_START) + len(selector)], selector, "install exact 96-byte ARMED two-slot selector"))
    changes.append(patch_exact(output, parent, NOTE_OFF_CALL, parent[off(NOTE_OFF_CALL):off(NOTE_OFF_CALL) + 6], call32(NOTE_OFF_CALL, NOTE_OFF_SELECTOR_ENTRY), "pin Note Off Ch10 hook to selector note-off adapter"))
    changes.append(patch_exact(output, parent, NOTE_ON_CALL, parent[off(NOTE_ON_CALL):off(NOTE_ON_CALL) + 6], call32(NOTE_ON_CALL, NOTE_ON_SELECTOR_ENTRY), "pin Note On Ch10 hook to selector note-on adapter"))
    changes.append(patch_exact(output, parent, PRODUCER_START, parent[off(PRODUCER_START):off(PRODUCER_START) + len(producer)], producer, "install split-entry r9-gated two-slot producer"))
    direct_call = short_call(DIRECT_PRODUCT_CALL, PRODUCER_START)
    segmented_call = short_call(SEGMENTED_PRODUCT_CALL, layout["segmented_stub"])
    changes.append(patch_exact(output, parent, DIRECT_PRODUCT_CALL, parent[off(DIRECT_PRODUCT_CALL):off(DIRECT_PRODUCT_CALL) + 4], direct_call, "direct accepted product call targets main producer entry"))
    changes.append(patch_exact(output, parent, SEGMENTED_PRODUCT_CALL, parent[off(SEGMENTED_PRODUCT_CALL):off(SEGMENTED_PRODUCT_CALL) + 4], segmented_call, "segmented accepted product call targets immediate-return no-mutation stub"))
    require(output[off(DIRECT_RELOAD_CALL):off(DIRECT_RELOAD_CALL) + 4] == parent[off(DIRECT_RELOAD_CALL):off(DIRECT_RELOAD_CALL) + 4] == bytes.fromhex("bfeaf838"), "direct reload intact")
    require(output[off(SEGMENTED_RELOAD_CALL):off(SEGMENTED_RELOAD_CALL) + 4] == parent[off(SEGMENTED_RELOAD_CALL):off(SEGMENTED_RELOAD_CALL) + 4] == bytes.fromhex("bfeade38"), "segmented reload intact")
    require(output[off(OFFICIAL_HANDLER):off(OFFICIAL_HANDLER) + 16] == parent[off(OFFICIAL_HANDLER):off(OFFICIAL_HANDLER) + 16], "official handler intact")
    diffs = difference_offsets(parent, output)
    expected = set()
    for change in changes:
        start = change["file_offset"]
        old = bytes.fromhex(change["old_hex"])
        new = bytes.fromhex(change["new_hex"])
        expected.update(start + i for i, pair in enumerate(zip(old, new)) if pair[0] != pair[1])
    require(set(diffs) == expected, "unexpected S1-C1-relative app diffs")
    manifest = {
        "format": FORMAT + ".app-manifest-v1",
        "runtime_base": f"0x{RUNTIME_BASE:08x}",
        "official_app_sha256": EXPECTED["official_app"],
        "s1c1_parent_app_sha256": EXPECTED["s1c1_app"],
        "output_app_sha256": sha256(output),
        "app_size": len(output),
        "selector": {"address": f"0x{SELECTOR_START:08x}", "end_exclusive": f"0x{SELECTOR_END:08x}", "bytes": len(selector), "sha256": sha256(selector)},
        "producer": {"entry": f"0x{PRODUCER_START:08x}", "segmented_stub": f"0x{layout['segmented_stub']:08x}", "end_exclusive": f"0x{layout['end']:08x}", "bytes_in_owned_range": len(producer), "owned_limit": f"0x{PRODUCER_END_LIMIT:08x}", "sha256": sha256(producer)},
        "selector_hooks": {
            "note_off": {"callsite": f"0x{NOTE_OFF_CALL:08x}", "entry": f"0x{NOTE_OFF_SELECTOR_ENTRY:08x}", "bytes": call32(NOTE_OFF_CALL, NOTE_OFF_SELECTOR_ENTRY).hex(), "fixed_notes": [FIXED_NOTE0, FIXED_NOTE1]},
            "note_on": {"callsite": f"0x{NOTE_ON_CALL:08x}", "entry": f"0x{NOTE_ON_SELECTOR_ENTRY:08x}", "bytes": call32(NOTE_ON_CALL, NOTE_ON_SELECTOR_ENTRY).hex(), "fixed_notes": [FIXED_NOTE0, FIXED_NOTE1]},
        },
        "call_routes": {
            "direct_callsite": {"address": f"0x{DIRECT_PRODUCT_CALL:08x}", "bytes": direct_call.hex(), "target": f"0x{PRODUCER_START:08x}"},
            "segmented_callsite": {"address": f"0x{SEGMENTED_PRODUCT_CALL:08x}", "bytes": segmented_call.hex(), "target": f"0x{layout['segmented_stub']:08x}"},
            "direct_reload_intact": {"address": f"0x{DIRECT_RELOAD_CALL:08x}", "bytes": "bfeaf838"},
            "segmented_reload_intact": {"address": f"0x{SEGMENTED_RELOAD_CALL:08x}", "bytes": "bfeade38"},
        },
        "gate": "main producer copies r9 to r0 and checks r0 == 0xa3 before lock/testset/state/slot mutation; route identity is call target, not LR/rets",
        "s1c1_relative_changed_byte_count": len(diffs),
        "s1c1_relative_changed_ranges": compact_ranges(diffs),
        "changes": changes,
    }
    return bytes(output), manifest, producer, layout, insns


def repack(input_fwsc: Path, app_path: Path, package_path: Path, manifest_path: Path) -> None:
    subprocess.run([
        sys.executable,
        str(HERE / "smk37_v15_app_patch.py"),
        "repack-app",
        str(input_fwsc),
        str(app_path),
        str(package_path),
        "--manifest",
        str(manifest_path),
    ], check=True)


def validate_package_and_rollback(stock_raw: bytes, stock_flash: bytes | bytearray, stock_app: bytes, candidate_app: bytes, package_path: Path, output_dir: Path) -> dict[str, Any]:
    cand_raw, cand_flash, cand_app = extract_app_from_fwsc(package_path)
    require(cand_app == candidate_app, "package embeds candidate app")
    app_diffs = difference_offsets(stock_app, candidate_app)
    flash_diffs = difference_offsets(stock_flash, cand_flash)
    raw_diffs = difference_offsets(stock_raw, cand_raw)
    expected_flash_offsets = sorted(APP_DATA_OFFSET + item for item in app_diffs)
    missing = sorted(set(expected_flash_offsets) - set(flash_diffs))
    require(not missing, f"missing app diffs in flash: {missing!r}")
    metadata_flash_offsets = sorted(set(flash_diffs) - set(expected_flash_offsets))
    unexpected_metadata = [item for item in metadata_flash_offsets if not (0x4000 <= item < 0x4100)]
    require(not unexpected_metadata, f"unexpected non-app flash diffs: {unexpected_metadata!r}")
    require(not any(item < PROTECTED_PREFIX_END for item in flash_diffs), "protected prefix unchanged")
    sectors = sorted({item - (item % SECTOR_SIZE) for item in flash_diffs})
    rollback_dir = output_dir / "rollback" / "official-v15-recovery-sectors"
    if rollback_dir.exists():
        shutil.rmtree(rollback_dir)
    rollback_dir.mkdir(parents=True, exist_ok=True)
    sector_entries = []
    for base in sectors:
        data = bytes(stock_flash[base:base + SECTOR_SIZE])
        name = f"official-v15-sector-{base:05x}.bin"
        (rollback_dir / name).write_bytes(data)
        sector_entries.append({"sector_base": f"0x{base:05x}", "size": len(data), "sha256": sha256(data), "file": f"rollback/official-v15-recovery-sectors/{name}"})
    reconstructed = bytearray(cand_flash)
    for base in sectors:
        reconstructed[base:base + SECTOR_SIZE] = stock_flash[base:base + SECTOR_SIZE]
    require(bytes(reconstructed) == bytes(stock_flash), "rollback sectors restore official flash")
    rollback_manifest = {
        "format": FORMAT + ".official-v15-sector-rollback-v1",
        "scope": "official-v15 exact changed flash sectors only; no device action performed",
        "sector_size": SECTOR_SIZE,
        "changed_sector_count": len(sector_entries),
        "changed_sectors": sector_entries,
        "official_flash_sha256": sha256(stock_flash),
        "candidate_flash_sha256": sha256(cand_flash),
        "reconstructed_flash_sha256": sha256(reconstructed),
        "rollback_restores_official_flash": True,
    }
    write_json(rollback_dir / "manifest.json", rollback_manifest)
    return {
        "validation_gate": "PASS",
        "package_sha256": sha256(cand_raw),
        "package_size": len(cand_raw),
        "app_sha256": sha256(candidate_app),
        "official_package_sha256": sha256(stock_raw),
        "official_app_sha256": sha256(stock_app),
        "candidate_flash_sha256": sha256(cand_flash),
        "official_flash_sha256": sha256(stock_flash),
        "changed_app_byte_count_vs_official": len(app_diffs),
        "changed_app_ranges_vs_official": compact_ranges(app_diffs),
        "changed_flash_byte_count_vs_official": len(flash_diffs),
        "changed_flash_ranges_vs_official": compact_ranges(flash_diffs),
        "changed_package_byte_count_vs_official": len(raw_diffs),
        "changed_package_ranges_vs_official": compact_ranges(raw_diffs),
        "expected_app_flash_offsets_match": True,
        "repacker_metadata_flash_offsets": [f"0x{item:05x}" for item in metadata_flash_offsets],
        "changed_flash_sectors": [f"0x{item:05x}" for item in sectors],
        "protected_prefix_0x0000_0x3fff_unchanged": True,
        "protected_hashes_official": protected_hashes(bytearray(stock_flash)),
        "protected_hashes_candidate": protected_hashes(bytearray(cand_flash)),
        "rollback_manifest": "rollback/official-v15-recovery-sectors/manifest.json",
        "rollback_restores_official_flash": True,
    }


def packet_evidence(output_dir: Path | None = None) -> dict[str, Any]:
    packets = []
    packet_dir = output_dir / "host" / "packets" if output_dir is not None else None
    if packet_dir is not None:
        packet_dir.mkdir(parents=True, exist_ok=True)
    rows = [
        (0, FIXED_NOTE0, PACKET0_INPUT, "Mooger #1", "D", 14, "mooger_runtime", "6a9b4097cce1d28780ef3a507f42999743cc10e09770c17c5c78d185e9abff27"),
        (1, FIXED_NOTE1, PACKET1_INPUT, "HAND DRUM", "D", 12, "hand_runtime", "c4e8458edeb04d8106ca60a35243525e6b5f3f5de272091492409a440e3a9a8d"),
    ]
    for order, (slot, fixed_note, path, name, bank, patch, expected_key, packet_sha) in enumerate(rows, 1):
        packet = path.read_bytes()
        payload = packet[len(HEADER):-1]
        packet_file = f"host/packets/slot{slot}-note{fixed_note}-direct-product-163.bin"
        require(len(packet) == DIRECT_TOTAL_LEN, f"packet length {path.name}")
        require(packet.startswith(HEADER) and packet.endswith(TERM), f"packet framing {path.name}")
        require(len(payload) == VOICE_SIZE, f"runtime payload length {path.name}")
        require(sha256(payload) == EXPECTED[expected_key], f"runtime hash {path.name}")
        require(sha256(packet) == packet_sha, f"packet hash {path.name}")
        if packet_dir is not None:
            (output_dir / packet_file).write_bytes(packet)
        packets.append({
            "order": order,
            "slot": slot,
            "fixed_note": fixed_note,
            "factory_bank_letter": bank,
            "factory_patch_1_based": patch,
            "factory_name": name,
            "runtime_object_path": f"inputs/{path.name}",
            "runtime_object_bytes": len(payload),
            "runtime_object_sha256": sha256(payload),
            "packet_length": len(packet),
            "packet_sha256": sha256(packet),
            "packet_file": packet_file,
            "packet_prefix_hex": packet[:18].hex(),
            "packet_suffix_hex": packet[-18:].hex(),
        })
    require(packets[0]["packet_length"] == packets[1]["packet_length"] == DIRECT_TOTAL_LEN, "packet lengths are 0xa3")
    return {"direct_packet_header_hex": HEADER.hex(), "direct_packet_terminator_hex": TERM.hex(), "packets_in_order": packets}


def render_host_sender_dry_run() -> str:
    return r'''#!/usr/bin/env python3
"""Dry-run host packet plan for S1-C2 v2.

This tool never opens MIDI devices. It verifies the two exact committed 163-byte
packet files and prints the fixed send order using the current evidence schema.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
EVIDENCE = HERE / "evidence.json"
HEADER = bytes.fromhex("f0430000011b")
TERM = b"\xf7"

def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of text.")
    args = parser.parse_args()
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    rows = []
    for item in evidence["host_packets"]["packets_in_order"]:
        packet_path = HERE / item["packet_file"]
        packet = packet_path.read_bytes()
        if len(packet) != item["packet_length"] or not packet.startswith(HEADER) or not packet.endswith(TERM):
            raise SystemExit(f"packet framing/length mismatch: {packet_path}")
        digest = sha256(packet)
        if digest != item["packet_sha256"]:
            raise SystemExit(f"packet hash mismatch: {packet_path}")
        rows.append({
            "order": item["order"],
            "slot": item["slot"],
            "fixed_note": item["fixed_note"],
            "factory_bank_letter": item["factory_bank_letter"],
            "factory_patch_1_based": item["factory_patch_1_based"],
            "factory_name": item["factory_name"],
            "packet_file": item["packet_file"],
            "packet_length": len(packet),
            "packet_sha256": digest,
        })
    output = {"status": "DRY_RUN_PASS", "send_enabled": False, "packets_in_order": rows}
    if args.json:
        print(json.dumps(output, indent=2, sort_keys=True))
    else:
        print("S1-C2 v2 host sender dry-run PASS")
        for row in rows:
            print(f"{row['order']}. slot{row['slot']} note {row['fixed_note']}: {row['factory_name']} {row['packet_length']} bytes sha256={row['packet_sha256']}")
        print("No MIDI device is opened by this dry-run tool.")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
'''


def render_report(evidence: dict[str, Any]) -> str:
    app = evidence["app"]
    pkg = evidence["package"]
    packets = evidence["host_packets"]["packets_in_order"]
    return f"""# S1-C2 two-slot selector live candidate PASS

Date: 2026-08-02 UTC  
Status: **PASS, candidate built offline**  
Scope: exact official v15 package plus exact live-PASS S1-C1 parent app. No device access, flash, OTA, reset, or live MIDI traffic was performed.

## Decision

The c0aa779 review BLOCK is remediated by self-contained v2 inputs, a split-entry validator, and actual guarded C live tools. Route separation occurs at the two H2 product callsites, without reading PI32 `rets`.

- Direct callsite `0x0201e468` encodes `{app['call_routes']['direct_callsite']['bytes']}` and targets the main producer entry `0x0201e1a2`.
- Segmented callsite `0x0201e49c` encodes `{app['call_routes']['segmented_callsite']['bytes']}` and targets the no-mutation immediate-return entry `{app['producer']['segmented_stub']}` inside `0x0201e1a2..0x0201e254`.
- Caller reloads at `0x0201e46c` and `0x0201e4a0` remain byte-exact: `bfeaf838` and `bfeade38`.
- Note Off `0x0201c63e` and Note On `0x0201c67c` are pinned to the exact 96-byte selector entries. The selector maps Ch10 note36 to slot0 and note45 to slot1 for both Note On and Note Off, with prior H2 fallback for all other notes.

## Exact artifacts

- App: `app.bin`, SHA-256 `{app['output_app_sha256']}`.
- FWSC: `{PACKAGE_NAME}`, SHA-256 `{pkg['package_sha256']}`.
- Selector: 96 bytes at `0x0201e13e..0x0201e19e`, SHA-256 `{app['selector']['sha256']}`.
- Producer plus segmented stub: `{app['producer']['bytes_in_owned_range']}` bytes at `0x0201e1a2..{app['producer']['end_exclusive']}`, SHA-256 `{app['producer']['sha256']}`. Fits the 178-byte owned range ending at `0x0201e254`.
- Official-v15 exact-sector rollback manifest: `{pkg['rollback_manifest']}`.

## Pinned packets for guarded sender

| Order | Slot | Fixed note | Factory source | Packet file | Runtime SHA-256 | Packet SHA-256 |
|---:|---:|---:|---|---|---|---|
| 1 | {packets[0]['slot']} | {packets[0]['fixed_note']} | Bank {packets[0]['factory_bank_letter']} patch {packets[0]['factory_patch_1_based']}, {packets[0]['factory_name']} | `{packets[0]['packet_file']}` | `{packets[0]['runtime_object_sha256']}` | `{packets[0]['packet_sha256']}` |
| 2 | {packets[1]['slot']} | {packets[1]['fixed_note']} | Bank {packets[1]['factory_bank_letter']} patch {packets[1]['factory_patch_1_based']}, {packets[1]['factory_name']} | `{packets[1]['packet_file']}` | `{packets[1]['runtime_object_sha256']}` | `{packets[1]['packet_sha256']}` |

## Guarded C live tools

The live-capable tools are source-only in `tools/` and require explicit confirmation for transport modes. The validation below compiled them but ran only `check`/`dry-run`/reject paths.

```sh
cc -O2 -g -std=c11 -Wall -Wextra -Wpedantic -Isrc tools/smk37_v15_s1c2_ota.c src/device_info.c src/fwsc.c src/protocol.c src/sha256.c src/usb_probe.c -o build/smk37-v15-s1c2-ota $(pkg-config --cflags --libs libusb-1.0)
cc -O2 -g -std=c11 -Wall -Wextra -Wpedantic -Isrc tools/smk37_v15_s1c2_send.c src/sha256.c -o build/smk37-v15-s1c2-send $(pkg-config --cflags --libs libusb-1.0)
build/smk37-v15-s1c2-ota check baselines/v15/analysis/flash-candidates/S1C2-two-slot-selector-live-v2/{PACKAGE_NAME}
build/smk37-v15-s1c2-send dry-run baselines/v15/analysis/flash-candidates/S1C2-two-slot-selector-live-v2/{packets[0]['packet_file']} baselines/v15/analysis/flash-candidates/S1C2-two-slot-selector-live-v2/{packets[1]['packet_file']}
```

- OTA confirmation token: `INSTALL-SMK37PRO-V15-S1C2-LIVE-V2-63E3CFA3`
- Sender confirmation token: `SEND-SMK37PRO-V15-S1C2-LIVE-V2-6A9B4097-C4E8458E`

## Validation matrix

The validator independently decodes the PI32 bytes and enforces:

- direct `r9 == 0xa3` gate occurs before `testset` and all lock/state/slot mutation;
- direct exact length first packet publishes slot0/note36 and enters LOADING;
- direct wrong length rejects before mutation and segmented packets enter the immediate-return stub at `0x0201e232`;
- direct exact length second packet publishes slot1/note45 and writes ARMED last;
- later direct exact packets reject without mutation;
- app/FWSC package embeds exactly the candidate app;
- rollback sectors reconstruct official-v15 flash exactly;
- `host_sender_dry_run.py --json` self-tests without opening any device transport. Live transport is provided only by the guarded C tools in `tools/`.

Validation output is captured in `validation.txt`. `SHA256SUMS` pins all candidate files.
"""


def build_once(output_dir: Path) -> dict[str, Any]:
    output_dir.mkdir(parents=True, exist_ok=True)
    require(sha256_path(OFFICIAL_FWSC) == EXPECTED["official_fwsc"], "official FWSC hash")
    require(sha256_path(OFFICIAL_APP) == EXPECTED["official_app"], "official app hash")
    require(sha256_path(S1C1_APP) == EXPECTED["s1c1_app"], "S1-C1 app hash")
    stock_raw, stock_flash, stock_app = extract_app_from_fwsc(OFFICIAL_FWSC)
    require(sha256(stock_app) == EXPECTED["official_app"], "official app inside FWSC")
    candidate_app, app_manifest, producer, layout, insns = build_app(S1C1_APP.read_bytes())
    app_path = output_dir / "app.bin"
    fwsc_path = output_dir / PACKAGE_NAME
    app_path.write_bytes(candidate_app)
    (output_dir / "producer.bin").write_bytes(producer)
    (output_dir / "producer.hex").write_text(producer.hex() + "\n", encoding="utf-8")
    (output_dir / "selector.bin").write_bytes(selector_bytes())
    (output_dir / "selector.hex").write_text(selector_bytes().hex() + "\n", encoding="utf-8")
    (output_dir / "decode.tsv").write_text(render_decode(insns), encoding="utf-8")
    write_json(output_dir / "app-manifest.json", app_manifest)
    repack(OFFICIAL_FWSC, app_path, fwsc_path, output_dir / "package-manifest.json")
    package_validation = validate_package_and_rollback(stock_raw, stock_flash, stock_app, candidate_app, fwsc_path, output_dir)
    (output_dir / "host_sender_dry_run.py").write_text(render_host_sender_dry_run(), encoding="utf-8")
    os.chmod(output_dir / "host_sender_dry_run.py", 0o755)
    evidence = {
        "format": FORMAT,
        "decision": "PASS",
        "candidate_built": True,
        "scope": "offline only; no device, OTA, flash, reset, or live MIDI traffic performed",
        "route_identity": "encoded by direct product call target 0x0201e1a2 and segmented product call target 0x0201e232, not LR/rets",
        "app": app_manifest,
        "package": package_validation,
        "host_packets": packet_evidence(output_dir),
        "producer_layout": {key: f"0x{value:08x}" for key, value in layout.items()},
        "instruction_ledger": insns,
        "official_handler_preserved_at": f"0x{OFFICIAL_HANDLER:08x}",
    }
    write_json(output_dir / "evidence.json", evidence)
    (output_dir / "report.md").write_text(render_report(evidence), encoding="utf-8")
    return evidence


def write_sums(output_dir: Path) -> None:
    names = []
    for path in sorted(output_dir.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS" and "__pycache__" not in path.parts:
            names.append(path.relative_to(output_dir).as_posix())
    (output_dir / "SHA256SUMS").write_text("".join(f"{sha256_path(output_dir / name)}  {name}\n" for name in names), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=HERE)
    parser.add_argument("--determinism-check", action="store_true")
    args = parser.parse_args()
    first = build_once(args.output_dir)
    if args.determinism_check:
        with tempfile.TemporaryDirectory(prefix="s1c2-live-det-", dir=os.environ.get("JCODE_SCRATCH_DIR")) as tmp:
            tmp_dir = Path(tmp)
            second = build_once(tmp_dir)
            compare = ["app.bin", PACKAGE_NAME, "app-manifest.json", "package-manifest.json", "producer.bin", "producer.hex", "selector.bin", "selector.hex", "decode.tsv", "evidence.json", "report.md", "host_sender_dry_run.py", "host/packets/slot0-note36-direct-product-163.bin", "host/packets/slot1-note45-direct-product-163.bin", "rollback/official-v15-recovery-sectors/manifest.json"]
            for rel in compare:
                require((args.output_dir / rel).read_bytes() == (tmp_dir / rel).read_bytes(), f"determinism mismatch: {rel}")
            for path in (args.output_dir / "rollback" / "official-v15-recovery-sectors").glob("official-v15-sector-*.bin"):
                rel = path.relative_to(args.output_dir)
                require(path.read_bytes() == (tmp_dir / rel).read_bytes(), f"determinism mismatch: {rel}")
            require(first == second, "determinism mismatch: evidence object")
    write_sums(args.output_dir)
    print(json.dumps({"app_sha256": first["app"]["output_app_sha256"], "package_sha256": first["package"]["package_sha256"], "producer_bytes": first["app"]["producer"]["bytes_in_owned_range"], "segmented_stub": first["app"]["producer"]["segmented_stub"]}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
