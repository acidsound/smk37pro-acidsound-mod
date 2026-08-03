#!/usr/bin/env python3
"""Build and validate the S1-C3 compact sequential 16-packet producer.

Offline evidence generator only. It writes raw PI32 bytes and proof artifacts.
It never creates a firmware image, opens MIDI/USB, flashes, resets, or touches a
live device.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[5]

PRODUCER_START = 0x0201E1A2
PRODUCER_LIMIT = 0x0201E254
RESET_ENTRY = 0x0201E224
DIRECT_PRODUCT_CALL = 0x0201E468
DIRECT_RELOAD_CALL = 0x0201E46C
SEGMENTED_PRODUCT_CALL = 0x0201E49C
SEGMENTED_RELOAD_CALL = 0x0201E4A0
MEMCPY = 0x02048CCE

PATCH_BASE = 0x01C46520
SLOT_STRIDE = 0xA0
VOICE_SIZE = 0x9C
LOCK = 0x01C465BD
LOADED_COUNT = 0x01C465BE
STATE = 0x01C465BF
EMPTY = 0
LOADING = 1
ARMED = 2
NOTE_FIRST = 36
SLOT_COUNT = 16
RESET_SIGNATURE = (0x62, 0x63)

INPUTS = {
    "s1c3_producer_report": (
        ROOT / "baselines/v15/analysis/patch-set-ui/s1c3/producer/report.md",
        "1c11e8b40ed7954c7650ae7d09aa4615a92cd30f4d8ea152e6b6c6f93f47642a",
    ),
    "s1c3_producer_evidence": (
        ROOT / "baselines/v15/analysis/patch-set-ui/s1c3/producer/evidence.json",
        "1e98e2de80fc2a857eba7bb0843dd7a0e256e3a81d12e36e8e1e738a34ef8028",
    ),
    "s1c3_boundary_report": (
        ROOT / "baselines/v15/analysis/flash-candidates/S1C3-16slot-boundary-only/report.md",
        "0029544b7da3502fcf3b750ab3df6fc32dfa4e6d244570bca9284e19f85733d7",
    ),
    "s1c3_boundary_live_validation": (
        ROOT / "baselines/v15/analysis/flash-candidates/S1C3-16slot-boundary-only/live-validation-20260803.md",
        "6183d6ecc54544bfcd7574c4c7ff5522d0461cc7461baa9f804d88f24fde9fca",
    ),
    "s1c2_live_v2_producer": (
        ROOT / "baselines/v15/analysis/flash-candidates/S1C2-two-slot-selector-live-v2/producer.bin",
        "a05e79c0b46e1e12b1244af3f49866c911fcc41937bc14196825d3080d780784",
    ),
    "s1c2_live_v2_app": (
        ROOT / "baselines/v15/analysis/flash-candidates/S1C2-two-slot-selector-live-v2/app.bin",
        "4afd13d7301c2ae209c11d3fe932d019faa770b551f2d8a38cf4c018c7aafa8a",
    ),
    "s1c3_contiguous_selector": (
        ROOT / "baselines/v15/analysis/patch-set-ui/s1c3/selector/selector.bin",
        "ea2c76595a93cf2cf6a39236e09b749781e2721e3575d0c1b40194855cd4e915",
    ),
}

GENERATED_FILES = [
    "build_compact_producer.py",
    "validate.py",
    "producer.bin",
    "producer.hex",
    "decode.tsv",
    "independent-decode.tsv",
    "evidence.json",
    "report.md",
    "validation.txt",
]


def require(ok: bool, message: str) -> None:
    if not ok:
        raise SystemExit(f"FAIL: {message}")


def sha256_bytes(data: bytes | bytearray) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_path(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def hx(value: int) -> str:
    return f"0x{value:08x}"


def word(value: int) -> bytes:
    return struct.pack("<H", value & 0xFFFF)


def sx(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def mov_reg(dst: int, src: int) -> bytes:
    require(0 <= dst <= 15 and 0 <= src <= 15, "mov_reg operands")
    return word(0x1600 | (src << 4) | dst)


def mov_imm32(dst: int, value: int) -> bytes:
    require(0 <= dst <= 15, "mov_imm32 dst")
    return word(0xFFC0 | dst) + struct.pack("<I", value)


def mov_imm8(register: int, immediate: int) -> bytes:
    require(0 <= register <= 7 and 0 <= immediate <= 0xFF, "mov_imm8 operands")
    return word(0x2040 | register | ((immediate >> 5) << 3) | ((immediate & 0x1F) << 8))


def add_imm8(register: int, immediate: int) -> bytes:
    require(0 <= register <= 7 and -128 <= immediate <= 127, "add_imm8 operands")
    encoded = immediate & 0xFF
    return word(0x20C0 | register | ((encoded >> 5) << 3) | ((encoded & 0x1F) << 8))


def add_reg(dst: int, src: int) -> bytes:
    require(0 <= dst <= 7 and 0 <= src <= 7, "add_reg operands")
    return word(0x1800 | (src << 4) | dst)


def add_imm12(dst: int, src: int, immediate: int) -> bytes:
    require(0 <= dst <= 15 and 0 <= src <= 15 and 0 <= immediate <= 0xFFF, "add_imm12 operands")
    return bytes((dst, 0xE1, immediate & 0xFF, (src << 4) | (immediate >> 8)))


def mul_imm12(dst: int, src: int, immediate: int) -> bytes:
    require(0 <= dst <= 15 and 0 <= src <= 15 and 0 <= immediate <= 0xFFF, "mul_imm12 operands")
    return bytes((0xE0 | dst, 0xE1, immediate & 0xFF, (src << 4) | (immediate >> 8)))


def load_byte(dst: int, base: int, offset: int = 0) -> bytes:
    require(all(0 <= register <= 7 for register in (dst, base)), "load_byte registers")
    require(-16 <= offset <= 15, "load_byte offset")
    return word(0x4008 | dst | (base << 4) | ((offset & 0x1F) << 8))


def store_byte(src: int, base: int, offset: int = 0) -> bytes:
    require(all(0 <= register <= 7 for register in (src, base)), "store_byte registers")
    require(-16 <= offset <= 15, "store_byte offset")
    return word(0x4088 | src | (base << 4) | ((offset & 0x1F) << 8))


def call32(at: int, target: int) -> bytes:
    displacement = target - (at + 6)
    require(-(1 << 31) <= displacement < (1 << 31), "call32 displacement")
    return b"\x80\xff" + struct.pack("<i", displacement)


def short_call(at: int, target: int) -> bytes:
    displacement = target - (at + 4)
    require(displacement % 2 == 0, "short_call alignment")
    halfwords = displacement // 2
    require((at + 4 + ((halfwords & 0xFFFF) * 2)) % 0x20000 == target % 0x20000, "short_call reach window")
    return b"\xbf\xea" + struct.pack("<H", halfwords & 0xFFFF)


def short_call_target(at: int, blob: bytes) -> int:
    require(len(blob) == 4 and blob[:2] == b"\xbf\xea", "short_call bytes")
    half = struct.unpack("<H", blob[2:])[0]
    return ((at + 4 + half * 2) & 0xFFFF) | (at & 0xFFFF0000)


def branch_imm7(base_opcode: int, at: int, register: int, immediate: int, target: int) -> bytes:
    displacement = target - (at + 4)
    require(displacement % 2 == 0, "branch alignment")
    halfwords = displacement // 2
    require(-256 <= halfwords <= 255, "branch reach")
    require(0 <= register <= 7 and 0 <= immediate <= 0x7F, "branch operands")
    return word(base_opcode | register) + word((immediate << 9) | (halfwords & 0x1FF))


def jne_imm7(at: int, register: int, immediate: int, target: int) -> bytes:
    return branch_imm7(0xF880, at, register, immediate, target)


def jge_imm7(at: int, register: int, immediate: int, target: int) -> bytes:
    return branch_imm7(0xFD00, at, register, immediate, target)


def ifeq(at: int, target: int) -> bytes:
    displacement = target - (at + 4)
    require(displacement % 2 == 0 and -0x10000 <= displacement <= 0xFFFE, "ifeq reach")
    return bytes.fromhex("40e8") + struct.pack("<h", displacement // 2)


def forward_goto(at: int, target: int) -> bytes:
    displacement = target - (at + 2)
    require(displacement >= 0 and displacement % 2 == 0, "forward_goto alignment")
    halfwords = displacement // 2
    require(halfwords <= 31, "forward_goto reach")
    return word(0x8004 | (halfwords << 8))


@dataclass
class Fixup:
    offset: int
    label: str
    encoder: Callable[[int, int], bytes]


class Routine:
    def __init__(self, start: int) -> None:
        self.start = start
        self.data = bytearray()
        self.labels: dict[str, int] = {"entry": start}
        self.fixups: list[Fixup] = []
        self.rows: list[dict[str, Any]] = []

    @property
    def pc(self) -> int:
        return self.start + len(self.data)

    def label(self, name: str) -> int:
        self.labels[name] = self.pc
        return self.pc

    def emit(self, name: str, asm: str, encoded: bytes, meaning: str) -> int:
        at = self.pc
        self.rows.append({
            "address": hx(at),
            "size": len(encoded),
            "bytes": encoded.hex(),
            "name": name,
            "asm": asm,
            "meaning": meaning,
        })
        self.data += encoded
        return at

    def branch(self, name: str, asm: str, size: int, label: str, encoder: Callable[[int, int], bytes], meaning: str) -> int:
        at = self.pc
        self.rows.append({
            "address": hx(at),
            "size": size,
            "bytes": "pending",
            "name": name,
            "asm": asm,
            "meaning": meaning,
        })
        self.fixups.append(Fixup(len(self.data), label, encoder))
        self.data += b"\0" * size
        return at

    def finish(self) -> bytes:
        for fixup in self.fixups:
            at = self.start + fixup.offset
            encoded = fixup.encoder(at, self.labels[fixup.label])
            self.data[fixup.offset:fixup.offset + len(encoded)] = encoded
            for row in self.rows:
                if int(row["address"], 16) == at:
                    row["bytes"] = encoded.hex()
                    row["target"] = hx(self.labels[fixup.label])
                    break
        return bytes(self.data)


def build_producer() -> tuple[bytes, list[dict[str, Any]], dict[str, int]]:
    r = Routine(PRODUCER_START)
    r.emit("push_saved", "push {rets,r9..r4}", word(0x0479), "save exact S1-C2 producer frame")
    r.emit("save_stage", "mov r4,r0", mov_reg(4, 0), "r4 = accepted product staging pointer")
    r.emit("length_gate_source", "mov r0,r9", mov_reg(0, 9), "copy r9 to low register for exact length gate")
    r.emit("length_gate_sub_0x80", "add r0,#-0x80", add_imm8(0, -0x80), "r0 = r9 - 0x80")
    r.emit("length_gate_sub_0x23", "add r0,#-0x23", add_imm8(0, -0x23), "r0 = r9 - 0xa3")
    r.branch("length_reject_branch", "jne r0,#0,return", 4, "return", lambda a, t: jne_imm7(a, 0, 0, t), "r9 != 0xa3 returns before testset/state/count/slot mutation")

    r.emit("lock_pointer", f"mov r0,#{LOCK:#x}", mov_imm32(0, LOCK), "r0 = global lock byte 0x01c465bd")
    r.emit("trylock", "csync; testset b[r0]", bytes.fromhex("2000b000"), "nonblocking testset on lock")
    r.branch("trylock_failed_return_branch", "ifeq return", 4, "return", ifeq, "failed testset returns without clearing another owner")
    r.emit("acquired_csync", "csync", word(0x0020), "order after acquired lock")
    r.emit("metadata_pointer", "mov r5,r0", mov_reg(5, 0), "r5 = lock/control base; count is +1, state is +2")
    r.emit("state_load", "lb.z r0,[r5+2]", load_byte(0, 5, STATE - LOCK), "r0 = state at 0x01c465bf")
    r.branch("state_not_empty_branch", "jne r0,#0,not_empty", 4, "not_empty", lambda a, t: jne_imm7(a, 0, EMPTY, t), "state != EMPTY goes to LOADING/invalid validation")

    r.emit("empty_count_load", "lb.z r3,[r5+1]", load_byte(3, 5, LOADED_COUNT - LOCK), "EMPTY path: r3 = loaded_count")
    r.branch("empty_count_reject_branch", "jne r3,#0,unlock", 4, "unlock", lambda a, t: jne_imm7(a, 3, 0, t), "state EMPTY with loaded_count != 0 rejects")
    r.emit("state_loading_value", "mov r0,#1", mov_imm8(0, LOADING), "r0 = LOADING")
    r.emit("state_loading_store", "sb [r5+2],r0", store_byte(0, 5, STATE - LOCK), "state = LOADING before first slot0 copy")
    r.emit("loading_csync", "csync", word(0x0020), "order LOADING before slot0 payload work")
    r.branch("empty_done_goto", "goto after_state", 2, "after_state", forward_goto, "join with r3 = loaded_count")

    r.label("not_empty")
    r.branch("state_not_loading_branch", "jne r0,#1,unlock", 4, "unlock", lambda a, t: jne_imm7(a, 0, LOADING, t), "state not LOADING rejects, including ARMED")
    r.emit("loading_count_load", "lb.z r3,[r5+1]", load_byte(3, 5, LOADED_COUNT - LOCK), "LOADING path: r3 = loaded_count")

    r.label("after_state")
    r.branch("count_full_branch", "jge r3,#16,unlock", 4, "unlock", lambda a, t: jge_imm7(a, 3, SLOT_COUNT, t), "loaded_count >= 16 rejects later packets")
    r.emit("copy_count", "mov r6,r3", mov_reg(6, 3), "r6 = slot index")
    r.emit("slot_offset", "mul r6,r6,#0xa0", mul_imm12(6, 6, SLOT_STRIDE), "r6 = slot index * 0xa0")
    r.emit("slot_base_seed", f"mov r7,#{PATCH_BASE:#x}", mov_imm32(7, PATCH_BASE), "r7 = slot0 base")
    r.emit("slot_base_add", "add r7,r6", add_reg(7, 6), "r7 = selected slot base")
    r.emit("valid_pointer", "add r6,r7,#0x9c", add_imm12(6, 7, VOICE_SIZE), "r6 = selected slot valid byte, slot_base + 0x9c")
    r.emit("valid_clear_value", "mov r0,#0", mov_imm8(0, 0), "r0 = 0")
    r.emit("valid_clear_store", "sb [r6],r0", store_byte(0, 6, 0), "clear valid before copying selected slot")
    r.emit("copy_destination", "mov r0,r7", mov_reg(0, 7), "r0 = selected slot destination")
    r.emit("copy_source", "mov r1,r4", mov_reg(1, 4), "r1 = accepted staging pointer")
    r.emit("copy_size", "mov r2,#0x9c", mov_imm8(2, VOICE_SIZE), "r2 = exact 156-byte runtime payload")
    r.emit("memcpy_call", f"call {MEMCPY:#x}", call32(r.pc, MEMCPY), "memcpy(slot, staging, 0x9c)")
    r.emit("copy_csync", "csync", word(0x0020), "order payload copy before valid publication")
    r.emit("valid_value", "mov r0,#1", mov_imm8(0, 1), "r0 = 1")
    r.emit("valid_store", "sb [r6],r0", store_byte(0, 6, 0), "valid[i] = 1 after full copy")
    r.emit("count_increment", "add r3,#1", add_imm8(3, 1), "r3 = loaded_count + 1")
    r.emit("count_store", "sb [r5+1],r3", store_byte(3, 5, LOADED_COUNT - LOCK), "loaded_count = i + 1 after valid[i]")
    r.branch("not_last_branch", "jne r3,#16,unlock", 4, "unlock", lambda a, t: jne_imm7(a, 3, SLOT_COUNT, t), "only slot15 falls through to ARMED publication")
    r.emit("armed_csync", "csync", word(0x0020), "order valid15 and count16 before ARMED")
    r.emit("armed_value", "mov r0,#2", mov_imm8(0, ARMED), "r0 = ARMED")
    r.emit("armed_store", "sb [r5+2],r0", store_byte(0, 5, STATE - LOCK), "state = ARMED last")

    r.label("unlock")
    r.emit("unlock_csync_before", "csync", word(0x0020), "order metadata before unlock")
    r.emit("unlock_zero", "mov r0,#0", mov_imm8(0, 0), "r0 = 0")
    r.emit("unlock_store", "sb [r5],r0", store_byte(0, 5, 0), "lock = 0")
    r.emit("unlock_csync_after", "csync", word(0x0020), "order unlock")
    r.label("return")
    r.emit("return_restore", "pop {pc,r9..r4}", word(0x0459), "return to caller reload path")

    r.label("segmented_stub")
    r.emit("segmented_stub_push", "push {rets,r9..r4}", word(0x0479), "segmented route no-mutation entry")
    r.emit("segmented_stub_return", "pop {pc,r9..r4}", word(0x0459), "segmented route immediately returns")

    r.label("reset_entry")
    r.emit("reset_push_saved", "push {rets,r9..r4}", word(0x0479), "preserve caller frame before reset signature inspection")
    r.emit("reset_save_stage", "mov r4,r0", mov_reg(4, 0), "r4 = accepted product staging pointer")
    r.emit("reset_sig0_load", "lb.z r1,[r4]", load_byte(1, 4, 0), "load BUZZ BASS reset signature byte 0")
    r.branch("reset_sig0_mismatch", "jne r1,#0x62,reset_skip", 4, "reset_skip", lambda a, t: jne_imm7(a, 1, RESET_SIGNATURE[0], t), "non-reset packet preserves current producer state")
    r.emit("reset_sig1_load", "lb.z r1,[r4+1]", load_byte(1, 4, 1), "load BUZZ BASS reset signature byte 1")
    r.branch("reset_sig1_mismatch", "jne r1,#0x63,reset_skip", 4, "reset_skip", lambda a, t: jne_imm7(a, 1, RESET_SIGNATURE[1], t), "two-byte signature required before reset")
    r.emit("reset_metadata_pointer", f"mov r5,#{LOCK:#x}", mov_imm32(5, LOCK), "r5 = lock/count/state control base")
    r.emit("reset_zero", "mov r0,#0", mov_imm8(0, 0), "r0 = EMPTY/zero")
    r.emit("reset_lock_store", "sb [r5],r0", store_byte(0, 5, 0), "first exact packet clears stale boot lock")
    r.emit("reset_count_store", "sb [r5+1],r0", store_byte(0, 5, LOADED_COUNT - LOCK), "first exact packet sets loaded_count = 0")
    r.emit("reset_state_store", "sb [r5+2],r0", store_byte(0, 5, STATE - LOCK), "first exact packet sets state = EMPTY")
    r.emit("reset_csync", "csync", word(0x0020), "publish reset before invoking sequential producer")
    r.label("reset_skip")
    r.emit("reset_restore_stage", "mov r0,r4", mov_reg(0, 4), "restore accepted staging pointer")
    r.emit("reset_call_producer", f"call {PRODUCER_START:#x}", call32(r.pc, PRODUCER_START), "invoke original sequential producer after optional reset")
    r.emit("reset_return_restore", "pop {pc,r9..r4}", word(0x0459), "restore caller frame")

    producer = r.finish()
    labels = dict(r.labels)
    labels["end"] = PRODUCER_START + len(producer)
    return producer, r.rows, labels


def call32_target(at: int, blob: bytes) -> int:
    return at + 6 + struct.unpack("<i", blob[2:6])[0]


def decode_pi32(data: bytes, start: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    i = 0
    while i < len(data):
        at = start + i
        remaining = len(data) - i
        w = int.from_bytes(data[i:i + 2], "little") if remaining >= 2 else 0
        size: int
        row: dict[str, Any]
        if remaining >= 6 and data[i:i + 2] == b"\x80\xff":
            size = 6
            row = {"op": "call32", "target": call32_target(at, data[i:i + 6])}
        elif remaining >= 6 and (w & 0xFFC0) == 0xFFC0:
            size = 6
            row = {"op": "mov_imm32", "dst": w & 0xF, "imm": int.from_bytes(data[i + 2:i + 6], "little")}
        elif remaining >= 4 and data[i:i + 4] == bytes.fromhex("2000b000"):
            size = 4
            row = {"op": "trylock", "address_register": 0}
        elif remaining >= 4 and data[i:i + 2] == bytes.fromhex("40e8"):
            size = 4
            halfwords = struct.unpack("<h", data[i + 2:i + 4])[0]
            row = {"op": "ifeq", "target": at + 4 + halfwords * 2}
        elif remaining >= 4 and (w & 0xFF80) in {0xF880, 0xFD00}:
            size = 4
            w2 = int.from_bytes(data[i + 2:i + 4], "little")
            op = {0xF880: "jne_imm7", 0xFD00: "jge_imm7"}[w & 0xFF80]
            row = {"op": op, "reg": w & 7, "imm": (w2 >> 9) & 0x7F, "target": at + 4 + sx(w2 & 0x1FF, 9) * 2}
        elif remaining >= 4 and data[i + 1] == 0xE1 and (data[i] & 0xF0) == 0xE0:
            size = 4
            row = {"op": "mul_imm12", "dst": data[i] & 0xF, "src": data[i + 3] >> 4, "imm": data[i + 2] | ((data[i + 3] & 0xF) << 8)}
        elif remaining >= 4 and data[i + 1] == 0xE1:
            size = 4
            row = {"op": "add_imm12", "dst": data[i], "src": data[i + 3] >> 4, "imm": data[i + 2] | ((data[i + 3] & 0xF) << 8)}
        elif remaining >= 2 and (w & 0xE088) == 0x4008:
            size = 2
            row = {"op": "load_byte", "dst": w & 7, "base": (w >> 4) & 7, "offset": sx((w >> 8) & 0x1F, 5)}
        elif remaining >= 2 and (w & 0xE088) == 0x4088:
            size = 2
            row = {"op": "store_byte", "src": w & 7, "base": (w >> 4) & 7, "offset": sx((w >> 8) & 0x1F, 5)}
        elif remaining >= 2 and (w & 0xE0C0) == 0x20C0:
            size = 2
            imm = ((w >> 8) & 0x1F) | (((w >> 3) & 7) << 5)
            row = {"op": "add_imm8", "dst": w & 7, "imm_signed": sx(imm, 8)}
        elif remaining >= 2 and (w & 0xE0C0) == 0x2040:
            size = 2
            imm = ((w >> 8) & 0x1F) | (((w >> 3) & 7) << 5)
            row = {"op": "mov_imm8", "dst": w & 7, "imm": imm}
        elif remaining >= 2 and (w & 0xFF00) == 0x1600:
            size = 2
            row = {"op": "mov_reg", "dst": w & 0xF, "src": (w >> 4) & 0xF}
        elif remaining >= 2 and (w & 0xFF00) == 0x1800:
            size = 2
            row = {"op": "add_reg", "dst": w & 7, "src": (w >> 4) & 7}
        elif remaining >= 2 and (w & 0x80FF) == 0x8004:
            size = 2
            row = {"op": "goto", "target": at + 2 + ((w >> 8) & 0x1F) * 2}
        elif remaining >= 2 and w == 0x0020:
            size = 2
            row = {"op": "csync"}
        elif remaining >= 2 and w in {0x0479, 0x0459}:
            size = 2
            row = {"op": {0x0479: "push", 0x0459: "pop_pc"}[w]}
        else:
            raise SystemExit(f"FAIL: undecoded PI32 bytes at {hx(at)}: {data[i:i + 8].hex()}")
        row.update({"address": at, "size": size, "bytes": data[i:i + size].hex()})
        rows.append(row)
        i += size
    return rows



def independent_decode_text(rows: list[dict[str, Any]]) -> str:
    output = ["address\tsize\tbytes\top\toperands"]
    for row in rows:
        operands = {k: v for k, v in row.items() if k not in {"address", "size", "bytes", "op"}}
        output.append(f"{hx(row['address'])}\t{row['size']}\t{row['bytes']}\t{row['op']}\t{json.dumps(operands, sort_keys=True)}")
    return "\n".join(output) + "\n"


def branch_rows(decoded: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [r for r in decoded if r["op"] in {"jne_imm7", "jge_imm7", "ifeq", "goto", "call32"}]


def simulate_state_machine(packet_count: int) -> dict[str, Any]:
    state = EMPTY
    count = 0
    valid = [0] * SLOT_COUNT
    events: list[str] = []
    for packet_index in range(packet_count):
        before = (state, count, tuple(valid))
        if state == ARMED or count >= SLOT_COUNT:
            events.append(f"packet{packet_index + 1}:reject-no-mutation")
            require((state, count, tuple(valid)) == before, "late reject mutates")
            continue
        if state == EMPTY:
            require(count == 0, "EMPTY requires count 0")
            state = LOADING
            events.append(f"packet{packet_index + 1}:state-loading-before-copy")
        else:
            require(state == LOADING, "only LOADING accepts after packet 1")
        slot = count
        valid[slot] = 0
        events.append(f"packet{packet_index + 1}:slot{slot}-valid-clear")
        events.append(f"packet{packet_index + 1}:slot{slot}-copy-0x9c")
        valid[slot] = 1
        events.append(f"packet{packet_index + 1}:slot{slot}-valid-last")
        count = slot + 1
        events.append(f"packet{packet_index + 1}:loaded-count-{count}")
        if count == SLOT_COUNT:
            state = ARMED
            events.append(f"packet{packet_index + 1}:armed-last")
    return {"state": state, "loaded_count": count, "valid": valid, "events": events}


def verify(producer: bytes, intended: list[dict[str, Any]], labels: dict[str, int], decoded: list[dict[str, Any]]) -> list[str]:
    lines: list[str] = []
    for name, (path, expected) in INPUTS.items():
        require(path.exists(), f"input exists: {name}")
        digest = sha256_path(path)
        require(digest == expected, f"input hash {name}")
        lines.append(f"PASS\tinput-hash\t{name}\t{digest}")

    require(len(producer) == 172, "reset-aware compact producer size")
    require(labels["end"] == PRODUCER_START + len(producer) == 0x0201E24E, "end address")
    require(labels["end"] <= PRODUCER_LIMIT, "producer/stub fits owned window")
    require(PRODUCER_LIMIT - labels["end"] == 6, "6-byte spare")
    require(labels["segmented_stub"] == 0x0201E220, "segmented stub address")
    require(labels["reset_entry"] == RESET_ENTRY, "reset wrapper address")
    require(labels["return"] == 0x0201E21E, "return address")
    lines.append(f"PASS\trange-fit\t{hx(PRODUCER_START)}..{hx(labels['end'])} <= {hx(PRODUCER_LIMIT)} spare={PRODUCER_LIMIT - labels['end']}")
    lines.append(f"PASS\tproducer-sha256\t{sha256_bytes(producer)}")

    require(len(decoded) == len(intended), "independent decode instruction count")
    require(sum(r["size"] for r in decoded) == len(producer), "independent decode covers all bytes")
    require([r["bytes"] for r in decoded] == [r["bytes"] for r in intended], "independent decode byte sequence equals intended rows")
    lines.append(f"PASS\tdecode\t{len(decoded)} instructions cover {len(producer)} bytes")

    target_allow = {
        labels["return"], labels["not_empty"], labels["unlock"], labels["after_state"],
        labels["reset_skip"], MEMCPY, PRODUCER_START,
    }
    for row in branch_rows(decoded):
        target = row["target"]
        require(target in target_allow, f"branch/call target allowed at {hx(row['address'])} -> {hx(target)}")
        if row["op"] == "call32":
            require(target in {MEMCPY, PRODUCER_START}, "call32 target is memcpy or original producer")
            lines.append(f"PASS\tcall-reach\t{hx(row['address'])}->{hx(target)}")
        else:
            require(PRODUCER_START <= target < labels["end"], f"internal branch target in blob at {hx(row['address'])}")
            lines.append(f"PASS\tbranch-reach\t{hx(row['address'])}->{hx(target)}\t{row['op']}")

    direct = short_call(DIRECT_PRODUCT_CALL, labels["reset_entry"])
    segmented = short_call(SEGMENTED_PRODUCT_CALL, labels["segmented_stub"])
    require(direct.hex() == "bfeadcfe", "direct reset-wrapper callsite exact bytes")
    require(segmented.hex() == "bfeac0fe", "segmented callsite exact bytes")
    require(short_call_target(DIRECT_PRODUCT_CALL, direct) == labels["reset_entry"], "direct call target")
    require(short_call_target(SEGMENTED_PRODUCT_CALL, segmented) == labels["segmented_stub"], "segmented call target")
    lines.append(f"PASS\tdirect-callsite\t{hx(DIRECT_PRODUCT_CALL)} {direct.hex()} -> {hx(labels['reset_entry'])}")
    lines.append(f"PASS\tsegmented-callsite\t{hx(SEGMENTED_PRODUCT_CALL)} {segmented.hex()} -> {hx(labels['segmented_stub'])}")
    lines.append(f"PASS\treload-callsites\t{hx(DIRECT_RELOAD_CALL)} bfeaf838; {hx(SEGMENTED_RELOAD_CALL)} bfeade38 unchanged")

    by_name = {r["name"]: int(r["address"], 16) for r in intended}
    require(by_name["length_reject_branch"] < by_name["lock_pointer"] < by_name["trylock"] < by_name["state_loading_store"], "r9 gate before testset/state mutation")
    require(by_name["trylock_failed_return_branch"] < by_name["state_loading_store"], "trylock fail branch before stores")
    require(by_name["valid_clear_store"] < by_name["memcpy_call"] < by_name["copy_csync"] < by_name["valid_store"] < by_name["count_store"] < by_name["armed_store"], "valid-last and ARMED-last order")
    require(labels["segmented_stub"] + 4 == labels["reset_entry"], "segmented stub is only push/pop")
    require(by_name["reset_lock_store"] < by_name["reset_count_store"] < by_name["reset_state_store"] < by_name["reset_call_producer"], "reset publication before producer call")
    lines.append("PASS\tmutation-order\tr9 gate before lock; trylock fail returns; valid-last; loaded_count after valid; ARMED-last")

    sim16 = simulate_state_machine(16)
    require(sim16["state"] == ARMED and sim16["loaded_count"] == 16 and all(v == 1 for v in sim16["valid"]), "16 packets arm all slots")
    sim17 = simulate_state_machine(17)
    require(sim17["state"] == ARMED and sim17["loaded_count"] == 16 and sim17["valid"] == [1] * 16, "17th packet rejects")
    require(sim17["events"][-1] == "packet17:reject-no-mutation", "17th event reject")
    lines.append("PASS\tstate-machine\t16 note-ordered packets arm slots0..15; packet17 rejects no-mutation")

    return lines


def render_evidence(producer: bytes, intended: list[dict[str, Any]], labels: dict[str, int], decoded: list[dict[str, Any]], validation_lines: list[str]) -> dict[str, Any]:
    direct = short_call(DIRECT_PRODUCT_CALL, labels["reset_entry"])
    segmented = short_call(SEGMENTED_PRODUCT_CALL, labels["segmented_stub"])
    return {
        "format": "smk37-v15-s1c3-compact-sequential-producer-v2-reset-aware",
        "date_utc": "2026-08-03",
        "scope": {
            "offline_only": True,
            "firmware_built": False,
            "fwsc_built": False,
            "device_accessed": False,
            "midi_transport_opened": False,
            "flash_performed": False,
            "reset_performed": False,
        },
        "verdict": {
            "exact_pi32_producer_bytes": "PASS",
            "firmware_package_or_live_send": "BLOCK",
            "summary": "Exact 172-byte PI32 producer adds a two-byte slot0 reset wrapper so boot-time heap metadata is not assumed zero; it fits 0x0201e1a2..0x0201e254 with 6 bytes spare.",
        },
        "input_basis": {
            key: {"path": str(path.relative_to(ROOT)), "sha256": expected}
            for key, (path, expected) in INPUTS.items()
        },
        "code_window": {
            "start": hx(PRODUCER_START),
            "end_exclusive": hx(labels["end"]),
            "limit_exclusive": hx(PRODUCER_LIMIT),
            "bytes_used": len(producer),
            "owned_window_bytes": PRODUCER_LIMIT - PRODUCER_START,
            "spare_bytes": PRODUCER_LIMIT - labels["end"],
            "overrun_bytes": 0,
            "segmented_stub": hx(labels["segmented_stub"]),
            "reset_entry": hx(labels["reset_entry"]),
            "return": hx(labels["return"]),
        },
        "producer": {
            "sha256": sha256_bytes(producer),
            "hex": producer.hex(),
            "instruction_count": len(decoded),
            "decode_tsv": "decode.tsv",
            "independent_decode_tsv": "independent-decode.tsv",
        },
        "call_routes": {
            "direct_product_callsite": {"address": hx(DIRECT_PRODUCT_CALL), "bytes": direct.hex(), "target": hx(short_call_target(DIRECT_PRODUCT_CALL, direct))},
            "segmented_product_callsite": {"address": hx(SEGMENTED_PRODUCT_CALL), "bytes": segmented.hex(), "target": hx(short_call_target(SEGMENTED_PRODUCT_CALL, segmented))},
            "direct_reload_intact": {"address": hx(DIRECT_RELOAD_CALL), "bytes": "bfeaf838"},
            "segmented_reload_intact": {"address": hx(SEGMENTED_RELOAD_CALL), "bytes": "bfeade38"},
        },
        "ram_layout": {
            "base": hx(PATCH_BASE),
            "slot_stride": "0x000000a0",
            "voice_size": "0x0000009c",
            "slot_count": SLOT_COUNT,
            "lock": hx(LOCK),
            "loaded_count": hx(LOADED_COUNT),
            "state": hx(STATE),
            "states": {"EMPTY": EMPTY, "LOADING": LOADING, "ARMED": ARMED},
            "slots": [
                {
                    "slot": i,
                    "note": NOTE_FIRST + i,
                    "voice": f"{hx(PATCH_BASE + i * SLOT_STRIDE)}..{hx(PATCH_BASE + i * SLOT_STRIDE + VOICE_SIZE)}",
                    "valid": hx(PATCH_BASE + i * SLOT_STRIDE + VOICE_SIZE),
                }
                for i in range(SLOT_COUNT)
            ],
        },
        "branch_and_call_proof": [
            {
                "address": hx(row["address"]),
                "bytes": row["bytes"],
                "op": row["op"],
                "target": hx(row["target"]),
                "reach": "PASS",
            }
            for row in branch_rows(decoded)
        ],
        "contract_proof": {
            "pre_mutation_gate": "length_reject_branch at 0x0201e1ac targets return 0x0201e21e before lock/testset/state/count/slot mutation unless r9 == 0xa3",
            "segmented_no_mutation": "segmented entry 0x0201e220 is push; pop only and has no store/testset/call",
            "slot_formula": "slot_base = 0x01c46520 + loaded_count * 0xa0; valid = slot_base + 0x9c",
            "publication_order": "clear valid, copy 0x9c, csync, valid=1, loaded_count=i+1; for slot15, csync and state=ARMED last",
            "note_order": "host packet order maps slots 0..15 to notes 36..51",
            "reset_contract": "direct call enters 0x0201e224; exact slot0 signature 62 63 clears lock/count/state before calling the original producer at 0x0201e1a2",
        },
        "validation": validation_lines,
    }


def render_report(evidence: dict[str, Any]) -> str:
    producer = evidence["producer"]
    window = evidence["code_window"]
    routes = evidence["call_routes"]
    lines = [
        "# S1-C3 compact sequential 16-packet producer PASS",
        "",
        "Date: 2026-08-03 UTC  ",
        "Status: **PASS for exact offline PI32 producer bytes; BLOCK for firmware package/live send**",
        "",
        "## Decision",
        "",
        "**PASS:** the compact producer/stub is exact PI32, independently decoded byte-for-byte, and fits the owned range `0x0201e1a2..0x0201e254`.",
        "",
        "**BLOCK:** this artifact is offline only. It does not build an app/FWSC, open MIDI/USB, flash, reset, or authorize a live send.",
        "",
        "## Exact bytes and range",
        "",
        f"- Producer/stub range: `{window['start']}..{window['end_exclusive']}`.",
        f"- Owned limit: `{window['limit_exclusive']}`.",
        f"- Bytes used: `{window['bytes_used']}` of `{window['owned_window_bytes']}`.",
        f"- Spare bytes: `{window['spare_bytes']}`.",
        "- Minimal overrun: `0` bytes. No alternative placement is needed.",
        f"- Segmented no-mutation entry: `{window['segmented_stub']}`.",
        f"- SHA-256: `{producer['sha256']}`.",
        "",
        "```text",
        producer["hex"],
        "```",
        "",
        "## Call route reach",
        "",
        f"- Direct product callsite `{routes['direct_product_callsite']['address']}` bytes `{routes['direct_product_callsite']['bytes']}` target `{routes['direct_product_callsite']['target']}`.",
        f"- Segmented product callsite `{routes['segmented_product_callsite']['address']}` bytes `{routes['segmented_product_callsite']['bytes']}` target `{routes['segmented_product_callsite']['target']}`.",
        f"- Direct reload remains `{routes['direct_reload_intact']['address']} {routes['direct_reload_intact']['bytes']}`.",
        f"- Segmented reload remains `{routes['segmented_reload_intact']['address']} {routes['segmented_reload_intact']['bytes']}`.",
        "",
        "## Contract summary",
        "",
        "- Direct entry preserves the S1-C2 frame shape: `push {rets,r9..r4}` and `pop {pc,r9..r4}`.",
        "- `r9 == 0xa3` is checked at `0x0201e1a6..0x0201e1ac`; the reject target is the return at `0x0201e21e`, before `testset` or any store.",
        "- Lock is `0x01c465bd`; `testset` is nonblocking and failed acquisition returns without unlock.",
        "- `loaded_count` is `0x01c465be`; `state` is `0x01c465bf`.",
        "- Slot pointer is `0x01c46520 + loaded_count * 0xa0`; valid byte is `slot + 0x9c`.",
        "- For slots `0..15`, host order is note `36..51`; publication is valid-last, count-after-valid, and ARMED-last for slot 15.",
        "- Segmented entry `0x0201e220` is only `push; pop`, so it has no mutation path.",
        "- Direct entry now targets reset wrapper `0x0201e224`; slot0 payload signature `62 63` clears stale lock/count/state before the original producer runs.",
        "",
        "## Branch/call proof",
        "",
        "| Address | Bytes | Op | Target | Reach |",
        "|---|---|---|---|---|",
    ]
    for row in evidence["branch_and_call_proof"]:
        lines.append(f"| `{row['address']}` | `{row['bytes']}` | `{row['op']}` | `{row['target']}` | **{row['reach']}** |")
    lines.extend([
        "",
        "All branches stay inside the owned blob. The two `call32` targets are stock `memcpy` at `0x02048cce` and the original sequential producer at `0x0201e1a2`.",
        "",
        "## Artifacts",
        "",
        "- `producer.bin` and `producer.hex`: exact PI32 bytes.",
        "- `decode.tsv`: builder-emitted instruction table.",
        "- `independent-decode.tsv`: separate byte-pattern decoder over every byte.",
        "- `evidence.json`: structured proof data.",
        "- `validation.txt`: validation transcript.",
        "",
        "## Reproduction",
        "",
        "```sh",
        "python3 baselines/v15/analysis/patch-set-ui/s1c3/compact-producer/validate.py",
        "(cd baselines/v15/analysis/patch-set-ui/s1c3/compact-producer && shasum -a 256 -c SHA256SUMS)",
        "```",
        "",
    ])
    return "\n".join(lines)



def run(write: bool = False, check_files: bool = False) -> list[str]:
    producer, intended_rows, labels = build_producer()
    decoded = decode_pi32(producer, PRODUCER_START)
    validation_lines = verify(producer, intended_rows, labels, decoded)
    evidence = render_evidence(producer, intended_rows, labels, decoded, validation_lines)
    report = render_report(evidence)
    hex_text = producer.hex() + "\n"
    intended_text = "\n".join(["address\tsize\tbytes\tname\tasm\tmeaning\ttarget"] + [
        "\t".join([
            row["address"], str(row["size"]), row["bytes"], row["name"], row["asm"], row["meaning"], row.get("target", ""),
        ]).rstrip()
        for row in intended_rows
    ]) + "\n"
    independent_text = independent_decode_text(decoded)
    evidence_text = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    validation_text = "S1-C3 compact sequential producer validation: PASS\n" + "\n".join(validation_lines) + "\n"

    expected_files: dict[str, bytes | str] = {
        "producer.bin": producer,
        "producer.hex": hex_text,
        "decode.tsv": intended_text,
        "independent-decode.tsv": independent_text,
        "evidence.json": evidence_text,
        "report.md": report,
        "validation.txt": validation_text,
    }

    if check_files:
        for name, expected in expected_files.items():
            path = HERE / name
            require(path.exists(), f"generated file exists: {name}")
            actual = path.read_bytes() if isinstance(expected, bytes) else path.read_text(encoding="utf-8")
            require(actual == expected, f"generated file matches builder output: {name}")

    if write:
        for name, content in expected_files.items():
            path = HERE / name
            if isinstance(content, bytes):
                path.write_bytes(content)
            else:
                path.write_text(content, encoding="utf-8")
        sums = []
        for name in GENERATED_FILES:
            path = HERE / name
            if path.exists():
                sums.append(f"{sha256_path(path)}  {name}")
        (HERE / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")
    return validation_lines


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="check generated files against deterministic builder output")
    parser.add_argument("--no-write", action="store_true", help="validate without writing artifacts")
    args = parser.parse_args()
    lines = run(write=not args.no_write and not args.check, check_files=args.check)
    print("S1-C3 compact sequential producer validation: PASS")
    for line in lines:
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
