#!/usr/bin/env python3
"""Build and validate the S1-C3 contiguous Ch10 16-slot selector blob.

Offline evidence generator only. It writes a raw reviewed selector blob and
proof artifacts. It never creates an app/FWSC image and never opens device,
USB, MIDI, OTA, flash, or reset paths.
"""
from __future__ import annotations

import csv
import hashlib
import json
import struct
from pathlib import Path
from typing import Any, Callable

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[5]

RUNTIME_BASE = 0x02000000
SELECTOR_START = 0x0201E13E
SELECTOR_END = 0x0201E19E
SELECTOR_WINDOW_BYTES = SELECTOR_END - SELECTOR_START
NOTE_OFF_ENTRY = SELECTOR_START
NOTE_ON_ENTRY = SELECTOR_START + 4
MEMCPY = 0x02048CCE
PATCH_SET_BASE = 0x01C46520
SLOT_STRIDE = 0xA0
VOICE_BYTES = 0x9C
VALID_OFFSET = 0x9C
LOCK_ADDR = 0x01C465BD
STATE_ADDR = 0x01C465BF
STATE_OFFSET_FROM_VALID0 = 3
CH10_NIBBLE = 9
NOTE_FIRST = 36
NOTE_AFTER_LAST = 52
SLOT_COUNT = 16
STATE_ARMED = 2

OFFICIAL_APP = ROOT / "baselines/v15/analysis/flash-candidates/S1C2-two-slot-selector-live-v2/inputs/v15-official-app.bin"
S1C2_LIVE_APP = ROOT / "baselines/v15/analysis/flash-candidates/S1C2-two-slot-selector-live-v2/app.bin"
S1C2_SELECTOR = ROOT / "baselines/v15/analysis/flash-candidates/S1C2-two-slot-selector-live-v2/selector.bin"
S1C2_LIVE_VALIDATION = ROOT / "baselines/v15/analysis/flash-candidates/S1C2-two-slot-selector-live-v2/live-validation-20260803.md"
S1C2_FINAL_REVIEW_JSON = ROOT / "baselines/v15/analysis/flash-candidates/S1C2-two-slot-selector-live-v2-final-review/independent-verification.json"

EXPECTED = {
    "official_app": "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055",
    "s1c2_live_app": "4afd13d7301c2ae209c11d3fe932d019faa770b551f2d8a38cf4c018c7aafa8a",
    "s1c2_selector": "adb8774971811f6dbdce8b7338f2265f18b8bb22544ccab746e74610366d4e35",
}


def require(ok: bool, message: str) -> None:
    if not ok:
        raise SystemExit(f"FAIL: {message}")


def sha256_bytes(data: bytes | bytearray) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_path(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def word(value: int) -> bytes:
    return struct.pack("<H", value & 0xFFFF)


def sx(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def mov_reg(dst: int, src: int) -> bytes:
    require(0 <= dst <= 15 and 0 <= src <= 15, "mov_reg operands")
    return word(0x1600 | (src << 4) | dst)


def mov_imm32(dst: int, value: int) -> bytes:
    require(0 <= dst <= 15, "mov_imm32 register")
    return word(0xFFC0 | dst) + struct.pack("<I", value)


def add_imm8(register: int, immediate: int) -> bytes:
    require(0 <= register <= 7 and -128 <= immediate <= 127, "add_imm8 operands")
    encoded = immediate & 0xFF
    return word(0x20C0 | register | ((encoded >> 5) << 3) | ((encoded & 0x1F) << 8))


def add_imm12(destination: int, source: int, immediate: int) -> bytes:
    require(0 <= destination <= 15 and 0 <= source <= 15 and 0 <= immediate <= 0xFFF, "add_imm12 operands")
    return bytes((destination, 0xE1, immediate & 0xFF, (source << 4) | (immediate >> 8)))


def add_reg(dst: int, src: int) -> bytes:
    """PI32 two-byte `add rDST,rSRC`, i.e. rDST += rSRC."""
    require(0 <= dst <= 7 and 0 <= src <= 7, "add_reg operands")
    return word(0x1800 | (src << 4) | dst)


def mul_imm12(destination: int, source: int, immediate: int) -> bytes:
    """PI32 four-byte immediate multiply, ordinary non-parallel form.

    This encoder reproduces exact official v15 rows:
    - e0e1a300: mul r0,r0,#0xa3
    - e1e1a020: mul r1,r2,#0xa0
    """
    require(0 <= destination <= 15 and 0 <= source <= 15 and 0 <= immediate <= 0xFFF, "mul_imm12 operands")
    return bytes((0xE0 | destination, 0xE1, immediate & 0xFF, (source << 4) | (immediate >> 8)))


def load_byte(destination: int, base: int, offset: int = 0) -> bytes:
    require(all(0 <= register <= 7 for register in (destination, base)), "load_byte registers")
    require(-16 <= offset <= 15, "load_byte offset")
    return word(0x4008 | destination | (base << 4) | ((offset & 0x1F) << 8))


def call32(at: int, target: int) -> bytes:
    displacement = target - (at + 6)
    require(-(1 << 31) <= displacement < (1 << 31), "call32 displacement")
    return b"\x80\xff" + struct.pack("<i", displacement)


def forward_goto(at: int, target: int) -> bytes:
    displacement = target - (at + 2)
    require(displacement >= 0 and displacement % 2 == 0, "forward goto alignment")
    halfwords = displacement // 2
    require(halfwords <= 31, "forward goto reach")
    return word(0x8004 | (halfwords << 8))


def branch_imm7(base_opcode: int, at: int, register: int, immediate: int, target: int) -> bytes:
    displacement = target - (at + 4)
    require(displacement % 2 == 0, "branch alignment")
    halfwords = displacement // 2
    require(-256 <= halfwords <= 255, "branch reach")
    require(0 <= register <= 7 and 0 <= immediate <= 0x7F, "branch operands")
    return word(base_opcode | register) + word((immediate << 9) | (halfwords & 0x1FF))


def jne_imm7(at: int, register: int, immediate: int, target: int) -> bytes:
    return branch_imm7(0xF880, at, register, immediate, target)


def jl_imm7(at: int, register: int, immediate: int, target: int) -> bytes:
    return branch_imm7(0xFD80, at, register, immediate, target)


def jge_imm7(at: int, register: int, immediate: int, target: int) -> bytes:
    return branch_imm7(0xFD00, at, register, immediate, target)


class Routine:
    def __init__(self, start: int):
        self.start = start
        self.data = bytearray()
        self.labels: dict[str, int] = {"start": start}
        self.fixups: list[tuple[int, str, Callable[[int, int], bytes]]] = []
        self.rows: list[dict[str, Any]] = []

    @property
    def pc(self) -> int:
        return self.start + len(self.data)

    def label(self, name: str) -> None:
        self.labels[name] = self.pc

    def emit(self, asm: str, encoded: bytes, meaning: str) -> None:
        self.rows.append({
            "address": f"0x{self.pc:08x}",
            "size": len(encoded),
            "bytes": encoded.hex(),
            "asm": asm,
            "meaning": meaning,
        })
        self.data += encoded

    def branch(self, asm: str, size: int, label: str, encoder: Callable[[int, int], bytes], meaning: str) -> None:
        at = self.pc
        self.rows.append({
            "address": f"0x{at:08x}",
            "size": size,
            "bytes": "pending",
            "asm": asm,
            "meaning": meaning,
        })
        self.fixups.append((len(self.data), label, encoder))
        self.data += b"\0" * size

    def finish(self) -> bytes:
        for offset, label, encoder in self.fixups:
            at = self.start + offset
            encoded = encoder(at, self.labels[label])
            self.data[offset:offset + len(encoded)] = encoded
            for row in self.rows:
                if int(row["address"], 16) == at:
                    row["bytes"] = encoded.hex()
                    break
        return bytes(self.data)


def build_selector_code() -> tuple[bytes, list[dict[str, Any]], dict[str, int]]:
    r = Routine(SELECTOR_START)
    r.emit("mov r3,r5", mov_reg(3, 5), "Note Off adapter: normalize proven Note Off note register r5")
    r.branch("goto core", 2, "core", forward_goto, "Note Off skips over Note On adapter")
    r.emit("mov r3,r6", mov_reg(3, 6), "Note On adapter: normalize proven Note On note register r6")
    r.label("core")
    r.emit("push {rets,r9..r4}", word(0x0479), "preserve original note/velocity/destination base registers")
    r.emit("mov r4,r0", mov_reg(4, 0), "save exact original memcpy destination for every fallback and selected copy")
    r.emit("mov r5,r9", mov_reg(5, 9), "copy channel nibble to low register for branch")
    r.branch("jne r5,#9,copy", 4, "copy", lambda a, t: jne_imm7(a, 5, CH10_NIBBLE, t), "non-Ch10 uses H2-correct fallback source")
    r.branch("jl r3,#36,copy", 4, "copy", lambda a, t: jl_imm7(a, 3, NOTE_FIRST, t), "notes below 36 use fallback before index arithmetic")
    r.branch("jge r3,#52,copy", 4, "copy", lambda a, t: jge_imm7(a, 3, NOTE_AFTER_LAST, t), "notes 52 and above use fallback before index arithmetic")
    r.emit("add r3,#-36", add_imm8(3, -NOTE_FIRST), "r3 = slot index 0..15")
    r.emit(f"mov r8,#{PATCH_SET_BASE:#x}", mov_imm32(8, PATCH_SET_BASE), "base of 16 resident 0xa0-byte slots")
    r.emit("add r5,r8,#0x9c", add_imm12(5, 8, VALID_OFFSET), "r5 = slot0 valid/control/generation/state metadata base")
    r.emit("lb.z r0,[r5+3]", load_byte(0, 5, STATE_OFFSET_FROM_VALID0), "load publication state at 0x01c465bf")
    r.branch("jne r0,#2,copy", 4, "copy", lambda a, t: jne_imm7(a, 0, STATE_ARMED, t), "only fully ARMED published sets are consumed")
    r.emit("mul r3,r3,#0xa0", mul_imm12(3, 3, SLOT_STRIDE), "r3 = slot index * 0xa0")
    r.emit("mov r5,r8", mov_reg(5, 8), "r5 = slot base seed")
    r.emit("add r5,r3", add_reg(5, 3), "r5 = selected slot base; r1 still holds fallback source")
    r.emit("add r6,r5,#0x9c", add_imm12(6, 5, VALID_OFFSET), "r6 = selected slot valid address")
    r.emit("lb.z r0,[r6]", load_byte(0, 6, 0), "load selected slot valid byte")
    r.branch("jne r0,#1,copy", 4, "copy", lambda a, t: jne_imm7(a, 0, 1, t), "invalid selected slot falls back with original r1 intact")
    r.emit("mov r1,r5", mov_reg(1, 5), "select resident slot source only after valid check")
    r.label("copy")
    r.emit("mov r0,r4", mov_reg(0, 4), "restore exact original destination before either selected or fallback memcpy")
    r.emit(f"call {MEMCPY:#x}", call32(r.pc, MEMCPY), "copy exactly caller-provided r2=0x9c via stock memcpy")
    r.emit("pop {pc,r9..r4}", word(0x0459), "restore ABI registers and return to official dispatcher")
    code = r.finish()
    return code, r.rows, dict(r.labels)


def call32_target(at: int, blob: bytes) -> int:
    return at + 6 + struct.unpack("<i", blob[2:6])[0]


def decode_selector(data: bytes, start: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    i = 0
    while i < len(data):
        at = start + i
        remaining = len(data) - i
        w = int.from_bytes(data[i:i + 2], "little") if remaining >= 2 else 0
        row: dict[str, Any]
        size: int
        if remaining >= 6 and data[i:i + 2] == b"\x80\xff":
            size = 6; row = {"op": "call32", "target": call32_target(at, data[i:i + 6]), "mutates": True}
        elif remaining >= 6 and (w & 0xFFC0) == 0xFFC0:
            size = 6; row = {"op": "mov_imm32", "dst": w & 0xF, "imm": int.from_bytes(data[i + 2:i + 6], "little")}
        elif remaining >= 4 and (w & 0xFF80) in {0xF880, 0xFD80, 0xFD00}:
            size = 4
            w2 = int.from_bytes(data[i + 2:i + 4], "little")
            op = {0xF880: "jne_imm7", 0xFD80: "jl_imm7", 0xFD00: "jge_imm7"}[w & 0xFF80]
            row = {"op": op, "reg": w & 7, "imm": (w2 >> 9) & 0x7F, "target": at + 4 + sx(w2 & 0x1FF, 9) * 2}
        elif remaining >= 4 and data[i + 1] == 0xE1 and (data[i] & 0xF0) == 0xE0:
            size = 4; row = {"op": "mul_imm12", "dst": data[i] & 0xF, "src": data[i + 3] >> 4, "imm": data[i + 2] | ((data[i + 3] & 0xF) << 8)}
        elif remaining >= 4 and data[i + 1] == 0xE1:
            size = 4; row = {"op": "add_imm12", "dst": data[i], "src": data[i + 3] >> 4, "imm": data[i + 2] | ((data[i + 3] & 0xF) << 8)}
        elif remaining >= 2 and (w & 0xE088) == 0x4008:
            size = 2; row = {"op": "load_byte", "dst": w & 7, "base": (w >> 4) & 7, "offset": sx((w >> 8) & 0x1F, 5)}
        elif remaining >= 2 and (w & 0xE0C0) == 0x20C0:
            imm = ((w >> 8) & 0x1F) | (((w >> 3) & 7) << 5)
            size = 2; row = {"op": "add_imm8", "dst": w & 7, "imm_signed": sx(imm, 8)}
        elif remaining >= 2 and (w & 0xFF00) == 0x1600:
            size = 2; row = {"op": "mov_reg", "dst": w & 0xF, "src": (w >> 4) & 0xF}
        elif remaining >= 2 and (w & 0xFF00) == 0x1800:
            size = 2; row = {"op": "add_reg", "dst": w & 7, "src": (w >> 4) & 7}
        elif remaining >= 2 and (w & 0x80FF) == 0x8004:
            size = 2; row = {"op": "goto", "target": at + 2 + ((w >> 8) & 0x1F) * 2}
        elif remaining >= 2 and w in {0x0479, 0x0459}:
            size = 2; row = {"op": {0x0479: "push", 0x0459: "pop_pc"}[w]}
        else:
            raise SystemExit(f"FAIL: undecoded selector byte at 0x{at:08x}: {data[i:i+8].hex()}")
        row.update({"address": at, "size": size, "bytes": data[i:i + size].hex()})
        rows.append(row)
        i += size
    return rows


def fmt_addr(value: Any) -> Any:
    if isinstance(value, int):
        return f"0x{value:08x}"
    return value


def write_decode_tsv(path: Path, rows: list[dict[str, Any]]) -> None:
    columns = ["address", "size", "bytes", "op", "target", "dst", "src", "reg", "imm", "imm_signed", "base", "offset", "mutates"]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, delimiter="\t", lineterminator="\n")
        writer.writerow(columns)
        for row in rows:
            writer.writerow([fmt_addr(row.get(column, "")) for column in columns])


def selector_decision(channel: int, note: int, state: int, valid: list[int]) -> str:
    if channel != CH10_NIBBLE:
        return "fallback"
    if note < NOTE_FIRST or note >= NOTE_AFTER_LAST:
        return "fallback"
    if state != STATE_ARMED:
        return "fallback"
    slot = note - NOTE_FIRST
    if valid[slot] != 1:
        return "fallback"
    return f"slot{slot}"


def validate_behavior() -> dict[str, Any]:
    cases = 0
    selected = 0
    fallback = 0
    valid_all = [1] * SLOT_COUNT
    valid_none = [0] * SLOT_COUNT
    for channel in range(16):
        for note in range(128):
            got = selector_decision(channel, note, STATE_ARMED, valid_all)
            expected = f"slot{note - NOTE_FIRST}" if channel == CH10_NIBBLE and NOTE_FIRST <= note < NOTE_AFTER_LAST else "fallback"
            require(got == expected, f"armed/all-valid behavior channel={channel} note={note}: {got} != {expected}")
            cases += 1
            selected += got.startswith("slot")
            fallback += got == "fallback"
            require(selector_decision(channel, note, 0, valid_all) == "fallback", "EMPTY must fallback")
            require(selector_decision(channel, note, 1, valid_all) == "fallback", "LOADING must fallback")
            require(selector_decision(channel, note, STATE_ARMED, valid_none) == "fallback", "invalid slots must fallback")
    return {"matrix_cases": cases, "armed_all_valid_selected_cases": selected, "armed_all_valid_fallback_cases": fallback}


def read_bytes(path: Path) -> bytes:
    require(path.exists(), f"missing input {path}")
    return path.read_bytes()


def main() -> None:
    official = read_bytes(OFFICIAL_APP)
    s1c2_app = read_bytes(S1C2_LIVE_APP)
    s1c2_selector = read_bytes(S1C2_SELECTOR)
    require(sha256_bytes(official) == EXPECTED["official_app"], "official v15 app hash")
    require(sha256_bytes(s1c2_app) == EXPECTED["s1c2_live_app"], "S1-C2 live app hash")
    require(sha256_bytes(s1c2_selector) == EXPECTED["s1c2_selector"], "S1-C2 selector hash")
    require("LIVE PASS" in S1C2_LIVE_VALIDATION.read_text(encoding="utf-8"), "S1-C2 live validation PASS evidence")
    final_review = json.loads(S1C2_FINAL_REVIEW_JSON.read_text(encoding="utf-8"))
    require(final_review["selector"]["bytes"] == 96 and final_review["status"] == "PASS", "S1-C2 independent selector verification")

    base = RUNTIME_BASE
    official_examples = {
        "jl r2,#3": (0x0201C616, jl_imm7(0x0201C616, 2, 3, 0x0201C710), "82fd7b06"),
        "jge r3,#0x3a": (0x02039276, jge_imm7(0x02039276, 3, 0x3A, 0x0203924C), "03fde975"),
        "jge r1,#1": (0x02055B0A, jge_imm7(0x02055B0A, 1, 1, 0x02055956), "01fd2403"),
        "mul r0,r0,#0xa3": (0x0200568A, mul_imm12(0, 0, 0xA3), "e0e1a300"),
        "mul r1,r2,#0xa0": (0x0201C630, mul_imm12(1, 2, 0xA0), "e1e1a020"),
        "add r1,r2": (0x020056AA, add_reg(1, 2), "2118"),
        "add r0,r6": (0x0201E522, add_reg(0, 6), "6018"),
    }
    example_evidence = {}
    for name, (addr, encoded, expected_hex) in official_examples.items():
        app_hex = official[addr - base: addr - base + len(encoded)].hex()
        require(encoded.hex() == expected_hex, f"encoder self-check {name}")
        require(app_hex == expected_hex, f"official byte check {name}: {app_hex}")
        example_evidence[name] = {"address": f"0x{addr:08x}", "bytes": expected_hex}

    code, rows, labels = build_selector_code()
    require(len(code) == 72, f"live selector code byte count {len(code)}")
    require(len(code) <= SELECTOR_WINDOW_BYTES, "selector fits current 96-byte placement window")
    padding = word(0x0459) * ((SELECTOR_WINDOW_BYTES - len(code)) // 2)
    selector_blob = code + padding
    require(len(selector_blob) == SELECTOR_WINDOW_BYTES, "padded selector blob size")
    require(selector_blob[len(code):] == word(0x0459) * 12, "padding is inert pop_pc words")

    decoded = decode_selector(code, SELECTOR_START)
    require(sum(row["size"] for row in decoded) == len(code), "decoded byte count")
    require(decoded[-3]["op"] == "mov_reg" and decoded[-2]["op"] == "call32" and decoded[-1]["op"] == "pop_pc", "copy tail shape")
    require(decoded[-2]["target"] == MEMCPY, "memcpy call target")
    branch_rows = [row for row in decoded if row["op"] in {"jne_imm7", "jl_imm7", "jge_imm7", "goto"}]
    require(all(SELECTOR_START <= row["target"] < SELECTOR_START + len(code) for row in branch_rows), "all branches target live selector code")
    require(all(row["target"] == labels["copy"] for row in decoded if row["op"] in {"jne_imm7", "jl_imm7", "jge_imm7"}), "all conditional rejects reach common copy fallback")
    require(decoded[0]["op"] == "mov_reg" and decoded[0]["src"] == 5 and decoded[0]["dst"] == 3, "Note Off adapter r5 to r3")
    require(decoded[2]["op"] == "mov_reg" and decoded[2]["src"] == 6 and decoded[2]["dst"] == 3, "Note On adapter r6 to r3")

    behavior = validate_behavior()
    slot_bounds = {
        "min_slot": 0,
        "max_slot": 15,
        "min_source": f"0x{PATCH_SET_BASE:08x}",
        "max_source": f"0x{PATCH_SET_BASE + 15 * SLOT_STRIDE:08x}",
        "max_voice_end_exclusive": f"0x{PATCH_SET_BASE + 15 * SLOT_STRIDE + VOICE_BYTES:08x}",
        "slot_region_end_exclusive": f"0x{PATCH_SET_BASE + 16 * SLOT_STRIDE:08x}",
    }
    require(PATCH_SET_BASE + 15 * SLOT_STRIDE + VOICE_BYTES == 0x01C46F1C, "max source bound")
    require(PATCH_SET_BASE + 16 * SLOT_STRIDE == 0x01C46F20, "slot region bound")

    (HERE / "selector.bin").write_bytes(selector_blob)
    (HERE / "selector-live-code.bin").write_bytes(code)
    (HERE / "selector.hex").write_text(selector_blob.hex() + "\n", encoding="utf-8")
    write_decode_tsv(HERE / "pi32-selector-decode.tsv", decoded)

    evidence = {
        "format": "smk37-v15-s1c3-contiguous-selector-evidence-v1",
        "status": {
            "raw_selector_design": "PASS",
            "firmware_candidate": "BLOCK",
            "reason": "Only a raw reviewed selector blob was produced. No app, FWSC, producer/parser, device, flash, OTA, or live MIDI action was created or performed.",
        },
        "scope": "offline files only; no build/flash/device/USB/MIDI/OTA/reset path",
        "current_s1c2_live_pass_basis": {
            "app_sha256": EXPECTED["s1c2_live_app"],
            "selector_sha256": EXPECTED["s1c2_selector"],
            "selector_bytes": 96,
            "live_validation": "LIVE PASS in flash-candidates/S1C2-two-slot-selector-live-v2/live-validation-20260803.md",
            "independent_selector_verification_status": final_review["status"],
        },
        "selector": {
            "start": f"0x{SELECTOR_START:08x}",
            "end_exclusive": f"0x{SELECTOR_END:08x}",
            "window_bytes": SELECTOR_WINDOW_BYTES,
            "live_code_bytes": len(code),
            "padding_bytes": len(selector_blob) - len(code),
            "sha256_selector_bin": sha256_bytes(selector_blob),
            "sha256_live_code": sha256_bytes(code),
            "note_off_entry": f"0x{NOTE_OFF_ENTRY:08x}",
            "note_on_entry": f"0x{NOTE_ON_ENTRY:08x}",
            "copy_tail": f"0x{labels['copy']:08x}",
            "core": f"0x{labels['core']:08x}",
            "memcpy": f"0x{MEMCPY:08x}",
            "hex": selector_blob.hex(),
        },
        "mapping": {
            "complexity": "O(1)",
            "channel_nibble": CH10_NIBBLE,
            "note_first_inclusive": NOTE_FIRST,
            "note_last_inclusive": NOTE_AFTER_LAST - 1,
            "slot_formula": "slot = note - 36",
            "source_formula": "0x01c46520 + (note - 36) * 0xa0",
            "fallback": "all non-Ch10, notes outside 36..51, non-ARMED, or invalid selected slots use original H2-correct source in r1",
        },
        "safety_contract": {
            "slot_base": f"0x{PATCH_SET_BASE:08x}",
            "slot_stride": f"0x{SLOT_STRIDE:02x}",
            "voice_bytes": f"0x{VOICE_BYTES:02x}",
            "slot_valid_offset": f"0x{VALID_OFFSET:02x}",
            "global_lock": f"0x{LOCK_ADDR:08x}",
            "publication_state": f"0x{STATE_ADDR:08x}",
            "state_values": {"EMPTY": 0, "LOADING": 1, "ARMED": 2},
            "consumer_locking": "none; selector reads only after state==ARMED and then checks selected slot valid",
            "producer_required_order": [
                "take global nonblocking PI32 testset lock at 0x01c465bd before mutation",
                "for each slot: valid=0 before copy, copy 0x9c voice bytes, csync, valid=1 last",
                "after all 16 slots are valid and bounds/checks pass: csync then state=ARMED last",
                "after ARMED: no in-place mutation until reboot or a separately reviewed inactive replacement protocol",
            ],
        },
        "abi": {
            "note_off": {"hook_callsite": "0x0201c63e", "entry": f"0x{NOTE_OFF_ENTRY:08x}", "note_register": "r5", "adapter": "mov r3,r5; goto core"},
            "note_on": {"hook_callsite": "0x0201c67c", "entry": f"0x{NOTE_ON_ENTRY:08x}", "note_register": "r6", "velocity_register": "r5", "adapter": "mov r3,r6; fall through"},
            "preserved_by_push_pop": ["r9", "r8", "r7", "r6", "r5", "r4", "rets/pc"],
            "restored_destination": "r0 is restored from r4 immediately before memcpy on selected and fallback paths",
            "source_register": "r1 remains original fallback source until after state/range/valid pass; selected path then assigns r1=slot base",
            "copy_count": "r2 is never modified by the selector and remains 0x9c from the official callsites",
        },
        "branch_reach": [{k: fmt_addr(v) for k, v in row.items() if k in {"address", "bytes", "op", "target", "reg", "imm"}} for row in branch_rows],
        "official_encoding_examples": example_evidence,
        "bounds": slot_bounds,
        "behavior_validation": behavior,
    }
    (HERE / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    report_lines = [
        "# S1-C3 contiguous Ch10 16-slot selector design",
        "",
        "Date: 2026-08-03 UTC",
        "Status: **PASS for raw selector design and bytes; BLOCK for firmware/live candidate.**",
        "Scope: offline-only analysis. No app/FWSC image, build/flash, USB, MIDI, OTA, reset, or device access was created or performed.",
        "",
        "## Decision",
        "",
        "**PASS:** The reviewed raw selector blob fits the exact current S1-C2 selector placement `0x0201e13e..0x0201e19e`. It maps Ch10 notes `36..51` to resident slots `0..15` in O(1) as `slot = note - 36`, for both Note On and Note Off, and falls back through the H2-correct original source for all outside-range or unpublished cases.",
        "",
        "**BLOCK:** This is not a flashable firmware candidate. A future child still needs a reviewed 16-slot producer/parser, heap/headroom proof, rollback package, independent review, and separately authorized live stress. This run intentionally emits only `selector.bin` plus proof artifacts.",
        "",
        "## Exact current basis",
        "",
        f"- Official v15 app SHA-256: `{EXPECTED['official_app']}`.",
        f"- S1-C2 live-PASS app SHA-256: `{EXPECTED['s1c2_live_app']}`.",
        f"- Current S1-C2 selector SHA-256: `{EXPECTED['s1c2_selector']}`, 96 bytes at `0x0201e13e..0x0201e19e`.",
        "- Live evidence: `flash-candidates/S1C2-two-slot-selector-live-v2/live-validation-20260803.md` records **LIVE PASS** for Note 36 selected slot0, Note 45 selected slot1, Note 40 fallback, no reboot/stuck-note report.",
        "- Independent byte decode basis: `flash-candidates/S1C2-two-slot-selector-live-v2-final-review/pi32-selector-decode.tsv` verified the two native adapters, fallback copy tail, and `memcpy` target.",
        "",
        "## Selector algorithm",
        "",
        "```c",
        "/* Note Off entry normalizes r5, Note On entry normalizes r6 into r3. */",
        "if (r9 != 9) goto fallback;",
        "if (note < 36 || note >= 52) goto fallback;",
        "if (*(uint8_t *)0x01c465bf != 2) goto fallback;  /* ARMED */",
        "slot = note - 36;",
        "src = (uint8_t *)0x01c46520 + slot * 0xa0;",
        "if (src[0x9c] != 1) goto fallback;",
        "r1 = src;",
        "fallback_or_selected_copy:",
        "r0 = original_destination;",
        "memcpy(r0, r1, r2);  /* r2 remains official 0x9c */",
        "```",
        "",
        "The range checks happen before subtracting `36`, so notes below `36` cannot underflow into an out-of-range slot pointer. `r1` is not changed until after the selected slot valid byte passes, so every reject path keeps the original H2/stock source.",
        "",
        "## Exact PI32 bytes",
        "",
        f"- Live code bytes: `{len(code)}`.",
        f"- Placement window bytes: `{SELECTOR_WINDOW_BYTES}`.",
        f"- Padding: `{len(selector_blob) - len(code)}` bytes, twelve inert `pop {{pc,r9..r4}}` words (`5904`) after the live return.",
        f"- `selector.bin` SHA-256: `{sha256_bytes(selector_blob)}`.",
        f"- `selector-live-code.bin` SHA-256: `{sha256_bytes(code)}`.",
        "",
        "```text",
        selector_blob.hex(),
        "```",
        "",
        "Full instruction decode is in `pi32-selector-decode.tsv`.",
        "",
        "## ABI proof",
        "",
        "- Note Off hook `0x0201c63e`: official/S1-C1 evidence proves `r5 = msg[1]`, `r0` is the per-voice destination, `r1` is the original source, `r2 = 0x9c`, and `r9` is the channel nibble. Entry `0x0201e13e` executes `mov r3,r5; goto core`.",
        "- Note On hook `0x0201c67c`: official/S1-C1 evidence proves `r6 = msg[1]` and `r5 = msg[2]` velocity. Entry `0x0201e142` executes `mov r3,r6` and falls through.",
        "- The shared core pushes `{rets,r9..r4}` before scratch use and pops `{pc,r9..r4}` after the copy. This restores Note On `r6` and velocity `r5`, and Note Off `r5`, before official metadata stores.",
        "- The selector never writes `r2`, so the official `0x9c` copy count is preserved.",
        "- The selector restores `r0` from `r4` immediately before `memcpy` on every selected and fallback path.",
        "",
        "## Valid, lock, and publication safety",
        "",
        "- Slot records occupy `0x01c46520..0x01c46f20`, 16 records at stride `0xa0`. The selected source is bounded to `0x01c46520..0x01c46e80`; selected voice end is at most `0x01c46f1c`, below the slot-region end `0x01c46f20`.",
        "- The selector consumes only when publication state byte `0x01c465bf == 2` (`ARMED`). `EMPTY`, `LOADING`, corrupt, and absent states fall back.",
        "- The selector then checks the selected slot valid byte at `slot+0x9c == 1`. Invalid selected slots fall back with original `r1` intact.",
        "- Producer lock is a producer-only invariant: future producer code must use the H2-compatible nonblocking `csync; testset` byte at `0x01c465bd`, publish each slot `valid=1` only after its `0x9c` copy and `csync`, and write `ARMED` last after all 16 slots pass bounds/checks. Consumers do not lock because v1 prohibits in-place mutation after `ARMED`.",
        "",
        "## Branch reach and placement",
        "",
        "All conditional rejects target the single copy tail inside the same live selector body. The longest conditional branch in this selector is well inside the signed 9-bit halfword window used by exact v15 `jne/jl/jge` forms. `call32` at the copy tail targets exact stock `memcpy` `0x02048cce`.",
        "",
        "The current 96-byte selector placement remains sufficient:",
        "",
        "| Item | Bytes |",
        "|---|---:|",
        f"| Note adapters and shared O(1) selector live code | {len(code)} |",
        f"| Inert padding to cover exact S1-C2 selector window | {len(selector_blob) - len(code)} |",
        f"| Total raw replacement blob | {len(selector_blob)} |",
        "| Existing S1-C2 selector window | 96 |",
        "",
        "## Validation performed",
        "",
        f"- Encoder self-checks reproduced exact official v15 `jl`, `jge`, `mul`, and `add` examples: `{', '.join(example_evidence)}`.",
        f"- Decoded all `{len(code)}` live bytes with no undecoded instruction.",
        f"- Exhaustive high-level behavior matrix checked `{behavior['matrix_cases']}` channel/note cases for ARMED/all-valid behavior plus EMPTY, LOADING, and invalid-slot fallback cases.",
        "- No firmware image was built and no live transport path was run.",
    ]
    (HERE / "report.md").write_text("\n".join(report_lines) + "\n", encoding="utf-8")

    validation_lines = [
        "S1-C3 contiguous selector validation: PASS",
        f"selector.bin bytes={len(selector_blob)} sha256={sha256_bytes(selector_blob)}",
        f"selector-live-code.bin bytes={len(code)} sha256={sha256_bytes(code)}",
        f"decode_instructions={len(decoded)}",
        f"behavior_matrix_cases={behavior['matrix_cases']}",
        "firmware_candidate=BLOCK (raw selector blob only; no app/FWSC/device/flash/OTA/MIDI)",
    ]
    (HERE / "validation.txt").write_text("\n".join(validation_lines) + "\n", encoding="utf-8")

    files = ["build_selector.py", "selector.bin", "selector-live-code.bin", "selector.hex", "pi32-selector-decode.tsv", "evidence.json", "report.md", "validation.txt"]
    sums = []
    for name in files:
        sums.append(f"{sha256_path(HERE / name)}  {name}")
    (HERE / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="utf-8")
    print("S1-C3 contiguous selector validation: PASS")
    print(f"selector.bin sha256={sha256_bytes(selector_blob)} bytes={len(selector_blob)}")
    print("firmware_candidate=BLOCK raw selector blob only")


if __name__ == "__main__":
    main()
