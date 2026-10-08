#!/usr/bin/env python3
"""Read-only official-v15 R03 producer/consumer placement analysis.

The script reads exact official-v15 artifacts, validates all patched-site bytes,
constructs the proposed PI32v2 routines in memory, and prints either JSON or a
human-readable validation log. It never writes or patches firmware.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import json
import struct
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[5]
APP = ROOT / "build/v15-official-app.bin"
FWSC = ROOT / "build/SMK-37_Pro_015.fwsc"
MANIFEST = ROOT / "baselines/v15/official/package-manifest.json"
LISTING = ROOT / "baselines/v15/analysis/quarkslab/results/quarkslab-exhaustive-listing.tsv.gz"

APP_SHA256 = "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055"
FWSC_SHA256 = "f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff"
LISTING_SHA256 = "f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347"
RUNTIME_BASE = 0x02000000

CAVE_START = 0x0201E13E
CAVE_END = 0x0201E254
MEMCPY = 0x02048CCE
NOTE_ON_CALL = 0x0201C67C
NOTE_OFF_CALL = 0x0201C63E
PRODUCT_DIRECT_CALL = 0x0201E468
PRODUCT_SEGMENTED_CALL = 0x0201E49C
SAVE_FIRST_WRITE_CALL = 0x02026DA6
SAVE_PACKER_CALL = 0x02026DAC
SAVE_REJECT_TARGET = 0x02026DD4

BSS_START = 0x01C099D4
BSS_SIZE_OLD = 0x0003CB48
BSS_END_OLD = BSS_START + BSS_SIZE_OLD
HEAP_BEGIN_OLD = 0x01C46520
STATE_START = 0x01C46520
STATE_END = 0x01C465E0
STATE_SIZE = STATE_END - STATE_START
VOICE_SIZE = 0x9C
META = STATE_START + VOICE_SIZE
HEAP_BEGIN_NEW = STATE_END
HEAP_END = 0x01C7FD30
BSS_SIZE_NEW = STATE_END - BSS_START
ANCHOR = 0x01C4651C
ANCHOR_BSS_SIZE = HEAP_BEGIN_OLD - BSS_START

# Exact official-v15 sbrk body at 0x0205e9da. The 0x62-byte body has the
# public AC79 SDK sbrk instruction shape. Its product-specific relocations are:
# static __init_addr at +0x10, HEAP_BEGIN at +0x20, HEAP_END at +0x28.
SBRK = 0x0205E9DA
SBRK_SIZE = 0x62
SBRK_SHA256 = "cfbf871082dc6e52b7dd08f678dc5b4080d6cd29d4b44da4e556fd481eabbe1a"
HEAP_BEGIN_INSN = 0x0205E9F8
HEAP_END_INSN = 0x0205EA00

EXPECTED_BYTES = {
    0x02000016: "c3ffd499c001",       # mov r3,#0x01c099d4
    0x0200001E: "c2ff48cb0300",       # mov r2,#0x0003cb48
    HEAP_BEGIN_INSN: "c5ff2065c401",  # mov r5,#0x01c46520
    HEAP_END_INSN: "caff30fdc701",    # mov r10,#0x01c7fd30
    NOTE_ON_CALL: "80ff4cc60200",
    NOTE_OFF_CALL: "80ff8ac60200",
    PRODUCT_DIRECT_CALL: "bfea69fe",
    PRODUCT_SEGMENTED_CALL: "bfea4ffe",
    SAVE_FIRST_WRITE_CALL: "beeaacee",
    SAVE_PACKER_CALL: "bfeac7b9",
}

REQUIRED_ROWS = {
    0x0201E462: "jne r0,#0xf7",
    0x0201E466: "mov r0,r8",
    PRODUCT_DIRECT_CALL: "call 0x0201e13e",
    0x0201E46C: "call 0x02005660",
    0x0201E480: "jne r1,#0xf7",
    0x0201E484: "jne r5,#0x9e",
    0x0201E49A: "mov r0,r6",
    PRODUCT_SEGMENTED_CALL: "call 0x0201e13e",
    0x0201E4A0: "call 0x02005660",
    0x0201C63A: "mov r2,#0x9c",
    0x0201C63C: "mov r1,r8",
    NOTE_OFF_CALL: "call 0x02048cce",
    0x0201C678: "mov r2,#0x9c",
    0x0201C67A: "mov r1,r8",
    NOTE_ON_CALL: "call 0x02048cce",
    0x02026D9E: "add r4,r8,0x1a14",
    0x02026DA2: "mov r2,#0xa3",
    0x02026DA4: "mov r0,r4",
    SAVE_FIRST_WRITE_CALL: "call 0x02004b02",
    0x02026DAA: "mov r0,r4",
    SAVE_PACKER_CALL: "call 0x0201e13e",
    SAVE_REJECT_TARGET: "movz r0,#0x1ec",
    0x02026DD8: "sb r15,[r8 + r0]",
}


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def word(value: int) -> bytes:
    return struct.pack("<H", value & 0xFFFF)


def mov_reg(dst: int, src: int) -> bytes:
    return word(0x1600 | (src << 4) | dst)


def mov_imm32(dst: int, value: int) -> bytes:
    return word(0xFFC0 | dst) + struct.pack("<I", value)


def mov_imm8(register: int, immediate: int) -> bytes:
    if not 0 <= register <= 7 or not 0 <= immediate <= 0xFF:
        raise ValueError("small immediate out of range")
    return word(0x2040 | register | ((immediate >> 5) << 3) | ((immediate & 0x1F) << 8))


def add_imm8(register: int, immediate: int) -> bytes:
    if not 0 <= register <= 7 or not -128 <= immediate <= 127:
        raise ValueError("add immediate out of range")
    encoded = immediate & 0xFF
    return word(0x20C0 | register | ((encoded >> 5) << 3) | ((encoded & 0x1F) << 8))


def load_byte(destination: int, base: int, offset: int = 0) -> bytes:
    if not all(0 <= r <= 7 for r in (destination, base)) or not -16 <= offset <= 15:
        raise ValueError("byte load out of range")
    return word(0x4008 | destination | (base << 4) | ((offset & 0x1F) << 8))


def store_byte(source: int, base: int, offset: int = 0) -> bytes:
    if not all(0 <= r <= 7 for r in (source, base)) or not -16 <= offset <= 15:
        raise ValueError("byte store out of range")
    return word(0x4088 | source | (base << 4) | ((offset & 0x1F) << 8))


def call32(at: int, target: int) -> bytes:
    return b"\x80\xff" + struct.pack("<i", target - (at + 6))


def call16(at: int, target: int) -> bytes:
    displacement = target - (at + 4)
    if displacement & 1 or not -0x8000 <= displacement // 2 <= 0x7FFF:
        raise ValueError("short call out of range")
    return b"\xbf\xea" + struct.pack("<h", displacement // 2)


def jne_imm7(at: int, register: int, immediate: int, target: int) -> bytes:
    displacement = target - (at + 4)
    if not 0 <= immediate <= 0x7F or displacement & 1:
        raise ValueError("conditional branch out of range")
    halfwords = displacement // 2
    if not -256 <= halfwords <= 255:
        raise ValueError("conditional branch out of range")
    return word(0xF880 | register) + word((immediate << 9) | (halfwords & 0x1FF))


def forward_goto(at: int, target: int) -> bytes:
    displacement = target - (at + 2)
    if displacement < 0 or displacement & 1 or displacement // 2 > 31:
        raise ValueError("compact forward goto out of range")
    return word(0x8004 | ((displacement // 2) << 8))


class Routine:
    def __init__(self, start: int, name: str):
        self.start = start
        self.name = name
        self.data = bytearray()
        self.labels: dict[str, int] = {}
        self.fixups: list[tuple[int, Callable[[int, int], bytes], str]] = []
        self.instructions: list[dict[str, Any]] = []

    @property
    def pc(self) -> int:
        return self.start + len(self.data)

    def label(self, name: str) -> None:
        self.labels[name] = self.pc

    def emit(self, text: str, encoded: bytes) -> None:
        self.instructions.append({"address": f"0x{self.pc:08x}", "size": len(encoded), "text": text, "bytes": encoded.hex()})
        self.data += encoded

    def branch(self, text: str, label: str, encoder: Callable[[int, int], bytes], size: int) -> None:
        at = self.pc
        self.instructions.append({"address": f"0x{at:08x}", "size": size, "text": text, "bytes": "pending"})
        self.fixups.append((len(self.data), encoder, label))
        self.data += b"\x00" * size

    def finish(self) -> bytes:
        for offset, encoder, label in self.fixups:
            at = self.start + offset
            encoded = encoder(at, self.labels[label])
            self.data[offset:offset + len(encoded)] = encoded
            for row in self.instructions:
                if int(row["address"], 16) == at:
                    row["bytes"] = encoded.hex()
                    break
        return bytes(self.data)


def build_note_on(start: int) -> Routine:
    r = Routine(start, "note_on_consumer")
    r.emit("push {rets,r9..r4}", word(0x0479))
    r.emit("mov r3,r9", mov_reg(3, 9))
    r.branch("jne r3,#9,stock_call", "stock_call", lambda a, t: jne_imm7(a, 3, 9, t), 4)
    r.emit(f"mov r6,#{META:#x}", mov_imm32(6, META))
    r.emit("lb.z r7,[r6+1]", load_byte(7, 6, 1))
    r.emit("add r7,#1", add_imm8(7, 1))
    r.branch("jne r7,#0,store_active", "store_active", lambda a, t: jne_imm7(a, 7, 0, t), 4)
    r.emit("add r7,#-1  ; saturate 0xff", add_imm8(7, -1))
    r.label("store_active")
    r.emit("sb r7,[r6+1]", store_byte(7, 6, 1))
    r.emit("lb.z r7,[r6+0]", load_byte(7, 6, 0))
    r.branch("jne r7,#0,owned", "owned", lambda a, t: jne_imm7(a, 7, 0, t), 4)
    r.branch("goto stock_call", "stock_call", forward_goto, 2)
    r.label("owned")
    r.emit(f"mov r1,#{STATE_START:#x}", mov_imm32(1, STATE_START))
    r.label("stock_call")
    r.emit(f"call {MEMCPY:#x}", call32(r.pc, MEMCPY))
    r.emit("pop {pc,r9..r4}", word(0x0459))
    r.finish()
    return r


def build_note_off(start: int) -> Routine:
    r = Routine(start, "note_off_consumer")
    r.emit("push {rets,r9..r4}", word(0x0479))
    r.emit("mov r3,r9", mov_reg(3, 9))
    r.branch("jne r3,#9,stock_path", "stock_path", lambda a, t: jne_imm7(a, 3, 9, t), 4)
    r.emit(f"mov r6,#{META:#x}", mov_imm32(6, META))
    r.emit("lb.z r7,[r6+0]", load_byte(7, 6, 0))
    r.branch("jne r7,#0,owned", "owned", lambda a, t: jne_imm7(a, 7, 0, t), 4)
    r.branch("goto selected", "selected", forward_goto, 2)
    r.label("owned")
    r.emit(f"mov r1,#{STATE_START:#x}", mov_imm32(1, STATE_START))
    r.label("selected")
    r.emit(f"call {MEMCPY:#x}", call32(r.pc, MEMCPY))
    r.emit("lb.z r7,[r6+1]", load_byte(7, 6, 1))
    r.branch("jne r7,#0,decrement", "decrement", lambda a, t: jne_imm7(a, 7, 0, t), 4)
    r.branch("goto done", "done", forward_goto, 2)
    r.label("decrement")
    r.emit("add r7,#-1", add_imm8(7, -1))
    r.emit("sb r7,[r6+1]", store_byte(7, 6, 1))
    r.label("done")
    r.emit("pop {pc,r9..r4}", word(0x0459))
    r.label("stock_path")
    r.emit(f"call {MEMCPY:#x}", call32(r.pc, MEMCPY))
    r.emit("pop {pc,r9..r4}", word(0x0459))
    r.finish()
    return r


def build_producer(start: int) -> Routine:
    r = Routine(start, "post_f7_producer")
    r.emit("push {rets,r6,r5,r4}", word(0x0476))
    r.emit("mov r4,r0  ; preserve stage", mov_reg(4, 0))
    r.emit(f"mov r5,#{META:#x}", mov_imm32(5, META))
    r.emit("lb.z r0,[r5+1]", load_byte(0, 5, 1))
    r.branch("jne r0,#0,reject", "reject", lambda a, t: jne_imm7(a, 0, 0, t), 4)
    r.emit("mov r0,#0", mov_imm8(0, 0))
    r.emit("sb r0,[r5+0]  ; valid=0", store_byte(0, 5, 0))
    r.emit(f"mov r0,#{STATE_START:#x}", mov_imm32(0, STATE_START))
    r.emit("mov r1,r4", mov_reg(1, 4))
    r.emit(f"mov r2,#{VOICE_SIZE:#x}", mov_imm8(2, VOICE_SIZE))
    r.emit(f"call {MEMCPY:#x}", call32(r.pc, MEMCPY))
    r.emit("lb.z r0,[r5+1]", load_byte(0, 5, 1))
    r.branch("jne r0,#0,reject", "reject", lambda a, t: jne_imm7(a, 0, 0, t), 4)
    r.emit("lb.z r0,[r5+2]", load_byte(0, 5, 2))
    r.emit("add r0,#1", add_imm8(0, 1))
    r.emit("sb r0,[r5+2]  ; generation++", store_byte(0, 5, 2))
    r.emit("mov r0,#1", mov_imm8(0, 1))
    r.emit("sb r0,[r5+0]  ; publish valid", store_byte(0, 5, 0))
    r.label("reject")
    r.emit("pop {pc,r6,r5,r4}", word(0x0456))
    r.finish()
    return r


def read_rows() -> dict[int, dict[str, str]]:
    with gzip.open(LISTING, "rt", encoding="utf-8", errors="replace", newline="") as f:
        return {int(row["address"], 16): row for row in csv.DictReader(f, delimiter="\t")}


def build_evidence() -> dict[str, Any]:
    app = APP.read_bytes()
    manifest = json.loads(MANIFEST.read_text())
    rows = read_rows()
    checks: list[dict[str, str]] = []

    def check(name: str, ok: bool, detail: Any) -> None:
        checks.append({"status": "PASS" if ok else "FAIL", "check": name, "detail": str(detail)})

    check("official-app-sha256", sha(APP) == APP_SHA256, sha(APP))
    check("official-package-sha256", sha(FWSC) == FWSC_SHA256, sha(FWSC))
    check("listing-sha256", sha(LISTING) == LISTING_SHA256, sha(LISTING))
    check("manifest-app-binding", manifest.get("app_sha256") == APP_SHA256, manifest.get("app_sha256"))
    check("manifest-package-binding", manifest.get("package_sha256") == FWSC_SHA256, manifest.get("package_sha256"))

    exact_bytes: dict[str, Any] = {}
    for address, expected_hex in EXPECTED_BYTES.items():
        got = app[address - RUNTIME_BASE: address - RUNTIME_BASE + len(bytes.fromhex(expected_hex))].hex()
        exact_bytes[f"0x{address:08x}"] = {"expected": expected_hex, "actual": got}
        check(f"bytes-0x{address:08x}", got == expected_hex, got)

    for address, needle in REQUIRED_ROWS.items():
        text = rows.get(address, {}).get("text", "")
        check(f"row-0x{address:08x}", needle in text, text or "missing")

    sbrk = app[SBRK - RUNTIME_BASE:SBRK - RUNTIME_BASE + SBRK_SIZE]
    check("sbrk-body-sha256", hashlib.sha256(sbrk).hexdigest() == SBRK_SHA256, hashlib.sha256(sbrk).hexdigest())
    check("sbrk-heap-begin-offset", sbrk[0x20:0x24] == struct.pack("<I", HEAP_BEGIN_OLD), sbrk[0x20:0x24].hex())
    check("sbrk-heap-end-offset", sbrk[0x28:0x2C] == struct.pack("<I", HEAP_END), sbrk[0x28:0x2C].hex())
    check(
        "opcode-call32-official-note-on",
        call32(NOTE_ON_CALL, MEMCPY).hex() == EXPECTED_BYTES[NOTE_ON_CALL],
        call32(NOTE_ON_CALL, MEMCPY).hex(),
    )
    check(
        "opcode-call16-official-product",
        call16(PRODUCT_DIRECT_CALL, CAVE_START).hex() == EXPECTED_BYTES[PRODUCT_DIRECT_CALL],
        call16(PRODUCT_DIRECT_CALL, CAVE_START).hex(),
    )
    check(
        "opcode-jne-imm7-official",
        jne_imm7(0x0201E40A, 0, 0, 0x0201E606).hex() == "80f8fc00",
        jne_imm7(0x0201E40A, 0, 0, 0x0201E606).hex(),
    )
    check(
        "opcode-forward-goto-official",
        forward_goto(0x02000EEC, 0x02000F1A).hex() == "0496",
        forward_goto(0x02000EEC, 0x02000F1A).hex(),
    )

    for value, expected_count in [(BSS_SIZE_OLD, 1), (HEAP_BEGIN_OLD, 1), (HEAP_END, 1)]:
        count = app.count(struct.pack("<I", value))
        check(f"unique-literal-{value:#x}", count == expected_count, count)

    check("old-bss-end", BSS_END_OLD == ANCHOR, f"0x{BSS_END_OLD:08x}")
    check("anchor-gap-size", HEAP_BEGIN_OLD - ANCHOR == 4, HEAP_BEGIN_OLD - ANCHOR)
    check("fixed-state-size", STATE_SIZE == 0xC0, hex(STATE_SIZE))
    check("new-bss-end", BSS_START + BSS_SIZE_NEW == STATE_END, f"0x{BSS_START + BSS_SIZE_NEW:08x}")
    check("new-heap-shrink", (HEAP_END - HEAP_BEGIN_OLD) - (HEAP_END - HEAP_BEGIN_NEW) == 0xC0, hex(HEAP_BEGIN_NEW - HEAP_BEGIN_OLD))

    on = build_note_on(CAVE_START)
    off = build_note_off(CAVE_START + len(on.data))
    producer = build_producer(CAVE_START + len(on.data) + len(off.data))
    routines = [on, off, producer]
    used = sum(len(r.data) for r in routines)
    check("note-on-size", len(on.data) == 48, len(on.data))
    check("note-off-size", len(off.data) == 56, len(off.data))
    check("producer-size", len(producer.data) == 54, len(producer.data))
    check("cave-used", used == 158, used)
    check("cave-fit", CAVE_START + used <= CAVE_END, f"end=0x{CAVE_START + used:08x} margin={CAVE_END - (CAVE_START + used)}")

    replacements = {
        f"0x{NOTE_ON_CALL:08x}": call32(NOTE_ON_CALL, on.start).hex(),
        f"0x{NOTE_OFF_CALL:08x}": call32(NOTE_OFF_CALL, off.start).hex(),
        f"0x{PRODUCT_DIRECT_CALL:08x}": call16(PRODUCT_DIRECT_CALL, producer.start).hex(),
        f"0x{PRODUCT_SEGMENTED_CALL:08x}": call16(PRODUCT_SEGMENTED_CALL, producer.start).hex(),
        f"0x{SAVE_FIRST_WRITE_CALL:08x}": (forward_goto(SAVE_FIRST_WRITE_CALL, SAVE_REJECT_TARGET) + b"\x00\x00").hex(),
        f"0x{SAVE_PACKER_CALL:08x}": "00000000",
        "0x0200001e": (word(0xFFC2) + struct.pack("<I", BSS_SIZE_NEW)).hex(),
        f"0x{HEAP_BEGIN_INSN:08x}": (word(0xFFC5) + struct.pack("<I", HEAP_BEGIN_NEW)).hex(),
    }
    expected_replacements = {
        f"0x{NOTE_ON_CALL:08x}": "80ffbc1a0000",
        f"0x{NOTE_OFF_CALL:08x}": "80ff2a1b0000",
        f"0x{PRODUCT_DIRECT_CALL:08x}": "bfea9dfe",
        f"0x{PRODUCT_SEGMENTED_CALL:08x}": "bfea83fe",
        f"0x{SAVE_FIRST_WRITE_CALL:08x}": "04960000",
        f"0x{SAVE_PACKER_CALL:08x}": "00000000",
        "0x0200001e": "c2ff0ccc0300",
        f"0x{HEAP_BEGIN_INSN:08x}": "c5ffe065c401",
    }
    check("replacement-encodings", replacements == expected_replacements, json.dumps(replacements, sort_keys=True))

    pointer_lower_bound = 208
    pointer_margin = (CAVE_END - CAVE_START) - pointer_lower_bound
    check("pointer-lower-bound-fits-mechanically", pointer_margin >= 0, f"lower_bound={pointer_lower_bound} margin={pointer_margin}")

    failed = [c for c in checks if c["status"] != "PASS"]
    evidence = {
        "scope": {
            "basis": "exact official v15 only; public SDK sbrk bytes are calibration, not an alternate firmware baseline",
            "no_device_access": True,
            "no_firmware_build": True,
            "no_flash": True,
            "no_v12": True,
            "no_r01d_boot_hook": True,
        },
        "inputs": {
            "app": str(APP.relative_to(ROOT)),
            "app_sha256": sha(APP),
            "package": str(FWSC.relative_to(ROOT)),
            "package_sha256": sha(FWSC),
            "listing": str(LISTING.relative_to(ROOT)),
            "listing_sha256": sha(LISTING),
        },
        "ram": {
            "bss_start": f"0x{BSS_START:08x}",
            "old_bss_size": f"0x{BSS_SIZE_OLD:08x}",
            "old_bss_end_exclusive": f"0x{BSS_END_OLD:08x}",
            "old_heap_begin": f"0x{HEAP_BEGIN_OLD:08x}",
            "heap_end": f"0x{HEAP_END:08x}",
            "fixed_state": {"start": f"0x{STATE_START:08x}", "end_exclusive": f"0x{STATE_END:08x}", "size": STATE_SIZE},
            "new_bss_size": f"0x{BSS_SIZE_NEW:08x}",
            "new_heap_begin": f"0x{HEAP_BEGIN_NEW:08x}",
            "anchor": f"0x{ANCHOR:08x}",
            "anchor_only_bss_size": f"0x{ANCHOR_BSS_SIZE:08x}",
            "metadata": {
                "voice": [f"0x{STATE_START:08x}", f"0x{META:08x}"],
                "valid_u8": f"0x{META:08x}",
                "active_count_u8": f"0x{META + 1:08x}",
                "generation_u8": f"0x{META + 2:08x}",
                "flags_reserved_u8": f"0x{META + 3:08x}",
                "reserved_tail": [f"0x{META + 4:08x}", f"0x{STATE_END:08x}"],
            },
        },
        "sbrk": {
            "entry": f"0x{SBRK:08x}",
            "size": SBRK_SIZE,
            "sha256": hashlib.sha256(sbrk).hexdigest(),
            "heap_begin_instruction": f"0x{HEAP_BEGIN_INSN:08x}",
            "heap_end_instruction": f"0x{HEAP_END_INSN:08x}",
        },
        "code": {
            "region": [f"0x{CAVE_START:08x}", f"0x{CAVE_END:08x}"],
            "capacity": CAVE_END - CAVE_START,
            "used": used,
            "margin": CAVE_END - CAVE_START - used,
            "routines": [
                {
                    "name": r.name,
                    "start": f"0x{r.start:08x}",
                    "end_exclusive": f"0x{r.start + len(r.data):08x}",
                    "size": len(r.data),
                    "sha256": hashlib.sha256(r.data).hexdigest(),
                    "hex": bytes(r.data).hex(),
                    "instructions": r.instructions,
                }
                for r in routines
            ],
        },
        "replacements": replacements,
        "exact_official_bytes": exact_bytes,
        "save_rejection": {
            "branch_patch": "replace first persistent write call at 0x02026da6 with goto 0x02026dd4 plus nop",
            "effect": "skips both storage writes, skips packer, clears obj+0x1ec at the stock rejection/exit path",
            "unreachable_packer_call_is_neutralized": True,
        },
        "pointer_anchor_alternative": {
            "mechanical_code_lower_bound": pointer_lower_bound,
            "mechanical_margin": pointer_margin,
            "decision": "BLOCK",
            "blockers": [
                "before allocation the four-byte anchor cannot simultaneously hold a pointer and a safe active-note count",
                "lazy malloc entry/context and failure behavior are not proven safe in the MIDI/SysEx handler",
                "it consumes the same 0xc0 heap capacity at runtime while adding allocation failure and publication races",
            ],
        },
        "decision": {
            "ram_ownership": "PASS_FIXED_RESERVATION",
            "code_capacity": "PASS_158_OF_278_BYTES",
            "save_policy": "PASS_NO_WRITE_REJECTION",
            "build_flash": "BLOCK",
            "blockers": [
                "no exact proof that producer and consumer contexts cannot interleave during the final active-count check and valid publication",
                "no approved IRQ-save/restore or scheduler-lock ABI has been incorporated",
                "no heap high-water evidence proves that reducing the arena by 0xc0 cannot expose an existing allocation failure",
            ],
        },
        "validation": checks,
    }
    if failed:
        raise SystemExit("validation failed: " + json.dumps(failed, indent=2))
    return evidence


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--format", choices=("json", "validation"), default="validation")
    args = parser.parse_args()
    evidence = build_evidence()
    if args.format == "json":
        print(json.dumps(evidence, indent=2, sort_keys=True))
    else:
        for row in evidence["validation"]:
            print(f"{row['status']}\t{row['check']}\t{row['detail']}")
        print("OVERALL\tPASS_STATIC_ANALYSIS_BUILD_FLASH_BLOCKED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
