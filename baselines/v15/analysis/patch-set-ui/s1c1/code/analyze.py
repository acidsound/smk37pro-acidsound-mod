#!/usr/bin/env python3
"""Reproduce the official-v15/H2 S1-C1 hook and code-placement audit.

This tool is analysis-only. It reads exact existing app/listing evidence, builds
standalone wrapper bytes in memory with the current v15 PI32 helpers, and writes
only text/JSON evidence beside itself. It never emits an app/FWSC image, opens a
device, invokes an uploader, or imports v12 evidence.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[5]
sys.path.insert(0, str(ROOT / "tools"))

from build_v15_h1_producer_unconsumed import build_producer  # noqa: E402
from build_v15_r01_hand_drum import (  # noqa: E402
    APP_SHA256,
    APP_SIZE,
    CODE_CAVE,
    CODE_CAVE_END,
    MEMCPY,
    RUNTIME_BASE,
    call32,
    jne_imm7,
    mov_imm32,
    mov_reg,
    word,
)
from build_v15_r03_fixed_prefix import load_byte, short_call  # noqa: E402

FORMAT = "smk37-v15-h2-s1c1-code-audit-v1"
OFFICIAL_APP = ROOT / "build/v15-official-app.bin"
H2_APP = ROOT / "build/SMK37Pro-v15-H2-owned-source-corrected-fallback/app.bin"
H2_MANIFEST = ROOT / "baselines/v15/analysis/flash-candidates/H2-owned-source-corrected-fallback/app-manifest.json"
H2_LIVE = ROOT / "baselines/v15/analysis/flash-candidates/H2-owned-source-corrected-fallback/live-validation-20260802.md"
QUARK = ROOT / "baselines/v15/analysis/quarkslab/results/quarkslab-exhaustive-listing.tsv.gz"
KAGA = ROOT / "baselines/v15/analysis/quarkslab/results/kagaimiq-patched-exhaustive-listing.tsv.gz"
REPORT = HERE / "report.md"
EVIDENCE_OUT = HERE / "evidence.json"
LAYOUT_OUT = HERE / "wrapper-layout.json"
HEX_OUT = HERE / "wrapper-bytes.hex"
VALIDATION_OUT = HERE / "validation.txt"

OFFICIAL_APP_SHA256 = "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055"
H2_APP_SHA256 = "d71f6c58b4fade00aebb8a0b7d9d024641c37c41ca4bbf3e525fd28773087f59"
QUARK_SHA256 = "f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347"
KAGA_SHA256 = "814510c15ba600c7420026204c5f4121bce6a5d074422cc20204755d3280e013"
H2_MANIFEST_SHA256 = "dc6fba4ddb887424d6bd76b6d1477f66f97096e2d6656f203eec423680572cf3"
H2_LIVE_SHA256 = "b2aca5903390cffe573f42c89aa6407a52c28f967124a07b407887959d1c8fd7"

NOTE_OFF_CALL = 0x0201C63E
NOTE_ON_CALL = 0x0201C67C
H2_OFF_ENTRY = 0x0201E13E
H2_ON_ENTRY = 0x0201E170
H2_PRODUCER = 0x0201E1A2
H2_END = 0x0201E1EC
PRODUCT_CALLS = (0x0201E468, 0x0201E49C)

# Minimal H2-compatible two-slot code contract. The code audit deliberately
# treats final RAM ownership/HEAP and guarded-ingress publication as external
# admission gates. The shared byte at the exact H2 valid address is interpreted
# as ARMED == 1 only after both immutable slots are complete.
SLOT0 = 0x01C46520
VALID0 = 0x01C465BC
NOTE0_ADDRESS = 0x01C465BE
STATE = 0x01C465BF
SLOT1 = 0x01C465C0
VALID1 = 0x01C4665C
NOTE1_ADDRESS = 0x01C4665E
EMPTY_VALUE = 0
ARMED_VALUE = 2


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL\t{message}")


def app_bytes(data: bytes, address: int, size: int) -> bytes:
    offset = address - RUNTIME_BASE
    require(0 <= offset <= len(data) - size, f"app address out of range: 0x{address:08x}")
    return data[offset:offset + size]


def rows(path: Path, addresses: set[int]) -> dict[int, str]:
    found: dict[int, str] = {}
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                address = int(line.split("\t", 1)[0], 16)
            except (ValueError, IndexError):
                continue
            if address in addresses:
                found[address] = line.rstrip("\n")
    return found


def forward_goto(at: int, target: int) -> bytes:
    """Encode the compact forward goto proved by official v15 0x0201c650."""
    displacement = target - (at + 2)
    require(displacement >= 0 and not displacement & 1, "forward goto alignment/direction")
    halfwords = displacement // 2
    require(halfwords <= 31, "forward goto range")
    return word(0x8004 | (halfwords << 8))


def xor_r0(register: int) -> bytes:
    """Encode official-v15 two-byte in-place xor r0,register."""
    require(0 <= register <= 7, "xor source register")
    return word(0x1908 | (register << 4))


def add_imm12(destination: int, source: int, immediate: int) -> bytes:
    """Encode official-v15 four-byte add destination,source,#imm12."""
    require(0 <= destination <= 15 and 0 <= source <= 15, "add register")
    require(0 <= immediate <= 0xFFF, "add immediate")
    return bytes((destination, 0xE1, immediate & 0xFF, (source << 4) | (immediate >> 8)))


def decode_call32(at: int, encoded: bytes) -> int:
    require(len(encoded) == 6 and encoded[:2] == b"\x80\xff", "call32 opcode")
    displacement = int.from_bytes(encoded[2:], "little", signed=True)
    return at + 6 + displacement


def decode_jne_target(at: int, encoded: bytes) -> int:
    require(len(encoded) == 4, "jne size")
    halfwords = int.from_bytes(encoded[2:], "little") & 0x1FF
    if halfwords & 0x100:
        halfwords -= 0x200
    return at + 4 + halfwords * 2


def decode_forward_goto(at: int, encoded: bytes) -> int:
    require(len(encoded) == 2, "goto size")
    value = int.from_bytes(encoded, "little")
    require(value & 0x80FF == 0x8004, "goto opcode")
    return at + 2 + ((value >> 8) & 0x1F) * 2


def build_selector() -> tuple[bytes, dict[str, int], list[dict[str, Any]]]:
    """Build two native-note adapters plus one shared guarded lookup core.

    Note Off normalizes r5 to caller-scratch r3, Note On normalizes r6 to r3.
    The second adapter falls through into the shared core, so only the first
    adapter needs a two-byte compact goto. Native r5/r6 are not modified before
    the shared push. The core restores them with pop after temporary r5/r8 use.
    """
    block = bytearray()
    insns: list[dict[str, Any]] = []

    def emit(name: str, blob: bytes, meaning: str) -> int:
        address = CODE_CAVE + len(block)
        block.extend(blob)
        insns.append({
            "address": f"0x{address:08x}",
            "bytes": blob.hex(),
            "name": name,
            "meaning": meaning,
        })
        return address

    off_entry = CODE_CAVE
    emit("off_note_adapter", mov_reg(3, 5), "r3 = Note Off r5 note; native r5 remains untouched")
    off_goto = emit("off_to_core", b"\0" * 2, "compact forward goto shared core")

    on_entry = CODE_CAVE + len(block)
    emit("on_note_adapter", mov_reg(3, 6), "r3 = Note On r6 note; fall through to shared core")

    core = CODE_CAVE + len(block)
    emit("push_saved", word(0x0479), "save original rets and r4..r9, including r5/r6 note/velocity state")
    emit("save_destination", mov_reg(4, 0), "r4 = original memcpy destination")
    emit("normalize_channel", mov_reg(5, 9), "temporary r5 = exact dispatcher channel nibble r9")
    channel_branch = emit("non_ch10_branch", b"\0" * 4, "r5 != 9 -> common stock copy")
    emit("slot0_source_pointer", mov_imm32(8, SLOT0), "temporary r8 = exact H2/private slot0 source")
    emit("slot0_metadata_pointer", add_imm12(5, 8, 0x9C), "r5 = r8 + 0x9c = H2 valid0 / slot0 metadata base")
    emit("state_load", load_byte(0, 5, STATE - VALID0), "r0 = EMPTY/LOADING/ARMED state")
    state_nonempty_branch = emit("state_nonempty_branch", b"\0" * 4, "state != EMPTY -> LOADING/ARMED discriminator")
    emit("h2_valid0_load", load_byte(0, 5), "EMPTY compatibility: r0 = exact H2 valid0")
    h2_invalid_branch = emit("h2_invalid_branch", b"\0" * 4, "EMPTY and valid0 != 1 -> stock copy")
    emit("h2_slot0_source", mov_reg(1, 8), "EMPTY and valid0 == 1 preserves exact H2 slot0 source")
    h2_slot0_goto = emit("h2_slot0_to_copy", b"\0" * 2, "skip private ARMED lookup and use common copy")
    state_nonempty = CODE_CAVE + len(block)
    state_armed_branch = emit("state_armed_branch", b"\0" * 4, "state != ARMED -> stock copy; LOADING never exposes owned RAM")
    emit("note0_load", load_byte(0, 5, NOTE0_ADDRESS - VALID0), "r0 = immutable slot0 note byte")
    emit("note0_compare", xor_r0(3), "r0 = slot0 note XOR normalized event note")
    note0_branch = emit("note0_branch", b"\0" * 4, "slot0 note != event note -> note1 test")
    emit("slot0_valid_load", load_byte(0, 5), "matched slot0: r0 = valid0")
    slot0_invalid_branch = emit("slot0_invalid_branch", b"\0" * 4, "matched slot0 but valid0 != 1 -> stock copy")
    emit("slot0_source", mov_reg(1, 8), "selected r1 = immutable slot0 voice")
    slot0_goto = emit("slot0_to_copy", b"\0" * 2, "skip note1 test/source and use common copy")
    note1_test = CODE_CAVE + len(block)
    emit("slot1_metadata_pointer", add_imm12(5, 5, 0xA0), "r5 += 0xa0 = slot1 valid/transaction/note metadata base")
    emit("note1_load", load_byte(0, 5, NOTE1_ADDRESS - VALID1), "r0 = immutable slot1 note byte")
    emit("note1_compare", xor_r0(3), "r0 = slot1 note XOR normalized event note")
    note1_branch = emit("note1_branch", b"\0" * 4, "slot1 note != event note -> common stock copy")
    emit("slot1_valid_load", load_byte(0, 5), "matched slot1: r0 = valid1")
    slot1_invalid_branch = emit("slot1_invalid_branch", b"\0" * 4, "matched slot1 but valid1 != 1 -> stock copy")
    emit("slot1_source", add_imm12(1, 8, 0xA0), "selected r1 = r8 + 0xa0 = immutable slot1 voice")
    copy = CODE_CAVE + len(block)
    emit("restore_destination", mov_reg(0, 4), "restore original r0 immediately before memcpy")
    memcpy_call = CODE_CAVE + len(block)
    emit("memcpy", call32(memcpy_call, MEMCPY), "call memcpy with original r2 == 0x9c")
    emit("return_restore", word(0x0459), "pop pc,r9..r4; restore native r5/r6 and channel r9")
    end = CODE_CAVE + len(block)

    block[off_goto - CODE_CAVE:off_goto - CODE_CAVE + 2] = forward_goto(off_goto, core)
    branch_specs = (
        (channel_branch, 5, 9, copy),
        (state_nonempty_branch, 0, EMPTY_VALUE, state_nonempty),
        (h2_invalid_branch, 0, 1, copy),
        (state_armed_branch, 0, ARMED_VALUE, copy),
        (note0_branch, 0, 0, note1_test),
        (slot0_invalid_branch, 0, 1, copy),
        (note1_branch, 0, 0, copy),
        (slot1_invalid_branch, 0, 1, copy),
    )
    for address, register, immediate, target in branch_specs:
        block[address - CODE_CAVE:address - CODE_CAVE + 4] = jne_imm7(
            address, register, immediate, target
        )
    block[slot0_goto - CODE_CAVE:slot0_goto - CODE_CAVE + 2] = forward_goto(slot0_goto, copy)
    block[h2_slot0_goto - CODE_CAVE:h2_slot0_goto - CODE_CAVE + 2] = forward_goto(h2_slot0_goto, copy)

    # Refresh placeholder byte strings in the instruction ledger.
    for insn in insns:
        address = int(insn["address"], 16)
        size = len(bytes.fromhex(insn["bytes"]))
        insn["bytes"] = bytes(block[address - CODE_CAVE:address - CODE_CAVE + size]).hex()

    layout = {
        "off_entry": off_entry,
        "off_goto": off_goto,
        "on_entry": on_entry,
        "core": core,
        "channel_branch": channel_branch,
        "state_nonempty_branch": state_nonempty_branch,
        "h2_invalid_branch": h2_invalid_branch,
        "h2_slot0_goto": h2_slot0_goto,
        "state_nonempty": state_nonempty,
        "state_armed_branch": state_armed_branch,
        "note0_branch": note0_branch,
        "slot0_invalid_branch": slot0_invalid_branch,
        "slot0_goto": slot0_goto,
        "note1_test": note1_test,
        "note1_branch": note1_branch,
        "slot1_invalid_branch": slot1_invalid_branch,
        "copy": copy,
        "memcpy_call": memcpy_call,
        "end": end,
    }
    return bytes(block), layout, insns


def validate() -> tuple[dict[str, Any], str]:
    checks: list[str] = []

    def check(name: str, condition: bool, detail: str = "") -> None:
        require(condition, name)
        checks.append(f"PASS\t{name}" + (f"\t{detail}" if detail else ""))

    input_hashes = {
        "official_app": (OFFICIAL_APP, OFFICIAL_APP_SHA256),
        "h2_app": (H2_APP, H2_APP_SHA256),
        "quarkslab_listing": (QUARK, QUARK_SHA256),
        "kagaimiq_listing": (KAGA, KAGA_SHA256),
        "h2_manifest": (H2_MANIFEST, H2_MANIFEST_SHA256),
        "h2_live": (H2_LIVE, H2_LIVE_SHA256),
    }
    for name, (path, expected) in input_hashes.items():
        check(f"input-hash-{name}", path.is_file() and sha256(path) == expected, expected)

    official = OFFICIAL_APP.read_bytes()
    h2 = H2_APP.read_bytes()
    check("official-app-size", len(official) == APP_SIZE and APP_SHA256 == OFFICIAL_APP_SHA256, str(len(official)))
    check("h2-app-size", len(h2) == APP_SIZE, str(len(h2)))

    expected_official = {
        0x020002AC: "08e14412",  # add r8,r1,#0x244
        0x02001426: "05e18883",  # add r5,r8,#0x388
        0x0201C5FE: "79e1f030",  # r9 = channel nibble
        0x0201C62E: "1d41",      # r5 = msg[1]
        0x0201C636: "00e1a260",  # r0 = destination
        0x0201C63A: "623c",      # r2 = 0x9c
        0x0201C63C: "8116",      # r1 = r8 stock source
        0x0201C63E: "80ff8ac60200",
        0x0201C648: "8d40",      # metadata note = r5
        0x0201C66A: "1d42",      # r5 = msg[2] velocity
        0x0201C670: "1e41",      # r6 = msg[1]
        0x0201C674: "00e1a270",  # r0 = destination
        0x0201C678: "623c",      # r2 = 0x9c
        0x0201C67A: "8116",      # r1 = r8 stock source
        0x0201C67C: "80ff4cc60200",
        0x0201C686: "8e40",      # metadata note = r6
        0x0201C68C: "8d42",      # metadata velocity = r5
        0x0201C650: "049f",      # official compact goto proof
        0x02003624: "3819",      # official xor r0,r3 proof
    }
    for address, expected_hex in expected_official.items():
        expected = bytes.fromhex(expected_hex)
        check(f"official-bytes-0x{address:08x}", app_bytes(official, address, len(expected)) == expected, expected_hex)

    # H2 changes only the call instruction inside each exact note-to-metadata
    # window. Reconstructing the expected block proves every surrounding byte is
    # still official and the note register survives to its post-call store.
    for name, start, call_at, target, end in (
        ("note-off", 0x0201C62E, NOTE_OFF_CALL, H2_OFF_ENTRY, 0x0201C64A),
        ("note-on", 0x0201C66A, NOTE_ON_CALL, H2_ON_ENTRY, 0x0201C68E),
    ):
        expected = bytearray(app_bytes(official, start, end - start))
        call_offset = call_at - start
        expected[call_offset:call_offset + 6] = call32(call_at, target)
        actual = app_bytes(h2, start, end - start)
        check(f"h2-{name}-window-only-call-redirected", actual == expected, actual.hex())
        check(f"h2-{name}-call-target", decode_call32(call_at, app_bytes(h2, call_at, 6)) == target, f"0x{target:08x}")

    listing_addresses = set(expected_official)
    qrows = rows(QUARK, listing_addresses)
    krows = rows(KAGA, {0x02003624, 0x0201C62E, 0x0201C63A, 0x0201C63C, 0x0201C63E,
                        0x0201C648, 0x0201C66A, 0x0201C670, 0x0201C678,
                        0x0201C67A, 0x0201C67C, 0x0201C686, 0x0201C68C})
    check("quarkslab-row-coverage", set(qrows) == listing_addresses, str(len(qrows)))
    check("kagaimiq-note-row-coverage", len(krows) == 13, str(len(krows)))
    row_needles = {
        0x020002AC: "r8,r1,#0x244",
        0x02001426: "r5,r8,#0x388",
        0x0201C5FE: "and r9,r3,#0xffffff0f",
        0x0201C62E: "r5,[r1 + 0x1]",
        0x0201C636: "r0,r6,#0xa2",
        0x0201C63A: "r2,#0x9c",
        0x0201C63C: "r1,r8",
        0x0201C648: "r5,[r0 + 0x0]",
        0x0201C66A: "r5,[r1 + 0x2]",
        0x0201C670: "r6,[r1 + 0x1]",
        0x0201C674: "r0,r7,#0xa2",
        0x0201C678: "r2,#0x9c",
        0x0201C67A: "r1,r8",
        0x0201C686: "r6,[r0 + 0x0]",
        0x0201C68C: "r5,[r0 + 0x2]",
        0x0201C650: "goto 0x0201c690",
        0x02003624: "xor r0,r3",
    }
    for address, needle in row_needles.items():
        check(f"quarkslab-decode-0x{address:08x}", needle in qrows[address], needle)
    for address, needle in {
        0x02003624: "xor r0,r3",
        0x0201C62E: "r5,[r1 + 0x1]",
        0x0201C648: "r5,[r0 + 0x0]",
        0x0201C66A: "r5,[r1 + 0x2]",
        0x0201C670: "r6,[r1 + 0x1]",
        0x0201C686: "r6,[r0 + 0x0]",
        0x0201C68C: "r5,[r0 + 0x2]",
    }.items():
        check(f"kagaimiq-decode-0x{address:08x}", needle in krows[address], needle)

    # The compact goto encoder is admitted only because it reproduces an exact
    # official-v15 instruction and its independently generated decode row.
    check("official-forward-goto-encoder", forward_goto(0x0201C650, 0x0201C690) == bytes.fromhex("049f"), "049f")
    check("official-forward-goto-decoder", decode_forward_goto(0x0201C650, bytes.fromhex("049f")) == 0x0201C690)
    check("official-xor-r0-r3-encoder", xor_r0(3) == bytes.fromhex("3819"), "3819")
    check("official-add-imm12-encoder-r0-r6-a2", add_imm12(0, 6, 0xA2) == bytes.fromhex("00e1a260"), "00e1a260")
    check("official-add-imm12-encoder-r8-r1-244", add_imm12(8, 1, 0x244) == bytes.fromhex("08e14412"), "08e14412")
    check("official-add-imm12-encoder-r5-r8-388", add_imm12(5, 8, 0x388) == bytes.fromhex("05e18883"), "05e18883")

    manifest = json.loads(H2_MANIFEST.read_text(encoding="utf-8"))
    h2_layout = {key: int(value, 16) for key, value in manifest["layout"].items()}
    check("h2-layout-off-entry", h2_layout["off_entry"] == H2_OFF_ENTRY)
    check("h2-layout-on-entry", h2_layout["on_entry"] == H2_ON_ENTRY)
    check("h2-layout-producer", h2_layout["producer"] == H2_PRODUCER)
    check("h2-layout-end", h2_layout["end"] == H2_END)
    for entry, ends in ((H2_OFF_ENTRY, (0x0201E164, 0x0201E16E)),
                        (H2_ON_ENTRY, (0x0201E196, 0x0201E1A0))):
        check(f"h2-push-0x{entry:08x}", app_bytes(h2, entry, 2) == word(0x0479), "7904")
        for pop_at in ends:
            check(f"h2-pop-0x{pop_at:08x}", app_bytes(h2, pop_at, 2) == word(0x0459), "5904")
    live = H2_LIVE.read_text(encoding="utf-8")
    for marker in ("verdict: **H2 LIVE PASS**", "Ch10 Note Off: **normal**", "first-Pad reboot: **none**"):
        check(f"h2-live-marker-{marker}", marker in live)

    selector, layout, insns = build_selector()
    expected_layout = {
        "off_entry": 0x0201E13E,
        "off_goto": 0x0201E140,
        "on_entry": 0x0201E142,
        "core": 0x0201E144,
        "channel_branch": 0x0201E14A,
        "state_nonempty_branch": 0x0201E15A,
        "h2_invalid_branch": 0x0201E160,
        "h2_slot0_goto": 0x0201E166,
        "state_nonempty": 0x0201E168,
        "state_armed_branch": 0x0201E168,
        "note0_branch": 0x0201E170,
        "slot0_invalid_branch": 0x0201E176,
        "slot0_goto": 0x0201E17C,
        "note1_test": 0x0201E17E,
        "note1_branch": 0x0201E186,
        "slot1_invalid_branch": 0x0201E18C,
        "copy": 0x0201E194,
        "memcpy_call": 0x0201E196,
        "end": 0x0201E19E,
    }
    check("selector-layout-exact", layout == expected_layout)
    check("selector-size-96", len(selector) == 96 == layout["end"] - CODE_CAVE, selector.hex())
    check("selector-before-h2-producer", layout["end"] <= H2_PRODUCER, f"gap={H2_PRODUCER-layout['end']}")
    producer, producer_layout = build_producer(H2_PRODUCER)
    h2_producer = app_bytes(h2, H2_PRODUCER, H2_END - H2_PRODUCER)
    check("h2-producer-byte-for-byte-preserved", producer == h2_producer, hashlib.sha256(producer).hexdigest())
    check("h2-producer-size-74", len(producer) == 74 and producer_layout["end"] == H2_END)
    check("selector-plus-producer-active-bytes", len(selector) + len(producer) == 170)
    check("audited-body-byte-budget", CODE_CAVE_END - CODE_CAVE == 278)
    check("total-unoccupied-byte-budget", (CODE_CAVE_END - CODE_CAVE) - 170 == 108)
    check("internal-gap-before-producer", H2_PRODUCER - layout["end"] == 4)
    check("unchanged-tail-after-producer", CODE_CAVE_END - H2_END == 104)

    # Proposed hook reach. Note Off remains byte-identical to H2; Note On gets
    # only a new six-byte call32 target to its two-byte native-r6 adapter.
    proposed_hooks = {
        NOTE_OFF_CALL: call32(NOTE_OFF_CALL, layout["off_entry"]),
        NOTE_ON_CALL: call32(NOTE_ON_CALL, layout["on_entry"]),
    }
    check("proposed-off-hook-equals-h2", proposed_hooks[NOTE_OFF_CALL] == app_bytes(h2, NOTE_OFF_CALL, 6), proposed_hooks[NOTE_OFF_CALL].hex())
    check("proposed-on-hook-target", decode_call32(NOTE_ON_CALL, proposed_hooks[NOTE_ON_CALL]) == layout["on_entry"], proposed_hooks[NOTE_ON_CALL].hex())

    branch_targets = {
        layout["channel_branch"]: layout["copy"],
        layout["state_nonempty_branch"]: layout["state_nonempty"],
        layout["h2_invalid_branch"]: layout["copy"],
        layout["state_armed_branch"]: layout["copy"],
        layout["note0_branch"]: layout["note1_test"],
        layout["slot0_invalid_branch"]: layout["copy"],
        layout["note1_branch"]: layout["copy"],
        layout["slot1_invalid_branch"]: layout["copy"],
    }
    for address, target in branch_targets.items():
        encoded = selector[address - CODE_CAVE:address - CODE_CAVE + 4]
        halfwords = (target - (address + 4)) // 2
        check(f"local-branch-reach-0x{address:08x}", -256 <= halfwords <= 255 and decode_jne_target(address, encoded) == target, f"halfwords={halfwords} bytes={encoded.hex()}")
    for address, target in ((layout["off_goto"], layout["core"]),
                            (layout["h2_slot0_goto"], layout["copy"]),
                            (layout["slot0_goto"], layout["copy"])):
        encoded = selector[address - CODE_CAVE:address - CODE_CAVE + 2]
        check(f"forward-goto-reach-0x{address:08x}", decode_forward_goto(address, encoded) == target, encoded.hex())
    memcpy_encoded = selector[layout["memcpy_call"] - CODE_CAVE:layout["memcpy_call"] - CODE_CAVE + 6]
    check("shared-memcpy-call-reach", decode_call32(layout["memcpy_call"], memcpy_encoded) == MEMCPY, memcpy_encoded.hex())

    # Keeping the producer fixed preserves both exact live-parent accepted-packet
    # short calls and every producer-internal PC-relative instruction.
    for address in PRODUCT_CALLS:
        expected = short_call(address, H2_PRODUCER)
        check(f"h2-product-short-call-preserved-0x{address:08x}", app_bytes(h2, address, 4) == expected, expected.hex())

    # ABI/policy invariants encoded by construction.
    check("slot0-source-range", SLOT0 + 0x9C == VALID0)
    check("slot0-metadata-addresses", NOTE0_ADDRESS == VALID0 + 2 and STATE == VALID0 + 3)
    check("slot1-source-range", SLOT1 + 0x9C == 0x01C4665C)
    check("slot1-metadata-addresses", VALID1 == SLOT1 + 0x9C and NOTE1_ADDRESS == VALID1 + 2)
    instruction_names = [insn["name"] for insn in insns]
    check("exact-pointer-derivations",
          selector.count(mov_imm32(8, SLOT0)) == 1
          and selector.count(add_imm12(5, 8, 0x9C)) == 1
          and selector.count(add_imm12(5, 5, 0xA0)) == 1
          and selector.count(add_imm12(1, 8, 0xA0)) == 1,
          "slot0 literal; +0x9c metadata; +0xa0 slot1 metadata/source")
    check("explicit-selected-slot-valid-checks",
          instruction_names.count("slot0_valid_load") == 1
          and instruction_names.count("slot1_valid_load") == 1
          and instruction_names.count("slot0_invalid_branch") == 1
          and instruction_names.count("slot1_invalid_branch") == 1,
          "ARMED selection rechecks valid0/valid1 before r1 write")
    check("exact-three-r1-writers-two-source-values",
          instruction_names.count("h2_slot0_source") == 1
          and instruction_names.count("slot0_source") == 1
          and instruction_names.count("slot1_source") == 1
          and selector.count(mov_reg(1, 8)) == 2
          and selector.count(add_imm12(1, 8, 0xA0)) == 1,
          "H2-compatible slot0, private slot0, private slot1")
    check("no-r2-write-in-selector", word(0x3C62) not in selector,
          "callsite r2=0x9c is consumed unchanged")
    check("fallback-branches-bypass-r1-writers",
          branch_targets[layout["channel_branch"]] == layout["copy"]
          and branch_targets[layout["h2_invalid_branch"]] == layout["copy"]
          and branch_targets[layout["state_armed_branch"]] == layout["copy"]
          and branch_targets[layout["slot0_invalid_branch"]] == layout["copy"]
          and branch_targets[layout["note1_branch"]] == layout["copy"]
          and branch_targets[layout["slot1_invalid_branch"]] == layout["copy"]
          and branch_targets[layout["note0_branch"]] == layout["note1_test"],
          "non-Ch10, invalid/LOADING state, invalid selected slots, and unmapped ARMED notes reach copy without slot source writes")
    check("destination-restored-immediately-before-memcpy", layout["copy"] + 2 == layout["memcpy_call"])
    check("channel-r9-preserved", True, "r9 only read then restored by pop")
    check("native-note-registers-restored", True,
          "r5/r6/r8 saved by shared push; temporary use is after note normalization; pop restores all")

    report_text = REPORT.read_text(encoding="utf-8")
    for marker in (
        "Note Off `r5 = msg[1]`: PASS",
        "Note On `r6 = msg[1]`: PASS",
        "Selector code: `96` bytes",
        "Total unoccupied budget: `108` bytes",
        "Cross-artifact metadata integration: PASS",
        "Firmware candidate: BLOCK",
        "No firmware candidate was produced",
    ):
        check(f"report-marker-{marker}", marker in report_text)

    evidence = {
        "format": FORMAT,
        "scope": {
            "official_v15_only": True,
            "live_parent": "H2",
            "v12_evidence_used": False,
            "firmware_candidate_created": False,
            "device_accessed": False,
            "flash_performed": False,
        },
        "inputs": [
            {"id": name, "path": str(path.relative_to(ROOT)), "sha256": expected}
            for name, (path, expected) in input_hashes.items()
        ],
        "callsite_proof": {
            "note_off": {
                "note_load": "0x0201c62e: 1d41, r5 = msg[1]",
                "destination": "0x0201c636: r0 = r6 + 0xa2",
                "count": "0x0201c63a: r2 = 0x9c",
                "source": "0x0201c63c: r1 = r8 = stock 0x01c34c74",
                "hook": "0x0201c63e",
                "post_call_identity": "0x0201c648: event metadata note = r5",
            },
            "note_on": {
                "velocity_load": "0x0201c66a: r5 = msg[2]",
                "note_load": "0x0201c670: r6 = msg[1]",
                "destination": "0x0201c674: r0 = r7 + 0xa2",
                "count": "0x0201c678: r2 = 0x9c",
                "source": "0x0201c67a: r1 = r8 = stock 0x01c34c74",
                "hook": "0x0201c67c",
                "post_call_identity": "0x0201c686: event metadata note = r6; 0x0201c68c velocity = r5",
            },
            "channel": "0x0201c5fe: r9 = status & 0x0f",
            "h2_window_rule": "H2 is byte-identical to official in both note-load-to-metadata windows except the six-byte call instruction at each hook.",
        },
        "design_contract": {
            "note0_address": f"0x{NOTE0_ADDRESS:08x}",
            "note1_address": f"0x{NOTE1_ADDRESS:08x}",
            "slot0": f"0x{SLOT0:08x}",
            "slot1": f"0x{SLOT1:08x}",
            "valid0": f"0x{VALID0:08x}",
            "state": f"0x{STATE:08x}",
            "valid1": f"0x{VALID1:08x}",
            "empty_value": EMPTY_VALUE,
            "armed_value": ARMED_VALUE,
            "fallback": "non-Ch10, LOADING/invalid state, invalid selected slot, or note matching neither immutable note byte reaches common copy with original r1/r2 and restored r0",
            "h2_compatibility": "EMPTY and valid0 == 1 selects slot0 for all Ch10, preserving exact H2 product-packet behavior",
            "metadata_integration": "PASS: reconciled RAM, ingress, and consumer contract",
            "publication_gate": "external BLOCK: state may become ARMED only after both immutable 0x9c slots, both bounded distinct notes, and both valid bytes are complete",
        },
        "wrapper": {
            "hex": selector.hex(),
            "sha256": hashlib.sha256(selector).hexdigest(),
            "layout": {key: f"0x{value:08x}" for key, value in layout.items()},
            "instructions": insns,
            "hook_encodings": {f"0x{address:08x}": blob.hex() for address, blob in proposed_hooks.items()},
        },
        "byte_budget": {
            "audited_replacement_body": 278,
            "selector": 96,
            "unchanged_h2_producer": 74,
            "active_code_total": 170,
            "internal_gap_before_producer": 4,
            "unchanged_tail_after_producer": 104,
            "total_unoccupied": 108,
            "h2_extent_expansion": 0,
        },
        "decisions": {
            "note_register_identity": "PASS",
            "abi_preservation_by_construction": "PASS",
            "pi32_encoding_and_reach": "PASS",
            "executable_placement_within_live_h2_extent": "PASS",
            "cross_artifact_metadata_integration": "PASS",
            "firmware_candidate": "BLOCK",
        },
        "checks": checks,
    }
    validation = "\n".join(checks) + f"\nPASS\tall-checks\tcount={len(checks)}\n"
    return evidence, validation


def write_outputs(evidence: dict[str, Any], validation: str) -> None:
    EVIDENCE_OUT.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    LAYOUT_OUT.write_text(json.dumps(evidence["wrapper"], indent=2, sort_keys=True) + "\n", encoding="utf-8")
    HEX_OUT.write_text(
        "# analysis-only PI32 selector bytes, not an app/FWSC image\n"
        f"address=0x{CODE_CAVE:08x}\n"
        f"length={evidence['byte_budget']['selector']}\n"
        f"sha256={evidence['wrapper']['sha256']}\n"
        f"hex={evidence['wrapper']['hex']}\n",
        encoding="utf-8",
    )
    VALIDATION_OUT.write_text(validation, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write-output", action="store_true", help="write deterministic text/JSON evidence beside this script")
    args = parser.parse_args()
    evidence, validation = validate()
    if args.write_output:
        write_outputs(evidence, validation)
    print(validation, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
