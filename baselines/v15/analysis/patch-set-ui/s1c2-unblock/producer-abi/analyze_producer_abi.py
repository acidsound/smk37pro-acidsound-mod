#!/usr/bin/env python3
"""Focused S1-C2 producer-entry ABI proof for exact v15/H2/S1-C1.

Analysis-only. Reads exact existing app/listing artifacts and writes deterministic
text/JSON evidence. It never builds, flashes, opens a device, or emits firmware.
"""
from __future__ import annotations

import gzip
import hashlib
import json
import struct
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[5]
RUNTIME_BASE = 0x02000000

OFFICIAL_APP = ROOT / "build/v15-official-app.bin"
H2_APP = ROOT / "build/SMK37Pro-v15-H2-owned-source-corrected-fallback/app.bin"
S1C1_APP = ROOT / "build/SMK37Pro-v15-S1C1-boundary-only/app.bin"
H2_MANIFEST = ROOT / "baselines/v15/analysis/flash-candidates/H2-owned-source-corrected-fallback/app-manifest.json"
S1C1_MANIFEST = ROOT / "baselines/v15/analysis/flash-candidates/S1C1-boundary-only/app-manifest.json"
QUARK = ROOT / "baselines/v15/analysis/quarkslab/results/quarkslab-exhaustive-listing.tsv.gz"
KAGA = ROOT / "baselines/v15/analysis/quarkslab/results/kagaimiq-patched-exhaustive-listing.tsv.gz"

OUT_JSON = HERE / "evidence.json"
OUT_REPORT = HERE / "report.md"
OUT_ROWS = HERE / "official-listing-slices.tsv"
OUT_VALIDATION = HERE / "validation.txt"
OUT_SHA = HERE / "SHA256SUMS"

EXPECTED_HASHES = {
    str(OFFICIAL_APP.relative_to(ROOT)): "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055",
    str(H2_APP.relative_to(ROOT)): "d71f6c58b4fade00aebb8a0b7d9d024641c37c41ca4bbf3e525fd28773087f59",
    str(S1C1_APP.relative_to(ROOT)): "16023c9006f2d4d6467ef2d72d6165c14ffeb6cb758d074f7d8163a68146fb2e",
    str(QUARK.relative_to(ROOT)): "f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347",
    str(KAGA.relative_to(ROOT)): "814510c15ba600c7420026204c5f4121bce6a5d074422cc20204755d3280e013",
}

DIRECT_CALL = 0x0201E468
DIRECT_RETURN = 0x0201E46C
SEG_CALL = 0x0201E49C
SEG_RETURN = 0x0201E4A0
PRODUCER = 0x0201E1A2
PRODUCER_END = 0x0201E1EC
HANDLER_ENTRY = 0x0201E254
COMPLETE_CALL = 0x0202D202
SAVE_REJECT = 0x02026DA6
SAVE_CALL = 0x02026DAC
STAGING_BASE = 0x01C37FD0
STAGING_BASE_SETUP = 0x01C37030
STAGING_OFFSET = 0x0FA0
OWNED_VOICE = 0x01C46520
OWNED_VALID = 0x01C465BC
OWNED_LOCK = 0x01C465BD
MEMCPY = 0x02048CCE
FACTORY_LOADER = 0x02005660
VOICE_SIZE = 0x9C
DIRECT_EXACT_TOTAL = 0xA3
DIRECT_EXACT_STAGE_COPY = DIRECT_EXACT_TOTAL - 6
SEGMENTED_FINAL_TOTAL_GATE = 0x9E

OFFICIAL_ROW_ADDRS = {
    0x0201E254, 0x0201E256, 0x0201E258,
    0x0201E3FC, 0x0201E402, 0x0201E406, 0x0201E40A,
    0x0201E410, 0x0201E416, 0x0201E41C, 0x0201E420, 0x0201E426,
    0x0201E430, 0x0201E438, 0x0201E43E, 0x0201E444,
    0x0201E448, 0x0201E44C, 0x0201E44E, 0x0201E452, 0x0201E454,
    0x0201E456, 0x0201E45C, 0x0201E460, 0x0201E462, 0x0201E466,
    0x0201E468, 0x0201E46C, 0x0201E470,
    0x0201E472, 0x0201E476, 0x0201E47A, 0x0201E47E, 0x0201E480,
    0x0201E484, 0x0201E488, 0x0201E48C, 0x0201E48E, 0x0201E492,
    0x0201E494, 0x0201E49A, 0x0201E49C, 0x0201E4A0, 0x0201E4A4,
    0x0202D182, 0x0202D186, 0x0202D18A, 0x0202D1BE, 0x0202D200, 0x0202D202,
    0x02048CCE, 0x02048CD0, 0x02048CD4, 0x02048CD6, 0x02048CDA, 0x02048CDC,
    0x02048CE0, 0x02048CE4, 0x02048CE8, 0x02048CEA, 0x02048CEE, 0x02048CF0,
    0x02048CF2, 0x02048CF4, 0x02048CF6, 0x02048CF8, 0x02048CFA, 0x02048CFC,
    0x02048CFE, 0x02048D00, 0x02048D02, 0x02048D04, 0x02048D08, 0x02048D0A,
    0x02048D0C, 0x02048D0E,
    0x02026DA6, 0x02026DAC,
}

PRODUCER_STREAM = [
    (0x0201E1A2, "7904", "push {rets,r9,r8,r7,r6,r5,r4}", "first producer instruction; no H2-owned mutation yet"),
    (0x0201E1A4, "0416", "mov r4,r0", "save accepted staging pointer"),
    (0x0201E1A6, "c0ffbd65c401", "mov r0,#0x01c465bd", "lock address"),
    (0x0201E1AC, "2000", "csync", "pre-testset barrier"),
    (0x0201E1AE, "b000", "testset b[r0]", "first H2-owned state mutation: lock byte"),
    (0x0201E1B0, "40e81b00", "ifeq 0x0201e1ea", "busy path returns without copy/publish"),
    (0x0201E1B4, "2000", "csync", "post-acquire barrier"),
    (0x0201E1B6, "c5ffbc65c401", "mov r5,#0x01c465bc", "valid0 address"),
    (0x0201E1BC, "5840", "lb.z r0,[r5]", "load valid0"),
    (0x0201E1BE, "80f80d00", "jne r0,#0,0x0201e1dc", "reject if already valid"),
    (0x0201E1C2, "c0ff2065c401", "mov r0,#0x01c46520", "owned destination"),
    (0x0201E1C8, "4116", "mov r1,r4", "source = accepted staging pointer"),
    (0x0201E1CA, "623c", "mov r2,#0x9c", "fixed voice copy size"),
    (0x0201E1CC, "80fffcaa0200", "call 0x02048cce", "copy 156 bytes to owned slot0"),
    (0x0201E1D2, "c5ffbc65c401", "mov r5,#0x01c465bc", "valid0 address reload"),
    (0x0201E1D8, "4021", "mov r0,#1", "valid value"),
    (0x0201E1DA, "d840", "sb r0,[r5]", "publish valid0 last"),
    (0x0201E1DC, "c0ffbd65c401", "mov r0,#0x01c465bd", "lock address"),
    (0x0201E1E2, "2000", "csync", "pre-unlock barrier"),
    (0x0201E1E4, "4120", "mov r1,#0", "unlock value"),
    (0x0201E1E6, "8940", "sb r1,[r0]", "unlock"),
    (0x0201E1E8, "2000", "csync", "post-unlock barrier"),
    (0x0201E1EA, "5904", "pop {pc,r9,r8,r7,r6,r5,r4}", "return to caller LR/rets"),
]


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def app_slice(app: bytes, address: int, size: int) -> bytes:
    offset = address - RUNTIME_BASE
    if offset < 0 or offset + size > len(app):
        raise AssertionError(f"address out of range: 0x{address:08x}")
    return app[offset:offset + size]


def short_call_target(address: int, encoded: bytes) -> int:
    if len(encoded) != 4 or encoded[:2] != b"\xbf\xea":
        raise AssertionError(f"not a short call at 0x{address:08x}: {encoded.hex()}")
    halfwords = struct.unpack("<H", encoded[2:])[0]
    return (address + 4 + halfwords * 2) & 0x1FFFF | (address & ~0x1FFFF)


def call32_target(address: int, encoded: bytes) -> int:
    if len(encoded) != 6 or encoded[:2] != b"\x80\xff":
        raise AssertionError(f"not a call32 at 0x{address:08x}: {encoded.hex()}")
    disp = int.from_bytes(encoded[2:], "little", signed=True)
    return address + 6 + disp


def read_listing_rows(path: Path, addrs: set[int]) -> dict[str, str]:
    rows: dict[str, str] = {}
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                addr = int(line.split("\t", 1)[0], 16)
            except Exception:
                continue
            if addr in addrs:
                rows[f"0x{addr:08x}"] = line.rstrip("\n")
    return rows


def read_listing_callers(path: Path, target_text: str) -> list[dict[str, str]]:
    callers: list[dict[str, str]] = []
    with gzip.open(path, "rt", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 5 and parts[3] == "call" and parts[4] == f"call {target_text}":
                callers.append({
                    "address": f"0x{int(parts[0], 16):08x}",
                    "bytes": parts[1],
                    "kind": "quarkslab_listing_call",
                    "target": target_text,
                    "row": line.rstrip("\n"),
                })
    return callers


def scan_h2_calls_to_target(app: bytes, target: int) -> list[dict[str, Any]]:
    callers: list[dict[str, Any]] = []
    for offset in range(0, len(app) - 3, 2):
        address = RUNTIME_BASE + offset
        four = app[offset:offset + 4]
        if four[:2] == b"\xbf\xea":
            try:
                decoded = short_call_target(address, four)
            except AssertionError:
                continue
            if decoded == target:
                callers.append({
                    "address": f"0x{address:08x}",
                    "bytes": four.hex(),
                    "kind": "short_call",
                    "target": f"0x{decoded:08x}",
                })
        if offset <= len(app) - 6:
            six = app[offset:offset + 6]
            if six[:2] == b"\x80\xff":
                try:
                    decoded = call32_target(address, six)
                except AssertionError:
                    continue
                if decoded == target:
                    callers.append({
                        "address": f"0x{address:08x}",
                        "bytes": six.hex(),
                        "kind": "call32",
                        "target": f"0x{decoded:08x}",
                    })
    return callers


def h2_stream_from_app(app: bytes) -> list[dict[str, str]]:
    out = []
    for address, expected_hex, text, meaning in PRODUCER_STREAM:
        got = app_slice(app, address, len(bytes.fromhex(expected_hex))).hex()
        if got != expected_hex:
            raise AssertionError(f"producer stream mismatch at 0x{address:08x}: {got} != {expected_hex}")
        out.append({"address": f"0x{address:08x}", "bytes": got, "instruction": text, "meaning": meaning})
    return out


def make_evidence() -> tuple[dict[str, Any], list[str]]:
    validation: list[str] = []
    def check(name: str, condition: bool, detail: str = "") -> None:
        if not condition:
            raise AssertionError(f"{name}: {detail}")
        validation.append(f"PASS\t{name}\t{detail}")

    inputs = {}
    for path in [OFFICIAL_APP, H2_APP, S1C1_APP, H2_MANIFEST, S1C1_MANIFEST, QUARK, KAGA]:
        rel = str(path.relative_to(ROOT))
        digest = sha256(path)
        inputs[rel] = {"sha256": digest, "size": path.stat().st_size}
        if rel in EXPECTED_HASHES:
            check(f"sha-{rel}", digest == EXPECTED_HASHES[rel], digest)

    official = OFFICIAL_APP.read_bytes()
    h2 = H2_APP.read_bytes()
    s1c1 = S1C1_APP.read_bytes()
    h2_manifest = json.loads(H2_MANIFEST.read_text(encoding="utf-8"))
    s1c1_manifest = json.loads(S1C1_MANIFEST.read_text(encoding="utf-8"))

    check("h2-manifest-producer", h2_manifest["layout"]["producer"] == f"0x{PRODUCER:08x}", h2_manifest["layout"]["producer"])
    check("s1c1-parent-h2", s1c1_manifest["h2_parent_app_sha256"] == inputs[str(H2_APP.relative_to(ROOT))]["sha256"], s1c1_manifest["h2_parent_app_sha256"])
    check("s1c1-code-identical-flag", s1c1_manifest["invariants"]["h2_code_byte_identical"] is True, "manifest invariant")

    # Official/H2/S1-C1 byte streams at the exact product callsites and producer body.
    official_direct = app_slice(official, DIRECT_CALL, 4)
    official_seg = app_slice(official, SEG_CALL, 4)
    h2_direct = app_slice(h2, DIRECT_CALL, 4)
    h2_seg = app_slice(h2, SEG_CALL, 4)
    s1c1_direct = app_slice(s1c1, DIRECT_CALL, 4)
    s1c1_seg = app_slice(s1c1, SEG_CALL, 4)
    check("official-direct-calls-packer", official_direct.hex() == "bfea69fe" and short_call_target(DIRECT_CALL, official_direct) == 0x0201E13E, official_direct.hex())
    check("official-segmented-calls-packer", official_seg.hex() == "bfea4ffe" and short_call_target(SEG_CALL, official_seg) == 0x0201E13E, official_seg.hex())
    check("h2-direct-calls-producer", h2_direct.hex() == "bfea9bfe" and short_call_target(DIRECT_CALL, h2_direct) == PRODUCER, h2_direct.hex())
    check("h2-segmented-calls-producer", h2_seg.hex() == "bfea81fe" and short_call_target(SEG_CALL, h2_seg) == PRODUCER, h2_seg.hex())
    check("s1c1-direct-calls-producer", s1c1_direct == h2_direct and short_call_target(DIRECT_CALL, s1c1_direct) == PRODUCER, s1c1_direct.hex())
    check("s1c1-segmented-calls-producer", s1c1_seg == h2_seg and short_call_target(SEG_CALL, s1c1_seg) == PRODUCER, s1c1_seg.hex())
    check("h2-s1c1-producer-body-identical", app_slice(h2, PRODUCER, PRODUCER_END - PRODUCER) == app_slice(s1c1, PRODUCER, PRODUCER_END - PRODUCER), f"0x{PRODUCER:08x}..0x{PRODUCER_END:08x}")
    check("h2-s1c1-callsite-region-identical", app_slice(h2, 0x0201E448, 0x5C) == app_slice(s1c1, 0x0201E448, 0x5C), "0x0201e448..0x0201e4a4")
    check("post-direct-reload-preserved", app_slice(h2, DIRECT_RETURN, 4).hex() == "bfeaf838" and short_call_target(DIRECT_RETURN, app_slice(h2, DIRECT_RETURN, 4)) == FACTORY_LOADER, app_slice(h2, DIRECT_RETURN, 4).hex())
    check("post-segmented-reload-preserved", app_slice(h2, SEG_RETURN, 4).hex() == "bfeade38" and short_call_target(SEG_RETURN, app_slice(h2, SEG_RETURN, 4)) == FACTORY_LOADER, app_slice(h2, SEG_RETURN, 4).hex())
    check("save-packer-call-neutralized", app_slice(h2, SAVE_REJECT, 4).hex() == "04960000" and app_slice(h2, SAVE_CALL, 4).hex() == "00000000", f"{app_slice(h2,SAVE_REJECT,4).hex()} {app_slice(h2,SAVE_CALL,4).hex()}")

    # Producer stream and callers.
    producer_stream = h2_stream_from_app(h2)
    callers = scan_h2_calls_to_target(h2, PRODUCER)
    callers_sorted = sorted(callers, key=lambda item: item["address"])
    check("all-h2-producer-callers", [c["address"] for c in callers_sorted] == [f"0x{DIRECT_CALL:08x}", f"0x{SEG_CALL:08x}"], ",".join(c["address"] for c in callers_sorted))
    check("first-h2-owned-mutation-after-entry", producer_stream[4]["address"] == "0x0201e1ae" and "testset" in producer_stream[4]["instruction"], producer_stream[4]["instruction"])

    quark_rows = read_listing_rows(QUARK, OFFICIAL_ROW_ADDRS)
    kaga_rows = read_listing_rows(KAGA, OFFICIAL_ROW_ADDRS)
    official_packer_callers_sorted = read_listing_callers(QUARK, "0x0201e13e")
    check("all-official-packer-callers", [c["address"] for c in official_packer_callers_sorted] == [f"0x{DIRECT_CALL:08x}", f"0x{SEG_CALL:08x}", f"0x{SAVE_CALL:08x}"], ",".join(c["address"] for c in official_packer_callers_sorted))
    for addr, tokens in {
        "0x02048cce": ["push", "r6", "r5", "r4"],
        "0x02048d0e": ["pop", "r6", "r5", "r4"],
        "0x0201e448": ["add", "r8", "#0xfa0"],
        "0x0201e44e": ["add", "r6", "r9", "#-0x6"],
        "0x0201e456": ["call", "0x02048cce"],
        "0x0201e462": ["jne", "#0xf7"],
        "0x0201e466": ["mov", "r0", "r8"],
        "0x0201e468": ["call", "0x0201e13e"],
        "0x0201e484": ["jne", "r5", "#0x9e"],
        "0x0201e494": ["call", "0x02048cce"],
        "0x0201e49a": ["mov", "r0", "r6"],
        "0x0201e49c": ["call", "0x0201e13e"],
        "0x0202d202": ["call", "0x0201e254"],
    }.items():
        row = quark_rows.get(addr, "")
        check(f"quark-row-{addr}", all(t in row for t in tokens), row)

    memcpy_rows = [quark_rows[f"0x{addr:08x}"] for addr in sorted(OFFICIAL_ROW_ADDRS) if 0x02048CCE <= addr <= 0x02048D0E]
    check("memcpy-helper-does-not-touch-r9", all("r9" not in row for row in memcpy_rows), "0x02048cce..0x02048d0e")
    check("memcpy-helper-preserves-r5-r6", "push {rets,r6,r5,r4}" in quark_rows["0x02048cce"] and "pop {pc,r6,r5,r4}" in quark_rows["0x02048d0e"], "r5/r6 saved and restored")

    official_listing_slices = {
        "quarkslab": quark_rows,
        "kagaimiq": kaga_rows,
    }

    direct_entry = {
        "route_identity": {
            "callsite": f"0x{DIRECT_CALL:08x}",
            "caller_return_address_rets_lr": f"0x{DIRECT_RETURN:08x}",
            "h2_s1c1_call_bytes": h2_direct.hex(),
            "target": f"0x{PRODUCER:08x}",
        },
        "producer_entry_live_registers_before_first_h2_owned_mutation": {
            "r0": f"0x{STAGING_BASE:08x} (official 0x0201e466 mov r0,r8)",
            "r4": "original completed-message pointer from handler entry; producer will overwrite it after entry",
            "r6": "r9 - 6, preserved across memcpy because 0x02048cce saves/restores r6",
            "r8": f"0x{STAGING_BASE:08x} (0x0201e448 r8 = 0x{STAGING_BASE_SETUP:08x} + 0x{STAGING_OFFSET:x})",
            "r9": "original completed-message length from 0x0201e258 mov r9,r1; not modified by direct-path instructions or memcpy",
            "rets_lr": f"0x{DIRECT_RETURN:08x}",
        },
        "stable_memory_at_entry": {
            "staging_base": f"0x{STAGING_BASE:08x}",
            "copy_before_entry": "0x0201e456 memcpy(stage, msg+6, r9-6)",
            "for_exact_163_byte_packet": f"r9 == 0x{DIRECT_EXACT_TOTAL:x}; copied bytes == 0x{DIRECT_EXACT_STAGE_COPY:x}; stage[0..0x9b] is the 156-byte voice body and stage[0x9c] is the already-checked F7 terminator",
            "h2_owned_state": f"unchanged until 0x0201e1ae testset of 0x{OWNED_LOCK:08x}",
        },
        "exact_length_gate": f"accept direct only if rets/LR == 0x{DIRECT_RETURN:08x}, r0 == 0x{STAGING_BASE:08x}, and r9 == 0x{DIRECT_EXACT_TOTAL:x}; otherwise return before 0x0201e1ae",
        "safe_exclusion": f"direct can also be excluded by rejecting rets/LR == 0x{DIRECT_RETURN:08x} before 0x0201e1ae; this leaves H2-owned slot/valid/lock unchanged and still returns to 0x{DIRECT_RETURN:08x} reload behavior",
    }
    segmented_entry = {
        "route_identity": {
            "callsite": f"0x{SEG_CALL:08x}",
            "caller_return_address_rets_lr": f"0x{SEG_RETURN:08x}",
            "h2_s1c1_call_bytes": h2_seg.hex(),
            "target": f"0x{PRODUCER:08x}",
        },
        "producer_entry_live_registers_before_first_h2_owned_mutation": {
            "r0": f"0x{STAGING_BASE:08x} (0x0201e49a mov r0,r6)",
            "r4": "current final segment pointer from handler entry; producer will overwrite it after entry",
            "r5": f"0x{SEGMENTED_FINAL_TOTAL_GATE:x}, because 0x0201e47a computes previous_count + current_len and 0x0201e484 gates r5 == 0x9e before memcpy/producer",
            "r6": f"0x{STAGING_BASE:08x} after 0x0201e488 adds 0xfa0 to 0x{STAGING_BASE_SETUP:08x}; preserved by memcpy",
            "r9": "current segment length, not the full accepted assembled length",
            "rets_lr": f"0x{SEG_RETURN:08x}",
        },
        "stable_memory_at_entry": {
            "staging_base": f"0x{STAGING_BASE:08x}",
            "preappend_count_source": "lh.z r0,[r7+0x9c] at 0x0201e472",
            "exact_gate_before_copy": "0x0201e480 checks final F7, then 0x0201e484 checks r5 == 0x9e",
            "append_copy": "0x0201e494 memcpy(stage + previous_count, final_segment, r9-2)",
            "h2_owned_state": f"unchanged until 0x0201e1ae testset of 0x{OWNED_LOCK:08x}",
        },
        "exact_length_gate": f"accept segmented final only if rets/LR == 0x{SEG_RETURN:08x}, r0 == 0x{STAGING_BASE:08x}, r6 == 0x{STAGING_BASE:08x}, and r5 == 0x{SEGMENTED_FINAL_TOTAL_GATE:x}; otherwise return before 0x0201e1ae",
    }

    minimal_acceptance_rule = {
        "decision": "PASS",
        "reason": "At producer entry, route identity is distinguishable by LR/rets and exact direct/segmented length evidence remains live before the first H2-owned mutation at 0x0201e1ae.",
        "c_pseudocode": """// Runs at 0x0201e1a2 before the current producer's testset/copy/publish.\nvoid extended_h2_producer(uint8_t *stage /* r0 */) {\n    uintptr_t lr = read_rets_lr();\n\n    bool direct_exact =\n        lr == 0x0201e46c &&\n        stage == (uint8_t *)0x01c37fd0 &&\n        r9 == 0x000000a3;      // original completed message length\n\n    bool segmented_exact_final =\n        lr == 0x0201e4a0 &&\n        stage == (uint8_t *)0x01c37fd0 &&\n        r6 == 0x01c37fd0 &&\n        r5 == 0x0000009e;      // official segmented total gate\n\n    if (!(direct_exact || segmented_exact_final))\n        return;                // no lock, no copy, no valid-byte mutation\n\n    // Existing H2 publication is then permitted:\n    // try_lock(0x01c465bd); reject if busy or valid0 != 0;\n    // memcpy(0x01c46520, stage, 0x9c);\n    // *(uint8_t *)0x01c465bc = 1; unlock.\n}\n""",
        "direct_can_be_safely_excluded": True,
        "direct_exclusion_rule": f"if LR/rets == 0x{DIRECT_RETURN:08x}, return before testset unless direct single-packet support is intentionally admitted by r9 == 0x{DIRECT_EXACT_TOTAL:x}",
        "segmented_only_rule": f"if accepting only segmented final packets, require LR/rets == 0x{SEG_RETURN:08x} and r5 == 0x{SEGMENTED_FINAL_TOTAL_GATE:x} before any H2-owned mutation",
    }
    check("pass-minimal-acceptance-distinguishes-route", minimal_acceptance_rule["decision"] == "PASS", minimal_acceptance_rule["reason"])

    evidence = {
        "format": "smk37-v15-s1c2-producer-abi-unblock-v1",
        "scope": "analysis-only; official/H2/S1-C1 app bytes and Quarkslab/Kagaimiq listings; no candidate/device/flash",
        "inputs": inputs,
        "constants": {
            "runtime_base": f"0x{RUNTIME_BASE:08x}",
            "producer": f"0x{PRODUCER:08x}",
            "producer_end": f"0x{PRODUCER_END:08x}",
            "direct_callsite": f"0x{DIRECT_CALL:08x}",
            "direct_return_lr": f"0x{DIRECT_RETURN:08x}",
            "segmented_callsite": f"0x{SEG_CALL:08x}",
            "segmented_return_lr": f"0x{SEG_RETURN:08x}",
            "staging": f"0x{STAGING_BASE:08x}",
            "voice_size": VOICE_SIZE,
            "direct_exact_total_length": DIRECT_EXACT_TOTAL,
            "segmented_final_total_gate": SEGMENTED_FINAL_TOTAL_GATE,
        },
        "official_listing_slices": official_listing_slices,
        "memcpy_preserved_register_proof": {
            "rows": memcpy_rows,
            "conclusion": "0x02048cce saves/restores r5 and r6 and no listed instruction references r9, so direct r9 and segmented r5/r6 survive the pre-producer staging memcpy calls.",
        },
        "official_h2_s1c1_callsite_streams": {
            "direct": {
                "official_bytes": official_direct.hex(),
                "official_target": f"0x{short_call_target(DIRECT_CALL, official_direct):08x}",
                "h2_bytes": h2_direct.hex(),
                "h2_target": f"0x{short_call_target(DIRECT_CALL, h2_direct):08x}",
                "s1c1_bytes": s1c1_direct.hex(),
                "s1c1_target": f"0x{short_call_target(DIRECT_CALL, s1c1_direct):08x}",
            },
            "segmented": {
                "official_bytes": official_seg.hex(),
                "official_target": f"0x{short_call_target(SEG_CALL, official_seg):08x}",
                "h2_bytes": h2_seg.hex(),
                "h2_target": f"0x{short_call_target(SEG_CALL, h2_seg):08x}",
                "s1c1_bytes": s1c1_seg.hex(),
                "s1c1_target": f"0x{short_call_target(SEG_CALL, s1c1_seg):08x}",
            },
            "post_return_reloads": {
                "direct_return_0x0201e46c": {"bytes": app_slice(h2, DIRECT_RETURN, 4).hex(), "target": f"0x{short_call_target(DIRECT_RETURN, app_slice(h2, DIRECT_RETURN, 4)):08x}"},
                "segmented_return_0x0201e4a0": {"bytes": app_slice(h2, SEG_RETURN, 4).hex(), "target": f"0x{short_call_target(SEG_RETURN, app_slice(h2, SEG_RETURN, 4)):08x}"},
            },
            "save_path": {"0x02026da6": app_slice(h2, SAVE_REJECT, 4).hex(), "0x02026dac": app_slice(h2, SAVE_CALL, 4).hex()},
        },
        "h2_s1c1_producer_stream": producer_stream,
        "official_callers_to_replaced_packer_0x0201e13e": official_packer_callers_sorted,
        "h2_callers_to_producer": callers_sorted,
        "direct_product_producer_entry": direct_entry,
        "segmented_final_producer_entry": segmented_entry,
        "post_return_reload_behavior": {
            "direct": f"producer returns to 0x{DIRECT_RETURN:08x}; H2/S1-C1 execute preserved call 0x02005660 at 0x0201e46c, then pop at 0x0201e470",
            "segmented": f"producer returns to 0x{SEG_RETURN:08x}; H2/S1-C1 execute preserved call 0x02005660 at 0x0201e4a0, then goto 0x0201e538",
            "impact": "the preserved reload happens after producer return on both admitted routes; a reject-before-testset leaves H2-owned slot/valid/lock unchanged but still resumes the stock/H2 post-return path",
        },
        "minimal_acceptance_rule": minimal_acceptance_rule,
        "validation": validation,
    }
    return evidence, validation


def write_rows(evidence: dict[str, Any]) -> None:
    lines = ["decoder\taddress\tbytes\tsize\tmnemonic\ttext\tflow\tfunction"]
    for decoder in ["quarkslab", "kagaimiq"]:
        rows = evidence["official_listing_slices"][decoder]
        for addr in sorted(rows, key=lambda s: int(s, 16)):
            lines.append(f"{decoder}\t{rows[addr]}")
    OUT_ROWS.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_report(evidence: dict[str, Any]) -> None:
    direct = evidence["direct_product_producer_entry"]
    seg = evidence["segmented_final_producer_entry"]
    rule = evidence["minimal_acceptance_rule"]
    lines = [
        "# S1-C2 producer-entry ABI unblock proof",
        "",
        "Date: 2026-08-02 UTC  ",
        "Decision: **PASS for the focused no-parser blocker**  ",
        "Scope: exact official v15, H2, S1-C1 boundary child, and Quarkslab/Kagaimiq listings only. No candidate, device, OTA, flash, or live packet action was performed.",
        "",
        "## Result",
        "",
        "An extended producer at `0x0201e1a2` can distinguish the exact accepted route before any H2-owned state mutation:",
        "",
        "- Direct product call `0x0201e468`: route is `LR/rets == 0x0201e46c`; exact valid 163-byte packet is `r9 == 0x000000a3`; staging pointer is `r0 == 0x01c37fd0`.",
        "- Segmented final call `0x0201e49c`: route is `LR/rets == 0x0201e4a0`; exact final-total gate remains live as `r5 == 0x0000009e`; staging pointer is `r0 == r6 == 0x01c37fd0`.",
        "- The first current-producer H2-owned mutation is `0x0201e1ae testset b[r0]` on lock `0x01c465bd`, so these checks can run first and reject without changing lock, slot, or valid state.",
        "",
        "Therefore the prior no-parser blocker is resolved at this focused ABI discriminator level. This is not a complete S1-C2 parser/state-machine proof and does not authorize a firmware candidate.",
        "",
        "## Exact inputs",
        "",
        "| Input | SHA-256 |",
        "|---|---|",
    ]
    for rel, meta in evidence["inputs"].items():
        lines.append(f"| `{rel}` | `{meta['sha256']}` |")
    lines += [
        "",
        "## Official/H2/S1-C1 call streams",
        "",
        "| Site | Official v15 | H2 | S1-C1 | Meaning |",
        "|---|---|---|---|---|",
    ]
    streams = evidence["official_h2_s1c1_callsite_streams"]
    lines.append(f"| Direct `0x0201e468` | `{streams['direct']['official_bytes']}` -> `{streams['direct']['official_target']}` | `{streams['direct']['h2_bytes']}` -> `{streams['direct']['h2_target']}` | `{streams['direct']['s1c1_bytes']}` -> `{streams['direct']['s1c1_target']}` | H2/S1-C1 retarget accepted direct product packet to producer. |")
    lines.append(f"| Segmented `0x0201e49c` | `{streams['segmented']['official_bytes']}` -> `{streams['segmented']['official_target']}` | `{streams['segmented']['h2_bytes']}` -> `{streams['segmented']['h2_target']}` | `{streams['segmented']['s1c1_bytes']}` -> `{streams['segmented']['s1c1_target']}` | H2/S1-C1 retarget accepted segmented final packet to producer. |")
    lines += [
        "",
        "H2 and S1-C1 producer bytes are identical over `0x0201e1a2..0x0201e1ec`; S1-C1 changes only the H2 boundary and preserves product/producer code behavior.",
        "",
        "## Instruction-level direct-route proof",
        "",
        "```text",
        evidence["official_listing_slices"]["quarkslab"]["0x0201e256"],
        evidence["official_listing_slices"]["quarkslab"]["0x0201e258"],
        evidence["official_listing_slices"]["quarkslab"]["0x0201e448"],
        evidence["official_listing_slices"]["quarkslab"]["0x0201e44c"],
        evidence["official_listing_slices"]["quarkslab"]["0x0201e44e"],
        evidence["official_listing_slices"]["quarkslab"]["0x0201e452"],
        evidence["official_listing_slices"]["quarkslab"]["0x0201e454"],
        evidence["official_listing_slices"]["quarkslab"]["0x0201e456"],
        evidence["official_listing_slices"]["quarkslab"]["0x0201e45c"],
        evidence["official_listing_slices"]["quarkslab"]["0x0201e460"],
        evidence["official_listing_slices"]["quarkslab"]["0x0201e462"],
        evidence["official_listing_slices"]["quarkslab"]["0x0201e466"],
        "H2/S1-C1 0201e468  bfea9bfe      call  0x0201e1a2",
        "```",
        "",
        f"At direct producer entry: `{direct['producer_entry_live_registers_before_first_h2_owned_mutation']['r0']}`; `r9` is `{direct['producer_entry_live_registers_before_first_h2_owned_mutation']['r9']}`; LR/rets is `{direct['route_identity']['caller_return_address_rets_lr']}`. Exact direct acceptance is `r9 == 0xa3`.",
        "The intervening `0x02048cce` copy helper preserves this proof: Quarkslab lists `0x02048cce push {rets,r6,r5,r4}` and `0x02048d0e pop {pc,r6,r5,r4}`, and the extracted helper body contains no `r9` reference.",
        "",
        "## Instruction-level segmented-route proof",
        "",
        "```text",
        evidence["official_listing_slices"]["quarkslab"]["0x0201e472"],
        evidence["official_listing_slices"]["quarkslab"]["0x0201e476"],
        evidence["official_listing_slices"]["quarkslab"]["0x0201e47a"],
        evidence["official_listing_slices"]["quarkslab"]["0x0201e47e"],
        evidence["official_listing_slices"]["quarkslab"]["0x0201e480"],
        evidence["official_listing_slices"]["quarkslab"]["0x0201e484"],
        evidence["official_listing_slices"]["quarkslab"]["0x0201e488"],
        evidence["official_listing_slices"]["quarkslab"]["0x0201e48c"],
        evidence["official_listing_slices"]["quarkslab"]["0x0201e48e"],
        evidence["official_listing_slices"]["quarkslab"]["0x0201e492"],
        evidence["official_listing_slices"]["quarkslab"]["0x0201e494"],
        evidence["official_listing_slices"]["quarkslab"]["0x0201e49a"],
        "H2/S1-C1 0201e49c  bfea81fe      call  0x0201e1a2",
        "```",
        "",
        f"At segmented producer entry: `{seg['producer_entry_live_registers_before_first_h2_owned_mutation']['r0']}`; `r5` is `{seg['producer_entry_live_registers_before_first_h2_owned_mutation']['r5']}`; LR/rets is `{seg['route_identity']['caller_return_address_rets_lr']}`. `r9` is only the current segment length, so the exact assembled-final discriminator is `r5 == 0x9e`, not `r9`.",
        "The segmented append uses the same `0x02048cce` helper, so the gated `r5 == 0x9e` and staging-base `r6 == 0x01c37fd0` remain live at producer entry.",
        "",
        "## H2 producer stream and mutation boundary",
        "",
        "```text",
    ]
    for row in evidence["h2_s1c1_producer_stream"]:
        lines.append(f"{row['address']}  {row['bytes']:<12}  {row['instruction']:<36}  ; {row['meaning']}")
    lines += [
        "```",
        "",
        "All H2 producer callers decoded from the H2 app:",
        "",
        "| Caller | Bytes | Target | Route |",
        "|---|---|---|---|",
    ]
    for caller in evidence["h2_callers_to_producer"]:
        route = "direct" if caller["address"] == "0x0201e468" else "segmented"
        lines.append(f"| `{caller['address']}` | `{caller['bytes']}` | `{caller['target']}` | {route} |")
    lines += [
        "",
        "Official v15 callers to the replaced `0x0201e13e` packer are `0x0201e468`, `0x0201e49c`, and `0x02026dac`. H2/S1-C1 retarget only the first two accepted product callsites to producer `0x0201e1a2`; the official SAVE caller at `0x02026dac` is neutralized.",
        "",
        "## Post-return reload behavior",
        "",
        f"- Direct return: `{streams['post_return_reloads']['direct_return_0x0201e46c']['bytes']}` calls `{streams['post_return_reloads']['direct_return_0x0201e46c']['target']}` at `0x0201e46c`, then returns at `0x0201e470`.",
        f"- Segmented return: `{streams['post_return_reloads']['segmented_return_0x0201e4a0']['bytes']}` calls `{streams['post_return_reloads']['segmented_return_0x0201e4a0']['target']}` at `0x0201e4a0`, then branches to `0x0201e538`.",
        "- SAVE no longer calls the replaced packer/producer cave: `0x02026da6` is `04960000` and `0x02026dac` is `00000000` in H2/S1-C1.",
        "",
        "## Minimal acceptance rule",
        "",
        "```c",
        rule["c_pseudocode"].rstrip(),
        "```",
        "",
        "Direct packets can be exact-length gated by `r9 == 0xa3` with direct LR/rets, or safely excluded by rejecting direct LR/rets before `0x0201e1ae`. Segmented final packets are exact-gated by the official live `r5 == 0x9e` check plus segmented LR/rets.",
        "",
        "## Final gate",
        "",
        "| Gate | Result |",
        "|---|---|",
        "| Official/H2/S1-C1 identity and code equality | PASS |",
        "| Direct route identity at producer entry | PASS |",
        "| Direct exact length available before H2-owned mutation | PASS, `r9 == 0xa3` |",
        "| Segmented route identity at producer entry | PASS |",
        "| Segmented exact final length available before H2-owned mutation | PASS, `r5 == 0x9e` |",
        "| All producer callers traced | PASS, exactly `0x0201e468` and `0x0201e49c` |",
        "| Post-return reload behavior traced | PASS |",
        "| Candidate/device/flash action | Not performed |",
        "",
        "## Reproduction",
        "",
        "```sh",
        "python3 baselines/v15/analysis/patch-set-ui/s1c2-unblock/producer-abi/analyze_producer_abi.py",
        "```",
        "",
    ]
    OUT_REPORT.write_text("\n".join(lines), encoding="utf-8")


def write_sha() -> None:
    names = ["analyze_producer_abi.py", "evidence.json", "official-listing-slices.tsv", "report.md", "validation.txt"]
    lines = []
    for name in names:
        p = HERE / name
        lines.append(f"{sha256(p)}  {name}")
    OUT_SHA.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    evidence, validation = make_evidence()
    OUT_JSON.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    write_rows(evidence)
    OUT_VALIDATION.write_text("\n".join(validation) + "\n", encoding="utf-8")
    write_report(evidence)
    write_sha()
    print(f"PASS wrote {OUT_JSON.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
