#!/usr/bin/env python3
"""Independent offline verification for exact S1-C2 live-v2 commit artifacts.

This script reads local files only. It never opens USB, MIDI, OTA, flash, or device
interfaces. Pass --root to review an isolated git archive rather than the live tree.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import struct
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
CANDIDATE_REL = Path("baselines/v15/analysis/flash-candidates/S1C2-two-slot-selector-live-v2")
PACKAGE = "SMK37Pro-v15-S1C2-two-slot-selector-live-v2.fwsc"
BASE = 0x02000000
SELECTOR_START, SELECTOR_END = 0x0201E13E, 0x0201E19E
PRODUCER_START, PRODUCER_END = 0x0201E1A2, 0x0201E236
SEGMENTED_STUB = 0x0201E232
OFFICIAL_HANDLER = 0x0201E254
DIRECT_PRODUCT_CALL, DIRECT_RELOAD_CALL = 0x0201E468, 0x0201E46C
SEGMENTED_PRODUCT_CALL, SEGMENTED_RELOAD_CALL = 0x0201E49C, 0x0201E4A0
NOTE_OFF_CALL, NOTE_ON_CALL = 0x0201C63E, 0x0201C67C
MEMCPY = 0x02048CCE
SECTOR_SIZE = 0x2000
EXPECTED_CHANGED_SECTORS = [0x04000, 0x20000, 0x22000, 0x2A000, 0x62000]
EXPECTED = {
    "official_fwsc": "f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff",
    "official_app": "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055",
    "s1c1_app": "16023c9006f2d4d6467ef2d72d6165c14ffeb6cb758d074f7d8163a68146fb2e",
    "candidate_app": "4afd13d7301c2ae209c11d3fe932d019faa770b551f2d8a38cf4c018c7aafa8a",
    "candidate_fwsc": "63e3cfa39473df08bd225df2c8ae81dbfe7aafbd31da6cc6dcf64ca03453681e",
    "candidate_flash": "2592990c071fcd7654f3ea913d70f341553d19f79801e693f74801fe160021ad",
    "official_flash": "f77e9ab3cee79113be78f3efacffb03c6cb9b87b78263010e16e81c472df0f9a",
    "selector": "adb8774971811f6dbdce8b7338f2265f18b8bb22544ccab746e74610366d4e35",
    "producer": "a05e79c0b46e1e12b1244af3f49866c911fcc41937bc14196825d3080d780784",
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"BLOCK: {message}")


def sha(data: bytes | bytearray) -> str:
    return hashlib.sha256(data).hexdigest()


def sx(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value ^ sign) - sign


def off(address: int) -> int:
    return address - BASE


def call32_target(at: int, blob: bytes) -> int:
    require(len(blob) == 6 and blob[:2] == b"\x80\xff", f"call32 encoding at 0x{at:08x}")
    return at + 6 + struct.unpack("<i", blob[2:])[0]


def short_call_target(at: int, blob: bytes) -> int:
    require(len(blob) == 4 and blob[:2] == b"\xbf\xea", f"short-call encoding at 0x{at:08x}")
    halfwords = struct.unpack("<H", blob[2:])[0]
    return ((at + 4 + halfwords * 2) & 0xFFFF) | (at & 0xFFFF0000)


def decode_pi32(data: bytes, start: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    index = 0
    while index < len(data):
        at = start + index
        remaining = len(data) - index
        word = int.from_bytes(data[index:index + 2], "little") if remaining >= 2 else 0
        row: dict[str, Any]
        size: int
        if remaining >= 4 and data[index:index + 4] == bytes.fromhex("2000b000"):
            size, row = 4, {"op": "trylock", "mutates": True, "detail": "csync; testset b[r0]"}
        elif remaining >= 6 and data[index:index + 2] == b"\x80\xff":
            size = 6
            row = {"op": "call32", "target": call32_target(at, data[index:index + size]), "mutates": True}
        elif remaining >= 4 and data[index:index + 2] == b"\xbf\xea":
            size = 4
            row = {"op": "short_call", "target": short_call_target(at, data[index:index + size])}
        elif remaining >= 4 and data[index:index + 2] == b"\x40\xe8":
            size = 4
            row = {"op": "ifeq", "target": at + 4 + struct.unpack("<h", data[index + 2:index + 4])[0] * 2}
        elif remaining >= 6 and (word & 0xFFC0) == 0xFFC0:
            size = 6
            row = {"op": "mov_imm32", "dst": word & 0xF, "imm": int.from_bytes(data[index + 2:index + 6], "little")}
        elif remaining >= 4 and (word & 0xF880) == 0xF880:
            size = 4
            word2 = int.from_bytes(data[index + 2:index + 4], "little")
            row = {
                "op": "jne_imm7",
                "reg": word & 7,
                "imm": (word2 >> 9) & 0x7F,
                "target": at + 4 + sx(word2 & 0x1FF, 9) * 2,
            }
        elif remaining >= 4 and data[index + 1] == 0xE1:
            size = 4
            row = {
                "op": "add_imm12",
                "dst": data[index],
                "src": data[index + 3] >> 4,
                "imm": data[index + 2] | ((data[index + 3] & 0xF) << 8),
            }
        elif remaining >= 2 and (word & 0xE088) == 0x4008:
            size = 2
            row = {"op": "load_byte", "dst": word & 7, "base": (word >> 4) & 7, "offset": sx((word >> 8) & 0x1F, 5)}
        elif remaining >= 2 and (word & 0xE088) == 0x4088:
            size = 2
            row = {"op": "store_byte", "src": word & 7, "base": (word >> 4) & 7, "offset": sx((word >> 8) & 0x1F, 5), "mutates": True}
        elif remaining >= 2 and (word & 0xE0C0) == 0x2040:
            size = 2
            row = {"op": "mov_imm8", "dst": word & 7, "imm": ((word >> 8) & 0x1F) | (((word >> 3) & 7) << 5)}
        elif remaining >= 2 and (word & 0xE0C0) == 0x20C0:
            size = 2
            immediate = ((word >> 8) & 0x1F) | (((word >> 3) & 7) << 5)
            row = {"op": "add_imm8", "dst": word & 7, "imm_signed": sx(immediate, 8)}
        elif remaining >= 2 and (word & 0xFF00) == 0x1600:
            size = 2
            row = {"op": "mov_reg", "dst": word & 0xF, "src": (word >> 4) & 0xF}
        elif remaining >= 2 and (word & 0x80FF) == 0x8004:
            size = 2
            row = {"op": "goto", "target": at + 2 + ((word >> 8) & 0x1F) * 2}
        elif remaining >= 2 and (word & 0xFF8F) == 0x1908:
            size = 2
            row = {"op": "xor_r0", "src": (word >> 4) & 7}
        elif remaining >= 2 and word in {0x0479, 0x0459, 0x0020}:
            size = 2
            row = {"op": {0x0479: "push", 0x0459: "pop_pc", 0x0020: "csync"}[word]}
        else:
            raise SystemExit(f"BLOCK: undecoded PI32 at 0x{at:08x}: {data[index:index + 8].hex()}")
        row.update({"address": at, "size": size, "bytes": data[index:index + size].hex()})
        rows.append(row)
        index += size
    return rows


def write_tsv(path: Path, rows: list[dict[str, Any]]) -> None:
    columns = ["address", "size", "bytes", "op", "target", "dst", "src", "reg", "imm", "imm_signed", "base", "offset", "mutates", "detail"]
    lines = ["\t".join(columns)]
    for row in rows:
        values = []
        for column in columns:
            value = row.get(column, "")
            if column in {"address", "target", "imm"} and isinstance(value, int):
                value = f"0x{value:08x}"
            values.append(str(value))
        lines.append("\t".join(values).rstrip("\t"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def load_parser(candidate: Path):
    parser_path = candidate / "smk37_v15_app_patch.py"
    spec = importlib.util.spec_from_file_location("review_smk37_v15_app_patch", parser_path)
    require(spec is not None and spec.loader is not None, "load committed FWSC parser")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def unpack_candidate_fwsc(raw: bytes, parser: Any) -> bytearray:
    payload = bytearray()
    for index in range(parser.FWSC_SLOTS):
        start = index * parser.FWSC_BLOCK_SIZE
        payload.extend(raw[start:start + parser.FWSC_DATA_SIZE])
    payload.extend(raw[parser.FWSC_SLOTS * parser.FWSC_BLOCK_SIZE:])
    require(len(payload) == parser.OFFICIAL_V15_PAYLOAD_SIZE, "candidate FWSC payload size")
    return payload


def verify_ledger(candidate: Path) -> dict[str, Any]:
    entries = []
    for line in (candidate / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ", 1)
        actual = sha((candidate / name).read_bytes())
        require(actual == digest, f"SHA256SUMS mismatch: {name}")
        entries.append({"path": name, "sha256": actual})
    require(len(entries) == 31, "SHA256SUMS entry count")
    return {"entry_count": len(entries), "all_match": True}


def verify_selector(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by = {row["address"]: row for row in rows}
    expected_ops = [
        "mov_reg", "goto", "mov_reg", "push", "mov_reg", "mov_reg", "jne_imm7",
        "mov_imm32", "add_imm12", "load_byte", "jne_imm7", "load_byte", "jne_imm7",
        "mov_reg", "goto", "jne_imm7", "load_byte", "xor_r0", "jne_imm7", "load_byte",
        "jne_imm7", "mov_reg", "goto", "add_imm12", "load_byte", "xor_r0", "jne_imm7",
        "load_byte", "jne_imm7", "add_imm12", "mov_reg", "call32", "pop_pc",
    ]
    require([row["op"] for row in rows] == expected_ops, "selector full instruction sequence")
    require(by[0x0201E13E]["dst"] == 3 and by[0x0201E13E]["src"] == 5, "Note Off r5 adapter")
    require(by[0x0201E142]["dst"] == 3 and by[0x0201E142]["src"] == 6, "Note On r6 adapter")
    require(by[0x0201E140]["target"] == 0x0201E144, "Note Off adapter reaches shared core")
    require(by[0x0201E14A]["reg"] == 5 and by[0x0201E14A]["imm"] == 9 and by[0x0201E14A]["target"] == 0x0201E194, "non-Ch10 fallback gate")
    require(by[0x0201E15A]["imm"] == 0 and by[0x0201E15A]["target"] == 0x0201E168, "EMPTY/nonempty state gate")
    require(by[0x0201E168]["imm"] == 2 and by[0x0201E168]["target"] == 0x0201E194, "ARMED gate and LOADING fallback")
    require(by[0x0201E170]["target"] == 0x0201E17E, "slot0 miss advances to slot1")
    for address in (0x0201E160, 0x0201E176, 0x0201E186, 0x0201E18C):
        require(by[address]["target"] == 0x0201E194, f"selector fallback target 0x{address:08x}")
    require(by[0x0201E166]["target"] == 0x0201E194 and by[0x0201E17C]["target"] == 0x0201E194, "selected slot paths reach common copy")
    require(by[0x0201E196]["target"] == MEMCPY, "selector memcpy target")
    require(rows[-1]["address"] == 0x0201E19C and rows[-1]["op"] == "pop_pc", "selector return")
    return {"bytes": 96, "instruction_count": len(rows), "fallback_copy": "0x0201e194", "memcpy": "0x02048cce"}


def verify_producer(rows: list[dict[str, Any]]) -> dict[str, Any]:
    by = {row["address"]: row for row in rows}
    expected_ops = [
        "push", "mov_reg", "mov_reg", "add_imm8", "add_imm8", "jne_imm7",
        "mov_imm32", "trylock", "ifeq", "csync", "mov_imm32", "load_byte",
        "jne_imm7", "mov_imm8", "store_byte", "csync", "mov_imm8", "store_byte",
        "mov_imm32", "mov_reg", "mov_imm8", "call32", "csync", "mov_imm8",
        "store_byte", "goto", "jne_imm7", "load_byte", "jne_imm7", "add_imm12",
        "load_byte", "jne_imm7", "mov_imm8", "store_byte", "mov_imm32", "mov_reg",
        "mov_imm8", "call32", "csync", "mov_imm8", "store_byte", "csync", "mov_imm8",
        "store_byte", "mov_imm32", "csync", "mov_imm8", "store_byte", "csync", "pop_pc",
        "push", "pop_pc",
    ]
    require([row["op"] for row in rows] == expected_ops, "producer full instruction sequence")
    require(by[0x0201E1A6]["dst"] == 0 and by[0x0201E1A6]["src"] == 9, "producer copies r9 to r0")
    require(by[0x0201E1A8]["imm_signed"] == -0x80 and by[0x0201E1AA]["imm_signed"] == -0x23, "producer computes r9 - 0xa3")
    require(by[0x0201E1AC]["imm"] == 0 and by[0x0201E1AC]["target"] == 0x0201E230, "wrong-length return gate")
    first_mutation = next(row for row in rows if row.get("mutates"))
    require(first_mutation["address"] == 0x0201E1B6 and first_mutation["op"] == "trylock", "no memory mutation before length gate")
    require(by[0x0201E1BA]["target"] == 0x0201E230, "failed trylock returns without unlock")
    require(by[0x0201E1C8]["target"] == 0x0201E1EE, "EMPTY versus nonempty route")
    require(by[0x0201E1EC]["target"] == 0x0201E222, "first publication then unlock")
    for address in (0x0201E1EE, 0x0201E1F4, 0x0201E1FE):
        require(by[address]["target"] == 0x0201E222, f"reject path reaches unlock 0x{address:08x}")
    require(by[0x0201E1E0]["target"] == MEMCPY and by[0x0201E210]["target"] == MEMCPY, "both producer memcpy targets")
    require(by[0x0201E1CE]["op"] == "store_byte" and by[0x0201E1EA]["op"] == "store_byte", "LOADING precedes valid0 publication")
    require(by[0x0201E21A]["op"] == "store_byte" and by[0x0201E220]["op"] == "store_byte", "valid1 precedes ARMED publication")
    require(by[0x0201E22C]["op"] == "store_byte" and by[0x0201E230]["op"] == "pop_pc", "unlock then return")
    require(by[SEGMENTED_STUB]["op"] == "push" and by[SEGMENTED_STUB + 2]["op"] == "pop_pc", "segmented immediate-return stub")
    return {"bytes": 148, "instruction_count": len(rows), "first_mutation": "0x0201e1b6", "segmented_stub": "0x0201e232"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True, help="Root of exact archived commit tree")
    parser.add_argument("--json-output", type=Path, default=HERE / "independent-verification.json")
    args = parser.parse_args()
    root = args.root.resolve()
    candidate = root / CANDIDATE_REL
    require(candidate.is_dir(), "candidate directory exists")

    ledger = verify_ledger(candidate)
    module = load_parser(candidate)
    official_raw = (candidate / "inputs/SMK-37_Pro_015.fwsc").read_bytes()
    candidate_raw = (candidate / PACKAGE).read_bytes()
    require(sha(official_raw) == EXPECTED["official_fwsc"], "official FWSC hash")
    require(sha(candidate_raw) == EXPECTED["candidate_fwsc"], "candidate FWSC hash")

    official_payload = module.unpack_fwsc(official_raw)[0]
    candidate_payload = unpack_candidate_fwsc(candidate_raw, module)
    official_flash = module.Ufw.parse(official_payload).flash()
    candidate_flash = module.Ufw.parse(candidate_payload).flash()
    official_app = module.AppImage.parse(official_flash).app_bytes()
    candidate_app = module.AppImage.parse(candidate_flash).app_bytes()
    require(sha(official_app) == EXPECTED["official_app"], "official app extracted from official FWSC")
    require(sha(candidate_app) == EXPECTED["candidate_app"], "candidate app extracted from candidate FWSC")
    require(candidate_app == (candidate / "app.bin").read_bytes(), "candidate FWSC embeds exact app.bin")
    require(sha(candidate_flash) == EXPECTED["candidate_flash"], "candidate flash hash")
    require(sha(official_flash) == EXPECTED["official_flash"], "official flash hash")

    changed_offsets = [index for index, pair in enumerate(zip(official_flash, candidate_flash)) if pair[0] != pair[1]]
    changed_sectors = sorted({index // SECTOR_SIZE * SECTOR_SIZE for index in changed_offsets})
    require(changed_sectors == EXPECTED_CHANGED_SECTORS, "exact changed sector set")
    require(candidate_flash[:0x4000] == official_flash[:0x4000], "protected 0x0000..0x3fff prefix unchanged")

    rollback_manifest = json.loads((candidate / "rollback/official-v15-recovery-sectors/manifest.json").read_text(encoding="utf-8"))
    reconstructed = bytearray(candidate_flash)
    manifest_sectors = []
    for item in rollback_manifest["changed_sectors"]:
        base = int(item["sector_base"], 16)
        data = (candidate / item["file"]).read_bytes()
        require(len(data) == SECTOR_SIZE, f"rollback sector size 0x{base:05x}")
        require(sha(data) == item["sha256"], f"rollback sector hash 0x{base:05x}")
        require(data == official_flash[base:base + SECTOR_SIZE], f"rollback sector exact official bytes 0x{base:05x}")
        reconstructed[base:base + SECTOR_SIZE] = data
        manifest_sectors.append(base)
    require(manifest_sectors == EXPECTED_CHANGED_SECTORS, "rollback manifest sector order and coverage")
    require(bytes(reconstructed) == bytes(official_flash), "rollback reconstructs exact official flash")
    require(module.AppImage.parse(reconstructed).app_bytes() == official_app, "rollback reconstructs exact official v15 app")

    selector = candidate_app[off(SELECTOR_START):off(SELECTOR_END)]
    producer = candidate_app[off(PRODUCER_START):off(PRODUCER_END)]
    require(sha(selector) == EXPECTED["selector"] and selector == (candidate / "selector.bin").read_bytes(), "selector slice and hash")
    require(sha(producer) == EXPECTED["producer"] and producer == (candidate / "producer.bin").read_bytes(), "producer slice and hash")
    selector_rows = decode_pi32(selector, SELECTOR_START)
    producer_rows = decode_pi32(producer, PRODUCER_START)
    selector_result = verify_selector(selector_rows)
    producer_result = verify_producer(producer_rows)
    write_tsv(HERE / "pi32-selector-decode.tsv", selector_rows)
    write_tsv(HERE / "pi32-producer-decode.tsv", producer_rows)

    routes = {
        "note_off": call32_target(NOTE_OFF_CALL, candidate_app[off(NOTE_OFF_CALL):off(NOTE_OFF_CALL) + 6]),
        "note_on": call32_target(NOTE_ON_CALL, candidate_app[off(NOTE_ON_CALL):off(NOTE_ON_CALL) + 6]),
        "direct_product": short_call_target(DIRECT_PRODUCT_CALL, candidate_app[off(DIRECT_PRODUCT_CALL):off(DIRECT_PRODUCT_CALL) + 4]),
        "segmented_product": short_call_target(SEGMENTED_PRODUCT_CALL, candidate_app[off(SEGMENTED_PRODUCT_CALL):off(SEGMENTED_PRODUCT_CALL) + 4]),
    }
    require(routes == {"note_off": SELECTOR_START, "note_on": SELECTOR_START + 4, "direct_product": PRODUCER_START, "segmented_product": SEGMENTED_STUB}, "exact route targets")
    require(candidate_app[off(DIRECT_RELOAD_CALL):off(DIRECT_RELOAD_CALL) + 4] == bytes.fromhex("bfeaf838"), "direct reload preserved")
    require(candidate_app[off(SEGMENTED_RELOAD_CALL):off(SEGMENTED_RELOAD_CALL) + 4] == bytes.fromhex("bfeade38"), "segmented reload preserved")
    require(candidate_app[off(OFFICIAL_HANDLER):off(OFFICIAL_HANDLER) + 0x20] == (candidate / "inputs/S1C1-boundary-only-app.bin").read_bytes()[off(OFFICIAL_HANDLER):off(OFFICIAL_HANDLER) + 0x20], "official handler preserved")

    result = {
        "status": "PASS",
        "reviewed_commit": "0f2c1f4acd76504b31b6fb624ec619110d0d611d",
        "scope": "offline files only; no USB, MIDI, OTA, flash, reset, or device interface opened",
        "ledger": ledger,
        "hashes": {
            "official_fwsc": sha(official_raw),
            "candidate_fwsc": sha(candidate_raw),
            "official_app": sha(official_app),
            "candidate_app": sha(candidate_app),
            "official_flash": sha(official_flash),
            "candidate_flash": sha(candidate_flash),
        },
        "changed_flash_bytes": len(changed_offsets),
        "changed_sectors": [f"0x{base:05x}" for base in changed_sectors],
        "protected_prefix_0x0000_0x3fff_unchanged": True,
        "rollback_reconstructs_exact_official_v15": True,
        "selector": selector_result,
        "producer": producer_result,
        "routes": {name: f"0x{target:08x}" for name, target in routes.items()},
        "reloads_and_official_handler_preserved": True,
    }
    args.json_output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("S1-C2 live v2 independent offline verification: PASS")
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
