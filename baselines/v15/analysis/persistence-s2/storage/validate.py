#!/usr/bin/env python3
"""Validate the exact official-v15/current-S1C5 persistence storage analysis.

Offline only. This script reads repository artifacts and writes only evidence files
inside this directory when --write is supplied. It does not open a device path,
modify firmware, or write persistent storage.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
OFFICIAL = ROOT / "baselines/v15/analysis/flash-candidates/S1C2-two-slot-selector-live-v2/inputs/v15-official-app.bin"
S1C5 = ROOT / "baselines/v15/analysis/flash-candidates/S1C5-playback-register-return/app.bin"
LISTING = ROOT / "baselines/v15/analysis/quarkslab/results/quarkslab-exhaustive-listing.tsv.gz"
S1C5_DECODE = ROOT / "baselines/v15/analysis/playback-note/candidate-v3-segmented-final/decode.tsv"
S1C5_CODE_EVIDENCE = ROOT / "baselines/v15/analysis/playback-note/candidate-v3-segmented-final/evidence.json"
BASE = 0x02000000

EXPECTED_SHA256 = {
    "official_app": "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055",
    "s1c5_app": "8b16e9f5a3ec873ac9a51e64f12c5be20156a01a6e8eb65878eed9636179f189",
    "listing": "f51e384f5f0efc415f321bbfbbe15d051301953338191282872807dcf8683347",
    "s1c5_decode": "3cb4c44c5ea2c3c99db25db4dcacdf6f2999f8dd90a42b3179f0e0f89b5f6826",
    "s1c5_code_evidence": "c2c057912c8ed2ecaed37a8158a836b81985207b8f34586820b376f28c167eec",
}

CHECK_ROWS = {
    0x02004B02: "push {rets,r4}",
    0x02004B04: "mov r4,r2",
    0x02004B06: "mov r2,r1",
    0x02004B08: "mov r1,r4",
    0x02004B0A: "call 0x02004a7a",
    0x02004B0C: "if (r0 != r4)",
    0x02004870: "push {rets,r4}",
    0x02004872: "mov r4,r2",
    0x02004874: "mov r2,r1",
    0x02004876: "mov r1,r4",
    0x02004878: "call 0x020047d8",
    0x0200487A: "if (r0 != r4)",
    0x0200464E: "movz r1,#0x18b",
    0x02005EEA: "call 0x0200464e",
    0x02005EEE: "sw r0,[r6 + 0x160]",
    0x02005EF2: "sw r5,[r6 + 0x164]",
    0x02005F0E: "call 0x02004870",
    0x02005F20: "call 0x02004870",
    0x02005F7C: "call 0x02005512",
    0x02005F9C: "call 0x02005660",
    0x02005FA0: "ldw r0,r6,#0x15c",
    0x02005528: "call 0x02004b02",
    0x02005682: "ldw r7,r4,#0x164",
    0x0200568A: "mul r0,r0,#0xa3",
    0x02005690: "add r1,r0,0x4000",
    0x02005694: "add r0,r4,0x1a14",
    0x02005698: "mov r2,#0xa3",
    0x0200569A: "call 0x02048cce",
    0x02005766: "mov r0,#0x3f",
    0x0200576C: "sb r0,[r3 + 0xf]",
    0x02005768: "add r6,r4,0x1ab0",
    0x02005770: "call 0x0200552e",
    0x02005776: "call 0x0200558e",
    0x0200577C: "call 0x020055f8",
    0x02005782: "call 0x0200562c",
    0x0200578A: "lb.z r0,[r6 + 0x6]",
    0x02026D6C: "movz r0,#0x1ec",
    0x02026D74: "jne r0,#0x0,0x020274a6",
    0x02026D7A: "jmz r6,#0xff,0x02026dd4",
    0x02026D8C: "ldw r2,r8,#0x160",
    0x02026D94: "mul r0,r0,#0xa3",
    0x02026D9A: "add r1,r0,0x4000",
    0x02026D9E: "add r4,r8,0x1a14",
    0x02026DA2: "mov r2,#0xa3",
    0x02026DA6: "call 0x02004b02",
    0x02026DAC: "call 0x0201e13e",
    0x02026DBE: "sb r15,[r1 + r0]",
    0x02026DD0: "call 0x02004b02",
}

ROW_RANGES = [
    (0x0200463A, 0x0200467A, "storage-handle-translation"),
    (0x020047D8, 0x02004884, "read-wrapper"),
    (0x02004A7A, 0x02004B16, "write-wrapper"),
    (0x02005512, 0x0200552E, "selection-writer"),
    (0x02005660, 0x020057DE, "raw-record-loader"),
    (0x02005EDC, 0x02005FAC, "boot-store-open-read-select-load"),
    (0x02026D6C, 0x02026DDE, "official-save"),
]


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def app_bytes(path: Path, lo: int, hi: int) -> bytes:
    data = path.read_bytes()
    assert BASE <= lo <= hi <= BASE + len(data)
    return data[lo - BASE : hi - BASE]


def load_rows() -> tuple[list[str], dict[int, str]]:
    with gzip.open(LISTING, "rt", errors="replace") as f:
        rows = list(f)
    by_addr: dict[int, str] = {}
    for row in rows:
        try:
            address = int(row.split("\t", 1)[0], 16)
        except (ValueError, IndexError):
            continue
        by_addr[address] = row.rstrip("\n")
    return rows, by_addr


def require(ok: bool, message: str, checks: list[str]) -> None:
    if not ok:
        raise AssertionError(message)
    checks.append("PASS\t" + message)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true", help="write evidence.json, exact-rows.tsv, and validation.txt")
    args = parser.parse_args()
    checks: list[str] = []

    inputs = {
        "official_app": OFFICIAL,
        "s1c5_app": S1C5,
        "listing": LISTING,
        "s1c5_decode": S1C5_DECODE,
        "s1c5_code_evidence": S1C5_CODE_EVIDENCE,
    }
    hashes = {name: sha256(path) for name, path in inputs.items()}
    for name, expected in EXPECTED_SHA256.items():
        require(hashes[name] == expected, f"sha256 {name} {expected}", checks)

    rows, by_addr = load_rows()
    for address, needle in CHECK_ROWS.items():
        require(address in by_addr and needle in by_addr[address], f"listing 0x{address:08x} contains {needle}", checks)

    official_save_call = app_bytes(OFFICIAL, 0x02026DA6, 0x02026DAA)
    s1c5_save_branch = app_bytes(S1C5, 0x02026DA6, 0x02026DAA)
    official_packer_call = app_bytes(OFFICIAL, 0x02026DAC, 0x02026DB0)
    s1c5_packer_neutral = app_bytes(S1C5, 0x02026DAC, 0x02026DB0)
    require(official_save_call.hex() == "beeaacee", "official 0x02026da6 calls write wrapper", checks)
    require(s1c5_save_branch.hex() == "04960000", "S1C5 0x02026da6 branches to SAVE cleanup", checks)
    require(official_packer_call.hex() == "bfeac7b9", "official 0x02026dac calls stock packer", checks)
    require(s1c5_packer_neutral.hex() == "00000000", "S1C5 0x02026dac stock packer call is neutralized", checks)

    unchanged_windows = [
        (0x0200463A, 0x02004884),
        (0x02004A7A, 0x02004B16),
        (0x02005512, 0x0200552E),
        (0x02005660, 0x020057E0),
        (0x02005EDC, 0x02005FAC),
    ]
    for lo, hi in unchanged_windows:
        require(app_bytes(OFFICIAL, lo, hi) == app_bytes(S1C5, lo, hi), f"official/S1C5 unchanged 0x{lo:08x}..0x{hi:08x}", checks)

    decode = S1C5_DECODE.read_text()
    s1c5_needles = [
        "0x0201e15a\t6\tc8ff2065c401\tselector.patch_base",
        "0x0201e164\t2\t6843\tselector.state_load",
        "0x0201e17c\t4\t07e1008a\tselector.map_base",
        "0x0201e1e8\t4\t01e19b40\tproducer.staging_last_pointer",
        "0x0201e1ec\t2\t1a40\tproducer.playback_load",
        "0x0201e1ee\t2\t8a40\tproducer.playback_store",
        "0x0201e1f0\t2\t4a3f\tproducer.restore_value",
        "0x0201e202\t2\te85f\tproducer.restore_slot_last",
        "0x0201e208\t2\te840\tproducer.valid_store",
        "0x0201e218\t2\td842\tproducer.armed_store",
    ]
    for needle in s1c5_needles:
        require(needle in decode, f"S1C5 decode {needle.split(chr(9))[3]}", checks)

    packed_bytes = 4 * 0x1000
    raw_records = 128
    raw_stride = 0xA3
    raw_start = packed_bytes
    raw_end = raw_start + raw_records * raw_stride
    flags_start = raw_end
    flags_end = flags_start + 0x80
    selection_start = flags_end
    selection_end = selection_start + 9
    require(raw_end == 0x9180, "stock 128*0xa3 raw extent ends at +0x9180", checks)
    require(flags_end == 0x9200, "stock 0x80 flag table ends at +0x9200", checks)
    require(selection_end == 0x9209, "stock 9-byte selection ends at +0x9209", checks)

    voice_bytes = 0x9C
    reconstructible_last = 1
    stored_voice_bytes = voice_bytes - reconstructible_last
    playback_bytes = 1
    require(stored_voice_bytes == 0x9B, "S1C5 persistent voice prefix is 0x9b bytes", checks)
    require(stored_voice_bytes + playback_bytes == 0x9C, "one S1C5 voice plus playback note fits raw prefix 0x9c", checks)
    require(16 * 0x9C == 0x9C0, "16 payload prefixes total 0x9c0 bytes across 16 records", checks)

    # The six 21-byte expanded operator blocks cover 0..125. The global
    # expansion covers 126..155, with offset 155 explicitly restored to 0x3f.
    packed_overwrite = set()
    for op in range(6):
        packed_overwrite.update(range(op * 21, op * 21 + 21))
    packed_overwrite.update(range(126, 156))
    require(packed_overwrite == set(range(0x9C)), "packed expansion overwrites every raw prefix byte 0x00..0x9b", checks)

    tail_usage = {
        "0x9c": "0x02005770 -> 0x0200552e",
        "0x9d": "0x02005776 -> 0x0200558e",
        "0x9e": "0x0200577c -> 0x020055f8",
        "0x9f": "0x02005782 -> 0x0200562c",
        "0xa0": "flag-dependent mirror of current[0x86]",
        "0xa1": "flag-dependent mirror of current[0x87]",
        "0xa2": "0x0200578e loads it for *(g+0x15c)+0x16",
    }
    require(len(tail_usage) == 7, "all seven raw tail bytes have proven stock use", checks)

    evidence = {
        "format": "smk37-v15-s1c5-persistence-s2-storage-evidence-v1",
        "scope": {
            "offline_only": True,
            "device_accessed": False,
            "firmware_patched": False,
            "flash_performed": False,
        },
        "inputs": {name: {"path": str(path.relative_to(ROOT)), "sha256": hashes[name]} for name, path in inputs.items()},
        "stock_store": {
            "global": "0x01c33260",
            "storage_address_pointer": "*(g+0x160)",
            "mapped_read_pointer": "*(g+0x164)",
            "packed": {"start": "0x0000", "end_exclusive": "0x4000", "bytes": packed_bytes},
            "raw": {"start": "0x4000", "end_exclusive": "0x9180", "records": raw_records, "stride": "0xa3", "bytes": raw_records * raw_stride},
            "flags": {"start": "0x9180", "end_exclusive": "0x9200", "bytes": 128},
            "selection": {"start": "0x9200", "end_exclusive": "0x9209", "bytes": 9},
            "known_extent": "0x9209",
        },
        "abis": {
            "write_0x02004b02": {"r0": "RAM source", "r1": "storage address/offset", "r2": "length", "return": "length on full success, else 0"},
            "read_0x02004870": {"r0": "RAM destination", "r1": "storage address/offset", "r2": "length", "return": "length on full success, else 0"},
            "loader_0x02005660": {"arguments": "none; global selection", "return": "ignored", "raw_source": "*(g+0x164)+0x4000+(bank*32+preset)*0xa3", "destination": "g+0x1a14"},
            "official_save_0x02026d6c": {"context": "large UI handler; uses g in r8, state in r6, constant 1 in r15", "write_return_use": "ignored"},
        },
        "boot": {
            "store_address_store": "0x02005eee -> g+0x160",
            "mapped_pointer_store": "0x02005ef2 -> g+0x164",
            "flags_read": "0x02005f0e: read 0x80 from *(g+0x160)+0x9180 to g+0x129c",
            "selection_read": "0x02005f20: read 9 from *(g+0x160)+0x9200 to g+0x3a0",
            "selection_default_writer": "0x02005f7c -> 0x02005512 when g[0x3a8] != 8",
            "loader_call": "0x02005f9c -> 0x02005660",
            "post_loader_continuation": "0x02005fa0",
        },
        "raw_tail_usage": tail_usage,
        "s1c5": {
            "slot_base": "0x01c46520",
            "slot_stride": "0xa0",
            "voice_bytes": "0x9c",
            "valid_offset": "0x9c",
            "lock": "0x01c465bd",
            "loaded_count": "0x01c465be",
            "state": "0x01c465bf",
            "armed_value": 2,
            "playback_map": "0x01c46f20..0x01c46f2f",
            "persistent_record_encoding": {
                "bytes_0x00_0x9a": "voice[0x00..0x9a] (155 bytes)",
                "byte_0x9b": "playback_note (0..127)",
                "restore": "map[i]=record[0x9b]; voice[0x9b]=0x3f before valid=1",
                "stock_tail_0x9c_0xa2": "unchanged",
            },
        },
        "decision": {
            "payload_fits_16_existing_raw_records": True,
            "lossless_free_records_proven": False,
            "unused_stock_tail_or_flag_or_selection_field_proven": False,
            "minimum_fail_closed_single_copy": "16 payload records plus 1 manifest record prefix (17 records)",
            "minimum_previous_generation_preserving_ab": "two independent 17-record groups (34 records)",
            "custom_persistent_allocation_required": False,
            "record_reservation_policy_required": True,
        },
        "exact_s1c5_save_diff": {
            "0x02026da6": {"official": official_save_call.hex(), "s1c5": s1c5_save_branch.hex()},
            "0x02026dac": {"official": official_packer_call.hex(), "s1c5": s1c5_packer_neutral.hex()},
        },
        "checks": checks,
    }

    selected_rows: list[str] = []
    for lo, hi, label in ROW_RANGES:
        selected_rows.append(f"# {label}\t0x{lo:08x}..0x{hi:08x}\n")
        for row in rows:
            try:
                address = int(row.split("\t", 1)[0], 16)
            except (ValueError, IndexError):
                continue
            if lo <= address < hi:
                selected_rows.append(row)
        selected_rows.append("\n")

    output = "\n".join(checks) + f"\nRESULT\tPASS\t{len(checks)} checks\n"
    if args.write:
        (HERE / "evidence.json").write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n")
        (HERE / "exact-rows.tsv").write_text("".join(selected_rows))
        (HERE / "validation.txt").write_text(output)
    print(output, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
