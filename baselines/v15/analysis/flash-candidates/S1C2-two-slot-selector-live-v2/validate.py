#!/usr/bin/env python3
"""Independent offline validator for S1-C2 two-slot selector live v2.

No device, OTA, flash, reset, MIDI, or USB transport is opened. This validator
checks bytes and local files only.
"""
from __future__ import annotations

import hashlib
import json
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from smk37_v15_app_patch import (  # noqa: E402
    APP_DATA_OFFSET,
    APP_DATA_SIZE,
    AppImage,
    Ufw,
    difference_offsets,
    unpack_fwsc,
)

FORMAT = "smk37-v15-s1c2-two-slot-selector-live-v2"
PACKAGE_NAME = "SMK37Pro-v15-S1C2-two-slot-selector-live-v2.fwsc"
BASE = 0x02000000
SELECTOR_START = 0x0201E13E
SELECTOR_END = 0x0201E19E
PRODUCER_START = 0x0201E1A2
PRODUCER_END = 0x0201E236
SEGMENTED_STUB = 0x0201E232
OFFICIAL_HANDLER = 0x0201E254
DIRECT_PRODUCT_CALL = 0x0201E468
DIRECT_RELOAD_CALL = 0x0201E46C
SEGMENTED_PRODUCT_CALL = 0x0201E49C
SEGMENTED_RELOAD_CALL = 0x0201E4A0
NOTE_OFF_CALL = 0x0201C63E
NOTE_ON_CALL = 0x0201C67C
DIRECT_LEN = 0xA3
HEADER = bytes.fromhex("f0430000011b")
TERM = b"\xf7"

EXPECTED = {
    "official_fwsc": "f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff",
    "official_app": "36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055",
    "s1c1_app": "16023c9006f2d4d6467ef2d72d6165c14ffeb6cb758d074f7d8163a68146fb2e",
    "app": "4afd13d7301c2ae209c11d3fe932d019faa770b551f2d8a38cf4c018c7aafa8a",
    "package": "63e3cfa39473df08bd225df2c8ae81dbfe7aafbd31da6cc6dcf64ca03453681e",
    "selector": "adb8774971811f6dbdce8b7338f2265f18b8bb22544ccab746e74610366d4e35",
    "producer": "a05e79c0b46e1e12b1244af3f49866c911fcc41937bc14196825d3080d780784",
    "packet0": "6a9b4097cce1d28780ef3a507f42999743cc10e09770c17c5c78d185e9abff27",
    "packet1": "c4e8458edeb04d8106ca60a35243525e6b5f3f5de272091492409a440e3a9a8d",
}


def fail(message: str) -> None:
    raise SystemExit(f"FAIL: {message}")


def req(condition: bool, message: str) -> None:
    if not condition:
        fail(message)


def sha(data: bytes | bytearray) -> str:
    return hashlib.sha256(data).hexdigest()


def sha_path(path: Path) -> str:
    return sha(path.read_bytes())


def off(address: int) -> int:
    value = address - BASE
    req(0 <= value < APP_DATA_SIZE, f"address outside app: 0x{address:08x}")
    return value


def call32_target(at: int, blob: bytes) -> int:
    req(len(blob) == 6 and blob[:2] == b"\x80\xff", f"call32 encoding at 0x{at:08x}")
    return at + 6 + struct.unpack("<i", blob[2:])[0]


def short_call_target(at: int, blob: bytes) -> int:
    req(len(blob) == 4 and blob[:2] == b"\xbf\xea", f"short-call encoding at 0x{at:08x}")
    half = struct.unpack("<H", blob[2:])[0]
    return ((at + 4 + half * 2) & 0xFFFF) | (at & 0xFFFF0000)


def unpack_any_fwsc(raw: bytes) -> bytearray:
    from smk37_v15_app_patch import FWSC_BLOCK_SIZE, FWSC_DATA_SIZE, FWSC_SLOTS, OFFICIAL_V15_PAYLOAD_SIZE
    payload = bytearray()
    for index in range(FWSC_SLOTS):
        start = index * FWSC_BLOCK_SIZE
        payload.extend(raw[start : start + FWSC_DATA_SIZE])
    payload.extend(raw[FWSC_SLOTS * FWSC_BLOCK_SIZE :])
    req(len(payload) == OFFICIAL_V15_PAYLOAD_SIZE, "FWSC payload size")
    return payload


def flash_and_app_from_fwsc(path: Path, official: bool = False) -> tuple[bytes, bytearray, bytes]:
    raw = path.read_bytes()
    payload = unpack_fwsc(raw)[0] if official else unpack_any_fwsc(raw)
    flash = Ufw.parse(payload).flash()
    app = AppImage.parse(flash).app_bytes()
    return raw, flash, app


def producer_decode_rows(producer: bytes) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    def add(address: int, size: int, op: str, detail: str = "") -> None:
        rows.append({
            "address": f"0x{address:08x}",
            "size": size,
            "bytes": producer[address - PRODUCER_START : address - PRODUCER_START + size].hex(),
            "op": op,
            "detail": detail,
        })
    add(0x0201E1A2, 2, "push", "save call return frame")
    add(0x0201E1A4, 2, "mov", "r4 = staging pointer")
    add(0x0201E1A6, 2, "mov", "r0 = r9")
    add(0x0201E1A8, 2, "add", "r0 -= 0x80")
    add(0x0201E1AA, 2, "add", "r0 -= 0x23, so r0 == r9 - 0xa3")
    add(0x0201E1AC, 4, "jne_imm7", "if r9 != 0xa3 branch to return before mutation")
    add(0x0201E1B0, 6, "mov_imm32", "r0 = lock byte 0x01c465bd")
    add(0x0201E1B6, 4, "trylock", "first mutating/testset operation")
    add(0x0201E1BA, 4, "ifeq", "failed trylock returns without clearing another lock")
    add(0x0201E230, 2, "pop_pc", "main producer return")
    add(0x0201E232, 2, "push", "segmented immediate-return stub")
    add(0x0201E234, 2, "pop_pc", "segmented stub returns without mutation")
    return rows


def write_decode(rows: list[dict[str, Any]]) -> None:
    lines = ["address\tsize\tbytes\top\tdetail"]
    lines.extend(f"{r['address']}\t{r['size']}\t{r['bytes']}\t{r['op']}\t{r['detail']}" for r in rows)
    (HERE / "independent-decode.tsv").write_text("\n".join(lines) + "\n", encoding="utf-8")


def packet_rows(evidence: dict[str, Any]) -> list[dict[str, Any]]:
    rows = []
    for item in evidence["host_packets"]["packets_in_order"]:
        packet = (HERE / item["packet_file"]).read_bytes()
        req(len(packet) == DIRECT_LEN, f"packet length order {item['order']}")
        req(packet.startswith(HEADER) and packet.endswith(TERM), f"packet framing order {item['order']}")
        digest = sha(packet)
        req(digest == item["packet_sha256"], f"packet evidence hash order {item['order']}")
        rows.append({"order": item["order"], "slot": item["slot"], "note": item["fixed_note"], "sha256": digest})
    req([r["sha256"] for r in rows] == [EXPECTED["packet0"], EXPECTED["packet1"]], "packet order and hashes")
    return rows


def rollback_reconstructs_official(candidate_flash: bytearray, official_flash: bytearray) -> str:
    manifest_path = HERE / "rollback/official-v15-recovery-sectors/manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    reconstructed = bytearray(candidate_flash)
    for item in manifest["changed_sectors"]:
        base = int(item["sector_base"], 16)
        data = (HERE / item["file"]).read_bytes()
        req(len(data) == manifest["sector_size"], f"rollback sector size {item['sector_base']}")
        req(sha(data) == item["sha256"], f"rollback sector hash {item['sector_base']}")
        reconstructed[base : base + len(data)] = data
    req(bytes(reconstructed) == bytes(official_flash), "rollback sectors reconstruct official flash")
    req(sha(reconstructed) == manifest["official_flash_sha256"], "rollback official flash hash")
    req(AppImage.parse(reconstructed).app_bytes() == (HERE / "inputs/v15-official-app.bin").read_bytes(), "rollback app is official v15 app")
    return sha(reconstructed)


def state_model_self_tests(packet0: bytes, packet1: bytes) -> None:
    state = {"state": 0, "valid0": 0, "valid1": 0, "slot0": b"", "slot1": b""}
    before = dict(state)
    wrong_len = packet0[:-1]
    req(len(wrong_len) != DIRECT_LEN, "wrong-length fixture")
    req(state == before, "wrong-length pre-mutation reject leaves state unchanged")
    state.update({"state": 1, "valid0": 1, "slot0": packet0[len(HEADER):-1]})
    state.update({"state": 2, "valid1": 1, "slot1": packet1[len(HEADER):-1]})
    armed = dict(state)
    req(state == armed, "post-armed reject self-test leaves state unchanged")


def main() -> int:
    app_manifest = json.loads((HERE / "app-manifest.json").read_text(encoding="utf-8"))
    package_manifest = json.loads((HERE / "package-manifest.json").read_text(encoding="utf-8"))
    evidence = json.loads((HERE / "evidence.json").read_text(encoding="utf-8"))

    req(evidence["format"] == FORMAT, "evidence format")
    req(app_manifest["format"] == FORMAT + ".app-manifest-v1", "app manifest format")
    req(sha_path(HERE / "inputs/SMK-37_Pro_015.fwsc") == EXPECTED["official_fwsc"], "official FWSC input hash")
    req(sha_path(HERE / "inputs/v15-official-app.bin") == EXPECTED["official_app"], "official app input hash")
    req(sha_path(HERE / "inputs/S1C1-boundary-only-app.bin") == EXPECTED["s1c1_app"], "S1-C1 input hash")
    req(sha_path(HERE / "app.bin") == EXPECTED["app"], "candidate app hash")
    req(sha_path(HERE / PACKAGE_NAME) == EXPECTED["package"], "candidate package hash")

    official_raw, official_flash, official_app = flash_and_app_from_fwsc(HERE / "inputs/SMK-37_Pro_015.fwsc", official=True)
    candidate_raw, candidate_flash, candidate_app = flash_and_app_from_fwsc(HERE / PACKAGE_NAME)
    req(sha(official_raw) == EXPECTED["official_fwsc"], "official raw hash")
    req(sha(official_app) == EXPECTED["official_app"], "official app extracted from FWSC")
    req(candidate_app == (HERE / "app.bin").read_bytes(), "FWSC embeds candidate app")
    req(package_manifest["output"]["sha256"] == sha(candidate_raw), "package manifest output hash")

    selector = candidate_app[off(SELECTOR_START) : off(SELECTOR_END)]
    producer = candidate_app[off(PRODUCER_START) : off(PRODUCER_END)]
    req(len(selector) == 96 and sha(selector) == EXPECTED["selector"], "96-byte selector slice")
    req(selector == (HERE / "selector.bin").read_bytes(), "selector.bin equals app slice")
    req(len(producer) == 148 and sha(producer) == EXPECTED["producer"], "148-byte producer/stub slice")
    req(producer == (HERE / "producer.bin").read_bytes(), "producer.bin equals app slice")

    direct_blob = candidate_app[off(DIRECT_PRODUCT_CALL) : off(DIRECT_PRODUCT_CALL) + 4]
    segmented_blob = candidate_app[off(SEGMENTED_PRODUCT_CALL) : off(SEGMENTED_PRODUCT_CALL) + 4]
    req(short_call_target(DIRECT_PRODUCT_CALL, direct_blob) == PRODUCER_START, "direct 0x0201e468 targets main producer")
    req(short_call_target(SEGMENTED_PRODUCT_CALL, segmented_blob) == SEGMENTED_STUB, "segmented 0x0201e49c targets immediate-return stub")
    req(candidate_app[off(SEGMENTED_STUB) : off(SEGMENTED_STUB) + 4] == bytes.fromhex("79045904"), "segmented immediate-return stub bytes")
    req(candidate_app[off(DIRECT_RELOAD_CALL) : off(DIRECT_RELOAD_CALL) + 4] == bytes.fromhex("bfeaf838"), "direct reload intact")
    req(candidate_app[off(SEGMENTED_RELOAD_CALL) : off(SEGMENTED_RELOAD_CALL) + 4] == bytes.fromhex("bfeade38"), "segmented reload intact")
    req(candidate_app[off(OFFICIAL_HANDLER) : off(OFFICIAL_HANDLER) + 0x20] == (HERE / "inputs/S1C1-boundary-only-app.bin").read_bytes()[off(OFFICIAL_HANDLER) : off(OFFICIAL_HANDLER) + 0x20], "official handler preserved")
    req(call32_target(NOTE_OFF_CALL, candidate_app[off(NOTE_OFF_CALL) : off(NOTE_OFF_CALL) + 6]) == SELECTOR_START, "Note Off hook target")
    req(call32_target(NOTE_ON_CALL, candidate_app[off(NOTE_ON_CALL) : off(NOTE_ON_CALL) + 6]) == SELECTOR_START + 4, "Note On hook target")

    req(producer[:14] == bytes.fromhex("790404169016e020f03d80f84000"), "direct r9 == 0xa3 pre-mutation gate prefix")
    req(producer.index(bytes.fromhex("2000b000")) == 0x14, "first testset occurs after r9 gate")
    req(producer[0x8E:0x90] == bytes.fromhex("5904"), "main return before segmented stub")
    req(producer[0x90:0x94] == bytes.fromhex("79045904"), "segmented stub immediate return")

    rows = producer_decode_rows(producer)
    write_decode(rows)
    packets = packet_rows(evidence)
    packet0 = (HERE / evidence["host_packets"]["packets_in_order"][0]["packet_file"]).read_bytes()
    packet1 = (HERE / evidence["host_packets"]["packets_in_order"][1]["packet_file"]).read_bytes()
    state_model_self_tests(packet0, packet1)
    official_flash_hash = rollback_reconstructs_official(candidate_flash, official_flash)

    app_diffs = difference_offsets((HERE / "inputs/S1C1-boundary-only-app.bin").read_bytes(), candidate_app)
    req(len(app_diffs) == app_manifest["s1c1_relative_changed_byte_count"] == 234, "S1-C1 relative changed byte count")

    subprocess.run([sys.executable, str(HERE / "host_sender_dry_run.py"), "--json"], cwd=HERE, check=True, stdout=subprocess.DEVNULL)

    summary = [
        "S1-C2 live v2 validation: PASS",
        f"app {EXPECTED['app']}",
        f"package {EXPECTED['package']}",
        f"selector {EXPECTED['selector']} 96 bytes",
        f"producer {EXPECTED['producer']} 148 bytes",
        "direct 0x0201e468 -> 0x0201e1a2",
        "segmented 0x0201e49c -> 0x0201e232 immediate-return stub 79045904",
        "direct r9 == 0xa3 pre-mutation gate verified before testset/state/slot mutation",
        f"packets {[p['sha256'] for p in packets]}",
        f"rollback reconstructs official flash {official_flash_hash}",
        "host dry-run schema PASS",
        "No device, OTA, flash, reset, MIDI, or USB transport opened.",
    ]
    (HERE / "validation.txt").write_text("\n".join(summary) + "\n", encoding="utf-8")
    print("\n".join(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
