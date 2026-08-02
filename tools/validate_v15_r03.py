#!/usr/bin/env python3
"""Validate the offline R03 fixed-prefix checkpoint and exact rollback bundle.

This validator makes no live-functional claim and performs no device access.
"""
from __future__ import annotations

import json
import subprocess
import sys
from hashlib import sha256
from pathlib import Path

from build_v15_r01_hand_drum import APP_SHA256, APP_SIZE, off
from build_v15_r03_fixed_prefix import (
    ATOMIC_LOCK_BODY,
    ATOMIC_UNLOCK_BODY,
    BSS_SIZE_INSN,
    BSS_SIZE_R03,
    CODE_CAVE,
    HEAP_BEGIN_INSN,
    HEAP_BEGIN_R03,
    LOCK,
    NOTE_OFF_CALL,
    NOTE_ON_CALL,
    PRODUCT_CALLS,
    RESERVED_END,
    SAVE_CALL,
    VALID,
    VOICE,
    VOICE_SIZE,
    build_cave,
    call32,
    short_call,
)
from build_v15_r03_rollback import EXPECTED_SECTORS
from smk37_v15_app_patch import FWSC_BLOCK_SIZE, FWSC_DATA_SIZE, FWSC_SLOTS, Ufw

ROOT = Path(__file__).resolve().parents[1]
OFFICIAL_APP = ROOT / "build/v15-official-app.bin"
R03_APP = ROOT / "build/v15-R03-fixed-prefix-app.bin"
OFFICIAL_PACKAGE = ROOT / "build/SMK-37_Pro_015.fwsc"
R03_PACKAGE = ROOT / "build/SMK37Pro-v15-R03-fixed-prefix.fwsc"
APP_MANIFEST = ROOT / "baselines/v15/analysis/flash-candidates/R03/app-manifest.json"
PACKAGE_MANIFEST = ROOT / "baselines/v15/analysis/flash-candidates/R03/package-manifest.json"
DECODER_TRACE = ROOT / "baselines/v15/analysis/flash-candidates/R03/decoder-trace.tsv"
DECODER_PROVENANCE = ROOT / "baselines/v15/analysis/flash-candidates/R03/decoder-provenance.json"
HEAP_EVIDENCE = ROOT / "baselines/v15/analysis/r03-owned-ram/heap-prefix-reservation/evidence.json"
ATOMIC_DIR = ROOT / "baselines/v15/analysis/r03-owned-ram/atomic-publish"
ATOMIC_SOURCE = ATOMIC_DIR / "r03-spinlock.c"
ATOMIC_OBJECT = ATOMIC_DIR / "r03-spinlock.pi32.o"
UPLOADER_SOURCE = ROOT / "tools/smk37_v15_r03_ota.c"
ROLLBACK_DIR = ROOT / "build/SMK37Pro-WL82-v15-R03-rollback-20260802-v2"
ROLLBACK_ZIP = ROOT / "build/SMK37Pro-WL82-v15-R03-rollback-20260802-v2.zip"
ROLLBACK_MANIFEST = ROLLBACK_DIR / "recovery-sectors/manifest.json"
ROLLBACK_GUARD = ROLLBACK_DIR / "restore/smk37_wl82_guarded_restore.py"

R03_APP_SHA256 = "1fff37674f4bb1d5b988dc1415ab29c7114bbcad9e12bfcd7cec9b687d1f6ecb"
R03_PACKAGE_SHA256 = "0ed23e567a623db4b143fa30a6846626d746098ed126c149ac724c0fab6c1937"
ROLLBACK_SHA256 = "6396f253825d067986131d830bcca8cce16ff9ca39b21c4220369958e90344f1"
ATOMIC_SOURCE_SHA256 = "9a19e5b85b37c1b7c6e0efafbf86e6847791d4e38db1172fee5cb1e1be8b4b9b"
ATOMIC_OBJECT_SHA256 = "754ae849bed042a05294bfa9d5cab2e2b7045b107e91da1cbee1b0e80adfdd32"
UPLOADER_SOURCE_SHA256 = "1991e84e31c8a9488d85d3356963b00eab8c7818b7f296e4dea232d4b40370a2"


def digest(data: bytes) -> str:
    return sha256(data).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(message)


def flash_from_package(path: Path) -> bytes:
    raw = path.read_bytes()
    payload = bytearray()
    for index in range(FWSC_SLOTS):
        start = index * FWSC_BLOCK_SIZE
        payload.extend(raw[start:start + FWSC_DATA_SIZE])
    payload.extend(raw[FWSC_SLOTS * FWSC_BLOCK_SIZE:])
    return bytes(Ufw.parse(bytes(payload)).flash())


def parse_trace(path: Path) -> dict[int, list[str]]:
    rows: dict[int, list[str]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        columns = line.split("\t")
        require(len(columns) >= 6, f"malformed decoder row: {line}")
        address = int(columns[0], 16)
        require(address not in rows, f"duplicate decoder address: 0x{address:08x}")
        rows[address] = columns
    return rows


def main() -> int:
    official = OFFICIAL_APP.read_bytes()
    r03 = R03_APP.read_bytes()
    require(len(official) == len(r03) == APP_SIZE, "app size mismatch")
    require(digest(official) == APP_SHA256, "official app hash mismatch")
    require(digest(r03) == R03_APP_SHA256, "R03 app hash mismatch")

    cave, layout = build_cave()
    require(layout == {
        "off_entry": 0x0201E13E,
        "off_stock": 0x0201E166,
        "on_entry": 0x0201E16E,
        "on_stock": 0x0201E196,
        "lock_entry": 0x0201E19E,
        "unlock_entry": 0x0201E1AA,
        "producer": 0x0201E1B4,
        "producer_unlock": 0x0201E1EA,
        "producer_return": 0x0201E1F6,
        "end": 0x0201E1F8,
    }, f"unexpected R03 layout: {layout}")
    require(r03[off(CODE_CAVE):off(CODE_CAVE) + len(cave)] == cave, "R03 cave bytes mismatch")
    require(r03[off(NOTE_OFF_CALL):off(NOTE_OFF_CALL) + 6] == call32(NOTE_OFF_CALL, layout["off_entry"]),
            "Note Off target mismatch")
    require(r03[off(NOTE_ON_CALL):off(NOTE_ON_CALL) + 6] == call32(NOTE_ON_CALL, layout["on_entry"]),
            "Note On target mismatch")
    for address, _, _ in PRODUCT_CALLS:
        require(r03[off(address):off(address) + 4] == short_call(address, layout["producer"]),
                f"producer target mismatch at 0x{address:08x}")
    require(r03[off(SAVE_CALL):off(SAVE_CALL) + 4] == b"\0" * 4, "SAVE is not disabled")
    require(r03[off(BSS_SIZE_INSN):off(BSS_SIZE_INSN) + 6] == BSS_SIZE_R03, "BSS size patch mismatch")
    require(r03[off(HEAP_BEGIN_INSN):off(HEAP_BEGIN_INSN) + 6] == HEAP_BEGIN_R03,
            "HEAP_BEGIN patch mismatch")
    require(r03[off(0x02005F9C):off(0x02005F9C) + 4] == official[off(0x02005F9C):off(0x02005F9C) + 4],
            "forbidden early boot hook changed")

    app_manifest = json.loads(APP_MANIFEST.read_text(encoding="utf-8"))
    require(app_manifest["format"] == "smk37-v15-r03-fixed-heap-prefix-v1", "app manifest format mismatch")
    require(app_manifest["output_app_sha256"] == R03_APP_SHA256, "app manifest hash mismatch")
    require(app_manifest["owned_ram"] == {
        "heap_capacity_reduction": 160,
        "initialization": "boot BSS zero extension, ending exactly at shifted HEAP_BEGIN",
        "range": "0x01c46520..0x01c465c0",
        "size": 160,
        "valid": "0x01c465bc",
        "lock": "0x01c465bd",
        "voice": "0x01c46520..0x01c465bc",
    }, "owned RAM manifest mismatch")
    require(VOICE + VOICE_SIZE == VALID and RESERVED_END - VOICE == 0xA0,
            "owned RAM layout is not the aligned 0xa0 construction")
    protocol = app_manifest["protocol"]
    require(protocol["publish_order"] == "voice, valid=1", "publish order mismatch")
    require(protocol["producer_serialization"] ==
            "PI32v2 atomic testset spinlock with csync before and after critical section",
            "producer serialization mismatch")
    require(protocol["reload_after_first_publish"] == "rejected until reboot", "snapshot is not immutable")
    require("active_count" not in json.dumps(app_manifest), "retired active-count protocol remains")
    require(len(app_manifest["changes"]) == 8, "unexpected app manifest change count")

    changed = {index for index, (before, after) in enumerate(zip(official, r03)) if before != after}
    allowed = set(range(off(CODE_CAVE), off(CODE_CAVE) + len(cave)))
    allowed.update(range(off(NOTE_OFF_CALL), off(NOTE_OFF_CALL) + 6))
    allowed.update(range(off(NOTE_ON_CALL), off(NOTE_ON_CALL) + 6))
    for address, _, _ in PRODUCT_CALLS:
        allowed.update(range(off(address), off(address) + 4))
    allowed.update(range(off(SAVE_CALL), off(SAVE_CALL) + 4))
    allowed.update(range(off(BSS_SIZE_INSN), off(BSS_SIZE_INSN) + 6))
    allowed.update(range(off(HEAP_BEGIN_INSN), off(HEAP_BEGIN_INSN) + 6))
    require(changed <= allowed, "R03 changed bytes outside declared ranges")
    require(len(changed) == 199, f"unexpected app changed-byte count: {len(changed)}")

    heap = json.loads(HEAP_EVIDENCE.read_text(encoding="utf-8"))
    require(heap["sbrk_match"]["v15_address"] == "0x0205e9da", "sbrk match address mismatch")
    require(heap["sbrk_match"]["fixed_bytes_exact"] == 80, "sbrk fixed-byte proof mismatch")
    require(heap["sbrk_match"]["recovered_symbols"] == {
        "HEAP_BEGIN": "0x01c46520",
        "HEAP_END": "0x01c7fd30",
        "sbrk.__init_addr": "0x01c32d94",
    }, "sbrk recovered symbols mismatch")
    require(RESERVED_END % 32 == 0 and RESERVED_END < 0x01C7FD30, "new heap boundary invalid")

    require(digest(ATOMIC_SOURCE.read_bytes()) == ATOMIC_SOURCE_SHA256,
            "official-toolchain atomic source hash mismatch")
    atomic_object = ATOMIC_OBJECT.read_bytes()
    require(digest(atomic_object) == ATOMIC_OBJECT_SHA256,
            "official-toolchain atomic object hash mismatch")
    require(ATOMIC_LOCK_BODY + ATOMIC_UNLOCK_BODY in atomic_object,
            "exact lock/unlock bodies are not contiguous in official PI32 object")
    require(r03[off(layout["lock_entry"]):off(layout["unlock_entry"])] == ATOMIC_LOCK_BODY,
            "embedded atomic lock body mismatch")
    require(r03[off(layout["unlock_entry"]):off(layout["producer"])] == ATOMIC_UNLOCK_BODY,
            "embedded atomic unlock body mismatch")
    require(ATOMIC_LOCK_BODY[4:8] == bytes.fromhex("40e8fdff"),
            "official objdump spin-loop branch bytes mismatch")
    require(VOICE + VOICE_SIZE == VALID and VALID + 1 == LOCK and LOCK < RESERVED_END,
            "voice/valid/lock ownership layout mismatch")

    uploader_source = UPLOADER_SOURCE.read_text(encoding="utf-8")
    require(digest(UPLOADER_SOURCE.read_bytes()) == UPLOADER_SOURCE_SHA256,
            "R03 exact uploader source hash mismatch")
    require("INSTALL-SMK37PRO-V15-R03-0ED23E56" in uploader_source,
            "R03 exact uploader confirmation token mismatch")
    require("0x0e, 0xd2, 0x3e, 0x56" in uploader_source and
            "0xac, 0x72, 0x4c, 0x0f, 0xab, 0x6c, 0x19, 0x37" in uploader_source,
            "R03 exact uploader package hash bytes mismatch")

    trace = parse_trace(DECODER_TRACE)
    provenance = json.loads(DECODER_PROVENANCE.read_text(encoding="utf-8"))
    require(provenance["candidate_app_sha256"] == R03_APP_SHA256, "decoder provenance hash mismatch")
    require(provenance["retained_rows"] == len(trace) == 124, "decoder trace row count mismatch")
    expected_decodes = {
        0x0200001E: ("c2ffeccb0300", "mov r2,#0x3cbec"),
        0x0201C63E: ("80fffa1a0000", "call 0x0201e13e"),
        0x0201C67C: ("80ffec1a0000", "call 0x0201e16e"),
        0x0201E142: ("83f81012", "jne r3,#0x9,0x0201e166"),
        0x0201E150: ("80f80902", "jne r0,#0x1,0x0201e166"),
        0x0201E15E: ("80ff6aab0200", "call 0x02048cce"),
        0x0201E172: ("83f81012", "jne r3,#0x9,0x0201e196"),
        0x0201E180: ("80f80902", "jne r0,#0x1,0x0201e196"),
        0x0201E18E: ("80ff3aab0200", "call 0x02048cce"),
        0x0201E19E: ("2000", "csync"),
        0x0201E1A0: ("b000", "testset b[r0]"),
        0x0201E1A6: ("2000", "csync"),
        0x0201E1A8: ("8000", "rts"),
        0x0201E1AA: ("2000", "csync"),
        0x0201E1AE: ("8940", "sb r1,[r0 + 0x0]"),
        0x0201E1B0: ("2000", "csync"),
        0x0201E1B2: ("8000", "rts"),
        0x0201E1BE: ("80ffdaffffff", "call 0x0201e19e"),
        0x0201E1CC: ("80f80d00", "jne r0,#0x0,0x0201e1ea"),
        0x0201E1DA: ("80ffeeaa0200", "call 0x02048cce"),
        0x0201E1E8: ("d840", "sb r0,[r5 + 0x0]"),
        0x0201E1F0: ("80ffb4ffffff", "call 0x0201e1aa"),
        0x0201E1F6: ("5904", "pop {pc,r9,r8,r7,r6,r5,r4}"),
        0x0201E468: ("bfeaa4fe", "call 0x0201e1b4"),
        0x0201E49C: ("bfea8afe", "call 0x0201e1b4"),
        0x02026DAC: ("0000", "nop"),
        0x02026DAE: ("0000", "nop"),
    }
    for address, (raw, display) in expected_decodes.items():
        require(address in trace, f"missing decoder row 0x{address:08x}")
        row = trace[address]
        require(row[1] == raw and row[4] == display,
                f"decoder mismatch at 0x{address:08x}: {row[1]} {row[4]}")
        size = int(row[2])
        require(r03[off(address):off(address) + size].hex() == raw,
                f"decoder bytes do not match R03 app at 0x{address:08x}")

    require(digest(R03_PACKAGE.read_bytes()) == R03_PACKAGE_SHA256, "R03 package hash mismatch")
    package_manifest = json.loads(PACKAGE_MANIFEST.read_text(encoding="utf-8"))
    require(package_manifest["safety_gate"] == "PASS", "package safety gate failed")
    require(package_manifest["output"]["sha256"] == R03_PACKAGE_SHA256, "package manifest hash mismatch")
    require(package_manifest["output"]["app_sha256"] == R03_APP_SHA256, "package app hash mismatch")
    require(package_manifest["changes"]["app_byte_count"] == 199, "package app diff count mismatch")
    require(package_manifest["changes"]["flash_byte_count_including_crc_fields"] == 207,
            "package flash diff count mismatch")
    require(package_manifest["protected_flash_hashes_before"] == package_manifest["protected_flash_hashes_after"],
            "protected flash hashes changed")

    stock_flash = flash_from_package(OFFICIAL_PACKAGE)
    r03_flash = flash_from_package(R03_PACKAGE)
    sectors = tuple(
        address for address in range(0, len(stock_flash), 0x1000)
        if stock_flash[address:address + 0x1000] != r03_flash[address:address + 0x1000]
    )
    require(sectors == EXPECTED_SECTORS, f"unexpected changed sectors: {sectors}")
    require(stock_flash[:0x4000] == r03_flash[:0x4000], "protected prefix changed")

    require(digest(ROLLBACK_ZIP.read_bytes()) == ROLLBACK_SHA256, "rollback ZIP hash mismatch")
    rollback = json.loads(ROLLBACK_MANIFEST.read_text(encoding="utf-8"))
    require(rollback["format"] == "smk37-v15-r03-forced-recovery-plan-v1", "rollback format mismatch")
    require(tuple(int(item["address"], 0) for item in rollback["sectors"]) == EXPECTED_SECTORS,
            "rollback sector order/set mismatch")
    for item in rollback["sectors"]:
        address = int(item["address"], 0)
        stock_sector = stock_flash[address:address + 0x1000]
        target_sector = r03_flash[address:address + 0x1000]
        sector_file = ROLLBACK_MANIFEST.parent / item["stock_file"]
        require(sector_file.read_bytes() == stock_sector, f"rollback stock sector mismatch 0x{address:05x}")
        require(item["stock_sha256"] == digest(stock_sector), f"rollback stock hash mismatch 0x{address:05x}")
        require(item["expected_target_sha256"] == digest(target_sector),
                f"rollback target hash mismatch 0x{address:05x}")

    completed = subprocess.run([sys.executable, str(ROLLBACK_GUARD), "self-test"],
                               check=False, capture_output=True, text=True)
    require(completed.returncode == 0 and "self-test PASS" in completed.stdout,
            f"rollback guard self-test failed: {completed.stdout}{completed.stderr}")

    print("v15 R03 fixed-prefix artifact, PI32 decode, package, and rollback: PASS")
    print("not a live functional claim; no device access performed")
    print("app", R03_APP_SHA256)
    print("package", R03_PACKAGE_SHA256)
    print("rollback", ROLLBACK_SHA256)
    print("sectors", " ".join(f"0x{x:05x}" for x in sectors))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
