#!/usr/bin/env python3
"""Validate the offline R03 fixed-prefix checkpoint and exact rollback bundle.

This validator makes no live-functional claim and performs no device access.
"""
from __future__ import annotations

import json
import struct
import subprocess
import sys
import zipfile
from hashlib import sha256
from pathlib import Path

from build_v15_r01_hand_drum import APP_SHA256, APP_SIZE, off
from build_v15_r03_fixed_prefix import (
    ATOMIC_SUCCESS_BARRIER,
    ATOMIC_TRY_PREFIX,
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
    SAVE_REJECT_BRANCH,
    SAVE_REJECT_CALL,
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
ATOMIC_SOURCE = ATOMIC_DIR / "r03-trylock.c"
ATOMIC_OBJECT = ATOMIC_DIR / "r03-trylock.pi32.o"
ATOMIC_OBJDUMP = ATOMIC_DIR / "official-objdump.txt"
ATOMIC_SDK_CONTRACT = ATOMIC_DIR / "pinned-sdk-spinlock-contract.txt"
ATOMIC_REPRODUCER = ATOMIC_DIR / "reproduce_trylock.sh"
UPLOADER_SOURCE = ROOT / "tools/smk37_v15_r03_ota.c"
ROLLBACK_DIR = ROOT / "build/SMK37Pro-WL82-v15-R03-rollback-20260802-v4"
ROLLBACK_ZIP = ROOT / "build/SMK37Pro-WL82-v15-R03-rollback-20260802-v4.zip"
ROLLBACK_MANIFEST = ROLLBACK_DIR / "recovery-sectors/manifest.json"
ROLLBACK_GUARD = ROLLBACK_DIR / "restore/smk37_wl82_guarded_restore.py"
ROLLBACK_WRAPPER = ROLLBACK_DIR / "restore/run-restore-elevated.ps1"

R03_APP_SHA256 = "3ff9c46b9686c0cea1348a11bed553ebd2d677e2d3452a0f436ce14f3ba5c788"
R03_PACKAGE_SHA256 = "001582c097277d6a4a619ed407cf121d5f30097ef82f312d53a2e45c4a9a5a62"
ROLLBACK_SHA256 = "ee8af217f78576a69ac1406ad839eb69721f031b8e2996825ef540d07a38c751"
ATOMIC_SOURCE_SHA256 = "2e82edb679ceb2e2c4e66903ceb96310ad4eb3f18aa24dd0b802fddd1bd8b3be"
ATOMIC_OBJECT_SHA256 = "e12ebf05608c78c4ba81cbea8eded0230ddd26febb89a2412174c694744c22c6"
ATOMIC_OBJDUMP_SHA256 = "faaf49e7fdd8a85c6cf79246a00c48678e3a96688d452a545fbc137200c6fb04"
ATOMIC_SDK_CONTRACT_SHA256 = "cc2d19dd8d71b015aae3ecaea222013927f269a98904165873b88e6e303a5245"
ATOMIC_REPRODUCER_SHA256 = "c783f5a7b47dd88090c6b152444662ee115533a934d00831baaf25f6b899a91e"
UPLOADER_SOURCE_SHA256 = "d0c2afdff619d907a68c12abed55269e38e00b17c0248f3039e7674c8a1f7eac"


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
        "producer": 0x0201E19E,
        "try_fail_branch": 0x0201E1AC,
        "producer_unlock": 0x0201E1D8,
        "producer_return": 0x0201E1E6,
        "end": 0x0201E1E8,
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
    require(r03[off(SAVE_REJECT_CALL):off(SAVE_REJECT_CALL) + 4] == SAVE_REJECT_BRANCH,
            "SAVE first persistent write is not bypassed")
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
            "nonblocking PI32v2 atomic testset try-lock; a concurrent or interrupt reentry returns immediately instead of spinning",
            "producer serialization mismatch")
    require(protocol["reload_after_first_publish"] == "rejected until reboot", "snapshot is not immutable")
    require("active_count" not in json.dumps(app_manifest), "retired active-count protocol remains")
    require("no-write rejection at 0x02026da6" in protocol["save"], "SAVE protocol is not no-write rejection")
    require(len(app_manifest["changes"]) == 9, "unexpected app manifest change count")

    changed = {index for index, (before, after) in enumerate(zip(official, r03)) if before != after}
    allowed = set(range(off(CODE_CAVE), off(CODE_CAVE) + len(cave)))
    allowed.update(range(off(NOTE_OFF_CALL), off(NOTE_OFF_CALL) + 6))
    allowed.update(range(off(NOTE_ON_CALL), off(NOTE_ON_CALL) + 6))
    for address, _, _ in PRODUCT_CALLS:
        allowed.update(range(off(address), off(address) + 4))
    allowed.update(range(off(SAVE_CALL), off(SAVE_CALL) + 4))
    allowed.update(range(off(SAVE_REJECT_CALL), off(SAVE_REJECT_CALL) + 4))
    allowed.update(range(off(BSS_SIZE_INSN), off(BSS_SIZE_INSN) + 6))
    allowed.update(range(off(HEAP_BEGIN_INSN), off(HEAP_BEGIN_INSN) + 6))
    require(changed <= allowed, "R03 changed bytes outside declared ranges")
    require(len(changed) == 187, f"unexpected app changed-byte count: {len(changed)}")

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
    official_try_body = bytes.fromhex("2000b00040e8030020004021800040208000")
    require(official_try_body in atomic_object,
            "exact nonblocking try-lock body is absent from official PI32 object")
    require(digest(ATOMIC_OBJDUMP.read_bytes()) == ATOMIC_OBJDUMP_SHA256,
            "official PI32 objdump transcript hash mismatch")
    objdump = ATOMIC_OBJDUMP.read_text(encoding="utf-8")
    require("testset b[r0]" in objdump and "ifeq goto 6" in objdump and
            "r0 = 1" in objdump and "r0 = 0" in objdump,
            "official PI32 objdump does not prove nonblocking try-lock semantics")
    require(digest(ATOMIC_SDK_CONTRACT.read_bytes()) == ATOMIC_SDK_CONTRACT_SHA256,
            "pinned SDK spinlock contract hash mismatch")
    sdk_contract = ATOMIC_SDK_CONTRACT.read_text(encoding="utf-8")
    require("e30b1ee375d1f2993fc23bf92c8b99006a6e5f9d" in sdk_contract and
            "preempt_disable();" in sdk_contract and
            "does not embed the blocking loop" in sdk_contract,
            "pinned SDK evidence does not explain why blocking spin is rejected")
    require(digest(ATOMIC_REPRODUCER.read_bytes()) == ATOMIC_REPRODUCER_SHA256,
            "official PI32 reproduction script hash mismatch")
    producer_bytes = r03[off(layout["producer"]):off(layout["end"])]
    require(ATOMIC_TRY_PREFIX in producer_bytes and ATOMIC_SUCCESS_BARRIER in producer_bytes,
            "embedded atomic try-lock prefix/barrier mismatch")
    try_fail = r03[off(layout["try_fail_branch"]):off(layout["try_fail_branch"]) + 4]
    require(bytes.fromhex("40e81b00") == try_fail,
            "embedded try-lock failure branch does not return without spinning")
    try_fail_target = layout["try_fail_branch"] + 4 + struct.unpack("<h", try_fail[2:])[0] * 2
    require(try_fail_target == layout["producer_return"],
            "embedded try-lock failure branch target mismatch")
    require(VOICE + VOICE_SIZE == VALID and VALID + 1 == LOCK and LOCK < RESERVED_END,
            "voice/valid/lock ownership layout mismatch")

    uploader_source = UPLOADER_SOURCE.read_text(encoding="utf-8")
    require(digest(UPLOADER_SOURCE.read_bytes()) == UPLOADER_SOURCE_SHA256,
            "R03 exact uploader source hash mismatch")
    require("INSTALL-SMK37PRO-V15-R03-001582C0" in uploader_source,
            "R03 exact uploader confirmation token mismatch")
    require("0x00, 0x15, 0x82, 0xc0" in uploader_source and
            "0x53, 0xa2, 0xe4, 0x5c, 0x4a, 0x9a, 0x5a, 0x62" in uploader_source,
            "R03 exact uploader package hash bytes mismatch")

    trace = parse_trace(DECODER_TRACE)
    provenance = json.loads(DECODER_PROVENANCE.read_text(encoding="utf-8"))
    require(provenance["candidate_app_sha256"] == R03_APP_SHA256, "decoder provenance hash mismatch")
    require(provenance["retained_rows"] == len(trace), "decoder trace row count mismatch")
    require(provenance["known_decoder_gap"] == {
        "address": "0x0201e1ac",
        "bytes": "40e81b00",
        "official_objdump": "40 e8 03 00 = ifeq goto forward failure path",
        "candidate_target": "0x0201e1e6 producer return without unlock or spin",
        "validation": "the same official-toolchain opcode is displacement-adjusted by the tested builder encoder and checked byte-for-byte",
    }, "decoder gap provenance mismatch")
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
        0x0201E1A8: ("2000", "csync"),
        0x0201E1AA: ("b000", "testset b[r0]"),
        0x0201E1B0: ("2000", "csync"),
        0x0201E1BA: ("80f80d00", "jne r0,#0x0,0x0201e1d8"),
        0x0201E1C8: ("80ff00ab0200", "call 0x02048cce"),
        0x0201E1D6: ("d840", "sb r0,[r5 + 0x0]"),
        0x0201E1DE: ("2000", "csync"),
        0x0201E1E2: ("8940", "sb r1,[r0 + 0x0]"),
        0x0201E1E4: ("2000", "csync"),
        0x0201E1E6: ("5904", "pop {pc,r9,r8,r7,r6,r5,r4}"),
        0x0201E468: ("bfea99fe", "call 0x0201e19e"),
        0x0201E49C: ("bfea7ffe", "call 0x0201e19e"),
        0x02026DA6: ("0496", "goto 0x02026dd4"),
        0x02026DA8: ("0000", "nop"),
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
    require(package_manifest["changes"]["app_byte_count"] == 187, "package app diff count mismatch")
    require(package_manifest["changes"]["flash_byte_count_including_crc_fields"] == 195,
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
    confirmations = (
        "I_UNDERSTAND_THIS_ERASES_EXACTLY_FIVE_R03_SECTORS",
        "I_HAVE_TWO_IDENTICAL_1MIB_DUMPS_AND_R03_TARGET_HASHES",
        "RESTORE_OFFICIAL_V15_SECTORS_NOW",
    )
    wrapper = ROLLBACK_WRAPPER.read_text(encoding="utf-8")
    require("FOUR_R02" not in wrapper and "R02_TARGET_HASHES" not in wrapper,
            "rollback elevated wrapper contains stale R02 confirmations")
    for confirmation in confirmations:
        require(wrapper.count(f"--confirm {confirmation}") == 1,
                f"rollback elevated wrapper confirmation mismatch: {confirmation}")
    with zipfile.ZipFile(ROLLBACK_ZIP) as archive:
        zip_wrapper_name = f"{ROLLBACK_DIR.name}/restore/run-restore-elevated.ps1"
        zip_wrapper = archive.read(zip_wrapper_name).decode("utf-8")
        require(zip_wrapper == wrapper, "rollback ZIP elevated wrapper differs from directory")
        for confirmation in confirmations:
            require(zip_wrapper.count(f"--confirm {confirmation}") == 1,
                    f"rollback ZIP confirmation mismatch: {confirmation}")
        require("FOUR_R02" not in zip_wrapper and "R02_TARGET_HASHES" not in zip_wrapper,
                "rollback ZIP contains stale R02 confirmations")
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
