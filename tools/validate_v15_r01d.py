#!/usr/bin/env python3
"""Validate R01d artifact integrity only.

This validator proves byte-level artifact properties for the official-v15-only
R01d checkpoint.  It is not a live-device test and must not be read as a claim
that the patch's musical behavior succeeds.
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

from build_v15_r01d_ram_mooger1 import (  # noqa: E402
    APP_SHA256 as OFFICIAL_APP_SHA,
    APP_SIZE,
    CHANNEL_10,
    CODE_CAVE,
    CODE_CAVE_END,
    CURRENT_SOURCE,
    FACTORY_LOADER,
    FORMAT,
    MEMCPY,
    MOOGER1_VOICE_NAME,
    MOOGER1_VOICE_OFFSET,
    NOTE_OFF_MEMCPY_CALL,
    NOTE_OFF_STOCK,
    NOTE_ON_MEMCPY_CALL,
    NOTE_ON_STOCK,
    POST_INIT_LOADER_CALL,
    POST_INIT_LOADER_STOCK,
    RAM_STAGING,
    SHORT_CALL_WINDOW_BYTES,
    SYSEX_CALLS,
    VOICE_COPY_SIZE,
    build_code_cave,
    call32,
    off,
    sha256 as sha256_bytes,
    short_call,
)

APP = ROOT / "build/v15-R01d-ram-mooger1-app.bin"
PACKAGE = ROOT / "build/SMK37Pro-v15-R01d-ram-mooger1.fwsc"
OFFICIAL_APP = ROOT / "build/v15-official-app.bin"
APP_MANIFEST = ROOT / "baselines/v15/analysis/flash-candidates/R01d/app-manifest.json"
PACKAGE_MANIFEST = ROOT / "baselines/v15/analysis/flash-candidates/R01d/package-manifest.json"
EXPECTED_APP_SHA = "bdcfdcf1b5e6d60e04e8c9316db94aa38e6cae4a7bcfaf63abefd38bb5347bb3"
EXPECTED_PACKAGE_SHA = "add7baacc38d90bcd28cf51a1d096abe0737c8430ec01f70d5b41423d5dc9a96"
EXPECTED_PAYLOAD_SHA = "299c08961b41462c5049f270a8c0596530dbbc7d7ee58fa74a175e4e951ae815"
EXPECTED_PACKED_SHA = "cf44a49e6157945f70bb144e42d7add0d88ee8ef1f2658ef8ab4a657e6e6a77c"
EXPECTED_SOURCE_DUMP_SHA = "1c202201a81ed6d956ec5398adff75ffcd805594a27370a56caafaf18223383b"
EXPECTED_ADDRESSES = {
    "0x02005f9c",
    "0x0201c63e",
    "0x0201c67c",
    "0x0201e13e",
    "0x0201e468",
    "0x0201e49c",
}
PROTECTED_HASHES = {
    "boot_and_flash_layout_0x0000_0x3fff": "d9f43191777656de01c7bed4f9e9ba2e34e94832c5d2ed02c3fc7ab7a6d9bd67",
    "isd_config_raw_0x38d0_0x3b8a": "0952afd96f533dd0fba72a8fab9cb4a4336f55424a1a89eecb13ff8a51a0eff0",
    "post_app_resources_and_reserved": "53718db6501441b091aeb48e21eedd480faebcae4743add53d1ae36d57b327e7",
    "uboot_boot_raw_0x00a0_0x38cf": "b5a0715940db344f951595e2d5a66050631c7721703cb06d33d8dc94eca3c861",
}


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require(condition: bool, message: str) -> None:
    if not condition:
        raise SystemExit(f"FAIL: {message}")


def slice_at(data: bytes, address: int, size: int) -> bytes:
    start = off(address)
    return data[start:start + size]


def exact_change_map(changes: list[dict[str, object]]) -> dict[str, dict[str, object]]:
    return {str(item["address"]): item for item in changes}


def changed_offsets(before: bytes, after: bytes) -> set[int]:
    require(len(before) == len(after), "app sizes differ")
    return {index for index, (left, right) in enumerate(zip(before, after)) if left != right}


def main() -> int:
    for path in (APP, PACKAGE, OFFICIAL_APP, APP_MANIFEST, PACKAGE_MANIFEST):
        require(path.is_file(), f"missing {path.relative_to(ROOT)}")

    official = OFFICIAL_APP.read_bytes()
    app = APP.read_bytes()
    app_manifest = json.loads(APP_MANIFEST.read_text())
    package_manifest = json.loads(PACKAGE_MANIFEST.read_text())
    cave, layout = build_code_cave()
    note_entry = layout["note_wrapper"]["entry"]
    require(isinstance(note_entry, int), "note wrapper entry not concrete")

    require(len(official) == APP_SIZE, "official app size mismatch")
    require(sha256_bytes(official) == OFFICIAL_APP_SHA, "official app SHA gate mismatch")
    require(len(app) == APP_SIZE, "R01d app size mismatch")
    require(sha256_bytes(app) == EXPECTED_APP_SHA, "R01d app SHA mismatch")
    require(file_sha256(PACKAGE) == EXPECTED_PACKAGE_SHA, "R01d package SHA mismatch")

    require(app_manifest["format"] == FORMAT, "app manifest format mismatch")
    require(app_manifest["artifact_scope"] == "artifact integrity only; not a functional success claim", "artifact scope missing")
    require(app_manifest["input_app_sha256"] == OFFICIAL_APP_SHA, "manifest official app gate mismatch")
    require(app_manifest["output_app_sha256"] == EXPECTED_APP_SHA, "manifest output app SHA mismatch")
    require(app_manifest["source_dump_sha256"] == EXPECTED_SOURCE_DUMP_SHA, "manifest dump source SHA mismatch")
    require({item["address"] for item in app_manifest["changes"]} == EXPECTED_ADDRESSES, "unexpected patch addresses")

    changes = exact_change_map(app_manifest["changes"])
    require(slice_at(official, CODE_CAVE, len(cave)) == bytes.fromhex(str(changes[f"0x{CODE_CAVE:08x}"]["old_hex"])), "code cave original bytes assertion failed")
    require(slice_at(app, CODE_CAVE, len(cave)) == cave, "code cave replacement bytes mismatch")
    require(slice_at(official, POST_INIT_LOADER_CALL, len(POST_INIT_LOADER_STOCK)) == POST_INIT_LOADER_STOCK, "post-init original bytes mismatch")
    require(slice_at(app, POST_INIT_LOADER_CALL, 4) == short_call(POST_INIT_LOADER_CALL, CODE_CAVE), "post-init short call bytes mismatch")
    require(slice_at(official, NOTE_ON_MEMCPY_CALL, len(NOTE_ON_STOCK)) == NOTE_ON_STOCK, "Note On original bytes mismatch")
    require(slice_at(app, NOTE_ON_MEMCPY_CALL, 6) == call32(NOTE_ON_MEMCPY_CALL, note_entry), "Note On wrapper call mismatch")
    require(slice_at(official, NOTE_OFF_MEMCPY_CALL, len(NOTE_OFF_STOCK)) == NOTE_OFF_STOCK, "Note Off original bytes mismatch")
    require(slice_at(app, NOTE_OFF_MEMCPY_CALL, 6) == call32(NOTE_OFF_MEMCPY_CALL, note_entry), "Note Off wrapper call mismatch")
    for address, expected in SYSEX_CALLS:
        require(slice_at(official, address, len(expected)) == expected, f"old SysEx original bytes mismatch at 0x{address:08x}")
        require(slice_at(app, address, len(expected)) == b"\0" * len(expected), f"old SysEx direct caller not neutralized at 0x{address:08x}")

    cave_end = layout["cave"]["end"]
    preload_end = layout["preload"]["end"]
    require(isinstance(cave_end, int) and isinstance(preload_end, int), "layout values not concrete")
    require(CODE_CAVE <= note_entry < cave_end <= CODE_CAVE_END, "code cave bounds failed")
    require(len(cave) == cave_end - CODE_CAVE, "code cave size mismatch")
    require(note_entry == preload_end, "note wrapper is not immediately after preload wrapper")
    require(len(cave) == 0x96, "unexpected code cave replacement size")
    require(VOICE_COPY_SIZE == 0x9C, "voice copy size changed")
    require(bytes.fromhex("4123") in cave, "Bank D mov r1,#3 encoding missing")
    require(bytes.fromhex("412d") in cave, "Mooger preset mov r1,#13 encoding missing")
    require(bytes.fromhex("2341") not in cave, "byte-swapped Bank D immediate encoding present")
    require(bytes.fromhex("2d41") not in cave, "byte-swapped preset immediate encoding present")

    post_call = short_call(POST_INIT_LOADER_CALL, CODE_CAVE)
    require(post_call.hex() == app_manifest["branch_ranges"]["post_init_call_new_hex"], "manifest post-init call encoding mismatch")
    require((POST_INIT_LOADER_CALL + 4 + (int.from_bytes(post_call[2:], "little") * 2)) % SHORT_CALL_WINDOW_BYTES == CODE_CAVE % SHORT_CALL_WINDOW_BYTES, "post-init short-call range check failed")
    require(call32(NOTE_ON_MEMCPY_CALL, note_entry).hex() == app_manifest["branch_ranges"]["note_on_call_new_hex"], "manifest Note On call encoding mismatch")
    require(call32(NOTE_OFF_MEMCPY_CALL, note_entry).hex() == app_manifest["branch_ranges"]["note_off_call_new_hex"], "manifest Note Off call encoding mismatch")

    evidence = app_manifest["evidence"]
    require(evidence["channel_register"] == "r9" and evidence["channel_10_nibble"] == CHANNEL_10, "channel gate evidence mismatch")
    require(evidence["factory_loader"] == f"0x{FACTORY_LOADER:08x}", "factory loader evidence mismatch")
    require(evidence["current_source"] == f"0x{CURRENT_SOURCE:08x}", "current source evidence mismatch")
    require(evidence["ram_staging"] == f"0x{RAM_STAGING:08x}", "RAM staging evidence mismatch")
    require(evidence["memcpy"] == f"0x{MEMCPY:08x}", "memcpy evidence mismatch")
    require(app_manifest["preload"]["name"] == MOOGER1_VOICE_NAME.decode("ascii"), "voice name mismatch")
    require(app_manifest["preload"]["bank_zero_based"] == 3, "bank index mismatch")
    require(app_manifest["preload"]["preset_zero_based"] == 13, "preset index mismatch")
    require(app_manifest["preload"]["packed_flash_offset"] == f"0x{MOOGER1_VOICE_OFFSET:08x}", "voice offset mismatch")
    require(app_manifest["preload"]["packed_sha256"] == EXPECTED_PACKED_SHA, "packed voice SHA mismatch")

    allowed_changed = set()
    for item in app_manifest["changes"]:
        address = int(str(item["address"]), 16)
        old = bytes.fromhex(str(item["old_hex"]))
        new = bytes.fromhex(str(item["new_hex"]))
        require(len(old) == len(new), f"manifest change length mismatch at 0x{address:08x}")
        require(slice_at(official, address, len(old)) == old, f"manifest old bytes mismatch at 0x{address:08x}")
        require(slice_at(app, address, len(new)) == new, f"manifest new bytes mismatch at 0x{address:08x}")
        start = off(address)
        allowed_changed.update(start + i for i, pair in enumerate(zip(old, new)) if pair[0] != pair[1])
    require(changed_offsets(official, app) == allowed_changed, "app diff has bytes outside manifest changes")

    require(package_manifest["format"] == "smk37-v15-application-only-patch-v1", "package format mismatch")
    require(package_manifest["safety_gate"] == "PASS", "repacker safety gate failed")
    require(package_manifest["input"]["app_sha256"] == OFFICIAL_APP_SHA, "package input app mismatch")
    require(package_manifest["input"]["sha256"] == "f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff", "official package SHA mismatch")
    require(package_manifest["output"]["app_sha256"] == EXPECTED_APP_SHA, "package output app mismatch")
    require(package_manifest["output"]["payload_sha256"] == EXPECTED_PAYLOAD_SHA, "package payload SHA mismatch")
    require(package_manifest["output"]["sha256"] == EXPECTED_PACKAGE_SHA, "package output SHA mismatch")
    require(package_manifest["protected_flash_hashes_before"] == PROTECTED_HASHES, "protected hashes before mismatch")
    require(package_manifest["protected_flash_hashes_after"] == PROTECTED_HASHES, "protected hashes after mismatch")
    require(package_manifest["protected_flash_hashes_before"] == package_manifest["protected_flash_hashes_after"], "protected region changed")

    print("v15 R01d artifact integrity only: PASS")
    print("not a functional success claim; no flash/OTA/device access performed")
    print("app", EXPECTED_APP_SHA)
    print("package", EXPECTED_PACKAGE_SHA)
    print("hooks: post-init preload + matched Note On/Off RAM source wrapper")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
