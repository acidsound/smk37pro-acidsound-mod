#!/usr/bin/env python3
"""Prepare a package-level v16 -> v15 comparison manifest (offline only).

This tool does NOT create a flash writer or authorize a restore. It verifies
both exact vendor FWSC containers, their distinct metadata interleaves, UFW
CRC/layout, and app headers, then records differing 4 KiB sectors in the
FWSC-unpacked flash.bin representation. Forced-loader dump conversion,
target-specific preconditions, downgrade compatibility, and v16 overhang
handling remain separate gates.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
sys.path.insert(0, str(TOOLS))

import smk37_v15_app_patch as v15  # noqa: E402

V15_PATH = ROOT / "baselines/v15/analysis/flash-candidates/S1C2-two-slot-selector-live-v2/inputs/SMK-37_Pro_015.fwsc"
V16_PATH = ROOT / "firmware/SMK-37 Pro_016.fwsc"
V15_PACKAGE_SHA256 = "f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff"
V16_PACKAGE_SHA256 = "2d98ce72530e71d617384963423820536f094501299e2cfec0a8d3c3fb6bcfb0"
V15_FLASH_SHA256 = "f77e9ab3cee79113be78f3efacffb03c6cb9b87b78263010e16e81c472df0f9a"
V16_FLASH_SHA256 = "5fa98871641617e08495086b57b4cf3257d31c60906dfb109d0453df59bb1540"
V15_SIZE = 701_140
V16_SIZE = 705_252
FWSC_BLOCK = 48
FWSC_DATA = 47
FLASH_SECTOR = 0x1000
V15_FLASH_SIZE = 0x9C000
V16_FLASH_SIZE = 0x9D000


class ValidationError(RuntimeError):
    pass


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require(ok: bool, message: str) -> None:
    if not ok:
        raise ValidationError(message)


def unpack_fwsc(raw: bytes, *, slots: int, version: int, package_size: int,
                package_sha256: str) -> tuple[bytes, bytes]:
    require(len(raw) == package_size, f"v{version} package size mismatch: {len(raw)}")
    require(sha256(raw) == package_sha256, f"v{version} exact package SHA-256 mismatch")
    require(len(raw) >= slots * FWSC_BLOCK, f"v{version} package is shorter than FWSC metadata")
    decoded = bytes((raw[i * FWSC_BLOCK + FWSC_DATA] + 0xFF - i) & 0xFF for i in range(slots))
    prefix = f"SMK-37 Pro_{version:03d}".encode("ascii")
    require(decoded.startswith(prefix), f"v{version} product/version metadata mismatch")
    payload = b"".join(raw[i * FWSC_BLOCK:i * FWSC_BLOCK + FWSC_DATA] for i in range(slots))
    payload += raw[slots * FWSC_BLOCK:]
    return payload, decoded


def extract_flash(payload: bytes, *, version: int, expected_length: int,
                  expected_sha256: str) -> tuple[bytes, list[dict[str, object]]]:
    ufw = v15.Ufw.parse(payload)
    flash_entries = [entry for entry in ufw.entries if entry.entry_type == 0 and entry.name == "flash.bin"]
    require(len(flash_entries) == 1, f"v{version} UFW must contain one flash.bin entry")
    entry = flash_entries[0]
    require(entry.offset == 0x400, f"v{version} flash.bin UFW offset changed")
    require(entry.size == expected_length, f"v{version} flash.bin length changed: 0x{entry.size:X}")
    flash = bytes(ufw.payload[entry.offset:entry.offset + entry.size])
    require(sha256(flash) == expected_sha256, f"v{version} flash.bin SHA-256 mismatch")
    entries = [
        {"index": e.index_in_list, "type": e.entry_type, "name": e.name,
         "offset": e.offset, "size": e.size, "sha256": sha256(bytes(ufw.payload[e.offset:e.offset + e.size]))}
        for e in ufw.entries
    ]
    return flash, entries


def inspect_app(flash: bytes, *, version: int, expected_area_size: int,
                expected_app_size: int, expected_app_sha256: str) -> dict[str, object]:
    # Decrypt the application area using the already validated shared SFC
    # transform; the JLFS header identifies the exact area size before the full
    # CRC checks are performed.
    header = bytearray(flash)
    v15.sfc_cipher(header, v15.APP_AREA_BASE, 0x40, v15.APP_AREA_BASE, v15.CHIP_KEY)
    area = v15.parse_jlfs_entry(header, v15.APP_AREA_BASE)
    app = v15.parse_jlfs_entry(header, v15.APP_ENTRY_HEADER)
    require(area.name == "app_area_head", f"v{version} app-area entry name mismatch")
    require(area.offset == 0x02000120, f"v{version} app entry point changed")
    require(area.size == expected_area_size, f"v{version} app-area size mismatch: 0x{area.size:X}")
    require(area.flags == 0x83 and area.reserved == 0xFF and area.index == 0,
            f"v{version} app-area entry attributes changed")
    require(app.name == "app.bin", f"v{version} app.bin entry name mismatch")
    require(app.offset == 0x120 and app.size == expected_app_size,
            f"v{version} app.bin layout mismatch")
    require(app.flags == 0x82 and app.reserved == 0xFF and app.index == 0,
            f"v{version} app.bin entry attributes changed")
    plain = bytearray(flash)
    area_end = v15.APP_AREA_BASE + area.size
    v15.sfc_cipher(plain, v15.APP_AREA_BASE, area_end - v15.APP_AREA_BASE,
                   v15.APP_AREA_BASE, v15.CHIP_KEY)
    checked_area = v15.parse_jlfs_entry(plain, v15.APP_AREA_BASE)
    checked_app = v15.parse_jlfs_entry(plain, v15.APP_ENTRY_HEADER)
    require(v15.crc16(plain[v15.APP_AREA_BASE + 32:area_end]) == checked_area.data_crc,
            f"v{version} app-area CRC mismatch")
    app_start = v15.APP_AREA_BASE + checked_app.offset
    app_data = bytes(plain[app_start:app_start + checked_app.size])
    require(len(app_data) == expected_app_size, f"v{version} short decoded app")
    require(sha256(app_data) == expected_app_sha256, f"v{version} decoded app SHA-256 mismatch")
    require(v15.crc16(app_data) == checked_app.data_crc, f"v{version} app.bin CRC mismatch")
    return {
        "area_start": v15.APP_AREA_BASE,
        "area_end_exclusive": area_end,
        "area_size": area.size,
        "app_entry_offset": checked_app.offset,
        "app_size": checked_app.size,
        "app_sha256": sha256(app_data),
    }


def create_manifest(v15_package: Path, v16_package: Path) -> dict[str, object]:
    raw15, raw16 = v15_package.read_bytes(), v16_package.read_bytes()
    payload15, metadata15 = unpack_fwsc(raw15, slots=20, version=15,
        package_size=V15_SIZE, package_sha256=V15_PACKAGE_SHA256)
    payload16, metadata16 = unpack_fwsc(raw16, slots=36, version=16,
        package_size=V16_SIZE, package_sha256=V16_PACKAGE_SHA256)
    flash15, entries15 = extract_flash(payload15, version=15,
        expected_length=V15_FLASH_SIZE, expected_sha256=V15_FLASH_SHA256)
    flash16, entries16 = extract_flash(payload16, version=16,
        expected_length=V16_FLASH_SIZE, expected_sha256=V16_FLASH_SHA256)

    app15 = inspect_app(flash15, version=15, expected_area_size=0x96CD3,
        expected_app_size=617_012,
        expected_app_sha256="36fe8299667d06d4e2c195ea0b125b8e3400a4dc010b45d6989354dd4e172055")
    app16 = inspect_app(flash16, version=16, expected_area_size=0x97757,
        expected_app_size=619_704,
        expected_app_sha256="0f64fbf6ffc454eea686d78cf89f35e593229765bdcf166f10a8bd714abcb09a")

    # Boot/layout sector must remain equal in the vendor package images. The
    # actual target's boot prefix is device-specific and must not be written.
    require(flash15[:0x4000] == flash16[:0x4000],
            "v15/v16 vendor package boot/layout prefix differs; abort package comparison")
    shared_length = min(len(flash15), len(flash16))
    sectors: list[dict[str, object]] = []
    for address in range(0, shared_length, FLASH_SECTOR):
        before = flash15[address:address + FLASH_SECTOR]
        after = flash16[address:address + FLASH_SECTOR]
        if before != after:
            sectors.append({
                "address": f"0x{address:05X}",
                "length": FLASH_SECTOR,
                "changed_byte_count": sum(a != b for a, b in zip(before, after)),
                "v15_fwsc_flash_sha256": sha256(before),
                "v16_fwsc_flash_sha256": sha256(after),
            })
    require(not any(int(item["address"], 0) < 0x4000 for item in sectors),
            "package diff unexpectedly includes the boot/layout prefix")

    overhang = flash16[len(flash15):]
    require(len(overhang) == 0x1000, "unexpected v16-only flash.bin overhang")
    return {
        "format": "smk37-v16-to-v15-package-diff-v1",
        "status": "OFFLINE_PACKAGE_DIFF_ONLY_NOT_FLASH_AUTHORIZATION",
        "restore_authorized": False,
        "device_access": "none",
        "packages": {
            "v15": {"path": str(v15_package), "size": len(raw15), "sha256": sha256(raw15),
                    "metadata_slots": 20, "metadata_prefix": metadata15[:14].decode("ascii"),
                    "payload_size": len(payload15), "flash_sha256": sha256(flash15),
                    "flash_size": len(flash15), "app": app15, "ufw_entries": entries15},
            "v16": {"path": str(v16_package), "size": len(raw16), "sha256": sha256(raw16),
                    "metadata_slots": 36, "metadata_prefix": metadata16[:14].decode("ascii"),
                    "payload_size": len(payload16), "flash_sha256": sha256(flash16),
                    "flash_size": len(flash16), "app": app16, "ufw_entries": entries16},
        },
        "package_diff": {
            "representation": "FWSC-unpacked flash.bin bytes; not forced-loader raw Flash bytes",
            "sector_size": FLASH_SECTOR,
            "boot_prefix_equal_in_packages": True,
            "changed_shared_sector_count": len(sectors),
            "changed_sectors": sectors,
            "v16_only_range": {
                "address": f"0x{len(flash15):05X}", "length": len(overhang),
                "sha256": sha256(overhang), "meaning": "unvalidated v16 package overhang; do not write or erase",
            },
        },
        "readiness": {
            "flash_writer_included": False,
            "ota_downgrade_authorized": False,
            "physical_restore_ready": False,
            "required_gates": [
                "Obtain a fresh 1 MiB WL82 forced-loader dump from the exact target after official v16 is installed.",
                "Obtain two byte-identical dumps and archive their hashes.",
                "Independently validate package-to-forced-loader byte mapping for all changed sectors and the v16-only range.",
                "Determine whether 0x9C000..0x9CFFF overlaps v15 user-data and how a downgrade preserves/restores it.",
                "Confirm product-specific 016-to-015 downgrade support and Windows tool command semantics with SMK/Jieli.",
                "Only then derive target-specific sector expectations and review a separate guarded writer.",
            ],
            "forbidden_until_gates_pass": [
                "full-chip erase or full-image write",
                "write of FWSC flash.bin sectors directly to the WL82 target",
                "blind use of isd_download -todisk",
                "use of an unrelated v15 rollback bundle",
            ],
        },
    }


def self_test() -> None:
    # Verify the structural fail-closed rules independent of local firmware files.
    raw = bytes((i * 11) & 0xFF for i in range(36 * FWSC_BLOCK))
    try:
        unpack_fwsc(raw, slots=20, version=15, package_size=len(raw), package_sha256=sha256(raw))
    except ValidationError:
        pass
    else:
        raise AssertionError("wrong slot count/metadata was accepted")
    require(V16_FLASH_SIZE > V15_FLASH_SIZE, "v16 overhang guard test failed")
    require(V16_FLASH_SIZE - V15_FLASH_SIZE == FLASH_SECTOR,
            "v16 overhang must be exactly one 4 KiB sector")
    print("self-test PASS: exact-version/slot/hash gates and v16-overhang stop")
    print("device access: none; restore_authorized: false")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--v15", type=Path, default=V15_PATH)
    parser.add_argument("--v16", type=Path, default=V16_PATH)
    parser.add_argument("--output", type=Path,
                        default=ROOT / "build/v16-to-v15-recovery/package-diff-manifest.json")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return 0
    try:
        manifest = create_manifest(args.v15, args.v16)
    except (OSError, ValueError, ValidationError) as error:
        print(f"SAFE STOP: {error}", file=sys.stderr)
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"package diff: {args.output}")
    print(f"changed package sectors: {manifest['package_diff']['changed_shared_sector_count']}")
    print("physical restore ready: false; no target accessed or written")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
