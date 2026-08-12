#!/usr/bin/env python3
"""Prepare read/verify-first M09 forced-recovery sector artifacts.

This tool never accesses a USB device and never writes flash. It extracts the
FWSC-unpacked `flash.bin` images from the exact stock-v12 and failed-M09
packages, then emits only the 4 KiB stock sectors whose bytes differ.
"""

from __future__ import annotations

import argparse
import json
from hashlib import sha256
from pathlib import Path

from smk37_app_patch import (
    FWSC_BLOCK_SIZE,
    FWSC_DATA_SIZE,
    FWSC_SLOTS,
    Ufw,
    decode_fwsc_metadata,
)


STOCK_PACKAGE_SHA256 = (
    "c6a9187e706aeae921447ec88e29fecbc618e3f1fc3de54c743c78e41781580a"
)
M09_PACKAGE_SHA256 = (
    "5ac1264eba85ce5f1747458a90203bc144d21f87dc66f189ca055b74700ab5c8"
)
FLASH_SIZE = 0x9C000
SECTOR_SIZE = 0x1000
EXPECTED_CHANGED_SECTORS = (0x04000, 0x20000, 0x21000, 0x27000, 0x5A000, 0x99000)


def digest(data: bytes) -> str:
    return sha256(data).hexdigest()


def extract_flash(path: Path, expected_sha256: str) -> bytes:
    raw = path.read_bytes()
    if digest(raw) != expected_sha256:
        raise SystemExit(f"package SHA-256 mismatch: {path}")
    decode_fwsc_metadata(raw)
    payload = bytearray()
    for index in range(FWSC_SLOTS):
        start = index * FWSC_BLOCK_SIZE
        payload.extend(raw[start : start + FWSC_DATA_SIZE])
    payload.extend(raw[FWSC_SLOTS * FWSC_BLOCK_SIZE :])
    flash = bytes(Ufw.parse(payload).flash())
    if len(flash) != FLASH_SIZE:
        raise SystemExit(f"unexpected Flash image size: 0x{len(flash):x}")
    return flash


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("stock_package", type=Path)
    parser.add_argument("m09_package", type=Path)
    parser.add_argument("output_directory", type=Path)
    args = parser.parse_args()

    stock = extract_flash(args.stock_package, STOCK_PACKAGE_SHA256)
    m09 = extract_flash(args.m09_package, M09_PACKAGE_SHA256)
    changed = tuple(
        offset
        for offset in range(0, FLASH_SIZE, SECTOR_SIZE)
        if stock[offset : offset + SECTOR_SIZE]
        != m09[offset : offset + SECTOR_SIZE]
    )
    if changed != EXPECTED_CHANGED_SECTORS:
        raise SystemExit(
            "changed-sector set is not the audited M09 set: "
            + ", ".join(f"0x{offset:05x}" for offset in changed)
        )

    args.output_directory.mkdir(parents=True, exist_ok=True)
    sectors = []
    for offset in changed:
        stock_sector = stock[offset : offset + SECTOR_SIZE]
        m09_sector = m09[offset : offset + SECTOR_SIZE]
        filename = f"stock-sector-{offset:05x}.bin"
        (args.output_directory / filename).write_bytes(stock_sector)
        sectors.append(
            {
                "address": f"0x{offset:05x}",
                "length": SECTOR_SIZE,
                "stock_file": filename,
                "stock_sha256": digest(stock_sector),
                "expected_m09_sha256": digest(m09_sector),
                "changed_byte_count": sum(a != b for a, b in zip(stock_sector, m09_sector)),
            }
        )

    manifest = {
        "format": "smk37-m09-forced-recovery-plan-v1",
        "hash_representation": (
            "FWSC-unpacked flash.bin bytes; not directly comparable to "
            "a forced-loader dump until its returned representation is validated"
        ),
        "safety_policy": {
            "device_access": "none; offline artifact preparation only",
            "required_before_write": (
                "two identical forced-loader dumps plus separately validated "
                "dump/package representation semantics"
            ),
            "write_scope": "six audited 4 KiB application sectors only",
            "forbidden": "chip erase, full-flash write, key burn, or boot-prefix write",
        },
        "stock_package_sha256": STOCK_PACKAGE_SHA256,
        "m09_package_sha256": M09_PACKAGE_SHA256,
        "stock_flash_sha256": digest(stock),
        "m09_flash_sha256": digest(m09),
        "flash_length": FLASH_SIZE,
        "sectors": sectors,
    }
    manifest_path = args.output_directory / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(manifest_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
