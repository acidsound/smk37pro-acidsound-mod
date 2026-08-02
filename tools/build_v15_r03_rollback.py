#!/usr/bin/env python3
"""Build the offline-only guarded official-v15 rollback bundle for R03.

The output restores only sectors that differ between the exact official v15
package and the exact R03 package. It copies the already reviewed R02 transport
and restore implementation, then tightens its immutable identifiers and sector
allow-list to R03. This tool never opens USB or writes Flash.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

from smk37_v15_app_patch import FWSC_BLOCK_SIZE, FWSC_DATA_SIZE, FWSC_SLOTS, Ufw

OFFICIAL_PACKAGE_SHA256 = "f7f1831cd7c9ad8b4831b6e71ea0bdbcdff9ae4c4077276b3c965511bf4d4fff"
R03_PACKAGE_SHA256 = "001582c097277d6a4a619ed407cf121d5f30097ef82f312d53a2e45c4a9a5a62"
EXPECTED_SECTORS = (0x04000, 0x20000, 0x22000, 0x2A000, 0x62000)
SECTOR_SIZE = 0x1000
BUNDLE_NAME = "SMK37Pro-WL82-v15-R03-rollback-20260802-v4"
TEMPLATE_NAME = "SMK37Pro-WL82-v15-R02-rollback-20260802-v1"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


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


def patched_guard(template: str) -> str:
    replacements = (
        ("v15 R02 rollback bundle", "v15 R03 rollback bundle"),
        ("exact four 4 KiB sectors", "exact five 4 KiB sectors"),
        ("{0x04000,0x20000,0x22000,0x2A000}",
         "{0x04000,0x20000,0x22000,0x2A000,0x62000}"),
        ("SECTORS = {0x04000, 0x20000, 0x22000, 0x2A000}",
         "SECTORS = {0x04000, 0x20000, 0x22000, 0x2A000, 0x62000}"),
        ("I_UNDERSTAND_THIS_ERASES_EXACTLY_FOUR_R02_SECTORS",
         "I_UNDERSTAND_THIS_ERASES_EXACTLY_FIVE_R03_SECTORS"),
        ("I_HAVE_TWO_IDENTICAL_1MIB_DUMPS_AND_R02_TARGET_HASHES",
         "I_HAVE_TWO_IDENTICAL_1MIB_DUMPS_AND_R03_TARGET_HASHES"),
        ("smk37-v15-r02-forced-recovery-plan-v1",
         "smk37-v15-r03-forced-recovery-plan-v1"),
        ("expected R02 hash", "expected R03 hash"),
        ("pre-erase R02 hash", "pre-erase R03 hash"),
    )
    result = template
    for old, new in replacements:
        require(old in result, f"guard template token missing: {old}")
        result = result.replace(old, new)
    require("R02" not in result and "r02" not in result, "stale R02 token in R03 guard")
    require("0x62000" in result, "R03 guard lacks heap-sector allow-list")
    return result


def patched_wrapper(template: str) -> str:
    replacements = (
        ("I_UNDERSTAND_THIS_ERASES_EXACTLY_FOUR_R02_SECTORS",
         "I_UNDERSTAND_THIS_ERASES_EXACTLY_FIVE_R03_SECTORS"),
        ("I_HAVE_TWO_IDENTICAL_1MIB_DUMPS_AND_R02_TARGET_HASHES",
         "I_HAVE_TWO_IDENTICAL_1MIB_DUMPS_AND_R03_TARGET_HASHES"),
    )
    result = template
    for old, new in replacements:
        require(old in result, f"wrapper template token missing: {old}")
        result = result.replace(old, new)
    require("R02" not in result and "r02" not in result,
            "stale R02 token in R03 elevated wrapper")
    for confirmation in (
        "I_UNDERSTAND_THIS_ERASES_EXACTLY_FIVE_R03_SECTORS",
        "I_HAVE_TWO_IDENTICAL_1MIB_DUMPS_AND_R03_TARGET_HASHES",
        "RESTORE_OFFICIAL_V15_SECTORS_NOW",
    ):
        require(result.count(f"--confirm {confirmation}") == 1,
                f"R03 elevated wrapper confirmation mismatch: {confirmation}")
    return result


def write_hashes(root: Path) -> None:
    entries = []
    for path in sorted(p for p in root.rglob("*") if p.is_file() and p.name != "SHA256SUMS.txt"):
        entries.append(f"{digest(path.read_bytes())}  {path.relative_to(root).as_posix()}")
    (root / "SHA256SUMS.txt").write_text("\n".join(entries) + "\n", encoding="utf-8")


def write_zip(root: Path, output: Path) -> None:
    top = root.name
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for directory in sorted((p for p in root.rglob("*") if p.is_dir()), key=lambda p: p.as_posix()):
            name = f"{top}/{directory.relative_to(root).as_posix()}/"
            info = zipfile.ZipInfo(name, (2026, 8, 2, 0, 0, 0))
            info.external_attr = (0o755 << 16) | 0x10
            archive.writestr(info, b"")
        for path in sorted((p for p in root.rglob("*") if p.is_file()), key=lambda p: p.as_posix()):
            name = f"{top}/{path.relative_to(root).as_posix()}"
            info = zipfile.ZipInfo(name, (2026, 8, 2, 0, 0, 0))
            mode = 0o755 if os.access(path, os.X_OK) else 0o644
            info.external_attr = mode << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--official", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--output-zip", type=Path, required=True)
    args = parser.parse_args()

    require(args.output_dir.name == BUNDLE_NAME, "unexpected R03 bundle directory name")
    require(not args.output_dir.exists(), "refusing to overwrite existing R03 rollback directory")
    require(not args.output_zip.exists(), "refusing to overwrite existing R03 rollback ZIP")
    require(args.template.name == TEMPLATE_NAME and args.template.is_dir(), "invalid R02 rollback template")
    require(digest(args.official.read_bytes()) == OFFICIAL_PACKAGE_SHA256, "official v15 package hash mismatch")
    require(digest(args.target.read_bytes()) == R03_PACKAGE_SHA256, "R03 package hash mismatch")

    stock = flash_from_package(args.official)
    target = flash_from_package(args.target)
    require(len(stock) == len(target), "flash length mismatch")
    sectors = tuple(
        address for address in range(0, len(stock), SECTOR_SIZE)
        if stock[address:address + SECTOR_SIZE] != target[address:address + SECTOR_SIZE]
    )
    require(sectors == EXPECTED_SECTORS, f"unexpected R03 sector set: {sectors}")

    for relative in (
        "tools/windows_scsi_transport.py",
        "THIRD-PARTY-NOTICES.md",
        "assets/wl82loader.bin",
    ):
        source = args.template / relative
        destination = args.output_dir / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)

    wrapper_source = (args.template / "restore/run-restore-elevated.ps1").read_text(encoding="utf-8")
    wrapper_path = args.output_dir / "restore/run-restore-elevated.ps1"
    wrapper_path.parent.mkdir(parents=True, exist_ok=True)
    wrapper_path.write_text(patched_wrapper(wrapper_source), encoding="utf-8")

    guard_source = (args.template / "restore/smk37_wl82_guarded_restore.py").read_text(encoding="utf-8")
    guard_path = args.output_dir / "restore/smk37_wl82_guarded_restore.py"
    guard_path.write_text(patched_guard(guard_source), encoding="utf-8")

    records = []
    sector_dir = args.output_dir / "recovery-sectors"
    sector_dir.mkdir(parents=True, exist_ok=True)
    for address in sectors:
        stock_bytes = stock[address:address + SECTOR_SIZE]
        target_bytes = target[address:address + SECTOR_SIZE]
        name = f"stock-sector-{address:05x}.bin"
        (sector_dir / name).write_bytes(stock_bytes)
        records.append({
            "address": f"0x{address:05x}",
            "length": SECTOR_SIZE,
            "stock_file": name,
            "stock_sha256": digest(stock_bytes),
            "expected_target_sha256": digest(target_bytes),
            "changed_byte_count": sum(a != b for a, b in zip(stock_bytes, target_bytes)),
        })

    manifest = {
        "format": "smk37-v15-r03-forced-recovery-plan-v1",
        "hash_representation": "FWSC-unpacked flash.bin bytes; same representation previously validated against WL82 forced-loader dumps",
        "safety_policy": {
            "device_access": "none; offline artifact preparation only",
            "required_before_write": "two identical fresh 1 MiB forced-loader dumps and exact R03 target-sector hashes",
            "write_scope": "five audited 4 KiB application sectors only",
            "forbidden": "chip erase, full-flash write, key burn, boot-prefix write, reset, or run-app",
        },
        "stock_package_sha256": OFFICIAL_PACKAGE_SHA256,
        "r03_package_sha256": R03_PACKAGE_SHA256,
        "stock_flash_sha256": digest(stock),
        "r03_flash_sha256": digest(target),
        "flash_length": len(stock),
        "sectors": records,
    }
    (sector_dir / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    (args.output_dir / "README.md").write_text(
        "# SMK-37 Pro v15 R03 guarded rollback\n\n"
        "Exact R03 fixed-prefix checkpoint failure state만 official v15로 되돌립니다.\n\n"
        f"- official v15 SHA-256: `{OFFICIAL_PACKAGE_SHA256}`\n"
        f"- R03 SHA-256: `{R03_PACKAGE_SHA256}`\n"
        "- permitted sectors: `0x04000`, `0x20000`, `0x22000`, `0x2A000`, `0x62000`\n\n"
        "두 fresh 1 MiB dump가 동일하고 다섯 sector가 exact R03 target hash와 일치할 때만 erase/write합니다. 다른 build에 재사용하지 마십시오.\n",
        encoding="utf-8",
    )
    write_hashes(args.output_dir)

    for path in (p for p in args.output_dir.rglob("*") if p.is_file()):
        data = path.read_bytes()
        require(b"FOUR_R02" not in data and b"R02_TARGET_HASHES" not in data,
                f"stale R02 confirmation token in bundle: {path.relative_to(args.output_dir)}")

    completed = subprocess.run([sys.executable, str(guard_path), "self-test"], check=False)
    require(completed.returncode == 0, "R03 guarded restore self-test failed")
    write_zip(args.output_dir, args.output_zip)
    print("R03 rollback bundle", digest(args.output_zip.read_bytes()))
    print("sectors", " ".join(f"0x{x:05x}" for x in sectors))
    print("offline only; no device access or Flash mutation performed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
